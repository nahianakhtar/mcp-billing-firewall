from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp_firewall.engine import (
    DEFAULT_TOOL_PRICES_MICRO,
    MCP_PROTOCOL_VERSION,
    FirewallLedgerStore,
    RationalTokenBucket,
    micro_to_usd_str,
    scan_and_scrub,
    usd_to_micro,
    verify_hmac_sha256,
)

BUILTIN_TOOLS: list[dict[str, Any]] = [
    {
        "name": "firewall_inspect",
        "description": "Inspect text or JSON payload for prompt-injection, SSRF, path traversal, and secret/PII redaction ($0.01/call).",
        "inputSchema": {
            "type": "object",
            "required": ["text"],
            "properties": {"text": {"type": "string"}},
        },
    },
    {
        "name": "ledger_quote",
        "description": "Compute exact 128-bit micro-dollar net amount, platform fee, and tax reserve ($0.05/call).",
        "inputSchema": {
            "type": "object",
            "required": ["gross_usd"],
            "properties": {
                "gross_usd": {"type": ["string", "number"]},
                "fee_bps": {"type": "integer", "default": 500},
                "tax_bps": {"type": "integer", "default": 3500},
            },
        },
    },
    {
        "name": "chain_status",
        "description": "Verify the SHA-256 hash-chained compliance audit ledger ($0.00/call).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _execute_builtin_tool(name: str, args: dict[str, Any], store: FirewallLedgerStore) -> dict[str, Any]:
    if name == "firewall_inspect":
        verdict = scan_and_scrub(args.get("text", ""), block_on_injection=False)
        return {
            "injection_rules": list(verdict.matched_rules),
            "redaction_count": verdict.redaction_count,
            "sanitized_text": verdict.sanitized_payload,
        }
    if name == "ledger_quote":
        gross = usd_to_micro(args["gross_usd"])
        fee_bps = int(args.get("fee_bps", 500))
        tax_bps = int(args.get("tax_bps", 3500))
        fee = (gross * fee_bps) // 10_000
        pre_tax = gross - fee
        tax = (pre_tax * tax_bps) // 10_000
        net = pre_tax - tax
        return {
            "gross_micro": str(gross),
            "fee_micro": str(fee),
            "tax_reserve_micro": str(tax),
            "net_micro": str(net),
            "net_usd": micro_to_usd_str(net),
        }
    if name == "chain_status":
        return store.verify_audit_chain()
    raise KeyError(f"Unknown tool: {name}")


def _forward_upstream(upstream_url: str, rpc_body: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(
        upstream_url,
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps(rpc_body).encode("utf-8"),
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        parsed = json.loads(resp.read().decode("utf-8"))
        if not isinstance(parsed, dict):
            return {"result": parsed}
        return {str(k): v for k, v in parsed.items()}


def make_handler(
    *,
    store: FirewallLedgerStore,
    bucket: RationalTokenBucket,
    tool_prices: dict[str, int],
    stripe_secret: str,
    polar_secret: str,
    checkout_url: str,
    upstream_url: str = "",
) -> type[BaseHTTPRequestHandler]:
    class FirewallHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send(self, code: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
            raw = b"" if payload is None else json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(code)
            if payload is not None:
                self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if raw:
                self.wfile.write(raw)

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/health":
                self._send(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "service": "mcp-billing-firewall",
                        "mcp_protocol": MCP_PROTOCOL_VERSION,
                        "tool_prices_micro": tool_prices,
                    },
                )
                return
            if path == "/metrics":
                self._send(HTTPStatus.OK, store.metrics_snapshot())
                return
            if path == "/audit/verify":
                self._send(HTTPStatus.OK, store.verify_audit_chain())
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        def _handle_webhook(self, provider: str, raw: bytes) -> None:
            secret = stripe_secret if provider == "stripe" else polar_secret
            sig_header = "X-Stripe-Signature" if provider == "stripe" else "X-Polar-Signature"
            sig = self.headers.get(sig_header, "")
            if not verify_hmac_sha256(raw, sig, secret):
                self._send(HTTPStatus.UNAUTHORIZED, {"error": f"Invalid {provider} HMAC signature"})
                return
            try:
                ev = json.loads(raw.decode("utf-8"))
                event_id = str(ev["event_id"]).strip()
                api_key = str(ev["api_key"]).strip()
                credit_micro = int(ev.get("credit_micro") or usd_to_micro(ev["credit_usd"]))
                plan = str(ev.get("plan", "prepaid_pro"))
                result = store.apply_credit_webhook(
                    event_id=event_id,
                    provider=provider,
                    api_key=api_key,
                    credit_micro=credit_micro,
                    plan=plan,
                )
                self._send(HTTPStatus.OK, result)
            except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
                self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        def _handle_mcp(self, raw: bytes, api_key: str) -> None:
            t0 = time.perf_counter_ns()
            try:
                rpc = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._send(HTTPStatus.BAD_REQUEST, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}})
                return

            req_id = rpc.get("id")
            method = str(rpc.get("method", ""))
            params = rpc.get("params") or {}

            if method == "notifications/initialized":
                self._send(HTTPStatus.ACCEPTED, None)
                return

            if method == "initialize":
                self._send(
                    HTTPStatus.OK,
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "capabilities": {"tools": {"listChanged": False}},
                            "serverInfo": {"name": "mcp-billing-firewall", "version": "1.0.0"},
                        },
                    },
                )
                return

            if method == "tools/list":
                self._send(
                    HTTPStatus.OK,
                    {"jsonrpc": "2.0", "id": req_id, "result": {"tools": BUILTIN_TOOLS}},
                )
                return

            if method != "tools/call":
                self._send(
                    HTTPStatus.BAD_REQUEST,
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unsupported method: {method}"}},
                )
                return

            tool_name = str(params.get("name", ""))
            args = params.get("arguments") or {}

            # 1. Exact rational rate limiter
            rl_ok, rem_milli, retry_sec = bucket.consume(api_key, cost_milli=1_000)
            if not rl_ok:
                lat_us = (time.perf_counter_ns() - t0) // 1_000
                store.append_audit(
                    api_key=api_key,
                    tool_name=tool_name,
                    verdict="RATE_LIMITED",
                    matched_rules=("token_bucket_429",),
                    cost_micro=0,
                    redactions=0,
                    latency_us=lat_us,
                )
                self._send(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32029, "message": "Rate limit exceeded"}},
                    extra_headers={"Retry-After": str(retry_sec), "X-RateLimit-Remaining-Milli": str(rem_milli)},
                )
                return

            # 2. Inbound security firewall (prompt injection / SSRF / traversal + PII redaction)
            in_verdict = scan_and_scrub(args, block_on_injection=True)
            if not in_verdict.allowed:
                lat_us = (time.perf_counter_ns() - t0) // 1_000
                chain = store.append_audit(
                    api_key=api_key,
                    tool_name=tool_name,
                    verdict="BLOCKED_FIREWALL",
                    matched_rules=in_verdict.matched_rules,
                    cost_micro=0,
                    redactions=in_verdict.redaction_count,
                    latency_us=lat_us,
                )
                self._send(
                    HTTPStatus.FORBIDDEN,
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32003,
                            "message": "Blocked by MCP security firewall",
                            "data": {"matched_rules": list(in_verdict.matched_rules), "audit": chain},
                        },
                    },
                )
                return

            # 3. Atomic SQLite WAL micro-credit metering (HTTP 402 + x402 payment challenge)
            cost_micro = tool_prices.get(tool_name, 10_000)
            paid, meter = store.charge_micro(api_key, cost_micro)
            if not paid:
                lat_us = (time.perf_counter_ns() - t0) // 1_000
                chain = store.append_audit(
                    api_key=api_key,
                    tool_name=tool_name,
                    verdict="PAYMENT_REQUIRED_402",
                    matched_rules=("insufficient_micro_credits",),
                    cost_micro=0,
                    redactions=in_verdict.redaction_count,
                    latency_us=lat_us,
                )
                x402_header = json.dumps({
                    "protocol": "x402-quote-v1",
                    "currency": "USD",
                    "required_micro_usd": cost_micro,
                    "shortfall_micro_usd": meter["shortfall_micro"],
                    "checkout_url": checkout_url,
                })
                self._send(
                    HTTPStatus.PAYMENT_REQUIRED,
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32002,
                            "message": "Payment required: insufficient micro-credit balance",
                            "data": {"meter": meter, "checkout_url": checkout_url, "audit": chain},
                        },
                    },
                    extra_headers={"X-Payment-Required": x402_header},
                )
                return

            # 4. Execute upstream proxy or built-in tool + outbound secret redaction
            try:
                if upstream_url:
                    raw_out = _forward_upstream(upstream_url, {"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": {"name": tool_name, "arguments": in_verdict.sanitized_payload}})
                    tool_output = raw_out.get("result", raw_out)
                else:
                    tool_output = _execute_builtin_tool(tool_name, in_verdict.sanitized_payload, store)
            except KeyError as exc:
                self._send(HTTPStatus.NOT_FOUND, {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": str(exc)}})
                return
            except (ValueError, TypeError, urllib.error.URLError) as exc:
                self._send(HTTPStatus.BAD_REQUEST, {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": str(exc)}})
                return

            out_verdict = scan_and_scrub(tool_output, block_on_injection=False)
            total_redactions = in_verdict.redaction_count + out_verdict.redaction_count
            lat_us = (time.perf_counter_ns() - t0) // 1_000
            chain = store.append_audit(
                api_key=api_key,
                tool_name=tool_name,
                verdict="ALLOWED",
                matched_rules=(),
                cost_micro=cost_micro,
                redactions=total_redactions,
                latency_us=lat_us,
            )
            result_obj = {
                "meter": meter,
                "firewall": {"redactions": total_redactions, "audit_seq": chain["seq"], "entry_hash": chain["entry_hash"]},
                "output": out_verdict.sanitized_payload,
            }
            self._send(
                HTTPStatus.OK,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(result_obj)}],
                        "structuredContent": result_obj,
                        "isError": False,
                    },
                },
                extra_headers={"X-RateLimit-Remaining-Milli": str(rem_milli)},
            )

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(min(length, 2 * 1024 * 1024))

            if path == "/mcp":
                api_key = self.headers.get("X-API-Key", "anon-trial").strip() or "anon-trial"
                self._handle_mcp(raw, api_key)
                return
            if path == "/webhooks/stripe":
                self._handle_webhook("stripe", raw)
                return
            if path == "/webhooks/polar":
                self._handle_webhook("polar", raw)
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    return FirewallHandler


def create_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8091,
    db_path: Path | None = None,
    initial_free_micro: int = 100_000,
    capacity_milli: int = 10_000,
    refill_per_sec_milli: int = 2_000,
    stripe_secret: str | None = None,
    polar_secret: str | None = None,
    upstream_url: str = "",
) -> ThreadingHTTPServer:
    resolved_db = db_path or (Path(__file__).resolve().parents[2] / "data" / "firewall.db")
    store = FirewallLedgerStore(resolved_db, initial_free_micro=initial_free_micro)
    bucket = RationalTokenBucket(capacity_milli=capacity_milli, refill_per_sec_milli=refill_per_sec_milli)
    handler = make_handler(
        store=store,
        bucket=bucket,
        tool_prices=dict(DEFAULT_TOOL_PRICES_MICRO),
        stripe_secret=stripe_secret or os.environ.get("STRIPE_WEBHOOK_SECRET", "whsec_local_stripe"),
        polar_secret=polar_secret or os.environ.get("POLAR_WEBHOOK_SECRET", "whsec_local_polar"),
        checkout_url=os.environ.get("CHECKOUT_URL", "https://polar.sh/"),
        upstream_url=upstream_url or os.environ.get("UPSTREAM_MCP_URL", ""),
    )
    return ThreadingHTTPServer((host, port), handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MCP 2025-11-25 Security Firewall, x402/Stripe/Polar Meter & Audit Ledger")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8091")))
    parser.add_argument("--db", type=Path, help="SQLite WAL path")
    parser.add_argument("--verify-chain", type=Path, help="Verify SHA-256 hash chain of an existing SQLite DB and exit")
    args = parser.parse_args(argv)

    if args.verify_chain is not None:
        res = FirewallLedgerStore(args.verify_chain).verify_audit_chain()
        print(json.dumps(res, indent=2))
        return 0 if res["valid"] else 2

    srv = create_server(host=args.host, port=args.port, db_path=args.db)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
