from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path
from typing import Any

MICRO_SCALE = Decimal(1_000_000)
MCP_PROTOCOL_VERSION = "2025-11-25"
GENESIS_HASH = "0" * 64

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("prompt_override", re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.IGNORECASE)),
    ("system_exfil", re.compile(r"(reveal|dump|print|leak)\s+(your\s+)?(system\s+prompt|hidden\s+instructions|api\s+keys?)", re.IGNORECASE)),
    ("ssrf_metadata", re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)", re.IGNORECASE)),
    ("ssrf_loopback", re.compile(r"https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])(?::\d+)?/", re.IGNORECASE)),
    ("shell_chain", re.compile(r"(;\s*(rm\s+-rf|curl\s+|wget\s+|nc\s+-e)|&&\s*cat\s+/etc/passwd)", re.IGNORECASE)),
    ("path_traversal", re.compile(r"(\.\./\.\./|/etc/shadow|/etc/passwd|C:\\Windows\\System32)", re.IGNORECASE)),
)

SECRET_SCRUB_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("BEARER_SECRET", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
)

DEFAULT_TOOL_PRICES_MICRO: dict[str, int] = {
    "firewall_inspect": 10_000,   # $0.01 per inspection
    "ledger_quote": 50_000,       # $0.05 per quote/audit
    "chain_status": 0,            # Free health/audit status tool
}


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def usd_to_micro(amount: str | float) -> int:
    clean = str(amount).strip().replace("$", "").replace(",", "")
    val = Decimal(clean)
    return int((val * MICRO_SCALE).quantize(Decimal(1), rounding=ROUND_HALF_EVEN))


def micro_to_usd_str(micro: int) -> str:
    dollars = (Decimal(micro) / MICRO_SCALE).quantize(Decimal("0.000001"), rounding=ROUND_HALF_EVEN)
    return f"${dollars:,.6f}"


def verify_hmac_sha256(payload: bytes, signature: str, secret: str) -> bool:
    sig = signature.strip()
    sig = sig.removeprefix("sha256=")
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


@dataclass(frozen=True)
class FirewallVerdict:
    allowed: bool
    matched_rules: tuple[str, ...]
    redaction_count: int
    sanitized_payload: Any


def scan_and_scrub(payload: Any, *, block_on_injection: bool = True) -> FirewallVerdict:
    """Recursively scan for prompt injection / SSRF / traversal and scrub secrets/PII."""
    matched: list[str] = []
    redactions = 0

    def _walk(node: Any) -> Any:
        nonlocal redactions
        if isinstance(node, str):
            for rule_name, pattern in INJECTION_PATTERNS:
                if pattern.search(node) and rule_name not in matched:
                    matched.append(rule_name)
            cleaned = node
            for label, sec_pat in SECRET_SCRUB_PATTERNS:
                cleaned, hits = sec_pat.subn(f"[REDACTED_{label}]", cleaned)
                redactions += hits
            return cleaned
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if isinstance(node, dict):
            return {str(k): _walk(v) for k, v in node.items()}
        return node

    sanitized = _walk(payload)
    allowed = not (block_on_injection and len(matched) > 0)
    return FirewallVerdict(
        allowed=allowed,
        matched_rules=tuple(matched),
        redaction_count=redactions,
        sanitized_payload=sanitized,
    )


class RationalTokenBucket:
    """Exact integer milli-token rate limiter with zero floating-point drift."""

    def __init__(self, capacity_milli: int = 10_000, refill_per_sec_milli: int = 2_000) -> None:
        self.capacity_milli = capacity_milli
        self.refill_per_sec_milli = refill_per_sec_milli
        self._lock = threading.Lock()
        self._state: dict[str, tuple[int, int]] = {}  # key -> (tokens_milli, last_ns)

    def consume(self, tenant_key: str, cost_milli: int = 1_000, now_ns: int | None = None) -> tuple[bool, int, int]:
        ts = time.monotonic_ns() if now_ns is None else now_ns
        with self._lock:
            tokens, last_ns = self._state.get(tenant_key, (self.capacity_milli, ts))
            elapsed_ns = max(0, ts - last_ns)
            refilled = (elapsed_ns * self.refill_per_sec_milli) // 1_000_000_000
            tokens = min(self.capacity_milli, tokens + refilled)
            if tokens >= cost_milli:
                tokens -= cost_milli
                self._state[tenant_key] = (tokens, ts)
                return True, tokens, 0
            deficit = cost_milli - tokens
            wait_ns = (deficit * 1_000_000_000 + self.refill_per_sec_milli - 1) // self.refill_per_sec_milli
            retry_after_sec = max(1, math.ceil(wait_ns / 1_000_000_000))
            self._state[tenant_key] = (tokens, ts)
            return False, tokens, retry_after_sec


class FirewallLedgerStore:
    """Concurrent-safe SQLite WAL micro-credit ledger, webhook dedup, and SHA-256 hash chain."""

    def __init__(self, db_path: Path, initial_free_micro: int = 100_000) -> None:
        self.db_path = db_path
        self.initial_free_micro = initial_free_micro
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        self._init_schema()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    api_key TEXT PRIMARY KEY,
                    plan TEXT NOT NULL DEFAULT 'free_trial',
                    balance_micro INTEGER NOT NULL,
                    spent_micro INTEGER NOT NULL DEFAULT 0,
                    calls_total INTEGER NOT NULL DEFAULT 0,
                    updated_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS webhook_events (
                    event_id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    api_key TEXT NOT NULL,
                    credit_micro INTEGER NOT NULL,
                    processed_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_chain (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts_utc TEXT NOT NULL,
                    api_key_hash TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    rules_json TEXT NOT NULL,
                    cost_micro INTEGER NOT NULL,
                    redactions INTEGER NOT NULL,
                    latency_us INTEGER NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                );
                """
            )

    def ensure_tenant(self, api_key: str) -> dict[str, Any]:
        with self._write_lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM tenants WHERE api_key = ?", (api_key,)).fetchone()
            if row is None:
                now = utc_now()
                conn.execute(
                    "INSERT INTO tenants (api_key, plan, balance_micro, spent_micro, calls_total, updated_utc) VALUES (?, 'free_trial', ?, 0, 0, ?)",
                    (api_key, self.initial_free_micro, now),
                )
                row = conn.execute("SELECT * FROM tenants WHERE api_key = ?", (api_key,)).fetchone()
            conn.execute("COMMIT")
            return dict(row)

    def charge_micro(self, api_key: str, cost_micro: int) -> tuple[bool, dict[str, Any]]:
        if cost_micro < 0:
            raise ValueError("cost_micro cannot be negative")
        with self._write_lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                now = utc_now()
                row = conn.execute("SELECT * FROM tenants WHERE api_key = ?", (api_key,)).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO tenants (api_key, plan, balance_micro, spent_micro, calls_total, updated_utc) VALUES (?, 'free_trial', ?, 0, 0, ?)",
                        (api_key, self.initial_free_micro, now),
                    )
                    balance, spent, calls, plan = self.initial_free_micro, 0, 0, "free_trial"
                else:
                    balance = int(row["balance_micro"])
                    spent = int(row["spent_micro"])
                    calls = int(row["calls_total"])
                    plan = str(row["plan"])

                if balance < cost_micro:
                    conn.execute("COMMIT")
                    return False, {
                        "plan": plan,
                        "balance_micro": balance,
                        "required_micro": cost_micro,
                        "shortfall_micro": cost_micro - balance,
                    }

                new_bal = balance - cost_micro
                conn.execute(
                    "UPDATE tenants SET balance_micro = ?, spent_micro = ?, calls_total = ?, updated_utc = ? WHERE api_key = ?",
                    (new_bal, spent + cost_micro, calls + 1, now, api_key),
                )
                conn.execute("COMMIT")
                return True, {
                    "plan": plan,
                    "balance_micro": new_bal,
                    "charged_micro": cost_micro,
                    "calls_total": calls + 1,
                }
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def apply_credit_webhook(self, *, event_id: str, provider: str, api_key: str, credit_micro: int, plan: str = "prepaid_pro") -> dict[str, Any]:
        if credit_micro <= 0:
            raise ValueError("credit_micro must be positive")
        with self._write_lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute("SELECT event_id FROM webhook_events WHERE event_id = ?", (event_id,)).fetchone()
                if existing is not None:
                    row = conn.execute("SELECT * FROM tenants WHERE api_key = ?", (api_key,)).fetchone()
                    conn.execute("COMMIT")
                    return {
                        "applied": False,
                        "already_processed": True,
                        "event_id": event_id,
                        "balance_micro": int(row["balance_micro"]) if row else 0,
                    }

                now = utc_now()
                row = conn.execute("SELECT * FROM tenants WHERE api_key = ?", (api_key,)).fetchone()
                if row is None:
                    new_bal = self.initial_free_micro + credit_micro
                    conn.execute(
                        "INSERT INTO tenants (api_key, plan, balance_micro, spent_micro, calls_total, updated_utc) VALUES (?, ?, ?, 0, 0, ?)",
                        (api_key, plan, new_bal, now),
                    )
                else:
                    new_bal = int(row["balance_micro"]) + credit_micro
                    conn.execute(
                        "UPDATE tenants SET plan = ?, balance_micro = ?, updated_utc = ? WHERE api_key = ?",
                        (plan, new_bal, now, api_key),
                    )

                conn.execute(
                    "INSERT INTO webhook_events (event_id, provider, api_key, credit_micro, processed_utc) VALUES (?, ?, ?, ?, ?)",
                    (event_id, provider, api_key, credit_micro, now),
                )
                conn.execute("COMMIT")
                return {
                    "applied": True,
                    "already_processed": False,
                    "event_id": event_id,
                    "provider": provider,
                    "plan": plan,
                    "balance_micro": new_bal,
                }
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def append_audit(
        self,
        *,
        api_key: str,
        tool_name: str,
        verdict: str,
        matched_rules: tuple[str, ...],
        cost_micro: int,
        redactions: int,
        latency_us: int,
    ) -> dict[str, Any]:
        key_hash = sha256_hex(api_key.encode("utf-8"))[:16]
        rules_json = canonical_json(list(matched_rules))
        ts = utc_now()
        with self._write_lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                last = conn.execute("SELECT entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1").fetchone()
                prev_hash = str(last["entry_hash"]) if last else GENESIS_HASH
                preimage = canonical_json({
                    "ts_utc": ts,
                    "api_key_hash": key_hash,
                    "tool_name": tool_name,
                    "verdict": verdict,
                    "rules_json": rules_json,
                    "cost_micro": cost_micro,
                    "redactions": redactions,
                    "latency_us": latency_us,
                    "prev_hash": prev_hash,
                })
                entry_hash = sha256_hex(preimage.encode("utf-8"))
                cur = conn.execute(
                    """
                    INSERT INTO audit_chain
                    (ts_utc, api_key_hash, tool_name, verdict, rules_json, cost_micro, redactions, latency_us, prev_hash, entry_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ts, key_hash, tool_name, verdict, rules_json, cost_micro, redactions, latency_us, prev_hash, entry_hash),
                )
                seq = int(cur.lastrowid or 0)
                conn.execute("COMMIT")
                return {"seq": seq, "prev_hash": prev_hash, "entry_hash": entry_hash}
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def verify_audit_chain(self) -> dict[str, Any]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM audit_chain ORDER BY seq ASC").fetchall()
        expected_prev = GENESIS_HASH
        for row in rows:
            if str(row["prev_hash"]) != expected_prev:
                return {"valid": False, "checked": len(rows), "broken_seq": int(row["seq"]), "reason": "prev_hash_mismatch"}
            preimage = canonical_json({
                "ts_utc": str(row["ts_utc"]),
                "api_key_hash": str(row["api_key_hash"]),
                "tool_name": str(row["tool_name"]),
                "verdict": str(row["verdict"]),
                "rules_json": str(row["rules_json"]),
                "cost_micro": int(row["cost_micro"]),
                "redactions": int(row["redactions"]),
                "latency_us": int(row["latency_us"]),
                "prev_hash": str(row["prev_hash"]),
            })
            recomputed = sha256_hex(preimage.encode("utf-8"))
            if recomputed != str(row["entry_hash"]):
                return {"valid": False, "checked": len(rows), "broken_seq": int(row["seq"]), "reason": "entry_hash_tampered"}
            expected_prev = recomputed
        return {"valid": True, "checked": len(rows), "head_hash": expected_prev}

    def metrics_snapshot(self) -> dict[str, Any]:
        with self.connect() as conn:
            t_stats = conn.execute("SELECT COUNT(*) AS n, COALESCE(SUM(spent_micro),0) AS spent, COALESCE(SUM(calls_total),0) AS calls FROM tenants").fetchone()
            a_stats = conn.execute("SELECT verdict, COUNT(*) AS c FROM audit_chain GROUP BY verdict").fetchall()
        return {
            "tenants": int(t_stats["n"]),
            "total_calls": int(t_stats["calls"]),
            "total_revenue_micro_usd": int(t_stats["spent"]),
            "total_revenue_usd": micro_to_usd_str(int(t_stats["spent"])),
            "verdicts": {str(r["verdict"]): int(r["c"]) for r in a_stats},
        }
