# `mcp-billing-firewall`

Zero-dependency Python 3.12 reverse proxy and security gateway for **MCP `2025-11-25` Streamable HTTP** servers. It unites four missing production primitives in one single-node runtime: inbound prompt-injection and SSRF blocking, outbound secret/PII scrubbing, atomic micro-credit `HTTP 402` / `x402` billing with Stripe and Polar HMAC webhooks, and a tamper-evident SHA-256 hash-chained SQLite WAL audit ledger.

Live browser simulator (zero API keys): [Open Interactive Firewall & Billing Workbench](https://nahianakhtar.github.io/demos/mcp-firewall/)

## Architecture Overview

1. **Exact Rational Rate Limiter**: Integer milli-token sliding token bucket preventing burst abuse with zero floating-point drift and exact `Retry-After` headers.
2. **Inbound & Outbound Security Firewall**: Blocks prompt overrides, cloud metadata SSRF (`169.254.169.254`), loopback pivots, shell chaining, and path traversal before tool execution, then scrubs API keys, bearer secrets, SSNs, and emails from both arguments and tool output.
3. **Concurrent Micro-Credit Metering (`10^-6 USD`)**: Executes atomic `BEGIN IMMEDIATE` deductions inside SQLite WAL (tested across 12 concurrent threads with zero double-spend). Exhausted tenants receive **HTTP `402 Payment Required`** with an `X-Payment-Required` (`x402`) quote header and checkout URL.
4. **Idempotent Stripe & Polar Webhooks**: Verifies `X-Stripe-Signature` and `X-Polar-Signature` via timing-safe HMAC-SHA256 and records every `event_id` in SQLite so replayed webhooks never double-credit balances.
5. **SHA-256 Compliance Audit Chain**: Chains every allowed, blocked, rate-limited, or `402` decision with `prev_hash` and `entry_hash`. Modifying a single byte inside SQLite fails `GET /audit/verify` and the `--verify-chain` CLI auditor immediately.

## Quickstart

```bash
PYTHONPATH=src python3 -m mcp_firewall.server --port 8091
# Verify offline test suite & strict static types:
ruff check . && mypy --strict src && PYTHONPATH=src pytest -q
```

## Commercial Open-Core & Integration Tiers

| Tier | Scope | Delivery |
| :--- | :--- | :--- |
| Open Source Core (MIT) | Full proxy, firewall rules, SQLite WAL micro-credit ledger, and CI tests | Free on GitHub Releases |
| Commercial Starter Kit (`$49`) | Packaged Docker/Fly deployment configs, Polar & Stripe webhook harnesses, and compliance export scripts | Polar.sh / Direct Download |
| Custom Deployment (`$450` PPD) | Wire `mcp-billing-firewall` in front of your existing MCP server with custom per-tool pricing and tests | 4 to 6 business days |
| Enterprise Compliance (`$950` PPD) | Multi-tenant OAuth 2.1, custom DLP patterns, SIEM forwarding, and NY written scope (`>= $800`) | Milestone acceptance |
