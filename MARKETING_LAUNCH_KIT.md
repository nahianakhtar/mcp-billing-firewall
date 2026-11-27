# PR, Branding, Marketing & Sales Launch Kit (`mcp-billing-firewall`)

## 1. Show HN Post (Hacker News)

**Title**: `Show HN: Zero-dependency MCP 2025-11-25 Security Firewall, HTTP 402 Meter & Audit Chain`

**Body**:
Standard MCP `2025-11-25` Streamable HTTP servers ship without native payment metering, prompt-injection defense, or tamper-evident compliance logs. Teams exposing internal tools to autonomous agents end up bolting together Redis, an API gateway, and custom webhook glue.

I built `mcp-billing-firewall` in pure Python 3.12 stdlib + SQLite WAL (`0` external runtime dependencies):

1. Exact integer milli-token rate limiter (`Retry-After` headers, zero floating-point drift).
2. Inbound prompt-override, cloud metadata SSRF (`169.254.169.254`), and traversal blocker plus outbound API key / email / SSN redaction.
3. Atomic `BEGIN IMMEDIATE` micro-credit ledger (`10^-6 USD`, tested under 12 concurrent threads with zero double-spend) returning `HTTP 402` + `X-Payment-Required` (`x402`) headers when credits run dry.
4. Timing-safe HMAC-SHA256 webhooks for both Polar.sh and Stripe with SQLite `event_id` replay deduplication.
5. SHA-256 hash-chained SQLite compliance ledger plus an offline `--verify-chain` CLI and GitHub Action.

Live browser simulator (zero API keys): https://nahianakhtar.github.io/demos/mcp-firewall/
MIT Source & Release `v1.0.0`: https://github.com/nahianakhtar/mcp-billing-firewall

## 2. LinkedIn Engineering Post #2 (Ready to Publish)

Shipping an MCP `2025-11-25` server for internal testing takes an afternoon. Exposing that same server to paying customers or enterprise agents requires four hard controls that the base spec leaves out:

1. Inbound prompt-injection and cloud metadata SSRF blocking before a tool ever runs.
2. Outbound API key and PII scrubbing so tool responses never leak secrets back into prompts.
3. Atomic micro-credit metering (`10^-6 USD` in SQLite WAL `BEGIN IMMEDIATE`) returning `HTTP 402` + `x402` payment quotes, topped up via idempotent Stripe or Polar HMAC webhooks.
4. Tamper-evident SHA-256 hash-chained audit logs where flipping one byte fails verification immediately.

I released the complete zero-dependency Python 3.12 runtime under MIT (`ruff`, `mypy --strict`, and 12-thread race-condition `pytest` suites passing in CI), alongside a live zero-key browser workbench to test attacks, webhook replays, and 1-byte chain tampering directly.

Try the interactive workbench: https://nahianakhtar.github.io/demos/mcp-firewall/
Source & `v1.0.0` release: https://github.com/nahianakhtar/mcp-billing-firewall

#MCP #AISecurity #Python #SQLite #APIEngineering

## 3. DEV Community Canonical Front Matter

```markdown
---
title: "Adding Prompt-Injection Defense, HTTP 402 Micro-Credit Billing, and SHA-256 Audit Chains to Any MCP 2025-11-25 Server"
published: true
canonical_url: https://nahianakhtar.github.io/demos/mcp-firewall/
tags: python, ai, security, mcp
---
```

## 4. X / Twitter 4-Post Technical Thread

- **Post 1**: Most remote MCP servers ship wide open: no per-tool credit metering, no SSRF/prompt-injection guard, and no compliance trail. I built a zero-dependency Python 3.12 reverse proxy that adds all four in one file + SQLite WAL. Live browser demo: https://nahianakhtar.github.io/demos/mcp-firewall/
- **Post 2**: Why micro-credits (`10^-6 USD`) inside SQLite `BEGIN IMMEDIATE`? Floating-point balances drift and naive read and write updates double-spend under burst concurrency. Twelve concurrent threads against a `$0.10` balance at `$0.02/call` allow exactly `5` calls and `0` leaks.
- **Post 3**: When balance hits zero, the proxy returns `HTTP 402` with an `X-Payment-Required` (`x402`) JSON quote. Signed Polar.sh or Stripe HMAC webhooks top up the balance and store `event_id` so webhook retries never double-credit.
- **Post 4**: Every allowed, blocked, rate-limited, or `402` event appends to a SHA-256 hash chain (`entry_hash = sha256(prev_hash + canonical_json)`). MIT code, Docker, MCP `server.json`, and GitHub Action are live at https://github.com/nahianakhtar/mcp-billing-firewall

## 5. Direct B2B & Upwork Fixed-Price Sales Pitch (`$450` / `$950` PPD)

Hello [Engineering Lead],
I noticed your team is shipping MCP tool connectors for [product / agent workflow]. Before opening those tools to production tenants, I can put a zero-dependency security firewall, per-tool `HTTP 402` / Stripe / Polar metering layer, and tamper-evident SHA-256 audit log in front of your existing MCP endpoint (`$450` fixed PPD in 4 to 6 days, or `$950` with multi-tenant OAuth 2.1 and custom DLP rules).

Test the firewall rules, webhook replay guard, and audit chain live in your browser: https://nahianakhtar.github.io/demos/mcp-firewall/
Best, Nahian
