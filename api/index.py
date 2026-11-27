"""Vercel Serverless Python entrypoint for MCP Billing Firewall & HTTP 402/x402 Proxy.

Delegates directly to mcp_firewall.server.make_handler so Vercel Python Functions
share 100% of the audited rate-limiting, prompt-injection/SSRF firewall, SQLite WAL
micro-credit metering, Polar/Stripe HMAC webhooks, and SHA-256 hash chain logic.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp_firewall.engine import (
    DEFAULT_TOOL_PRICES_MICRO,
    FirewallLedgerStore,
    RationalTokenBucket,
)
from mcp_firewall.server import make_handler

_STORE = FirewallLedgerStore(
    Path(os.environ.get("FIREWALL_DB_PATH", "/tmp/mcp_billing_firewall.db")),
    initial_free_micro=int(os.environ.get("FIREWALL_FREE_MICRO", "50000")),
)
_BUCKET = RationalTokenBucket()

handler = make_handler(
    store=_STORE,
    bucket=_BUCKET,
    tool_prices=dict(DEFAULT_TOOL_PRICES_MICRO),
    stripe_secret=os.environ.get("STRIPE_WEBHOOK_SECRET", ""),
    polar_secret=os.environ.get("POLAR_WEBHOOK_SECRET", ""),
    checkout_url=os.environ.get("CHECKOUT_URL", "https://polar.sh/nahianakhtar"),
    upstream_url=os.environ.get("UPSTREAM_MCP_URL", ""),
)
