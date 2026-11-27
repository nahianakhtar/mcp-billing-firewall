# Vercel and Stripe Commercial Revenue Runbook

## 1. Zero Cost Serverless Deployment on Vercel
The `api/index.py` handler and `vercel.json` rewrite map expose `mcp-billing-firewall` directly on Vercel Python Functions with zero external runtime packages.

```bash
# 1. Authenticate once interactively
npx vercel login

# 2. Link and configure production secrets (never commit keys to git)
npx vercel link --yes
npx vercel env add STRIPE_WEBHOOK_SECRET production
npx vercel env add POLAR_WEBHOOK_SECRET production

# 3. Deploy staged preview, verify /health and /mcp, then promote to production
npx vercel deploy
npx vercel --prod
```

## 2. Commercial Stripe Product and Payment Link Catalog
Create these five Stripe SKUs in `testmode` first, verify webhook credit delivery to `POST https://<your-vercel-app>/webhooks/stripe`, then activate `livemode`:

| SKU Code | Product Title | Price (USD) | Billing Type | Fee Rail |
| :--- | :--- | :--- | :--- | :--- |
| `KIT-D-FIREWALL` | MCP Billing Firewall Starter Kit (ZIP + Docker + CI) | `$49.00` | One time | Card / Polar MoR |
| `PPD-DIAG-175` | 48 Hour MCP, QA, or CI Diagnostic Repair | `$175.00` | Fixed PPD | Stripe ACH (`0.8%`) |
| `PPD-FIREWALL-450` | Production MCP Security Firewall and Metering Setup | `$450.00` | Fixed PPD | Stripe ACH (`0.8%`) |
| `PPD-COMPLIANCE-950` | Multi Tenant OAuth 2.1, DLP, and SHA256 Audit Suite | `$950.00` | Fixed PPD (NY Written SOW) | Stripe ACH (`$5` cap) |
| `PPP-CPA-PILOT` | Accounting and Tax Verification Pipeline Pilot + Retainer | `$1,000.00` + `$350.00/mo` | Risk Reversed PPP (NY Written SOW) | Stripe ACH (`$5` cap) |

## 3. Webhook Verification Checklist
1. Register `https://<your-vercel-app>/webhooks/stripe` listening to `checkout.session.completed` and `payment_intent.succeeded`.
2. Attach `metadata.tenant_id` on every Payment Link or Checkout Session so the proxy credits `amount_total * 10000` micro USD automatically with `event_id` replay protection.
3. Reserve 35% of cleared net payouts into your dedicated tax reserve sub account.
