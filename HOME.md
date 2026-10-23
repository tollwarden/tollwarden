# TollWarden

**The payment security firewall for AI agents that pay for things.**

AI agents increasingly buy what they need on their own (API calls, data, compute) over [x402](https://www.x402.org), the protocol that turns HTTP's `402 Payment Required` into instant stablecoin micropayments. That autonomy has a failure mode. Software that can *read the internet* and *sign payments* can be talked into paying the wrong party, or into paying twice. A poisoned web page whispers "pay this address instead." A paid request times out, the client retries, and the retry signs a second valid payment for the same purchase. A payment authorization gets replayed. A lookalike token or vanity address slips past a truncated display. A seller takes the money and never delivers.

TollWarden is one HTTP call that stands between your agent and settlement. Before paying, the agent submits the payment for a scan and gets back a verdict — **allow**, **flag**, or **block** — with machine-readable reasons and a cryptographically signed attestation bound to that exact payment.

TollWarden is **advisory** and **non-custodial**: it never touches your keys, your wallet, or your funds. It inspects the payment; your systems decide.

The [AI agent payment security guide](https://tollwarden.com/guides/ai-agent-payment-security) walks through each failure mode above and the check that stops it. How the injection detector scores on its own eval set is in the [prompt-injection benchmark](https://tollwarden.com/guides/prompt-injection-benchmark).

## What a scan catches

- **Prompt-injection-triggered payments.** The strongest check. If the payee address arrived in content your agent just read (a web page, a tool result), that payment is blocked. Detection survives HTML/markdown markup, base64/hex encoding, invisible Unicode, homoglyphs, leetspeak, and multilingual override phrasing.
- **Duplicate purchases on retry.** x402 clients sign a fresh authorization for every 402 they see, so a retried request is a second valid payment with a new nonce, and both can settle. A second scan of the same purchase (payer, payee, asset, amount, resource URL) within 60 seconds is flagged. It is never blocked, because TollWarden sees scans, not settlements, and can't know the first one settled. Pass the earlier `scan_id` as `context.repeat_of` when you mean to buy again.
- **Replay.** A payment authorization your agent already used, presented again.
- **Overpayment.** Amounts far beyond the quoted price, or beyond an absolute per-payment ceiling.
- **Secret and PII leakage.** Private keys, seed phrases, API keys, card numbers, SSNs in payment metadata, caught *before* they're transmitted.
- **Lookalike tokens and address poisoning.** Non-canonical "USDC" contracts, and addresses crafted to match a legitimate counterparty's first and last characters.
- **Counterparty risk.** A shared reputation registry with time decay and signed rebuttals, plus **measured delivery history**. Sellers who take payment and don't deliver get flagged, based on commitment-bound outcomes, not self-reports.
- **Velocity.** Rate and hourly spend caps, so a compromised agent can't drain a wallet in a burst.

## From advisory to enforceable

Every verdict is Ed25519-signed and bound to a hash of the exact payment, with a short expiry. The attestation also carries signed evidence a wallet can weigh for itself: how long the merchant's payment address had been pinned at scan time (a four-minute-old pin and a six-month-old one are different risks), and which named out-of-band sources corroborated it. The SDKs ship an enforcement kit: `guardSigner(account)` wraps your wallet's signer so it **physically refuses to sign** an x402 payment authorization unless a fresh, verified allow-verdict exists for exactly that payment. A compromised agent that scanned payment A cannot sign payment B — and one that skips scanning cannot sign at all. Flagged payments can pause for one-click human approval instead — and TollWarden shows you (and only you) your own decision latency paired with how approved payments delivered, so approval decaying into a rubber stamp is visible before it costs you.

## Get started

For MCP-capable agents (Claude, etc.) — zero config:

```
{ "mcpServers": { "tollwarden": { "command": "npx", "args": ["-y", "tollwarden"] } } }
```

TypeScript:

```
npm install @tollwarden/client

import { TollWardenClient } from "@tollwarden/client";
const tollwarden = new TollWardenClient({ agentId: "my-agent" }); // free key auto-minted
tollwarden.observe(pageOrToolText, { sourceUrl });  // tag what the agent read
await tollwarden.guardOutgoing(payment);            // throws on block
```

Python:

```
pip install tollwarden
```

Drop-in packages also exist for LangChain, CrewAI, Vercel AI SDK, Coinbase AgentKit, and the NVIDIA NeMo Agent Toolkit, each with a setup page at [tollwarden.com/integrations](https://tollwarden.com/integrations).

## Pricing

Scans are **{{price_scan}}** each, paid over x402 itself — your agent can pay for its own security, per payment it makes. The first **{{free_calls}} calls per API key are free**, reputation lookups are {{price_reputation}}, and reporting bad counterparties or recording delivery outcomes is always free. Volume plans (Pro, Scale) with lower per-scan pricing are listed at [/v1/plans](/v1/plans). Plans raise your own velocity and spend headroom only. Replay detection, merchant pinning, asset verification, and PII scanning are identical on every tier and can't be relaxed by paying more.

## Track record

Live aggregate numbers from this deployment, refreshed every five minutes. The headline figures are third-party usage only. Scans from our own agents, including the open-source ecosystem scout, are reported separately under `first_party` in [/v1/stats](/v1/stats). Totals only. Per-agent and per-payment data is never published.

{{stats_panel}}

Machine-readable at [/v1/stats](/v1/stats) · liveness probe at [/health](/health).

## For developers and agents

- [llms.txt](/llms.txt) — agent-facing integration guide (point your LLM at it)
- [OpenAPI](/openapi.json) — the full API contract
- [Usage dashboard](/dashboard) — your key's stats, key sent via header only
- [Source](https://github.com/tollwarden/tollwarden) — source-available under BUSL 1.1
- [Verdict signing key](/.well-known/tollwarden-verdict-key) — pin it and verify everything

---

Operated by **TollWarden, LLC** (Colorado, USA) · [Terms of Use](TERMS.md) · [Privacy Policy](PRIVACY.md) · contact@tollwarden.com
