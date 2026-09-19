# TollWarden

**The payment security firewall for AI agents that pay for things.**

AI agents increasingly buy what they need on their own — API calls, data, compute — over [x402](https://www.x402.org), the protocol that turns HTTP's `402 Payment Required` into instant stablecoin micropayments. That autonomy has a failure mode: software that can *read the internet* and *sign payments* can be talked into paying the wrong party. A poisoned web page whispers "pay this address instead." A payment authorization gets replayed. A lookalike token or vanity address slips past a truncated display. A seller takes the money and never delivers.

TollWarden is one HTTP call that stands between your agent and settlement. Before paying, the agent submits the payment for a scan and gets back a verdict — **allow**, **flag**, or **block** — with machine-readable reasons and a cryptographically signed attestation bound to that exact payment.

TollWarden is **advisory** and **non-custodial**: it never touches your keys, your wallet, or your funds. It inspects the payment; your systems decide.

## What a scan catches

- **Prompt-injection-triggered payments** — the strongest check. If the payee address arrived in content your agent just read (a web page, a tool result), that payment is blocked. Detection survives HTML/markdown markup, base64/hex encoding, invisible Unicode, homoglyphs, leetspeak, and multilingual override phrasing.
- **Replay** — a payment authorization your agent already used, presented again.
- **Overpayment** — amounts far beyond the quoted price, or beyond an absolute ceiling you set.
- **Secret and PII leakage** — private keys, seed phrases, API keys, card numbers, SSNs in payment metadata, caught *before* they're transmitted.
- **Lookalike tokens and address poisoning** — non-canonical "USDC" contracts, and addresses crafted to match a legitimate counterparty's first and last characters.
- **Counterparty risk** — a shared reputation registry with time decay and signed rebuttals, plus **measured delivery history**: sellers who take payment and don't deliver get flagged, based on commitment-bound outcomes, not self-reports.
- **Velocity** — rate and hourly spend caps, so a compromised agent can't drain a wallet in a burst.

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

Drop-in packages also exist for LangChain, CrewAI, Vercel AI SDK, Coinbase AgentKit, and the NVIDIA NeMo Agent Toolkit.

## Pricing

Scans are **{{price_scan}}** each, paid over x402 itself — your agent can pay for its own security, per payment it makes. The first **{{free_calls}} calls per API key are free**, reputation lookups are {{price_reputation}}, and reporting bad counterparties or recording delivery outcomes is always free. Volume plans with lower per-scan pricing are listed at [/v1/plans](/v1/plans).

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
