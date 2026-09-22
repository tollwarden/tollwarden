# TollWarden — submission-ready listing copy

Service URL: `https://tollwarden.com` (custom domain, live).

---

## Agentic.Market

**Name:** TollWarden

**Category:** Security / Payments Infrastructure

**Short description (≤160 chars):**
Payment security firewall for x402. Screens payments for PII/secret leaks, nonce replay, overpayment & prompt-injection-triggered payments. Non-custodial.

**Long description:**
TollWarden is a drop-in security layer for agents that pay (or get paid) over x402. Before your agent settles a payment, one API call screens it for the vulnerability classes that actually drain agent wallets: secrets and PII leaking through payment metadata, replayed payment authorizations (nonce reuse), overpayment above what was quoted, and — most importantly — payments triggered by prompt-injected content the agent just read rather than its own plan. Incoming 402 offers get screened too: homoglyph/IP-literal/shortener resource URLs, credential demands, and price sanity. A shared counterparty report registry lets agents flag bad actors after the fact (reporting is always free) and every scan cross-checks it. TollWarden is advisory and non-custodial: it never touches keys, wallets, or funds, and wraps around whatever facilitator you already use. Verdicts are allow/flag/block with machine-readable, per-check reasons your agent can act on — and every verdict is Ed25519-signed and payment-bound, so a wallet can be configured to physically refuse unscanned payments. Flags can pause for a human: one click on an operator webhook mints a short-lived signed override for exactly that payment. And after settlement, TollWarden closes the loop: delivery outcomes (did the seller actually ship?) are captured automatically by the SDK payment wrappers, bound to real scans so delivery history can't be faked, and fed back into every agent's future scans. Leaked API keys are rotatable in one call with usage and plan carried over. Available as HTTP API, `/.well-known/x402` manifest, agent card, MCP tools, and drop-in packages for LangChain, CrewAI, NeMo, Coinbase AgentKit, and the Vercel AI SDK.

**Pricing table:**

| Endpoint | Price |
|---|---|
| `POST /v1/scan/outgoing` — screen an outgoing payment | $0.01 |
| `POST /v1/scan/incoming` — screen an incoming payment request | $0.01 |
| `GET /v1/reputation/:address` — counterparty report lookup | $0.01 |
| `POST /v1/reputation/report` — report a bad counterparty | Free |
| First 100 calls per API key (`POST /v1/keys`) | Free |
| Plans (`GET /v1/plans`): Pro $4.99/30d → $0.005/scan · Scale $19.99/30d → $0.002/scan | Subscribed via x402 |

**Payment:** x402 (exact scheme), USDC on Base mainnet, settled via Coinbase CDP facilitator.

**Links:**
- Base URL: `https://tollwarden.com`
- Manifest: `https://tollwarden.com/.well-known/x402`
- Agent card: `https://tollwarden.com/.well-known/agent-card.json`
- SDK: `npm install @tollwarden/client` (https://www.npmjs.com/package/@tollwarden/client)
- Docs: `https://tollwarden.com/` (self-documenting) + repo README

---

## x402scan

Submit at: https://www.x402scan.com/resources/register — paste each paid resource URL; x402scan validates the 402 schema automatically.

**Resource URLs to submit:**
1. `https://tollwarden.com/v1/scan/outgoing`
2. `https://tollwarden.com/v1/scan/incoming`
3. `https://tollwarden.com/v1/reputation/0x0000000000000000000000000000000000000000` (path-parameterized)

**Name:** TollWarden — x402 Payment Security Firewall

**Category:** Security / Infrastructure

**Description (short):**
Advisory firewall for x402 payment traffic. POST a payment (or a 402 offer you received) and get an allow/flag/block verdict with reasons: PII/secret leakage in payment metadata, nonce replay, overpayment vs expected price, prompt-injection-triggered payment detection, resource-URL risk, shared counterparty reputation, and measured delivery-outcome history (does this seller actually ship?). Signed verdicts enable wallet-side enforcement; flags can escalate to a human for one-click signed overrides. Non-custodial — wraps your existing wallet/facilitator. $0.01/scan, first 100 calls free per API key.

**Pricing:** $0.01 per scan (USDC, Base, exact scheme) · reputation reporting free · 100 free calls per key

---

## One-liner (for directories that want a single sentence)

TollWarden is a non-custodial payment security firewall for x402: one API call screens any payment for PII/secret leaks, nonce replay, overpayment, prompt-injection-triggered spending, and never-shipping sellers, returning a signed allow/flag/block verdict your wallet can enforce — with human escalation on flags and automatic delivery-outcome tracking after settlement, without TollWarden ever touching your keys, wallet, or funds.

---

## Packages (npm / PyPI)

Beyond the hosted service, TollWarden ships published client SDKs and **five** framework integrations. Each carries the "scan before you pay" toolset plus a framework-native provenance hook, and points back at the service.

| Package | Registry | What it is | Link |
|---|---|---|---|
| `@tollwarden/client` | npm | TypeScript client SDK + wallet enforcement kit | https://www.npmjs.com/package/@tollwarden/client |
| `tollwarden` | npm | Server + MCP server (`npx tollwarden`) | https://www.npmjs.com/package/tollwarden |
| `tollwarden` | PyPI | Python client SDK + enforcement kit | https://pypi.org/project/tollwarden/ |
| `@tollwarden/ai-sdk` | npm | Vercel AI SDK integration | https://www.npmjs.com/package/@tollwarden/ai-sdk |
| `langchain-tollwarden` | PyPI | LangChain integration | https://pypi.org/project/langchain-tollwarden/ |
| `crewai-tollwarden` | PyPI | CrewAI integration | https://pypi.org/project/crewai-tollwarden/ |
| `nemo-tollwarden` | PyPI | NeMo Agent Toolkit integration | https://pypi.org/project/nemo-tollwarden/ |
| `agentkit-tollwarden` | PyPI | Coinbase AgentKit integration | https://pypi.org/project/agentkit-tollwarden/ |

**Short blurb (for a registry that lists SDKs/integrations):**
TollWarden gives agents "scan before you pay" for x402 payments. Drop-in packages for LangChain, CrewAI, NeMo Agent Toolkit, Coinbase AgentKit, and the Vercel AI SDK add three tools (scan / check reputation / report) plus a provenance hook that auto-tags what the agent reads — so prompt-injection-triggered-payment detection works with no prompt engineering — and a `guarded_payment` wrapper that refuses blocked payments by construction. The core SDKs (npm `@tollwarden/client`, PyPI `tollwarden`) add wallet-side enforcement (signers that refuse unscanned payments), human-in-the-loop approval waiting, and automatic delivery-outcome reporting from the payment path. Advisory and non-custodial.

---

## External docs submissions — checklist

Each framework maintains a community / providers / integrations docs surface; getting TollWarden listed there is how that framework's users discover it. Ready-to-submit copy already lives beside each integration as `docs/tollwarden.md` (or `.mdx`). Confirm the exact contribution path in each repo's CONTRIBUTING before opening the PR.

- [x] **LangChain** — integrations-docs PR **submitted** 2026-07-16. Copy: `integrations/langchain-tollwarden/docs/tollwarden.mdx`.
- [ ] **Vercel AI SDK** — add to the AI SDK community providers/integrations docs. Target repo: `vercel/ai` (the docs that render at ai-sdk.dev). Copy: `integrations/ai-sdk/docs/tollwarden.mdx`. Prereq: package published to npm ✅.
- [ ] **CrewAI** — add to the CrewAI tools/integrations docs. Target repo: `crewAIInc/crewAI` (docs), community tools section. Copy: `integrations/crewai-tollwarden/docs/tollwarden.mdx`.
- [ ] **NeMo Agent Toolkit** — PR to `NVIDIA/NeMo-Agent-Toolkit` (precedent: PR #17 merged `agentpay-mcp`). Copy: `integrations/nemo-tollwarden/docs/tollwarden.md`.
- [ ] **Coinbase AgentKit** — submit the action provider to `coinbase/agentkit` (they accept community action providers). Copy: `integrations/agentkit-tollwarden/docs/tollwarden.md`.

**Per-submission framing (reuse for each):** lead with prompt-injection-triggered-payment detection (the differentiator), not "generic payment security." Every listing should link the package, the source folder, and `https://tollwarden.com/llms.txt`.
