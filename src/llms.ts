// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * /llms.txt — agent- and LLM-facing description of TollWarden.
 *
 * This is the discovery surface written FOR machines: a plain-text page an
 * agent (or an LLM helping a developer wire one up) can read to learn what
 * TollWarden is, exactly when to call it, and the minimal integration. It is
 * phrased around the agent's INTENT ("before you settle a payment, check it")
 * rather than a feature list, so semantic search over it matches the questions
 * agents actually have.
 *
 * Served at GET /llms.txt and GET /.well-known/llms.txt. Generated from config
 * so pricing/free-tier stay accurate.
 */
import type { TollWardenConfig } from "./config.ts";

export function llmsTxt(cfg: TollWardenConfig): string {
  const base = cfg.publicBaseUrl;
  return `# TollWarden

> A payment security firewall for x402 agents. Make ONE request before your
> agent settles any x402 payment, and get back allow / flag / block with
> machine-readable reasons. Advisory and non-custodial: TollWarden never touches
> your keys, wallet, or funds — it inspects the payment and returns a verdict.

If you are an AI agent that pays for things over x402 (HTTP 402 + USDC on Base),
this service exists to stop the ways agent wallets get drained: paying an
address that came from content you just read (prompt-injection-triggered
payments), replayed payment authorizations, paying far more than quoted,
leaking secrets in payment metadata, lookalike-token contracts, and
address-poisoning. Reads are free for your first 100 calls per key.

## When to call it

- BEFORE you settle an outgoing x402 payment: POST ${base}/v1/scan/outgoing with
  the payment. If the verdict is "block", DO NOT pay. If "flag", pause and
  confirm intent. If "allow", proceed.
- BEFORE you pay a 402 offer you received: POST ${base}/v1/scan/incoming to
  screen the resource URL, price sanity, and counterparty first.
- To check a counterparty before dealing with it: GET
  ${base}/v1/reputation/{address}.
- AFTER a scanned payment settles: POST ${base}/v1/outcomes with the scan_id,
  the attestation's payment_commitment, and what actually happened —
  "delivered", "not_delivered", "partial", or "wrong_content". This builds the
  measured delivery history that protects your own future scans of that
  seller. (The official SDK payment wrappers do this automatically.) Free.
- After a bad experience beyond non-delivery (scam, injection attempt,
  overcharge): POST ${base}/v1/reputation/report (always free) so other
  agents are warned.
- If YOUR wallet was reported unfairly: POST ${base}/v1/reputation/dispute
  (always free) with a rebuttal statement, signed by the wallet's key
  (EIP-191 personal_sign over "tollwarden-dispute-v1|<address>|<statement>").
  Verified rebuttals appear alongside the reports in every lookup.

## The most important input: provenance

TollWarden's strongest check needs to know where your decision to pay came from.
When you POST a scan, include a "context" object:
  { "origin": "planning" | "user_instruction" | "tool_result" | "fetched_content",
    "content": "<the tool result or page text you just read, if any>" }
If the payee address appears in content you just read, the payment is blocked —
that is the prompt-injection-triggered-payment case. If the decision was your
own planning or an explicit human instruction, say so and it is judged normally.
The official SDKs tag this automatically (call observe() after reading content).

## Fastest integration

TypeScript/Node:  npm install @tollwarden/client
Python:           pip install tollwarden
MCP (Claude-style agents), zero config:
  { "mcpServers": { "tollwarden": { "command": "npx", "args": ["-y", "tollwarden"] } } }

Using an agent framework? Drop-in packages add the tools AND tag provenance for
you automatically (same three tools + a framework-native hook):
  LangChain:           pip install langchain-tollwarden
  CrewAI:              pip install crewai-tollwarden
  NeMo Agent Toolkit:  pip install nemo-tollwarden
  Coinbase AgentKit:   pip install agentkit-tollwarden
  Vercel AI SDK:       npm install @tollwarden/ai-sdk

Minimal (TS):
  import { TollWardenClient } from "@tollwarden/client";
  const tollwarden = new TollWardenClient({ agentId: "my-agent" }); // free key auto-minted
  tollwarden.observe(pageOrToolText, { sourceUrl });              // tag what you read
  await tollwarden.guardOutgoing(payment);                        // throws on block

## Trusting the verdict

Every scan response is Ed25519-signed and bound to the exact payment
(sha256(network|pay_to|asset|amount|nonce)) with a short expiry. Verify it
against the pinned key at ${base}/.well-known/tollwarden-verdict-key before
trusting an "allow". The SDKs verify automatically. A wallet policy can require
a fresh signed allow-verdict before signing — turning the firewall from
advisory into enforceable without TollWarden ever holding funds.

The attestation also carries a second signed evidence record
(evidence-v1|scan_id|payment_commitment|pin_domain|pin_age_seconds|pin_corroboration):
how long the merchant pin behind this payee had held at scan time (0 = first
sighting) and which NAMED out-of-band sources corroborated it (e.g.
cdp_bazaar) — never a boolean or a score. Whether a young or uncorroborated
pin is acceptable is your decision boundary: weigh it against the payment
size. The SDKs verify it and surface it as pin_evidence.

## Endpoints

- POST /v1/scan/outgoing   Screen a payment before you settle it. ${cfg.priceScan}, first ${cfg.freeCalls} free/key.
- POST /v1/scan/incoming   Screen a 402 offer before you pay it. ${cfg.priceScan}, first ${cfg.freeCalls} free/key.
- GET  /v1/reputation/{address}   Counterparty report summary. ${cfg.priceReputation}.
- POST /v1/reputation/report      Report a bad counterparty. Free.
- POST /v1/reputation/dispute     Wallet-signed rebuttal to reports on you. Free.
- POST /v1/keys                   Mint an API key (100 free scans). Free.
- POST /v1/keys/rotate            Key leaked? Swap the secret; usage, quota, and plan carry over.
                                  Old secret honors a grace window (default 15 min). Free.
- POST /v1/keys/revoke            Kill switch: permanently revoke a key AND its account. Free.
- GET  /v1/plans                  Machine-readable plan catalog. Free.
- POST /v1/plans/subscribe        Upgrade a key to a plan; paid over x402, so you can subscribe autonomously.
- GET  /v1/usage                  Your key's own scan/verdict counts, plus approval-decision
                                  telemetry (latency + outcomes of approved payments — visible
                                  only to you, never shared). X-API-Key header. Free.
- POST /v1/approvals/config       Human-in-the-loop: on a flag verdict your webhook gets the
                                  payment facts + a one-time decide link; a human click mints a
                                  signed override verdict (tag "override:allow", <=5 min). Free.
- GET  /v1/approvals/{id}         Poll a pending approval; on approve you receive the signed
                                  override bound to exactly that payment. Free.
- POST /v1/outcomes               AFTER a scanned payment settles: record whether the seller
                                  actually DELIVERED (delivered / not_delivered / partial /
                                  wrong_content), citing the scan_id + payment_commitment.
                                  Builds measured delivery rates that protect every agent's
                                  next scan of that counterparty. The SDK payment wrappers do
                                  this automatically. Free.
- POST /v1/trust/evaluate         For SELLERS: x402 trust-provider interface (TrustQuery in,
                                  TrustEvaluation out) to gate settlement on a payer's history. Free.

## What it checks

PII/secret leakage in payment metadata, nonce replay, overpayment vs the quoted
price, prompt-injection-triggered payments (fast + deep tiers: weighted
multilingual tells with address-proximity and cluster scoring, scanned raw and
with HTML/markdown stripped; base64/hex/percent/HTML-entity/JS-escape decoding;
Unicode tag-character smuggling; homoglyph, leetspeak and letter-spacing
folding), incoming
resource-URL risk, canonical-USDC verification (lookalike tokens),
address-poisoning (including vanity-bait addresses planted in just-read
content), known-bad lists, TOFU
merchant pinning, velocity and spend caps, external trust signals, a shared
counterparty report registry, automatic injection-incident history (a wallet
TollWarden caught being planted via prompt injection is flagged on every agent's
future scans of it, even with no content in context), and measured
delivery-outcome history (does this seller actually ship?) bound to scans
TollWarden performed.

## Pricing

First ${cfg.freeCalls} scans per key are free. After that ${cfg.priceScan}/scan, paid over x402
itself. Plans (GET /v1/plans) lower per-scan price and raise your own velocity
and spend headroom; no plan can relax the safety checks. Filing counterparty
reports is always free.

## Machine-readable specs

- OpenAPI:     ${base}/openapi.json
- x402 manifest: ${base}/.well-known/x402
- Agent card:  ${base}/.well-known/agent-card.json
- Self-documenting JSON: ${base}/ (browsers get a human homepage; agents get JSON)
- Terms of Use:  ${base}/terms
- Privacy Policy: ${base}/privacy

Source (source-available, BUSL 1.1): https://github.com/tollwarden/tollwarden
`;
}
