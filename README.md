# TollWarden

**A payment security firewall for [x402](https://x402.org) — screen every micropayment before it settles.**

[![x402](https://img.shields.io/badge/x402-v2-blue)](https://github.com/x402-foundation/x402)
[![network](https://img.shields.io/badge/settles%20on-Base%20(USDC)-0052FF)](https://docs.cdp.coinbase.com/x402/quickstart-for-sellers)
[![tests](https://img.shields.io/badge/tests-563%2F563-brightgreen)](test/run-tests.ts)
[![npm](https://img.shields.io/npm/v/@tollwarden/client?label=sdk)](https://www.npmjs.com/package/@tollwarden/client)
[![license](https://img.shields.io/badge/license-BUSL--1.1-lightgrey)](LICENSE)

Agents that pay over x402 get drained in predictable ways: secrets leak through payment metadata, captured authorizations get replayed, quoted prices get inflated, and poisoned web content tricks agents into paying addresses they never planned to pay. TollWarden is one `POST` before settlement that checks for all of it and returns **allow / flag / block** with machine-readable, per-check reasons — in **~0.6 ms**.

TollWarden is **advisory and non-custodial**: it never touches private keys, wallets, or funds. It wraps around whatever facilitator and wallet your agent already uses. And it's a first-class x402 seller itself — its endpoints are paid via the official x402 middleware, settle through the Coinbase CDP facilitator, and carry Bazaar discovery metadata.

```
Agent decides to pay ──► POST /v1/scan/outgoing ──► allow ──► wallet settles
                                   │
                                   ├──► flag  ──► agent pauses / confirms intent
                                   └──► block ──► wallet refuses (reason attached)
```

## Use it in 30 seconds

```bash
npm install @tollwarden/client    # TypeScript/Node
pip install tollwarden           # Python
```

```ts
import { TollWardenClient, TollWardenBlockedError } from "@tollwarden/client";
const tollwarden = new TollWardenClient({ agentId: "my-agent" }); // free API key auto-minted, 100 free scans

tollwarden.observe(fetchedPageText, { sourceUrl }); // tag what your agent just read → injection detection
await tollwarden.guardOutgoing(payment);            // throws TollWardenBlockedError on a block verdict
```

**New here? [Protect your x402 agent in 5 minutes →](QUICKSTART.md)**

The SDK ([`sdk/`](sdk/), zero dependencies) also verifies every verdict's Ed25519 attestation against a pinned key, tracks your free-call quota, and can subscribe to [plans](#api) autonomously. Wallet authors get standalone `verifyAttestation()` / `computePaymentCommitment()` — and the **enforcement kit**: `TollWardenEnforcer.guardSigner(account)` wraps any viem/ethers signer so it physically refuses to sign an x402 payment authorization without a fresh, payment-bound allow-verdict.

## Framework integrations

Building on an agent framework? TollWarden ships drop-in packages that give your agent "scan before you pay" in about two lines — a toolset plus a provenance mechanism that auto-tags what the agent reads, so the prompt-injection-triggered-payment detector works without any prompt engineering:

| Framework | Package | Install |
|---|---|---|
| LangChain | [`langchain-tollwarden`](integrations/langchain-tollwarden) | `pip install langchain-tollwarden` |
| CrewAI | [`crewai-tollwarden`](integrations/crewai-tollwarden) | `pip install crewai-tollwarden` |
| NeMo Agent Toolkit | [`nemo-tollwarden`](integrations/nemo-tollwarden) | `pip install nemo-tollwarden` |
| Coinbase AgentKit | [`agentkit-tollwarden`](integrations/agentkit-tollwarden) | `pip install agentkit-tollwarden` |
| Vercel AI SDK | [`@tollwarden/ai-sdk`](integrations/ai-sdk) | `npm install @tollwarden/ai-sdk` |

Each exposes the same three tools (scan / check reputation / report) plus a framework-native provenance hook — a callback (LangChain), an after-tool-call hook (CrewAI), an explicit `content` argument (NeMo), a wallet-aware action (AgentKit), or an `onStepFinish` handler (Vercel AI SDK) — and a `guarded_payment` / `guardedPayment` wrapper for enforcement by construction (the payment executor never runs on a block verdict). See each package's README for the two-line setup.

## What it catches

**Core detectors**

| Check | What it catches |
|---|---|
| PII / secret detection | EVM private keys, seed phrases, AWS/OpenAI/Anthropic/GitHub/Slack keys, JWTs, `?api_key=` URL credentials, SSNs, Luhn-validated card numbers, emails, phones — in `resource_url`, `description`, `reason`, and `metadata`, *before* they're transmitted |
| Replay detection | Nonce reuse (stale or captured payment authorizations), scoped `network:payer:nonce`, configurable TTL window |
| Overpayment detection | Above a configurable multiple of expected price (flag ≥3×, block ≥10×) plus an absolute ceiling |
| Prompt-injection-triggered payments | Payments whose *decision* originated from content the agent just read (tool result / fetched page) rather than its own planning step; escalates on weighted injection tells in that content (override/redirect phrasing across a broad verb/object corpus and in 8 languages: English, Spanish, Portuguese, French, German, Russian, Chinese, Japanese; spoofed system/chat-template/Guidance markers, smuggled model boundary tokens, fabricated conversation turns, concealment, business-email-compromise phrasing — "our payment address has changed, no need to verify" — and urgency pressure), with extra weight when a tell sits near an address-like token. Scored the way injections are shaped: weak tells only add up when they cluster, pressure alone (urgency, transcript form, hidden characters) never blocks, and a human's own "pay X to 0x…" instruction is not scored against them. Content is scanned both raw and with HTML tags, entities and markdown emphasis stripped, so `**Ignore** all <b>previous</b>&nbsp;instructions` reads as the sentence it renders as. Blocks when the `pay_to` address itself came from that content — even split across lines or separators, missing its `0x`, or laced with invisible characters |
| Resource URL risk (incoming) | IP-literal hosts, punycode/homoglyphs, link shorteners, `user@host` tricks, non-HTTPS, credential demands ("send your seed phrase") |
| Counterparty reputation | Shared post-hoc report registry, cross-checked on every scan; reporting is always free. Blocked injection scans also feed it automatically: a wallet caught being planted in just-read content (or used as vanity-bait) is flagged on every agent's future scans of it — one detection becomes network-wide protection (flag-only; scan inputs are client-supplied) |
| Delivery outcomes | Measured, commitment-bound delivery history per counterparty — a clean payment to a seller who never ships still fails you. Sellers with low delivery rates or repeated no-ships get flagged (never blocked: H-2 applies to measured history too) |

**Zero-latency hardening tier** — checks that hold even when the calling agent's narration is compromised:

| Check | What it catches |
|---|---|
| Velocity limits | ≥N scans/min (flag; block at 2×), cumulative hourly spend cap — rate and spend are observed facts, not self-reports. Scoped to the **account behind your API key**, so a fresh `agent_id` per request opens no new window; only anonymous scans fall back to `agent_id`/`payer` |
| First-contact size cap | First payment to a never-seen counterparty above a threshold |
| Asset verification | `asset` contract that isn't canonical USDC on the declared network (lookalike-token attack) |
| Merchant pinning (TOFU) | Two tiers. **Your account's own pin**: `pay_to` rotation on a domain *you* have paid before → block — nobody else can have written that record. **Shared observation**: the first address *any* caller presented for the domain; a mismatch there is a flag ("another caller saw a different address"), because both sides are client input — it becomes a block only once the non-blocking CDP Bazaar cross-check has verified the pinned address as the domain's merchant. Pin **age** and the **named** corroboration sources ship as signed attestation fields (see below), so a wallet can tell a four-minute-old pin from a six-month-old one instead of trusting both equally |
| Address poisoning | `pay_to` that matches a counterparty you have paid, your own pinned merchant, or a CDP-verified pin on its first + last characters but differs in the middle — the truncated-display ("0x2096…287C") vanity-address attack → block. A lookalike of an address some *other* caller merely presented → flag, so a stranger cannot seed a vanity "pin" and get your honest payment blocked as the lookalike. Also catches bait: a near-copy of the recipient or a trusted address *planted in the content the agent just read*. Blocked payments are rolled back out of trust state, so repeat attempts keep detecting |
| ScoutScore trust signal (opt-in) | Merchant domains rated LOW/VERY_LOW by [ScoutScore](https://scoutscore.ai) (spam farms, template clones, dead endpoints) → flag, clearly labeled as an external third-party signal. Lookups are async + cached (zero scan latency), share the domain only, and can never block on their own. Enable with `SCOUTSCORE=on` |
| Known-bad list | O(1) membership against a curated/synced badlist |
| Deep content analysis | Encoded/obfuscated injection payloads decoded and rescanned: base64 (both alphabets, line-wrapped, space-chunked, double-encoded), hex, percent-encoding, HTML entities, JS/JSON `\x`/`\u` escapes, Unicode tag-character smuggling ("invisible ASCII"), zero-width and homoglyph obfuscation (Cyrillic, Greek, IPA, small capitals, dotless-i — plus a mixed-script-word signal for lookalikes the fold table does not know), leetspeak (`1gn0re`) and letter-spacing (`i g n o r e`). Every pass is linear in the 200 KB content cap and guarded by a latency test. Bypassed below `MICRO_BYPASS_USD` (default $0.005) per payment, but drip-resistant: once cumulative scanned spend to a counterparty crosses the same threshold, the deep tier runs anyway, and it always runs on content declared `tool_result` / `fetched_content`; overridable per request via `policy.force_deep` |

**Signed verdicts.** Every response carries an Ed25519 `attestation` over `scan_id|direction|verdict|risk_score|scanned_at|payment_commitment|expires_at` (public key at `/.well-known/tollwarden-verdict-key`). The `payment_commitment` is `sha256(network|pay_to|asset|amount|nonce)`, so a wallet can confirm an allow-verdict belongs to *this* payment and hasn't been replayed onto another, and reject it after `expires_at`. Wallet policies can require a fresh signed allow-verdict before signing — turning the firewall from advisory into enforceable, still without TollWarden touching funds.

**Signed pin evidence.** Scan attestations also carry a second signed record — `evidence-v1|scan_id|payment_commitment|pin_domain|pin_age_seconds|pin_corroboration` (same key, bound to the same scan and payment). It publishes how long the merchant pin behind this payee had held at scan time (`0` = first sighting) and which out-of-band sources corroborated it — each **named** (today: `cdp_bazaar`, the CDP Bazaar merchant index listing the domain among the pinned address's resources), never a boolean and never a composite score, because a corroboration that succeeded through a genuinely independent channel and one the attacker already controls would be the same bit, and source strength is a per-merchant judgment that belongs to you. Folding "young pin, corroborated" into a single allow/flag would make a risk-tolerance call TollWarden has no business making: with separate signed fields, a wallet can accept a four-minute-old corroborated pin for a cent and refuse it for fifty dollars. The verdict message itself stays frozen at its 7 fields — deployed verifiers are unaffected, and both SDKs verify the evidence record and surface it as `pin_evidence`. One honest limit: verifiers tolerate an *absent* evidence record (older servers, override attestations), so absence proves nothing — a stripped record is indistinguishable from an old server, and only the signed empty fields assert "no pin applies". If your policy requires pin evidence, decide explicitly what an attestation without it means to you. Every signed field is a compatibility commitment: fields get added, never quietly changed or withdrawn.

**Wallet-side enforcement.** Both SDKs ship that policy turnkey: `TollWardenEnforcer.guardSigner(account)` (TS: viem accounts, ethers v6 signers) / `TollWardenEnforcer.guard_signer(account)` (Python: eth-account, all call shapes) wraps the signer in a proxy that recomputes the payment commitment *from the typed data being signed* (EIP-3009 / ERC-2612) and refuses the signature unless a fresh, pinned-key-verified allow-verdict exists for exactly that commitment. Approvals are single-use and expire with the attestation; a compromised agent that scans payment A cannot sign payment B, and one that skips scanning cannot sign at all. Optional **local policy** bounds it further: a hard recipient allowlist (`allowedRecipients`) and per-payment / cumulative spend caps (`maxAmountAtomic` / `maxTotalAtomic`), checked against the typed data at signature time with no server involved — even a payment carrying a valid allow-verdict is refused if it pays an unlisted recipient or exceeds the caps, so a subverted advisory layer can only move bounded amounts to known parties. The agent can never extend the allowlist; the one escape hatch is opt-in (`overrideAdmitsRecipient`, on top of `acceptOverrides`): a human-approved override from [step-up approvals](#human-in-the-loop-step-up-approvals) admits exactly the payment it binds — never the recipient, and never past the spend caps. Fail-closed and fully local; the two implementations are cross-validated against the same production signer — see [`sdk/README.md`](sdk/README.md#enforcement-a-wallet-that-refuses-unscanned-payments) and [`sdk-python/README.md`](sdk-python/README.md#enforcement-a-wallet-that-refuses-unscanned-payments). It composes with the default payment path: pass the enforcer to `wrapFetchWithTollWarden(…, { enforcer })` / `wrap_transport_with_tollwarden(…, enforcer=…)` and each scanned offer's verdict becomes the signing authority for the one nonce-bearing authorization the x402 client mints for it.

**Tamper-evident audit log.** Every scan decision is appended to a hash-chained log (`AUDIT_LOG=on`) that stores a SHA-256 of the payment plus non-sensitive transaction facts — never the plaintext PII/secrets it scans. `GET /v1/audit/verify` recomputes the chain and reports any tampering; `GET /v1/audit/head` returns the current head hash for external anchoring. See `SECURITY-AUDIT.md`.

## API

| Endpoint | Price | Description |
|---|---|---|
| `POST /v1/scan/outgoing` | $0.01¹ | Screen a payment your agent is about to make |
| `POST /v1/scan/incoming` | $0.01¹ | Screen a 402 offer / payment request your agent received |
| `GET /v1/reputation/:address` | $0.01 | Counterparty report summary |
| `POST /v1/reputation/report` | free | Report a bad counterparty after the fact |
| `POST /v1/keys` | free | Issue an API key — **first 100 calls free** per key |
| `POST /v1/keys/rotate` | free | Swap your key's secret for a fresh one — usage, free quota, and plan carry over; old secret honors a grace window (default 15 min, max 24 h) |
| `POST /v1/keys/revoke` | free | Permanently kill a leaked key and its account (requires `{"confirm": true}`; irreversible) |
| `POST /v1/approvals/config` | free | Enable [human-in-the-loop approvals](#human-in-the-loop-step-up-approvals): flag verdicts pause for a human decision via your webhook |
| `GET /v1/approvals/:id` | free | Poll a pending approval; on approve, returns the signed `override:allow` verdict |
| `POST /v1/outcomes` | free | Record whether a scanned, settled payment [actually delivered](#delivery-outcomes) (commitment-bound; the SDK wrappers do this automatically) |
| `GET /v1/plans` | free | Machine-readable plan catalog (tiers, limits, subscribe mechanics) |
| `GET /v1/usage` | free | Your key's own usage stats: scan/verdict counts, free-tier quota, plan status, and [approval-decision telemetry](#human-in-the-loop-step-up-approvals) (visible only to you) |
| `POST /v1/trust/evaluate` | free | [x402 trust-provider interface](https://github.com/x402-foundation/x402/issues/2299) — sellers gate settlement on a payer's history (TrustQuery → PASS/FAIL/UNCERTAIN + evidence) |
| `GET /dashboard` | free | Browser usage dashboard for your key (see [Dashboard](#dashboard)) |
| `POST /v1/plans/subscribe` | plan price | Subscribe/renew a key on a plan — itself paid via x402, so agents upgrade autonomously |
| `GET /.well-known/x402` | free | x402 manifest |
| `GET /.well-known/agent-card.json` | free | Agent card |
| `GET /.well-known/erc8004.json` | free | ERC-8004 agent registration file (tokenURI of TollWarden's on-chain identity) |
| `GET /.well-known/tollwarden-verdict-key` | free | Ed25519 public key for verdict attestations |
| `GET /v1/audit/verify` | free | Verify the audit-log hash chain (integrity check) |
| `GET /v1/audit/head` | free | Current audit-log head hash + sequence |
| `GET /` · `GET /health` | free | Self-documenting schema / liveness |

¹ Per-scan price drops on a plan: **Pro** ($4.99/30d) → $0.005/scan with 6× velocity headroom and deep content analysis on every scan; **Scale** ($19.99/30d) → $0.002/scan at the hard-ceiling limits. Plans raise *your own* thresholds only — replay detection, merchant pinning, asset verification, and PII scanning are identical on every tier and can't be relaxed by paying more. See `GET /v1/plans`.

Send the key from `POST /v1/keys` in the `X-API-Key` header; the first `FREE_CALLS` (default 100) calls bypass payment. After that, unpaid calls get a standard x402 `402 Payment Required` — any x402 client (`@x402/fetch`, `x402-requests`, …) handles pay-and-retry automatically.

**Key lifecycle.** The account is the identity; the `psk_` secret is just a credential pointing at it. If a key leaks, `POST /v1/keys/rotate` mints a replacement secret bound to the same account — usage history, remaining free calls, and any active plan carry over unchanged (rotation never resets the free tier, so it can't be farmed). The old secret keeps scanning through an optional grace window (`grace_seconds`, default 900, `0` = dies instantly, max 24 h) so a fleet can switch over without downtime, but during grace it can no longer rotate or revoke — a leaked old secret can't take over the account. `POST /v1/keys/revoke` (with `{"confirm": true}`) is the kill switch: key and account die permanently, and the tombstone persists so the dead key keeps failing with a named reason instead of a mystery 401. Rotating the owner key? Update `ADMIN_KEY_SHA256` to the `api_key_sha256` in the rotate response.

### Example: scan an outgoing payment

```jsonc
POST /v1/scan/outgoing
{
  "agent_id": "my-agent",                    // labels the scan; limits are scoped to your key's account
  "payment": {
    "scheme": "exact",
    "network": "eip155:8453",
    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // enables canonical-USDC check + server-known decimals
    "amount": "10000",                       // atomic units ($0.01 USDC); amount_usd only if you have no atomic amount
    "pay_to": "0x2096...287C",
    "payer": "0xYourAgentWallet",
    "resource_url": "https://api.example.com/premium/report",
    "description": "Premium market report",
    "nonce": "0x1a2b3c...",
    "reason": "User asked for a market summary; this API was in my plan."
  },
  "expected_price_usd": 0.01,
  "context": {
    "origin": "planning",                    // planning | user_instruction | tool_result | fetched_content
    "content": "<the tool result / fetched page the agent just read, if any>",
    "content_source_url": "https://example.com/article"
  },
  "policy": { "force_deep": false }          // optional tiering overrides
}
```

`context.origin` is the key input for injection detection: payments prompted by just-read content are the primary prompt-injection exfiltration path and get elevated scrutiny.

### Example response (replay blocked)

```json
{
  "scan_id": "b7911f8b-164f-45a4-a610-5fd3a45a5c8b",
  "direction": "outgoing",
  "verdict": "block",
  "risk_score": 95,
  "checks": [
    {
      "id": "replay.nonce_reuse",
      "verdict": "block",
      "severity": "critical",
      "reason": "Nonce reuse detected: this nonce was first seen 2026-07-14T09:32:50Z (scan b7911f8b-…) and has now appeared 2 times. A reused nonce means a stale or captured payment authorization is being replayed."
    }
  ],
  "scanned_at": "2026-07-14T09:33:12Z",
  "advisory": "Recommended action: DO NOT settle this payment. ...",
  "attestation": {
    "alg": "ed25519",
    "public_key_spki_hex": "302a3005...",
    "message": "b7911f8b-...|outgoing|block|95|2026-07-14T09:33:12Z|<payment_commitment>|2026-07-14T09:38:12Z",
    "signature_hex": "...",
    "payment_commitment": "sha256(network|pay_to|asset|amount|nonce)",
    "expires_at": "2026-07-14T09:38:12Z",
    "evidence": {
      "message": "evidence-v1|b7911f8b-...|<payment_commitment>|api.example.com|7776000|cdp_bazaar",
      "signature_hex": "...",
      "pin": { "domain": "api.example.com", "age_seconds": 7776000, "corroboration": ["cdp_bazaar"] }
    }
  }
}
```

## Dashboard

**Usage dashboard — `GET /dashboard`.** A single self-contained page where any key holder can see their own scan counts, verdict breakdown, free-tier quota, plan status, and (when approvals are configured) their own [approval-decision telemetry](#human-in-the-loop-step-up-approvals). Paste your `psk_` key and hit View; the key is sent only as an `X-API-Key` header to `GET /v1/usage` (never in a URL, so it can't leak via history, referrers, or server logs), and each key can only ever see its own account. Served with a locked-down CSP (`default-src 'none'`, zero external resources) and rendered exclusively via `textContent`. 

## Human-in-the-loop step-up approvals

A `flag` verdict no longer has to be a dead end. Configure a webhook once and every flag pauses for a human decision:

```jsonc
POST /v1/approvals/config   (X-API-Key)
{ "webhook_url": "https://hooks.your-ops.com/tollwarden" }   // "format": "slack" for a Slack-style message
→ { "enabled": true, "webhook_secret": "psw_..." }        // shown ONCE; deliveries are HMAC-SHA256-signed
```

On a flag, your webhook receives the payment facts (the **full** `pay_to` — never truncated) and a one-time decide link. The reviewer opens `/approve`, checks the address character by character, and clicks Approve or Deny. Approval mints a short-lived (≤5 min) Ed25519-signed **override verdict** carrying the distinct tag `override:allow` in the signed message itself — an override can never masquerade as an organic allow, and it is bound to exactly the flagged payment's commitment. Blocks are never approvable; decisions are idempotent, single-token, and recorded in the tamper-evident audit log.

The agent side is two lines with the SDK:

```ts
const scan = await tollwarden.scanOutgoing(payment);
if (scan.verdict === "flag" && scan.approval) {
  const override = await tollwarden.waitForApproval(scan, { payment }); // polls; throws on deny/expiry
  enforcer.approve(override, payment);                               // requires acceptOverrides: true
}
```

(Python: `tollwarden.wait_for_approval(scan, payment=payment)` / `TollWardenEnforcer(..., accept_overrides=True)`.)

**Why `acceptOverrides` is opt-in:** an agent that holds its own API key could configure the approval webhook to point somewhere it can read, then "approve" its own flags — no human involved. Overrides are only trustworthy when the webhook receiver is out of the agent's reach (your ops channel, not the agent's environment). The enforcement kit therefore refuses `override:allow` unless the wallet owner explicitly opts in, exactly like `allowFlagged`.

**Decision telemetry — watch yourself drift.** In most deployments, human approval decays into a compliance formality approved reflexively — and that decay is invisible in any single observation: a reviewer approving in 8 seconds after three months of 40 looks identical, in one log line, to a reviewer who got calibrated. So TollWarden records the **decision latency** of every approval (both timestamps are server-stamped) and pairs each approved payment with its later [delivery outcome](#delivery-outcomes). `GET /v1/usage` and the dashboard show your own aggregates — recent vs. baseline median latency, approval rate, and how approved payments actually delivered. Recent median shrinking while the approval rate sits near 100% is the legible signature of rubber-stamping; the outcome pairing is what separates that from "the operator got faster because the flags got predictable". Raw aggregates only, no composite score — and the data is **visible only to the key that owns it**: it never feeds a verdict and never appears in reputation lookups, trust evaluations, or public stats, because a public record of who rubber-stamps is a targeting list.

**Disabling.** Per key: `POST /v1/approvals/config` with `{"webhook_url": null}` — the response carries an advisory reminding you that flags return to advisory-only (nothing pauses, no overrides are minted, and an `acceptOverrides` wallet has no flag→payment path anymore); pending approvals stay decidable until they expire. Server-wide: `APPROVALS=off` refuses new configs and opens no new approvals, with the same advisory, while in-flight approvals remain decidable so a mid-flight disable strands nothing.

## Delivery outcomes

Every scan check validates the *payment* — well-formed, un-manipulated. None of them can tell you the seller will actually **deliver**: a perfectly clean payment to a seller who never ships still fails the agent. The outcome loop closes that gap with measured history instead of accusations:

- x402 delivery is usually **synchronous** — the resource arrives in the paid response — so the SDK payment-path wrappers (`wrapFetchWithTollWarden` / `wrap_transport_with_tollwarden`) observe it mechanically and report it **automatically**: paid 2xx → `delivered`, paid 5xx/second-402 → `not_delivered`, with status/bytes/latency evidence (opt out with `reportOutcomes: false`). Settling some other way? `POST /v1/outcomes` or `client.reportOutcome(scan, ...)` directly.
- Every outcome is **bound to a scan TollWarden performed**: the report must present the `scan_id` + `payment_commitment` pair, one outcome per scan, keyed scans only from the scanning account. Fabricating delivery history requires making real, scanned payments — an anti-Sybil property free-text reports can't have.
- Aggregated delivery rates surface in `GET /v1/reputation/:address` and in a `delivery` check on every future scan of that counterparty: low rates and repeated no-ships **flag** (never block — measured history is still third-party signal, audit H-2 applies).
- The **denominator is public too**: reputation lookups report `scans_seen` (non-blocked scans TollWarden performed against the counterparty) and `report_coverage` alongside the outcome counts — so selectively reported outcomes read as low coverage instead of passing as a complete record, and a counterparty with scans but zero reported outcomes shows that population instead of reading as "no history". Coverage is informational only (scan counts are client-driven) and never feeds a flag.

Honest limits: this measures that content *arrived*, not that it was *good* — quality judgments stay with `POST /v1/reputation/report` — and it covers digital, synchronous x402 delivery, not physical shipment.

## Local development

For contributors and anyone auditing the detectors — runs entirely offline, payments disabled, no wallet needed:

```bash
git clone https://github.com/tollwarden/tollwarden && cd tollwarden
npm install

npm run dev            # local dev server — payments off
npm run demo:replay    # replay-attack demo: fresh nonce ALLOW → reused nonce BLOCK
npm test               # 563-test detector + hardening + plans + audit-log + dashboard + key-lifecycle + approvals + outcomes suite
npm run eval           # detection eval corpus: attack payloads + benign FP guards, graded via real scans (gates CI + publish)
```

## Performance

Measured on the zero-dependency dev server (same handlers as production): **2,000 sequential scans in 1.20 s → 0.60 ms/scan round-trip**, including HTTP, JSON parsing, the full check suite, and Ed25519 signing. Deployed latency is dominated by network RTT; on the paid path, the x402 verify/settle round-trip to the facilitator (inherent to x402, identical on any host) dominates everything else.

## The hosted service

The production service at **https://tollwarden.com** is live on Base mainnet, indexed in the [x402 Bazaar](https://docs.cdp.coinbase.com/x402/bazaar), registered on [x402scan](https://www.x402scan.com), monitored with a tamper-evident audit chain, and registered as an on-chain [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) agent (agentId **59586** in the IdentityRegistry on Base — the token's URI resolves back to this service's registration file). Verify it yourself:

```bash
curl https://tollwarden.com/health
curl https://tollwarden.com/.well-known/x402
curl https://tollwarden.com/v1/audit/verify
curl https://tollwarden.com/.well-known/erc8004.json
```

### Public stats, and who is in them

`GET /v1/stats` publishes aggregate service numbers (scan totals, verdict split, distinct
agents, self-measured 90-day uptime). The response reports **third-party and first-party
usage separately**. Keys the operator tags as first-party (our own agents, chiefly the
open-source ecosystem scout that buys real x402 resources twice a day) are counted under
`first_party`, and the homepage panel shows `third_party` only. The attribution comes from
per-key usage counters recorded at scan time, so it is authenticated by the key that made
each scan and covers scans made before a key was tagged.

Why publish the first-party number instead of quietly subtracting it? The scout is public
and its run count is checkable, so a reader can reconcile the figure themselves. A
disclosure sentence is a claim someone has to trust. A number that reconciles is evidence.

Tagging is owner-only (`POST /v1/admin/keys/first-party`, guarded the same way as
`/v1/admin/stats`, taking the key **hash** rather than the key). There is no client-facing
way to set the flag. A caller able to tag itself first-party could remove its own scans
from the public third-party denominator, which is the exact thing the split exists to
prevent.

## MCP server

Listed in the [official MCP registry](https://registry.modelcontextprotocol.io) as **`com.tollwarden/tollwarden`** — or run it directly with zero config:

```jsonc
// claude_desktop_config.json / any MCP client
{
  "mcpServers": {
    "tollwarden": {
      "command": "npx",
      "args": ["-y", "tollwarden"],
      "env": { "TOLLWARDEN_API_KEY": "psk_..." } // optional — mint one with the mint_api_key tool
    }
  }
}
```

Twelve tools over stdio: `scan_outgoing_payment`, `scan_incoming_payment`, `check_counterparty_reputation`, `report_counterparty`, `report_payment_outcome` (close the loop after settlement — builds measured delivery history), `dispute_reputation` (wallet-signed rebuttal shown alongside reports — never erases them), `mint_api_key`, `rotate_api_key` (leaked-key recovery — fresh secret, same account), `check_approval_status` (poll a human-in-the-loop approval), `get_plans`, `subscribe_plan`, and `verify_verdict_attestation` (full Ed25519 verification performed locally — pinned key, commitment recompute, expiry, plus the signed pin-evidence record: returns `pin_evidence` with pin age and named corroboration sources). Defaults to the production service; set `TOLLWARDEN_URL` to point elsewhere.

## Detection defaults (hosted service)

Published for transparency — these are the thresholds your scans are judged against on the Starter tier ([plans](#api) raise the velocity/spend headroom; nothing can relax the safety checks):

| Behavior | Default |
|---|---|
| Overpayment | flag ≥3× expected price, block ≥10×, absolute ceiling $10 |
| Velocity | flag ≥10 scans/min (block at 2×), $5/hour cumulative spend cap |
| First contact | first payment to a never-seen counterparty flagged above $1 |
| Deep content analysis | bypassed below $0.005 payment value — until cumulative scanned spend to the counterparty crosses $0.005, then always on for that pair (`policy.force_deep` overrides; always on for Pro/Scale) |
| Replay window | nonces tracked for 24 h |
| Asset check | non-canonical USDC on the declared network → block |
| Merchant pinning | TOFU per resource domain, per account: rotation on a domain your account pinned → block; rotation against another caller's unverified observation → flag; against a CDP-verified pin → block for anyone. Pin age + named corroboration sources published as signed attestation evidence |
| Address poisoning | ≥4 shared hex chars on both ends of a known address (but not equal) → block when the known address is yours (paid before / your pin) or CDP-verified, flag when it is another caller's unverified pin; same lookalike planted in just-read content → block (untrusted origin, trusted reference) or flag |
| Payment value | resolved from the atomic `amount` and **server-known** token decimals (canonical USDC = 6). A client-declared `asset_decimals` that disagrees is ignored and flagged; `amount_usd` is used only when no atomic amount is given, and is flagged when it disagrees with one |
| ScoutScore signal | opt-in (`SCOUTSCORE=on`); LOW/VERY_LOW-rated domains → flag (never block); cached 24h |
| Verdict signing | Ed25519, always on, 5-minute attestation expiry |

Local dev configuration for contributors is documented in [`.env.example`](.env.example).

## Architecture

```
src/
  index.ts        Express + @x402/express middleware + CDP facilitator + Bazaar extension
  devserver.ts    Zero-dependency dev server (payments off) — same API surface
  api.ts          Framework-agnostic handlers (both servers route here)
  scanner.ts      Detector orchestration, tiering, verdict aggregation
  detectors/      pii · replay · overpayment · injection (fast + deep) · urlrisk
                  asset · badlist · pinning · poisoning · scoutscore · velocity · offerdrift
  reputation.ts   Shared report registry
  outcomes.ts     Delivery-outcome ledger (commitment-bound) + delivery check
  approvals.ts    Human-in-the-loop step-up approvals (webhook + overrides)
  approvepage.ts  Human decide page (GET /approve)
  dashboard.ts    Self-contained usage dashboard (GET /dashboard)
  admindash.ts    Owner dashboard, audit-log-backed (GET /admin)
  verdictsign.ts  Ed25519 verdict attestation
  manifest.ts     /.well-known/x402 + agent card + ERC-8004 registration
  store.ts        JSON-file-backed state (tiny interface)
  auditlog.ts     Tamper-evident hash-chained decision log
  commitment.ts   Payment hashing (attestation binding + audit digest)
mcp/server.ts     MCP server (12 tools — npx tollwarden)
examples/         replay-demo.ts — reused-nonce attack blocked end-to-end
test/             563-test suite (detectors, hardening, plans, crypto, audit, dashboards, key lifecycle, approvals, outcomes — npm test)
eval/             detection eval corpus + runner (attacks must catch, benign must pass — npm run eval, gates CI)
sdk/              TypeScript client SDK + wallet enforcement kit + payment-path wrapper (npm: @tollwarden/client, 127 tests)
sdk-python/       Python client SDK + wallet enforcement kit + payment-path wrapper (PyPI: tollwarden, 131 tests)
```

Design notes: verdicts aggregate worst-first (any block ⇒ block); `risk_score` is severity-based with compounding for multiple independent findings; the detection core has **zero runtime dependencies**, so the full suite runs with `node --experimental-strip-types` and no install.

## Security & custody model

- **Non-custodial, advisory-only.** TollWarden sees payment *metadata* — it never signs, holds, or routes funds. The settle/refuse decision stays with your wallet/facilitator (optionally enforced via signed verdicts).
- Detected secrets are **redacted in responses** (first 4 + last 2 chars) and never persisted. Scan payloads are processed in memory; only nonce fingerprints, pins, velocity counters, reputation reports, and API-key usage are stored.
- **Threat model — what holds against whom.** Two attacker tiers matter, and they are not the same:
  - A **confused agent** — a prompt-injected model still making tool calls through its normal harness — is what TollWarden is built for. Detection catches manipulated payments; velocity and spend caps, first-contact limits, and merchant pinning are computed server-side from observed scans, so they bind on every scanned payment no matter what the model believes; and `guardSigner` closes the skip-scanning hole at the wallet, because the wrapped signer recomputes the commitment from the typed data actually being signed and refuses without a fresh allow-verdict — with optional local policy (recipient allowlist + spend caps) bounding even approved payments. (`context.origin` is self-declared, so an agent that lies about provenance weakens the content tier — the caps, pinning, and signer enforcement don't depend on it.)
  - A **compromised process** — attacker code running where the wallet's private key is readable — defeats any in-process wrapper, including our enforcer: it can sign with the raw key and never touch TollWarden. TollWarden is non-custodial and never holds your key, which also means it cannot protect a key your own process exposes. For this tier the mitigation is key isolation — keep the signer in a separate process, KMS, or hardware, and run the enforcer at that boundary so nothing inside the agent process can produce a signature. (The auto-minted `psk_` API key is a scan credential only: it can spend your TollWarden quota, never your funds.)
- **Honest limitations:** injection detection is heuristic, not semantic; novel phrasings can evade the content tier (our public eval corpus tracks known gaps). The reputation registry accepts unauthenticated reports and should be treated as a signal, not ground truth.

## Contributing

Issues and PRs welcome — particularly new detector patterns (with tests) and SDK improvements (the TS and Python clients live in [`sdk/`](sdk/) and [`sdk-python/`](sdk-python/)). Run `npm test` before submitting; every detector change needs a covering test. By submitting a contribution you agree to license it to TollWarden, LLC under the terms of the [LICENSE](LICENSE), and you grant TollWarden, LLC the right to relicense the contribution as part of the Licensed Work (including under the Change License).

## License

[Business Source License 1.1](LICENSE) (source-available). You can read, run, modify, and self-host TollWarden, and use the SDKs/MCP server against the hosted service — including inside commercial products. What the license restricts is offering the code itself as a competing paid payment-security service. Each version converts to Apache 2.0 four years after release. Versions ≤ 1.4.0 remain MIT.
