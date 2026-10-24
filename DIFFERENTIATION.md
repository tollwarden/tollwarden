# How TollWarden differs

Several services now answer the question "is this agent payment safe right now". Most of them answer it with a score, and a score leaves three gaps. It covers one or two failure modes, so an agent still pays twice on retry or pays a lookalike token. It is advice, so a model that was talked into paying can ignore it. And it is often built from inputs anyone can manufacture, so the attacker can farm the history that the score reads. TollWarden is built around five properties that close those gaps, and each one can be checked against the code in this repo.

## 1. One call runs seven checks

An agent that pays over x402 can go wrong in seven distinct ways, and each is usually sold as its own product. One `POST /v1/scan/outgoing` runs all of them and returns one verdict (`allow`, `flag` or `block`) with a machine-readable reason per check.

| Failure mode | Check IDs | Default verdict |
| --- | --- | --- |
| Payee injected by content the agent read | `injection.payto_from_content`, `injection.content_tells` | Block when the payee came from untrusted content |
| Replayed authorization | `replay.nonce_reuse` | Block |
| Overpayment against the quoted price | `overpay.flag_multiple`, `overpay.block_multiple`, `overpay.absolute_cap` | Flag at 3×, block at 10× or above $10 |
| Lookalike token | `asset.not_canonical_usdc` | Block |
| Address poisoning | `poison.lookalike`, `pin.mismatch` | Block |
| Secrets in payment metadata | `pii.evm_private_key`, `pii.seed_phrase` and others | Block for keys and credentials, flag for email and phone |
| Duplicate purchase on client retry | `replay.duplicate_purchase` | Flag |

The same call also runs URL risk, velocity and first-contact caps, merchant pinning, counterparty reports and delivery history. The detectors are in [`src/detectors/`](src/detectors), the full check list is in the [README](README.md#what-it-catches), and the thresholds are under [detection defaults](README.md#detection-defaults-hosted-service).

## 2. The signer refuses without a payment-bound verdict

Every verdict carries an Ed25519 attestation over `sha256(network|pay_to|asset|amount|nonce)` that expires after five minutes. `TollWardenEnforcer.guardSigner(account)` wraps a viem or ethers signer (`guard_signer` wraps eth-account in Python), recomputes that commitment from the typed data it is asked to sign, and refuses unless a fresh allow verdict, verified against a pinned key, exists for exactly that payment. Approvals are single-use. An agent that scans one payment cannot sign another, an agent that skips the scan cannot sign at all, and if TollWarden is unreachable nothing new can be approved, so it fails closed.

The enforcer also takes a recipient allowlist and per-payment and lifetime spend caps, checked locally against the typed data with no server involved. A payment with a valid allow verdict is still refused if it pays an unlisted recipient or exceeds a cap. Source is in [`sdk/src/enforce.ts`](sdk/src/enforce.ts) and the Python SDK.

A score can inform a decision. A verdict bound to the payment can be enforced at the key.

## 3. It sees the signature that wallet policies may miss

On EVM an x402 payment is not a transaction. The client signs EIP-712 typed data (an EIP-3009 `TransferWithAuthorization`) and a facilitator submits it later. A wallet policy engine that evaluates transactions, with per-period spend limits or recipient rules written for transfers, may never see that signature, so its limits do not apply to x402 spending. Check whether your wallet's policies cover typed-data signing before relying on them.

TollWarden scans the payment fields that go into the signature, and `guardSigner` evaluates the EIP-3009 and ERC-2612 typed data itself at signing time. Other typed data passes through by default, and `strictTypes: true` refuses anything it does not recognize.

## 4. Delivery history is bound to real scans

Whether a seller actually delivers is the one thing a buyer pays for, and a free-text report of it costs nothing to fake. A delivery outcome in TollWarden must present the `scan_id` and `payment_commitment` of a scan TollWarden performed, one outcome per scan, and a keyed scan's outcome can be filed only by the account that made it. Fabricating delivery history therefore means making real, scanned payments. The SDK payment wrappers report outcomes automatically (a paid 2xx is `delivered`, a paid 5xx or a second 402 is `not_delivered`).

Reputation lookups also publish the denominator. `scans_seen` and `report_coverage` sit beside the outcome counts, so a selectively reported record reads as low coverage instead of a complete one. See [`src/outcomes.ts`](src/outcomes.ts).

## 5. Signals other parties can feed never block

A trust score is gameable when its inputs are. TollWarden follows a rule from its security audit (finding H-2). Any signal derived from data that someone other than the paying account can supply may flag a payment and must never block it. Counterparty reports, delivery history, report coverage and anonymous scan history all fall under it. Reporter credibility can raise a flag's confidence but cannot turn it into a block. Blocks come from the payment you submit and the content you pass with it, or from the operator-curated badlist. The rule is stated in [`src/reputation.ts`](src/reputation.ts) and [`src/outcomes.ts`](src/outcomes.ts), and the test suite checks it.

The cost of the rule is that a seller with a bad record still gets a flag rather than a block. The benefit is that nobody can get a competitor's payments blocked by filing reports or seeding history.

## Limits

- **Advisory unless enforced.** A verdict stops a payment only if your code acts on it. `guardOutgoing` throws on a block, the framework packages' `guardedPayment` never calls your payment function on a block, and `guardSigner` makes it binding at the key.
- **In-process wrappers fall to a compromised process.** Code that can read the private key can sign with it directly. Keep the signer in a separate process, a KMS or hardware, and run the enforcer at that boundary.
- **Scans, not settlements.** TollWarden cannot know whether an authorization settled, which is why the duplicate-purchase check flags and never blocks.
- **Provenance is self-declared.** `context.origin` comes from the client, so an agent that lies about where a decision came from weakens the content checks. The caps, pinning and signer enforcement do not depend on it.
- **Pattern matching has gaps.** Injection tells and secret patterns catch known shapes. A secret in an unknown format, or wording the tell scoring misses, passes. Address provenance and the recipient allowlist hold regardless of wording.

TollWarden is non-custodial. It never touches keys, wallets or funds, and it wraps the wallet and facilitator stack the agent already uses. It is also a registered [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) agent (agentId 59586 on Base), with its registration file at `/.well-known/erc8004.json`.
