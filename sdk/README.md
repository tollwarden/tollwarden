# @tollwarden/client

Official TypeScript/Node SDK for [TollWarden](https://tollwarden.com) — the payment security firewall for [x402](https://x402.org) micropayments. One call before your agent settles a payment; allow/flag/block comes back with machine-readable reasons.

Zero runtime dependencies. Node 18+.

```bash
npm install @tollwarden/client
```

## 30 seconds

```ts
import { TollWardenClient, TollWardenBlockedError } from "@tollwarden/client";

const tollwarden = new TollWardenClient({ agentId: "my-agent" }); // mints a free API key on first use (100 free scans)

try {
  await tollwarden.guardOutgoing(payment, { expectedPriceUsd: 0.01 });
  // verdict was allow (or flag) — safe to hand to your wallet
} catch (e) {
  if (e instanceof TollWardenBlockedError) {
    console.error("Payment blocked:", e.scan.checks); // machine-readable reasons
  } else throw e;
}
```

## The one-line diff: scan every payment by default

If you already follow the [official x402 buyer quickstart](https://docs.x402.org/getting-started/quickstart-for-buyers), you have a line like `wrapFetchWithPayment(fetch, x402Client)`. Wrap it:

```ts
import { TollWardenClient, wrapFetchWithTollWarden } from "@tollwarden/client";
import { wrapFetchWithPayment } from "@x402/fetch";

const tollwarden = new TollWardenClient({ agentId: "my-agent" });
const fetchWithPay = wrapFetchWithTollWarden(wrapFetchWithPayment(fetch, x402Client), tollwarden);
// use fetchWithPay exactly as before
```

Every x402 payment your agent makes is now scanned before it settles. Non-402 responses pass through untouched (zero overhead). On a 402, the payment is guarded as an outgoing payment (overpayment, address poisoning, velocity, injection provenance — anything you `observe()`d feeds the detector), the offer is scanned as an incoming request (URL risk, credential demands, asset verification, reputation), and only passing verdicts reach the paying fetch. A block throws `TollWardenBlockedError` **before any payment is signed**; unparseable 402 offers fail closed. Options: `strict` (refuse flags too), `scanOffer`, `expectedPriceUsd`, `onScan` telemetry, `baseFetch`, and `enforcer` — pass a `TollWardenEnforcer` and every passing verdict is registered as signing authority, so a `guardSigner()`-wrapped account inside the paying fetch signs only what was scanned (see [enforcement](#enforcement-a-wallet-that-refuses-unscanned-payments)).

## The important part: provenance tagging

TollWarden's strongest detector catches **payments triggered by prompt-injected content** — but it needs to know where your agent's decision came from. Tell it:

```ts
// After EVERY tool result / fetched page your agent reads:
tollwarden.observe(toolResultText, { sourceUrl: "https://api.example.com/page" });

// The next scan (within 5 min) is automatically tagged:
//   context.origin = "fetched_content" | "tool_result"
//   context.content = the observed text (truncated to 8 KB)
// If the pay-to address turns out to have COME FROM that content → block.

// When the decision is the agent's own plan or a human said so:
tollwarden.notePlanning();
tollwarden.noteUserInstruction();
```

Each observation is consumed by one scan; unrelated later scans aren't mislabeled.

## Verified verdicts (on by default)

Every scan response carries an Ed25519 attestation binding the verdict to the exact payment. The SDK:

1. pins the server's verdict key (fetched once from `/.well-known/tollwarden-verdict-key`, or supply `verdictKeyHex` to hard-pin),
2. verifies the signature **against the pinned key** — never the key embedded in the response,
3. recomputes the payment commitment `sha256(network|pay_to|asset|amount|nonce)` locally and rejects attestations issued for a *different* payment (replay defense),
4. enforces `expires_at`.

Any failure throws `AttestationError`. Wallet authors: `verifyAttestation(scan, payment, trustedKeyHex)` and `computePaymentCommitment(payment)` are exported standalone, so a wallet policy can require a fresh, payment-bound allow-verdict before signing — turning the firewall from advisory into enforceable.

## Enforcement: a wallet that refuses unscanned payments

Everything above is advisory — a compromised agent can skip the scan. The enforcement kit closes that gap at the signing layer:

```ts
import { TollWardenClient, TollWardenEnforcer } from "@tollwarden/client";
import { privateKeyToAccount } from "viem/accounts";

const tollwarden  = new TollWardenClient({ agentId: "my-agent" });
const enforcer = new TollWardenEnforcer({ trustedKeyHex: await tollwarden.verdictKey() });
const account  = enforcer.guardSigner(privateKeyToAccount(process.env.EVM_PRIVATE_KEY!));
// hand `account` to your x402 client exactly as before — it is a drop-in Proxy

const scan = await tollwarden.guardOutgoing(payment);  // throws on block
enforcer.approve(scan, payment);                    // registers the allow-verdict locally
// x402 pay-and-retry now succeeds. ANY other payment authorization the wallet
// is asked to sign — different recipient, amount, asset, chain, or nonce —
// throws TollWardenEnforcementError before the signature exists.
```

How the binding works: the wrapped signer intercepts EIP-712 payment authorizations (EIP-3009 `TransferWithAuthorization`/`ReceiveWithAuthorization` — the x402 "exact" scheme — plus ERC-2612 `Permit`; both viem's single-argument and ethers v6's `(domain, types, message)` call shapes), reconstructs the payment from the typed data itself, and recomputes the commitment `sha256(network|pay_to|asset|amount|nonce)`. Only a live approval for **exactly that commitment** lets the signature happen — so "scan payment A, sign payment B" fails structurally, not by convention.

**Pre-sign approvals.** In the default path you scan the 402 *offer*, and an offer has no nonce — the x402 client mints the EIP-3009 nonce when it signs. An approval registered from a nonce-less payment binds `(network, pay_to, asset, amount)` and admits exactly **one** authorization carrying those facts, whatever nonce it ends up with (single-use is what stops a second). An approval registered *with* a nonce still requires that exact nonce. The two compose in one line:

```ts
const enforcer    = new TollWardenEnforcer({ trustedKeyHex: await tollwarden.verdictKey() });
const account     = enforcer.guardSigner(privateKeyToAccount(process.env.EVM_PRIVATE_KEY!));
const fetchWithPay = wrapFetchWithTollWarden(wrapFetchWithPayment(fetch, x402ClientFor(account)), tollwarden, { enforcer });
// every 402: scanned → verdict registered → the guarded account signs that authorization and nothing else
```

Guarantees and options: approvals are verified against the **pinned** verdict key at `approve()` time (tampered/replayed/expired attestations throw), are **single-use** by default (`reusable: true` to opt out), expire with the attestation (tighten with `maxAgeMs`), gate on allow-only verdicts (`allowFlagged: true` to accept flags; `acceptOverrides: true` to accept human-approved `override:allow` verdicts from [step-up approvals](../README.md#human-in-the-loop-step-up-approvals) — opt-in because a self-webhooked agent could approve its own flags), and can be `revoke()`d. Unrecognized typed data passes through by default; `strictTypes: true` makes the signer deny-by-default. Enforcement is fully local and fail-closed — if TollWarden is unreachable, nothing new can be approved. For flags that pause for a human (`scan.approval` present), `client.waitForApproval(scan, { payment })` polls until the operator decides and returns the signed override.

**Local policy: allowlist + spend caps.** The verdict gate answers "was this exact payment scanned and allowed?" — local policy answers a different question: "is this payment inside the bounds I set, no matter what any scan said?" Configure it on the enforcer and it is checked against the typed data at signature time, entirely offline and independent of approvals:

```ts
const enforcer = new TollWardenEnforcer({
  trustedKeyHex: await tollwarden.verdictKey(),
  allowedRecipients: ["0xKnownMerchantA…", "0xKnownMerchantB…"], // hard allowlist (case-insensitive; [] = deny all)
  maxAmountAtomic: 1_000_000,   // per payment: 1 USDC (6 decimals)
  maxTotalAtomic: 10_000_000,   // cumulative across this enforcer's lifetime: 10 USDC
});
```

Even a payment carrying a valid allow-verdict is refused if it pays an unlisted recipient or exceeds a cap — so if everything upstream is confused or compromised, the wallet can still only move bounded amounts to known parties. Unparseable values under a cap are refused (fail-closed); `enforcer.totalAuthorizedAtomic()` reports the running total. Atomic units are only comparable within one asset (for x402 that's USDC); bound multi-asset flows with separate enforcers.

**Growing the allowlist.** The agent can never extend the list — that's the point (an injected agent's first move would be to add the attacker). New recipients are added out of band, by whoever owns the enforcer config. For a smoother path there's one opt-in escape hatch: `overrideAdmitsRecipient: true` (requires `acceptOverrides`) lets a human-approved `override:allow` from [step-up approvals](../README.md#human-in-the-loop-step-up-approvals) satisfy the allowlist for **exactly the payment it binds** — the human admits one commitment-bound payment, the list itself never changes, spend caps still apply, and a plain allow-verdict never admits. It inherits the `acceptOverrides` security note: only meaningful when the approval webhook receiver is out of the agent's reach.

**Delivery outcomes (automatic).** The payment-path wrapper also closes the loop after settlement: x402 delivery is synchronous, so it observes the paid response mechanically and reports the outcome — 2xx → `delivered`, 5xx or a second 402 → `not_delivered`, with status/bytes/latency evidence — bound to the scan it just performed (`scan_id` + `payment_commitment`, one outcome per scan, so delivery history can't be faked). Fire-and-forget: it never delays the response. Opt out with `reportOutcomes: false`; settling another way? call `client.reportOutcome(scan, outcome, evidence)` yourself. Sellers with low measured delivery rates get flagged on everyone's future scans.

Scope note: this guards the typed-data path x402 uses. If your signer also exposes raw `signTransaction`, gate that at your policy layer too.

## Paying for scans and plans (x402)

Your first 100 calls per key are free. Beyond that, construct the client with an x402 payment-capable fetch and everything—scans and plan purchases—pays for itself:

```ts
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const x402 = new x402Client();
registerExactEvmScheme(x402, { signer: privateKeyToAccount(process.env.EVM_PRIVATE_KEY) });

const tollwarden = new TollWardenClient({
  agentId: "my-agent",
  fetch: wrapFetchWithPayment(fetch, x402),
  autoRenew: true, // re-subscribe automatically near plan expiry (spends money — opt-in)
});

await tollwarden.getPlans();        // free catalog: Starter / Pro ($4.99/30d, $0.005/scan) / Scale ($19.99/30d, $0.002/scan)
await tollwarden.subscribe("pro");  // pays $4.99 over x402, upgrades this key for 30 days
```

Plans raise *your own* velocity/spend thresholds and cut per-scan price. Replay detection, merchant pinning, asset verification, and PII scanning are identical on every tier — no plan can relax them.

## Reputation

```ts
await tollwarden.report({ address: "0xbad…", category: "non_delivery", reason: "paid, no data" }); // always free
await tollwarden.reputation("0xsomeone…"); // report summary (paid / free-tier)
```

## API surface

`TollWardenClient` — `scanOutgoing`, `scanIncoming`, `guardOutgoing`, `guardIncoming`, `observe`, `notePlanning`, `noteUserInstruction`, `getPlans`, `subscribe`, `report`, `reputation`, `ensureApiKey`, `verdictKey`, plus `freeCallsRemaining` / `plan` state.
Payment path — `wrapFetchWithTollWarden`, `paymentFromOffer`.
Enforcement — `TollWardenEnforcer` (`approve`, `guardSigner`, `assertApproved`, `assertApprovedFor`, `revoke`, `clear`), `paymentFromTypedData`.
Standalone — `verifyAttestation`, `computePaymentCommitment`.
Errors — `TollWardenError` (`.status`, `.body`), `TollWardenBlockedError` (`.scan`), `AttestationError`, `TollWardenEnforcementError` (`.commitment`, `.primaryType`).

[BUSL 1.1](../LICENSE) (source-available; using this SDK against the hosted service is expressly permitted, including in commercial products). TollWarden is advisory and non-custodial: this SDK never touches your keys, wallet, or funds.
