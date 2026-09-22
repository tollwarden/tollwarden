# tollwarden (Python)

Official Python SDK for [TollWarden](https://tollwarden.com) — the payment security firewall for [x402](https://x402.org) micropayments. One call before your agent settles a payment; allow/flag/block comes back with machine-readable reasons.

Python 3.9+. Single dependency (`cryptography`, for Ed25519 attestation verification).

```bash
pip install tollwarden
```

## 30 seconds

```python
from tollwarden import TollWardenClient, TollWardenBlockedError

tollwarden = TollWardenClient(agent_id="my-agent")  # mints a free API key on first use (100 free scans)

try:
    tollwarden.guard_outgoing(payment, expected_price_usd=0.01)
    # verdict was allow (or flag) — safe to hand to your wallet
except TollWardenBlockedError as e:
    print("Payment blocked:", e.scan["checks"])  # machine-readable reasons
```

## The one-line diff: scan every payment by default

Wrap your x402 payment-capable transport and every payment is scanned before it settles:

```python
from tollwarden import TollWardenClient, wrap_transport_with_tollwarden

tollwarden = TollWardenClient(agent_id="my-agent")
guarded = wrap_transport_with_tollwarden(my_x402_transport, tollwarden)
# use `guarded` anywhere a transport goes
```

Non-402 responses pass through untouched (zero overhead). On a 402, the payment is guarded as an outgoing payment (overpayment, address poisoning, velocity, injection provenance — anything you `observe()`d feeds the detector), the offer is scanned as an incoming request (URL risk, credential demands, asset verification, reputation), and only passing verdicts reach the paying transport. A block raises `TollWardenBlockedError` **before any payment is signed**; unparseable 402 offers fail closed. Options: `strict`, `scan_offer`, `expected_price_usd`, `on_scan` telemetry, `base_transport`, and `enforcer` — pass a `TollWardenEnforcer` and every passing verdict is registered as signing authority, so a `guard_signer()`-wrapped account inside the paying transport signs only what was scanned (see enforcement below).

## The important part: provenance tagging

TollWarden's strongest detector catches **payments triggered by prompt-injected content** — but it needs to know where your agent's decision came from. Tell it:

```python
# After EVERY tool result / fetched page your agent reads:
tollwarden.observe(tool_result_text, source_url="https://api.example.com/page")

# The next scan (within 5 min) is automatically tagged:
#   context.origin = "fetched_content" | "tool_result"
#   context.content = the observed text (truncated to 8 KB)
# If the pay-to address turns out to have COME FROM that content -> block.

# When the decision is the agent's own plan, or a human said so:
tollwarden.note_planning()
tollwarden.note_user_instruction()
```

Each observation is consumed by one scan; unrelated later scans aren't mislabeled. LangChain/CrewAI users: call `observe()` in your tool-output callback and `guard_outgoing()` in your payment tool — two lines total.

## Verified verdicts (on by default)

Every scan response carries an Ed25519 attestation binding the verdict to the exact payment. The SDK pins the server's verdict key (fetched once, or pass `verdict_key_hex` to hard-pin), verifies the signature **against the pinned key**, recomputes the payment commitment `sha256(network|pay_to|asset|amount|nonce)` locally (rejecting attestations issued for a *different* payment — replay defense), and enforces expiry. Any failure raises `AttestationError`.

The verifier is cross-validated in CI against attestations signed by the production Node signer, so Python and TypeScript agree byte-for-byte.

Wallet authors: `verify_attestation(scan, payment, trusted_key_hex)` and `compute_payment_commitment(payment)` are importable standalone.

## Enforcement: a wallet that refuses unscanned payments

Everything above is advisory — a compromised agent can skip the scan. The enforcement kit closes that gap at the signing layer:

```python
from tollwarden import TollWardenClient, TollWardenEnforcer
from eth_account import Account

tollwarden  = TollWardenClient(agent_id="my-agent")
enforcer = TollWardenEnforcer(trusted_key_hex=tollwarden.verdict_key())
account  = enforcer.guard_signer(Account.from_key(PRIVATE_KEY))
# hand `account` to your x402 client exactly as before — it is a drop-in proxy

scan = tollwarden.guard_outgoing(payment)  # raises on block
enforcer.approve(scan, payment)         # registers the allow-verdict locally
# x402 pay-and-retry now succeeds. ANY other payment authorization the wallet
# is asked to sign — different recipient, amount, asset, chain, or nonce —
# raises TollWardenEnforcementError before the signature exists.
```

How the binding works: the wrapped signer intercepts EIP-712 payment authorizations (EIP-3009 `TransferWithAuthorization`/`ReceiveWithAuthorization` — the x402 "exact" scheme — plus ERC-2612 `Permit`; eth-account's positional, keyword, and `full_message=` call shapes are all recognized), reconstructs the payment from the typed data itself, and recomputes the commitment `sha256(network|pay_to|asset|amount|nonce)`. Only a live approval for **exactly that commitment** lets the signature happen — so "scan payment A, sign payment B" fails structurally, not by convention.

**Pre-sign approvals.** In the default path you scan the 402 *offer*, and an offer has no nonce — the x402 client mints the EIP-3009 nonce when it signs. An approval registered from a nonce-less payment binds `(network, pay_to, asset, amount)` and admits exactly **one** authorization carrying those facts, whatever nonce it ends up with (single-use is what stops a second). An approval registered *with* a nonce still requires that exact nonce. The two compose in one line:

```python
enforcer = TollWardenEnforcer(trusted_key_hex=tollwarden.verdict_key())
account  = enforcer.guard_signer(Account.from_key(PRIVATE_KEY))
guarded  = wrap_transport_with_tollwarden(paying_transport_for(account), tollwarden, enforcer=enforcer)
# every 402: scanned → verdict registered → the guarded account signs that authorization and nothing else
```

Guarantees and options: approvals are verified against the **pinned** verdict key at `approve()` time (tampered/replayed/expired attestations raise), are **single-use** by default (`reusable=True` to opt out), expire with the attestation (tighten with `max_age_s`), gate on allow-only verdicts (`allow_flagged=True` to accept flags; `accept_overrides=True` to accept human-approved `override:allow` verdicts from step-up approvals — opt-in because a self-webhooked agent could approve its own flags), and can be `revoke()`d. Unrecognized typed data passes through by default; `strict_types=True` makes the signer deny-by-default. Enforcement is fully local and fail-closed — if TollWarden is unreachable, nothing new can be approved. For flags that pause for a human (`scan["approval"]` present), `client.wait_for_approval(scan, payment=payment)` polls until the operator decides and returns the signed override.

**Local policy: allowlist + spend caps.** The verdict gate answers "was this exact payment scanned and allowed?" — local policy answers a different question: "is this payment inside the bounds I set, no matter what any scan said?" Configure it on the enforcer and it is checked against the typed data at signature time, entirely offline and independent of approvals:

```python
enforcer = TollWardenEnforcer(
    trusted_key_hex=tollwarden.verdict_key(),
    allowed_recipients=["0xKnownMerchantA…", "0xKnownMerchantB…"],  # hard allowlist (case-insensitive; [] = deny all)
    max_amount_atomic=1_000_000,   # per payment: 1 USDC (6 decimals)
    max_total_atomic=10_000_000,   # cumulative across this enforcer's lifetime: 10 USDC
)
```

Even a payment carrying a valid allow-verdict is refused if it pays an unlisted recipient or exceeds a cap — so if everything upstream is confused or compromised, the wallet can still only move bounded amounts to known parties. Unparseable values under a cap are refused (fail-closed); `enforcer.total_authorized_atomic` reports the running total. Atomic units are only comparable within one asset (for x402 that's USDC); bound multi-asset flows with separate enforcers.

**Growing the allowlist.** The agent can never extend the list — that's the point (an injected agent's first move would be to add the attacker). New recipients are added out of band, by whoever owns the enforcer config. For a smoother path there's one opt-in escape hatch: `override_admits_recipient=True` (requires `accept_overrides`) lets a human-approved `override:allow` from step-up approvals satisfy the allowlist for **exactly the payment it binds** — the human admits one commitment-bound payment, the list itself never changes, spend caps still apply, and a plain allow-verdict never admits. It inherits the `accept_overrides` security note: only meaningful when the approval webhook receiver is out of the agent's reach.

**Delivery outcomes (automatic).** The payment-path wrapper also closes the loop after settlement: x402 delivery is synchronous, so it observes the paid response mechanically and reports the outcome — 2xx → `delivered`, 5xx or a second 402 → `not_delivered`, with status/bytes/latency evidence — bound to the scan it just performed (`scan_id` + `payment_commitment`, one outcome per scan, so delivery history can't be faked). Reported on a daemon thread: it never delays the response. Opt out with `report_outcomes=False`; settling another way? call `client.report_outcome(scan, outcome, ...)` yourself. Sellers with low measured delivery rates get flagged on everyone's future scans.

The gate is cross-validated in CI: an attestation signed by the production Node signer authorizes a signature through the Python enforcer end to end, so both SDKs enforce identical semantics.

Scope note: this guards the typed-data path x402 uses. If your signer also exposes raw `sign_transaction`, gate that at your policy layer too.

## Paying for scans and plans (x402)

Your first 100 calls per key are free. Beyond that, pass a payment-capable `transport` — any callable `(method, url, headers, body_bytes) -> (status, headers, body_bytes)` that settles x402 challenges (e.g. wrapping an x402 Python client):

```python
tollwarden = TollWardenClient(agent_id="my-agent", transport=my_x402_transport, auto_renew=True)

tollwarden.get_plans()        # free catalog: Starter / Pro ($4.99/30d, $0.005/scan) / Scale ($19.99/30d, $0.002/scan)
tollwarden.subscribe("pro")   # pays $4.99 over x402, upgrades this key for 30 days
```

Plans raise *your own* velocity/spend thresholds and cut per-scan price. Replay detection, merchant pinning, asset verification, and PII scanning are identical on every tier — no plan can relax them.

## Reputation

```python
tollwarden.report("0xbad...", "non_delivery", "paid, no data")  # always free
tollwarden.reputation("0xsomeone...")                           # report summary (paid / free-tier)
```

## API surface

`TollWardenClient` — `scan_outgoing`, `scan_incoming`, `guard_outgoing`, `guard_incoming`, `observe`, `note_planning`, `note_user_instruction`, `wait_for_approval`, `configure_approvals`, `report_outcome`, `get_plans`, `subscribe`, `report`, `reputation`, `ensure_api_key`, `verdict_key`, plus `free_calls_remaining` / `plan` state.
Payment path — `wrap_transport_with_tollwarden`, `payment_from_offer`.
Enforcement — `TollWardenEnforcer` (`approve`, `guard_signer`, `assert_approved`, `assert_approved_for`, `revoke`, `clear`), `payment_from_typed_data`.
Standalone — `verify_attestation`, `compute_payment_commitment`.
Errors — `TollWardenError` (`.status`, `.body`), `TollWardenBlockedError` (`.scan`), `AttestationError`, `TollWardenEnforcementError` (`.commitment`, `.primary_type`).

[BUSL 1.1](../LICENSE) (source-available; using this SDK against the hosted service is expressly permitted, including in commercial products). TollWarden is advisory and non-custodial: this SDK never touches your keys, wallet, or funds.
