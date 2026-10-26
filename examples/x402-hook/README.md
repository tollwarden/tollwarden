# TollWarden as an x402 `onBeforePaymentCreation` hook

The official x402 client signs whatever its selected requirement asks for, as long as a registered scheme can sign it. The client gives one place to stop that before a signature exists, the `onBeforePaymentCreation` hook. It runs after the client has picked a requirement from the 402 and before the scheme signs. A hook that returns `{ abort: true, reason }` makes the client throw `Payment creation aborted: <reason>`, and nothing is signed.

`hook.ts` registers a TollWarden scan there. It scans the selected requirement with `context.phase: "pre_sign"` (no nonce exists yet) and aborts on a block. What happens on a flag, and what happens when TollWarden does not answer, are both parameters you set.

```ts
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { tollwardenHook } from "./hook.ts";

const client = new x402Client();
registerExactEvmScheme(client, { signer });
client.onBeforePaymentCreation(
  tollwardenHook({
    apiKey: process.env.TOLLWARDEN_API_KEY,
    payer: signer.address,
    onFlag: "abort",        // or "allow" to sign flagged payments anyway
    onUnavailable: "abort", // fail closed. "allow" fails open
    timeoutMs: 2000,
    expectedPriceUsd: 0.001, // the listing price the agent chose from
    offer: listingEntry,     // that listing, sent as context.offer
  }),
);
const pay = wrapFetchWithPayment(fetch, client);
```

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `onFlag` | none, required | `"abort"` refuses to sign a flagged payment, `"allow"` signs it |
| `onUnavailable` | none, required | What to do on a timeout, a non-200 answer or a network error. `"abort"` fails closed, `"allow"` fails open |
| `timeoutMs` | 2000 | Hard timeout on the scan request |
| `expectedPriceUsd` | not sent | Number or function of the hook context. Sent as `expected_price_usd` |
| `offer` | not sent | The listing or offer the agent decided from, JSON text or an object. Sent as `context.offer` |
| `baseUrl` | `https://tollwarden.com` | TollWarden instance |
| `apiKey` | not sent | Sent as `x-api-key` |
| `agentId`, `payer` | not sent | Scope duplicate and velocity checks |
| `origin` | `"planning"` | `context.origin`, where the decision to pay came from |
| `onScan` | none | Called with every completed scan, for logging |

Neither failure mode is a default, so the choice is written down at the call site. Failing closed stops payments while the check is down. Failing open keeps the agent working with no check at all.

Set `expectedPriceUsd` and `offer` from what the agent knew before the 402 arrived, usually the catalogue entry it picked the resource from. Copying them from the 402 itself compares the 402 with itself and catches nothing. With both set and the default thresholds, a live 402 that asks more than the listing is flagged (`overpay.flag_multiple` from 3 times, `drift.price` from 2 times), blocked from 10 times (`overpay.block_multiple`), and a 402 whose `payTo` differs from the listing is flagged as `drift.pay_to`.

### The `prePaymentCheck` shape

`tollwardenPrePaymentCheck(options)` returns the same check as `({ url, method, requirement }) => Promise<{ allow, reason }>`, the shape proposed for the AgentKit x402 provider in [coinbase/agentkit#1550](https://github.com/coinbase/agentkit/pull/1550). That PR is unmerged, so the shape may change. The hook context has no HTTP method, and the method is not sent to TollWarden.

## Run the demo

Offline. A local seller answers 402s whose terms each scenario sets, TollWarden is the dev server (`src/devserver.ts`) started as a child process with no data dir, and the key is generated in memory and never printed. The seller never settles, so the demo only measures whether the client signed.

```bash
npm ci
node --experimental-strip-types examples/x402-hook/demo.ts
```

| # | Scenario | Result |
| --- | --- | --- |
| 1 | Live 402 matches the $0.001 listing | Signed |
| 2 | Price rose to $0.005 on retry, `onFlag: "abort"` | Not signed, `overpay.flag_multiple` and `drift.price` |
| 3 | Same, `onFlag: "allow"` | Signed |
| 4 | Price rose to $2.00, `onFlag: "allow"` | Not signed, `overpay.block_multiple` |
| 5 | `payTo` differs from the listing | Not signed, `drift.pay_to` |
| 6 | TollWarden accepts the connection and never answers, `onUnavailable: "abort"` | Not signed after 300 ms |
| 7 | Same, `onUnavailable: "allow"` | Signed |

It then calls `tollwardenPrePaymentCheck` directly for a $2.00 requirement and expects `allow: false`. The script exits 0 when all eight end as expected. Set `TOLLWARDEN_URL` (and `TOLLWARDEN_API_KEY`) to run it against another instance.

## Limits

- **The hook is advisory and in-process.** It stops the client from signing, and nothing else. A compromised process, or code that signs without this client, skips it. For enforcement at the wallet, wrap the signer with `TollWardenEnforcer.guardSigner` ([`sdk/README.md`](../../sdk/README.md#enforcement-a-wallet-that-refuses-unscanned-payments)), which refuses to sign without a fresh allow verdict for that exact payment.
- **It sees the requirement, not the signed payment.** A pre-sign scan has no nonce, so nonce replay cannot be checked here. Scan the signed payload as well (`onAfterPaymentCreation`, `context.phase: "post_sign"`) for that. [`examples/double-pay-repro`](../double-pay-repro) shows the post-sign half.
- **A repeat purchase flags.** Two pre-sign scans of the same purchase in the same scope within 60 seconds flag `replay.duplicate_purchase` at low severity, because the first may have been signed. With `onFlag: "abort"` a deliberate second purchase is refused. The hook does not send `context.repeat_of`, so an agent that buys the same resource again on purpose needs to pass the earlier `scan_id` there (or report the first purchase as delivered).
- **A listing is also seller-supplied.** An `offer` from a catalogue makes an attacker on the 402 path change two records instead of one. It does not protect against a seller who lies in both. Listings also go stale honestly, which is why price and payee drift flag rather than block.
- **Latency is on the payment path.** Every payment waits for the scan, up to `timeoutMs`.
- **Plain fetch, not the SDK.** The scan is a direct `POST /v1/scan/outgoing` because the `tollwarden-x402-client` TypeScript SDK does not forward `context.offer` yet.
- Tested with `@x402/core`, `@x402/fetch` and `@x402/evm` 2.18.0, as pinned in this repo's lockfile. The hook signature and abort shape were read from `@x402/core` 2.18.0 (`x402Client.createPaymentPayload`).
