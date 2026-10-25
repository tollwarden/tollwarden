# Double pay on retry, reproduced

An x402 buyer can pay twice for one purchase without any bug in its signing code. The seller settles the first payment and the response is lost (a gateway timeout after broadcast, a 5xx, a dropped connection). The agent retries, the seller answers with a fresh 402, and the reference client signs a second authorization with a new EIP-3009 nonce. Both authorizations are valid, so both can settle. A nonce-replay check admits the second one, because the nonces differ, and a per-payment spend cap admits it, because it is one small payment.

This example reproduces that with the real `@x402/fetch` and `@x402/evm` clients, and shows TollWarden flagging the second authorization as `replay.duplicate_purchase`. The question it was built to answer is in [x402#3438](https://github.com/x402-foundation/x402/issues/3438).

## What it does

1. A local seller answers `GET /report` with a 402 for $0.001 USDC on Base Sepolia.
2. The buyer, `wrapFetchWithPayment` from `@x402/fetch`, signs authorization 1 and sends it.
3. The seller verifies and settles it, then answers 502 with no `PAYMENT-RESPONSE`, so the buyer cannot tell the payment landed.
4. The agent retries the 5xx once, as most HTTP clients and agent frameworks do. The seller answers a fresh 402, and the client signs authorization 2 with a new nonce.
5. The seller settles authorization 2 and answers 200.

Each signed authorization is scanned by TollWarden (`POST /v1/scan/outgoing`, `context.phase` `post_sign`) from the client's `onAfterPaymentCreation` hook. The first scan allows. The second flags `replay.duplicate_purchase` at medium severity, because the same purchase (payer, network, pay_to, asset, amount and resource) was authorized under a different nonce within the last 60 seconds.

## Run it

Offline, the default. Nothing leaves the machine. The key is generated in memory and never printed, the facilitator is a local fake, and TollWarden is the dev server (`src/devserver.ts`) started as a child process with no data dir.

```bash
npm ci
node --experimental-strip-types examples/double-pay-repro/repro.ts
```

The fake facilitator applies the rules USDC's `transferWithAuthorization` applies on chain. The signature must recover to `from`, the time must fall inside `validAfter` and `validBefore`, and the `(authorizer, nonce)` pair must be unused. Nothing in those rules ties two authorizations to one purchase.

Expected ending.

```
One purchase. 2 authorizations signed, 2 settled.
replay.duplicate_purchase on the second scan, flagged.
```

The script exits 0 when it sees two settlements and the flag, and 1 otherwise.

### With the flag acted on

```bash
node --experimental-strip-types examples/double-pay-repro/repro.ts --guard
```

The hook throws when the second scan flags a duplicate, so the client never sends authorization 2. It was signed, and it stays valid until its `validBefore` (300 seconds here), but nobody holds it except this process. The run ends with one settlement.

### On Base Sepolia

`--sepolia` swaps the fake for a real facilitator, so both authorizations settle on chain. The seller and TollWarden still run locally.

1. Make a throwaway test wallet with `npm run gen:wallet` and fund it with Base Sepolia USDC from the [CDP faucet](https://portal.cdp.coinbase.com/products/faucet). The run spends $0.002 of test USDC. The facilitator pays the gas.
2. Run it with the key in the environment, never in a file.

```bash
EVM_PRIVATE_KEY=0xYOUR_TEST_KEY node --experimental-strip-types examples/double-pay-repro/repro.ts --sepolia
```

The output lists both settlement transaction hashes. Look them up on [Base Sepolia BaseScan](https://sepolia.basescan.org) to confirm two `TransferWithAuthorization` transfers for one purchase.

| Variable | Default | Meaning |
| --- | --- | --- |
| `EVM_PRIVATE_KEY` | none, required with `--sepolia` | Test wallet key, read at run time |
| `PAY_TO` | the payer's own address with `--sepolia` | Where the test USDC goes. Paying yourself keeps the balance, and still produces two transfers |
| `FACILITATOR_URL` | `https://x402.org/facilitator` (the `@x402/core` default) | Facilitator used for verify and settle |
| `TOLLWARDEN_URL` | a local dev server | Scan against another instance instead |
| `TOLLWARDEN_API_KEY` | none | Sent as `x-api-key` when set |

## Limits

- **TollWarden sees scans, not settlements.** It cannot know whether authorization 1 settled, so it flags the second authorization rather than blocking it. The same bytes are also what a deliberate second purchase looks like. Purchase intent is not in the payment, which is why `context.repeat_of` or a delivered outcome on the earlier scan clears the flag.
- **It only sees what is scanned.** The check matches the latest scan of the same purchase under the same scope (the API key's account, or the declared `agent_id` and payer) within 60 seconds (`DUPLICATE_PURCHASE_WINDOW_SECONDS`, up to 3600). A retry after the window, or an authorization the client never scanned, is not flagged.
- **The hook is advisory and in-process.** `--guard` shows where to act on the flag. A compromised process skips any hook. For enforcement at the wallet, wrap the signer with `TollWardenEnforcer.guardSigner` ([`sdk/README.md`](../../sdk/README.md#enforcement-a-wallet-that-refuses-unscanned-payments)), which refuses to sign without a fresh allow verdict for that exact payment.
- **The seller half is out of scope.** Answering a fresh 402 for a payment the seller already settled is a seller defect in its own right ([x402#3437](https://github.com/x402-foundation/x402/issues/3437)). This example only covers what the buyer can see.
- **Tested here offline only.** The `--sepolia` path was run against a local mock facilitator, not the public one. Whether a given facilitator accepts a transfer to the payer's own address is unverified, so set `PAY_TO` to a second address you control if it refuses.
- Tested with `@x402/fetch` 2.18.0 and `@x402/evm` 2.18.0, as pinned in this repo's lockfile. Newer clients may change the retry path, and the buyer-side retry here is the agent's own, not the wrapper's.
