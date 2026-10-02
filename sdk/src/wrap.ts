// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * The one-line diff: TollWarden in the default x402 payment path.
 *
 * The official x402 buyer quickstart is:
 *
 *     const fetchWithPay = wrapFetchWithPayment(fetch, x402Client);
 *
 * Change it to:
 *
 *     const fetchWithPay = wrapFetchWithTollWarden(wrapFetchWithPayment(fetch, x402Client), tollwarden);
 *
 * and every x402 payment the agent makes is scanned before it settles:
 *
 *  1. The request is first sent with a NON-paying fetch (the probe).
 *  2. On a 402, the payment the agent is about to authorize is guarded as an
 *     OUTGOING payment — overpayment, poisoning, velocity, injection
 *     provenance (anything the client `observe()`d feeds the injection
 *     detector here).
 *  3. The offer (the server's payment requirements) is scanned as an INCOMING
 *     payment request — resource-URL risk, credential demands, asset
 *     verification, counterparty reputation.
 *  4. Only on passing verdicts is the request re-sent through the
 *     payment-capable fetch, which performs the actual x402 pay-and-retry.
 *
 * A block verdict throws TollWardenBlockedError BEFORE any payment is signed —
 * the paying fetch is never invoked. Unparseable 402 offers fail CLOSED.
 * Non-402 responses pass through untouched with zero added latency.
 *
 * Both scans send `context.phase: "pre_sign"`: they run before signing, and
 * an offer has no nonce. Without it the server flags replay.no_nonce on every
 * offer, and an allow-only enforcer refuses every payment.
 *
 * The offer scan declares the same `context.origin` the outgoing scan sent
 * (its `declared_origin`), without the content. Both scans describe one
 * decision, but the outgoing scan consumes the client's provenance, so the
 * offer scan used to go out as "unknown" and flag injection.unknown_origin.
 * `strict` then refused every payment, however the decision was tagged. The
 * content is analysed once, on the outgoing scan. With `strict`, a decision
 * prompted by observe()d content is still refused, because the offer scan
 * flags injection.untrusted_origin and cannot re-check content it was not sent.
 *
 * With `enforcer` set, the wrapper also registers each passing outgoing
 * verdict with a TollWardenEnforcer, so a signer wrapped by
 * `enforcer.guardSigner()` inside the paying fetch will sign exactly the
 * authorization that was scanned — the offer has no nonce yet, and the
 * enforcer matches the later nonce-bearing authorization to the pre-sign
 * approval (see enforce.ts). This is the composition that makes the default
 * path enforced rather than advisory:
 *
 *     const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
 *     const account  = enforcer.guardSigner(privateKeyToAccount(KEY));
 *     const pay      = wrapFetchWithPayment(fetch, x402ClientFor(account));
 *     const fetchWithPay = wrapFetchWithTollWarden(pay, tollwarden, { enforcer });
 *
 * An allow-only enforcer approves only an allow verdict, so tag where the
 * decision came from before the request (tollwarden.notePlanning(),
 * noteUserInstruction() or observe()). An untagged scan flags
 * injection.unknown_origin, and that flag is refused before anything is signed.
 */
import { TollWardenBlockedError, TollWardenError, type TollWardenClient, type PaymentDetails, type ScanResponse } from "./index.ts";
import type { TollWardenEnforcer } from "./enforce.ts";

export interface WrapFetchOptions {
  /** Register every passing outgoing verdict as signing authority with this
   * enforcer (see the module comment). A verdict the enforcer refuses to
   * approve — a flag without `allowFlagged`, for instance — throws
   * TollWardenEnforcementError here, before the paying fetch runs. */
  enforcer?: Pick<TollWardenEnforcer, "approve">;
  /** Non-paying fetch used for the initial probe. Default: globalThis.fetch. */
  baseFetch?: typeof fetch;
  /** Also throw on "flag" verdicts (default: only "block"). */
  strict?: boolean;
  /** Scan the 402 offer as an incoming payment request first. Default: true. */
  scanOffer?: boolean;
  /** Expected price in USD, or a function deriving it from the parsed offer. */
  expectedPriceUsd?: number | ((offer: PaymentDetails) => number | undefined);
  /** Observe scans as they happen (telemetry/logging). */
  onScan?: (phase: "incoming" | "outgoing", scan: ScanResponse) => void;
  /** Automatically report the delivery outcome of every paid request (default
   * true): 2xx → delivered; 5xx/4xx/second-402 after payment → not_delivered,
   * with mechanical evidence. Fire-and-forget — never delays the response.
   * The outcome is commitment-bound to the outgoing scan, feeding measured
   * delivery rates for every agent's future scans of this counterparty. */
  reportOutcomes?: boolean;
}

/**
 * x402 v1 EVM network names and the CAIP-2 ids for the same chains. The same
 * table as the server's X402_V1_NETWORKS (src/detectors/asset.ts), copied from
 * EVM_NETWORK_CHAIN_ID_MAP in @x402/evm, the v1 client's own name to chain-id
 * table. Python's payment_from_offer carries the identical table.
 */
const X402_V1_NETWORKS: Readonly<Record<string, string>> = {
  ethereum: "eip155:1",
  sepolia: "eip155:11155111",
  abstract: "eip155:2741",
  "abstract-testnet": "eip155:11124",
  "base-sepolia": "eip155:84532",
  base: "eip155:8453",
  "avalanche-fuji": "eip155:43113",
  avalanche: "eip155:43114",
  iotex: "eip155:4689",
  sei: "eip155:1329",
  "sei-testnet": "eip155:1328",
  polygon: "eip155:137",
  "polygon-amoy": "eip155:80002",
  peaq: "eip155:3338",
  story: "eip155:1514",
  educhain: "eip155:41923",
  "skale-base-sepolia": "eip155:324705682",
  megaeth: "eip155:4326",
  monad: "eip155:143",
  stable: "eip155:988",
  "stable-testnet": "eip155:2201",
};

/**
 * Defensive mapping from an x402 402 body's requirements entry to payment fields.
 *
 * `network` is emitted as the network that will be SIGNED. A v1 client signs
 * EIP-3009 for the chainId its own table gives a v1 name (exact match), and
 * guardSigner recomputes the commitment over `eip155:<chainId>`, so a v1 name
 * becomes that CAIP-2 id here. The scanned payment, the enforcer's approval
 * and the signed authorization then commit to the same network. Any other
 * string passes through unchanged.
 *
 * `extra.decimals` is the SELLER's claim about its own token. It is forwarded
 * only as an integer in 0..36 (the range the server reads) so the server can
 * flag a declaration it refuses; the server never lets it shrink a payment
 * under a USD cap. Python's payment_from_offer forwards and drops exactly the
 * same values.
 */
export function paymentFromOffer(entry: Record<string, unknown>, requestUrl: string): PaymentDetails {
  const s = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);
  const amount = s(entry.maxAmountRequired) ?? s(entry.amount) ?? (typeof entry.maxAmountRequired === "number" ? String(entry.maxAmountRequired) : undefined);
  const extra = (typeof entry.extra === "object" && entry.extra !== null ? entry.extra : {}) as Record<string, unknown>;
  const decimals = extra.decimals;
  const network = s(entry.network);
  return {
    scheme: s(entry.scheme),
    network: network !== undefined && Object.hasOwn(X402_V1_NETWORKS, network) ? X402_V1_NETWORKS[network] : network,
    asset: s(entry.asset),
    amount,
    asset_decimals: typeof decimals === "number" && Number.isInteger(decimals) && decimals >= 0 && decimals <= 36 ? decimals : undefined,
    pay_to: s(entry.payTo) ?? s(entry.pay_to),
    resource_url: s(entry.resource) ?? requestUrl,
    description: s(entry.description),
  };
}

/**
 * Wrap an x402 payment-capable fetch so every payment is scanned first.
 *
 * @param paymentFetch  the paying fetch (e.g. the return value of
 *                      wrapFetchWithPayment from @x402/fetch)
 * @param tollwarden       a TollWardenClient (its observe()/notePlanning() state
 *                      feeds provenance into the outgoing scan)
 */
export function wrapFetchWithTollWarden(
  paymentFetch: typeof fetch,
  tollwarden: TollWardenClient,
  opts: WrapFetchOptions = {},
): typeof fetch {
  const baseFetch = opts.baseFetch ?? fetch;
  const scanOffer = opts.scanOffer ?? true;

  return async function tollwardenGuardedFetch(input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]): Promise<Response> {
    const probe = await baseFetch(input, init);
    if (probe.status !== 402) return probe; // free / already-authorized: zero overhead

    // Parse the offer. An unparseable 402 fails CLOSED: we will not hand an
    // offer we cannot inspect to a fetch that pays automatically.
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    let offer: PaymentDetails;
    try {
      const body = (await probe.clone().json()) as { accepts?: Array<Record<string, unknown>> };
      const entry = Array.isArray(body?.accepts) ? body.accepts[0] : undefined;
      if (!entry || typeof entry !== "object") throw new Error("no accepts[] in 402 body");
      offer = paymentFromOffer(entry, url);
    } catch (e) {
      throw new TollWardenError(
        `refusing to auto-pay an unparseable 402 offer from ${url} (${(e as Error).message}). ` +
          "Fail-closed: pass the request to your payment client manually if this endpoint is trusted.",
        402,
      );
    }

    const expected =
      typeof opts.expectedPriceUsd === "function" ? opts.expectedPriceUsd(offer) : opts.expectedPriceUsd;

    // 1) The payment we are about to authorize, as an OUTGOING payment.
    // This runs first because scans consume the client's provenance
    // observation — it must feed the outgoing (injection-provenance) scan,
    // not be swallowed by the offer scan. `phase` rides alongside that
    // provenance (see buildContext), it does not replace it.
    const outgoing = await tollwarden.scanOutgoing(offer, { expectedPriceUsd: expected, phase: "pre_sign" });
    opts.onScan?.("outgoing", outgoing);
    if (outgoing.verdict === "block" || (opts.strict && outgoing.verdict === "flag")) {
      throw new TollWardenBlockedError(outgoing);
    }

    // 2) The 402 offer itself, as an INCOMING payment request (URL risk,
    // credential demands, asset verification, reputation). It declares the
    // origin the outgoing scan sent, without the content (see the module
    // comment).
    if (scanOffer) {
      const declared = outgoing.declared_origin;
      const incoming = await tollwarden.scanIncoming(offer, {
        expectedPriceUsd: expected,
        phase: "pre_sign",
        ...(declared !== undefined ? { context: { origin: declared } } : {}),
      });
      opts.onScan?.("incoming", incoming);
      if (incoming.verdict === "block" || (opts.strict && incoming.verdict === "flag")) {
        throw new TollWardenBlockedError(incoming);
      }
    }

    // 3) Verdicts passed — hand signing authority to the enforcer (if any),
    //    then let the payment-capable fetch do the x402 dance. Registered
    //    only now, after BOTH scans, so an offer the incoming scan refused
    //    never leaves an approval behind.
    opts.enforcer?.approve(outgoing, offer);
    const started = Date.now();
    const paid = await paymentFetch(input, init);

    // 4) Delivery-outcome capture: x402 delivery is synchronous — the resource
    // arrives in this very response — so "did they ship?" is mechanically
    // observable right here. Reported async; a reporting failure never
    // affects the response. Quality judgment stays with report(): we only
    // auto-judge what is mechanical.
    if ((opts.reportOutcomes ?? true) && tollwarden.reportOutcome) {
      const contentLength = Number(paid.headers.get("content-length"));
      const outcome: "delivered" | "not_delivered" =
        paid.status >= 200 && paid.status < 300 ? "delivered" : "not_delivered"; // incl. a SECOND 402 after paying
      void tollwarden
        .reportOutcome(outgoing, outcome, {
          status: paid.status,
          contentType: paid.headers.get("content-type") ?? undefined,
          bytes: Number.isFinite(contentLength) ? contentLength : undefined,
          latencyMs: Date.now() - started,
        })
        .catch(() => undefined);
    }
    return paid;
  } as typeof fetch;
}
