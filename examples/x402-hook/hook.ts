// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * TollWarden as an x402 client `onBeforePaymentCreation` hook.
 *
 * The x402 client runs this hook after it has selected a payment requirement
 * and before the scheme signs anything. The hook scans the selected
 * requirement with `context.phase: "pre_sign"` (there is no nonce yet) and
 * returns `{ abort: true, reason }` on a block, which makes the client throw
 * "Payment creation aborted: <reason>" so nothing is signed.
 *
 *   const client = new x402Client();
 *   registerExactEvmScheme(client, { signer });
 *   client.onBeforePaymentCreation(tollwardenHook({
 *     onFlag: "abort",
 *     onUnavailable: "abort",   // fail closed. "allow" fails open.
 *   }));
 *   const pay = wrapFetchWithPayment(fetch, client);
 *
 * Advisory and in-process. A compromised process skips any hook. For
 * enforcement at the wallet, wrap the signer with
 * TollWardenEnforcer.guardSigner (sdk/README.md).
 *
 * The scan goes over plain fetch rather than the tollwarden-x402-client SDK,
 * because the SDK does not forward `context.offer` yet.
 */
import type { BeforePaymentCreationHook, PaymentCreationContext } from "@x402/core/client";

type Requirement = PaymentCreationContext["selectedRequirements"];

export interface Check { id: string; verdict: "allow" | "flag" | "block"; severity: string; reason: string }
export interface Scan { scan_id: string; verdict: "allow" | "flag" | "block"; risk_score: number; checks: Check[] }

export interface HookOptions {
  /** TollWarden base URL. Default https://tollwarden.com */
  baseUrl?: string;
  /** Sent as x-api-key when set. */
  apiKey?: string;
  agentId?: string;
  /** The paying address, if known before signing. Scopes duplicate and velocity checks. */
  payer?: string;
  /** Where the decision to pay came from. Default "planning". */
  origin?: "planning" | "user_instruction" | "tool_result" | "fetched_content" | "unknown";
  /** What to do on a flag verdict. "abort" refuses to sign, "allow" signs anyway. */
  onFlag: "abort" | "allow";
  /**
   * What to do when TollWarden does not answer in time, answers non-200, or
   * cannot be reached. "abort" fails closed (no payment while the check is
   * down). "allow" fails open (payments continue unchecked). No default, so
   * the choice is written down where the hook is registered.
   */
  onUnavailable: "abort" | "allow";
  /** Hard timeout for the scan, in milliseconds. Default 2000. */
  timeoutMs?: number;
  /**
   * The price the agent expected, in USD, before it saw this 402. Usually the
   * catalogue or listing price it chose the resource from. Sent as
   * `expected_price_usd`. Leave it out rather than copying the 402's own amount,
   * which would compare the 402 with itself.
   */
  expectedPriceUsd?: number | ((ctx: PaymentCreationContext) => number | undefined);
  /**
   * The listing or offer the agent decided from, as JSON text or an object.
   * Sent as `context.offer`, so a live 402 whose pay_to, price, scheme,
   * network or asset drifted from it is flagged.
   */
  offer?: unknown | ((ctx: PaymentCreationContext) => unknown);
  /** Called with every completed scan, for logging. */
  onScan?: (scan: Scan, ctx: PaymentCreationContext) => void;
}

export interface Decision { allow: boolean; reason: string; scan?: Scan }

function resolve<T>(v: T | ((ctx: PaymentCreationContext) => T) | undefined, ctx: PaymentCreationContext): T | undefined {
  return typeof v === "function" ? (v as (c: PaymentCreationContext) => T)(ctx) : v;
}

function summarize(scan: Scan, verdict: "flag" | "block"): string {
  const hits = scan.checks.filter((c) => c.verdict === verdict).map((c) => `${c.id}: ${c.reason}`);
  return `TollWarden ${verdict} (scan ${scan.scan_id}). ${hits.join(" | ")}`;
}

/** Scan one requirement and turn the verdict into allow or refuse under the options. */
export async function decide(ctx: PaymentCreationContext, opts: HookOptions): Promise<Decision> {
  const req: Requirement = ctx.selectedRequirements;
  const offer = resolve(opts.offer, ctx);
  const expected = resolve(opts.expectedPriceUsd, ctx);
  const body = {
    agent_id: opts.agentId,
    payment: {
      scheme: req.scheme,
      network: req.network,
      asset: req.asset,
      amount: req.amount,
      pay_to: req.payTo,
      payer: opts.payer,
      resource_url: ctx.paymentRequired.resource?.url,
      description: ctx.paymentRequired.resource?.description,
    },
    expected_price_usd: expected,
    context: {
      origin: opts.origin ?? "planning",
      phase: "pre_sign",
      offer: offer === undefined ? undefined : typeof offer === "string" ? offer : JSON.stringify(offer),
    },
  };
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.apiKey) headers["x-api-key"] = opts.apiKey;

  let scan: Scan;
  try {
    const res = await fetch(`${opts.baseUrl ?? "https://tollwarden.com"}/v1/scan/outgoing`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(opts.timeoutMs ?? 2000),
    });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    scan = (await res.json()) as Scan;
  } catch (err) {
    const why = err instanceof Error && err.name === "TimeoutError" ? `no answer within ${opts.timeoutMs ?? 2000} ms` : err instanceof Error ? err.message : String(err);
    return opts.onUnavailable === "allow"
      ? { allow: true, reason: `TollWarden unavailable (${why}), failing open` }
      : { allow: false, reason: `TollWarden unavailable (${why}), failing closed` };
  }
  opts.onScan?.(scan, ctx);

  if (scan.verdict === "block") return { allow: false, reason: summarize(scan, "block"), scan };
  if (scan.verdict === "flag") {
    return opts.onFlag === "allow"
      ? { allow: true, reason: summarize(scan, "flag"), scan }
      : { allow: false, reason: summarize(scan, "flag"), scan };
  }
  return { allow: true, reason: `TollWarden allow (scan ${scan.scan_id})`, scan };
}

/** The hook. Register it with `client.onBeforePaymentCreation(...)`. */
export function tollwardenHook(opts: HookOptions): BeforePaymentCreationHook {
  return async (ctx) => {
    const d = await decide(ctx, opts);
    if (!d.allow) return { abort: true, reason: d.reason };
  };
}

/**
 * The same check in the `prePaymentCheck({ url, method, requirement }) =>
 * { allow, reason }` shape proposed in coinbase/agentkit#1550, which is
 * unmerged. The hook context carries no HTTP method, so this shape takes it
 * from the caller. The method is not sent to TollWarden.
 */
export function tollwardenPrePaymentCheck(opts: HookOptions) {
  return async ({ url, requirement }: { url: string; method: string; requirement: Requirement }): Promise<{ allow: boolean; reason?: string }> => {
    const ctx: PaymentCreationContext = {
      paymentRequired: { x402Version: 2, resource: { url, description: "", mimeType: "" }, accepts: [requirement] },
      selectedRequirements: requirement,
    };
    const d = await decide(ctx, opts);
    return d.allow ? { allow: true } : { allow: false, reason: d.reason };
  };
}
