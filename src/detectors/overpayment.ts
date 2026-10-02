// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Overpayment detection: compares the actual payment amount against the
 * expected price and an absolute ceiling.
 *
 * Value resolution is the trust boundary every USD-denominated check stands
 * on (overpayment, hourly spend cap, first-contact cap, the deep-tier value
 * gate), so it is deliberately conservative about client input:
 *
 *   - `amount` (atomic units) is the number the wallet actually signs. When
 *     the asset is canonical USDC on a known network, or when no asset is
 *     declared, decimals are taken from the server's own table (6), and a
 *     client-supplied `asset_decimals` that disagrees is IGNORED and flagged.
 *   - For a declared asset TollWarden does not know (any asset on a network
 *     missing from CANONICAL_USDC, x402 v1 names such as "base" included),
 *     `asset_decimals` cannot be verified, and in the SDK path it is copied
 *     straight from the seller's 402 offer. So it may RAISE the value but
 *     never lower it below the 6-decimal reading, i.e. decimals =
 *     min(declared, 6). A declaration above 6 is ignored and flagged. A
 *     genuine 18-decimal token is then over-valued by 10^12 and will usually
 *     hit the absolute ceiling. That is the intended failure direction; the
 *     alternative let a seller declare 18 for a 6-decimal token and shrink a
 *     payment under every USD cap (audit 2026-10-02).
 *   - `amount_usd` is used only when no atomic amount is present. It is
 *     self-reported; the wallet-side enforcer's atomic caps are the backstop
 *     for callers who cannot supply the atomic amount.
 */
import type { CheckResult, PaymentDetails } from "../types.ts";
import { knownAssetDecimals } from "./asset.ts";

export const DEFAULT_DECIMALS = 6; // USDC, the x402 default asset

export type ValueSource =
  | "atomic_known"     // amount + decimals from the server's asset table
  | "atomic_default"   // amount, no asset declared → USDC decimals assumed
  | "atomic_declared"  // amount, asset unknown to the server → min(declared, 6)
  | "self_reported"    // amount_usd only
  | "none";

/**
 * A declared decimals count worth reading, as an integer in 0..36 given as a
 * number or (in offers) a digit string. Anything else counts as undeclared.
 */
export function parseDeclaredDecimals(v: unknown): number | undefined {
  const n = typeof v === "number" ? v : typeof v === "string" && /^\d{1,2}$/.test(v.trim()) ? Number(v.trim()) : NaN;
  return Number.isInteger(n) && n >= 0 && n <= 36 ? n : undefined;
}

export interface ResolvedValue {
  usd: number | null;
  source: ValueSource;
  /** Decimals actually used to convert `amount` (atomic sources only). */
  decimals?: number;
  /** What the client declared in `asset_decimals`, when it did. */
  declared?: number;
}

/** Resolve the payment's USD value, with provenance. See the module comment. */
export function resolveValue(payment: PaymentDetails): ResolvedValue {
  const declared = parseDeclaredDecimals(payment.asset_decimals);

  if (payment.amount !== undefined) {
    const atomic = Number(payment.amount);
    if (Number.isFinite(atomic)) {
      const known = knownAssetDecimals(payment.network, payment.asset);
      let decimals: number;
      let source: ValueSource;
      if (known !== null) {
        decimals = known;
        source = "atomic_known";
      } else if (!payment.asset) {
        decimals = DEFAULT_DECIMALS;
        source = "atomic_default";
      } else {
        // Unverifiable asset. Fewer decimals than 6 only raises the value and
        // is honored; more would shrink it and is ignored (and flagged below).
        decimals = Math.min(declared ?? DEFAULT_DECIMALS, DEFAULT_DECIMALS);
        source = "atomic_declared";
      }
      const usd = atomic / 10 ** decimals;
      if (Number.isFinite(usd)) return { usd, source, decimals, declared };
    }
  }
  if (typeof payment.amount_usd === "number" && Number.isFinite(payment.amount_usd)) {
    return { usd: payment.amount_usd, source: "self_reported", declared };
  }
  return { usd: null, source: "none", declared };
}

/** Resolve the payment's USD value (see resolveValue for the trust rules). */
export function resolveUsd(payment: PaymentDetails): number | null {
  return resolveValue(payment).usd;
}

/**
 * Surfaces a client-declared `asset_decimals` that the server refused to use.
 * On canonical USDC the only honest value is 6; anything else is a client bug
 * or an attempt to shrink the value under every USD cap. On an asset the
 * server cannot verify, a declaration above 6 is either that same attempt or
 * a genuine high-decimal token the caps now over-value, and only a human
 * checking the token can tell which. Flag, not block: the value itself was
 * computed without the declaration, so the caps hold either way, and this
 * just makes the declaration visible.
 */
export function checkValueProvenance(payment: PaymentDetails): CheckResult | null {
  const v = resolveValue(payment);
  if (v.source === "self_reported" || v.source === "none" || v.usd === null) return null;

  // Both an atomic amount and a self-reported USD figure were supplied and
  // they disagree. The atomic amount (what gets signed) is authoritative;
  // the self-report is surfaced so a client that under-reports is visible.
  if (
    typeof payment.amount_usd === "number" &&
    Number.isFinite(payment.amount_usd) &&
    v.usd > 0 &&
    Math.abs(payment.amount_usd / v.usd - 1) > 0.01
  ) {
    return {
      id: "value.usd_mismatch",
      name: "Payment value",
      verdict: "flag",
      severity: "medium",
      reason: `amount_usd=${payment.amount_usd} disagrees with the atomic amount (${payment.amount} → $${v.usd.toFixed(6)} at ${v.decimals} decimals). The atomic amount is what the wallet signs, so it is the value every cap was judged on; the self-reported figure was ignored. Fix the client — or, if the atomic amount is wrong, do not sign it.`,
      details: { amount_usd_declared: payment.amount_usd, amount_usd: v.usd, used_decimals: v.decimals, value_source: v.source },
    };
  }

  if (v.declared === undefined || v.declared === v.decimals) return null;
  const reason =
    v.source === "atomic_declared"
      ? `asset_decimals=${v.declared} was declared for asset ${payment.asset} on ${payment.network ?? "an undeclared network"}, which TollWarden cannot verify. An unverifiable declaration may raise a payment's value but never lower it below the ${DEFAULT_DECIMALS}-decimal reading, so every cap judged this payment at ${v.decimals} decimals ($${v.usd.toFixed(6)}). Declaring ${v.declared} for a ${DEFAULT_DECIMALS}-decimal token would shrink the payment under every USD cap; if the token really has ${v.declared} decimals it is over-valued here and the caps may refuse it. Check the token's decimals on-chain before signing. In the SDK path this value comes from the seller's 402 offer.`
      : `asset_decimals=${v.declared} was declared, but ${
          v.source === "atomic_known" ? `the asset is canonical USDC on ${payment.network}` : "no asset was declared and USDC is assumed"
        } (${v.decimals} decimals). The value was computed from the server-known decimals, not the declared ones — declaring more decimals than the token has would shrink the payment under every USD cap. Fix the client, or declare the actual asset contract.`;
  return {
    id: "value.decimals_ignored",
    name: "Payment value",
    verdict: "flag",
    severity: "medium",
    reason,
    details: { declared_decimals: v.declared, used_decimals: v.decimals, amount_usd: v.usd, value_source: v.source },
  };
}

export function checkOverpayment(
  payment: PaymentDetails,
  expectedUsd: number | undefined,
  opts: { flagMultiple: number; blockMultiple: number; maxUsd: number },
): CheckResult {
  const usd = resolveUsd(payment);
  if (usd === null) {
    return {
      id: "overpay.no_amount",
      name: "Overpayment detection",
      verdict: "flag",
      severity: "low",
      reason:
        "Payment amount could not be determined (provide amount + asset, or amount_usd). Overpayment protection cannot be verified.",
    };
  }

  if (usd <= 0) {
    return {
      id: "overpay.non_positive",
      name: "Overpayment detection",
      verdict: "block",
      severity: "high",
      reason: `Payment amount resolves to $${usd.toFixed(6)} — zero or negative amounts are malformed and are sometimes used to probe payment plumbing. Refuse and re-quote.`,
      details: { amount_usd: usd },
    };
  }

  if (usd > opts.maxUsd) {
    return {
      id: "overpay.absolute_cap",
      name: "Overpayment detection",
      verdict: "block",
      severity: "high",
      reason: `Payment of $${usd.toFixed(4)} exceeds the configured absolute ceiling of $${opts.maxUsd}. Raise MAX_PAYMENT_USD if intentional.`,
      details: { amount_usd: usd, max_usd: opts.maxUsd },
    };
  }

  if (expectedUsd !== undefined && expectedUsd > 0) {
    const ratio = usd / expectedUsd;
    if (ratio >= opts.blockMultiple) {
      return {
        id: "overpay.block_multiple",
        name: "Overpayment detection",
        verdict: "block",
        severity: "high",
        reason: `Payment of $${usd.toFixed(4)} is ${ratio.toFixed(1)}× the expected price of $${expectedUsd.toFixed(4)} (block threshold ${opts.blockMultiple}×).`,
        details: { amount_usd: usd, expected_usd: expectedUsd, ratio },
      };
    }
    if (ratio >= opts.flagMultiple) {
      return {
        id: "overpay.flag_multiple",
        name: "Overpayment detection",
        verdict: "flag",
        severity: "medium",
        reason: `Payment of $${usd.toFixed(4)} is ${ratio.toFixed(1)}× the expected price of $${expectedUsd.toFixed(4)} (flag threshold ${opts.flagMultiple}×). Verify the quote before proceeding.`,
        details: { amount_usd: usd, expected_usd: expectedUsd, ratio },
      };
    }
  }

  return {
    id: "overpay.clean",
    name: "Overpayment detection",
    verdict: "allow",
    severity: "info",
    reason:
      expectedUsd !== undefined
        ? `Payment of $${usd.toFixed(4)} is within expected bounds ($${expectedUsd.toFixed(4)} expected).`
        : `Payment of $${usd.toFixed(4)} is under the absolute ceiling; no expected price supplied for ratio checks.`,
  };
}
