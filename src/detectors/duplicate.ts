// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Duplicate-purchase detection: one purchase authorized twice.
 *
 * replay.nonce_reuse catches ONE authorization presented twice. It cannot
 * catch what x402 clients actually do on retry. The reference client mints a
 * fresh EIP-3009 nonce for every 402 it sees (x402#3438), so a retried
 * purchase arrives as a second, valid authorization with a new nonce. Both
 * can settle, because the first stays valid until its validBefore
 * (now + maxTimeoutSeconds), and the wallet is debited twice. Velocity does
 * not see it either: one duplicate is far below any rate cap.
 *
 * The signal: an OUTGOING scan whose purchase (history scope, payer, network,
 * pay_to, asset, amount, resource_url) matches the latest non-blocked scan of
 * the same purchase within DUPLICATE_PURCHASE_WINDOW_SECONDS, as a different
 * authorization:
 *
 *   prior nonce  this nonce
 *   n1           n1      same authorization: replay.nonce_reuse owns it. Skip.
 *   none         n       the post-sign re-scan of a pre-sign scan (the flow
 *                        replay.pre_sign recommends). Binds n to the attempt.
 *                        Skip. A third nonce after that flags.
 *   n1           n2      two signed authorizations → flag (medium).
 *   n1           none    a fresh pre-sign scan after an authorization already
 *                        exists → flag (medium).
 *   none         none    two pre-sign scans. In the SDK wrapper each one
 *                        licenses a signature → flag (low: the first may never
 *                        have been signed).
 *
 * Legitimate repeats (polling a paid feed, buying the same report twice) clear
 * the flag in two ways. Neither is a standing exemption:
 *  - The earlier attempt's delivery outcome was reported as delivered, partial
 *    or wrong_content. It completed and the buyer has the result, so buying
 *    again is a decision, not a retry. The SDK payment wrappers report this
 *    automatically. not_delivered does NOT clear it: a paid call that came
 *    back as an error is exactly the call that gets retried.
 *  - context.repeat_of names the earlier attempt's scan_id. It acknowledges
 *    that one attempt only, so a retry loop that rebuilds its state each time
 *    cannot produce it by accident, and the next repeat needs its own.
 * Anything else goes through the usual flag path (enforcer policy, step-up
 * approval).
 *
 * Flag, never block (H-2). For anonymous scans the scope is the
 * client-declared agent_id / payer, so anyone can seed a record under someone
 * else's payer. Even under an account's own scope the signal cannot tell a
 * retry from an intended repeat (purchase intent is not in the bytes), and
 * TollWarden sees scans, not settlements: it cannot know the first
 * authorization settled. A block would assert what TollWarden cannot observe,
 * and blocks are not approvable, leaving a legitimate repeat no way through.
 *
 * Scan ids are echoed (prior_scan_id, in the reason) only under an account
 * scope. An anonymous scope is client-declared, so echoing would hand anyone
 * who knows a payer and a purchase that payer's latest scan_id, and with it
 * the means to file an outcome on it (a pre-sign scan's commitment is
 * computable) and silence the payer's next retry flag. Anonymous callers
 * already hold their own earlier scan_id for repeat_of.
 *
 * O(1) on the hot path: one Map lookup on a hashed key and at most two
 * scan-index lookups. checkDuplicatePurchase only reads. recordPurchase writes
 * after the verdict is aggregated, and only for a scan that was not blocked:
 * a refused payment is not a purchase a later retry could duplicate, so a
 * block leaves the prior record exactly as it was (the same rollback the
 * scanner applies to trust state). Expiry runs on the store's timer.
 */
import { createHash } from "node:crypto";
import type { CheckResult, PaymentDetails, ScanRequest, Verdict } from "../types.ts";
import type { PurchaseRecord, Store } from "../store.ts";
import { networkKey } from "./asset.ts";

const NAME = "Duplicate purchase detection";

/** Outcomes that mean the earlier attempt completed and the buyer saw it. */
const COMPLETED_OUTCOMES = new Set(["delivered", "partial", "wrong_content"]);

/** Scan ids kept per attempt: the scan that recorded it, plus the post-sign
 * scan that bound its nonce. */
const MAX_SCAN_IDS = 2;

function normAmount(p: PaymentDetails): string | null {
  const a = p.amount?.trim();
  if (a) return /^\d+$/.test(a) ? BigInt(a).toString() : a;
  return typeof p.amount_usd === "number" ? `usd:${p.amount_usd}` : null;
}

function normResource(raw: string | undefined): string | null {
  const r = raw?.trim();
  if (!r) return null;
  try {
    const u = new URL(r);
    u.hash = ""; // never sent to the server, so not part of the purchase
    return u.href;
  } catch {
    return r;
  }
}

/**
 * Store key for a purchase: `${scope}|sha256(tuple)`. The tuple is hashed so
 * resource URLs are never persisted. The scope prefix stays readable so key
 * rotation and revocation can move or drop an account's records.
 * Null when the scan cannot identify a purchase (no scope, pay_to, amount or
 * resource).
 */
export function purchaseKey(p: PaymentDetails, scope: string | undefined): string | null {
  const payTo = p.pay_to?.trim().toLowerCase();
  const amount = normAmount(p);
  const resource = normResource(p.resource_url);
  if (!scope || !payTo || amount === null || resource === null) return null;
  const tuple = JSON.stringify([
    (p.payer ?? "").trim().toLowerCase(),
    networkKey(p.network) ?? "",
    payTo,
    (p.asset ?? "").trim().toLowerCase(),
    amount,
    resource,
  ]);
  return `${scope}|${createHash("sha256").update(tuple, "utf8").digest("hex")}`;
}

/** What this scan will write if it is not blocked. */
export interface PurchaseObservation {
  key: string;
  record: PurchaseRecord;
}

export interface DuplicateResult {
  check: CheckResult | null;
  observation: PurchaseObservation | null;
}

export interface DuplicateOptions {
  /** Echo earlier scan ids. Only for a server-resolved account scope (see the
   * module comment). */
  revealScanIds?: boolean;
  now?: number;
}

export function checkDuplicatePurchase(
  req: ScanRequest,
  store: Store,
  scope: string | undefined,
  scanId: string,
  windowSeconds: number,
  opts: DuplicateOptions = {},
): DuplicateResult {
  const now = opts.now ?? Date.now();
  const reveal = opts.revealScanIds === true;
  const none: DuplicateResult = { check: null, observation: null };
  if (!(windowSeconds > 0)) return none;
  const key = purchaseKey(req.payment, scope);
  if (key === null) return none;

  const nonce = req.payment.nonce?.trim() || null;
  const fresh: PurchaseObservation = { key, record: { scan_ids: [scanId], at: now, nonce, attempts: 1 } };
  const prior = store.purchases.get(key);
  if (!prior || now - prior.at >= windowSeconds * 1000) return { check: null, observation: fresh };

  // The same authorization again is nonce replay, which replay.nonce_reuse
  // blocks. Reporting it twice would add nothing, and a blocked scan writes
  // nothing anyway.
  if (nonce !== null && prior.nonce === nonce) return none;

  // First nonce for an attempt scanned pre-sign: this is that attempt's
  // post-sign scan, not a second purchase. Bind the nonce so a THIRD
  // authorization is caught.
  if (prior.nonce === null && nonce !== null) {
    const scan_ids = [...prior.scan_ids, scanId].slice(-MAX_SCAN_IDS);
    return { check: null, observation: { key, record: { ...prior, scan_ids, at: now, nonce } } };
  }

  const seconds = Math.max(0, Math.round((now - prior.at) / 1000));
  const latest = prior.scan_ids[prior.scan_ids.length - 1];
  const priorRef = reveal ? `scan ${latest}` : "an earlier scan in this scope";
  const priorDetail = reveal ? { prior_scan_id: latest } : {};

  const repeatOf = req.context?.repeat_of;
  if (repeatOf && prior.scan_ids.includes(repeatOf)) {
    return {
      check: {
        id: "replay.repeat_acknowledged",
        name: NAME,
        verdict: "allow",
        severity: "info",
        reason: `Identical purchase scanned ${seconds}s ago (scan ${repeatOf}); context.repeat_of acknowledges it as a deliberate repeat.`,
        details: { prior_scan_id: repeatOf, seconds_since_prior: seconds, basis: "repeat_of" },
      },
      observation: fresh,
    };
  }

  let priorOutcome: string | undefined;
  for (const id of prior.scan_ids) {
    const o = store.scanIndex.get(id)?.outcome;
    if (o) priorOutcome = o;
  }
  if (priorOutcome && COMPLETED_OUTCOMES.has(priorOutcome)) {
    return {
      check: {
        id: "replay.repeat_acknowledged",
        name: NAME,
        verdict: "allow",
        severity: "info",
        reason: `Identical purchase scanned ${seconds}s ago (${priorRef}), whose outcome was reported as ${priorOutcome}. That attempt completed, so this is a new purchase, not a retry.`,
        details: { ...priorDetail, seconds_since_prior: seconds, basis: `outcome:${priorOutcome}` },
      },
      observation: fresh,
    };
  }

  const attempts = prior.attempts + 1;
  const evidence =
    prior.nonce !== null && nonce !== null ? "distinct_authorizations"
    : prior.nonce !== null ? "prior_authorization"
    : "prior_pre_sign_scan";
  const what =
    evidence === "distinct_authorizations"
      ? `was authorized ${seconds}s ago (${priorRef}) under a different nonce`
      : evidence === "prior_authorization"
        ? `was authorized ${seconds}s ago (${priorRef}), and this pre-sign scan precedes a second authorization`
        : `was scanned before signing ${seconds}s ago (${priorRef}) and is being scanned before signing again; if the earlier attempt was signed, this one authorizes the purchase a second time`;
  const parts = [
    `Possible duplicate purchase: an identical payment (same pay_to, asset, amount and resource) ${what}.`,
    "x402 clients sign a fresh authorization for every 402 they see, so a retried request can settle twice: the earlier authorization stays valid until its validBefore.",
  ];
  if (priorOutcome === "not_delivered") {
    parts.push("The earlier attempt was reported not_delivered. If its authorization settled anyway, paying again pays twice.");
  }
  if (attempts > 2) {
    parts.push(`This is attempt ${attempts} in a row, each within ${windowSeconds}s of the last, which looks like a retry loop.`);
  }
  if (repeatOf) {
    parts.push(
      reveal
        ? `context.repeat_of names ${repeatOf}, but the latest identical attempt is ${latest}.`
        : `context.repeat_of names ${repeatOf}, which is not the latest identical attempt.`,
    );
  }
  parts.push(
    `Check whether the earlier attempt settled before paying again. For a deliberate repeat, set context.repeat_of to ${reveal ? `"${latest}"` : "the scan_id of your latest scan of this purchase"} or report that attempt's delivery outcome.`,
  );

  return {
    check: {
      id: "replay.duplicate_purchase",
      name: NAME,
      verdict: "flag",
      severity: evidence === "prior_pre_sign_scan" ? "low" : "medium",
      reason: parts.join(" "),
      details: {
        ...priorDetail,
        seconds_since_prior: seconds,
        window_seconds: windowSeconds,
        attempts,
        evidence,
        ...(priorOutcome ? { prior_outcome: priorOutcome } : {}),
        ...(repeatOf ? { repeat_of_unmatched: repeatOf } : {}),
      },
    },
    observation: { key, record: { scan_ids: [scanId], at: now, nonce, attempts } },
  };
}

/**
 * Write this scan's purchase record once its verdict is known. A blocked scan
 * writes nothing: the prior record (if any) stays the reference for the next
 * attempt. Delete-then-set keeps the Map ordered by recency, so the size
 * cap's oldest-first eviction drops the stalest records.
 */
export function recordPurchase(store: Store, obs: PurchaseObservation | null, verdict: Verdict): void {
  if (!obs || verdict === "block") return;
  store.purchases.delete(obs.key);
  store.purchases.set(obs.key, obs.record);
  store.markDirty();
}
