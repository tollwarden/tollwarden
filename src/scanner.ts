// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/** Scan orchestration: runs detectors and aggregates a verdict. */
import { randomUUID } from "node:crypto";
import type { CheckResult, Direction, ScanRequest, ScanResponse, Verdict } from "./types.ts";
import type { TollWardenConfig } from "./config.ts";
import type { Store } from "./store.ts";
import { scanPii } from "./detectors/pii.ts";
import { checkReplay } from "./detectors/replay.ts";
import { checkOverpayment, checkValueProvenance, resolveUsd } from "./detectors/overpayment.ts";
import { checkInjection, deepContentAnalysis } from "./detectors/injection.ts";
import { checkOfferDrift, checkFreshnessClaim } from "./detectors/offerdrift.ts";
import { checkUrlRisk } from "./detectors/urlrisk.ts";
import { checkAsset } from "./detectors/asset.ts";
import { checkBadlist } from "./detectors/badlist.ts";
import { checkPinning, checkCdpPinStatus, payeeEstablished, scheduleCdpPinVerify, tenantPinFor } from "./detectors/pinning.ts";
import { tenantKey } from "./store.ts";
import { checkAddressPoisoning, checkContentLookalikes } from "./detectors/poisoning.ts";
import { checkScoutScore, scheduleScoutScoreRefresh } from "./detectors/scoutscore.ts";
import { checkVelocity } from "./detectors/velocity.ts";
import { checkInjectionHistory, checkReputation, recordInjectionIncidents } from "./reputation.ts";
import { checkDelivery } from "./outcomes.ts";

const SEVERITY_SCORE: Record<string, number> = {
  info: 0,
  low: 15,
  medium: 40,
  high: 70,
  critical: 95,
};

function aggregate(checks: CheckResult[]): { verdict: Verdict; risk: number } {
  let verdict: Verdict = "allow";
  let risk = 0;
  for (const c of checks) {
    if (c.verdict === "block") verdict = "block";
    else if (c.verdict === "flag" && verdict === "allow") verdict = "flag";
    risk = Math.max(risk, SEVERITY_SCORE[c.severity] ?? 0);
  }
  // Multiple independent flags compound.
  const flags = checks.filter((c) => c.verdict !== "allow").length;
  if (flags > 1) risk = Math.min(100, risk + (flags - 1) * 5);
  return { verdict, risk };
}

function advisory(direction: Direction, verdict: Verdict): string {
  if (verdict === "allow") {
    return "No issues detected. TollWarden is advisory — final settlement remains with your wallet/facilitator.";
  }
  if (verdict === "flag") {
    return direction === "outgoing"
      ? "Review the flagged checks before authorizing settlement. Consider pausing this payment and confirming intent against the agent's plan."
      : "Review the flagged checks before acting on this payment request. Consider verifying the counterparty out-of-band.";
  }
  return direction === "outgoing"
    ? "Recommended action: DO NOT settle this payment. At least one check found a condition consistent with fund exfiltration or data leakage."
    : "Recommended action: DO NOT comply with this payment request. At least one check found a condition consistent with fraud.";
}

/**
 * Who is scanning, as the SERVER knows it. `tenant` is the hash of the API
 * key the caller presented (resolved by the API layer, never read from the
 * request body); null/undefined for anonymous x402-paid scans. Every
 * stateful, block-capable check — pins, velocity, counterparty history,
 * cumulative spend — keys on this when present, so a key-holder's history is
 * its own and cannot be written or evaded by choosing request fields.
 */
export interface ScanScope {
  tenant?: string | null;
}

export function runScan(
  direction: Direction,
  req: ScanRequest,
  cfg: TollWardenConfig,
  store: Store,
  scope: ScanScope = {},
): ScanResponse {
  const scanId = randomUUID();
  const payment = req.payment ?? {};
  const usd = resolveUsd(payment);
  const checks: CheckResult[] = [];
  const tenant = scope.tenant ?? null;
  // History scope: the server-resolved account when there is one; the
  // client-declared agent_id / payer only for anonymous scans (where the
  // caller pays per scan and has no account to be held to).
  const velocityKey = tenant ?? req.agent_id ?? payment.payer?.toLowerCase();
  const velocityLabel = tenant
    ? `account ${tenant.slice(0, 8)}…`
    : velocityKey
      ? `agent "${velocityKey}"`
      : "";
  const payToLc = payment.pay_to?.toLowerCase();

  // Resource domain, resolved once. Pure — no state touched.
  let pinDomain: string | null = null;
  try {
    pinDomain = payment.resource_url ? new URL(payment.resource_url).hostname.toLowerCase() : null;
  } catch {
    pinDomain = null;
  }
  const pinExistedBefore = pinDomain !== null && store.pins.has(pinDomain);
  const tenantPinExistedBefore = pinDomain !== null && tenantPinFor(store, tenant, pinDomain) !== undefined;

  // Read prior pin state BEFORE checkPinning writes it (TOFU pins on first
  // sighting). "The payee was already established for this domain" is a fact
  // the caller could not have forged — its own account's pin, or a global pin
  // the CDP index corroborates; a stranger's unverified pin does NOT count. It
  // is the only input allowed to MITIGATE the provenance finding, and it can
  // only ever lower a flag — never raise one.
  // Gated on cfg.pinning: with pinning off nothing maintains the pin map, so a
  // stale entry must not be treated as evidence.
  const payeeEstablishedBefore = cfg.pinning && payeeEstablished(store, tenant, pinDomain, payToLc);

  // --- core detectors ---
  checks.push(...scanPii(payment));
  checks.push(checkReplay(payment, store, scanId, cfg.nonceTtlHours, req.context?.phase));
  checks.push(
    checkOverpayment(payment, req.expected_price_usd, {
      flagMultiple: cfg.overpayFlagMultiple,
      blockMultiple: cfg.overpayBlockMultiple,
      maxUsd: cfg.maxPaymentUsd,
    }),
  );
  // A client-declared asset_decimals the server refused to use is made
  // visible (the value above was already computed from server-known decimals).
  const valueProvenance = checkValueProvenance(payment);
  if (valueProvenance) checks.push(valueProvenance);
  checks.push(...checkInjection(payment, req.context, { payeeEstablishedBefore }));

  // Offer drift: the payment about to be signed vs the offer it was decided
  // from. Parse-only and stateless, so it runs in the fast tier alongside the
  // other structural checks.
  checks.push(...checkOfferDrift(payment, req.context));

  // Advisory only: tells the buyer which verification to run when the offer
  // sells recency. Never gates — see checkFreshnessClaim.
  checks.push(...checkFreshnessClaim(payment, req.context));

  // Deep content tier: bypassed for micropayments unless forced (developer policy).
  // NOTE (audit M-2): a missing/unparseable amount does NOT unlock the deep
  // tier — otherwise an attacker omits `amount` to force the expensive path for
  // free. Unknown value is treated as below-threshold; use policy.force_deep to
  // opt in explicitly.
  // Cumulative trigger: the per-payment micro bypass must not be a permanent
  // blind spot. An attacker dripping value below MICRO_BYPASS_USD per payment
  // unlocks the deep tier anyway once the lifetime SCANNED spend from this
  // agent key to this counterparty crosses the same threshold. (Scans, not
  // settlements — re-scanning over-counts, which only unlocks deep EARLIER.)
  // Untrusted-origin trigger: value is the wrong gate for the deep tier when
  // the request carries counterparty-controlled prose. A $0.001 offer is
  // exactly where an injection payload is CHEAPEST to plant, and the fast tier
  // alone does not see base64/unicode obfuscation. So content the agent
  // declares as tool_result / fetched_content always gets the deep tier,
  // whatever it cost.
  //
  // This does not reopen audit M-2 (omit `amount` to force the expensive path
  // for free): the trigger requires positively DECLARING an untrusted origin,
  // which by itself raises a provenance finding. An attacker who sets it buys
  // themselves more scrutiny, not less — the same reasoning as the cumulative
  // counter below.
  const cumKey = velocityKey && payToLc ? `${velocityKey}|${payToLc}` : null;
  const cumulativeUsd = (cumKey ? store.cumulativeSpend.get(cumKey)?.usd ?? 0 : 0) + (usd ?? 0);
  const singleEligible = usd !== null && usd >= cfg.microBypassUsd;
  const cumulativeEligible = !singleEligible && cumKey !== null && cumulativeUsd >= cfg.microBypassUsd;
  const untrustedOrigin =
    req.context?.origin === "tool_result" || req.context?.origin === "fetched_content";
  const untrustedContentEligible =
    !singleEligible && !cumulativeEligible && untrustedOrigin && !!req.context?.content;
  const deepEligible =
    req.policy?.skip_deep !== true &&
    (req.policy?.force_deep === true ||
      singleEligible ||
      cumulativeEligible ||
      untrustedContentEligible);
  if (deepEligible) {
    checks.push(...deepContentAnalysis(payment, req.context));
    if (untrustedContentEligible && req.policy?.force_deep !== true) {
      checks.push({
        id: "tier.deep_untrusted_origin",
        name: "Scan tiering",
        verdict: "allow",
        severity: "info",
        reason: `Deep content analysis ran despite the micro value (${usd === null ? "unknown" : `$${usd.toFixed(4)}`} < $${cfg.microBypassUsd} MICRO_BYPASS_USD): the content is declared ${req.context?.origin}. Counterparty-controlled prose is analysed on content provenance, not on payment value — a cheap offer is not a safe one.`,
      });
    }
    if (cumulativeEligible && req.policy?.force_deep !== true && req.context?.content) {
      checks.push({
        id: "tier.deep_cumulative",
        name: "Scan tiering",
        verdict: "allow",
        severity: "info",
        reason: `Deep content analysis ran despite the micro value (${usd === null ? "unknown" : `$${usd.toFixed(4)}`}): cumulative scanned spend to this counterparty ($${cumulativeUsd.toFixed(4)}) crossed the $${cfg.microBypassUsd} MICRO_BYPASS_USD threshold. Dripping micro-payments does not evade the deep tier.`,
      });
    }
  } else if (req.context?.content) {
    checks.push({
      id: "tier.deep_bypassed",
      name: "Scan tiering",
      verdict: "allow",
      severity: "info",
      reason: `Deep content analysis bypassed (value ${usd === null ? "unknown" : `$${usd.toFixed(4)}`} < $${cfg.microBypassUsd} MICRO_BYPASS_USD; cumulative to this counterparty $${cumulativeUsd.toFixed(4)}). Set policy.force_deep to override.`,
    });
  }

  if (direction === "incoming") {
    checks.push(...checkUrlRisk(payment));
  }

  // --- zero-latency hardening tier ---
  checks.push(checkAsset(payment, cfg.allowNonUsdc));

  const badlistHit = checkBadlist(payment, store);
  if (badlistHit) checks.push(badlistHit);

  // Address poisoning: MUST run before pinning and velocity — both record
  // this scan's pay_to into trust state (pin / counterparty history), and the
  // lookalike has to be judged against state that does not yet contain it.
  const poisoningScope = { key: velocityKey, tenant };
  const poisoning = checkAddressPoisoning(req, store, poisoningScope);
  if (poisoning) checks.push(poisoning);

  // Vanity-bait addresses planted in just-read content (near-copies of the
  // recipient or of a known-good address). Read-only; same ordering rationale.
  const contentLookalike = checkContentLookalikes(req, store, poisoningScope);
  if (contentLookalike) checks.push(contentLookalike);

  // Snapshot pre-scan trust state so a BLOCKED payment can be rolled out of
  // it below (a blocked lookalike must not become "known" and silence the
  // poisoning detector on the next attempt).
  const counterpartyWasKnown =
    !!(velocityKey && payToLc && (store.counterparties.get(velocityKey) ?? []).includes(payToLc));

  if (cfg.pinning) {
    checks.push(...checkPinning(payment, store, tenant));
    const cdpStatus = checkCdpPinStatus(payment, store);
    if (cdpStatus) checks.push(cdpStatus);
    if (cfg.cdpPinVerify && payment.resource_url) {
      try {
        scheduleCdpPinVerify(store, new URL(payment.resource_url).hostname.toLowerCase());
      } catch {
        // unparseable URL already reported by other checks
      }
    }
  }

  // ScoutScore external trust signal: reads only the cache (zero latency);
  // the refresh runs out-of-band, same pattern as the CDP pin cross-check.
  if (cfg.scoutScore) {
    const scout = checkScoutScore(payment, store);
    if (scout) checks.push(scout);
    if (pinDomain !== null) scheduleScoutScoreRefresh(store, pinDomain, cfg.scoutScoreUrl);
  }

  if (direction === "outgoing") {
    checks.push(...checkVelocity(req, usd, store, cfg, { key: velocityKey, label: velocityLabel }));
  }

  checks.push(checkReputation(store, payment.pay_to));

  // System-observed injection history: has a previous BLOCKED scan (anyone's)
  // structurally implicated this pay_to? Reads the ledger only — this scan's
  // own incidents are recorded after aggregation, so a scan never flags itself.
  const injHistory = checkInjectionHistory(store, payment.pay_to);
  if (injHistory) checks.push(injHistory);

  // Delivery outcomes: measured, commitment-bound delivery history for this
  // counterparty AND for the resource domain across pay_to rotations
  // (flag-only — H-2 applies to measured history too).
  checks.push(...checkDelivery(store, payment, cfg));

  const { verdict, risk } = aggregate(checks);

  // A BLOCKED payment must not grow trust state: roll back the counterparty
  // history entry and the pin this scan just created, so the lookalike isn't
  // "known" (exact match) on the next attempt, silencing the detectors.
  if (verdict === "block") {
    if (!counterpartyWasKnown && velocityKey && payToLc) {
      const seen = store.counterparties.get(velocityKey);
      const i = seen ? seen.indexOf(payToLc) : -1;
      if (seen && i >= 0) {
        seen.splice(i, 1);
        store.markDirty();
      }
    }
    if (pinDomain !== null && !pinExistedBefore && store.pins.delete(pinDomain)) {
      store.markDirty();
    }
    if (pinDomain !== null && tenant && !tenantPinExistedBefore && store.tenantPins.delete(tenantKey(tenant, pinDomain))) {
      store.markDirty();
    }
    // Feed this block's structurally-implicated addresses into the shared
    // incident ledger: the next scan of the same wallet — by ANY agent, with
    // no content in context — inherits the signal as a flag.
    recordInjectionIncidents(store, req, scanId, checks);
  }

  // Accumulate lifetime scanned spend for the cumulative deep-tier trigger.
  // Deliberately includes blocked scans: over-counting only widens deep
  // coverage, and an attacker inflating their OWN counter just deep-scans
  // themselves sooner.
  if (cumKey && usd !== null && usd > 0) {
    const nowIso = new Date().toISOString();
    const rec = store.cumulativeSpend.get(cumKey) ?? { usd: 0, scans: 0, first_at: nowIso, last_at: nowIso };
    rec.usd += usd;
    rec.scans += 1;
    rec.last_at = nowIso;
    store.cumulativeSpend.set(cumKey, rec);
    store.markDirty();
  }
  return {
    scan_id: scanId,
    direction,
    verdict,
    risk_score: risk,
    checks,
    scanned_at: new Date().toISOString(),
    advisory: advisory(direction, verdict),
  };
}
