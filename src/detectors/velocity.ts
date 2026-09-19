// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Velocity & policy limits. These are the checks that hold even when the
 * calling agent's narration is compromised: rate of payments, cumulative
 * spend, and first-contact size caps are observable facts, not self-reports.
 *
 * Scope key: the server-resolved account (API-key hash) when the caller
 * presented a key; only anonymous scans fall back to the client-declared
 * agent_id / payer. A key-holder therefore cannot escape its own caps by
 * rotating `agent_id` per request (audit 2026-09-19) — and since plan
 * headroom is granted per key, the cap and the headroom now share a scope.
 * All O(1)/O(window).
 */
import type { CheckResult, ScanRequest } from "../types.ts";
import type { TollWardenConfig } from "../config.ts";
import type { Store } from "../store.ts";

const HOUR = 3600_000;
const MINUTE = 60_000;

export interface VelocityScope {
  /** Storage key the windows are kept under. */
  key?: string;
  /** Human-readable label for reason strings (never a raw key hash). */
  label?: string;
}

export function checkVelocity(
  req: ScanRequest,
  usd: number | null,
  store: Store,
  cfg: TollWardenConfig,
  scope?: VelocityScope,
): CheckResult[] {
  const key = scope ? scope.key : req.agent_id ?? req.payment.payer?.toLowerCase();
  const label = scope?.label ?? (key ? `agent "${key}"` : "");
  if (!key) {
    return [
      {
        id: "velocity.unscoped",
        name: "Velocity & policy limits",
        verdict: "flag",
        severity: "low",
        reason:
          "No API key, agent_id, or payer supplied, so rate and spend caps cannot be applied. Include one to enable velocity protection.",
      },
    ];
  }

  const results: CheckResult[] = [];
  const now = Date.now();

  // --- sliding windows (this scan included) ---
  const events = (store.velocity.get(key) ?? []).filter((e) => now - e.t < HOUR);
  const perMinute = events.filter((e) => now - e.t < MINUTE).length + 1;
  const hourUsd = events.reduce((s, e) => s + e.usd, 0) + (usd ?? 0);
  events.push({ t: now, usd: usd ?? 0 });
  store.velocity.set(key, events);
  store.markDirty();

  if (perMinute >= cfg.maxPaymentsPerMinute * 2) {
    results.push({
      id: "velocity.rate_block",
      name: "Velocity & policy limits",
      verdict: "block",
      severity: "critical",
      reason: `${perMinute} payment scans in the last minute for ${label} — ≥2× the configured rate of ${cfg.maxPaymentsPerMinute}/min. This pattern is consistent with a wallet-drain loop.`,
      details: { per_minute: perMinute, limit: cfg.maxPaymentsPerMinute },
    });
  } else if (perMinute >= cfg.maxPaymentsPerMinute) {
    results.push({
      id: "velocity.rate_flag",
      name: "Velocity & policy limits",
      verdict: "flag",
      severity: "medium",
      reason: `${perMinute} payment scans in the last minute for ${label} (configured rate: ${cfg.maxPaymentsPerMinute}/min).`,
      details: { per_minute: perMinute, limit: cfg.maxPaymentsPerMinute },
    });
  }

  if (hourUsd > cfg.maxUsdPerHour) {
    results.push({
      id: "velocity.spend_cap",
      name: "Velocity & policy limits",
      verdict: "block",
      severity: "high",
      reason: `Cumulative scanned spend of $${hourUsd.toFixed(4)} in the last hour for ${label} exceeds the $${cfg.maxUsdPerHour} cap (MAX_USD_PER_HOUR).`,
      details: { hour_usd: hourUsd, cap_usd: cfg.maxUsdPerHour },
    });
  }

  // --- first payment to a never-seen counterparty ---
  const payTo = req.payment.pay_to?.toLowerCase();
  if (payTo) {
    const seen = store.counterparties.get(key) ?? [];
    if (!seen.includes(payTo)) {
      if (usd !== null && usd > cfg.firstPaymentMaxUsd) {
        results.push({
          id: "velocity.first_contact_size",
          name: "Velocity & policy limits",
          verdict: "flag",
          severity: "medium",
          reason: `First payment from ${label} to counterparty ${payTo} is $${usd.toFixed(4)} — above the $${cfg.firstPaymentMaxUsd} first-contact cap (FIRST_PAYMENT_MAX_USD). Consider a small test payment first.`,
          details: { amount_usd: usd, cap_usd: cfg.firstPaymentMaxUsd },
        });
      }
      seen.push(payTo);
      if (seen.length > 1000) seen.shift();
      store.counterparties.set(key, seen);
      store.markDirty();
    }
  }

  if (results.length === 0) {
    results.push({
      id: "velocity.clean",
      name: "Velocity & policy limits",
      verdict: "allow",
      severity: "info",
      reason: `Rate (${perMinute}/min) and hourly spend ($${hourUsd.toFixed(4)}) are within limits for ${label}.`,
    });
  }
  return results;
}
