// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Merchant pinning (TOFU — trust on first use), in two tiers.
 *
 * TENANT pin — this account's own history. The first time an API key scans a
 * resource domain, its pay_to is pinned FOR THAT KEY; a later scan by the same
 * key with a DIFFERENT pay_to is blocked. No other caller can have written
 * this record, so the block rests on nothing the attacker controls.
 *
 * GLOBAL observation — the first pay_to ANY caller presented for the domain.
 * Written from client input, so by itself it is advisory: a mismatch FLAGS
 * ("another caller saw a different address here"). It graduates to a block
 * only when the async CDP Bazaar cross-check has VERIFIED the pinned address
 * as the merchant serving this domain — a server-observed corroboration no
 * caller can supply.
 *
 * Why two tiers (audit 2026-09-19, H-2): a single global pin map let any
 * $0.01 caller pin a victim domain to an attacker address, blocking every
 * other agent's honest payment to the real merchant and seeding the
 * poisoning detector's known-good set. The tenant tier keeps the hard block
 * where it is safe; the global tier keeps the shared early-warning value
 * without letting one client's input decide another client's verdict.
 *
 * Zero latency at scan time. Optionally, a non-blocking background cross-check
 * against the CDP Bazaar merchant index verifies global pins out-of-band.
 */
import type { CheckResult, PaymentDetails, PinEvidence } from "../types.ts";
import type { PinRecord, Store } from "../store.ts";
import { tenantKey } from "../store.ts";

export function domainOf(resourceUrl: string | undefined): string | null {
  if (!resourceUrl) return null;
  try {
    return new URL(resourceUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function freshPin(payTo: string): PinRecord {
  return { pay_to: payTo, first_seen: new Date().toISOString(), times_seen: 1, cdp_status: "unchecked" };
}

/** Read-only: the tenant's own pin for a domain, if any. */
export function tenantPinFor(store: Store, tenant: string | null | undefined, domain: string | null): PinRecord | undefined {
  if (!tenant || !domain) return undefined;
  return store.tenantPins.get(tenantKey(tenant, domain));
}

/**
 * Read-only: is `payTo` an ESTABLISHED payee for this domain — i.e. pinned
 * by evidence the caller could not have forged? True when the tenant's own
 * pin already names it, or when the global pin names it AND the CDP Bazaar
 * cross-check has verified that pin. An unverified global pin created by
 * some other caller does not count: the injection detector uses this to
 * LOWER a provenance flag, and a stranger must not be able to buy that
 * mitigation for an address they planted.
 */
export function payeeEstablished(
  store: Store,
  tenant: string | null | undefined,
  domain: string | null,
  payTo: string | undefined,
): boolean {
  if (!domain || !payTo) return false;
  const t = tenantPinFor(store, tenant, domain);
  if (t && t.pay_to === payTo) return true;
  const g = store.pins.get(domain);
  return !!(g && g.pay_to === payTo && g.cdp_status === "verified");
}

/**
 * Runs the tenant tier (when a server-resolved tenant is known) and then the
 * global tier. A tenant mismatch short-circuits to the block without touching
 * the global map: a blocked scan must not grow shared state.
 */
export function checkPinning(payment: PaymentDetails, store: Store, tenant?: string | null): CheckResult[] {
  const domain = domainOf(payment.resource_url);
  const payTo = payment.pay_to?.toLowerCase();

  if (!domain || !payTo) {
    return [
      {
        id: "pin.unscoped",
        name: "Merchant pinning",
        verdict: "allow",
        severity: "info",
        reason: "Pinning needs both resource_url and pay_to; check skipped.",
      },
    ];
  }

  const results: CheckResult[] = [];

  // --- tenant tier: this account's own history ---
  if (tenant) {
    const key = tenantKey(tenant, domain);
    const own = store.tenantPins.get(key);
    if (!own) {
      store.tenantPins.set(key, freshPin(payTo));
      store.markDirty();
    } else if (own.pay_to === payTo) {
      own.times_seen += 1;
      store.markDirty();
    } else {
      return [
        {
          id: "pin.mismatch",
          name: "Merchant pinning",
          verdict: "block",
          severity: "critical",
          reason: `Payment address for ${domain} CHANGED: this account pinned ${own.pay_to} (since ${own.first_seen}, seen ${own.times_seen}×) but this payment targets ${payTo}. Address rotation on a domain you have paid before is the signature of a redirection attack. If the merchant legitimately rotated wallets, ask the operator to clear the pin for this domain.`,
          details: { domain, pinned: own.pay_to, presented: payTo, pinned_since: own.first_seen, scope: "account" },
        },
      ];
    }
  }

  // --- global tier: what any caller has presented for this domain ---
  const global = store.pins.get(domain);
  if (!global) {
    store.pins.set(domain, freshPin(payTo));
    store.markDirty();
    results.push({
      id: "pin.created",
      name: "Merchant pinning",
      verdict: "allow",
      severity: "info",
      reason: `First sighting of ${domain}: pinned to ${payTo} (trust on first use${tenant ? ", for this account and as a shared observation" : ""}).`,
    });
    return results;
  }

  if (global.pay_to === payTo) {
    global.times_seen += 1;
    store.markDirty();
    results.push({
      id: "pin.match",
      name: "Merchant pinning",
      verdict: "allow",
      severity: "info",
      reason: `pay_to matches the pinned address for ${domain} (seen ${global.times_seen}×, pinned ${global.first_seen}${global.cdp_status === "verified" ? ", CDP-verified" : ""}).`,
    });
    return results;
  }

  if (global.cdp_status === "verified") {
    // Server-observed corroboration: the CDP Bazaar index lists the pinned
    // address as the merchant serving this domain. A different address is a
    // redirection regardless of who first reported the pin.
    results.push({
      id: "pin.mismatch",
      name: "Merchant pinning",
      verdict: "block",
      severity: "critical",
      reason: `Payment address for ${domain} does not match its CDP-verified merchant address ${global.pay_to} (pinned ${global.first_seen}, seen ${global.times_seen}×): this payment targets ${payTo}. The Bazaar index corroborates the pinned address, so the presented one is a redirection.`,
      details: { domain, pinned: global.pay_to, presented: payTo, pinned_since: global.first_seen, scope: "cdp_verified" },
    });
    return results;
  }

  // Unverified shared observation: another caller saw a different address.
  // Client-supplied on both sides, so H-2 caps this at a flag. The tenant
  // tier above is where a hard block comes from once THIS account has its
  // own history with the domain.
  results.push({
    id: "pin.observed_mismatch",
    name: "Merchant pinning",
    verdict: "flag",
    severity: "high",
    reason: `Another caller previously presented ${global.pay_to} as the payment address for ${domain} (first seen ${global.first_seen}, ${global.times_seen}×); this payment targets ${payTo}. That observation is unverified and could itself be wrong, so this is a flag, not a block — verify the merchant's address out-of-band before paying. Your own account's history with this domain is what turns a later mismatch into a block.`,
    details: { domain, observed: global.pay_to, presented: payTo, observed_since: global.first_seen, scope: "shared_unverified" },
  });
  return results;
}

/**
 * Pin facts for the signed evidence record — READ-ONLY, computed at
 * attestation time (after the scanner has created/updated/rolled-back pins,
 * so a blocked first-sighting whose pin was rolled back honestly reads as "no
 * pin"). Prefers the tenant's own pin (age = how long THIS account has seen
 * the binding) and falls back to the global observation. Returns facts only
 * when the pin refers to THIS payment's payee (pin.pay_to === payment.pay_to):
 * a pin held by a different address is not evidence about the presented one.
 * Corroboration is read from the global record, since that is what the CDP
 * cross-check annotates. Null when pinning is disabled (nothing maintains the
 * pin map, so a stale entry must not be signed as evidence), when no pin
 * applies, or when the stored timestamp is unusable (never sign a garbage age).
 */
export function pinEvidenceFor(
  payment: PaymentDetails,
  store: Store,
  pinningEnabled: boolean,
  scannedAt: string,
  tenant?: string | null,
): PinEvidence | null {
  if (!pinningEnabled) return null;
  const domain = domainOf(payment.resource_url);
  const payTo = payment.pay_to?.toLowerCase();
  if (!domain || !payTo) return null;
  const own = tenantPinFor(store, tenant, domain);
  const global = store.pins.get(domain);
  const pin = own && own.pay_to === payTo ? own : global && global.pay_to === payTo ? global : undefined;
  if (!pin) return null;
  const ageMs = Date.parse(scannedAt) - Date.parse(pin.first_seen);
  if (!Number.isFinite(ageMs)) return null;
  const corroborated = !!(global && global.pay_to === payTo && global.cdp_status === "verified");
  return {
    domain,
    age_seconds: Math.max(0, Math.floor(ageMs / 1000)),
    corroboration: corroborated ? ["cdp_bazaar"] : [],
  };
}

/**
 * Non-blocking CDP Bazaar cross-check: does the CDP merchant index list this
 * domain among the resources served by the globally pinned pay_to? Fire-and-
 * forget — never in the scan's latency path. Enable with CDP_PIN_VERIFY=on.
 */
export function scheduleCdpPinVerify(store: Store, domain: string): void {
  const pin = store.pins.get(domain);
  if (!pin || pin.cdp_status !== "unchecked") return;

  setImmediate(async () => {
    try {
      const res = await fetch(
        `https://api.cdp.coinbase.com/platform/v2/x402/discovery/merchant?payTo=${encodeURIComponent(pin.pay_to)}`,
        { signal: AbortSignal.timeout(10_000) },
      );
      if (res.status === 404) return; // merchant not indexed (yet) — stay unchecked
      if (!res.ok) return;
      const data = (await res.json()) as { resources?: Array<{ resource?: string }> };
      const domains = (data.resources ?? [])
        .map((r) => domainOf(r.resource))
        .filter((d): d is string => d !== null);
      if (domains.length === 0) return;
      pin.cdp_status = domains.includes(domain) ? "verified" : "mismatch";
      store.markDirty();
    } catch {
      // best-effort; pin stays "unchecked"
    }
  });
}

/** Surface an out-of-band CDP mismatch found by a previous background check. */
export function checkCdpPinStatus(payment: PaymentDetails, store: Store): CheckResult | null {
  const domain = domainOf(payment.resource_url);
  if (!domain) return null;
  const pin = store.pins.get(domain);
  if (!pin || pin.cdp_status !== "mismatch") return null;
  return {
    id: "pin.cdp_mismatch",
    name: "Merchant pinning",
    verdict: "flag",
    severity: "high",
    reason: `Background CDP Bazaar check: the pinned pay_to for ${domain} is indexed as a merchant, but ${domain} is not among its registered resources. Verify the merchant identity out-of-band.`,
    details: { domain, pinned: pin.pay_to },
  };
}
