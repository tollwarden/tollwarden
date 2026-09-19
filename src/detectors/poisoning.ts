// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Address-poisoning detection.
 *
 * The attack: an attacker generates a vanity address whose FIRST and LAST
 * characters match an address the victim pays regularly, betting that agents
 * (and humans) verify addresses by their displayed form — "0x2096…287C" —
 * and never check the middle. Poisoned history entries, injected content, and
 * spoofed 402 offers all rely on this truncated-display blind spot.
 *
 * The defense: compare this payment's pay_to against addresses this account
 * has actually paid before (its counterparty history), its own pinned
 * merchants, and CDP-verified global pins. An address that is NOT an exact
 * match but shares a significant prefix AND suffix with a known address is
 * overwhelmingly likely to be adversarial: for random 20-byte addresses, a
 * ≥4-hex-char match on both ends happens by chance ~1 in 4 billion pairs —
 * while vanity-grinding exactly that match costs an attacker seconds.
 *
 * Two trust tiers in the known-good set (audit 2026-09-19, H-2). A lookalike
 * of an address the CALLER established (own history, own pins) or that the
 * CDP index corroborates BLOCKS. A lookalike of an address some OTHER caller
 * merely presented (an unverified global pin) only FLAGS: otherwise an
 * attacker could seed a global pin with a vanity lookalike of the victim's
 * real merchant and have the victim's honest payment blocked as the
 * "lookalike" — client input reaching a block decision.
 *
 * Like pinning, this is a fact about history, not about the agent's
 * narration — it holds even when the agent's context is fully compromised.
 */
import type { CheckResult, ScanRequest } from "../types.ts";
import type { Store } from "../store.ts";
import { stripInvisible } from "./injection.ts";

/** Chars (after "0x") that must match on BOTH ends to call it a lookalike. */
const PREFIX_MIN = 4;
const SUFFIX_MIN = 4;

const EVM_ADDR = /^0x[0-9a-f]{40}$/;

function sharedPrefix(a: string, b: string): number {
  let n = 0;
  while (n < a.length && n < b.length && a[n] === b[n]) n++;
  return n;
}

function sharedSuffix(a: string, b: string): number {
  let n = 0;
  while (n < a.length && n < b.length && a[a.length - 1 - n] === b[b.length - 1 - n]) n++;
  return n;
}

interface KnownAddress {
  address: string;
  source: string; // human-readable provenance for the reason string
  /** True when the caller could not have had this address planted on them by
   * another client: own history, own tenant pin, or a CDP-verified global pin. */
  trusted: boolean;
}

/** Identity the history is scoped under. `key` is the server-resolved tenant
 * when the caller presented an API key, else the client-declared agent_id /
 * payer (anonymous scans). `tenant` is the key hash, or null when anonymous. */
export interface PoisoningScope {
  key?: string;
  tenant?: string | null;
}

function scopeOf(req: ScanRequest, scope?: PoisoningScope): PoisoningScope {
  if (scope) return scope;
  return { key: req.agent_id ?? req.payment.payer?.toLowerCase(), tenant: null };
}

/**
 * Known-good set: this scope's own payment history, its own tenant pins, and
 * global pins split by whether the CDP cross-check verified them. Scoped to
 * the caller's history so one tenant's counterparty list is never revealed
 * through another tenant's scan reasons.
 */
function knownGood(store: Store, scope: PoisoningScope): KnownAddress[] {
  const known: KnownAddress[] = [];
  if (scope.key) {
    for (const addr of store.counterparties.get(scope.key) ?? []) {
      known.push({ address: addr, source: "a counterparty this agent has paid before", trusted: true });
    }
  }
  if (scope.tenant) {
    const prefix = `${scope.tenant}|`;
    for (const [k, pin] of store.tenantPins) {
      if (k.startsWith(prefix)) {
        known.push({ address: pin.pay_to, source: `this account's pinned address for ${k.slice(prefix.length)}`, trusted: true });
      }
    }
  }
  for (const [domain, pin] of store.pins) {
    const verified = pin.cdp_status === "verified";
    known.push({
      address: pin.pay_to,
      source: verified ? `the CDP-verified pinned address for ${domain}` : `an address another caller presented for ${domain}`,
      trusted: verified,
    });
  }
  return known;
}

function bestLookalike(
  candidate: string,
  known: KnownAddress[],
): { k: KnownAddress; pre: number; suf: number } | null {
  const body = candidate.slice(2);
  let best: { k: KnownAddress; pre: number; suf: number } | null = null;
  for (const k of known) {
    if (candidate === k.address || !EVM_ADDR.test(k.address)) continue;
    const kb = k.address.slice(2);
    const pre = sharedPrefix(body, kb);
    const suf = sharedSuffix(body, kb);
    if (pre >= PREFIX_MIN && suf >= SUFFIX_MIN) {
      // Prefer a trusted match over an untrusted one at equal similarity, so
      // an attacker's planted pin can never downgrade a real hit to a flag.
      const better =
        !best ||
        (k.trusted && !best.k.trusted) ||
        (k.trusted === best.k.trusted && pre + suf > best.pre + best.suf);
      if (better) best = { k, pre, suf };
    }
  }
  return best;
}

/**
 * Returns a CheckResult if pay_to is a lookalike of a known-good address
 * (block when the known address is trusted, flag when it is only another
 * caller's unverified observation), or null when there is nothing to report
 * (exact match, no similarity, or nothing to compare against). Must run
 * BEFORE velocity records this scan's counterparty and before pinning writes
 * its pin, so the lookalike is judged against history that does not yet
 * include it.
 */
export function checkAddressPoisoning(req: ScanRequest, store: Store, scope?: PoisoningScope): CheckResult | null {
  const payTo = req.payment.pay_to?.toLowerCase();
  if (!payTo || !EVM_ADDR.test(payTo)) return null; // non-EVM shapes: nothing to compare

  const known = knownGood(store, scopeOf(req, scope));
  if (known.length === 0) return null;

  // Exact match with any known address = the real counterparty. Fine.
  if (known.some((k) => k.address === payTo)) return null;

  const best = bestLookalike(payTo, known);
  if (!best) return null;

  const body = payTo.slice(2);
  const truncated = `"0x${body.slice(0, 4)}…${body.slice(-4)}"`;
  if (best.k.trusted) {
    return {
      id: "poison.lookalike",
      name: "Address poisoning",
      verdict: "block",
      severity: "critical",
      reason:
        `pay_to ${payTo} matches ${best.k.address} (${best.k.source}) on its first ${best.pre} and last ${best.suf} characters but is a DIFFERENT address. ` +
        `Truncated displays (${truncated}) make these indistinguishable — this is the signature of an address-poisoning attack. ` +
        `Verify the full address out-of-band before paying; if this is genuinely a new counterparty, use a distinct agent_id context or pay after human confirmation.`,
      details: {
        presented: payTo,
        similar_to: best.k.address,
        shared_prefix_chars: best.pre,
        shared_suffix_chars: best.suf,
        similar_source: best.k.source,
      },
    };
  }
  return {
    id: "poison.lookalike_observed",
    name: "Address poisoning",
    verdict: "flag",
    severity: "high",
    reason:
      `pay_to ${payTo} matches ${best.k.address} (${best.k.source}) on its first ${best.pre} and last ${best.suf} characters but is a DIFFERENT address. ` +
      `That reference is another caller's unverified observation, so this is a flag rather than a block (either address could be the planted one). ` +
      `Verify the full address out-of-band before paying.`,
    details: {
      presented: payTo,
      similar_to: best.k.address,
      shared_prefix_chars: best.pre,
      shared_suffix_chars: best.suf,
      similar_source: best.k.source,
      scope: "shared_unverified",
    },
  };
}

// Address extraction for content scanning: a full EVM address NOT embedded in
// a longer hex run (so the first 40 chars of a tx hash don't match).
const EVM_ADDR_IN_TEXT = /(?<![0-9a-fA-F])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])/g;

/**
 * Vanity-bait detection in just-read content: an address in the content (or
 * the 402 offer) that is a near-copy of the payment recipient or of a known
 * counterparty/pinned merchant. Exact appearances of pay_to are the injection
 * detector's job; a NEAR-copy is poisoning bait — someone is planting an
 * address designed to be mistaken for the real one under truncated display.
 */
export function checkContentLookalikes(req: ScanRequest, store: Store, scope?: PoisoningScope): CheckResult | null {
  const payTo = req.payment.pay_to?.toLowerCase();
  const text = [req.context?.content, req.context?.offer].filter(Boolean).join("\n");
  if (!text) return null;

  const candidates = new Set<string>();
  for (const m of stripInvisible(text).matchAll(EVM_ADDR_IN_TEXT)) {
    candidates.add(m[0].toLowerCase());
  }
  if (payTo) candidates.delete(payTo);
  if (candidates.size === 0) return null;

  // Reference set: the recipient itself, plus the same known-good set the
  // pay_to poisoning check uses (scoped counterparty history + pins).
  const known: KnownAddress[] = [];
  if (payTo && EVM_ADDR.test(payTo)) {
    known.push({ address: payTo, source: "this payment's recipient", trusted: true });
  }
  known.push(...knownGood(store, scopeOf(req, scope)));
  if (known.length === 0) return null;

  let best: { candidate: string; k: KnownAddress; pre: number; suf: number } | null = null;
  for (const candidate of candidates) {
    const sim = bestLookalike(candidate, known);
    if (!sim) continue;
    const better =
      !best ||
      (sim.k.trusted && !best.k.trusted) ||
      (sim.k.trusted === best.k.trusted && sim.pre + sim.suf > best.pre + best.suf);
    if (better) best = { candidate, ...sim };
  }
  if (!best) return null;

  const origin = req.context?.origin;
  const fromUntrusted = origin === "tool_result" || origin === "fetched_content";
  // Only a TRUSTED reference can carry the block; a near-copy of some other
  // caller's unverified pin is a flag whatever the origin (H-2).
  const block = fromUntrusted && best.k.trusted;
  const body = best.k.address.slice(2);
  return {
    id: "poison.lookalike_in_content",
    name: "Address poisoning",
    verdict: block ? "block" : "flag",
    severity: block ? "critical" : "high",
    reason:
      `The content preceding this payment contains ${best.candidate}, which matches ${best.k.address} (${best.k.source}) on its first ${best.pre} and last ${best.suf} characters but is a DIFFERENT address. ` +
      `Planting a near-copy of a trusted address ("0x${body.slice(0, 4)}…${body.slice(-4)}" under truncated display) is address-poisoning bait. ` +
      `Do not copy payment addresses from this content; verify the recipient out-of-band.`,
    details: {
      found_in_content: best.candidate,
      // The planted bait address (not pay_to) is the attacker-controlled one —
      // the incident ledger records it so a later payment TO the bait flags.
      implicated_address: best.candidate,
      similar_to: best.k.address,
      shared_prefix_chars: best.pre,
      shared_suffix_chars: best.suf,
      similar_source: best.k.source,
      reference_trusted: best.k.trusted,
      origin: origin ?? "unknown",
    },
  };
}
