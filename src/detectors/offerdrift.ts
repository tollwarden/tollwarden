// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Offer drift: does the payment the agent is about to make still match the
 * offer it decided from?
 *
 * Discovery and settlement are two different fetches, and the ecosystem drifts
 * between them in practice. Observed in the wild:
 *
 *   * a seller listed at $0.005 whose live 402 demanded $2.00 — a 400× jump
 *     between the catalogue entry and the paid method;
 *   * a seller advertising scheme `exact` whose paid method answered with
 *     scheme `upto` (usage-billed against a ceiling), which the stock client
 *     cannot construct and which changes the amount from a price into a cap;
 *   * multi-rail offers whose cheap leg is a decoy: the agent reads the $0.001
 *     Base leg and settles a materially more expensive leg on another network.
 *
 * All of these are structural inconsistencies WITHIN one scan request: the
 * client hands TollWarden both the offer it read and the payment it is about to
 * sign, and the two disagree. Forging that inconsistency gains an attacker
 * nothing — it only earns them more scrutiny — so it is not a Sybil-forgeable
 * third-party claim and the pay_to case may block (same rationale as
 * `injection.payto_from_content`). Price, scheme, network and asset drift all
 * have legitimate readings (re-quoting, rail choice) and therefore only flag;
 * hard value ceilings remain the overpayment detector's job.
 *
 * Zero dependencies. Parse-only, no network, no state.
 */
import type { CheckResult, PaymentDetails, ScanContext } from "../types.ts";
import { knownAssetDecimals } from "./asset.ts";
import { DEFAULT_DECIMALS, parseDeclaredDecimals, resolveValue } from "./overpayment.ts";

/** Cap on offer parsing work — offers are small; a huge blob is not an offer. */
const MAX_OFFER_CHARS = 64_000;
/** Below this ratio, price differences are rounding/quote noise. */
const PRICE_FLAG_RATIO = 2;
/** At or above this ratio the drift is severe enough to raise severity. */
const PRICE_HIGH_RATIO = 10;

interface OfferTerms {
  pay_to?: string;
  scheme?: string;
  network?: string;
  asset?: string;
  usd?: number;
  /** Decimals `usd` was computed with, when the offer priced in atomic units. */
  usd_decimals?: number;
  /** How many alternative legs the offer carried, when it was a multi-rail list. */
  legs?: number;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

/**
 * Money in x402 offers appears as an atomic string (`maxAmountRequired`) or as
 * a human price (`price: 0.005`, `price: "$0.005"`). Atomic needs decimals; a
 * bare human number is already USD.
 *
 * Decimals for the ADVERTISED side mirror resolveValue's rule for the payment
 * side. Server-known decimals win (canonical USDC = 6). Otherwise the offer's
 * own declaration (usually the seller's `extra.decimals`) is honored only when
 * it makes the advertised price SMALLER than the 6-decimal reading, i.e.
 * max(declared, 6). The payment side may only read LARGER, so a declaration on
 * either side can widen the measured drift but never narrow it, and for one
 * token the measured payment/offer ratio is never below the ratio of the
 * atomic amounts.
 */
function usdFromOffer(
  o: Record<string, unknown>,
  network: string | undefined,
  asset: string | undefined,
): { usd: number; decimals?: number } | undefined {
  const atomicRaw = o.maxAmountRequired ?? o.amountRequired ?? o.amount;
  if (atomicRaw !== undefined && atomicRaw !== null) {
    const atomic = Number(atomicRaw);
    const declared = parseDeclaredDecimals(
      o.asset_decimals ?? o.assetDecimals ?? (o.extra as Record<string, unknown> | undefined)?.decimals,
    );
    const decimals = knownAssetDecimals(network, asset) ?? Math.max(declared ?? DEFAULT_DECIMALS, DEFAULT_DECIMALS);
    if (Number.isFinite(atomic)) {
      const usd = atomic / 10 ** decimals;
      if (Number.isFinite(usd)) return { usd, decimals };
    }
  }
  const priceRaw = o.price ?? o.price_usd ?? o.priceUsd ?? o.amount_usd ?? o.amountUsd;
  if (typeof priceRaw === "number" && Number.isFinite(priceRaw)) return { usd: priceRaw };
  if (typeof priceRaw === "string") {
    const n = Number(priceRaw.replace(/[$,\s]/g, ""));
    if (Number.isFinite(n)) return { usd: n };
  }
  return undefined;
}

function termsOf(o: Record<string, unknown>): OfferTerms {
  const network = str(o.network ?? o.chain ?? o.chainId ?? o.chain_id);
  const asset = str(o.asset ?? o.token ?? o.currency);
  const value = usdFromOffer(o, network, asset);
  return {
    pay_to: str(o.payTo ?? o.pay_to ?? o.payee ?? o.recipient)?.toLowerCase(),
    scheme: str(o.scheme)?.toLowerCase(),
    network: network?.toLowerCase(),
    asset: asset?.toLowerCase(),
    usd: value?.usd,
    usd_decimals: value?.decimals,
  };
}

/** Collect every candidate offer object out of the shapes sellers actually send. */
function candidateOffers(parsed: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(parsed)) {
    return parsed.filter((x): x is Record<string, unknown> => typeof x === "object" && x !== null);
  }
  if (typeof parsed !== "object" || parsed === null) return [];
  const o = parsed as Record<string, unknown>;
  // x402 envelope: { x402Version, accepts: [...] }. Bazaar listings sometimes
  // nest the same list under `offers` / `items` / `resource`.
  for (const key of ["accepts", "offers", "items"]) {
    const list = o[key];
    if (Array.isArray(list)) {
      const inner = list.filter((x): x is Record<string, unknown> => typeof x === "object" && x !== null);
      if (inner.length > 0) return inner;
    }
  }
  return [o];
}

/**
 * Pick the leg the payment is actually settling. Prefer an exact
 * network+scheme match, then network, then the sole entry — so a multi-rail
 * offer is compared against the rail being paid rather than against its
 * cheapest advertised leg.
 */
function selectLeg(
  legs: Array<Record<string, unknown>>,
  payment: PaymentDetails,
): { terms: OfferTerms | null; matched: boolean } {
  const all = legs.map(termsOf);
  if (all.length === 0) return { terms: null, matched: false };
  const net = payment.network?.toLowerCase();
  const scheme = payment.scheme?.toLowerCase();

  if (net && scheme) {
    const exact = all.find((t) => t.network === net && t.scheme === scheme);
    if (exact) return { terms: { ...exact, legs: all.length }, matched: true };
  }
  if (net) {
    const byNet = all.find((t) => t.network === net);
    if (byNet) return { terms: { ...byNet, legs: all.length }, matched: true };
  }
  // No leg matches the rail being paid. With a single-leg offer that is just
  // the ordinary compare-everything case; with several legs it is the finding.
  return { terms: { ...all[0], legs: all.length }, matched: all.length === 1 };
}

export function checkOfferDrift(
  payment: PaymentDetails,
  context: ScanContext | undefined,
): CheckResult[] {
  const raw = context?.offer;
  if (!raw || raw.length > MAX_OFFER_CHARS) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Offers are frequently pasted as prose or as a header dump. Nothing to
    // compare structurally; the injection tiers still read the text.
    return [];
  }

  const legs = candidateOffers(parsed);
  const { terms, matched } = selectLeg(legs, payment);
  if (!terms) return [];

  const results: CheckResult[] = [];
  const name = "Offer drift";

  // 1. Recipient drift. The offer the agent says it read names one payee; the
  //    payment goes somewhere else. Structural, and the signature of a
  //    redirection between discovery and settlement.
  const payToLc = payment.pay_to?.toLowerCase();
  //
  //    Flag, not block, and deliberately so. Sellers do legitimately rotate
  //    wallets, which makes a catalogue entry stale rather than hostile — and
  //    an agent cannot tell TollWarden whether the offer it passed is the live 402
  //    or a day-old listing. A false-positive BLOCK refuses an honest payment;
  //    a flag stops an unattended agent and asks a human, which is the right
  //    outcome for a payee mismatch either way. The domain-level version of
  //    this (same domain, changed payee, seen before) is `pin.mismatch` and
  //    DOES block, because prior observation removes the staleness excuse.
  if (terms.pay_to && payToLc && terms.pay_to !== payToLc) {
    results.push({
      id: "drift.pay_to",
      name,
      verdict: "flag",
      severity: "critical",
      reason: `The offer this payment came from names recipient ${terms.pay_to}, but the payment is addressed to ${payToLc}. The payee changed between the offer the agent read and the payment it is about to sign — re-fetch the 402 and scan the live offer for the exact method you intend to pay.`,
      details: { offer_pay_to: terms.pay_to, payment_pay_to: payToLc },
    });
  }

  // 2. Multi-rail offers: no advertised leg matches the rail being settled.
  if (!matched && (terms.legs ?? 1) > 1) {
    results.push({
      id: "drift.no_matching_leg",
      name,
      verdict: "flag",
      severity: "medium",
      reason: `The offer advertises ${terms.legs} payment legs, none of which matches this payment's network/scheme (${payment.network ?? "unknown"} / ${payment.scheme ?? "unknown"}). A multi-rail offer whose cheap leg is a decoy settles on a rail the agent never priced — compare against the leg you are actually paying.`,
      details: {
        legs: terms.legs,
        payment_network: payment.network ?? null,
        payment_scheme: payment.scheme ?? null,
      },
    });
  }

  // 3. Scheme drift. `exact` → `upto` turns the amount from a price into a
  //    ceiling billed by usage, which is a materially different commitment.
  const paymentScheme = payment.scheme?.toLowerCase();
  if (terms.scheme && paymentScheme && terms.scheme !== paymentScheme) {
    const toCeiling = paymentScheme === "upto";
    results.push({
      id: "drift.scheme",
      name,
      verdict: "flag",
      severity: toCeiling ? "high" : "medium",
      reason:
        `The offer advertises scheme "${terms.scheme}" but this payment uses scheme "${paymentScheme}".` +
        (toCeiling
          ? " Under `upto` the amount is a usage-billed CEILING, not a price — the settled value can be anything up to it, and the agent priced a fixed charge."
          : " Scheme drift between the advertised offer and the paid method also breaks stock x402 clients, so a failure here may be interop rather than intent."),
      details: { offer_scheme: terms.scheme, payment_scheme: paymentScheme },
    });
  }

  // 4. Rail drift: paying on a network or in an asset the offer did not name.
  const paymentNetwork = payment.network?.toLowerCase();
  // Single-leg offers only: a multi-leg mismatch is already reported, and more
  // precisely, as drift.no_matching_leg above.
  if (terms.network && paymentNetwork && terms.network !== paymentNetwork && (terms.legs ?? 1) === 1) {
    results.push({
      id: "drift.network",
      name,
      verdict: "flag",
      severity: "medium",
      reason: `The offer names network "${terms.network}" but this payment settles on "${paymentNetwork}". Alternative rails frequently carry a materially different real value than the advertised leg.`,
      details: { offer_network: terms.network, payment_network: paymentNetwork },
    });
  }
  const paymentAsset = payment.asset?.toLowerCase();
  if (terms.asset && paymentAsset && terms.asset !== paymentAsset) {
    results.push({
      id: "drift.asset",
      name,
      verdict: "flag",
      severity: "medium",
      reason: `The offer names asset ${terms.asset} but this payment sends ${paymentAsset}. Confirm the asset before settling — token identity is what determines the real value transferred.`,
      details: { offer_asset: terms.asset, payment_asset: paymentAsset },
    });
  }

  // 5. Price drift. Direction matters: paying MORE than advertised is the
  //    bait-and-switch; paying less is usually a stale quote and merely gets
  //    rejected by the seller.
  const paymentValue = resolveValue(payment);
  const paymentUsd = paymentValue.usd;
  if (terms.usd !== undefined && terms.usd > 0 && paymentUsd !== null && paymentUsd > 0) {
    const ratio = paymentUsd / terms.usd;
    if (ratio >= PRICE_FLAG_RATIO || ratio <= 1 / PRICE_FLAG_RATIO) {
      const up = ratio >= 1;
      const factor = up ? ratio : 1 / ratio;
      results.push({
        id: "drift.price",
        name,
        verdict: "flag",
        severity: up && ratio >= PRICE_HIGH_RATIO ? "high" : "medium",
        reason: `This payment is ${factor.toFixed(1)}× ${up ? "MORE" : "less"} than the offer it came from: offer $${terms.usd.toFixed(6)}, payment $${paymentUsd.toFixed(6)}.${up ? " A live 402 demanding far more than its catalogue listing is a price trap — the live offer is what you pay, so price the live 402, not the listing." : " A payment below the advertised price is normally a stale quote and will simply be refused."}`,
        details: {
          offer_usd: terms.usd,
          payment_usd: paymentUsd,
          ratio,
          offer_decimals: terms.usd_decimals ?? null,
          payment_decimals: paymentValue.decimals ?? null,
        },
      });
    }
  }

  if (results.length === 0) {
    results.push({
      id: "drift.clean",
      name,
      verdict: "allow",
      severity: "info",
      reason: `Payment terms match the offer supplied in context.offer${(terms.legs ?? 1) > 1 ? ` (leg ${terms.network ?? "?"}/${terms.scheme ?? "?"} of ${terms.legs})` : ""}.`,
    });
  }
  return results;
}

// ---------------------------------------------------------------------------
// Freshness claims
// ---------------------------------------------------------------------------

/**
 * Words that sell recency as the product. Deliberately narrow: these are
 * claims about the DATA being current, not generic marketing adjectives.
 */
const FRESHNESS_CLAIM =
  /\b(?:real[\s-]?time|realtime|live|up[\s-]?to[\s-]?(?:the[\s-]?)?(?:date|minute|second)|current(?:ly)?|latest|most recent|recent|fresh|instant|streaming|as[\s-]of|intraday|spot price|now)\b/i;

/**
 * Fields by which a seller binds its own answer to a validity window. When an
 * offer advertises these, the seller has published a checkable contract.
 */
const FRESHNESS_CONTRACT_FIELD =
  /\b(?:validUntilBlock|valid_until|validUntil|computedAtBlock|computed_at|data_as_of|dataAsOf|as_of|asOf|expires_at|expiresAt|data_age|dataAge|timestamp|updated_at|updatedAt)\b/;

/**
 * A seller that sells "recent" data can deliver a stale snapshot and still
 * look like a successful settlement: HTTP 200, well-formed body, plausible
 * shape. Two real cases drove this — a "recent earthquakes" feed that served a
 * 30-day-old broadcast reporting zero events against 411 real ones upstream,
 * and a token-metadata endpoint that answered ~1,800 blocks past its OWN
 * declared `validUntilBlock`.
 *
 * Neither is detectable from the offer alone; both are trivially detectable at
 * verification time IF the buyer knows to look. So this check does not judge
 * the seller — it is a pre-purchase advisory that fires when the offer sells
 * recency, telling the agent which check to run before it reports `delivered`.
 *
 * Informational by construction: advertising fresh data is not suspicious, and
 * flagging it would dead-end unattended agents on the large and mostly honest
 * population of live-data sellers. It costs nothing when ignored and converts a
 * silent `delivered` into a defensible `wrong_content` when heeded.
 */
export function checkFreshnessClaim(
  payment: PaymentDetails,
  context: ScanContext | undefined,
): CheckResult[] {
  const offer = context?.offer ?? "";
  const described = `${payment.description ?? ""} ${payment.resource_url ?? ""}`;
  const haystack = `${offer} ${described}`;
  if (haystack.length > MAX_OFFER_CHARS) return [];

  const claim = haystack.match(FRESHNESS_CLAIM);
  if (!claim) return [];
  const contractField = haystack.match(FRESHNESS_CONTRACT_FIELD);

  return [
    {
      id: "freshness.claim_advertised",
      name: "Freshness contract",
      verdict: "allow",
      severity: "info",
      reason:
        `This offer sells recency ("${claim[0]}")${contractField ? ` and publishes its own validity field \`${contractField[0]}\`` : ""}. ` +
        (contractField
          ? `Before reporting delivery, check the response against that field: a value served past its own declared window is a broken freshness contract regardless of how well-formed the body is.`
          : `Before reporting delivery, compare at least one volatile value against a free upstream reference captured at purchase time. A stale snapshot returns HTTP 200 with a plausible body, so settlement success is not evidence of freshness.`) +
        ` Report \`wrong_content\` or \`partial\` when the data does not match its claimed recency.`,
      details: {
        claim: claim[0],
        contract_field: contractField ? contractField[0] : null,
      },
    },
  ];
}
