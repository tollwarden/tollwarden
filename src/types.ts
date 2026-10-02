// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/** TollWarden core types. Zero runtime dependencies. */

export type Verdict = "allow" | "flag" | "block";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Direction = "outgoing" | "incoming";

export type PaymentOrigin =
  | "planning"          // agent's own planning/deliberation step
  | "user_instruction"  // explicit human instruction
  | "tool_result"       // decision was formed after reading a tool result
  | "fetched_content"   // decision was formed after reading a fetched page/doc
  | "unknown";

export interface PaymentDetails {
  /** x402 scheme, e.g. "exact" */
  scheme?: string;
  /** CAIP-2 network id, e.g. "eip155:8453". x402 v1 names ("base") are
   * resolved by networkKey for lookups; the commitment hashes it as sent. */
  network?: string;
  /** Token contract address (e.g. USDC) */
  asset?: string;
  /** Amount in atomic token units (string), e.g. "10000" = $0.01 USDC */
  amount?: string;
  /** Alternative: decimal USD value */
  amount_usd?: number;
  /** Token decimals if amount is atomic units (default 6 = USDC) */
  asset_decimals?: number;
  /** Recipient address */
  pay_to?: string;
  /** Paying agent's address (optional, scopes replay + velocity tracking) */
  payer?: string;
  /** The resource being purchased */
  resource_url?: string;
  description?: string;
  /** Free-text reason the agent recorded for making this payment */
  reason?: string;
  /** Payment nonce (from the signed payment payload) */
  nonce?: string;
  valid_until?: string;
  metadata?: Record<string, string>;
}

export interface ScanContext {
  /** Where the decision to pay originated */
  origin?: PaymentOrigin;
  /** The content the agent just read (tool result / fetched page), for injection analysis */
  content?: string;
  /** URL the content came from, if any */
  content_source_url?: string;
  /**
   * When in the payment flow this scan runs. "pre_sign" = before the client
   * has signed (EIP-3009 nonces don't exist yet, so a missing nonce is
   * expected, not suspicious). "post_sign" or absent = full replay coverage
   * expected.
   */
  phase?: "pre_sign" | "post_sign";
  /**
   * The raw 402 offer / discovery payload (e.g. the `accepts` entry or Bazaar
   * listing) the payment terms came from. The pay_to address is EXPECTED to
   * appear here — it is exempt from the address-provenance check, but still
   * scanned for injection tells. Prose the agent read goes in `content`.
   */
  offer?: string;
}

export interface ScanPolicy {
  /** Run the deep content-analysis tier even below the micropayment threshold */
  force_deep?: boolean;
  /** Skip the deep tier regardless of value (developer policy) */
  skip_deep?: boolean;
}

export interface ScanRequest {
  agent_id?: string;
  payment: PaymentDetails;
  /** What the agent expected this to cost, in USD (e.g. from the 402 quote or a catalog) */
  expected_price_usd?: number;
  context?: ScanContext;
  policy?: ScanPolicy;
}

export interface CheckResult {
  id: string;
  name: string;
  verdict: Verdict;
  severity: Severity;
  reason: string;
  details?: Record<string, unknown>;
}

/** Merchant-pin facts published in the signed evidence record. The point is a
 * DECISION BOUNDARY, not transparency: folding "young pin, corroborated" into
 * a single allow/flag makes a risk-tolerance call that belongs to the wallet
 * owner and depends on payment size. Separate signed fields let a wallet
 * accept a four-minute-old corroborated pin for a cent and refuse it for
 * fifty dollars. */
export interface PinEvidence {
  /** Resource domain the pin is for (lowercased hostname). */
  domain: string;
  /** Whole seconds this domain↔pay_to pin had held at scan time. 0 = first sighting. */
  age_seconds: number;
  /**
   * Named out-of-band sources that positively corroborated the domain↔pay_to
   * binding. Each entry NAMES the source (today: "cdp_bazaar" — the CDP Bazaar
   * merchant index lists this domain among the pinned address's resources);
   * a boolean would erase exactly the distinction that matters, and a
   * composite strength score is the boolean again with decimals. Source
   * strength is a per-merchant property — rank them yourself. Empty = no
   * source has corroborated this pin.
   */
  corroboration: string[];
}

/** Ed25519 attestation over the verdict, so wallet policies can require a TollWarden allow-verdict. */
export interface VerdictAttestation {
  alg: "ed25519";
  /** SPKI DER, hex-encoded. Also served at /.well-known/tollwarden-verdict-key */
  public_key_spki_hex: string;
  /** Signed message: scan_id|direction|verdict|risk_score|scanned_at|payment_commitment|expires_at
   * COMPATIBILITY: this message is FROZEN at 7 fields — deployed verifiers
   * hard-reject any other count. New signed facts go in `evidence`, never here. */
  message: string;
  signature_hex: string;
  /** sha256(network|pay_to|asset|amount|nonce) — binds the verdict to this payment */
  payment_commitment: string;
  /** ISO time after which the attestation must be rejected */
  expires_at: string;
  /**
   * Second signed record carrying scan-time evidence beyond the verdict —
   * currently merchant-pin age and named corroboration sources. Signed by the
   * same verdict key over
   *   evidence-v1|scan_id|payment_commitment|pin_domain|pin_age_seconds|pin_corroboration
   * (pin fields empty when no pin applies to this payment's payee;
   * pin_corroboration is "none" or a comma-joined source list). Bound to the
   * same scan_id + commitment as the verdict message so it cannot be replayed
   * onto another attestation; it shares the attestation's expiry. `pin` is a
   * convenience mirror of EXACTLY the signed-derived fields — verifiers parse
   * the signed message and reject a mirror with anything else (an extra key
   * would be unsigned data riding a verified response); the mirror shape is
   * frozen by that choice. Present on organic scan attestations; override
   * attestations carry no evidence record — and since verifiers tolerate
   * absence for compatibility, an ABSENT record asserts nothing (it could be
   * an older server or stripped in transit); only the signed empty fields
   * assert "no pin applies". Every signed field is a compatibility
   * commitment — fields are added, never silently changed or withdrawn.
   */
  evidence?: {
    message: string;
    signature_hex: string;
    pin: PinEvidence | null;
  };
}

export interface ScanResponse {
  scan_id: string;
  direction: Direction;
  verdict: Verdict;
  /** 0 (clean) – 100 (maximum risk) */
  risk_score: number;
  checks: CheckResult[];
  scanned_at: string;
  advisory: string;
  attestation?: VerdictAttestation;
}

export type ReportCategory =
  | "scam"
  | "non_delivery"
  | "prompt_injection"
  | "overcharge"
  | "impersonation"
  | "replay_abuse"
  | "other";

export interface ReputationReport {
  address: string;
  category: ReportCategory;
  reason: string;
  reporter_agent_id: string;
  evidence_url?: string;
  reported_at: string;
}

/**
 * A system-observed injection incident: a scan BLOCKED with a finding that
 * structurally implicated this address as attacker-controlled (pay_to planted
 * in just-read content, an encoded payload embedding it, or a vanity-bait
 * lookalike found in content). Recorded automatically at scan time — no one
 * has to remember to file a report — so one agent's detection protects every
 * agent's next scan of the same wallet.
 *
 * SECURITY (audit H-2 applies): scan inputs are client-supplied, so a Sybil
 * can stage scans that implicate an honest wallet. Incidents therefore cap at
 * "flag" in scans (never block) and are weighted by observer credibility ×
 * time decay, exactly like self-asserted reports.
 */
export interface InjectionIncident {
  address: string;
  /** The check that implicated the address (e.g. injection.payto_from_content) */
  check_id: string;
  /** Declared payment origin at the time (tool_result, fetched_content, …) */
  origin: string;
  /** Who was scanning: agent_id ?? payer ?? "anon" — the same identity
   * credibility() keys on, so minting fresh observers counts half. */
  observer: string;
  scan_id: string;
  at: string;
}

/** A signed rebuttal from a reported wallet. Verified at submission time:
 * the EIP-191 personal_sign signature over the canonical dispute message
 * (see reputation.ts) must recover to `address`, proving key ownership.
 * The signature is stored and surfaced so third parties can re-verify. */
export interface ReputationDispute {
  address: string;
  statement: string;
  signature: string;
  disputed_at: string;
}

export interface ReputationSummary {
  address: string;
  status: "clean" | "reported";
  risk: "none" | "low" | "medium" | "high";
  report_count: number;
  distinct_reporters: number;
  /** v2 risk input: sum over distinct reporters of credibility × time decay
   * (90-day half-life). Fresh anonymous reporter = 0.5; observed payment
   * history raises credibility toward 1.0. Thresholds: ≥2.5 high, ≥1.0
   * medium, >0.1 low — so five fresh anonymous reporters still grade high,
   * but stale reports fade to "none" in ~7 months instead of forever. */
  weighted_score: number;
  /** Signed, verified rebuttals from the reported wallet (newest first). */
  disputes?: ReputationDispute[];
  categories: Record<string, number>;
  first_reported?: string;
  last_reported?: string;
  /** System-observed injection incidents: scans TollWarden itself BLOCKED where
   * this address was structurally implicated (see InjectionIncident). Weighted
   * like reports (credibility × 90-day decay); null = no incident history. */
  injection_history?: {
    incident_count: number;
    distinct_observers: number;
    weighted_score: number;
    /** Which checks implicated the address, with counts */
    check_ids: Record<string, number>;
    first_at: string;
    last_at: string;
  } | null;
  /** Measured, commitment-bound delivery outcomes, plus the ledger's
   * DENOMINATOR (scans_seen / report_coverage) so selective outcome reporting
   * is legible as low coverage. Null only when TollWarden has neither outcomes
   * nor counted scans for the address; when scans exist but no outcome was
   * ever reported, outcomes_total is 0 and only the coverage fields are
   * present. Coverage is informational only (scan counts are client-driven)
   * and never feeds a flag. */
  delivery?: {
    outcomes_total: number;
    delivered?: number;
    not_delivered?: number;
    partial?: number;
    wrong_content?: number;
    delivery_rate?: number;
    smoothed_delivery_rate?: number;
    distinct_reporters?: number;
    first_at?: string;
    last_at?: string;
    /** Non-blocked scans of this counterparty since the counter began. */
    scans_seen?: number;
    scans_tracked_since?: string | null;
    /** outcomes_total / scans_seen, clamped to [0,1]; null when scans_seen is 0. */
    report_coverage?: number | null;
  } | null;
}
