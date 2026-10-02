// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * @tollwarden/client — official client SDK for TollWarden, the payment security
 * firewall for x402 micropayments (https://tollwarden.com).
 *
 * Zero runtime dependencies. Node 18+ (global fetch; node:crypto for Ed25519).
 *
 * What it adds over raw HTTP:
 *  - Provenance auto-tagging: call `observe()` whenever your agent reads
 *    external content (tool results, fetched pages); scans are automatically
 *    tagged with `context.origin` + the content, which powers TollWarden's
 *    prompt-injection-triggered-payment detection.
 *  - API key management: mints a key on first use, tracks the free-call quota.
 *  - Plans: subscribe/renew autonomously when constructed with an x402
 *    payment-capable fetch (e.g. wrapFetchWithPayment from @x402/fetch).
 *  - Attestation verification: every scan response's Ed25519 attestation is
 *    checked against a pinned server key, the payment commitment is recomputed
 *    locally, and expiry is enforced — so a tampered or replayed verdict fails.
 *
 * Quick start:
 *   import { TollWardenClient } from "@tollwarden/client";
 *   const tollwarden = new TollWardenClient();
 *   tollwarden.observe(toolResultText, { sourceUrl: "https://api.example.com" });
 *   const scan = await tollwarden.guardOutgoing(payment, { expectedPriceUsd: 0.01 });
 *   // throws TollWardenBlockedError on a block verdict; otherwise safe to settle
 */
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

// Wallet-side enforcement kit: TollWardenEnforcer, guardSigner, paymentFromTypedData.
export * from "./enforce.ts";
// Default-payment-path wrapper: wrapFetchWithTollWarden (scan before every x402 payment).
export * from "./wrap.ts";

// ---------------------------------------------------------------------------
// Types (mirrors the server's public API)
// ---------------------------------------------------------------------------
export type Verdict = "allow" | "flag" | "block" | "override:allow";
export type PaymentOrigin = "planning" | "user_instruction" | "tool_result" | "fetched_content" | "unknown";
/** When in the payment flow a scan runs. "pre_sign" = before the payment is
 * signed, so it has no nonce yet and the server does not flag the missing
 * one. A nonce that IS present is replay-checked either way. Absent means
 * post_sign. */
export type ScanPhase = "pre_sign" | "post_sign";

export interface PaymentDetails {
  scheme?: string;
  network?: string;
  asset?: string;
  amount?: string;
  amount_usd?: number;
  asset_decimals?: number;
  pay_to?: string;
  payer?: string;
  resource_url?: string;
  description?: string;
  reason?: string;
  nonce?: string;
  valid_until?: string;
  metadata?: Record<string, string>;
}

export interface CheckResult {
  id: string;
  name: string;
  verdict: Verdict;
  severity: "info" | "low" | "medium" | "high" | "critical";
  reason: string;
  details?: Record<string, unknown>;
}

/** Merchant-pin facts from the attestation's signed evidence record. Whether
 * a young or uncorroborated pin is acceptable is YOUR decision boundary —
 * e.g. accept a four-minute-old corroborated pin for a cent, refuse it for
 * fifty dollars. */
export interface PinEvidence {
  /** Resource domain the pin is for (lowercased hostname). */
  domain: string;
  /** Whole seconds the domain↔pay_to pin had held at scan time. 0 = first sighting. */
  age_seconds: number;
  /** NAMED out-of-band sources that corroborated the pin (e.g. "cdp_bazaar").
   * Deliberately not a boolean and never a score — source strength is a
   * per-merchant property; rank them yourself. Empty = uncorroborated. */
  corroboration: string[];
}

export interface VerdictAttestation {
  alg: "ed25519";
  public_key_spki_hex: string;
  /** 7-field verdict message (frozen format):
   * scan_id|direction|verdict|risk_score|scanned_at|payment_commitment|expires_at */
  message: string;
  signature_hex: string;
  payment_commitment: string;
  expires_at: string;
  /** Second signed record (same key) over
   * evidence-v1|scan_id|payment_commitment|pin_domain|pin_age_seconds|pin_corroboration
   * — bound to this scan + commitment; shares the attestation's expiry.
   * `pin` mirrors the signed fields for convenience; verifyAttestation
   * cross-checks it against the message. Absent on override attestations and
   * on servers predating the evidence record. */
  evidence?: {
    message: string;
    signature_hex: string;
    pin: PinEvidence | null;
  };
}

export interface ScanResponse {
  scan_id: string;
  direction: "outgoing" | "incoming";
  verdict: Verdict;
  risk_score: number;
  checks: CheckResult[];
  scanned_at: string;
  advisory: string;
  attestation?: VerdictAttestation;
  /** Added by the SDK: result of local attestation verification (absent when verification is disabled). */
  attestation_verified?: boolean;
  /** Added by the SDK after verifying the attestation's signed evidence
   * record: the merchant-pin facts, or null when no pin applies to this
   * payment's payee. Absent (undefined) when the server sent no evidence
   * record or verification is disabled. */
  pin_evidence?: PinEvidence | null;
  /** Present on a flag verdict when the key has human-in-the-loop approvals
   * configured: a human is being asked to decide. Poll with waitForApproval(). */
  approval?: PendingApproval;
}

/** Attached to a flag scan when the operator has approvals configured. */
export interface PendingApproval {
  approval_id: string;
  status: "pending";
  expires_at: string;
  poll: string;
  note: string;
}

/** GET /v1/approvals/{id} response shape. */
export interface ApprovalState {
  approval_id: string;
  scan_id: string;
  status: "pending" | "approved" | "denied" | "expired";
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  /** Scan-shaped override (verdict "override:allow" + attestation), present when approved. */
  override?: ScanResponse;
}

export interface ScanOptions {
  agentId?: string;
  expectedPriceUsd?: number;
  /** Explicit provenance; overrides the automatic observation-based tagging. */
  context?: { origin?: PaymentOrigin; content?: string; content_source_url?: string; phase?: ScanPhase };
  /** Sent as `context.phase` ALONGSIDE whichever provenance applies, so
   * unlike `context` it keeps the automatic observation-based tagging. Wins
   * over `context.phase`. wrapFetchWithTollWarden sets "pre_sign". */
  phase?: ScanPhase;
  policy?: { force_deep?: boolean; skip_deep?: boolean };
  /** With guard*: also throw on "flag" verdicts (default: only "block"). */
  strict?: boolean;
}

export interface PlanInfo {
  id: string;
  name: string;
  price: string;
  duration_days: number | null;
  description: string;
  limits: Record<string, unknown>;
}

export interface ClientOptions {
  /** Service base URL. Default: https://tollwarden.com */
  baseUrl?: string;
  /** Existing API key. If omitted and autoKey is on, one is minted on first use. */
  apiKey?: string;
  /** Mint an API key automatically on first use (100 free calls). Default: true. */
  autoKey?: boolean;
  /** Stable agent identifier — scopes TollWarden's velocity limits to your agent. */
  agentId?: string;
  /**
   * fetch implementation. Pass an x402 payment-capable fetch (e.g.
   * wrapFetchWithPayment from @x402/fetch) to transparently pay for scans
   * beyond the free tier and for plan subscriptions. Default: global fetch.
   */
  fetch?: typeof fetch;
  /** Origin used when no observation/explicit context exists. Default: "unknown". */
  defaultOrigin?: PaymentOrigin;
  /** How long an observation stays "recent" for auto-tagging. Default: 5 minutes. */
  observationTtlMs?: number;
  /** Max bytes of observed content attached to a scan. Default: 8192. */
  maxContentBytes?: number;
  /** Verify each scan's Ed25519 attestation against the pinned server key. Default: true. */
  verifyAttestations?: boolean;
  /** Pin the server verdict key (hex SPKI DER). Default: fetched once from /.well-known/tollwarden-verdict-key. */
  verdictKeyHex?: string;
  /** Re-subscribe automatically when the active plan is within renewWindowMs of expiry. Default: false (spends money). */
  autoRenew?: boolean;
  /** Renewal window. Default: 24h. */
  renewWindowMs?: number;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
export class TollWardenError extends Error {
  readonly status?: number;
  readonly body?: unknown;
  constructor(message: string, status?: number, body?: unknown) {
    super(message);
    this.name = "TollWardenError";
    this.status = status;
    this.body = body;
  }
}

/** Thrown by guardOutgoing/guardIncoming when the verdict is block (or flag in strict mode). */
export class TollWardenBlockedError extends TollWardenError {
  readonly scan: ScanResponse;
  constructor(scan: ScanResponse) {
    super(
      `TollWarden verdict: ${scan.verdict} (risk ${scan.risk_score}). ` +
        scan.checks
          .filter((c) => c.verdict !== "allow")
          .map((c) => `${c.id}: ${c.reason}`)
          .join("; "),
    );
    this.name = "TollWardenBlockedError";
    this.scan = scan;
  }
}

export class AttestationError extends TollWardenError {
  constructor(message: string) {
    super(message);
    this.name = "AttestationError";
  }
}

// ---------------------------------------------------------------------------
// Attestation verification (standalone — usable without a client instance)
// ---------------------------------------------------------------------------

/** Recomputes the server's payment commitment: sha256(network|pay_to↓|asset↓|amount|nonce). */
export function computePaymentCommitment(p: PaymentDetails): string {
  const amount =
    p.amount !== undefined ? String(p.amount)
    : p.amount_usd !== undefined ? `usd:${p.amount_usd}`
    : "";
  const canonical = [
    p.network ?? "",
    (p.pay_to ?? "").toLowerCase(),
    (p.asset ?? "").toLowerCase(),
    amount,
    p.nonce ?? "",
  ].join("|");
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

/** Parsed, signature-verified evidence from an attestation. `pin` is null when
 * the (verified) record states no pin applies to this payment's payee. */
export interface VerifiedEvidence {
  pin: PinEvidence | null;
}

/**
 * Full attestation check. Throws AttestationError with a specific reason on
 * any failure. Checks, in order:
 *  1. signature over `message` verifies under `trustedKeyHex` (the PINNED key —
 *     never the key embedded in the response, which an attacker controls);
 *  2. message fields match the scan (id, direction, verdict, risk, time);
 *  3. the commitment in the message matches one recomputed from `payment`;
 *  4. the attestation has not expired;
 *  5. when a signed evidence record is present: its signature verifies under
 *     the same pinned key, it is bound to this same scan_id + commitment, and
 *     the `pin` convenience mirror matches the signed message.
 *
 * Returns the verified evidence ({pin: PinEvidence | null}), or null when the
 * attestation carries no evidence record this SDK version can parse (older
 * server, override attestation, or a future evidence version).
 */
export function verifyAttestation(
  scan: ScanResponse,
  payment: PaymentDetails,
  trustedKeyHex: string,
  now: Date = new Date(),
): VerifiedEvidence | null {
  const att = scan.attestation;
  if (!att) throw new AttestationError("scan carries no attestation");

  // Definite-assignment assertion: the catch below always rethrows, so every
  // path that reaches the evidence check has an assigned key.
  let key!: ReturnType<typeof createPublicKey>;
  let ok = false;
  try {
    key = createPublicKey({ key: Buffer.from(trustedKeyHex, "hex"), format: "der", type: "spki" });
    ok = edVerify(null, Buffer.from(att.message, "utf8"), key, Buffer.from(att.signature_hex, "hex"));
  } catch (e) {
    throw new AttestationError(`signature check failed to run: ${(e as Error).message}`);
  }
  if (!ok) throw new AttestationError("Ed25519 signature invalid under the pinned server key");

  const [scanId, direction, verdict, risk, scannedAt, commitment, expiresAt] = att.message.split("|");
  if (scanId !== scan.scan_id || direction !== scan.direction || verdict !== scan.verdict ||
      Number(risk) !== scan.risk_score || scannedAt !== scan.scanned_at) {
    throw new AttestationError("attested message does not match the scan response fields");
  }
  const recomputed = computePaymentCommitment(payment);
  if (commitment !== recomputed) {
    throw new AttestationError(
      "payment commitment mismatch — this attestation was issued for a DIFFERENT payment (possible attestation replay)",
    );
  }
  if (Date.parse(expiresAt) <= now.getTime()) {
    throw new AttestationError(`attestation expired at ${expiresAt}`);
  }

  // --- signed evidence record (pin age + named corroboration sources) ---
  const ev = att.evidence;
  if (!ev) return null; // older server or an override attestation
  let evOk = false;
  try {
    evOk = edVerify(null, Buffer.from(ev.message, "utf8"), key, Buffer.from(ev.signature_hex, "hex"));
  } catch (e) {
    throw new AttestationError(`evidence signature check failed to run: ${(e as Error).message}`);
  }
  if (!evOk) throw new AttestationError("evidence signature invalid under the pinned server key");

  const parts = ev.message.split("|");
  if (parts[0] !== "evidence-v1") return null; // authenticated but not a version this SDK parses
  if (parts.length !== 6) throw new AttestationError("malformed evidence-v1 message");
  const [, evScanId, evCommitment, domain, age, sources] = parts;
  if (evScanId !== scan.scan_id || evCommitment !== commitment) {
    throw new AttestationError(
      "evidence record is bound to a DIFFERENT scan/payment (possible evidence replay)",
    );
  }
  let pin: PinEvidence | null = null;
  if (domain) {
    // ASCII-digit grammar, exactly like the Python SDK — Number() coercion
    // would admit "1e3"/"0x10"/" 5" and split a mixed-language fleet.
    if (!/^[0-9]+$/.test(age)) {
      throw new AttestationError("malformed evidence-v1 message: pin_age_seconds is not a non-negative integer");
    }
    pin = {
      domain,
      age_seconds: Number(age),
      corroboration: sources && sources !== "none" ? sources.split(",") : [],
    };
  }
  // The convenience mirror must be EXACTLY the signed-derived fields (or null):
  // the mirror is the one unsigned part of the attestation, so an extra key
  // here would be unsigned data riding a verified response into code that
  // lazily reads att.evidence.pin. Strict by deliberate, documented choice —
  // all three verifiers (TS, Python, MCP) reject extras identically, so a
  // future server that grew the mirror would fail its own SDK tests instead
  // of breaking deployed fleets one language at a time. Compared field-wise,
  // never by serialization: JSON key order is not meaningful.
  if (ev.pin !== undefined) {
    const m = ev.pin;
    const mirrorMatches =
      m === null
        ? pin === null
        : pin !== null &&
          typeof m === "object" &&
          Object.keys(m).length === 3 &&
          m.domain === pin.domain &&
          m.age_seconds === pin.age_seconds &&
          Array.isArray(m.corroboration) &&
          m.corroboration.length === pin.corroboration.length &&
          m.corroboration.every((s, i) => s === pin!.corroboration[i]);
    if (!mirrorMatches) {
      throw new AttestationError("evidence `pin` mirror does not match the signed evidence message");
    }
  }
  return { pin };
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------
interface Observation {
  content: string;
  sourceUrl?: string;
  kind: "tool_result" | "fetched_content";
  at: number;
}

export class TollWardenClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly autoKey: boolean;
  private readonly agentId?: string;
  private readonly defaultOrigin: PaymentOrigin;
  private readonly observationTtlMs: number;
  private readonly maxContentBytes: number;
  private readonly shouldVerify: boolean;
  private readonly autoRenew: boolean;
  private readonly renewWindowMs: number;

  private apiKey?: string;
  private pinnedKeyHex?: string;
  private lastObservation: Observation | null = null;
  private explicitOrigin: PaymentOrigin | null = null;

  /** Free calls left on the current key, per the last response header (null = unknown). */
  freeCallsRemaining: number | null = null;
  /** Active plan state, tracked from subscribe() responses. */
  plan: { id: string; expires_at: string } | null = null;

  constructor(opts: ClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? "https://tollwarden.com").replace(/\/+$/, "");
    this.fetchImpl = opts.fetch ?? fetch;
    this.apiKey = opts.apiKey;
    this.autoKey = opts.autoKey ?? true;
    this.agentId = opts.agentId;
    this.defaultOrigin = opts.defaultOrigin ?? "unknown";
    this.observationTtlMs = opts.observationTtlMs ?? 5 * 60_000;
    this.maxContentBytes = opts.maxContentBytes ?? 8192;
    this.shouldVerify = opts.verifyAttestations ?? true;
    this.pinnedKeyHex = opts.verdictKeyHex;
    this.autoRenew = opts.autoRenew ?? false;
    this.renewWindowMs = opts.renewWindowMs ?? 24 * 3600_000;
  }

  // -- provenance -----------------------------------------------------------

  /**
   * Record that the agent just read external content. Call this after every
   * tool result / fetched page your agent processes; the next scan within the
   * observation TTL is tagged with it, enabling injection-triggered-payment
   * detection. Content is truncated to maxContentBytes.
   */
  observe(content: string, meta: { sourceUrl?: string; kind?: "tool_result" | "fetched_content" } = {}): void {
    this.lastObservation = {
      content: content.slice(0, this.maxContentBytes),
      sourceUrl: meta.sourceUrl,
      kind: meta.kind ?? (meta.sourceUrl ? "fetched_content" : "tool_result"),
      at: Date.now(),
    };
    this.explicitOrigin = null;
  }

  /** Mark that the NEXT payment decision came from the agent's own planning step. */
  notePlanning(): void {
    this.explicitOrigin = "planning";
    this.lastObservation = null;
  }

  /** Mark that the NEXT payment decision came from an explicit human instruction. */
  noteUserInstruction(): void {
    this.explicitOrigin = "user_instruction";
    this.lastObservation = null;
  }

  private buildContext(explicit?: ScanOptions["context"], phase?: ScanPhase): { origin: PaymentOrigin; content?: string; content_source_url?: string; phase?: ScanPhase } {
    // Phase says WHEN the scan runs, not where the decision came from, so it
    // rides along with whichever provenance applies and never replaces it.
    const p = phase ?? explicit?.phase;
    const ctx = this.provenanceContext(explicit);
    return p === undefined ? ctx : { ...ctx, phase: p };
  }

  private provenanceContext(explicit?: ScanOptions["context"]): { origin: PaymentOrigin; content?: string; content_source_url?: string } {
    if (explicit) return { origin: explicit.origin ?? this.defaultOrigin, content: explicit.content, content_source_url: explicit.content_source_url };
    if (this.explicitOrigin) return { origin: this.explicitOrigin };
    const obs = this.lastObservation;
    if (obs && Date.now() - obs.at <= this.observationTtlMs) {
      return { origin: obs.kind, content: obs.content, content_source_url: obs.sourceUrl };
    }
    return { origin: this.defaultOrigin };
  }

  // -- plumbing --------------------------------------------------------------

  private async request(method: string, path: string, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.apiKey) headers["x-api-key"] = this.apiKey;
    return this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  private async requestJson<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.request(method, path, body);
    const remaining = res.headers.get("x-free-calls-remaining");
    if (remaining !== null) this.freeCallsRemaining = Number(remaining);
    let parsed: unknown = null;
    try {
      parsed = await res.json();
    } catch {
      /* non-JSON error body */
    }
    if (!res.ok) {
      const msg = (parsed as { error?: string } | null)?.error ?? `HTTP ${res.status}`;
      if (res.status === 402) {
        throw new TollWardenError(
          "Payment required and this client's fetch cannot pay. Construct TollWardenClient with an x402 payment-capable fetch (e.g. wrapFetchWithPayment from @x402/fetch), supply an API key with free calls remaining, or subscribe to a plan.",
          402,
          parsed,
        );
      }
      throw new TollWardenError(msg, res.status, parsed);
    }
    return parsed as T;
  }

  /** Mint an API key if none is set (autoKey). Returns the active key. */
  async ensureApiKey(): Promise<string> {
    if (this.apiKey) return this.apiKey;
    if (!this.autoKey) throw new TollWardenError("no API key set and autoKey is disabled");
    const r = await this.requestJson<{ api_key: string; free_calls_remaining?: number }>(
      "POST",
      "/v1/keys",
      this.agentId ? { agent_id: this.agentId } : {},
    );
    this.apiKey = r.api_key;
    if (typeof r.free_calls_remaining === "number") this.freeCallsRemaining = r.free_calls_remaining;
    return this.apiKey;
  }

  /** The pinned verdict key (fetched once from /.well-known/tollwarden-verdict-key unless supplied). */
  async verdictKey(): Promise<string> {
    if (this.pinnedKeyHex) return this.pinnedKeyHex;
    const r = await this.requestJson<{ public_key_spki_hex: string }>("GET", "/.well-known/tollwarden-verdict-key");
    this.pinnedKeyHex = r.public_key_spki_hex;
    return this.pinnedKeyHex;
  }

  // -- scans -----------------------------------------------------------------

  private async scan(direction: "outgoing" | "incoming", payment: PaymentDetails, opts: ScanOptions = {}): Promise<ScanResponse> {
    await this.ensureApiKey().catch(() => undefined); // scanning without a key still works via x402-paid fetch
    await this.maybeRenew();
    const body = {
      agent_id: opts.agentId ?? this.agentId,
      payment,
      expected_price_usd: opts.expectedPriceUsd,
      context: this.buildContext(opts.context, opts.phase),
      policy: opts.policy,
    };
    const scan = await this.requestJson<ScanResponse>("POST", `/v1/scan/${direction}`, body);
    if (this.shouldVerify && scan.attestation) {
      const evidence = verifyAttestation(scan, payment, await this.verdictKey()); // throws on tamper/replay/expiry
      scan.attestation_verified = true;
      if (evidence) scan.pin_evidence = evidence.pin;
    }
    // A consumed observation shouldn't leak provenance onto unrelated later scans.
    this.lastObservation = null;
    this.explicitOrigin = null;
    return scan;
  }

  /** Scan a payment the agent is about to make. Returns the verdict; never throws on flag/block. */
  scanOutgoing(payment: PaymentDetails, opts?: ScanOptions): Promise<ScanResponse> {
    return this.scan("outgoing", payment, opts);
  }

  /** Scan a 402 offer / payment request the agent received. */
  scanIncoming(payment: PaymentDetails, opts?: ScanOptions): Promise<ScanResponse> {
    return this.scan("incoming", payment, opts);
  }

  /** Scan and THROW TollWardenBlockedError on block (and on flag when opts.strict). */
  async guardOutgoing(payment: PaymentDetails, opts: ScanOptions = {}): Promise<ScanResponse> {
    const scan = await this.scan("outgoing", payment, opts);
    if (scan.verdict === "block" || (opts.strict && scan.verdict === "flag")) throw new TollWardenBlockedError(scan);
    return scan;
  }

  /** Scan an incoming offer and THROW on block (and on flag when opts.strict). */
  async guardIncoming(payment: PaymentDetails, opts: ScanOptions = {}): Promise<ScanResponse> {
    const scan = await this.scan("incoming", payment, opts);
    if (scan.verdict === "block" || (opts.strict && scan.verdict === "flag")) throw new TollWardenBlockedError(scan);
    return scan;
  }

  // -- human-in-the-loop approvals ---------------------------------------------

  /**
   * Wait for a human decision on a flagged scan (requires the operator to have
   * configured approvals via POST /v1/approvals/config). Polls until approved,
   * denied, expired, or timeout.
   *
   *   const scan = await tollwarden.scanOutgoing(payment);
   *   if (scan.verdict === "flag" && scan.approval) {
   *     const override = await tollwarden.waitForApproval(scan, { payment });
   *     enforcer.approve(override, payment); // needs acceptOverrides: true
   *   }
   *
   * Returns the override scan-shaped object (verdict "override:allow", signed
   * attestation bound to the payment commitment). Throws TollWardenError on deny/
   * expiry/timeout. When opts.payment is supplied (recommended) and this client
   * verifies attestations, the override is verified against the pinned key and
   * that exact payment before being returned.
   */
  async waitForApproval(
    scanOrId: ScanResponse | string,
    opts: { timeoutMs?: number; intervalMs?: number; payment?: PaymentDetails } = {},
  ): Promise<ScanResponse> {
    const approvalId = typeof scanOrId === "string" ? scanOrId : scanOrId.approval?.approval_id;
    if (!approvalId) {
      throw new TollWardenError(
        "no approval to wait for: the scan carries no `approval` (either the verdict was not flag, or the key has no approvals config — POST /v1/approvals/config first)",
      );
    }
    const timeoutMs = opts.timeoutMs ?? 600_000; // matches the default pending TTL
    const intervalMs = Math.max(opts.intervalMs ?? 3000, 250);
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const state = await this.requestJson<ApprovalState>("GET", `/v1/approvals/${encodeURIComponent(approvalId)}`);
      if (state.status === "approved" && state.override) {
        if (this.shouldVerify && state.override.attestation && opts.payment) {
          verifyAttestation(state.override, opts.payment, await this.verdictKey());
          state.override.attestation_verified = true;
        }
        return state.override;
      }
      if (state.status === "denied") throw new TollWardenError(`approval ${approvalId} was DENIED by the operator`, 403, state);
      if (state.status === "expired") throw new TollWardenError(`approval ${approvalId} expired before a decision`, 410, state);
      if (Date.now() + intervalMs > deadline) throw new TollWardenError(`timed out waiting for approval ${approvalId}`, 408, state);
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }

  /**
   * Configure (or disable, with webhookUrl: null) human-in-the-loop approvals
   * for this key. Returns the webhook signing secret ONCE — store it; every
   * delivery carries X-TollWarden-Signature: sha256=HMAC-SHA256(secret, body).
   * SECURITY: the decide link each delivery carries is a bearer credential —
   * point the webhook somewhere the agent itself cannot read.
   */
  async configureApprovals(webhookUrl: string | null, opts: { format?: "json" | "slack" } = {}): Promise<{ enabled: boolean; webhook_secret?: string }> {
    await this.ensureApiKey();
    return this.requestJson("POST", "/v1/approvals/config", { webhook_url: webhookUrl, format: opts.format });
  }

  // -- delivery outcomes ---------------------------------------------------------

  /**
   * Record whether a scanned, settled payment actually DELIVERED. The report
   * is bound to the scan (scan_id + payment_commitment), so delivery history
   * can't be fabricated without real, scanned payments. One outcome per scan.
   * The payment-path wrapper (wrapFetchWithTollWarden) calls this automatically;
   * call it yourself when you settle payments some other way.
   */
  async reportOutcome(
    scan: ScanResponse,
    outcome: "delivered" | "not_delivered" | "partial" | "wrong_content",
    evidence?: {
      status?: number;
      contentType?: string;
      bytes?: number;
      latencyMs?: number;
      /**
       * Whether the paid response carried a settlement-receipt header. Pass
       * "absent" when the transfer is visible on-chain but the seller returned
       * no receipt: such calls read as FREE to a stock client, and future
       * buyers get flagged to reconcile on-chain rather than pay twice.
       */
      settlementReceipt?: "present" | "absent";
    },
  ): Promise<unknown> {
    const commitment = scan.attestation?.payment_commitment;
    if (!commitment) {
      throw new TollWardenError("cannot report an outcome: the scan carries no attestation/payment_commitment (verdict signing disabled?)");
    }
    return this.requestJson("POST", "/v1/outcomes", {
      scan_id: scan.scan_id,
      payment_commitment: commitment,
      outcome,
      evidence: evidence
        ? {
            status: evidence.status,
            content_type: evidence.contentType,
            bytes: evidence.bytes,
            latency_ms: evidence.latencyMs,
            settlement_receipt: evidence.settlementReceipt,
          }
        : undefined,
    });
  }

  // -- reputation --------------------------------------------------------------

  /** File a counterparty report (always free). */
  async report(input: { address: string; category: string; reason: string; reporterAgentId?: string; evidenceUrl?: string }): Promise<unknown> {
    return this.requestJson("POST", "/v1/reputation/report", {
      address: input.address,
      category: input.category,
      reason: input.reason,
      reporter_agent_id: input.reporterAgentId ?? this.agentId ?? "@tollwarden/client",
      evidence_url: input.evidenceUrl,
    });
  }

  /** Counterparty report summary (paid / free-tier). */
  async reputation(address: string): Promise<unknown> {
    await this.ensureApiKey().catch(() => undefined);
    return this.requestJson("GET", `/v1/reputation/${encodeURIComponent(address)}`);
  }

  // -- plans --------------------------------------------------------------------

  /** Machine-readable plan catalog (free). */
  async getPlans(): Promise<{ plans: PlanInfo[]; hard_ceilings: Record<string, number> }> {
    return this.requestJson("GET", "/v1/plans");
  }

  /**
   * Subscribe the current key to a plan (or renew it). Requires an x402
   * payment-capable fetch — the endpoint is paid at the plan's price. A key is
   * minted first if none exists.
   */
  async subscribe(planId: string): Promise<{ plan: string; expires_at: string }> {
    await this.ensureApiKey();
    const r = await this.requestJson<{ plan: string; expires_at: string; api_key?: string }>(
      "POST",
      "/v1/plans/subscribe",
      { plan: planId, agent_id: this.agentId },
    );
    if (r.api_key) this.apiKey = r.api_key;
    this.plan = { id: r.plan, expires_at: r.expires_at };
    return { plan: r.plan, expires_at: r.expires_at };
  }

  private renewWarned = false;
  private async maybeRenew(): Promise<void> {
    if (!this.autoRenew || !this.plan) return;
    const msLeft = Date.parse(this.plan.expires_at) - Date.now();
    if (msLeft > this.renewWindowMs) return;
    try {
      await this.subscribe(this.plan.id);
    } catch (e) {
      if (!this.renewWarned) {
        this.renewWarned = true;
        console.warn(`@tollwarden/client: plan auto-renewal failed (${(e as Error).message}); continuing on default tier after expiry.`);
      }
    }
  }
}
