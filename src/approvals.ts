// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Human-in-the-loop step-up approvals (ROADMAP §6).
 *
 * Fills the gap between flag and block: when a scan for a configured key
 * returns "flag", TollWarden notifies the operator's webhook with the payment
 * facts and a one-time decide link. A human reviews the FULL pay_to (the
 * address-poisoning lesson) and one click mints a short-lived Ed25519-signed
 * OVERRIDE verdict — tag "override:allow", never plain "allow" — bound to
 * exactly that payment's commitment. The wallet-side enforcement kit accepts
 * overrides only when the operator opts in (acceptOverrides).
 *
 * Security invariants:
 *  - Overrides only upgrade flag → allow. Blocks are never approvable, and
 *    decide-time re-asserts the record's CAPTURED original verdict was "flag"
 *    (approvability is never derived from mutable state).
 *  - The decide token is a bearer credential: sha256-hashed at rest,
 *    single-decision, constant-time compared. Unknown-id and bad-token
 *    failures are indistinguishable (no probe oracle).
 *  - Webhook SSRF defense (live mode): https only; the hostname is resolved
 *    and EVERY address must be public (loopback/private/link-local/ULA
 *    rejected); the request then connects to a checked IP with TLS servername
 *    pinned to the original hostname, so a rebinding DNS answer at fetch time
 *    changes nothing. Dev mode allows http/loopback so tests can drive it.
 *  - Webhook delivery is fire-and-forget (setImmediate + timeout + one retry):
 *    it can never delay a scan or change a verdict.
 *  - Threat model note: an agent that holds its own API key could configure a
 *    webhook it controls and "approve" its own flags. That is why the
 *    enforcement kit's acceptOverrides defaults to false and the docs require
 *    the webhook receiver to be out of the agent's reach.
 */
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { isIP } from "node:net";
import type { TollWardenConfig } from "./config.ts";
import { APPROVAL_RING_MAX, approvalStatsOf, hashApiKey, type ApprovalFacts, type ApprovalRecord, type KeyRecord, type Store } from "./store.ts";
import type { VerdictSigner } from "./verdictsign.ts";
import type { ApiResult } from "./api.ts";
import type { ScanRequest, ScanResponse } from "./types.ts";
import { paymentCommitment } from "./commitment.ts";
import { redactSecrets } from "./detectors/pii.ts";

// ---------------------------------------------------------------------------
// Webhook URL validation + SSRF-safe delivery
// ---------------------------------------------------------------------------

/** Is this (v4 or v6) address private/loopback/link-local/ULA/unspecified? */
export function isPrivateAddress(addr: string): boolean {
  const a = addr.toLowerCase();
  if (isIP(a) === 4) {
    const p = a.split(".").map(Number);
    return (
      p[0] === 0 || // "this" network
      p[0] === 10 ||
      p[0] === 127 || // loopback
      (p[0] === 169 && p[1] === 254) || // link-local (cloud metadata lives here)
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127) // CGNAT
    );
  }
  // v6: loopback, unspecified, link-local fe80::/10, ULA fc00::/7, v4-mapped.
  if (a === "::1" || a === "::") return true;
  if (a.startsWith("fe8") || a.startsWith("fe9") || a.startsWith("fea") || a.startsWith("feb")) return true;
  if (a.startsWith("fc") || a.startsWith("fd")) return true;
  const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateAddress(mapped[1]);
  return false;
}

/** Structural validation of an operator-supplied webhook URL. Live mode is
 * strict (https, no IP literals, no obviously-internal names); dev mode
 * additionally allows http + loopback so local tests can receive deliveries. */
export function validateWebhookUrl(raw: string, mode: "live" | "dev"): { ok: true; url: URL } | { ok: false; error: string } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, error: "webhook_url is not a valid URL" };
  }
  const host = url.hostname.toLowerCase();
  if (mode === "dev" && (url.protocol === "http:" || url.protocol === "https:")) {
    return { ok: true, url };
  }
  if (url.protocol !== "https:") return { ok: false, error: "webhook_url must be https" };
  if (isIP(host)) return { ok: false, error: "webhook_url must use a hostname, not an IP literal" };
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".home.arpa") ||
    !host.includes(".")
  ) {
    return { ok: false, error: "webhook_url must be a public hostname" };
  }
  if (url.username || url.password) return { ok: false, error: "webhook_url must not carry credentials" };
  return { ok: true, url };
}

const WEBHOOK_TIMEOUT_MS = 5000;

/**
 * Deliver one signed payload. Live mode: resolve the hostname, reject if ANY
 * address is private, then connect to a vetted IP with the TLS servername +
 * Host header pinned to the original hostname (kills DNS-rebinding TOCTOU).
 * Redirects are not followed. Resolves to true on 2xx.
 */
async function deliverWebhook(url: URL, body: string, secret: string, mode: "live" | "dev"): Promise<boolean> {
  const signature = createHmac("sha256", secret).update(body, "utf8").digest("hex");
  const headers = {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "x-tollwarden-signature": `sha256=${signature}`,
    host: url.host,
  };

  let connectHost = url.hostname;
  if (mode === "live") {
    let addrs;
    try {
      addrs = await dnsLookup(url.hostname, { all: true });
    } catch {
      return false;
    }
    if (!addrs.length || addrs.some((a) => isPrivateAddress(a.address))) return false;
    connectHost = addrs[0].address; // connect to the address we just vetted
  }

  return new Promise((resolve) => {
    const isHttps = url.protocol === "https:";
    const req = (isHttps ? httpsRequest : httpRequest)(
      {
        host: connectHost,
        port: url.port ? Number(url.port) : isHttps ? 443 : 80,
        path: `${url.pathname}${url.search}`,
        method: "POST",
        headers,
        timeout: WEBHOOK_TIMEOUT_MS,
        ...(isHttps ? { servername: url.hostname } : {}),
      },
      (res) => {
        res.resume(); // drain; the response body is untrusted and ignored
        resolve((res.statusCode ?? 0) >= 200 && (res.statusCode ?? 0) < 300);
      },
    );
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(false));
    req.end(body);
  });
}

// ---------------------------------------------------------------------------
// Config endpoint
// ---------------------------------------------------------------------------

/** POST /v1/approvals/config — set/replace/disable the caller's webhook.
 * Auth: the caller's CURRENT key (in-grace rotated secrets are refused by the
 * caller in api.ts via requireLiveKey — this function receives the live hash). */
export function setApprovalConfig(
  store: Store,
  cfg: TollWardenConfig,
  keyHash: string,
  body: unknown,
): ApiResult {
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;

  // Per-key opt-out is always honored — including while the server-level
  // switch is off — so an operator can clean up their config at any time.
  if (b.webhook_url === null || b.webhook_url === false) {
    const had = store.approvalConfigs.delete(keyHash);
    store.markDirty();
    return {
      status: 200,
      body: {
        enabled: false,
        advisory: had
          ? "Human-in-the-loop approvals are now DISABLED for this key. Flag verdicts return to advisory-only: nothing will pause for review and no override verdicts will be minted, so an enforcement-kit wallet with acceptOverrides has no path from flag to payment anymore. Already-pending approvals remain decidable until they expire. Re-enable any time by POSTing a webhook_url."
          : "Approvals were not enabled for this key. Flag verdicts are advisory-only.",
      },
    };
  }

  if (!cfg.approvalsEnabled) {
    return {
      status: 404,
      body: {
        error: "Human-in-the-loop approvals are disabled on this server (APPROVALS=off).",
        advisory: "Flag verdicts are advisory-only on this deployment: they will not pause for review and no override verdicts are minted. Ask the operator to set APPROVALS=on to enable step-up approvals.",
      },
    };
  }

  if (typeof b.webhook_url !== "string") {
    return { status: 400, body: { error: "Provide webhook_url (https URL to receive approval requests), or null to disable." } };
  }
  const checked = validateWebhookUrl(b.webhook_url.slice(0, 2000), cfg.mode);
  if (!checked.ok) return { status: 400, body: { error: checked.error } };
  const format = b.format === "slack" ? "slack" : "json";

  const secret = `psw_${randomBytes(24).toString("hex")}`;
  store.approvalConfigs.set(keyHash, {
    webhook_url: checked.url.toString(),
    format,
    secret,
    created_at: new Date().toISOString(),
  });
  store.markDirty();
  return {
    status: 200,
    body: {
      enabled: true,
      webhook_url: checked.url.toString(),
      format,
      webhook_secret: secret,
      note:
        "Store the secret now — it is shown once. Every delivery carries header X-TollWarden-Signature: sha256=<HMAC-SHA256(secret, raw body)>; verify it before trusting a payload. " +
        "SECURITY: the decide link in each delivery is a bearer credential — anyone who can read your webhook destination can approve payments. Point it somewhere the agent itself cannot read, or overrides are self-approvable." +
        (format === "slack" ? " Slack format puts the decide link in channel history — anyone in the channel can decide. Prefer a private channel or the json format." : ""),
    },
  };
}

// ---------------------------------------------------------------------------
// Approval creation (called from handleScan on a flag verdict)
// ---------------------------------------------------------------------------

/** Shape attached to a flag scan response when an approval was opened. */
export interface ApprovalAttachment {
  approval_id: string;
  status: "pending";
  expires_at: string;
  poll: string;
  note: string;
}

/**
 * Open a pending approval for a flagged scan and fire the operator webhook.
 * Returns the attachment for the scan response, or null when the key has no
 * approvals config (or the approvals map is at capacity — fail closed).
 * The webhook fires via setImmediate: it can never delay the scan response.
 */
export function maybeCreateApproval(
  store: Store,
  cfg: TollWardenConfig,
  keyHash: string,
  scan: ScanResponse,
  req: ScanRequest,
): ApprovalAttachment | null {
  if (!cfg.approvalsEnabled) return null; // feature switched off: flags stay advisory-only
  const config = store.approvalConfigs.get(keyHash);
  if (!config) return null;
  if (scan.verdict !== "flag") return null; // blocks are never approvable; allows need nothing
  if (store.approvals.size >= cfg.approvalsMax) return null; // fail closed, never evict in-flight

  const approvalId = randomUUID();
  const token = `pst_${randomBytes(24).toString("hex")}`;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + cfg.approvalsPendingTtlMinutes * 60_000).toISOString();
  const p = req.payment;
  const facts: ApprovalFacts = {
    pay_to: p.pay_to ?? "",
    amount: p.amount,
    amount_usd: req.expected_price_usd ?? p.amount_usd,
    network: p.network,
    asset: p.asset,
    // PRIVACY §3: facts are persisted in the store snapshot and POSTed to the
    // operator's webhook (possibly a Slack channel). Mask detected secrets/PII
    // with the scan's own redaction BEFORE truncating, so a cut can never
    // leave a partial secret the patterns no longer recognize.
    resource_url: typeof p.resource_url === "string" ? redactSecrets(p.resource_url).slice(0, 500) : undefined,
    description: typeof p.description === "string" ? redactSecrets(p.description).slice(0, 300) : undefined,
    agent_id: req.agent_id,
    risk_score: scan.risk_score,
    fired: scan.checks.filter((c) => c.verdict !== "allow").map((c) => c.id),
  };

  const record: ApprovalRecord = {
    approval_id: approvalId,
    token_hash: hashApiKey(token),
    key_hash: keyHash,
    scan_id: scan.scan_id,
    direction: scan.direction,
    original_verdict: scan.verdict,
    payment_commitment: paymentCommitment(p),
    facts,
    status: "pending",
    created_at: now.toISOString(),
    expires_at: expiresAt,
  };
  store.approvals.set(approvalId, record);
  // Telemetry: count the request on the owning account (the approval record
  // itself is pruned 24h after creation, so counters live on the KeyRecord).
  const ownerRec = store.keys.get(keyHash);
  if (ownerRec) approvalStatsOf(ownerRec).requested += 1;
  store.markDirty();

  // The token travels ONLY in the webhook payload (bearer credential), in the
  // URL FRAGMENT so it never appears in any server's request logs.
  const decideUrl = `${cfg.publicBaseUrl}/approve#id=${approvalId}&token=${token}`;
  const payload =
    config.format === "slack"
      ? JSON.stringify({
          text:
            `:warning: TollWarden flagged a payment and is waiting for your decision.\n` +
            `*Pay to:* \`${facts.pay_to}\` (verify the FULL address)\n` +
            `*Amount:* ${facts.amount_usd !== undefined ? `$${facts.amount_usd}` : facts.amount ?? "?"} on ${facts.network ?? "?"}\n` +
            `*Resource:* ${facts.resource_url ?? "-"}\n` +
            `*Checks fired:* ${facts.fired.join(", ") || "-"} (risk ${facts.risk_score})\n` +
            `<${decideUrl}|Review and decide> — expires ${expiresAt}`,
        })
      : JSON.stringify({
          type: "tollwarden.approval.pending",
          approval_id: approvalId,
          scan_id: scan.scan_id,
          created_at: record.created_at,
          expires_at: expiresAt,
          decide_url: decideUrl,
          payment: facts,
        });

  setImmediate(() => {
    void deliverWebhook(new URL(config.webhook_url), payload, config.secret, cfg.mode).then((ok) => {
      if (!ok) {
        // One retry after 2s; then give up silently (the agent still sees the
        // pending approval on the scan response and the operator can poll).
        setTimeout(() => {
          void deliverWebhook(new URL(config.webhook_url), payload, config.secret, cfg.mode);
        }, 2000).unref?.();
      }
    });
  });

  return {
    approval_id: approvalId,
    status: "pending",
    expires_at: expiresAt,
    poll: `GET /v1/approvals/${approvalId}`,
    note: "This flag is awaiting human review. Poll with your API key; on approval you receive a signed override verdict valid for a few minutes.",
  };
}

// ---------------------------------------------------------------------------
// Token-authed endpoints (the human side)
// ---------------------------------------------------------------------------

/** Constant-time token check against the stored hash. */
function tokenMatches(record: ApprovalRecord, token: unknown): boolean {
  if (typeof token !== "string" || !token) return false;
  const given = Buffer.from(hashApiKey(token), "utf8");
  const want = Buffer.from(record.token_hash, "utf8");
  return given.length === want.length && timingSafeEqual(given, want);
}

/** Uniform failure: unknown id and bad token are indistinguishable (no oracle). */
const NOT_FOUND: ApiResult = { status: 404, body: { error: "Unknown approval or invalid token." } };

function liveStatus(record: ApprovalRecord): ApprovalRecord["status"] {
  if (record.status === "pending" && Date.parse(record.expires_at) <= Date.now()) return "expired";
  return record.status;
}

/** POST /v1/approvals/inspect {approval_id, token} — the decide page's data
 * source. Non-consuming; shows the FULL pay_to (address-poisoning lesson). */
export function handleApprovalInspect(store: Store, body: unknown): ApiResult {
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const record = typeof b.approval_id === "string" ? store.approvals.get(b.approval_id) : undefined;
  if (!record || !tokenMatches(record, b.token)) return NOT_FOUND;
  return {
    status: 200,
    body: {
      approval_id: record.approval_id,
      status: liveStatus(record),
      created_at: record.created_at,
      expires_at: record.expires_at,
      decided_at: record.decided_at ?? null,
      payment: record.facts,
      payment_commitment: record.payment_commitment,
      warning:
        "Verify the FULL pay_to address character by character before approving — truncated-display lookalikes (address poisoning) are a real attack.",
    },
  };
}

/**
 * POST /v1/approvals/decide {approval_id, token, decision: "approve"|"deny"}.
 * Idempotent: the first decision wins; repeating it returns the same outcome
 * (a webhook retry or double-click must not look like tampering). On approve,
 * mints the override attestation — after re-asserting the captured original
 * verdict was exactly "flag".
 */
export function handleApprovalDecide(
  store: Store,
  cfg: TollWardenConfig,
  signer: VerdictSigner | null,
  body: unknown,
): ApiResult {
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const record = typeof b.approval_id === "string" ? store.approvals.get(b.approval_id) : undefined;
  if (!record || !tokenMatches(record, b.token)) return NOT_FOUND;

  const decision = b.decision === "approve" ? "approved" : b.decision === "deny" ? "denied" : null;
  if (!decision) return { status: 400, body: { error: 'decision must be "approve" or "deny".' } };

  const status = liveStatus(record);
  if (status === "expired") {
    // Same once-only pending → expired transition as pruneApprovals; whichever
    // observes it first counts it.
    if (record.status === "pending") {
      const rec = store.keys.get(record.key_hash);
      if (rec) approvalStatsOf(rec).expired += 1;
    }
    record.status = "expired";
    store.markDirty();
    return { status: 410, body: { approval_id: record.approval_id, status: "expired", error: "This approval expired before a decision was made. The agent must re-scan." } };
  }
  if (status !== "pending") {
    // Already decided: idempotent replay of the SAME outcome; a conflicting
    // decision is refused (first decision wins).
    if (record.status === decision) {
      return { status: 200, body: { approval_id: record.approval_id, status: record.status, decided_at: record.decided_at } };
    }
    return { status: 409, body: { approval_id: record.approval_id, status: record.status, error: `Already ${record.status}; a decision is final.` } };
  }

  // Approvability is asserted from the CAPTURED verdict, never recomputed
  // state: only a scan that was exactly "flag" can ever be overridden.
  if (decision === "approved" && record.original_verdict !== "flag") {
    return { status: 409, body: { error: "Only flag verdicts can be approved. Blocks are never overridable." } };
  }
  if (decision === "approved" && !signer) {
    return { status: 503, body: { error: "Verdict signing is disabled on this server (VERDICT_SIGNING=off); overrides cannot be minted." } };
  }

  const decidedAt = new Date().toISOString();
  record.status = decision;
  record.decided_at = decidedAt;

  // Decision latency, captured NOW: the approval record is pruned 24h after
  // creation and the audit event carries no created_at, so this is the only
  // moment the pair exists. Both timestamps are server-stamped — nothing here
  // is client-supplied. Clamped non-negative; a corrupt created_at yields no
  // ring entry rather than a garbage latency.
  const latencyMs = Date.parse(decidedAt) - Date.parse(record.created_at);
  const ownerRec = store.keys.get(record.key_hash);
  if (ownerRec) {
    const stats = approvalStatsOf(ownerRec);
    stats[decision] += 1;
    if (Number.isFinite(latencyMs)) {
      // The payment may have settled and reported its outcome BEFORE the
      // human decided (flags are advisory — the agent can proceed while the
      // approval is pending). outcomes.ts only stamps rings at report time,
      // so pick up an already-recorded outcome here or the pairing is lost.
      const priorOutcome = store.scanIndex.get(record.scan_id)?.outcome;
      stats.recent.push({
        scan_id: record.scan_id,
        decided_at: decidedAt,
        latency_ms: Math.max(0, latencyMs),
        decision,
        ...(priorOutcome ? { outcome: priorOutcome } : {}),
      });
      if (stats.recent.length > APPROVAL_RING_MAX) {
        stats.recent.splice(0, stats.recent.length - APPROVAL_RING_MAX);
      }
    }
  }

  if (decision === "approved" && signer) {
    const attestation = signer.attestOverride(
      { scan_id: record.scan_id, direction: record.direction, risk_score: record.facts.risk_score, approved_at: decidedAt },
      record.payment_commitment,
      cfg.overrideTtlSeconds,
    );
    // Scan-shaped so SDK verifyAttestation field-matching works unchanged.
    record.override = {
      scan_id: record.scan_id,
      direction: record.direction,
      verdict: "override:allow",
      risk_score: record.facts.risk_score,
      checks: [],
      scanned_at: decidedAt,
      advisory: "Human-approved override of a flag verdict. Valid only for the attested payment commitment, for a few minutes.",
      attestation,
    };
  }
  store.markDirty();

  // Non-repudiation: every human decision lands in the hash-chained audit log.
  store.auditLog?.append({
    ts: decidedAt,
    scan_id: record.scan_id,
    direction: record.direction,
    verdict: record.original_verdict as "flag",
    risk_score: record.facts.risk_score,
    agent_id: record.facts.agent_id,
    payment_sha256: record.payment_commitment,
    network: record.facts.network,
    pay_to: record.facts.pay_to,
    amount_usd: record.facts.amount_usd ?? null,
    fired: [decision === "approved" ? "approval.approved" : "approval.denied"],
    attestation_sig: decision === "approved" ? (record.override as { attestation?: { signature_hex?: string } })?.attestation?.signature_hex : undefined,
    ...(Number.isFinite(latencyMs) ? { approval_latency_ms: Math.max(0, latencyMs) } : {}),
  });

  return {
    status: 200,
    body: {
      approval_id: record.approval_id,
      status: record.status,
      decided_at: decidedAt,
      ...(decision === "approved"
        ? { note: "Override minted. The agent's next poll of GET /v1/approvals/{id} receives the signed override verdict." }
        : { note: "Denied. The agent's poll will report the denial; the payment should not proceed." }),
    },
  };
}

// ---------------------------------------------------------------------------
// Key-authed polling (the agent side)
// ---------------------------------------------------------------------------

/** GET /v1/approvals/{id} — the owning key polls for the outcome. Read-only,
 * so in-grace rotated secrets may poll (same policy as /v1/usage). */
export function handleApprovalPoll(store: Store, approvalId: string, apiKey: string | undefined): ApiResult {
  if (!apiKey) return { status: 401, body: { error: "Provide your API key in the X-API-Key header." } };
  const resolved = store.resolveKey(apiKey);
  if (!resolved.rec || !resolved.hash) return { status: 401, body: { error: "Unknown or invalid API key." } };
  const record = store.approvals.get(approvalId);
  // Ownership: same uniform 404 whether the id is unknown or owned by another
  // key — an approval id must not be a probe oracle either.
  if (!record || record.key_hash !== resolved.hash) {
    return { status: 404, body: { error: "Unknown approval." } };
  }
  const status = liveStatus(record);
  return {
    status: 200,
    body: {
      approval_id: record.approval_id,
      scan_id: record.scan_id,
      status,
      created_at: record.created_at,
      expires_at: record.expires_at,
      decided_at: record.decided_at ?? null,
      ...(status === "approved" && record.override ? { override: record.override } : {}),
    },
  };
}

// ---------------------------------------------------------------------------
// Owner-only decision telemetry (surfaced via /v1/usage)
// ---------------------------------------------------------------------------

function median(sorted: number[]): number | null {
  if (!sorted.length) return null;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
}

function windowStats(entries: NonNullable<KeyRecord["approval_stats"]>["recent"]): {
  count: number;
  median_latency_ms: number | null;
  approval_rate: number | null;
} {
  const latencies = entries.map((e) => e.latency_ms).sort((a, b) => a - b);
  const approved = entries.filter((e) => e.decision === "approved").length;
  return {
    count: entries.length,
    median_latency_ms: median(latencies),
    approval_rate: entries.length ? Number((approved / entries.length).toFixed(4)) : null,
  };
}

/** How many of the newest ring entries form the "recent" window. */
const RECENT_WINDOW = 20;

/**
 * The /v1/usage `approvals` block: decision counts, latency aggregates split
 * recent-vs-baseline, and delivery outcomes of approved payments. The split
 * exists because decay to rubber-stamping is invisible in any single
 * observation — a reviewer approving in 8 seconds after three months of 40
 * looks identical in one log line to a reviewer who got calibrated. Median
 * latency shrinking while the approval rate stays near 100% is the legible
 * signature; approved payments that later report not_delivered are what
 * separates the benign reading from the bad one. Raw aggregates only — no
 * composite "rubber-stamp score": scoring the operator is the owner's call.
 *
 * PRIVACY: owner-only, by construction — callable only from handleUsage,
 * which resolves the caller's own key. Never reachable from reputation,
 * trust, public stats, or admin paths.
 */
export function approvalTelemetry(store: Store, rec: KeyRecord, keyHash: string): object {
  const stats = rec.approval_stats ?? { requested: 0, approved: 0, denied: 0, expired: 0, recent: [] };
  const ring = stats.recent;
  const recent = ring.slice(-RECENT_WINDOW);
  const baseline = ring.slice(0, Math.max(0, ring.length - RECENT_WINDOW));
  const outcomes = { delivered: 0, not_delivered: 0, partial: 0, wrong_content: 0, unreported: 0 };
  for (const e of ring) {
    if (e.decision !== "approved") continue;
    if (e.outcome && e.outcome in outcomes) outcomes[e.outcome as keyof typeof outcomes] += 1;
    else outcomes.unreported += 1;
  }
  const allLatencies = ring.map((e) => e.latency_ms).sort((a, b) => a - b);
  return {
    configured: store.approvalConfigs.has(keyHash),
    requested: stats.requested,
    approved: stats.approved,
    denied: stats.denied,
    expired: stats.expired,
    decision_latency_ms:
      allLatencies.length > 0
        ? {
            count: allLatencies.length,
            median: median(allLatencies),
            // Nearest-rank p90: ceil(0.9n)-1 — floor(0.9n) would return the
            // maximum (p100) whenever n is a multiple of 10.
            p90: allLatencies[Math.max(0, Math.ceil(allLatencies.length * 0.9) - 1)],
          }
        : null,
    recent: recent.length ? windowStats(recent) : null,
    baseline: baseline.length ? windowStats(baseline) : null,
    approved_outcomes: outcomes,
    note:
      "Visible only to this key — never shared, never fed into any verdict. Watch for: recent median latency shrinking while the approval rate stays near 100% (drift toward rubber-stamping), especially alongside not_delivered outcomes on approved payments.",
  };
}

/** Key rotation moves the account to a new hash — approvals, and the scan
 * index entries that gate outcome reporting, follow it. */
export function migrateApprovalsOnRotate(store: Store, oldHash: string, newHash: string): void {
  const config = store.approvalConfigs.get(oldHash);
  if (config) {
    store.approvalConfigs.delete(oldHash);
    store.approvalConfigs.set(newHash, config);
  }
  for (const record of store.approvals.values()) {
    if (record.key_hash === oldHash) record.key_hash = newHash;
  }
  for (const entry of store.scanIndex.values()) {
    if (entry.key_hash === oldHash) entry.key_hash = newHash;
  }
  store.markDirty();
}
