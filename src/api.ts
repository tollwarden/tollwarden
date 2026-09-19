// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Framework-agnostic API handlers. Both the production Express app (index.ts)
 * and the zero-dependency dev server (devserver.ts) route into these.
 */
import { randomUUID, timingSafeEqual } from "node:crypto";
import type { TollWardenConfig } from "./config.ts";
import { hashApiKey, type Store } from "./store.ts";
import type { VerdictSigner } from "./verdictsign.ts";
import { runScan } from "./scanner.ts";
import { sanitizeScanRequest } from "./sanitize.ts";
import { paymentCommitment, paymentDigest } from "./commitment.ts";
import { addDispute, addReport, disputeMessage, summarize } from "./reputation.ts";
import { activatePlanOnKey, activePlan, getPlan, plansCatalog, resolveEffectiveConfig } from "./plans.ts";
import { approvalTelemetry, maybeCreateApproval, migrateApprovalsOnRotate, setApprovalConfig } from "./approvals.ts";
import { pinEvidenceFor } from "./detectors/pinning.ts";
import { VERSION } from "./version.ts";

export interface ApiResult {
  status: number;
  body: unknown;
}

/** Keys are hashed at rest via store.hashApiKey (audit M-3); raw shown once, on issue. */
const hashKey = hashApiKey;

/** 401 body for a key that is positively dead. Deliberately specific: unlike
 * "unknown key" (kept indistinguishable from a typo so probes learn nothing),
 * a tombstoned key is already unusable — naming why it stopped working is
 * pure operational value for the legitimate owner mid-incident. */
function deadKeyResult(dead: "rotated" | "revoked"): ApiResult {
  return {
    status: 401,
    body: {
      error:
        dead === "rotated"
          ? "This API key was rotated and its grace period has ended. Use the replacement key returned by POST /v1/keys/rotate."
          : "This API key was revoked. Mint a fresh key with POST /v1/keys.",
      code: dead === "rotated" ? "key_rotated" : "key_revoked",
    },
  };
}

function mintKey(store: Store, agentId?: string): string {
  const key = `psk_${randomUUID().replace(/-/g, "")}`;
  store.keys.set(hashKey(key), {
    created_at: new Date().toISOString(),
    agent_id: typeof agentId === "string" ? agentId.slice(0, 200) : undefined,
    calls_used: 0,
  });
  store.markDirty();
  return key;
}

export function createApiKey(store: Store, cfg: TollWardenConfig, agentId?: string): ApiResult {
  const key = mintKey(store, agentId);
  return {
    status: 201,
    body: {
      api_key: key,
      free_calls_remaining: cfg.freeCalls,
      note: `Send this key in the X-API-Key header. Your first ${cfg.freeCalls} calls are free; after that, calls are paid via x402 (${cfg.priceScan}/scan). Store it now — it is not recoverable.`,
    },
  };
}

/**
 * Free-tier check. Returns true if this request should bypass x402 payment
 * (valid key with remaining free quota). Increments usage on success.
 */
export function consumeFreeCall(store: Store, cfg: TollWardenConfig, apiKey: string | undefined): boolean {
  const { rec } = store.resolveKey(apiKey);
  if (!rec) return false;
  if (rec.calls_used >= cfg.freeCalls) return false;
  rec.calls_used += 1;
  store.markDirty();
  return true;
}

export function freeCallsRemaining(store: Store, cfg: TollWardenConfig, apiKey: string | undefined): number | null {
  const { rec } = store.resolveKey(apiKey);
  if (!rec) return null;
  return Math.max(0, cfg.freeCalls - rec.calls_used);
}

export function handleScan(
  direction: "outgoing" | "incoming",
  body: unknown,
  cfg: TollWardenConfig,
  store: Store,
  signer?: VerdictSigner | null,
  apiKey?: string,
): ApiResult {
  // Sanitization guarantees detector type assumptions: type-confused fields
  // degrade to "absent" (reduced coverage -> flagged), never crash or bypass.
  const req = sanitizeScanRequest(body);
  if (!req) {
    return {
      status: 400,
      body: { error: "Request body must be JSON with a `payment` object. See GET / for the schema." },
    };
  }
  // Per-key plan overrides (velocity/spend headroom, deep-scan policy), clamped
  // to hard ceilings. Safety-critical checks are not plan-configurable.
  const eff = resolveEffectiveConfig(cfg, store, apiKey);
  // The scan's history scope is the ACCOUNT behind the presented key (resolved
  // here, from the header — never from the body). Anonymous scans get none.
  const tenant = store.resolveKey(apiKey).hash;
  const scan = runScan(direction, req, eff, store, { tenant });
  // Pin evidence is read AFTER runScan: the scanner has already created this
  // scan's TOFU pin (age 0 on first sighting) and rolled back any pin a
  // blocked scan created — so the signed evidence reflects post-rollback truth.
  if (signer) {
    const pin = pinEvidenceFor(req.payment, store, eff.pinning, scan.scanned_at, tenant);
    scan.attestation = signer.attest(scan, paymentCommitment(req.payment), undefined, pin);
  }

  // Tamper-evident audit record of the DECISION. Stores only a hash of the
  // payment — never the plaintext PII/secrets that were scanned.
  store.auditLog?.append({
    ts: scan.scanned_at,
    scan_id: scan.scan_id,
    direction: scan.direction,
    verdict: scan.verdict,
    risk_score: scan.risk_score,
    agent_id: req.agent_id,
    payment_sha256: paymentDigest(req.payment),
    network: req.payment.network,
    pay_to: req.payment.pay_to,
    amount_usd: req.expected_price_usd ?? req.payment.amount_usd ?? null,
    fired: scan.checks.filter((c) => c.verdict !== "allow").map((c) => c.id),
    attestation_sig: scan.attestation?.signature_hex,
    // Resolved from the presented key, never from the request body. Omitted
    // (rather than false) for third-party scans so record shape is unchanged.
    ...(store.resolveKey(apiKey).rec?.first_party ? { first_party: true } : {}),
  });

  // Per-key aggregate stats for the usage dashboard (counts only — no payment
  // data, no PII). Only recorded for a recognized key; anonymous paid scans
  // aren't attributable to an account.
  // Rolling scan index: lets a later outcome report (POST /v1/outcomes) be
  // verified as belonging to a scan we actually performed, and pins the
  // counterparty it aggregates against to what was scanned.
  const indexedKeyHash = apiKey ? store.resolveKey(apiKey).hash : null;
  // Resource domain, recorded only for non-blocked scans: a blocked scan (e.g.
  // a pin mismatch presenting someone else's domain) must not be able to seed
  // outcome history under that domain — same invariant as the trust-state
  // rollback in the scanner.
  let scanDomain: string | null = null;
  if (scan.verdict !== "block" && req.payment.resource_url) {
    try {
      scanDomain = new URL(req.payment.resource_url).hostname.toLowerCase();
    } catch {
      scanDomain = null;
    }
  }
  const indexedPayTo = (req.payment.pay_to ?? "").trim().toLowerCase();
  store.scanIndex.set(scan.scan_id, {
    commitment: paymentCommitment(req.payment),
    pay_to: indexedPayTo,
    ...(scanDomain ? { domain: scanDomain } : {}),
    verdict: scan.verdict,
    ...(indexedKeyHash ? { key_hash: indexedKeyHash } : {}),
    at: scan.scanned_at,
  });

  // Coverage denominator: count this counterparty's non-blocked scans so
  // outcome coverage (outcomes reported / scans seen) is measurable in
  // reputation lookups. Blocked scans are excluded — they must not settle, so
  // no outcome is ever expected of them.
  if (indexedPayTo && scan.verdict !== "block") {
    const sc = store.scanCounts.get(indexedPayTo) ?? { scans: 0, first_at: scan.scanned_at, last_at: scan.scanned_at };
    sc.scans += 1;
    sc.last_at = scan.scanned_at;
    store.scanCounts.set(indexedPayTo, sc);
    store.markDirty();
  }

  let approval: ReturnType<typeof maybeCreateApproval> = null;
  if (apiKey) {
    const { rec, hash } = store.resolveKey(apiKey);
    if (rec) {
      const s = rec.scans ?? { total: 0, allow: 0, flag: 0, block: 0 };
      s.total += 1;
      s[scan.verdict] += 1;
      rec.scans = s;
      rec.last_used_at = scan.scanned_at;
      store.markDirty();
    }
    // Human-in-the-loop: a flag on a key with an approvals config opens a
    // pending approval and notifies the operator's webhook (fire-and-forget —
    // never delays the scan, never changes the verdict).
    if (hash) approval = maybeCreateApproval(store, cfg, hash, scan, req);
  }

  return { status: 200, body: approval ? { ...scan, approval } : scan };
}

export function handleReputationLookup(address: string, store: Store): ApiResult {
  if (typeof address !== "string" || address.length < 6 || address.length > 200) {
    return { status: 400, body: { error: "Provide a wallet address, e.g. /v1/reputation/0xabc..." } };
  }
  return { status: 200, body: summarize(store, address) };
}

export function handleReputationReport(body: unknown, store: Store): ApiResult {
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const s = (v: unknown): string => (typeof v === "string" ? v : "");
  const res = addReport(store, {
    address: s(b.address).slice(0, 200),
    category: s(b.category),
    reason: s(b.reason).slice(0, 1000),
    reporter_agent_id: s(b.reporter_agent_id).slice(0, 200),
    evidence_url: typeof b.evidence_url === "string" ? b.evidence_url.slice(0, 2000) : undefined,
  });
  if (!res.ok) return { status: 400, body: { error: res.error } };
  return { status: 201, body: { accepted: true, report: res.report } };
}

/**
 * POST /v1/reputation/dispute — a reported wallet attaches a signed rebuttal.
 * Ownership proof: EIP-191 personal_sign over the canonical dispute message,
 * verified to recover to the disputed address. Free + rate-limited like
 * report filing; both sides of the registry cost the same to speak.
 */
export function handleReputationDispute(body: unknown, store: Store): ApiResult {
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const s = (v: unknown): string => (typeof v === "string" ? v : "");
  const res = addDispute(store, {
    address: s(b.address).slice(0, 200),
    statement: s(b.statement).slice(0, 2000),
    signature: s(b.signature).slice(0, 200),
  });
  if (!res.ok) return { status: 400, body: { error: res.error, sign_this: typeof b.address === "string" && typeof b.statement === "string" ? disputeMessage(s(b.address), s(b.statement).trim()) : undefined } };
  return { status: 201, body: { accepted: true, dispute: res.dispute } };
}

export function handlePlansCatalog(cfg: TollWardenConfig): ApiResult {
  return { status: 200, body: plansCatalog(cfg) };
}

/**
 * Activate/renew a plan on the caller's key. Payment enforcement happens in
 * the transport layer (index.ts gates this route with x402 at the plan's
 * price); by the time this runs, the subscription fee has settled (or the
 * server is in dev mode). If no key is supplied, one is minted and returned.
 */
export function handlePlanSubscribe(body: unknown, cfg: TollWardenConfig, store: Store, apiKey?: string): ApiResult {
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const planId = typeof b.plan === "string" ? b.plan : "";
  const plan = getPlan(planId);
  if (!plan) {
    return { status: 400, body: { error: `Unknown plan. Valid plans: ${["pro", "scale"].join(", ")} — see GET /v1/plans.` } };
  }
  let key = apiKey;
  let minted = false;
  // resolveKey (not a raw hash lookup) so an in-grace rotated key renews its
  // own account instead of getting a brand-new one minted.
  if (!key || !store.resolveKey(key).rec) {
    key = mintKey(store, typeof b.agent_id === "string" ? b.agent_id : undefined);
    minted = true;
  }
  const activated = activatePlanOnKey(store, key, plan);
  return {
    status: 200,
    body: {
      plan: activated.plan_id,
      expires_at: activated.expires_at,
      ...(minted ? { api_key: key, note: "New API key minted (none supplied). Store it now — it is not recoverable." } : {}),
      limits: plan.limits,
      renewal: "POST the same body again before expiry to extend from the current expiry date.",
    },
  };
}

/**
 * Usage stats for the CALLER'S OWN key (X-API-Key). A key can only ever see
 * its own account — the lookup is keyed by the hash of the presented key, so
 * there is no way to read another account's data, and no key is ever returned
 * or logged. Aggregates only; contains no payment data or PII.
 */
export function handleUsage(cfg: TollWardenConfig, store: Store, apiKey: string | undefined): ApiResult {
  if (!apiKey) {
    return { status: 401, body: { error: "Provide your API key in the X-API-Key header." } };
  }
  const resolved = store.resolveKey(apiKey);
  if (resolved.dead) return deadKeyResult(resolved.dead);
  const rec = resolved.rec;
  if (!rec) {
    // Same shape as an auth failure — never distinguish "no such key" from
    // "wrong key", to avoid confirming key validity to a probe.
    return { status: 401, body: { error: "Unknown or invalid API key." } };
  }
  const active = activePlan(store, apiKey);
  const scans = rec.scans ?? { total: 0, allow: 0, flag: 0, block: 0 };
  return {
    status: 200,
    body: {
      account: {
        created_at: rec.created_at,
        agent_id: rec.agent_id ?? null,
        last_used_at: rec.last_used_at ?? null,
      },
      free_tier: {
        included: cfg.freeCalls,
        used: rec.calls_used,
        remaining: Math.max(0, cfg.freeCalls - rec.calls_used),
      },
      plan: active
        ? { id: active.plan.id, name: active.plan.name, expires_at: active.expires_at, price_per_scan: active.plan.limits.price_per_scan }
        : { id: "starter", name: "Starter (default)", expires_at: null, price_per_scan: cfg.priceScan },
      scans: {
        total: scans.total,
        allow: scans.allow,
        flag: scans.flag,
        block: scans.block,
        block_rate: scans.total ? Number((scans.block / scans.total).toFixed(4)) : 0,
      },
      // Owner-only decision telemetry (never in reputation/trust/public stats
      // — see approvalTelemetry). resolved.hash is non-null here: rec exists.
      approvals: approvalTelemetry(store, rec, resolved.hash as string),
    },
  };
}

/** Shared auth for the key-lifecycle endpoints. Returns the live record or an
 * ApiResult error. In-grace rotated secrets are refused (403): a leaked OLD
 * secret must never rotate/revoke the account out from under the real owner. */
function requireLiveKey(
  store: Store,
  apiKey: string | undefined,
): { rec: import("./store.ts").KeyRecord; hash: string } | { err: ApiResult } {
  if (!apiKey) {
    return { err: { status: 401, body: { error: "Provide your API key in the X-API-Key header." } } };
  }
  const r = store.resolveKey(apiKey);
  if (r.dead) return { err: deadKeyResult(r.dead) };
  if (!r.rec || !r.hash) {
    return { err: { status: 401, body: { error: "Unknown or invalid API key." } } };
  }
  if (r.viaGrace) {
    return {
      err: {
        status: 403,
        body: {
          error:
            "This key was already rotated. It still works for scans until its grace period ends, but only the current key can rotate or revoke the account.",
          code: "key_superseded",
        },
      },
    };
  }
  return { rec: r.rec, hash: r.hash };
}

const GRACE_DEFAULT_SECONDS = 900; // 15 min: long enough to redeploy a fleet
const GRACE_MAX_SECONDS = 86_400; // 24 h hard cap — a leaked key must die

/**
 * Rotate the caller's API key: mint a fresh secret bound to the SAME account.
 * Usage counters, remaining free calls, plan, and dashboard stats all carry
 * over — the psk_ secret is a credential, not the identity. The old secret
 * keeps working for `grace_seconds` (default 900, 0 = immediately dead, max
 * 24h) so a fleet can switch over without downtime; during grace it can scan
 * but NOT rotate/revoke (see requireLiveKey). Rotation never resets the free
 * tier, so it cannot be farmed.
 */
export function handleKeyRotate(store: Store, cfg: TollWardenConfig, apiKey: string | undefined, body: unknown): ApiResult {
  const auth = requireLiveKey(store, apiKey);
  if ("err" in auth) return auth.err;
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const requested = typeof b.grace_seconds === "number" && Number.isFinite(b.grace_seconds) ? b.grace_seconds : GRACE_DEFAULT_SECONDS;
  const grace = Math.min(Math.max(Math.floor(requested), 0), GRACE_MAX_SECONDS);

  const newKey = `psk_${randomUUID().replace(/-/g, "")}`;
  const newHash = hashKey(newKey);
  const now = new Date();
  const graceUntil = new Date(now.getTime() + grace * 1000).toISOString();

  // Move the account to the new hash; tombstone the old secret. The approvals
  // config and any in-flight approvals belong to the ACCOUNT, so they follow.
  store.keys.delete(auth.hash);
  store.keys.set(newHash, auth.rec);
  store.revoked.set(auth.hash, {
    revoked_at: now.toISOString(),
    reason: "rotated",
    ...(grace > 0 ? { grace_until: graceUntil, successor: newHash } : {}),
  });
  migrateApprovalsOnRotate(store, auth.hash, newHash);
  // Pins, velocity windows, counterparty history, and cumulative spend belong
  // to the ACCOUNT: they follow the rotation, so rotating cannot reset a cap.
  store.rekeyTenant(auth.hash, newHash);
  store.markDirty();

  const isAdminKey = !!cfg.adminKeyHash && auth.hash === cfg.adminKeyHash;
  return {
    status: 200,
    body: {
      api_key: newKey,
      api_key_sha256: newHash,
      rotated_at: now.toISOString(),
      previous_key_valid_until: grace > 0 ? graceUntil : null,
      carried_over: {
        free_calls_remaining: Math.max(0, cfg.freeCalls - auth.rec.calls_used),
        plan: auth.rec.plan ?? null,
        scans_total: auth.rec.scans?.total ?? 0,
      },
      note:
        "Store the new key now — it is not recoverable. Your usage history, free-call quota, and plan carried over unchanged." +
        (isAdminKey
          ? " This key is bound to the /admin dashboard (ADMIN_KEY_SHA256): update that env var to api_key_sha256 above, or admin access stays locked."
          : ""),
    },
  };
}

/**
 * Permanently revoke the caller's API key (the leaked-key kill switch).
 * Requires `{"confirm": true}` — this is irreversible: the account's usage
 * history, remaining free calls, and any active plan die with it. The secret's
 * tombstone persists, so the dead key keeps failing with an explanatory 401.
 */
export function handleKeyRevoke(store: Store, cfg: TollWardenConfig, apiKey: string | undefined, body: unknown): ApiResult {
  const auth = requireLiveKey(store, apiKey);
  if ("err" in auth) return auth.err;
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  if (b.confirm !== true) {
    return {
      status: 400,
      body: {
        error:
          'Revocation is irreversible: usage history, remaining free calls, and any active plan are destroyed. POST again with {"confirm": true} to proceed — or use POST /v1/keys/rotate to swap the secret and KEEP the account.',
      },
    };
  }
  const now = new Date().toISOString();
  store.keys.delete(auth.hash);
  store.revoked.set(auth.hash, { revoked_at: now, reason: "revoked" });
  // The account dies with the key: drop its webhook config and expire any
  // pending approvals so nothing decidable outlives the revocation.
  store.approvalConfigs.delete(auth.hash);
  for (const rec of store.approvals.values()) {
    if (rec.key_hash === auth.hash && rec.status === "pending") rec.status = "expired";
  }
  store.dropTenant(auth.hash);
  store.markDirty();
  return {
    status: 200,
    body: {
      revoked: true,
      revoked_at: now,
      note: "The key and its account are permanently dead. Mint a fresh key with POST /v1/keys.",
    },
  };
}

/** POST /v1/approvals/config — authed by the caller's CURRENT key (in-grace
 * rotated secrets are refused: configuring the approval channel is a
 * security-sensitive operation, same policy as rotate/revoke). */
export function handleApprovalConfig(store: Store, cfg: TollWardenConfig, apiKey: string | undefined, body: unknown): ApiResult {
  const auth = requireLiveKey(store, apiKey);
  if ("err" in auth) return auth.err;
  return setApprovalConfig(store, cfg, auth.hash, body);
}

/**
 * Owner-only, all-time service stats (the /admin dashboard's data source).
 * Unlocked by the ONE key whose SHA-256 matches cfg.adminKeyHash
 * (ADMIN_KEY_SHA256 env var) — compared in constant time. 404 when
 * unconfigured so the route doesn't advertise itself; 401 otherwise uses the
 * same shape as /v1/usage so probes learn nothing. Aggregates only — no
 * per-customer keys, agent ids, addresses, or payment data are returned.
 */
/**
 * Owner-only gate, shared by every /v1/admin route. Returns an ApiResult to
 * send back when the caller is NOT the owner, or null when it is.
 *
 * Fails closed in three ways, all deliberate. No configured admin hash means
 * the routes do not exist (404, not 403, so their existence is not probeable).
 * The comparison is timing-safe. And a hash match alone is not enough: the key
 * must still be LIVE in the store, so a rotated or revoked admin key loses
 * admin access, which is the point of revocation. After rotating, update
 * ADMIN_KEY_SHA256 to the new hash (the rotate response includes it).
 */
function requireOwner(cfg: TollWardenConfig, store: Store, apiKey: string | undefined): ApiResult | null {
  if (!cfg.adminKeyHash) return { status: 404, body: { error: "Not found" } };
  if (!apiKey) {
    return { status: 401, body: { error: "Provide your API key in the X-API-Key header." } };
  }
  const given = Buffer.from(hashKey(apiKey), "utf8");
  const want = Buffer.from(cfg.adminKeyHash, "utf8");
  if (given.length !== want.length || !timingSafeEqual(given, want)) {
    return { status: 401, body: { error: "Unknown or invalid API key." } };
  }
  const live = store.resolveKey(apiKey);
  if (!live.rec || live.viaGrace) {
    return { status: 401, body: { error: "Unknown or invalid API key." } };
  }
  return null;
}

/**
 * POST /v1/admin/keys/first-party — mark a key as operator-owned.
 *
 * Owner-only, and deliberately the ONLY way the flag can ever be set. It is
 * never derivable from request input on a scan, and POST /v1/keys cannot set
 * it, because a caller able to tag itself first-party could remove its own
 * scans from the public third-party denominator.
 *
 * Takes the key HASH, not the key, so tagging an agent never requires sending
 * that agent's live credential anywhere. The hash is what /v1/keys returns on
 * creation and what /v1/keys/rotate returns on rotation.
 *
 * Only scans recorded AFTER tagging carry the flag. Existing audit records are
 * immutable by design, so the split is honest going forward and silent about
 * the past rather than retroactively rewritten.
 */
export function handleAdminSetFirstParty(
  cfg: TollWardenConfig,
  store: Store,
  apiKey: string | undefined,
  body: unknown,
): ApiResult {
  const denied = requireOwner(cfg, store, apiKey);
  if (denied) return denied;

  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const keyHash = typeof b.key_hash === "string" ? b.key_hash.trim().toLowerCase() : "";
  if (!/^[0-9a-f]{64}$/.test(keyHash)) {
    return { status: 400, body: { error: "key_hash must be the 64-hex SHA-256 of the target key." } };
  }
  if (typeof b.first_party !== "boolean") {
    return { status: 400, body: { error: "first_party must be true or false." } };
  }

  const rec = store.keys.get(keyHash);
  if (!rec) return { status: 404, body: { error: "Unknown key hash." } };

  if (b.first_party) rec.first_party = true;
  else delete rec.first_party;
  store.markDirty();

  return {
    status: 200,
    body: {
      key_hash: keyHash,
      first_party: rec.first_party === true,
      note:
        "Applies to scans recorded from now on. Audit records are immutable, so earlier scans on this key stay counted as third-party.",
    },
  };
}

export function handleAdminStats(cfg: TollWardenConfig, store: Store, apiKey: string | undefined): ApiResult {
  const denied = requireOwner(cfg, store, apiKey);
  if (denied) return denied;

  // Per-key counters (exist only for keyed scans, since the dashboard feature).
  const keyed = { total: 0, allow: 0, flag: 0, block: 0 };
  let withPlan = 0;
  let active7d = 0;
  const weekAgo = Date.now() - 7 * 86400_000;
  for (const rec of store.keys.values()) {
    if (rec.scans) {
      keyed.total += rec.scans.total;
      keyed.allow += rec.scans.allow;
      keyed.flag += rec.scans.flag;
      keyed.block += rec.scans.block;
    }
    if (rec.plan) withPlan += 1;
    if (rec.last_used_at && Date.parse(rec.last_used_at) > weekAgo) active7d += 1;
  }

  return {
    status: 200,
    body: {
      accounts: { total_keys: store.keys.size, with_plan: withPlan, active_7d: active7d },
      keyed_scans: keyed,
      registry: { reports: store.reports.length, pins: store.pins.size, badlist: store.badlist.size },
      // All-time truth (includes anonymous scans): derived from the audit log.
      audit: store.auditLog
        ? { head: store.auditLog.head(), ...store.auditLog.stats(30) }
        : null,
    },
  };
}

export function serviceInfo(cfg: TollWardenConfig): ApiResult {
  return {
    status: 200,
    body: {
      name: "TollWarden",
      tagline: "Payment security firewall for x402 micropayments. Advisory, non-custodial.",
      version: VERSION,
      mode: cfg.mode,
      endpoints: {
        "POST /v1/keys": `Free (rate-limited: ${cfg.keysPerIpPerDay}/IP/day). Issue an API key with a free-call allowance.`,
        "POST /v1/keys/rotate": "Free (X-API-Key header). Swap your key's secret for a fresh one — usage, free quota, and plan carry over. Old secret honors an optional grace window (default 15 min, max 24 h).",
        "POST /v1/keys/revoke": 'Free (X-API-Key header, body {"confirm": true}). Permanently kill a leaked key AND its account. Irreversible.',
        "POST /v1/scan/outgoing": `${cfg.priceScan} (first ${cfg.freeCalls} calls free per key). Screen a payment your agent is about to make.`,
        "POST /v1/scan/incoming": `${cfg.priceScan} (first ${cfg.freeCalls} calls free per key). Screen a payment request / 402 offer your agent received.`,
        "GET /v1/reputation/:address": `${cfg.priceReputation} (first ${cfg.freeCalls} calls free per key). Counterparty report summary.`,
        "POST /v1/reputation/report": `Free (rate-limited: ${cfg.reportsPerIpPerHour}/IP/hour). Report a bad counterparty after the fact.`,
        "POST /v1/reputation/dispute": `Free (rate-limited: ${cfg.reportsPerIpPerHour}/IP/hour). Attach a signed rebuttal to your wallet's report record. Sign "tollwarden-dispute-v1|<address>|<statement>" with the reported wallet's key (EIP-191 personal_sign) — key ownership is the authentication.`,
        "GET /v1/plans": "Free. Machine-readable plan catalog (pricing tiers, limits, how to subscribe).",
        "POST /v1/trust/evaluate": `Free (rate-limited: ${cfg.trustQueriesPerIpPerHour}/IP/hour). x402 trust-provider interface: TrustQuery about a payer in, TrustEvaluation (PASS/FAIL/UNCERTAIN + evidence) out — for sellers gating settlement.`,
        "POST /v1/approvals/config": "Free (X-API-Key). Configure human-in-the-loop approvals: on a flag verdict, your webhook gets the payment facts + a one-time decide link; a human click mints a short-lived signed override verdict.",
        "GET /v1/approvals/{id}": "Free (X-API-Key). Poll a pending approval; on approve you receive the signed override:allow verdict bound to that exact payment.",
        "POST /v1/outcomes": `Free (rate-limited: ${cfg.outcomesPerIpPerHour}/IP/hour). Record whether a scanned, settled payment actually DELIVERED (delivered/not_delivered/partial/wrong_content). Must present the scan_id + payment_commitment of a real scan — outcomes are commitment-bound, one per scan. Delivery rates feed reputation lookups and future scans.`,
        "POST /v1/plans/subscribe": "x402-paid at the plan's price. Upgrade your API key to a plan; renew by paying again.",
        "GET /v1/usage": "Free. Your own key's usage stats (X-API-Key header): scan/verdict counts, free-tier quota, plan status, and approval-decision telemetry (latency + delivery outcomes of approved payments — visible only to you, never shared).",
        "GET /dashboard": "Free. Browser usage dashboard for your key — key is sent via header only, never a URL.",
        "GET /.well-known/x402": "Free. x402 manifest.",
        "GET /.well-known/agent-card.json": "Free. Agent card.",
        "GET /.well-known/erc8004.json": "Free. ERC-8004 agent registration file (on-chain identity tokenURI).",
        "GET /.well-known/tollwarden-verdict-key": "Free. Ed25519 public key for verdict attestations.",
        "GET /health": "Free. Liveness.",
        "GET /v1/stats": "Free. Public aggregate service stats with third-party and first-party (operator-owned) usage reported separately, so the operator's own agents never inflate the headline figures. Scan totals, verdict split, distinct agents, self-measured 90-day uptime. Cached ~5 min; aggregates only.",
        "GET /terms": "Free. Terms of Use (human-readable).",
        "GET /privacy": "Free. Privacy Policy (human-readable).",
      },
      checks: [
        "pii: PII/secret detection on resource_url, description, reason, metadata",
        "replay: nonce reuse tracking",
        "overpay: configurable multiple-of-expected-price + absolute ceiling + non-positive amounts — value resolved from the atomic amount and SERVER-known token decimals (a client-declared asset_decimals that disagrees is ignored and flagged)",
        "injection: prompt-injection-triggered payment provenance analysis (fast tier)",
        "injection-deep: base64 + unicode-obfuscation rescan (bypassed below MICRO_BYPASS_USD; policy.force_deep overrides)",
        "url: resource URL structural risk (incoming)",
        "asset: canonical-USDC verification (lookalike-token defense)",
        "badlist: known-bad address list",
        "pin: TOFU merchant pinning (domain -> pay_to), two tiers — your own account's pin blocks on rotation; a shared observation from other callers only flags unless the async CDP Bazaar cross-check verified it",
        "poison: address-poisoning detection (pay_to matching a counterparty you have paid, your own pinned merchant, or a CDP-verified pin on first+last chars but differing in the middle → block; a lookalike of another caller's unverified pin → flag)",
        "scout: ScoutScore external trust signal for merchant domains (opt-in, async + cached, flag-only)",
        "velocity: rate, hourly spend cap, first-contact size cap (outgoing) — scoped to your API key's account, not to a request field",
        "reputation: shared counterparty report registry v2 — 90-day half-life time decay, reporter-credibility weighting (observed payment history counts more than fresh anonymous ids), signed wallet rebuttals surfaced alongside reports",
        "delivery: measured, commitment-bound delivery-outcome history per counterparty (flag-only — a clean payment to a seller who never ships still fails you)",
      ],
      attestation:
        "Verdicts are Ed25519-signed (see /.well-known/tollwarden-verdict-key). Wallet policies can require a fresh allow-verdict before signing.",
      scan_request_schema: {
        agent_id: "string (optional; labels the scan — velocity, pins, and counterparty history are scoped to your API key's account, and to agent_id only for anonymous scans)",
        payment: {
          scheme: "exact",
          network: "eip155:8453",
          asset: "0x... (token contract; enables canonical-USDC verification)",
          amount: "atomic units, e.g. '10000'",
          amount_usd: "or decimal USD",
          asset_decimals: "6 (informational — the server resolves decimals from `asset`; a disagreeing value is ignored and flagged)",
          pay_to: "0x... recipient",
          payer: "0x... payer (optional)",
          resource_url: "https://...",
          description: "string",
          reason: "why the agent is paying",
          nonce: "payment nonce",
          metadata: { any: "string values" },
        },
        expected_price_usd: 0.01,
        context: {
          origin: "planning | user_instruction | tool_result | fetched_content | unknown",
          content: "the content the agent just read (for injection analysis)",
          content_source_url: "https://...",
        },
        policy: {
          force_deep: "boolean — run deep content analysis even below the micropayment threshold",
          skip_deep: "boolean — skip deep analysis regardless of value",
        },
      },
      custody: "TollWarden never touches private keys, wallets, or funds. Verdicts are advisory (and signed, for wallets that choose to enforce them).",
    },
  };
}
