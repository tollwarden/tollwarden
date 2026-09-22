// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * OpenAPI 3.1 document for TollWarden, served at GET /openapi.json (free).
 *
 * This is the canonical machine-readable discovery contract used by
 * x402scan and agent tooling. Payment metadata follows the x402scan
 * discovery spec: paid operations carry `x-payment-info` (decimal USD)
 * and a `402` response; runtime 402 behavior remains authoritative.
 * See https://www.x402scan.com/discovery/spec
 */
import type { TollWardenConfig } from "./config.ts";
import { VERSION } from "./version.ts";

function usd(price: string): string {
  // "$0.01" -> "0.010000" (decimal USD; NOT atomic units — those are runtime-only)
  return Number(price.replace("$", "")).toFixed(6);
}

function paidOp(price: string) {
  return {
    "x-payment-info": {
      price: { mode: "fixed", currency: "USD", amount: usd(price) },
      protocols: [{ x402: {} }],
    },
  };
}

// ---------------------------------------------------------------------------
// Component schemas (mirror src/types.ts)
// ---------------------------------------------------------------------------
const PaymentDetails = {
  type: "object",
  description:
    "The payment (or 402 offer) to screen. Provide as many fields as you have — every field improves detection coverage.",
  properties: {
    scheme: { type: "string", description: 'x402 scheme, e.g. "exact"' },
    network: { type: "string", description: 'CAIP-2 network id, e.g. "eip155:8453"' },
    asset: { type: "string", description: "Token contract address (e.g. USDC)" },
    amount: { type: "string", description: 'Amount in atomic token units, e.g. "10000" = $0.01 USDC' },
    amount_usd: { type: "number", description: "Alternative when no atomic amount is available: decimal USD value (self-reported; ignored and flagged when it disagrees with `amount`)" },
    asset_decimals: { type: "integer", description: "Informational. Decimals are resolved server-side from `asset` (canonical USDC = 6); a declared value that disagrees is ignored and flagged. Honored only for assets the server does not know." },
    pay_to: { type: "string", description: "Recipient address" },
    payer: { type: "string", description: "Paying agent's address (optional; scopes replay tracking, and velocity/history for anonymous scans)" },
    resource_url: { type: "string", description: "The resource being purchased" },
    description: { type: "string" },
    reason: { type: "string", description: "Free-text reason the agent recorded for making this payment" },
    nonce: { type: "string", description: "Payment nonce (from the signed payment payload)" },
    valid_until: { type: "string" },
    metadata: { type: "object", additionalProperties: { type: "string" } },
  },
} as const;

const ScanRequest = {
  type: "object",
  required: ["payment"],
  properties: {
    agent_id: { type: "string", description: "Stable identifier for the calling agent. Labels the scan; velocity, pins, and counterparty history are scoped to your API key's account, and to agent_id only for anonymous scans." },
    payment: PaymentDetails,
    expected_price_usd: {
      type: "number",
      description: "What the agent expected this to cost, in USD (e.g. from the 402 quote or a catalog). Enables overpayment detection.",
    },
    context: {
      type: "object",
      description: "Provenance of the decision to pay. Enables prompt-injection-triggered-payment detection.",
      properties: {
        origin: {
          type: "string",
          enum: ["planning", "user_instruction", "tool_result", "fetched_content", "unknown"],
          description: "Where the decision to pay originated",
        },
        content: { type: "string", description: "The content the agent just read (tool result / fetched page), for injection analysis" },
        content_source_url: { type: "string" },
        offer: {
          type: "string",
          description: "The raw 402 offer / discovery payload the payment terms came from. Enables offer-drift checks (payment vs the offer it came from); its pay_to is expected, not treated as injected.",
        },
        phase: {
          type: "string",
          enum: ["pre_sign", "post_sign"],
          description: "pre_sign: scanning before the payment is signed, so a missing nonce is expected. Absent = post_sign (full replay coverage expected).",
        },
      },
    },
    policy: {
      type: "object",
      properties: {
        force_deep: { type: "boolean", description: "Run the deep content-analysis tier even below the micropayment threshold" },
        skip_deep: { type: "boolean", description: "Skip the deep tier regardless of value (developer policy)" },
      },
    },
  },
} as const;

const CheckResult = {
  type: "object",
  properties: {
    id: { type: "string" },
    name: { type: "string" },
    verdict: { type: "string", enum: ["allow", "flag", "block"] },
    severity: { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
    reason: { type: "string" },
    details: { type: "object" },
  },
  required: ["id", "name", "verdict", "severity", "reason"],
} as const;

const ScanResponse = {
  type: "object",
  required: ["scan_id", "direction", "verdict", "risk_score", "checks", "scanned_at", "advisory"],
  properties: {
    scan_id: { type: "string" },
    direction: { type: "string", enum: ["outgoing", "incoming"] },
    verdict: { type: "string", enum: ["allow", "flag", "block"] },
    risk_score: { type: "integer", minimum: 0, maximum: 100, description: "0 (clean) – 100 (maximum risk)" },
    checks: { type: "array", items: CheckResult },
    scanned_at: { type: "string" },
    advisory: { type: "string" },
    attestation: {
      type: "object",
      description:
        "Ed25519 attestation binding the verdict to this exact payment. Verify with the key at /.well-known/tollwarden-verdict-key.",
      properties: {
        alg: { type: "string", enum: ["ed25519"] },
        public_key_spki_hex: { type: "string" },
        message: {
          type: "string",
          description:
            "Frozen 7-field verdict message: scan_id|direction|verdict|risk_score|scanned_at|payment_commitment|expires_at. New signed facts go in `evidence`, never here.",
        },
        signature_hex: { type: "string" },
        payment_commitment: { type: "string", description: "sha256(network|pay_to|asset|amount|nonce)" },
        expires_at: { type: "string" },
        evidence: {
          type: "object",
          description:
            "Second signed record (same key): evidence-v1|scan_id|payment_commitment|pin_domain|pin_age_seconds|pin_corroboration. Publishes how long the merchant pin behind this payee had held at scan time (0 = first sighting; empty = no pin applies) and which NAMED out-of-band sources corroborated it (e.g. cdp_bazaar) — never a boolean or a composite score; source strength is the verifier's judgment. Bound to the same scan_id + commitment; shares the attestation's expiry. `pin` mirrors the signed fields for convenience — verifiers must parse the signed message (the SDKs cross-check the mirror). Absent on override attestations.",
          properties: {
            message: { type: "string" },
            signature_hex: { type: "string" },
            pin: {
              type: ["object", "null"],
              properties: {
                domain: { type: "string" },
                age_seconds: { type: "integer", minimum: 0 },
                corroboration: { type: "array", items: { type: "string" } },
              },
            },
          },
        },
      },
    },
  },
} as const;

const ReputationSummary = {
  type: "object",
  properties: {
    address: { type: "string" },
    status: { type: "string", enum: ["clean", "reported"] },
    risk: { type: "string", enum: ["none", "low", "medium", "high"] },
    report_count: { type: "integer" },
    distinct_reporters: { type: "integer" },
    weighted_score: {
      type: "number",
      description:
        "v2 risk input: per-reporter credibility (0.5 anonymous → 1.0 with observed payment history) × 90-day-half-life time decay, summed over distinct reporters. Risk grades on this, not raw counts: ≥2.5 high, ≥1.0 medium, >0.1 low.",
    },
    categories: { type: "object", additionalProperties: { type: "integer" } },
    first_reported: { type: "string" },
    last_reported: { type: "string" },
    disputes: {
      type: "array",
      description: "Signed rebuttals from the reported wallet, newest first. Each was verified (EIP-191 personal_sign recovering to the address) at submission; the signature is included so you can re-verify.",
      items: {
        type: "object",
        properties: {
          address: { type: "string" },
          statement: { type: "string" },
          signature: { type: "string" },
          disputed_at: { type: "string" },
        },
      },
    },
    injection_history: {
      type: ["object", "null"],
      description:
        "System-observed incidents: scans TollWarden itself BLOCKED where this address was structurally implicated as attacker-controlled (planted in just-read content, embedded in an encoded payload, or used as vanity-bait). Recorded automatically at scan time and weighted like reports (observer credibility × 90-day decay). Stronger than a self-asserted report, but still flag-only in scans — scan inputs are client-supplied.",
      properties: {
        incident_count: { type: "integer" },
        distinct_observers: { type: "integer" },
        weighted_score: { type: "number" },
        check_ids: { type: "object", additionalProperties: { type: "integer" } },
        first_at: { type: "string" },
        last_at: { type: "string" },
      },
    },
    delivery: {
      type: ["object", "null"],
      description:
        "Measured, commitment-bound delivery outcomes for this counterparty, plus the ledger's denominator: scans_seen counts the non-blocked scans TollWarden performed against it, and report_coverage is outcomes_total over that — so selectively reported outcomes read as low coverage instead of passing as a complete record. When scans exist but no outcome was ever reported, outcomes_total is 0 and only the coverage fields are present. Coverage is informational only (scan counts are client-driven) and never feeds a flag; null means no outcomes and no counted scans.",
      properties: {
        outcomes_total: { type: "integer" },
        delivered: { type: "integer" },
        not_delivered: { type: "integer" },
        partial: { type: "integer" },
        wrong_content: { type: "integer" },
        delivery_rate: { type: "number", description: "Raw observed rate — always reported, never the flag trigger." },
        smoothed_delivery_rate: { type: "number", description: "Prior-smoothed rate (Beta prior, mean 0.9, strength 10) — what flag decisions compare." },
        distinct_reporters: { type: "integer" },
        first_at: { type: "string" },
        last_at: { type: "string" },
        scans_seen: { type: "integer", description: "Non-blocked scans of this counterparty since the counter began — the outcome ledger's denominator." },
        scans_tracked_since: { type: ["string", "null"] },
        report_coverage: { type: ["number", "null"], description: "outcomes_total / scans_seen, clamped to [0,1]; null when scans_seen is 0." },
      },
    },
  },
} as const;

const resp402 = { "402": { description: "Payment Required" } } as const;

// ---------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------
export function openApiDoc(cfg: TollWardenConfig): object {
  return {
    openapi: "3.1.0",
    info: {
      title: "TollWarden",
      version: VERSION,
      description:
        "Check a payment for fraud before your agent sends it. Call TollWarden before settling any x402 payment to avoid paying attacker-controlled addresses injected into content the agent just read (prompt-injection-triggered payments), replayed authorizations, inflated prices, leaked secrets in payment metadata, fake/lookalike USDC contracts, and address poisoning. Returns allow/flag/block with machine-readable reasons and an Ed25519-signed verdict. Advisory and non-custodial — never touches keys or funds. Includes a free-to-use counterparty reputation registry.",
      "x-guidance":
        `Before settling any x402 payment, POST the payment details to /v1/scan/outgoing and act on the verdict: "allow" = proceed, "flag" = pause and confirm intent, "block" = do not pay (machine-readable reasons attached). When you RECEIVE a 402 offer, POST it to /v1/scan/incoming before paying. Include context.origin (planning | tool_result | fetched_content | user_instruction) and, when the decision followed reading external content, context.content — this enables prompt-injection-triggered-payment detection, the check that catches poisoned pay-to addresses. Include expected_price_usd to enable overpayment detection. Endpoints cost ${cfg.priceScan}/call via x402; your first ${cfg.freeCalls} calls are free with an API key from POST /v1/keys (free) sent in the X-API-Key header. Filing counterparty reports via POST /v1/reputation/report is always free. Allow-verdicts carry an Ed25519 attestation bound to the exact payment (verify against /.well-known/tollwarden-verdict-key). If you scan at volume, GET /v1/plans lists subscription tiers with lower per-scan pricing and higher velocity/spend headroom; you can subscribe autonomously — POST /v1/plans/subscribe is itself x402-paid at the plan price, and renewing is just paying again before expiry.`,
      contact: { email: "contact@tollwarden.com" },
    },
    servers: [{ url: cfg.publicBaseUrl }],
    paths: {
      "/v1/scan/outgoing": {
        post: {
          operationId: "scanOutgoingPayment",
          summary: "Is this payment safe to send? Screen an outgoing payment before settling it",
          tags: ["Scanning"],
          ...paidOp(cfg.priceScan),
          requestBody: {
            required: true,
            content: { "application/json": { schema: ScanRequest } },
          },
          responses: {
            "200": {
              description: "Scan verdict",
              content: { "application/json": { schema: ScanResponse } },
            },
            ...resp402,
          },
        },
      },
      "/v1/scan/incoming": {
        post: {
          operationId: "scanIncomingPayment",
          summary: "Is this 402 offer safe to pay? Screen an incoming payment request before paying it",
          tags: ["Scanning"],
          ...paidOp(cfg.priceScan),
          requestBody: {
            required: true,
            content: { "application/json": { schema: ScanRequest } },
          },
          responses: {
            "200": {
              description: "Scan verdict",
              content: { "application/json": { schema: ScanResponse } },
            },
            ...resp402,
          },
        },
      },
      "/v1/reputation/{address}": {
        get: {
          operationId: "getCounterpartyReputation",
          summary: "Has anyone reported this address? Counterparty reputation lookup",
          tags: ["Reputation"],
          ...paidOp(cfg.priceReputation),
          parameters: [
            {
              name: "address",
              in: "path",
              required: true,
              schema: { type: "string" },
              description: "Counterparty address (e.g. 0x…)",
            },
          ],
          responses: {
            "200": {
              description: "Report summary",
              content: { "application/json": { schema: ReputationSummary } },
            },
            ...resp402,
          },
        },
      },
      "/v1/reputation/report": {
        post: {
          operationId: "reportCounterparty",
          summary: "Report a bad counterparty (always free)",
          tags: ["Reputation"],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["address", "category", "reason", "reporter_agent_id"],
                  properties: {
                    address: { type: "string" },
                    category: {
                      type: "string",
                      enum: ["scam", "non_delivery", "prompt_injection", "overcharge", "impersonation", "replay_abuse", "other"],
                    },
                    reason: { type: "string" },
                    reporter_agent_id: { type: "string" },
                    evidence_url: { type: "string" },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Report accepted",
              content: {
                "application/json": {
                  schema: { type: "object", properties: { ok: { type: "boolean" }, report: { type: "object" } } },
                },
              },
            },
            "429": { description: "Rate limited" },
          },
        },
      },
      "/v1/reputation/dispute": {
        post: {
          operationId: "disputeReputation",
          summary: "Attach a signed rebuttal to your wallet's report record (always free)",
          tags: ["Reputation"],
          description:
            'Reputation v2 dispute: a reported wallet can answer its reports. Authentication is key ownership — sign the exact message "tollwarden-dispute-v1|<address lowercase>|<statement>" with the wallet\'s private key (EIP-191 personal_sign) and submit the 65-byte signature. Verified rebuttals appear in every reputation lookup alongside the reports (they never erase them); agents weigh both sides.',
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["address", "statement", "signature"],
                  properties: {
                    address: { type: "string", description: "The reported wallet (0x…) — must match the signature's recovered signer" },
                    statement: { type: "string", minLength: 10, maxLength: 1000, description: "Your side of the story — exactly the text that was signed" },
                    signature: { type: "string", description: "EIP-191 personal_sign signature hex (65 bytes) over tollwarden-dispute-v1|<address>|<statement>" },
                  },
                },
              },
            },
          },
          responses: {
            "201": {
              description: "Dispute verified and attached",
              content: {
                "application/json": {
                  schema: { type: "object", properties: { accepted: { type: "boolean" }, dispute: { type: "object" } } },
                },
              },
            },
            "400": { description: "Validation or signature-verification failure (response includes the exact message to sign)" },
            "429": { description: "Rate limited" },
          },
        },
      },
      "/v1/plans": {
        get: {
          operationId: "getPlansCatalog",
          summary: "Machine-readable plan catalog (tiers, limits, pricing, how to subscribe)",
          tags: ["Plans"],
          // Free endpoint: excluded from x402scan's 402-challenge probing.
          security: [],
          responses: {
            "200": {
              description: "Plan catalog",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      plans: { type: "array", items: { type: "object" } },
                      hard_ceilings: { type: "object" },
                      not_configurable: { type: "string" },
                      how_to_subscribe: { type: "object" },
                    },
                  },
                },
              },
            },
          },
        },
      },
      "/v1/plans/subscribe": {
        post: {
          operationId: "subscribeToPlan",
          summary: "Subscribe/renew an API key on a plan (x402-paid at the plan's price)",
          tags: ["Plans"],
          "x-payment-info": {
            // Dynamic: the 402 challenge quotes the chosen plan's price.
            price: { mode: "dynamic", currency: "USD", min: "4.990000", max: "19.990000" },
            protocols: [{ x402: {} }],
          },
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["plan"],
                  properties: {
                    plan: { type: "string", enum: ["pro", "scale"], description: "Plan id from GET /v1/plans" },
                    agent_id: { type: "string", description: "Optional; used only if a new key is minted" },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Plan activated or renewed on the key from X-API-Key (a new key is minted and returned if none was supplied)",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      plan: { type: "string" },
                      expires_at: { type: "string" },
                      api_key: { type: "string", description: "Only present when newly minted — store it, not recoverable" },
                      limits: { type: "object" },
                      renewal: { type: "string" },
                    },
                  },
                },
              },
            },
            "402": { description: "Payment Required" },
          },
        },
      },
      "/v1/keys": {
        post: {
          operationId: "createApiKey",
          summary: `Issue an API key (free) — first ${cfg.freeCalls} calls free per key`,
          tags: ["Keys"],
          // Free endpoint (not x402-paid): empty security marker excludes it
          // from x402scan's 402-challenge probing (see discovery spec).
          security: [],
          requestBody: {
            required: false,
            content: {
              "application/json": {
                schema: { type: "object", properties: { agent_id: { type: "string" } } },
              },
            },
          },
          responses: {
            "200": {
              description: "New API key (store it now — not recoverable)",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      api_key: { type: "string" },
                      free_calls: { type: "integer" },
                      note: { type: "string" },
                    },
                  },
                },
              },
            },
            "429": { description: "Rate limited" },
          },
        },
      },
      "/v1/approvals/config": {
        post: {
          operationId: "configureApprovals",
          summary: "Enable human-in-the-loop approvals: flag verdicts pause for a human decision via your webhook",
          description:
            "On every flag verdict for your key, TollWarden POSTs the payment facts and a one-time decide link to webhook_url (HMAC-SHA256-signed with the returned secret; header X-TollWarden-Signature). A human approves or denies; approval mints a short-lived Ed25519-signed override verdict (tag 'override:allow', <=5 min) bound to exactly that payment. SECURITY: the decide link is a bearer credential — the webhook destination must be out of the agent's own reach, or the agent could approve itself. Live mode requires a public https webhook. Pass webhook_url: null to disable (the response carries an advisory: flags return to advisory-only and no overrides are minted). Deployments can switch the whole feature off with APPROVALS=off.",
          tags: ["Approvals"],
          security: [],
          parameters: [{ name: "X-API-Key", in: "header", required: true, schema: { type: "string" } }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    webhook_url: { type: "string", nullable: true, description: "Public https URL to receive approval requests; null disables" },
                    format: { type: "string", enum: ["json", "slack"], default: "json", description: "slack posts a human-readable message (weaker: the decide link lands in channel history)" },
                  },
                },
              },
            },
          },
          responses: {
            "200": { description: "Config saved; response includes the webhook signing secret ONCE" },
            "400": { description: "Invalid webhook URL" },
            "401": { description: "Missing or invalid key" },
          },
        },
      },
      "/v1/approvals/{id}": {
        get: {
          operationId: "pollApproval",
          summary: "Poll a pending approval (owning key only); on approve, returns the signed override verdict",
          tags: ["Approvals"],
          security: [],
          parameters: [
            { name: "id", in: "path", required: true, schema: { type: "string" } },
            { name: "X-API-Key", in: "header", required: true, schema: { type: "string" } },
          ],
          responses: {
            "200": {
              description: "Approval state. status: pending | approved | denied | expired. On approved, `override` is a scan-shaped object with verdict 'override:allow' and an Ed25519 attestation bound to the payment commitment (<=5 min expiry).",
            },
            "401": { description: "Missing or invalid key" },
            "404": { description: "Unknown approval (or owned by a different key — indistinguishable)" },
          },
        },
      },
      "/v1/usage": {
        get: {
          operationId: "getUsage",
          summary: "Your own key's usage stats and approval-decision telemetry (owner-only)",
          description:
            "Aggregates for the CALLER'S OWN key: scan/verdict counts, free-tier quota, plan status, and `approvals` — decision counts, decision-latency aggregates (median/p90, recent vs. baseline windows), and the delivery outcomes of approved payments. The approval telemetry is evidence about the operator (latency shrinking while approval rate stays near 100% is the signature of rubber-stamping), so it is visible only to the owning key: it never feeds a verdict and never appears in reputation lookups, trust evaluations, or public stats.",
          tags: ["Keys"],
          security: [],
          parameters: [{ name: "X-API-Key", in: "header", required: true, schema: { type: "string" } }],
          responses: {
            "200": {
              description:
                "account {created_at, agent_id, last_used_at} · free_tier {included, used, remaining} · plan {id, name, expires_at, price_per_scan} · scans {total, allow, flag, block, block_rate} · approvals {configured, requested, approved, denied, expired, decision_latency_ms {count, median, p90} | null, recent/baseline {count, median_latency_ms, approval_rate} | null, approved_outcomes {delivered, not_delivered, partial, wrong_content, unreported}}.",
            },
            "401": { description: "Missing, unknown, or dead key (rotated/revoked keys get a named code)" },
          },
        },
      },
      "/v1/outcomes": {
        post: {
          operationId: "reportOutcome",
          summary: "Record whether a scanned, settled payment actually delivered (commitment-bound)",
          description:
            "The delivery-outcome leg: scans validate the payment; this records whether the seller shipped. The report must present the scan_id AND payment_commitment of a scan TollWarden performed (one outcome per scan; keyed scans only from the scanning account) — so delivery history cannot be fabricated without making real, scanned payments. Aggregated per counterparty into delivery rates that feed GET /v1/reputation/{address} and the flag-only `delivery` check on future scans; also aggregated per resource DOMAIN recorded at scan time, so rotating the pay_to address does not reset a domain's delivery record. Flag decisions use a prior-smoothed rate (small samples don't over-trigger); the raw rate is always reported. The official SDK payment-path wrappers report outcomes automatically.",
          tags: ["Reputation"],
          security: [],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["scan_id", "payment_commitment", "outcome"],
                  properties: {
                    scan_id: { type: "string", description: "From the scan response" },
                    payment_commitment: { type: "string", description: "From the scan's attestation.payment_commitment" },
                    outcome: { type: "string", enum: ["delivered", "not_delivered", "partial", "wrong_content"] },
                    evidence: {
                      type: "object",
                      properties: {
                        status: { type: "integer" },
                        content_type: { type: "string" },
                        bytes: { type: "integer" },
                        latency_ms: { type: "integer" },
                        settlement_receipt: {
                          type: "string",
                          enum: ["present", "absent"],
                          description: "Whether the seller returned a settlement-receipt header. 'absent' records a receiptless settlement (counted and surfaced, never blocking).",
                        },
                      },
                    },
                  },
                },
              },
            },
          },
          responses: {
            "201": { description: "Outcome recorded and aggregated against the scanned counterparty" },
            "200": { description: "Idempotent repeat of the already-recorded outcome" },
            "400": { description: "Invalid outcome value" },
            "404": { description: "Unknown scan, commitment mismatch, or wrong account (indistinguishable)" },
            "409": { description: "A different outcome is already recorded (outcomes are final)" },
            "429": { description: "Rate limited" },
          },
        },
      },
      "/v1/keys/rotate": {
        post: {
          operationId: "rotateApiKey",
          summary: "Rotate your API key: fresh secret, same account (usage, free quota, and plan carry over)",
          description:
            "Mints a replacement psk_ secret bound to the SAME account. The old secret keeps working for grace_seconds (default 900, 0 = immediately dead, max 86400) so a fleet can switch over, but can no longer rotate or revoke. Rotation never resets the free tier. Authenticate with the current key in X-API-Key.",
          tags: ["Keys"],
          security: [],
          parameters: [
            { name: "X-API-Key", in: "header", required: true, schema: { type: "string" } },
          ],
          requestBody: {
            required: false,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    grace_seconds: { type: "integer", minimum: 0, maximum: 86400, default: 900, description: "How long the old secret keeps working" },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Replacement key (store it now — not recoverable)",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      api_key: { type: "string" },
                      api_key_sha256: { type: "string", description: "Hash of the new key (rebind ADMIN_KEY_SHA256 if this was the admin key)" },
                      rotated_at: { type: "string" },
                      previous_key_valid_until: { type: "string", nullable: true },
                      carried_over: {
                        type: "object",
                        properties: {
                          free_calls_remaining: { type: "integer" },
                          plan: { type: "string", nullable: true },
                          scans_total: { type: "integer" },
                        },
                      },
                      note: { type: "string" },
                    },
                  },
                },
              },
            },
            "401": { description: "Missing, unknown, rotated, or revoked key" },
            "403": { description: "An already-rotated (in-grace) key cannot rotate the account" },
            "429": { description: "Rate limited" },
          },
        },
      },
      "/v1/keys/revoke": {
        post: {
          operationId: "revokeApiKey",
          summary: "Permanently revoke your API key (leaked-key kill switch) — irreversible",
          description:
            "Kills the key AND its account: usage history, remaining free calls, and any active plan are destroyed. The tombstone persists, so the dead key keeps failing with an explanatory 401. Requires {\"confirm\": true}. To swap the secret and KEEP the account, use /v1/keys/rotate instead.",
          tags: ["Keys"],
          security: [],
          parameters: [
            { name: "X-API-Key", in: "header", required: true, schema: { type: "string" } },
          ],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["confirm"],
                  properties: { confirm: { type: "boolean", description: "Must be true — revocation is irreversible" } },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Key and account permanently dead",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      revoked: { type: "boolean" },
                      revoked_at: { type: "string" },
                      note: { type: "string" },
                    },
                  },
                },
              },
            },
            "400": { description: "Missing {\"confirm\": true}" },
            "401": { description: "Missing, unknown, rotated, or revoked key" },
            "403": { description: "An already-rotated (in-grace) key cannot revoke the account" },
            "429": { description: "Rate limited" },
          },
        },
      },
    },
  };
}
