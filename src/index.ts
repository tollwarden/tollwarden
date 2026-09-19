// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * TollWarden — production entrypoint.
 * Express + official x402 middleware (@x402/express) + CDP facilitator + Bazaar discovery.
 *
 * Paid routes (x402, "exact" scheme, USDC):
 *   POST /v1/scan/outgoing        cfg.priceScan
 *   POST /v1/scan/incoming        cfg.priceScan
 *   GET  /v1/reputation/:address  cfg.priceReputation
 * Free routes (rate-limited where writable):
 *   POST /v1/keys, POST /v1/reputation/report, GET /, /health, /.well-known/*
 *
 * Free tier: first cfg.freeCalls calls per API key (X-API-Key header) bypass payment.
 */
import express from "express";
import { join } from "node:path";
import { timingSafeEqual } from "node:crypto";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { facilitator as cdpFacilitator } from "@coinbase/x402";
import {
  bazaarResourceServerExtension,
  declareDiscoveryExtension,
} from "@x402/extensions/bazaar";

import { loadConfig } from "./config.ts";
import { Store } from "./store.ts";
import { AuditLog } from "./auditlog.ts";
import { VerdictSigner } from "./verdictsign.ts";
import { RateLimiter } from "./ratelimit.ts";
import {
  consumeFreeCall,
  createApiKey,
  freeCallsRemaining,
  handlePlansCatalog,
  handlePlanSubscribe,
  handleReputationDispute,
  handleReputationLookup,
  handleReputationReport,
  handleAdminSetFirstParty,
  handleAdminStats,
  handleApprovalConfig,
  handleKeyRevoke,
  handleKeyRotate,
  handleScan,
  handleUsage,
  serviceInfo,
} from "./api.ts";
import { PLANS, resolveEffectiveConfig, type Plan } from "./plans.ts";
import { x402Manifest, agentCard, erc8004Registration, logoSvg } from "./manifest.ts";
import { openApiDoc } from "./openapi.ts";
import { dashboardHtml } from "./dashboard.ts";
import { adminDashboardHtml } from "./admindash.ts";
import { approvePageHtml } from "./approvepage.ts";
import { handleApprovalDecide, handleApprovalInspect, handleApprovalPoll } from "./approvals.ts";
import { handleOutcomeReport } from "./outcomes.ts";
import { llmsTxt } from "./llms.ts";
import { homePageHtml, termsPageHtml, privacyPageHtml } from "./pages.ts";
import { publicStats } from "./pubstats.ts";
import { handleTrustEvaluate } from "./trust.ts";

const cfg = loadConfig();
const store = new Store(cfg.dataDir, {
  nonceTtlHours: cfg.nonceTtlHours,
  maxEntries: cfg.maxStoreEntries,
});
store.loadBadlist(cfg.badlistPath ?? join(cfg.dataDir, "badlist.json"));
if (cfg.auditLog) store.auditLog = new AuditLog(join(cfg.dataDir, "audit.log"));
const signer = cfg.verdictSigning ? new VerdictSigner(cfg.dataDir) : null;

const keyLimiter = new RateLimiter(cfg.keysPerIpPerDay, 24 * 3600_000);
const reportLimiter = new RateLimiter(cfg.reportsPerIpPerHour, 3600_000);
const trustLimiter = new RateLimiter(cfg.trustQueriesPerIpPerHour, 3600_000);
const approvalLimiter = new RateLimiter(cfg.approvalActionsPerIpPerHour, 3600_000);
const outcomesLimiter = new RateLimiter(cfg.outcomesPerIpPerHour, 3600_000);

if (cfg.mode === "live" && !cfg.payTo) {
  console.error("PAY_TO (receiving wallet address) is required in live mode. Set TOLLWARDEN_MODE=dev to run without payments.");
  process.exit(1);
}

const app = express();
app.set("trust proxy", 1); // Render/most PaaS terminate TLS at a proxy; req.ip = client IP
// Audit C-1: make the router reject path variants (trailing slash, case) rather
// than route them to a handler that the payment gate's exact-string matcher
// would then let through for free. Combined with the normalized matcher below.
app.set("strict routing", true);
app.set("case sensitive routing", true);
app.use(express.json({ limit: "512kb" }));

// ---------------------------------------------------------------------------
// x402 payment layer
// ---------------------------------------------------------------------------
const SCAN_PAYMENT_EXAMPLE = {
  payment: {
    scheme: "exact",
    network: "eip155:8453",
    amount: "50000",
    asset_decimals: 6,
    pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    resource_url: "https://api.example.com/premium",
    description: "Premium data access",
    nonce: "0x1a2b3c",
  },
  expected_price_usd: 0.05,
  context: { origin: "planning" },
};

const SCAN_INPUT_SCHEMA = {
  properties: {
    agent_id: { type: "string", description: "Identifier of the scanning agent (labels the scan; velocity and history are scoped to your API key's account, and to agent_id only for anonymous scans)" },
    payment: {
      type: "object",
      description:
        "The x402 payment (or payment request) to screen: scheme, network, amount (atomic) or amount_usd, asset, pay_to, payer, resource_url, description, reason, nonce, metadata",
    },
    expected_price_usd: { type: "number", description: "What the agent expected this to cost (USD)" },
    context: {
      type: "object",
      description:
        "Provenance: origin (planning|user_instruction|tool_result|fetched_content|unknown), content (the content the agent just read), content_source_url",
    },
    policy: {
      type: "object",
      description: "Tiering overrides: force_deep / skip_deep for the deep content-analysis tier",
    },
  },
  required: ["payment"],
};

const SCAN_OUTPUT_EXAMPLE = {
  scan_id: "6f9c9d5e-…",
  direction: "outgoing",
  verdict: "block",
  risk_score: 95,
  checks: [
    {
      id: "replay.nonce_reuse",
      verdict: "block",
      severity: "critical",
      reason: "Nonce reuse detected: first seen 2026-07-14T09:00:00Z …",
    },
  ],
  scanned_at: "2026-07-14T09:01:00Z",
  advisory: "Recommended action: DO NOT settle this payment. …",
  attestation: {
    alg: "ed25519",
    message: "6f9c9d5e-…|outgoing|block|95|2026-07-14T09:01:00Z",
    signature_hex: "…",
  },
};

// The SDK types CAIP-2 network ids as a template-literal type.
const x402Network = cfg.network as `${string}:${string}`;

function makeResourceServer() {
  const facilitatorClient =
    cfg.facilitator === "cdp"
      ? new HTTPFacilitatorClient(cdpFacilitator) // uses CDP_API_KEY_ID / CDP_API_KEY_SECRET env vars
      : new HTTPFacilitatorClient({ url: "https://x402.org/facilitator" });

  const server = new x402ResourceServer(facilitatorClient).register(
    x402Network,
    new ExactEvmScheme(),
  );

  // Bazaar indexing: register the resource-server extension so declared
  // discovery metadata is attached to verify/settle calls and CDP catalogs
  // the routes after the first successful settlement.
  try {
    const s = server as unknown as {
      registerExtension?: (ext: unknown) => unknown;
      use?: (ext: unknown) => unknown;
    };
    if (typeof s.registerExtension === "function") s.registerExtension(bazaarResourceServerExtension);
    else if (typeof s.use === "function") s.use(bazaarResourceServerExtension);
  } catch (err) {
    console.warn("Bazaar extension registration failed (service still works, just not Bazaar-indexed):", err);
  }
  return server;
}

/** x402 layer for the scan/reputation routes at a given per-scan price.
 * One instance exists per distinct plan price; the payment gate picks the
 * instance matching the caller's active plan. */
function buildX402Layer(scanPrice: string) {
  const server = makeResourceServer();
  const network = x402Network;

  const scanAccepts = [
    { scheme: "exact", price: scanPrice, network, payTo: cfg.payTo },
  ];

  // Typed loosely: the SDK's RoutesConfig uses branded/template-literal types
  // that vary across minor versions; the runtime shape below follows the
  // official seller quickstart exactly.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const routes: any = {
    "POST /v1/scan/outgoing": {
      accepts: scanAccepts,
      description:
        "Payment security firewall scan for an OUTGOING x402 payment: PII/secret leak detection in payment metadata, nonce replay detection, overpayment detection, prompt-injection-triggered payment analysis (fast + deep tiers), canonical-USDC asset verification, merchant pinning, velocity/spend caps, and counterparty reputation cross-check. Returns allow/flag/block with per-check reasons and an Ed25519-signed verdict. Advisory and non-custodial.",
      mimeType: "application/json",
      extensions: {
        ...declareDiscoveryExtension({
          input: SCAN_PAYMENT_EXAMPLE,
          inputSchema: SCAN_INPUT_SCHEMA,
          bodyType: "json",
          output: { example: SCAN_OUTPUT_EXAMPLE },
        }),
      },
    },
    "POST /v1/scan/incoming": {
      accepts: scanAccepts,
      description:
        "Payment security firewall scan for an INCOMING x402 payment request (402 offer): resource URL risk, credential-demand detection, price sanity, replay detection, canonical-USDC asset verification, merchant pinning, and counterparty reputation. Returns allow/flag/block with per-check reasons and an Ed25519-signed verdict. Advisory and non-custodial.",
      mimeType: "application/json",
      extensions: {
        ...declareDiscoveryExtension({
          input: SCAN_PAYMENT_EXAMPLE,
          inputSchema: SCAN_INPUT_SCHEMA,
          bodyType: "json",
          output: { example: { ...SCAN_OUTPUT_EXAMPLE, direction: "incoming" } },
        }),
      },
    },
    "GET /v1/reputation/:address": {
      accepts: [
        { scheme: "exact", price: cfg.priceReputation, network, payTo: cfg.payTo },
      ],
      description:
        "Counterparty reputation lookup for x402 payments: aggregated post-hoc reports (scam, non-delivery, prompt injection, overcharge, impersonation, replay abuse) filed by other agents, with distinct-reporter counts and risk level.",
      mimeType: "application/json",
      extensions: {
        ...declareDiscoveryExtension({
          input: { address: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C" },
          inputSchema: {
            properties: {
              address: { type: "string", description: "Wallet address to look up" },
            },
            required: ["address"],
          },
          output: {
            example: {
              address: "0x…",
              status: "reported",
              risk: "medium",
              report_count: 3,
              distinct_reporters: 2,
              categories: { non_delivery: 2, overcharge: 1 },
            },
          },
        }),
      },
    },
  };

  return paymentMiddleware(routes, server);
}

/** x402 layer for POST /v1/plans/subscribe at a specific plan's price. */
function buildSubscribeLayer(plan: Plan) {
  const server = makeResourceServer();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const routes: any = {
    "POST /v1/plans/subscribe": {
      accepts: [{ scheme: "exact", price: plan.price, network: x402Network, payTo: cfg.payTo }],
      description: `Subscribe your TollWarden API key to the ${plan.name} plan (${plan.price} / ${plan.duration_days} days): ${plan.description}`,
      mimeType: "application/json",
    },
  };
  return paymentMiddleware(routes, server);
}

if (cfg.mode === "live") {
  // One scan-price layer per distinct plan price (default + each plan).
  const scanPrices = new Set<string>([cfg.priceScan, ...PLANS.map((p) => p.limits.price_per_scan)]);
  const paidByScanPrice = new Map<string, ReturnType<typeof buildX402Layer>>();
  for (const price of scanPrices) paidByScanPrice.set(price, buildX402Layer(price));
  const subscribeByPlan = new Map<string, ReturnType<typeof buildSubscribeLayer>>();
  for (const plan of PLANS) subscribeByPlan.set(plan.id, buildSubscribeLayer(plan));

  // Normalize before matching so a trailing slash or different case can never
  // route a request AROUND the payment gate (audit C-1).
  const normPath = (req: express.Request): string => req.path.replace(/\/+$/, "").toLowerCase();
  const isPaidRoute = (req: express.Request): boolean => {
    const p = normPath(req);
    return (
      (req.method === "POST" && (p === "/v1/scan/outgoing" || p === "/v1/scan/incoming")) ||
      (req.method === "GET" && /^\/v1\/reputation\/[^/]+$/.test(p))
    );
  };

  app.use((req, res, next) => {
    // Plan subscriptions: always paid at the plan's price — the free-call
    // quota never covers a subscription purchase. Unknown plan ids skip
    // payment and fall through to the handler's 400 (nothing to quote).
    if (req.method === "POST" && normPath(req) === "/v1/plans/subscribe") {
      const planId = (req.body as { plan?: unknown } | undefined)?.plan;
      const mw = typeof planId === "string" ? subscribeByPlan.get(planId) : undefined;
      if (!mw) return next();
      return mw(req, res, next);
    }
    if (!isPaidRoute(req)) return next();
    const apiKey = req.header("x-api-key");
    if (consumeFreeCall(store, cfg, apiKey)) {
      const remaining = freeCallsRemaining(store, cfg, apiKey);
      if (remaining !== null) res.setHeader("X-Free-Calls-Remaining", String(remaining));
      return next(); // free-tier call: skip payment
    }
    // Per-plan scan pricing: quote the caller's plan price (default otherwise).
    const eff = resolveEffectiveConfig(cfg, store, apiKey);
    const paid = paidByScanPrice.get(eff.priceScan) ?? paidByScanPrice.get(cfg.priceScan)!;
    return paid(req, res, next); // x402: 402 → pay → retry
  });
} else {
  console.log("TollWarden running in DEV mode — x402 payments disabled, all endpoints free.");
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
// Content-negotiated index: browsers (Accept: text/html) get the human
// homepage rendered from HOME.md; agents and curl (Accept: */*) keep getting
// the self-documenting JSON that llms.txt and existing tooling point at.
app.get("/", (req, res) => {
  const home = homePageHtml(cfg, publicStats(store));
  if (home !== null && req.accepts(["json", "html"]) === "html") {
    htmlPage(home, res);
    return;
  }
  const r = serviceInfo(cfg);
  res.status(r.status).json(r.body);
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, mode: cfg.mode, time: new Date().toISOString() });
});

// Public aggregate service stats + self-measured uptime (the homepage's
// "track record" data). Free and unauthenticated, so it must stay O(1): it
// serves the pubstats TTL cache and never reads the audit log per request.
// Aggregates only — same privacy rules as /v1/admin/stats, minus the per-day
// breakdown and USD totals (see pubstats.ts).
app.get("/v1/stats", (_req, res) => {
  res.json(publicStats(store));
});

app.get("/.well-known/x402", (_req, res) => {
  res.json(x402Manifest(cfg));
});

// Agent/LLM-facing discovery page (intent-first, plain text).
app.get("/llms.txt", (_req, res) => {
  res.type("text/plain; charset=utf-8").send(llmsTxt(cfg));
});
app.get("/.well-known/llms.txt", (_req, res) => {
  res.type("text/plain; charset=utf-8").send(llmsTxt(cfg));
});

// Legal pages, rendered from the canonical TERMS.md / PRIVACY.md. Static HTML
// with no script at all, so the CSP here doesn't even allow inline script.
const htmlPage = (html: string | null, res: express.Response): void => {
  if (html === null) {
    res.status(404).json({ error: "Document not available in this deployment" });
    return;
  }
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.type("html").send(html);
};
app.get("/terms", (_req, res) => htmlPage(termsPageHtml(), res));
app.get("/privacy", (_req, res) => htmlPage(privacyPageHtml(), res));

app.get("/.well-known/agent-card.json", (_req, res) => {
  res.json(agentCard(cfg));
});

// ERC-8004 on-chain identity: this file is the agentURI/tokenURI of TollWarden's
// agent NFT in the IdentityRegistry on Base (minted by the PAY_TO wallet).
app.get("/.well-known/erc8004.json", (_req, res) => {
  res.json(erc8004Registration(cfg));
});

app.get("/logo.svg", (_req, res) => {
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.type("image/svg+xml").send(logoSvg());
});

// Canonical machine-readable API contract (x402scan discovery + agent tooling).
app.get("/openapi.json", (_req, res) => {
  res.json(openApiDoc(cfg));
});

const verdictKeyHandler = (_req: express.Request, res: express.Response) => {
  if (!signer) {
    res.status(404).json({ error: "Verdict signing disabled (VERDICT_SIGNING=off)" });
    return;
  }
  res.json(signer.publicKeyInfo());
};
app.get("/.well-known/tollwarden-verdict-key", verdictKeyHandler);
// Legacy path from before the TollWarden rename — deployed SDKs (< 0.6.0) pin this URL.
app.get("/.well-known/paysafe-verdict-key", verdictKeyHandler);

app.post("/v1/keys", (req, res) => {
  if (!keyLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.keysPerIpPerDay} keys per IP per day.` });
    return;
  }
  const r = createApiKey(store, cfg, (req.body as { agent_id?: string } | undefined)?.agent_id);
  res.status(r.status).json(r.body);
});

// Key lifecycle. Both share the key-mint limiter (each rotate writes a
// tombstone, so it must not be free to hammer) and are never payment-gated.
app.post("/v1/keys/rotate", (req, res) => {
  if (!keyLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.keysPerIpPerDay} key operations per IP per day.` });
    return;
  }
  const r = handleKeyRotate(store, cfg, req.header("x-api-key"), req.body);
  res.status(r.status).json(r.body);
});

app.post("/v1/keys/revoke", (req, res) => {
  if (!keyLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.keysPerIpPerDay} key operations per IP per day.` });
    return;
  }
  const r = handleKeyRevoke(store, cfg, req.header("x-api-key"), req.body);
  res.status(r.status).json(r.body);
});

app.post("/v1/scan/outgoing", (req, res) => {
  const r = handleScan("outgoing", req.body, cfg, store, signer, req.header("x-api-key"));
  res.status(r.status).json(r.body);
});

app.post("/v1/scan/incoming", (req, res) => {
  const r = handleScan("incoming", req.body, cfg, store, signer, req.header("x-api-key"));
  res.status(r.status).json(r.body);
});

app.get("/v1/plans", (_req, res) => {
  const r = handlePlansCatalog(cfg);
  res.status(r.status).json(r.body);
});

// Usage stats for the caller's own key (free, never payment-gated).
app.get("/v1/usage", (req, res) => {
  const r = handleUsage(cfg, store, req.header("x-api-key"));
  res.status(r.status).json(r.body);
});

// Self-contained usage dashboard. Locked-down CSP: the page loads zero external
// resources and only ever calls same-origin /v1/usage, so there is nowhere for
// a hypothetical injected script to send data. The API key lives only in the
// browser and is sent as a header — never in the URL.
app.get("/dashboard", (_req, res) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.type("html").send(dashboardHtml());
});

// Owner-only all-time stats (see handleAdminStats: 404 unless ADMIN_KEY_SHA256
// is set; 401 for any key but the owner's). Free, never payment-gated.
app.get("/v1/admin/stats", (req, res) => {
  const r = handleAdminStats(cfg, store, req.header("x-api-key"));
  res.status(r.status).json(r.body);
});

// Owner dashboard — same CSP posture as /dashboard: zero external resources,
// key via header only, read-only endpoints.
// Owner-only: mark a key as operator-owned so its scans are reported
// separately from third-party usage. See handleAdminSetFirstParty.
app.post("/v1/admin/keys/first-party", (req, res) => {
  const r = handleAdminSetFirstParty(cfg, store, req.header("x-api-key"), req.body);
  res.status(r.status).json(r.body);
});

app.get("/admin", (_req, res) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.type("html").send(adminDashboardHtml());
});

// --- Human-in-the-loop step-up approvals (free, never payment-gated) ---

// Configure the operator webhook (X-API-Key; current key only). Shares the
// key limiter — config writes must not be free to hammer.
app.post("/v1/approvals/config", (req, res) => {
  if (!keyLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.keysPerIpPerDay} key operations per IP per day.` });
    return;
  }
  const r = handleApprovalConfig(store, cfg, req.header("x-api-key"), req.body);
  res.status(r.status).json(r.body);
});

// Token-authed endpoints for the human decide flow (no API key involved).
app.post("/v1/approvals/inspect", (req, res) => {
  if (!approvalLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.approvalActionsPerIpPerHour} approval actions per IP per hour.` });
    return;
  }
  const r = handleApprovalInspect(store, req.body);
  res.status(r.status).json(r.body);
});

app.post("/v1/approvals/decide", (req, res) => {
  if (!approvalLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.approvalActionsPerIpPerHour} approval actions per IP per hour.` });
    return;
  }
  const r = handleApprovalDecide(store, cfg, signer, req.body);
  res.status(r.status).json(r.body);
});

// Delivery-outcome ledger: record whether a scanned, settled payment actually
// delivered. Free, commitment-bound (see outcomes.ts), never payment-gated.
app.post("/v1/outcomes", (req, res) => {
  if (!outcomesLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.outcomesPerIpPerHour} outcome reports per IP per hour.` });
    return;
  }
  const r = handleOutcomeReport(store, cfg, req.header("x-api-key"), req.body);
  res.status(r.status).json(r.body);
});

// The owning key polls for the outcome (override attestation on approve).
app.get("/v1/approvals/:id", (req, res) => {
  const r = handleApprovalPoll(store, req.params.id, req.header("x-api-key"));
  res.status(r.status).json(r.body);
});

// The human decide page — the webhook's decide link lands here with the
// one-time token in the URL FRAGMENT (never sent to any server). Same CSP
// posture as the dashboards; facts render via textContent only.
app.get("/approve", (_req, res) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.type("html").send(approvePageHtml());
});

// Payment for this route is enforced by the gate above (x402 at the plan's
// price); in dev mode it activates directly.
app.post("/v1/plans/subscribe", (req, res) => {
  const r = handlePlanSubscribe(req.body, cfg, store, req.header("x-api-key"));
  res.status(r.status).json(r.body);
});

app.get("/v1/reputation/:address", (req, res) => {
  const r = handleReputationLookup(req.params.address, store);
  res.status(r.status).json(r.body);
});

// x402 trust-provider interface (#2299): TrustQuery in, TrustEvaluation out.
// Free + rate-limited; sellers call this from onBeforeSettle to gate on the
// payer's history. FAILs come only from the curated badlist (audit H-2).
app.post("/v1/trust/evaluate", (req, res) => {
  if (!trustLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.trustQueriesPerIpPerHour} trust evaluations per IP per hour.` });
    return;
  }
  const r = handleTrustEvaluate(req.body, cfg, store);
  res.status(r.status).json(r.body);
});

app.post("/v1/reputation/report", (req, res) => {
  if (!reportLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.reportsPerIpPerHour} reports per IP per hour.` });
    return;
  }
  const r = handleReputationReport(req.body, store);
  res.status(r.status).json(r.body);
});

// Signed rebuttal from a reported wallet (reputation v2). Free; shares the
// report limiter — both sides of the registry cost the same to speak.
app.post("/v1/reputation/dispute", (req, res) => {
  if (!reportLimiter.allow(req.ip ?? "unknown")) {
    res.status(429).json({ error: `Rate limit: max ${cfg.reportsPerIpPerHour} disputes per IP per hour.` });
    return;
  }
  const r = handleReputationDispute(req.body, store);
  res.status(r.status).json(r.body);
});

// Audit trail integrity (no record contents exposed — only chain head + a
// verification result). Useful for external monitoring / anchoring.
app.get("/v1/audit/head", (_req, res) => {
  if (!store.auditLog) {
    res.status(404).json({ error: "Audit log disabled (AUDIT_LOG=off)" });
    return;
  }
  res.json(store.auditLog.head());
});

app.get("/v1/audit/verify", (_req, res) => {
  if (!store.auditLog) {
    res.status(404).json({ error: "Audit log disabled (AUDIT_LOG=off)" });
    return;
  }
  res.json(store.auditLog.verify());
});

// Full-log export for offsite/WORM backup. Gated by ADMIN_TOKEN (X-Admin-Token
// header, constant-time compare); 404 when unconfigured so the route doesn't
// advertise itself. Records contain payment hashes + non-sensitive facts only.
app.get("/v1/audit/export", (req, res) => {
  if (!cfg.adminToken || !store.auditLog) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  const given = Buffer.from(req.header("x-admin-token") ?? "", "utf8");
  const want = Buffer.from(cfg.adminToken, "utf8");
  if (given.length !== want.length || !timingSafeEqual(given, want)) {
    res.status(403).json({ error: "forbidden" });
    return;
  }
  res.type("application/x-ndjson").send(store.auditLog.exportRaw());
});

// JSON error handler: never leak stack traces.
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("handler error:", err);
  res.status(500).json({ error: "internal error" });
});

const serverInstance = app.listen(cfg.port, () => {
  console.log(`TollWarden listening on :${cfg.port} (${cfg.mode} mode, network ${cfg.network}, facilitator ${cfg.facilitator})`);
});

process.on("SIGTERM", () => {
  serverInstance.close(() => {
    store.close();
    process.exit(0);
  });
});
