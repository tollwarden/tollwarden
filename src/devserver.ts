// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Zero-dependency dev server (node:http only). Same API surface as index.ts
 * but with x402 payments disabled — for local development, CI, and the
 * examples/ scripts. Run: npm run dev
 */
import { createServer } from "node:http";
import { join } from "node:path";
import { loadConfig } from "./config.ts";
import { Store } from "./store.ts";
import { AuditLog } from "./auditlog.ts";
import { VerdictSigner } from "./verdictsign.ts";
import { RateLimiter } from "./ratelimit.ts";
import {
  createApiKey,
  handleAdminStats,
  handleApprovalConfig,
  handleKeyRevoke,
  handleKeyRotate,
  handlePlansCatalog,
  handlePlanSubscribe,
  handleReputationDispute,
  handleReputationLookup,
  handleReputationReport,
  handleScan,
  handleUsage,
  serviceInfo,
} from "./api.ts";
import { x402Manifest, agentCard, erc8004Registration, logoSvg } from "./manifest.ts";
import { openApiDoc } from "./openapi.ts";
import { dashboardHtml } from "./dashboard.ts";
import { adminDashboardHtml } from "./admindash.ts";
import { approvePageHtml } from "./approvepage.ts";
import { llmsTxt } from "./llms.ts";
import { homePageHtml, termsPageHtml, privacyPageHtml, canonicalLinkHeader, robotsTxt, sitemapXml, NOINDEX } from "./pages.ts";
import { publicStats } from "./pubstats.ts";
import { handleTrustEvaluate } from "./trust.ts";
import { handleApprovalDecide, handleApprovalInspect, handleApprovalPoll } from "./approvals.ts";
import { handleOutcomeReport } from "./outcomes.ts";
import type { ApiResult } from "./api.ts";

const cfg = { ...loadConfig(), mode: "dev" as const };
const ephemeral = process.env.DATA_DIR === "none";
const store = new Store(ephemeral ? null : cfg.dataDir, {
  nonceTtlHours: cfg.nonceTtlHours,
  maxEntries: cfg.maxStoreEntries,
});
store.loadBadlist(cfg.badlistPath ?? join(cfg.dataDir, "badlist.json"));
if (cfg.auditLog) store.auditLog = new AuditLog(ephemeral ? null : join(cfg.dataDir, "audit.log"));
const signer = cfg.verdictSigning ? new VerdictSigner(ephemeral ? null : cfg.dataDir) : null;

const keyLimiter = new RateLimiter(cfg.keysPerIpPerDay, 24 * 3600_000);
const reportLimiter = new RateLimiter(cfg.reportsPerIpPerHour, 3600_000);
const trustLimiter = new RateLimiter(cfg.trustQueriesPerIpPerHour, 3600_000);
const approvalLimiter = new RateLimiter(cfg.approvalActionsPerIpPerHour, 3600_000);
const outcomesLimiter = new RateLimiter(cfg.outcomesPerIpPerHour, 3600_000);
const LIMITED: ApiResult = { status: 429, body: { error: "Rate limit exceeded for this endpoint. Try again later." } };

/** Canonical `Link` header for an indexable page; none without a public https origin. */
function canonicalHeader(path: string): Record<string, string> {
  const link = canonicalLinkHeader(cfg, path);
  return link === null ? {} : { link };
}

function readBody(req: import("node:http").IncomingMessage): Promise<unknown> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > 512 * 1024) req.destroy();
    });
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : undefined);
      } catch {
        resolve(undefined);
      }
    });
  });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;
  const method = req.method ?? "GET";
  const ip = req.socket.remoteAddress ?? "unknown";

  let out: ApiResult;
  try {
    if (method === "GET" && path === "/") {
      // Same content negotiation as production: HTML for browsers, JSON otherwise.
      const home = homePageHtml(cfg, publicStats(store));
      if (home !== null && /text\/html/.test(req.headers.accept ?? "")) {
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
          "vary": "Accept",
          ...canonicalHeader("/"),
        });
        res.end(home);
        return;
      }
      res.setHeader("vary", "Accept");
      out = serviceInfo(cfg);
    }
    else if (method === "GET" && path === "/health")
      out = { status: 200, body: { ok: true, mode: cfg.mode, time: new Date().toISOString() } };
    else if (method === "GET" && path === "/v1/stats")
      out = { status: 200, body: publicStats(store) };
    else if (method === "GET" && path === "/.well-known/x402")
      out = { status: 200, body: x402Manifest(cfg) };
    else if (method === "GET" && (path === "/llms.txt" || path === "/.well-known/llms.txt")) {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end(llmsTxt(cfg));
      return;
    }
    else if (method === "GET" && path === "/openapi.json")
      out = { status: 200, body: openApiDoc(cfg) };
    else if (method === "GET" && path === "/.well-known/agent-card.json")
      out = { status: 200, body: agentCard(cfg) };
    else if (method === "GET" && path === "/.well-known/erc8004.json")
      out = { status: 200, body: erc8004Registration(cfg) };
    else if (method === "GET" && path === "/logo.svg") {
      res.writeHead(200, { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400" });
      res.end(logoSvg());
      return;
    }
    else if (method === "GET" && (path === "/.well-known/tollwarden-verdict-key" || path === "/.well-known/paysafe-verdict-key"))
      out = signer
        ? { status: 200, body: signer.publicKeyInfo() }
        : { status: 404, body: { error: "Verdict signing disabled (VERDICT_SIGNING=off)" } };
    else if (method === "POST" && path === "/v1/keys") {
      if (!keyLimiter.allow(ip)) out = LIMITED;
      else {
        const body = (await readBody(req)) as { agent_id?: string } | undefined;
        out = createApiKey(store, cfg, body?.agent_id);
      }
    } else if (method === "POST" && path === "/v1/keys/rotate") {
      // Shares the key-mint limiter: rotation writes a tombstone per call, so
      // it must not be free to hammer.
      if (!keyLimiter.allow(ip)) out = LIMITED;
      else out = handleKeyRotate(store, cfg, req.headers["x-api-key"] as string | undefined, await readBody(req));
    } else if (method === "POST" && path === "/v1/keys/revoke") {
      if (!keyLimiter.allow(ip)) out = LIMITED;
      else out = handleKeyRevoke(store, cfg, req.headers["x-api-key"] as string | undefined, await readBody(req));
    } else if (method === "POST" && path === "/v1/scan/outgoing")
      out = handleScan("outgoing", await readBody(req), cfg, store, signer, req.headers["x-api-key"] as string | undefined);
    else if (method === "POST" && path === "/v1/scan/incoming")
      out = handleScan("incoming", await readBody(req), cfg, store, signer, req.headers["x-api-key"] as string | undefined);
    else if (method === "GET" && path === "/v1/plans")
      out = handlePlansCatalog(cfg);
    else if (method === "GET" && path === "/v1/usage")
      out = handleUsage(cfg, store, req.headers["x-api-key"] as string | undefined);
    else if (method === "GET" && (path === "/terms" || path === "/privacy")) {
      const html = path === "/terms" ? termsPageHtml(cfg) : privacyPageHtml(cfg);
      if (html === null) out = { status: 404, body: { error: "Document not available in this deployment" } };
      else {
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
          ...canonicalHeader(path),
        });
        res.end(html);
        return;
      }
    }
    else if (method === "GET" && path === "/robots.txt") {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end(robotsTxt(cfg));
      return;
    }
    else if (method === "GET" && path === "/sitemap.xml") {
      res.writeHead(200, { "content-type": "application/xml; charset=utf-8" });
      res.end(sitemapXml(cfg));
      return;
    }
    else if (method === "GET" && (path === "/dashboard" || path === "/admin" || path === "/approve")) {
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "x-robots-tag": NOINDEX,
      });
      res.end(path === "/admin" ? adminDashboardHtml() : path === "/approve" ? approvePageHtml() : dashboardHtml());
      return;
    }
    else if (method === "POST" && path === "/v1/approvals/config") {
      if (!keyLimiter.allow(ip)) out = LIMITED;
      else out = handleApprovalConfig(store, cfg, req.headers["x-api-key"] as string | undefined, await readBody(req));
    }
    else if (method === "POST" && path === "/v1/approvals/inspect") {
      if (!approvalLimiter.allow(ip)) out = LIMITED;
      else out = handleApprovalInspect(store, await readBody(req));
    }
    else if (method === "POST" && path === "/v1/approvals/decide") {
      if (!approvalLimiter.allow(ip)) out = LIMITED;
      else out = handleApprovalDecide(store, cfg, signer, await readBody(req));
    }
    else if (method === "GET" && /^\/v1\/approvals\/[^/]+$/.test(path))
      out = handleApprovalPoll(store, decodeURIComponent(path.split("/").pop() ?? ""), req.headers["x-api-key"] as string | undefined);
    else if (method === "POST" && path === "/v1/outcomes") {
      if (!outcomesLimiter.allow(ip)) out = LIMITED;
      else out = handleOutcomeReport(store, cfg, req.headers["x-api-key"] as string | undefined, await readBody(req));
    }
    else if (method === "GET" && path === "/v1/admin/stats")
      out = handleAdminStats(cfg, store, req.headers["x-api-key"] as string | undefined);
    else if (method === "POST" && path === "/v1/plans/subscribe")
      // Dev mode: no payments — activates directly, for local testing.
      out = handlePlanSubscribe(await readBody(req), cfg, store, req.headers["x-api-key"] as string | undefined);
    else if (method === "POST" && path === "/v1/trust/evaluate") {
      if (!trustLimiter.allow(ip)) out = LIMITED;
      else out = handleTrustEvaluate(await readBody(req), cfg, store);
    }
    else if (method === "POST" && path === "/v1/reputation/report") {
      if (!reportLimiter.allow(ip)) out = LIMITED;
      else out = handleReputationReport(await readBody(req), store);
    } else if (method === "POST" && path === "/v1/reputation/dispute") {
      // Shares the report limiter: both sides of the registry cost the same.
      if (!reportLimiter.allow(ip)) out = LIMITED;
      else out = handleReputationDispute(await readBody(req), store);
    } else if (method === "GET" && /^\/v1\/reputation\/[^/]+$/.test(path))
      out = handleReputationLookup(decodeURIComponent(path.split("/").pop() ?? ""), store);
    else if (method === "GET" && path === "/v1/audit/head")
      out = store.auditLog
        ? { status: 200, body: store.auditLog.head() }
        : { status: 404, body: { error: "Audit log disabled (AUDIT_LOG=off)" } };
    else if (method === "GET" && path === "/v1/audit/verify")
      out = store.auditLog
        ? { status: 200, body: store.auditLog.verify() }
        : { status: 404, body: { error: "Audit log disabled (AUDIT_LOG=off)" } };
    else out = { status: 404, body: { error: `No route: ${method} ${path}` } };
  } catch (err) {
    console.error("handler error:", err);
    out = { status: 500, body: { error: "internal error" } };
  }

  res.writeHead(out.status, { "content-type": "application/json" });
  res.end(JSON.stringify(out.body, null, 2));
});

server.listen(cfg.port, () => {
  console.log(`TollWarden DEV server (no payments) listening on :${cfg.port}`);
});
