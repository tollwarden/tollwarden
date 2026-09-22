// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Human-facing pages.
 *
 * The legal pages (GET /terms, GET /privacy) are rendered from the canonical
 * TERMS.md / PRIVACY.md at the package root by the tiny markdown renderer
 * below (single source of truth: the same files GitHub renders).
 *
 * The homepage (GET / for browsers) is a dedicated server-rendered template
 * (homeBodyHtml) rather than rendered HOME.md: the proof-led layout — live
 * headline numbers, verdict bar, stat tiles, detector table — can't be
 * expressed in the mini markdown dialect. HOME.md remains the GitHub-facing
 * prose document; keep the two in sync when copy changes.
 *
 * Everything stays static HTML with no script and zero external resources,
 * under the same locked-down CSP as the dashboards. Pricing comes from
 * config and the plan catalog (plans.ts) so it can't drift from what the
 * payment gate actually charges; stats come from the TTL-cached public
 * snapshot (pubstats.ts), refreshed every five minutes.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { TollWardenConfig } from "./config.ts";
import type { PublicStats } from "./pubstats.ts";
import { PLANS } from "./plans.ts";

function loadFile(filename: string): Buffer | null {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 5; i++) {
    try {
      return readFileSync(join(dir, filename));
    } catch {
      // keep walking up
    }
    dir = dirname(dir);
  }
  return null; // never crash the server over a missing doc; the route falls back
}

function loadDoc(filename: string): string | null {
  return loadFile(filename)?.toString("utf8") ?? null;
}

let ogImageCache: Buffer | null | undefined;

/** The 1200×630 link-preview image (og-image.png at the package root), or null if absent. */
export function ogImagePng(): Buffer | null {
  if (ogImageCache === undefined) ogImageCache = loadFile("og-image.png");
  return ogImageCache;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------------------
// Search-engine metadata. Head tags only (meta, never <link> or <script>), so
// the pages keep their zero-external-resource / no-script guarantees; the
// canonical URL travels as an HTTP Link header instead (canonicalLinkHeader).
// ---------------------------------------------------------------------------

/** Indexable public pages: sitemap entries and the canonical-URL allowlist. */
export const INDEXABLE_PATHS = ["/", "/terms", "/privacy"] as const;

export const HOME_TITLE = "TollWarden — payment security firewall for AI agents";
export const HOME_DESCRIPTION =
  "Payment firewall for AI agents on x402: catches prompt-injection-triggered payments, replays, overpayment and lookalike tokens. Signed verdicts, non-custodial.";

/**
 * The public origin for canonical URLs, or null when it isn't a real https
 * deployment (the localhost default, or PUBLIC_BASE_URL left unset) — a
 * canonical pointing at localhost would tell crawlers to drop the page.
 */
export function canonicalOrigin(cfg: TollWardenConfig): string | null {
  const base = cfg.publicBaseUrl.replace(/\/+$/, "");
  return /^https:\/\/[^/]+$/.test(base) ? base : null;
}

export function canonicalUrl(cfg: TollWardenConfig, path: string): string | null {
  const origin = canonicalOrigin(cfg);
  return origin === null ? null : origin + (path === "/" ? "/" : path);
}

/** `Link: <url>; rel="canonical"` header value (RFC 8288; honored by Google). */
export function canonicalLinkHeader(cfg: TollWardenConfig, path: string): string | null {
  const url = canonicalUrl(cfg, path);
  return url === null ? null : `<${url}>; rel="canonical"`;
}

function seoMeta(cfg: TollWardenConfig, title: string, description: string, path: string): string {
  const url = canonicalUrl(cfg, path);
  // Preview scrapers need an absolute image URL, so no public origin -> no image.
  const image = ogImagePng() === null ? null : canonicalUrl(cfg, "/og-image.png");
  return [
    `<meta name="description" content="${escapeHtml(description)}">`,
    `<meta property="og:type" content="website">`,
    `<meta property="og:site_name" content="TollWarden">`,
    `<meta property="og:title" content="${escapeHtml(title)}">`,
    `<meta property="og:description" content="${escapeHtml(description)}">`,
    ...(url === null ? [] : [`<meta property="og:url" content="${escapeHtml(url)}">`]),
    ...(image === null ? [] : [
      `<meta property="og:image" content="${escapeHtml(image)}">`,
      `<meta property="og:image:width" content="1200">`,
      `<meta property="og:image:height" content="630">`,
      `<meta property="og:image:alt" content="TollWarden — the payment security firewall for AI agents">`,
    ]),
    `<meta name="twitter:card" content="${image === null ? "summary" : "summary_large_image"}">`,
    `<meta name="twitter:title" content="${escapeHtml(title)}">`,
    `<meta name="twitter:description" content="${escapeHtml(description)}">`,
  ].join("\n");
}

/**
 * robots.txt. The API and discovery JSON are for agents, not search results.
 * /dashboard, /admin and /approve are deliberately NOT disallowed: they carry
 * `X-Robots-Tag: noindex`, and a crawler blocked by robots.txt never fetches
 * the page, so never sees the noindex — the URL could still be indexed.
 */
export function robotsTxt(cfg: TollWardenConfig): string {
  const origin = canonicalOrigin(cfg);
  return [
    "User-agent: *",
    "Allow: /",
    "Disallow: /v1/",
    "",
    ...(origin === null ? [] : [`Sitemap: ${origin}/sitemap.xml`, ""]),
  ].join("\n");
}

/** sitemap.xml over the indexable pages; empty urlset without a public https origin. */
export function sitemapXml(cfg: TollWardenConfig): string {
  const urls = INDEXABLE_PATHS.map((p) => canonicalUrl(cfg, p))
    .filter((u): u is string => u !== null)
    .map((u) => `  <url><loc>${escapeHtml(u)}</loc></url>`);
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join("\n")}
</urlset>
`;
}

/**
 * Pre-rename hostnames still attached to the service. They must keep serving
 * everything machine-facing — old SDKs (< 0.6.0) default to this origin and
 * POST scans there (a 301 can turn a POST into a GET), and the ERC-8004
 * tokenURI on Base points at its /.well-known/erc8004.json — so only the
 * human pages move.
 */
export const LEGACY_HOSTS: ReadonlySet<string> = new Set(["paysafe-agent.com", "www.paysafe-agent.com"]);

/**
 * 301 target for a browser request to an indexable page on a legacy host, or
 * null to serve the request normally. `/` redirects only when the client asked
 * for HTML: agents fetching the JSON index from the old origin keep getting it.
 */
export function legacyHostRedirect(
  cfg: TollWardenConfig,
  req: { method: string; host: string | undefined; path: string; search: string; wantsHtml: boolean },
): string | null {
  if (req.method !== "GET" && req.method !== "HEAD") return null;
  const host = (req.host ?? "").toLowerCase().replace(/:\d+$/, "");
  if (!LEGACY_HOSTS.has(host)) return null;
  if (!(INDEXABLE_PATHS as readonly string[]).includes(req.path)) return null;
  if (req.path === "/" && !req.wantsHtml) return null;
  const target = canonicalUrl(cfg, req.path);
  return target === null ? null : target + (req.search.startsWith("?") ? req.search : "");
}

/** Header for pages that must never appear in search results (dashboards, approvals). */
export const NOINDEX = "noindex, nofollow";

/** GitHub-style heading slug: "5. The reputation registry" -> "5-the-reputation-registry". */
function slug(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");
}

/** Repo-relative doc links become site routes; everything else must be a safe scheme. */
function linkHref(url: string): string | null {
  const base = url.split("#")[0];
  if (base === "TERMS.md") return "/terms" + url.slice(base.length);
  if (base === "PRIVACY.md") return "/privacy" + url.slice(base.length);
  if (/^(https:\/\/|http:\/\/|mailto:|#|\/)/.test(url)) return url;
  return null; // unknown relative target (e.g. a repo file): render as plain text
}

function inline(md: string): string {
  let s = escapeHtml(md);
  s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/\*([^*\s][^*]*)\*/g, "<em>$1</em>");
  s = s.replace(/\[([^\]]+)\]\(([^()\s]+)\)/g, (m: string, text: string, url: string) => {
    const href = linkHref(url);
    return href ? `<a href="${escapeHtml(href)}">${text}</a>` : text;
  });
  return s;
}

function tableRow(line: string): string[] {
  return line
    .replace(/^\s*\|/, "")
    .replace(/\|\s*$/, "")
    .split("|")
    .map((c) => c.trim());
}

function renderMarkdown(md: string): string {
  const lines = md.split(/\r?\n/);
  const out: string[] = [];
  let para: string[] = [];
  let list: string[] = [];
  let table: string[][] = [];
  let fence: string[] | null = null;

  const flushPara = () => {
    if (para.length) out.push(`<p>${inline(para.join(" "))}</p>`);
    para = [];
  };
  const flushList = () => {
    if (list.length) out.push(`<ul>${list.map((li) => `<li>${inline(li)}</li>`).join("")}</ul>`);
    list = [];
  };
  const flushTable = () => {
    if (table.length) {
      const [head, ...body] = table;
      out.push(
        `<table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead><tbody>` +
          body.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("") +
          `</tbody></table>`,
      );
    }
    table = [];
  };
  const flushAll = () => {
    flushPara();
    flushList();
    flushTable();
  };

  for (const line of lines) {
    if (fence !== null) {
      if (/^```/.test(line)) {
        out.push(`<pre><code>${escapeHtml(fence.join("\n"))}</code></pre>`);
        fence = null;
      } else fence.push(line);
      continue;
    }
    const heading = /^(#{1,3})\s+(.*)$/.exec(line);
    if (/^```/.test(line)) {
      flushAll();
      fence = [];
    } else if (/^\{\{[a-z_]+\}\}$/.test(line.trim())) {
      // A placeholder alone on a line passes through unwrapped (no <p>), so a
      // later substitution may inject block-level HTML (the stats panel).
      flushAll();
      out.push(line.trim());
    } else if (heading) {
      flushAll();
      const level = heading[1].length;
      out.push(`<h${level} id="${slug(heading[2])}">${inline(heading[2])}</h${level}>`);
    } else if (/^-{3,}\s*$/.test(line)) {
      flushAll();
      out.push("<hr>");
    } else if (/^\s*\|/.test(line)) {
      flushPara();
      flushList();
      if (!/^[\s|:-]+$/.test(line)) table.push(tableRow(line)); // skip the |---| separator
    } else if (/^-\s+/.test(line)) {
      flushPara();
      flushTable();
      list.push(line.replace(/^-\s+/, ""));
    } else if (line.trim() === "") {
      flushAll();
    } else {
      flushList();
      flushTable();
      para.push(line.trim());
    }
  }
  if (fence !== null) out.push(`<pre><code>${escapeHtml(fence.join("\n"))}</code></pre>`);
  flushAll();
  return out.join("\n");
}

/** Shared shell: base palette + prose styles (legal pages use only these). */
const BASE_CSS = `
  :root { color-scheme: dark; --bg:#0b0e14; --inset:#0d1017; --card:#141a24; --line:#232c3b; --fg:#e6edf3; --muted:#8b98a9; --accent:#4c8dff; --allow:#3fb950; --flag:#d29922; --block:#f85149; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  h1 { font-size:26px; line-height:1.3; margin:0 0 16px; }
  h2 { font-size:19px; line-height:1.3; margin:32px 0 10px; padding-top:16px; border-top:1px solid var(--line); }
  h3 { font-size:16px; margin:24px 0 8px; }
  p, li { color:var(--fg); }
  ul { padding-left:22px; margin:10px 0; }
  li { margin:6px 0; }
  a { color:var(--accent); }
  code { background:var(--inset); border:1px solid var(--line); padding:1px 5px; border-radius:4px; font:13px ui-monospace,SFMono-Regular,Menlo,monospace; }
  pre { background:var(--inset); border:1px solid var(--line); border-radius:8px; padding:14px; overflow-x:auto; }
  pre code { background:none; border:0; padding:0; font-size:13px; line-height:1.5; white-space:pre-wrap; word-break:break-word; }
  hr { border:0; border-top:1px solid var(--line); margin:32px 0; }
  table { border-collapse:collapse; width:100%; margin:14px 0; font-size:14px; display:block; overflow-x:auto; }
  th, td { border:1px solid var(--line); padding:8px 10px; text-align:left; vertical-align:top; }
  th { background:var(--card); }
  footer { margin-top:48px; padding-top:16px; border-top:1px solid var(--line); color:var(--muted); font-size:13px; }
  footer a { color:var(--muted); }`;

function markdownPageHtml(cfg: TollWardenConfig, title: string, description: string, path: string, markdown: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
${seoMeta(cfg, title, description, path)}
<style>
${BASE_CSS}
  .wrap { max-width:760px; margin:0 auto; padding:32px 20px 64px; }
</style>
</head>
<body>
<div class="wrap">
${renderMarkdown(markdown)}
<footer><a href="/">TollWarden</a> · <a href="/terms">Terms of Use</a> · <a href="/privacy">Privacy Policy</a> · <a href="https://github.com/tollwarden/tollwarden">Source</a></footer>
</div>
</body>
</html>`;
}

// Rendered once per process; keyed by base URL because the page embeds it.
const legalCache = new Map<string, string | null>();

function fmtInt(n: number): string {
  return n.toLocaleString("en-US");
}

/* ------------------------------------------------------------------ */
/*  Homepage (proof-led layout)                                        */
/* ------------------------------------------------------------------ */

const HOME_CSS = `
${BASE_CSS}
  .navbar { border-bottom:1px solid var(--line); }
  .navin { max-width:840px; margin:0 auto; padding:14px 20px; display:flex; align-items:baseline; justify-content:space-between; flex-wrap:wrap; gap:8px; }
  .navin .brand { color:var(--fg); font-weight:600; font-size:16px; text-decoration:none; }
  .navin nav { display:flex; gap:20px; font-size:14px; flex-wrap:wrap; }
  .navin nav a { color:var(--muted); text-decoration:none; }
  .navin nav a:hover { text-decoration:underline; }
  main { max-width:840px; margin:0 auto; padding:48px 20px 64px; }
  .live { color:var(--muted); font:12px ui-monospace,SFMono-Regular,Menlo,monospace; text-transform:uppercase; letter-spacing:.04em; margin-bottom:14px; }
  .hero-h { font-size:34px; line-height:1.3; margin:0; font-weight:600; letter-spacing:-.01em; text-wrap:pretty; }
  .hero-h .num { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-weight:700; }
  .hero-h .num.bad { color:var(--block); }
  .tagline { font-size:19px; line-height:1.5; margin:14px 0 0; max-width:640px; }
  .lede { margin:10px 0 0; max-width:640px; color:var(--muted); }
  .lede .v-allow { color:var(--allow); } .lede .v-flag { color:var(--flag); } .lede .v-block { color:var(--block); }
  .bar { display:flex; height:10px; border-radius:6px; overflow:hidden; background:var(--inset); margin:24px 0 10px; }
  .seg-allow { background:var(--allow); } .seg-flag { background:var(--flag); } .seg-block { background:var(--block); } .seg-empty { background:var(--line); }
  .legend { display:flex; gap:16px; flex-wrap:wrap; color:var(--muted); font-size:13px; }
  .legend div::before { content:""; display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; }
  .lg-allow::before { background:var(--allow); } .lg-flag::before { background:var(--flag); } .lg-block::before { background:var(--block); }
  .statgrid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; margin:20px 0 0; }
  .stat { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; }
  .stat .n { font-size:26px; font-weight:700; line-height:1.2; }
  .stat .n.ok { color:var(--allow); } .stat .n.warn { color:var(--flag); } .stat .n.bad { color:var(--block); }
  .stat .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; margin-top:2px; }
  .statmeta { color:var(--muted); font-size:13px; margin:12px 0 0; max-width:720px; }
  .ctarow { display:flex; gap:12px; flex-wrap:wrap; align-items:center; margin:24px 0 0; }
  .btn { display:inline-block; background:var(--accent); color:#04101f; font-weight:600; font-size:14px; padding:9px 16px; border-radius:8px; text-decoration:none; }
  .btn:hover { background:#3d78e0; }
  .install { display:flex; align-items:center; gap:10px; background:var(--inset); border:1px solid var(--line); border-radius:8px; padding:8px 12px; font:13px ui-monospace,SFMono-Regular,Menlo,monospace; }
  .prose { max-width:720px; }
  .vcard { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; margin:16px 0 0; }
  .vhead { display:flex; align-items:center; gap:12px; margin-bottom:12px; flex-wrap:wrap; }
  .vbadge { display:inline-flex; align-items:center; gap:6px; background:rgba(248,81,73,.12); color:var(--block); border:1px solid var(--block); border-radius:999px; padding:2px 10px; font:12px ui-monospace,SFMono-Regular,Menlo,monospace; }
  .vbadge::before { content:""; width:7px; height:7px; border-radius:50%; background:var(--block); }
  .vmeta { font:13px ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--muted); }
  .vcard pre { margin:0; }
  .detrow { display:grid; grid-template-columns:220px 1fr; gap:16px; padding:14px 0; border-top:1px solid var(--line); }
  .detrow .dn { font-weight:600; font-size:15px; line-height:1.5; }
  .detrow .dc { font:12px ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--muted); margin-top:2px; word-break:break-all; }
  .detrow .dd { color:var(--muted); font-size:14px; line-height:1.65; margin:0; }
  .twocol { display:grid; grid-template-columns:1fr 1fr; gap:24px; margin:16px 0 0; align-items:start; }
  .twocol p { margin:0 0 10px; }
  .startcards { display:flex; flex-direction:column; gap:16px; margin:16px 0 0; max-width:720px; }
  .startcards .kicker { font:12px ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; margin-bottom:10px; }
  .startcards .vcard { margin:0; }
  .pricetable { margin:16px 0 0; max-width:720px; }
  .pricetable .row { display:grid; grid-template-columns:1fr 1fr 1fr 1.4fr; gap:16px; padding:10px 0; border-top:1px solid var(--line); font-size:14px; }
  .pricetable .row:last-child { border-bottom:1px solid var(--line); }
  .pricetable .head { font:12px ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
  .pricetable .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .pricetable .muted { color:var(--muted); }
  @media (max-width:640px) {
    .hero-h { font-size:26px; }
    .detrow { grid-template-columns:1fr; gap:4px; }
    .twocol { grid-template-columns:1fr; }
    .pricetable .row { grid-template-columns:1fr 1fr; }
  }`;

interface Detector {
  name: string;
  checks: string;
  desc: string;
}

/** Check IDs are the literal values emitted by the detectors in src/detectors/. */
const DETECTORS: Detector[] = [
  {
    name: "Prompt-injection-triggered payments",
    checks: "injection.payto_from_content",
    desc: "The strongest check. If the payee address arrived in content your agent just read — a web page, a tool result — that payment is blocked. Detection survives HTML/markdown markup, base64/hex encoding, invisible Unicode, homoglyphs, leetspeak, and multilingual override phrasing.",
  },
  {
    name: "Replay",
    checks: "replay.nonce_reuse",
    desc: "A payment authorization your agent already used, presented again.",
  },
  {
    name: "Overpayment",
    checks: "overpay.flag_multiple · overpay.absolute_cap",
    desc: "Amounts far beyond the quoted price, or beyond an absolute ceiling you set.",
  },
  {
    name: "Secret and PII leakage",
    checks: "pii.evm_private_key · pii.seed_phrase · …",
    desc: "Private keys, seed phrases, API keys, card numbers, SSNs in payment metadata — caught before they're transmitted.",
  },
  {
    name: "Lookalike tokens and address poisoning",
    checks: "asset.not_canonical_usdc · poison.lookalike",
    desc: "Non-canonical \"USDC\" contracts, and addresses crafted to match a legitimate counterparty's first and last characters — the truncated-display attack.",
  },
  {
    name: "Counterparty risk",
    checks: "reputation.reported · delivery.low_rate",
    desc: "A shared reputation registry with time decay and signed rebuttals, plus measured delivery history: sellers who take payment and don't deliver get flagged, based on commitment-bound outcomes, not self-reports.",
  },
  {
    name: "Velocity",
    checks: "velocity.rate_flag · velocity.spend_cap",
    desc: "Rate and hourly spend caps, so a compromised agent can't drain a wallet in a burst.",
  },
];

/**
 * Scan cost is a BENCHMARK, not a live measurement, so it lives in the prose
 * with its provenance attached rather than as a tile in the live grid. Every
 * tile in the grid reads from the snapshot and falls to an honest zero (or
 * "n/a") without one; a hardcoded figure sitting among them would read as
 * live and would still be asserted on a page that has no data at all.
 * Figure and method must stay in sync with the Performance section of README.md.
 */
const PERF_META = `Scan cost is measured offline, not live: 2,000 sequential scans against the zero-dependency dev server (same handlers as production) ran <strong>1.20 s total — 0.60 ms per scan</strong> round-trip, including HTTP, JSON parsing, the full check suite and Ed25519 signing. Deployed latency is dominated by network RTT.`;

/**
 * The live panel: headline, verdict bar, and stat tiles. Every number here
 * comes from the TTL-cached public snapshot and is formatted server-side, so
 * the markup stays static divs with inline width percentages only. The tiles
 * are the breakdown behind the bar and must reconcile with it —
 * screened = allowed + flagged + blocked.
 *
 * Headline figures are THIRD-PARTY only. Blended totals would count the
 * operator's own agents (chiefly the ecosystem scout) as usage, and the scout
 * is public, so anyone could do the subtraction themselves. Better that the
 * panel does it first and says so.
 */
function heroStatsHtml(stats?: PublicStats | null): string {
  const total = stats?.third_party.scans ?? 0;
  const blocked = stats?.third_party.blocked ?? 0;
  const flagged = stats?.third_party.flagged ?? 0;
  const firstParty = stats?.first_party.scans ?? 0;
  const allowed = Math.max(0, total - blocked - flagged);
  const u = stats?.uptime ?? null;
  const pct = (n: number) => ((n / total) * 100).toFixed(2);
  const bar =
    total > 0
      ? `<div class="seg-allow" style="width:${pct(allowed)}%" title="allowed: ${fmtInt(allowed)}"></div>` +
        `<div class="seg-flag" style="width:${pct(flagged)}%" title="flagged: ${fmtInt(flagged)}"></div>` +
        `<div class="seg-block" style="width:${pct(blocked)}%" title="blocked: ${fmtInt(blocked)}"></div>`
      : `<div class="seg-empty" style="width:100%"></div>`;
  const partyMeta =
    firstParty > 0
      ? `Third-party usage only — our own agents, including the open-source ecosystem scout, account for a further ${fmtInt(firstParty)} screenings, reported separately under <code>first_party</code> in <a href="/v1/stats">/v1/stats</a>. Totals only; per-agent and per-payment data is never published.`
      : `Third-party usage only — scans from our own agents are counted separately under <code>first_party</code> in <a href="/v1/stats">/v1/stats</a>. Totals only; per-agent and per-payment data is never published.`;
  const uptimeMeta = u
    ? `Uptime is self-measured process liveness (a heartbeat cannot see network-level unreachability), recording since ${escapeHtml(u.measured_since.slice(0, 10))}. Refreshed every five minutes; machine-readable at <a href="/v1/stats">/v1/stats</a>, liveness probe at <a href="/health">/health</a>.`
    : `Uptime is self-measured process liveness; no heartbeats recorded yet. Refreshed every five minutes; machine-readable at <a href="/v1/stats">/v1/stats</a>, liveness probe at <a href="/health">/health</a>.`;
  return `<div class="live">Live · third-party usage only · refreshed every five minutes</div>
<h1 class="hero-h"><span class="num">${fmtInt(total)}</span> payments screened. <span class="num bad">${fmtInt(blocked)}</span> blocked before settlement.</h1>
<p class="tagline"><strong>The payment security firewall for AI agents that pay for things.</strong></p>
<p class="lede">One HTTP call between your agent and settlement. Submit the payment, get back <span class="v-allow">allow</span>, <span class="v-flag">flag</span> or <span class="v-block">block</span> — with machine-readable reasons and an Ed25519 attestation bound to that exact payment. Advisory and non-custodial: it never touches your keys, your wallet, or your funds.</p>
<div class="bar">${bar}</div>
<div class="legend"><div class="lg-allow">allow</div><div class="lg-flag">flag</div><div class="lg-block">block</div></div>
<div class="statgrid">
<div class="stat"><div class="n">${fmtInt(total)}</div><div class="l">Payments screened</div></div>
<div class="stat"><div class="n ok">${fmtInt(allowed)}</div><div class="l">Allowed</div></div>
<div class="stat"><div class="n warn">${fmtInt(flagged)}</div><div class="l">Flagged</div></div>
<div class="stat"><div class="n bad">${fmtInt(blocked)}</div><div class="l">Blocked</div></div>
<div class="stat"><div class="n">${fmtInt(stats?.third_party.distinct_agents ?? 0)}</div><div class="l">Distinct agents</div></div>
<div class="stat"><div class="n${u ? " ok" : ""}">${u ? `${u.pct.toFixed(2)}%` : "n/a"}</div><div class="l">Uptime · 90 days</div></div>
</div>
<p class="statmeta">${partyMeta}</p>
<p class="statmeta">${uptimeMeta}</p>
<p class="statmeta">${PERF_META}</p>`;
}

function homeBodyHtml(cfg: TollWardenConfig, stats?: PublicStats | null): string {
  const detectorRows = DETECTORS.map(
    (d) =>
      `<div class="detrow"><div><div class="dn">${escapeHtml(d.name)}</div><div class="dc">${escapeHtml(d.checks)}</div></div><p class="dd">${escapeHtml(d.desc)}</p></div>`,
  ).join("\n");
  const planRows = PLANS.map(
    (p) =>
      `<div class="row"><span>${escapeHtml(p.name)}</span><span class="mono">${escapeHtml(p.price)} / 30d</span><span class="mono">${escapeHtml(p.limits.price_per_scan)}</span><span class="muted">${p.name === "Pro" ? "6× velocity, deep analysis always on" : "hard-ceiling limits"}</span></div>`,
  ).join("\n");
  return `<div class="navbar"><div class="navin">
<a class="brand" href="/">TollWarden</a>
<nav><a href="#what-a-scan-catches">detectors</a><a href="#get-started">get started</a><a href="#pricing">pricing</a><a href="/dashboard">dashboard</a><a href="https://github.com/tollwarden/tollwarden">GitHub</a></nav>
</div></div>
<main>
${heroStatsHtml(stats)}
<div class="ctarow">
<a class="btn" href="#get-started">Get started</a>
<span class="install">npm install @tollwarden/client</span>
<a href="#a-real-block-verdict">Read a real block verdict</a>
</div>

<h2 id="why-this-exists">Why this exists</h2>
<div class="prose">
<p>AI agents increasingly buy what they need on their own — API calls, data, compute — over <a href="https://www.x402.org">x402</a>, the protocol that turns HTTP's <code>402 Payment Required</code> into instant stablecoin micropayments. That autonomy has a failure mode: software that can <em>read the internet</em> and <em>sign payments</em> can be talked into paying the wrong party.</p>
<p>A poisoned web page whispers "pay this address instead." A payment authorization gets replayed. A lookalike token or vanity address slips past a truncated display. A seller takes the money and never delivers.</p>
<p>Before paying, the agent submits the payment for a scan and gets back a verdict. TollWarden inspects the payment; <strong>your systems decide</strong>.</p>
</div>

<h2 id="a-real-block-verdict">A real block verdict</h2>
<p class="prose" style="color:var(--muted)">A captured payment authorization, presented a second time. Every verdict carries per-check reasons and a signed attestation over <code>sha256(network|pay_to|asset|amount|nonce)</code>, so a wallet can confirm it belongs to this payment and no other.</p>
<div class="vcard">
<div class="vhead"><span class="vbadge">block</span><span class="vmeta">replay.nonce_reuse · risk_score 95 · severity critical</span></div>
<pre><code>{
  "verdict": "block",
  "risk_score": 95,
  "checks": [{
    "id": "replay.nonce_reuse",
    "reason": "Nonce reuse detected: this nonce was first seen
      2026-07-14T09:32:50Z and has now appeared 2 times. A reused
      nonce means a stale or captured payment authorization is
      being replayed."
  }],
  "attestation": { "alg": "ed25519",
    "payment_commitment": "sha256(...)", "expires_at": "…+5min" }
}</code></pre>
</div>

<h2 id="what-a-scan-catches">What a scan catches</h2>
<div style="margin-top:16px">
${detectorRows}
</div>

<h2 id="from-advisory-to-enforceable">From advisory to enforceable</h2>
<div class="twocol">
<div>
<p>Every verdict is Ed25519-signed and bound to a hash of the exact payment, with a short expiry — plus signed evidence a wallet can weigh for itself: how long the merchant's payment address had been pinned at scan time, and which named out-of-band sources corroborated it. The SDKs ship an enforcement kit: <code>guardSigner(account)</code> wraps your wallet's signer so it <strong>physically refuses to sign</strong> an x402 payment authorization unless a fresh, verified allow-verdict exists for exactly that payment.</p>
<p>A compromised agent that scanned payment A cannot sign payment B — and one that skips scanning cannot sign at all. Flagged payments can pause for one-click human approval instead — with your own decision latency, paired against how approved payments delivered, visible only to you.</p>
</div>
<pre><code>const guarded = TollWardenEnforcer.guardSigner(account, {
  allowedRecipients: ["0x2096…287C"],
  maxTotalAtomic: 5_000_000n
});
// unscanned payment → signature refused</code></pre>
</div>

<h2 id="get-started">Get started</h2>
<div class="startcards">
<div class="vcard"><div class="kicker">MCP — zero config</div>
<pre><code>{ "mcpServers": { "tollwarden": { "command": "npx", "args": ["-y", "tollwarden"] } } }</code></pre></div>
<div class="vcard"><div class="kicker">TypeScript</div>
<pre><code>npm install @tollwarden/client

const tollwarden = new TollWardenClient({ agentId: "my-agent" });
tollwarden.observe(pageText, { sourceUrl });
await tollwarden.guardOutgoing(payment); // throws on block</code></pre></div>
<div class="vcard"><div class="kicker">Python</div>
<pre><code>pip install tollwarden

tollwarden = TollWardenClient(agent_id="my-agent")
tollwarden.guard_outgoing(payment)</code></pre></div>
</div>
<p class="prose" style="color:var(--muted);font-size:14px;margin-top:14px">Drop-in packages: LangChain · CrewAI · Vercel AI SDK · Coinbase AgentKit · NVIDIA NeMo Agent Toolkit — the first ${cfg.freeCalls} calls per key are free, no signup.</p>

<h2 id="pricing">Pricing</h2>
<p class="prose">Scans are <strong>${escapeHtml(cfg.priceScan)}</strong> each, paid over x402 itself — your agent pays for its own security, per payment it makes. The first <strong>${cfg.freeCalls} calls per API key are free</strong>. Reputation lookups are ${escapeHtml(cfg.priceReputation)}; reporting bad counterparties and recording delivery outcomes is always free.</p>
<div class="pricetable">
<div class="row head"><span>Plan</span><span>Price</span><span>Per scan</span><span>Headroom</span></div>
<div class="row"><span>Starter (default)</span><span class="mono">$0.00</span><span class="mono">${escapeHtml(cfg.priceScan)}</span><span class="muted">defaults</span></div>
${planRows}
</div>
<p class="statmeta">Plans raise your own velocity and spend headroom only — replay detection, merchant pinning, asset verification, and PII scanning are identical on every tier and can't be relaxed by paying more. Machine-readable at <a href="/v1/plans">/v1/plans</a>.</p>

<h2 id="for-developers-and-agents">For developers and agents</h2>
<ul class="prose">
<li><a href="/llms.txt">llms.txt</a> — agent-facing integration guide (point your LLM at it)</li>
<li><a href="/openapi.json">OpenAPI</a> — the full API contract</li>
<li><a href="/dashboard">Usage dashboard</a> — your key's stats, key sent via header only</li>
<li><a href="https://github.com/tollwarden/tollwarden">Source</a> — source-available under BUSL 1.1</li>
<li><a href="/.well-known/tollwarden-verdict-key">Verdict signing key</a> — pin it and verify everything</li>
</ul>
<footer>Operated by <strong>TollWarden, LLC</strong> (Colorado, USA) · <a href="/terms">Terms of Use</a> · <a href="/privacy">Privacy Policy</a> · <a href="https://github.com/tollwarden/tollwarden">Source</a> · contact@tollwarden.com</footer>
</main>`;
}

/**
 * Browser homepage. Rendered per request from config (pricing — llms.txt
 * policy) and the TTL-cached public snapshot (pubstats.ts, five-minute
 * refresh). Static markup only — no script, zero external resources — so it
 * serves under the same locked-down CSP as the dashboards
 * (style-src 'unsafe-inline' covers the inline width percentages on the
 * verdict bar).
 */
export function homePageHtml(cfg: TollWardenConfig, stats?: PublicStats | null): string | null {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(HOME_TITLE)}</title>
${seoMeta(cfg, HOME_TITLE, HOME_DESCRIPTION, "/")}
<style>
${HOME_CSS}
</style>
</head>
<body>
${homeBodyHtml(cfg, stats)}
</body>
</html>`;
}

function legalPageHtml(cfg: TollWardenConfig, file: string, title: string, description: string, path: string): string | null {
  const key = `${path}|${cfg.publicBaseUrl}`;
  if (!legalCache.has(key)) {
    const md = loadDoc(file);
    legalCache.set(key, md === null ? null : markdownPageHtml(cfg, title, description, path, md));
  }
  return legalCache.get(key)!;
}

export function termsPageHtml(cfg: TollWardenConfig): string | null {
  return legalPageHtml(cfg, "TERMS.md", "TollWarden — Terms of Use",
    "Terms of Use for TollWarden, the advisory, non-custodial payment security firewall for AI agents using x402.", "/terms");
}

export function privacyPageHtml(cfg: TollWardenConfig): string | null {
  return legalPageHtml(cfg, "PRIVACY.md", "TollWarden — Privacy Policy",
    "What TollWarden records when your agent scans an x402 payment, and how long it is kept.", "/privacy");
}
