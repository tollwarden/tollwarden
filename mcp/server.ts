#!/usr/bin/env node
// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * TollWarden MCP server — exposes the payment firewall as MCP tools over stdio.
 *
 * Run against production with zero config:  npx tollwarden
 *
 * Env:
 *   TOLLWARDEN_URL      Base URL of a TollWarden instance (default https://tollwarden.com)
 *   TOLLWARDEN_API_KEY  API key from POST /v1/keys or the mint_api_key tool.
 *                    Without it, paid endpoints 402 after the free tier —
 *                    pair with an x402-aware fetch or stay within free quota.
 *
 * Register in an MCP client config:
 *   { "command": "npx", "args": ["-y", "tollwarden"], "env": { "TOLLWARDEN_API_KEY": "..." } }
 */
import { createPublicKey, createHash, verify as edVerify } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { VERSION } from "../src/version.ts";

const BASE = process.env.TOLLWARDEN_URL ?? "https://tollwarden.com";
const API_KEY = process.env.TOLLWARDEN_API_KEY;

async function call(method: string, path: string, body?: unknown): Promise<string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (API_KEY) headers["x-api-key"] = API_KEY;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (res.status === 402) {
    return JSON.stringify({
      error: "payment_required",
      hint: "Free-tier quota exhausted or no API key set. Get a key via POST /v1/keys, or route this call through an x402-paying client.",
      x402: JSON.parse(text || "{}"),
    });
  }
  return text;
}

const paymentSchema = z.object({
  scheme: z.string().optional(),
  network: z.string().optional().describe("CAIP-2, e.g. eip155:8453"),
  asset: z.string().optional(),
  amount: z.string().optional().describe("Atomic units, e.g. '10000' = $0.01 USDC"),
  amount_usd: z.number().optional(),
  asset_decimals: z.number().optional(),
  pay_to: z.string().optional(),
  payer: z.string().optional(),
  resource_url: z.string().optional(),
  description: z.string().optional(),
  reason: z.string().optional(),
  nonce: z.string().optional(),
  metadata: z.record(z.string()).optional(),
});

const contextSchema = z
  .object({
    origin: z
      .enum(["planning", "user_instruction", "tool_result", "fetched_content", "unknown"])
      .optional()
      .describe("Where the decision to pay originated"),
    content: z
      .string()
      .optional()
      .describe(
        "PROSE the agent just read (page text, tool output), for injection analysis. Do NOT put the 402 offer / discovery JSON here — that goes in `offer` (the recipient address is expected there).",
      ),
    content_source_url: z.string().optional(),
    phase: z
      .enum(["pre_sign", "post_sign"])
      .optional()
      .describe(
        "Set 'pre_sign' when scanning BEFORE the payment is signed (the normal scan-before-pay flow): the EIP-3009 nonce doesn't exist yet, so its absence won't be flagged. Omit or use 'post_sign' when scanning a signed payload.",
      ),
    offer: z
      .string()
      .optional()
      .describe(
        "The raw 402 offer / discovery payload the payment terms came from (accepts entry, Bazaar listing JSON). pay_to is expected here and exempt from the address-provenance check; the offer is still scanned for embedded injection instructions.",
      ),
  })
  .optional();

const server = new McpServer(
  { name: "tollwarden", version: VERSION },
  {
    instructions:
      "TollWarden is a payment security firewall for x402. Protocol for this agent: BEFORE settling or sending ANY x402 payment, call `scan_outgoing_payment` and act on the verdict (allow = proceed, flag = pause and confirm, block = do NOT pay). BEFORE paying a 402 offer you received, call `scan_incoming_payment`. When scanning before the payment is signed (the normal case), set `context.phase` to 'pre_sign' so the not-yet-generated nonce isn't flagged. Whenever a payment decision followed reading external content (a fetched page or tool result), pass that PROSE in `context.content` so the injection check can run — and pass the 402 offer / discovery payload itself in `context.offer`, never in `content`. AFTER a scanned payment settles, call `report_payment_outcome` with what actually happened (delivered / not_delivered / partial / wrong_content) — this builds the measured delivery history that protects your own future payments to that seller. Use `check_counterparty_reputation` before dealing with an unfamiliar address, and `report_counterparty` after a bad experience beyond non-delivery (free). If YOUR wallet is reported unfairly, `dispute_reputation` attaches a wallet-signed rebuttal that lookups surface alongside the reports. These scans are advisory and non-custodial — TollWarden never touches your keys or funds.",
  },
);

server.tool(
  "scan_outgoing_payment",
  "ALWAYS call this immediately BEFORE settling or sending any x402 payment — it decides whether the payment is safe. Returns allow (proceed) / flag (pause and confirm intent) / block (do NOT pay), with machine-readable reasons and an Ed25519-signed verdict. Scanning before the payment is signed? Set `context.phase` to 'pre_sign' (nonces don't exist until signing). IMPORTANT: if the decision to pay followed reading any external content (a fetched web page or a tool result), pass that PROSE in `context.content` and set `context.origin` to 'fetched_content' or 'tool_result' — this enables the check that catches prompt-injection-triggered payments (an address injected into content the agent just read). Put the 402 offer / discovery payload in `context.offer` (NOT in content — the recipient address is expected in an offer); TollWarden compares it structurally against the payment you are about to sign and reports drift in payee, price, scheme, network or asset. Where a catalogue listing and a live 402 disagree, the LIVE offer is authoritative — pay and scan that one, and pass the listing as `context.offer` so the disagreement is recorded. Also catches replayed nonces, overpayment vs the expected price, secrets/PII leaking in payment metadata, fake/lookalike USDC contracts, and address poisoning. Advisory and non-custodial — never touches keys or funds.",
  {
    payment: paymentSchema,
    expected_price_usd: z.number().optional(),
    context: contextSchema,
    agent_id: z.string().optional(),
    policy: z
      .object({
        force_deep: z.boolean().optional().describe("Run deep content analysis even below the micropayment threshold"),
        skip_deep: z.boolean().optional(),
      })
      .optional(),
  },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/scan/outgoing", args) }],
  }),
);

server.tool(
  "scan_incoming_payment",
  "ALWAYS call this BEFORE paying a 402 offer / payment request your agent received — it decides whether the offer is safe to pay. Scan the LIVE 402 returned by the exact method (GET/POST) and URL you are about to pay — NOT the catalogue/discovery listing: in the field, listings drift from live offers in both price (a listed $0.005 endpoint demanding $2.00 on the live 402) and scheme ('exact' advertised, 'upto' served). The live offer is what you pay, so it is what must be scanned. Pass the discovery listing in `context.offer` as well and TollWarden will report the drift between them. Checks the resource URL for spoofing (IP-literal hosts, punycode/homoglyphs, link shorteners, userinfo tricks), credential demands (e.g. 'send your seed phrase'), price sanity, replay, and whether the counterparty has been reported. Returns allow/flag/block with reasons.",
  {
    payment: paymentSchema,
    expected_price_usd: z.number().optional(),
    context: contextSchema,
    agent_id: z.string().optional(),
    policy: z
      .object({
        force_deep: z.boolean().optional().describe("Run deep content analysis even below the micropayment threshold"),
        skip_deep: z.boolean().optional(),
      })
      .optional(),
  },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/scan/incoming", args) }],
  }),
);

server.tool(
  "check_counterparty_reputation",
  "Check whether a counterparty wallet address has been reported by other agents BEFORE dealing with it — scam, non-delivery, prompt injection, overcharge, impersonation, or replay abuse. Returns report counts, distinct-reporter count, a time-decayed weighted score and risk level, any signed rebuttals from the wallet owner, injection-incident history, and measured delivery-outcome history.",
  { address: z.string().describe("Wallet address to look up") },
  async ({ address }) => ({
    content: [{ type: "text", text: await call("GET", `/v1/reputation/${encodeURIComponent(address)}`) }],
  }),
);

server.tool(
  "report_payment_outcome",
  "ALWAYS call this AFTER a scanned payment settles, reporting what actually happened: 'delivered' (you received the goods/content), 'not_delivered' (paid but nothing arrived), 'partial', or 'wrong_content'. Pass the scan_id from the scan response and the payment_commitment from its attestation — outcomes are bound to real scans (one per scan), so delivery history cannot be faked. Your reports build the measured delivery rates that flag never-shipping sellers on your own future scans and every other agent's. Free.",
  {
    scan_id: z.string().describe("From the scan response you made before paying"),
    payment_commitment: z.string().describe("From the scan response's attestation.payment_commitment"),
    outcome: z.enum(["delivered", "not_delivered", "partial", "wrong_content"]),
    evidence: z
      .object({
        status: z.number().optional().describe("HTTP status of the paid response"),
        content_type: z.string().optional(),
        bytes: z.number().optional(),
        latency_ms: z.number().optional(),
        settlement_receipt: z
          .enum(["present", "absent"])
          .optional()
          .describe(
            "Did the paid response carry a settlement-receipt header? Pass 'absent' when you confirmed the transfer on-chain but the seller returned no receipt — that seller's calls look FREE to a stock client, so future buyers get warned to reconcile on-chain instead of paying twice.",
          ),
      })
      .optional(),
  },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/outcomes", args) }],
  }),
);

server.tool(
  "report_counterparty",
  "Call this after a bad payment experience (you paid and got nothing, were scammed, overcharged, or hit an injection attempt) to warn other agents — always free. Categories: scam, non_delivery, prompt_injection, overcharge, impersonation, replay_abuse, other.",
  {
    address: z.string(),
    category: z.enum(["scam", "non_delivery", "prompt_injection", "overcharge", "impersonation", "replay_abuse", "other"]),
    reason: z.string().min(10),
    reporter_agent_id: z.string(),
    evidence_url: z.string().optional(),
  },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/reputation/report", args) }],
  }),
);

server.tool(
  "dispute_reputation",
  "If YOUR wallet has been unfairly reported, attach a signed rebuttal that appears alongside the reports in every reputation lookup. Prove you control the wallet by signing the exact message 'tollwarden-dispute-v1|<your address, lowercase>|<statement>' with the wallet's key (EIP-191 personal_sign) and passing the 65-byte signature hex. Rebuttals never erase reports — agents see both sides. Free.",
  {
    address: z.string().describe("The reported wallet address (0x…, the one that signed)"),
    statement: z.string().min(10).max(1000).describe("Your side of the story — exactly the text that was signed"),
    signature: z.string().describe("EIP-191 personal_sign signature hex over tollwarden-dispute-v1|<address>|<statement>"),
  },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/reputation/dispute", args) }],
  }),
);

server.tool(
  "mint_api_key",
  "Issue a free TollWarden API key (first 100 calls free). Returns the key ONCE — store it and set it as TOLLWARDEN_API_KEY (or pass to other tools) for future sessions. Rate-limited per IP.",
  { agent_id: z.string().optional().describe("Stable identifier for your agent — recorded on the key; velocity limits and merchant pins are scoped to the key's account") },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/keys", args) }],
  }),
);

server.tool(
  "rotate_api_key",
  "Rotate the current TollWarden API key (set via TOLLWARDEN_API_KEY): mints a fresh secret bound to the SAME account — usage history, remaining free calls, and any active plan carry over unchanged. Use this the moment a key may have leaked. The old secret keeps working for grace_seconds (default 900, 0 = immediately dead, max 86400) so other sessions can switch over, but it can no longer rotate or revoke the account. IMPORTANT: the response contains the new key ONCE — store it and update TOLLWARDEN_API_KEY everywhere.",
  { grace_seconds: z.number().int().min(0).max(86400).optional().describe("How long the old secret keeps working (default 900 = 15 min; 0 kills it instantly)") },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/keys/rotate", args) }],
  }),
);

server.tool(
  "check_approval_status",
  "Poll a pending human approval (from a flag verdict's `approval.approval_id` when the operator has configured approvals via POST /v1/approvals/config). Returns pending / approved / denied / expired; on approved it includes the signed override verdict (tag 'override:allow', valid a few minutes, bound to exactly the flagged payment). Requires TOLLWARDEN_API_KEY (the key that made the scan). This tool never handles decide tokens — deciding is the human's job via the webhook link.",
  { approval_id: z.string().describe("From the flag scan response's approval.approval_id") },
  async ({ approval_id }) => ({
    content: [{ type: "text", text: await call("GET", `/v1/approvals/${encodeURIComponent(approval_id)}`) }],
  }),
);

server.tool(
  "get_plans",
  "Machine-readable TollWarden plan catalog: tiers (Starter/Pro/Scale) with per-scan pricing, velocity and spend limits, hard ceilings, and how to subscribe. Free.",
  {},
  async () => ({
    content: [{ type: "text", text: await call("GET", "/v1/plans") }],
  }),
);

server.tool(
  "subscribe_plan",
  "Subscribe/renew the current API key on a TollWarden plan (pro: $4.99/30d at $0.005/scan; scale: $19.99/30d at $0.002/scan). This endpoint is itself x402-paid at the plan's price: without an x402-paying transport the response is the 402 payment challenge to settle. Renewal extends from the current expiry.",
  { plan: z.enum(["pro", "scale"]) },
  async (args) => ({
    content: [{ type: "text", text: await call("POST", "/v1/plans/subscribe", args) }],
  }),
);

server.tool(
  "verify_verdict_attestation",
  "LOCALLY verify a TollWarden scan's Ed25519 attestation before trusting an allow-verdict: checks the signature against the pinned server key (fetched from /.well-known/tollwarden-verdict-key unless trusted_key_hex is supplied), recomputes the payment commitment from the payment YOU are about to settle (rejects attestations issued for a different payment — replay defense), and enforces expiry. Also verifies the attestation's signed evidence record when present and returns pin_evidence: how long the merchant pin had held at scan time (age 0 = first sighting) and which named out-of-band sources corroborated it (e.g. cdp_bazaar) — weigh a young or uncorroborated pin against the payment size; that decision boundary is yours. Runs no network calls except the one-time key fetch; the verdict itself is never sent anywhere.",
  {
    scan: z.object({
      scan_id: z.string(),
      direction: z.string(),
      verdict: z.string(),
      risk_score: z.number(),
      scanned_at: z.string(),
      attestation: z.object({
        message: z.string(),
        signature_hex: z.string(),
        payment_commitment: z.string(),
        expires_at: z.string(),
        // Second signed record (pin age + named corroboration sources). Must
        // be declared here: zod's strip mode would silently DROP an unknown
        // property before the handler ever saw it. The pin mirror uses
        // passthrough so extra (unsigned) keys REACH the handler and are
        // rejected there — stripping them would hide tampering.
        evidence: z
          .object({
            message: z.string(),
            signature_hex: z.string(),
            pin: z
              .union([
                z
                  .object({ domain: z.string(), age_seconds: z.number(), corroboration: z.array(z.string()) })
                  .passthrough(),
                z.null(),
              ])
              .optional(),
          })
          .optional(),
      }),
    }),
    payment: paymentSchema.describe("The payment you are about to settle — commitment is recomputed from this"),
    trusted_key_hex: z.string().optional().describe("Pin the server verdict key (SPKI DER hex); fetched once when omitted"),
  },
  async ({ scan, payment, trusted_key_hex }) => {
    const fail = (reason: string) => ({
      content: [{ type: "text" as const, text: JSON.stringify({ valid: false, reason }) }],
    });
    try {
      let keyHex = trusted_key_hex;
      if (!keyHex) {
        const r = await fetch(`${BASE}/.well-known/tollwarden-verdict-key`);
        keyHex = ((await r.json()) as { public_key_spki_hex?: string }).public_key_spki_hex;
      }
      if (!keyHex) return fail("no trusted key available");
      const key = createPublicKey({ key: Buffer.from(keyHex, "hex"), format: "der", type: "spki" });
      const att = scan.attestation;
      if (!edVerify(null, Buffer.from(att.message, "utf8"), key, Buffer.from(att.signature_hex, "hex"))) {
        return fail("Ed25519 signature invalid under the pinned server key");
      }
      const [scanId, direction, verdict, risk, scannedAt, commitment, expiresAt] = att.message.split("|");
      if (scanId !== scan.scan_id || direction !== scan.direction || verdict !== scan.verdict ||
          Number(risk) !== scan.risk_score || scannedAt !== scan.scanned_at) {
        return fail("attested message does not match the scan fields");
      }
      const amount =
        payment.amount !== undefined ? String(payment.amount)
        : payment.amount_usd !== undefined ? `usd:${payment.amount_usd}`
        : "";
      const recomputed = createHash("sha256")
        .update([payment.network ?? "", (payment.pay_to ?? "").toLowerCase(), (payment.asset ?? "").toLowerCase(), amount, payment.nonce ?? ""].join("|"), "utf8")
        .digest("hex");
      if (commitment !== recomputed) {
        return fail("payment commitment mismatch — attestation was issued for a DIFFERENT payment (possible replay)");
      }
      if (Date.parse(expiresAt) <= Date.now()) return fail(`attestation expired at ${expiresAt}`);

      // Evidence record (pin age + named corroboration): verify when present.
      // Absent = older server (fine). Signature failure or wrong binding =
      // tampering = the whole attestation is rejected.
      let pinEvidence: { domain: string | null; age_seconds: number | null; corroboration: string[] } | undefined;
      const ev = scan.attestation.evidence;
      if (ev) {
        if (!edVerify(null, Buffer.from(ev.message, "utf8"), key, Buffer.from(ev.signature_hex, "hex"))) {
          return fail("evidence signature invalid under the pinned server key");
        }
        const parts = ev.message.split("|");
        if (parts[0] === "evidence-v1") {
          // Same grammar the SDKs enforce — lockstep on rejects, not just accepts.
          if (parts.length !== 6) return fail("malformed evidence-v1 message");
          const [, evScanId, evCommitment, domain, age, sources] = parts;
          if (evScanId !== scanId || evCommitment !== commitment) {
            return fail("evidence record is bound to a different scan/payment (possible replay)");
          }
          if (domain && !/^[0-9]+$/.test(age)) {
            return fail("malformed evidence-v1 message: pin_age_seconds is not a non-negative integer");
          }
          pinEvidence = domain
            ? {
                domain,
                age_seconds: Number(age),
                corroboration: sources && sources !== "none" ? sources.split(",") : [],
              }
            : { domain: null, age_seconds: null, corroboration: [] };
          // The mirror must be EXACTLY the signed-derived fields (or null) —
          // it is the one unsigned part of the attestation, so extra keys are
          // unsigned data riding a verified response. Field-wise, never by
          // serialization; strict identically in TS/Python/MCP.
          const mirror = ev.pin;
          if (mirror !== undefined) {
            const signed = domain ? { domain, age_seconds: Number(age), corroboration: pinEvidence.corroboration } : null;
            const mirrorMatches =
              mirror === null
                ? signed === null
                : signed !== null &&
                  Object.keys(mirror).length === 3 &&
                  mirror.domain === signed.domain &&
                  mirror.age_seconds === signed.age_seconds &&
                  mirror.corroboration.length === signed.corroboration.length &&
                  mirror.corroboration.every((s, i) => s === signed.corroboration[i]);
            if (!mirrorMatches) {
              return fail("evidence `pin` mirror does not match the signed evidence message (tampered convenience copy)");
            }
          }
        }
        // Unknown evidence version: authenticated but not parseable by this
        // tool version — surface nothing rather than guess.
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            valid: true,
            verdict: scan.verdict,
            expires_at: expiresAt,
            ...(pinEvidence !== undefined ? { pin_evidence: pinEvidence } : {}),
          }),
        }],
      };
    } catch (e) {
      return fail(`verification error: ${(e as Error).message}`);
    }
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
