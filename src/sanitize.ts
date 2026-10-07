// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Input sanitization for scan requests. Detectors assume declared types;
 * this layer guarantees them, so a type-confused (or malicious) payload can
 * never crash a detector or smuggle a non-string past a regex scan.
 * Every coercion here is strip-don't-throw: unknown shapes degrade to
 * "field absent", which the detectors already treat as reduced coverage
 * (flagged), never as trust.
 */
import type { PaymentOrigin, ScanRequest } from "./types.ts";

const ORIGINS = new Set<string>([
  "planning",
  "user_instruction",
  "tool_result",
  "fetched_content",
  "unknown",
]);

function str(v: unknown, max: number): string | undefined {
  return typeof v === "string" ? v.slice(0, max) : undefined;
}

function finiteNum(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Returns null when there is no usable `payment` object at all. */
export function sanitizeScanRequest(raw: unknown): ScanRequest | null {
  if (!isPlainObject(raw) || !isPlainObject(raw.payment)) return null;
  const p = raw.payment;

  const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);
  let metadata: Record<string, string> | undefined;
  if (isPlainObject(p.metadata)) {
    // Null-prototype object + explicit dangerous-key skip: belt-and-suspenders
    // against prototype pollution (audit L-2).
    const md: Record<string, string> = Object.create(null);
    for (const [k, v] of Object.entries(p.metadata)) {
      if (DANGEROUS_KEYS.has(k)) continue;
      if (typeof v === "string") md[k.slice(0, 200)] = v.slice(0, 10_000);
    }
    if (Object.keys(md).length > 0) metadata = md;
  }

  const ctx = isPlainObject(raw.context) ? raw.context : {};
  const originRaw = typeof ctx.origin === "string" ? ctx.origin : undefined;
  // Unrecognized origin values must NOT slip past provenance checks: they
  // normalize to "unknown", which the injection detector flags.
  const origin: PaymentOrigin | undefined =
    ctx.origin === undefined ? undefined
    : originRaw !== undefined && ORIGINS.has(originRaw) ? (originRaw as PaymentOrigin)
    : "unknown";

  const policy = isPlainObject(raw.policy) ? raw.policy : {};

  return {
    agent_id: str(raw.agent_id, 200),
    payment: {
      scheme: str(p.scheme, 100),
      network: str(p.network, 100),
      asset: str(p.asset, 200),
      amount:
        typeof p.amount === "string" ? p.amount.slice(0, 100)
        : typeof p.amount === "number" ? String(p.amount)
        : undefined,
      amount_usd: finiteNum(p.amount_usd),
      asset_decimals: finiteNum(p.asset_decimals),
      pay_to: str(p.pay_to, 200),
      payer: str(p.payer, 200),
      resource_url: str(p.resource_url, 2000),
      description: str(p.description, 10_000),
      reason: str(p.reason, 10_000),
      nonce: str(p.nonce, 500),
      valid_until: str(p.valid_until, 100),
      metadata,
    },
    expected_price_usd: finiteNum(raw.expected_price_usd),
    context: {
      origin,
      content: str(ctx.content, 200_000),
      content_source_url: str(ctx.content_source_url, 2000),
      // Unrecognized phase values degrade to undefined (= post_sign coverage
      // expectations) so a typo can't relax the replay check.
      phase: ctx.phase === "pre_sign" || ctx.phase === "post_sign" ? ctx.phase : undefined,
      offer: str(ctx.offer, 200_000),
      repeat_of: str(ctx.repeat_of, 100),
    },
    policy: {
      force_deep: policy.force_deep === true,
      skip_deep: policy.skip_deep === true,
    },
  };
}
