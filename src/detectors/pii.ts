// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * PII / secret detection over payment metadata.
 * Scans resource_url, description, reason, and metadata values BEFORE they leave the agent.
 * Zero dependencies.
 */
import type { CheckResult, PaymentDetails, Severity, Verdict } from "../types.ts";

interface Pattern {
  id: string;
  label: string;
  severity: Severity;
  verdict: Verdict;
  re: RegExp;
  /** Optional post-match validator (e.g. Luhn for credit cards) */
  validate?: (match: string) => boolean;
  /**
   * Optional exemption: a match for which this pattern has a documented
   * innocent reading. When present, ALL matches are enumerated and the first
   * non-exempt one is reported — a single exempt match must never mask a real
   * secret later in the same string (`?token=0x…&api_key=REAL`).
   */
  exempt?: (match: string) => string | null;
}

/**
 * `?token=0x` + 40 hex is an ERC-20 contract address — the single most common
 * Web3 API query shape (`?token=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`),
 * and a public identifier, not a credential. It is address-shaped, not
 * entropy-shaped.
 *
 * Deliberately narrow: only the `token` parameter, only an exact 0x+40-hex
 * value. `secret=`, `password=`, `api_key=`, `private_key=` and `auth=` have no
 * innocent reading even when the value happens to look address-shaped, and a
 * bearer token that is exactly 42 characters of `0x`-prefixed hex does not
 * occur in practice. A 64-hex value is a private key, not an address, and is
 * caught by `evm_private_key` regardless.
 *
 * Guard cases: benign `token_contract_address_param` (must stay allow) and
 * attack `token_param_real_secret` / `token_address_then_apikey` (must stay
 * block). Removing the exemption fails the first; widening it fails the others.
 */
const ADDRESS_SHAPED_TOKEN_PARAM = /^[?&]token=0x[0-9a-fA-F]{40}$/;

function exemptAddressShapedToken(match: string): string | null {
  return ADDRESS_SHAPED_TOKEN_PARAM.test(match)
    ? "token parameter carries an address-shaped value (0x + 40 hex), which is an ERC-20 contract address rather than a credential"
    : null;
}

function luhnValid(raw: string): boolean {
  const digits = raw.replace(/[^0-9]/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

const PATTERNS: Pattern[] = [
  // ---- secrets: block ----
  {
    id: "evm_private_key",
    label: "EVM private key",
    severity: "critical",
    verdict: "block",
    re: /\b(?:0x)?[0-9a-fA-F]{64}\b/,
  },
  {
    id: "aws_access_key",
    label: "AWS access key ID",
    severity: "critical",
    verdict: "block",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  },
  {
    id: "openai_key",
    label: "OpenAI API key",
    severity: "critical",
    verdict: "block",
    re: /\bsk-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: "anthropic_key",
    label: "Anthropic API key",
    severity: "critical",
    verdict: "block",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: "github_token",
    label: "GitHub token",
    severity: "critical",
    verdict: "block",
    re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  },
  {
    id: "slack_token",
    label: "Slack token",
    severity: "critical",
    verdict: "block",
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  },
  {
    id: "jwt",
    label: "JWT / bearer token",
    severity: "high",
    verdict: "block",
    re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
  {
    id: "generic_secret_param",
    label: "credential in URL/query parameter",
    severity: "high",
    verdict: "block",
    re: /[?&](?:api[_-]?key|apikey|token|secret|password|passwd|private[_-]?key|auth)=[^&\s]{6,}/i,
    exempt: exemptAddressShapedToken,
  },
  // ---- PII: block the worst, flag the rest ----
  {
    id: "ssn",
    label: "US Social Security number",
    severity: "high",
    verdict: "block",
    re: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/,
  },
  {
    id: "credit_card",
    label: "payment card number",
    severity: "high",
    verdict: "block",
    re: /\b(?:\d[ -]?){13,19}\b/,
    validate: luhnValid,
  },
  {
    id: "email",
    label: "email address",
    severity: "medium",
    verdict: "flag",
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  },
  {
    id: "phone",
    label: "phone number",
    severity: "medium",
    verdict: "flag",
    re: /(?:\+\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b/,
  },
];

/** Heuristic seed-phrase detector: 12+ consecutive lowercase dictionary-shaped words. */
function looksLikeSeedPhrase(text: string): string | null {
  const m = text.match(/\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b/);
  if (!m) return null;
  const words = m[0].trim().split(/\s+/);
  const distinct = new Set(words);
  // Natural sentences repeat stop-words heavily; mnemonics rarely repeat.
  if (distinct.size >= Math.max(10, Math.floor(words.length * 0.8))) return m[0];
  return null;
}

function redact(s: string): string {
  if (s.length <= 8) return "****";
  return `${s.slice(0, 4)}…${s.slice(-2)} (${s.length} chars)`;
}

/**
 * Replace every secret/PII match in `text` with the same redacted form scan
 * responses report (`redact`). Same PATTERNS, same Luhn validation, same
 * exemptions as `scanPii` — so anything a scan would report is masked, and an
 * exempt match (an address-shaped `?token=0x…`) is left readable exactly as
 * the scan leaves it unreported. Used wherever payment prose is persisted or
 * forwarded (the approval excerpt: store snapshot + operator webhook).
 */
export function redactSecrets(text: string): string {
  let out = text;
  for (const p of PATTERNS) {
    const g = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : `${p.re.flags}g`);
    out = out.replace(g, (m) => {
      if (p.validate && !p.validate(m)) return m;
      if (p.exempt && p.exempt(m)) return m;
      return redact(m);
    });
  }
  // Each pass strictly removes dictionary-shaped words, so this terminates;
  // the cap is belt-and-braces.
  for (let i = 0; i < 16; i++) {
    const seed = looksLikeSeedPhrase(out);
    if (!seed) break;
    out = out.split(seed).join(redact(seed));
  }
  return out;
}

const SCANNED_FIELDS: Array<keyof PaymentDetails> = [
  "resource_url",
  "description",
  "reason",
];

export function scanPii(payment: PaymentDetails): CheckResult[] {
  const results: CheckResult[] = [];
  /** Informational records of applied exemptions; never suppress `pii.clean`. */
  const exemptions: CheckResult[] = [];
  const fields: Array<[string, string]> = [];

  for (const f of SCANNED_FIELDS) {
    const v = payment[f];
    if (typeof v === "string" && v.length > 0) fields.push([f, v]);
  }
  for (const [k, v] of Object.entries(payment.metadata ?? {})) {
    if (typeof v === "string" && v.length > 0) fields.push([`metadata.${k}`, v]);
  }

  for (const [field, value] of fields) {
    for (const p of PATTERNS) {
      let hit: string | null = null;
      let exemptedAs: string | null = null;
      if (p.exempt) {
        // Enumerate every match so an exempt one cannot mask a real secret
        // further along the same string. (Only patterns that declare an
        // exemption are enumerated: widening `validate` patterns the same way
        // would give credit_card more chances to hit Luhn by coincidence.)
        const g = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : `${p.re.flags}g`);
        for (const m of value.matchAll(g)) {
          if (p.validate && !p.validate(m[0])) continue;
          const why = p.exempt(m[0]);
          if (why) {
            exemptedAs ??= why;
            continue;
          }
          hit = m[0];
          break;
        }
      } else {
        const m = value.match(p.re);
        if (m && (!p.validate || p.validate(m[0]))) hit = m[0];
      }

      if (hit === null) {
        if (exemptedAs) {
          exemptions.push({
            id: `pii.${p.id}_exempt`,
            name: "PII / secret detection",
            verdict: "allow",
            severity: "info",
            reason: `Field "${field}": ${exemptedAs}. Recorded so the exemption is visible in the scan rather than silent.`,
            details: { field, pattern: p.id },
          });
        }
        continue;
      }
      const m = [hit];
      results.push({
        id: `pii.${p.id}`,
        name: "PII / secret detection",
        verdict: p.verdict,
        severity: p.severity,
        reason: `Detected ${p.label} in payment field "${field}". This would be transmitted to the counterparty and facilitator.`,
        details: { field, match: redact(m[0]) },
      });
    }
    const seed = looksLikeSeedPhrase(value);
    if (seed) {
      results.push({
        id: "pii.seed_phrase",
        name: "PII / secret detection",
        verdict: "block",
        severity: "critical",
        reason: `Field "${field}" appears to contain a wallet seed phrase (${seed.split(/\s+/).length} dictionary words). Never transmit seed material in payment metadata.`,
        details: { field, match: redact(seed) },
      });
    }
  }

  if (results.length === 0) {
    results.push({
      id: "pii.clean",
      name: "PII / secret detection",
      verdict: "allow",
      severity: "info",
      reason: "No PII or secret material detected in payment metadata.",
    });
  }
  results.push(...exemptions);
  return results;
}
