// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Wallet-side enforcement kit.
 *
 * Turns TollWarden from advisory into ENFORCED: a wrapped signer physically
 * refuses to sign an x402 payment authorization unless a fresh, Ed25519-
 * verified TollWarden allow-verdict exists for exactly that payment. Because the
 * verdict's payment commitment — sha256(network|pay_to|asset|amount|nonce) —
 * is recomputed from the typed data the wallet is being asked to sign, a
 * compromised agent cannot scan one payment and settle another: any change to
 * the recipient, amount, asset, chain, or nonce changes the commitment and
 * the signature is refused.
 *
 *   const tollwarden  = new TollWardenClient({ agentId: "my-agent" });
 *   const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED_KEY });
 *   const account  = enforcer.guardSigner(privateKeyToAccount(PRIVATE_KEY));
 *
 *   const scan = await tollwarden.guardOutgoing(payment);  // throws on block
 *   enforcer.approve(scan, payment);                    // registers the verdict
 *   // ... hand `account` to your x402 client as usual. It will only ever
 *   // sign authorizations whose commitment carries a live allow-verdict.
 *
 * Design notes:
 *  - Zero dependencies, signer-agnostic: anything with a `signTypedData`
 *    method works (viem accounts/wallet clients, ethers v6 signers, custom).
 *    The wrapper is a Proxy — every other property/method passes through.
 *  - Recognized payment types: EIP-3009 TransferWithAuthorization /
 *    ReceiveWithAuthorization (the x402 "exact" scheme on EVM) and ERC-2612
 *    Permit. Other typed data passes through by default; set
 *    `strictTypes: true` to refuse everything unrecognized (deny-by-default).
 *  - Approvals are SINGLE-USE by default and expire with the attestation
 *    (plus an optional tighter `maxAgeMs`), so a verdict can't be hoarded.
 *  - PRE-SIGN approvals: the default payment path scans the 402 OFFER, and
 *    an offer has no nonce — the x402 client mints the EIP-3009 nonce at
 *    signing time. An approval registered from a nonce-less payment binds
 *    (network, pay_to, asset, amount) and admits exactly ONE authorization
 *    carrying those facts, whatever nonce it ends up with; single-use is what
 *    stops it admitting a second. An approval registered WITH a nonce still
 *    requires that exact nonce. Combine `reusable: true` with pre-sign
 *    approvals only if you accept that any number of authorizations for the
 *    same facts may sign until expiry.
 *  - Enforcement never phones home: approval happens locally against the
 *    pinned key. If TollWarden is unreachable, nothing new can be approved —
 *    fail-closed, which is the point.
 *  - LOCAL POLICY (optional): `allowedRecipients` plus `maxAmountAtomic` /
 *    `maxTotalAtomic` spend caps, checked against the typed data at sign time
 *    with no server involved. Deliberately independent of the verdict layer:
 *    even a payment with a valid allow-verdict is refused if it exceeds the
 *    caps or pays an unlisted recipient, so a compromised advisory path can
 *    only move bounded amounts to known parties.
 */
import {
  computePaymentCommitment,
  verifyAttestation,
  type PaymentDetails,
  type ScanResponse,
  type VerdictAttestation,
} from "./index.ts";

// ---------------------------------------------------------------------------
// Typed-data shapes (structural — no viem/ethers dependency)
// ---------------------------------------------------------------------------
export interface Eip712DomainLike {
  name?: string;
  version?: string;
  chainId?: number | bigint | string;
  verifyingContract?: string;
}

export interface TypedDataLike {
  domain?: Eip712DomainLike;
  types?: Record<string, unknown>;
  primaryType?: string;
  message?: Record<string, unknown>;
}

/** Anything with a signTypedData method (viem account, ethers signer, ...). */
export interface TypedDataSigner {
  signTypedData(...args: unknown[]): Promise<unknown>;
}

export interface EnforcerOptions {
  /** PINNED TollWarden verdict key (hex SPKI DER, from /.well-known/tollwarden-verdict-key).
   * Required — enforcement without a pinned key would trust whatever key a
   * forged response embeds. */
  trustedKeyHex: string;
  /** Also accept "flag" verdicts (default false: allow-only). */
  allowFlagged?: boolean;
  /** Accept human-approved "override:allow" verdicts (default false — OPT IN).
   * An agent that holds its own API key can configure the approval webhook to
   * point at itself and "approve" its own flags; overrides are only
   * trustworthy when the webhook receiver is out of the agent's reach. Turn
   * this on only when a human you trust controls the decide link. */
  acceptOverrides?: boolean;
  /** Tighter freshness bound than the attestation's own expires_at, measured
   * from approve() time. Optional. */
  maxAgeMs?: number;
  /** Let one approval sign multiple times (default false: single-use). */
  reusable?: boolean;
  /** Refuse to sign ANY typed data that isn't a recognized payment
   * authorization (default false: unrecognized types pass through). */
  strictTypes?: boolean;
  /** LOCAL POLICY — hard recipient allowlist. When set, a recognized payment
   * authorization whose recipient (`to`/`spender`) is not on this list is
   * refused at sign time, valid approval or not. Checked against the typed
   * data actually being signed, entirely offline — the bound holds even if
   * every advisory layer above it is wrong or compromised. Case-insensitive.
   * An EMPTY array refuses all recognized payments (deny-all). */
  allowedRecipients?: string[];
  /** LOCAL POLICY escape hatch — let a human-approved "override:allow"
   * verdict satisfy the recipient allowlist for EXACTLY the payment it binds
   * (default false). The list itself never changes and the spend caps still
   * apply: this admits one commitment-bound payment, never a recipient. A
   * plain allow-verdict never admits — only the override path, which exists
   * to be out of the agent's reach. Requires acceptOverrides (construction
   * error otherwise) and inherits its security note: only meaningful when
   * the approval webhook receiver is controlled by a human you trust. */
  overrideAdmitsRecipient?: boolean;
  /** LOCAL POLICY — per-authorization cap, in atomic units of the asset
   * (USDC has 6 decimals, so 1_000_000 = $1). An authorization whose value
   * exceeds this is refused at sign time regardless of approvals. */
  maxAmountAtomic?: bigint | number | string;
  /** LOCAL POLICY — cumulative cap, in atomic units, across every
   * authorization this enforcer instance allows to be signed. Once the
   * running total would exceed it, signing is refused; construct a new
   * enforcer to reset. Atomic units are only comparable within one asset —
   * for x402 that is USDC, but if your flow signs for multiple assets, bound
   * them with separate enforcers. */
  maxTotalAtomic?: bigint | number | string;
}

export class TollWardenEnforcementError extends Error {
  readonly commitment?: string;
  readonly primaryType?: string;
  constructor(message: string, info: { commitment?: string; primaryType?: string } = {}) {
    super(message);
    this.name = "TollWardenEnforcementError";
    this.commitment = info.commitment;
    this.primaryType = info.primaryType;
  }
}

interface Approval {
  attestation: VerdictAttestation;
  scanId: string;
  verdict: string;
  approvedAt: number;
  used: boolean;
}

/**
 * Map an EIP-712 payload to the payment fields the commitment binds.
 * Returns null for typed data that is not a recognized payment authorization.
 */
export function paymentFromTypedData(td: TypedDataLike): PaymentDetails | null {
  const pt = td.primaryType;
  if (!pt) return null;
  const m = td.message ?? {};
  const d = td.domain ?? {};
  const s = (v: unknown): string =>
    typeof v === "string" ? v : typeof v === "number" || typeof v === "bigint" ? String(v) : "";
  const network = d.chainId !== undefined && d.chainId !== null && s(d.chainId) !== "" ? `eip155:${s(d.chainId)}` : "";
  const asset = typeof d.verifyingContract === "string" ? d.verifyingContract : "";

  // EIP-3009 — how the x402 "exact" scheme authorizes USDC transfers on EVM.
  if (pt === "TransferWithAuthorization" || pt === "ReceiveWithAuthorization") {
    return { network, asset, pay_to: s(m.to), payer: s(m.from), amount: s(m.value), nonce: s(m.nonce) };
  }
  // ERC-2612 Permit — a spend approval is a payment authorization too.
  if (pt === "Permit") {
    return { network, asset, pay_to: s(m.spender), payer: s(m.owner), amount: s(m.value), nonce: s(m.nonce) };
  }
  return null;
}

export class TollWardenEnforcer {
  private readonly trustedKeyHex: string;
  private readonly allowFlagged: boolean;
  private readonly acceptOverrides: boolean;
  private readonly maxAgeMs: number | null;
  private readonly reusable: boolean;
  private readonly strictTypes: boolean;
  private readonly allowedRecipients: Set<string> | null;
  private readonly overrideAdmitsRecipient: boolean;
  private readonly maxAmountAtomic: bigint | null;
  private readonly maxTotalAtomic: bigint | null;
  private authorizedTotal = 0n;
  private readonly approvals = new Map<string, Approval>();

  constructor(opts: EnforcerOptions) {
    if (!opts.trustedKeyHex) {
      throw new TollWardenEnforcementError(
        "trustedKeyHex is required: pin the TollWarden verdict key (GET /.well-known/tollwarden-verdict-key) — enforcement must never trust a key embedded in a response.",
      );
    }
    this.trustedKeyHex = opts.trustedKeyHex;
    this.allowFlagged = opts.allowFlagged ?? false;
    this.acceptOverrides = opts.acceptOverrides ?? false;
    this.maxAgeMs = opts.maxAgeMs ?? null;
    this.reusable = opts.reusable ?? false;
    this.strictTypes = opts.strictTypes ?? false;
    this.allowedRecipients = opts.allowedRecipients
      ? new Set(opts.allowedRecipients.map((a) => a.trim().toLowerCase()))
      : null;
    this.overrideAdmitsRecipient = opts.overrideAdmitsRecipient ?? false;
    if (this.overrideAdmitsRecipient && !this.acceptOverrides) {
      throw new TollWardenEnforcementError(
        "overrideAdmitsRecipient requires acceptOverrides: an enforcer that refuses override verdicts could never admit one, so this combination is a dead setting, not a policy.",
      );
    }
    this.maxAmountAtomic = toAtomic(opts.maxAmountAtomic, "maxAmountAtomic");
    this.maxTotalAtomic = toAtomic(opts.maxTotalAtomic, "maxTotalAtomic");
  }

  /**
   * The LOCAL POLICY gate: recipient allowlist and spend caps, checked against
   * the payment extracted from the typed data being signed. Deliberately
   * independent of the verdict/approval layer — it bounds what even a fully
   * approved payment can move, so a subverted advisory layer still can't
   * exceed the caps or reach an unlisted recipient. guardSigner calls this
   * before the approval gate; it is public so wallet authors can pre-check.
   */
  assertPolicy(payment: PaymentDetails, primaryType?: string): void {
    if (this.allowedRecipients) {
      const payTo = (payment.pay_to ?? "").trim().toLowerCase();
      if (!this.allowedRecipients.has(payTo) && !this.overrideAdmits(payment)) {
        throw new TollWardenEnforcementError(
          `recipient ${payment.pay_to || "(empty)"} is not on the local recipient allowlist (${this.allowedRecipients.size} allowed${
            this.overrideAdmitsRecipient ? "; a human-approved override:allow for this exact payment would admit it" : ""
          }); refusing to sign`,
          { primaryType },
        );
      }
    }
    if (this.maxAmountAtomic === null && this.maxTotalAtomic === null) return;
    const amount = parseAtomicAmount(payment.amount);
    if (amount === null) {
      // Caps configured but the value isn't a plain non-negative integer:
      // fail closed — an unparseable amount must not slip past a spend cap.
      throw new TollWardenEnforcementError(
        `spend caps are configured but this authorization's value (${payment.amount ?? "missing"}) is not a plain integer in atomic units; refusing to sign`,
        { primaryType },
      );
    }
    if (this.maxAmountAtomic !== null && amount > this.maxAmountAtomic) {
      throw new TollWardenEnforcementError(
        `authorization value ${amount} exceeds the local per-payment cap of ${this.maxAmountAtomic} atomic units; refusing to sign`,
        { primaryType },
      );
    }
    if (this.maxTotalAtomic !== null && this.authorizedTotal + amount > this.maxTotalAtomic) {
      throw new TollWardenEnforcementError(
        `authorization value ${amount} would take this enforcer's authorized total to ${this.authorizedTotal + amount}, past the local cumulative cap of ${this.maxTotalAtomic} atomic units (${this.authorizedTotal} already authorized); refusing to sign`,
        { primaryType },
      );
    }
  }

  /** Does a registered, human-approved override admit this exact payment past
   * the recipient allowlist? Matches on the payment COMMITMENT, so the
   * admission cannot be transferred to any other payment — and only verdicts
   * approve() already vetted as "override:allow" against the pinned key count.
   * Liveness (expiry, single-use) is still enforced by assertApproved, which
   * always runs after this gate. */
  private overrideAdmits(payment: PaymentDetails): boolean {
    if (!this.overrideAdmitsRecipient) return false;
    return this.findApproval(payment)?.approval.verdict === "override:allow";
  }

  /**
   * Locate the approval for a payment: first by its exact commitment, then —
   * when the payment carries a nonce — by the commitment of the same facts
   * WITHOUT the nonce (a pre-sign approval, registered from the 402 offer
   * before any nonce existed). Never widens beyond that: an approval with a
   * nonce only ever matches that nonce.
   */
  private findApproval(payment: PaymentDetails): { commitment: string; approval: Approval } | null {
    const exact = computePaymentCommitment(payment);
    const a = this.approvals.get(exact);
    if (a) return { commitment: exact, approval: a };
    if (payment.nonce) {
      const preSign = computePaymentCommitment({ ...payment, nonce: undefined });
      const b = this.approvals.get(preSign);
      if (b) return { commitment: preSign, approval: b };
    }
    return null;
  }

  /**
   * The sign-time gate keyed by PAYMENT rather than by commitment: resolves
   * the approval (exact, else pre-sign) and runs assertApproved on it.
   * Returns the commitment that was consumed.
   */
  assertApprovedFor(payment: PaymentDetails, primaryType?: string): string {
    const found = this.findApproval(payment);
    const commitment = found?.commitment ?? computePaymentCommitment(payment);
    this.assertApproved(commitment, primaryType);
    return commitment;
  }

  /** Total atomic value of payment authorizations this enforcer has allowed
   * to be signed. Counts authorizations the gates passed, not settlements. */
  totalAuthorizedAtomic(): bigint {
    return this.authorizedTotal;
  }

  /** Count an authorization against the cumulative cap — called by guardSigner
   * once BOTH gates (policy, approval) have passed for a recognized payment. */
  private recordAuthorized(payment: PaymentDetails): void {
    const amount = parseAtomicAmount(payment.amount);
    if (amount !== null) this.authorizedTotal += amount;
  }

  /**
   * Register a scan verdict as signing authority for its payment. Verifies the
   * attestation against the PINNED key (signature, field match, commitment,
   * expiry — throws AttestationError on any failure), then requires an allow
   * verdict (or flag with allowFlagged). Returns the payment commitment.
   */
  approve(scan: ScanResponse, payment: PaymentDetails): string {
    verifyAttestation(scan, payment, this.trustedKeyHex);
    const acceptable =
      scan.verdict === "allow" ||
      (scan.verdict === "flag" && this.allowFlagged) ||
      (scan.verdict === "override:allow" && this.acceptOverrides);
    if (!acceptable) {
      throw new TollWardenEnforcementError(
        `refusing to approve a "${scan.verdict}" verdict for signing${
          scan.verdict === "flag"
            ? " (set allowFlagged to accept flags)"
            : scan.verdict === "override:allow"
              ? " (human-approved overrides require the acceptOverrides opt-in — see its security note)"
              : ""
        }`,
      );
    }
    const commitment = computePaymentCommitment(payment);
    this.approvals.set(commitment, {
      attestation: scan.attestation as VerdictAttestation,
      scanId: scan.scan_id,
      verdict: scan.verdict,
      approvedAt: Date.now(),
      used: false,
    });
    return commitment;
  }

  /** Withdraw signing authority for a commitment. */
  revoke(commitment: string): void {
    this.approvals.delete(commitment);
  }

  /** Drop all approvals. */
  clear(): void {
    this.approvals.clear();
  }

  /**
   * The sign-time gate. Throws TollWardenEnforcementError unless a live,
   * unexpired (and unused, unless reusable) approval exists for this
   * commitment; consumes it on success.
   */
  assertApproved(commitment: string, primaryType?: string): void {
    const a = this.approvals.get(commitment);
    if (!a) {
      throw new TollWardenEnforcementError(
        `no TollWarden allow-verdict for this payment authorization (commitment ${commitment.slice(0, 16)}…). ` +
          `Scan the payment and call enforcer.approve(scan, payment) first. If the payment was scanned, its ` +
          `recipient/amount/asset/chain/nonce differs from what is now being signed — which is exactly what this gate exists to catch.`,
        { commitment, primaryType },
      );
    }
    if (a.used && !this.reusable) {
      throw new TollWardenEnforcementError(
        `this allow-verdict was already used to sign once (scan ${a.scanId}); approvals are single-use. Re-scan to sign again.`,
        { commitment, primaryType },
      );
    }
    const expiresAt = Date.parse(a.attestation.expires_at);
    const staleAt = this.maxAgeMs !== null ? a.approvedAt + this.maxAgeMs : Infinity;
    const deadline = Math.min(expiresAt, staleAt);
    if (Date.now() >= deadline) {
      this.approvals.delete(commitment);
      throw new TollWardenEnforcementError(
        `the allow-verdict for this payment is stale (scan ${a.scanId}, deadline ${new Date(deadline).toISOString()}). Re-scan to obtain a fresh verdict.`,
        { commitment, primaryType },
      );
    }
    a.used = true;
  }

  /**
   * Wrap a signer so signTypedData refuses x402/EIP-3009/Permit payment
   * authorizations that lack a live approval. Every other property and method
   * of the signer passes through untouched (Proxy), so the wrapped signer is
   * a drop-in replacement for viem accounts, ethers signers, etc.
   *
   * Scope: this guards the typed-data path x402 uses. If your signer exposes
   * other fund-moving paths (signTransaction), gate those at your policy
   * layer too.
   */
  guardSigner<T extends TypedDataSigner>(signer: T): T {
    // viem calls account.signTypedData(typedData); ethers v6 uses
    // signer.signTypedData(domain, types, message). Support both shapes.
    const enforcer = this;
    const wrapped = async function (this: unknown, ...args: unknown[]): Promise<unknown> {
      const td: TypedDataLike =
        args.length >= 3
          ? { domain: args[0] as Eip712DomainLike, types: args[1] as Record<string, unknown>, message: args[2] as Record<string, unknown>, primaryType: inferPrimaryType(args[1]) }
          : ((args[0] ?? {}) as TypedDataLike);
      const payment = paymentFromTypedData(td);
      if (payment === null) {
        if (enforcer.strictTypes) {
          throw new TollWardenEnforcementError(
            `strictTypes: refusing to sign unrecognized typed data (primaryType ${td.primaryType ?? "unknown"})`,
            { primaryType: td.primaryType },
          );
        }
        return signer.signTypedData(...args);
      }
      // Local policy first (allowlist, caps — offline, approval-independent),
      // then the verdict/approval gate; count against the cumulative cap only
      // when both have passed and the signature is about to happen.
      enforcer.assertPolicy(payment, td.primaryType);
      enforcer.assertApprovedFor(payment, td.primaryType);
      enforcer.recordAuthorized(payment);
      return signer.signTypedData(...args);
    };
    return new Proxy(signer, {
      get(target, prop, receiver) {
        if (prop === "signTypedData") return wrapped;
        const value = Reflect.get(target, prop, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  }
}

/** Parse a policy cap option into a non-negative bigint (null = not set).
 * Throws on anything that isn't a plain integer — a cap that silently failed
 * to parse would be a cap that silently doesn't exist. */
function toAtomic(v: bigint | number | string | undefined, name: string): bigint | null {
  if (v === undefined) return null;
  try {
    const b = BigInt(v);
    if (b < 0n) throw new Error("negative");
    return b;
  } catch {
    throw new TollWardenEnforcementError(`${name} must be a non-negative integer amount in atomic units (got ${String(v)})`);
  }
}

/** Parse a typed-data value into a non-negative bigint, or null if it isn't
 * a plain integer (callers with caps configured treat null as refuse). */
function parseAtomicAmount(amount: string | undefined): bigint | null {
  if (typeof amount !== "string" || !/^\d+$/.test(amount)) return null;
  return BigInt(amount);
}

/** ethers v6 passes (domain, types, message) with no primaryType — infer it
 * as the type that no other type references (EIP-712 convention). */
function inferPrimaryType(types: unknown): string | undefined {
  if (typeof types !== "object" || types === null) return undefined;
  const names = Object.keys(types as Record<string, unknown>).filter((n) => n !== "EIP712Domain");
  const referenced = new Set<string>();
  for (const n of names) {
    const fields = (types as Record<string, unknown>)[n];
    if (!Array.isArray(fields)) continue;
    for (const f of fields) {
      const t = (f as { type?: string })?.type ?? "";
      referenced.add(t.replace(/\[\]$/, ""));
    }
  }
  return names.find((n) => !referenced.has(n)) ?? names[0];
}
