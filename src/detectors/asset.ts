// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Asset verification: is the token being paid actually canonical USDC on the
 * declared network? Paying in a worthless lookalike token is a known x402
 * attack shape. Static table lookup — zero latency.
 */
import type { CheckResult, PaymentDetails } from "../types.ts";

export const CANONICAL_USDC: Record<string, string> = {
  "eip155:1": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",     // Ethereum
  "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  // Base
  "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", // Base Sepolia
  "eip155:137": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",   // Polygon PoS
  "eip155:42161": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", // Arbitrum One
};

/**
 * x402 v1 network names and the CAIP-2 ids v2 uses for the same chains.
 * Copied from EVM_NETWORK_CHAIN_ID_MAP in @x402/evm 2.18.0 (the v1 client's
 * own name to chain-id table, which sets the chainId it signs for); a test
 * pins this copy to the installed package. v1 has no name for Arbitrum, so
 * eip155:42161 is reachable only by its CAIP-2 id.
 *
 * Without this, a seller writing "base" in its 402 (which paymentFromOffer
 * copies verbatim) turned the lookalike-token BLOCK into the low
 * `asset.unknown_network` flag.
 */
export const X402_V1_NETWORKS: Readonly<Record<string, string>> = {
  ethereum: "eip155:1",
  sepolia: "eip155:11155111",
  abstract: "eip155:2741",
  "abstract-testnet": "eip155:11124",
  "base-sepolia": "eip155:84532",
  base: "eip155:8453",
  "avalanche-fuji": "eip155:43113",
  avalanche: "eip155:43114",
  iotex: "eip155:4689",
  sei: "eip155:1329",
  "sei-testnet": "eip155:1328",
  polygon: "eip155:137",
  "polygon-amoy": "eip155:80002",
  peaq: "eip155:3338",
  story: "eip155:1514",
  educhain: "eip155:41923",
  "skale-base-sepolia": "eip155:324705682",
  megaeth: "eip155:4326",
  monad: "eip155:143",
  stable: "eip155:988",
  "stable-testnet": "eip155:2201",
};

/**
 * The key a declared network is looked up and compared by: lowercased, with
 * x402 v1 names resolved to CAIP-2. Lookups and comparisons ONLY. The payment
 * keeps the string it was presented with, because payment_commitment hashes
 * that string and the wallet-side enforcer recomputes it.
 */
export function networkKey(network: string | undefined): string | undefined {
  if (!network) return undefined;
  const n = network.trim().toLowerCase();
  return Object.hasOwn(X402_V1_NETWORKS, n) ? X402_V1_NETWORKS[n] : n;
}

/**
 * Canonical USDC contract for a declared network (CAIP-2 or x402 v1 name).
 * Own keys only: a plain-object index on "constructor" or "__proto__" used to
 * return a prototype member and throw in the scan.
 */
export function canonicalUsdcFor(network: string | undefined): string | undefined {
  const key = networkKey(network);
  return key !== undefined && Object.hasOwn(CANONICAL_USDC, key) ? CANONICAL_USDC[key] : undefined;
}

/** Every canonical USDC deployment above uses 6 decimals. */
const USDC_DECIMALS = 6;

/**
 * Server-known token decimals for (network, asset), or null when the asset is
 * not one TollWarden can vouch for. Value checks resolve decimals from HERE,
 * never from the request: `asset_decimals` is client-supplied, and declaring
 * 18 for a 6-decimal token shrinks a $10 transfer to $0.00001 in every
 * USD-denominated cap (audit 2026-09-19). For assets this returns null on,
 * see resolveValue in overpayment.ts (a declaration may only raise the value).
 */
export function knownAssetDecimals(network: string | undefined, asset: string | undefined): number | null {
  if (!asset) return null;
  const canonical = canonicalUsdcFor(network);
  if (!canonical) return null;
  return asset.toLowerCase() === canonical.toLowerCase() ? USDC_DECIMALS : null;
}

export function checkAsset(payment: PaymentDetails, allowNonUsdc: boolean): CheckResult {
  const { asset, network } = payment;

  if (!asset) {
    return {
      id: "asset.not_declared",
      name: "Asset verification",
      verdict: "allow",
      severity: "info",
      reason: "No asset contract supplied; canonical-USDC verification skipped. Include `asset` for full coverage.",
    };
  }

  const canonical = canonicalUsdcFor(network);
  if (!canonical) {
    return {
      id: "asset.unknown_network",
      name: "Asset verification",
      verdict: "flag",
      severity: "low",
      reason: `No canonical USDC reference for network "${network ?? "undeclared"}"; cannot verify the asset contract.`,
      details: { asset, network },
    };
  }

  if (asset.toLowerCase() !== canonical.toLowerCase()) {
    return {
      id: "asset.not_canonical_usdc",
      name: "Asset verification",
      verdict: allowNonUsdc ? "flag" : "block",
      severity: allowNonUsdc ? "medium" : "high",
      reason: `Asset ${asset} is NOT canonical USDC on ${network} (expected ${canonical}). Lookalike-token payments transfer worthless tokens that display as "USDC".${allowNonUsdc ? " (Downgraded to flag: ALLOW_NON_USDC=on.)" : " Set ALLOW_NON_USDC=on if you intentionally transact in other tokens."}`,
      details: { asset, expected: canonical, network },
    };
  }

  return {
    id: "asset.canonical",
    name: "Asset verification",
    verdict: "allow",
    severity: "info",
    reason: `Asset is canonical USDC on ${network}.`,
  };
}
