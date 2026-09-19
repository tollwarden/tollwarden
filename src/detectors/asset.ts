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

/** Every canonical USDC deployment above uses 6 decimals. */
const USDC_DECIMALS = 6;

/**
 * Server-known token decimals for (network, asset), or null when the asset is
 * not one TollWarden can vouch for. Value checks resolve decimals from HERE,
 * never from the request: `asset_decimals` is client-supplied, and declaring
 * 18 for a 6-decimal token shrinks a $10 transfer to $0.00001 in every
 * USD-denominated cap (audit 2026-09-19).
 */
export function knownAssetDecimals(network: string | undefined, asset: string | undefined): number | null {
  if (!network || !asset) return null;
  const canonical = CANONICAL_USDC[network];
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

  const canonical = network ? CANONICAL_USDC[network] : undefined;
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
