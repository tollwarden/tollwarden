// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/** /.well-known/x402 manifest + agent card. */
import type { TollWardenConfig } from "./config.ts";
import { VERSION } from "./version.ts";

// USDC contract addresses per network (for manifest display; the x402
// middleware resolves assets itself from the price string).
const USDC: Record<string, string> = {
  "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
};

function priceToAtomicUsdc(price: string): string {
  const usd = Number(price.replace("$", ""));
  return String(Math.round(usd * 1_000_000));
}

function resourceEntry(cfg: TollWardenConfig, path: string, description: string, price: string) {
  return {
    resource: `${cfg.publicBaseUrl}${path}`,
    type: "http",
    x402Version: 2,
    accepts: [
      {
        scheme: "exact",
        network: cfg.network,
        amount: priceToAtomicUsdc(price),
        asset: USDC[cfg.network] ?? USDC["eip155:8453"],
        payTo: cfg.payTo,
        maxTimeoutSeconds: 60,
      },
    ],
    metadata: { description },
  };
}

export function x402Manifest(cfg: TollWardenConfig): object {
  return {
    x402Version: 2,
    name: "TollWarden",
    description:
      "Check a payment for fraud before your agent sends it. Call TollWarden before settling any x402 payment to avoid the ways agent wallets get drained: paying an attacker-controlled address injected into web or tool content the agent just read (prompt-injection-triggered payments), replayed payment authorizations, paying more than the quoted price, leaking secrets or private keys through payment metadata, fake/lookalike USDC token contracts, and address poisoning. Returns allow/flag/block with machine-readable reasons; verdicts are Ed25519-signed so a wallet can enforce them. Advisory and non-custodial — never touches keys or funds. Includes a shared counterparty reputation registry (free to report to).",
    resources: [
      resourceEntry(
        cfg,
        "/v1/scan/outgoing",
        "Is this payment safe to send? Screen an outgoing x402 payment BEFORE settling it. Catches payments to an address that came from content the agent just read (prompt-injection-triggered payments), replayed nonces, overpayment vs the quoted price, secrets/PII leaking in payment metadata, fake/lookalike USDC contracts, address poisoning, velocity anomalies, and known-bad or reported counterparties. Returns allow/flag/block with per-check reasons and an Ed25519-signed verdict.",
        cfg.priceScan,
      ),
      resourceEntry(
        cfg,
        "/v1/scan/incoming",
        "Is this 402 offer safe to pay? Screen an incoming x402 payment request BEFORE paying it. Checks the resource URL for spoofing (IP-literal hosts, punycode/homoglyphs, link shorteners, credential demands like 'send your seed phrase'), price sanity, replay, and whether the counterparty has been reported. Returns allow/flag/block with reasons.",
        cfg.priceScan,
      ),
      resourceEntry(
        cfg,
        "/v1/reputation/{address}",
        "Has anyone reported this address? Check a counterparty before dealing with it: aggregated post-hoc reports (scam, non-delivery, prompt injection, overcharge, impersonation, replay abuse) filed by other agents, with distinct-reporter counts and a risk level.",
        cfg.priceReputation,
      ),
    ],
    free_tier: `First ${cfg.freeCalls} calls free per API key — POST /v1/keys (no payment) to get one.`,
    reporting: `POST /v1/reputation/report is always free, so agents can flag bad counterparties after the fact.`,
    custody: "non-custodial; advisory verdicts only",
    plans: {
      catalog: `${cfg.publicBaseUrl}/v1/plans`,
      summary:
        "Subscription tiers with lower per-scan pricing and higher velocity/spend headroom. Agents can subscribe and renew autonomously: POST /v1/plans/subscribe is itself x402-paid at the plan price. Safety-critical checks are identical on every tier.",
    },
  };
}

/** ERC-8004 IdentityRegistry singleton — same vanity address on Base mainnet,
 * Ethereum mainnet, and 35+ other chains. */
export const ERC8004_IDENTITY_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";

/** Minimal scriptless logo (served at /logo.svg) so the ERC-8004 registration
 * file can carry the spec's `image` field without any external asset host. */
export function logoSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect width="64" height="64" rx="14" fill="#0e1526"/>
  <g fill="none" stroke="#0b5cff" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round">
    <path d="M21 12 C16 12 15.5 14.5 15.5 19 V26.5 C15.5 30 13.5 32 10.5 32 C13.5 32 15.5 34 15.5 37.5 V45 C15.5 49.5 16 52 21 52"/>
    <path d="M43 12 C48 12 48.5 14.5 48.5 19 V26.5 C48.5 30 50.5 32 53.5 32 C50.5 32 48.5 34 48.5 37.5 V45 C48.5 49.5 48 52 43 52"/>
  </g>
  <circle cx="32" cy="32" r="9" fill="#22c55e"/>
  <circle cx="32" cy="32" r="5.4" fill="none" stroke="#0e1526" stroke-width="1.8"/>
</svg>
`;
}

/**
 * ERC-8004 registration file (/.well-known/erc8004.json) — the tokenURI
 * target for TollWarden's on-chain agent identity. The identity NFT is minted BY
 * the PAY_TO wallet (admintools/register-erc8004.ts), so the wallet that
 * receives x402 payments and the on-chain identity are the same key. The file
 * must exist BEFORE the mint (it is passed as agentURI), but the agentId only
 * exists after — so `registrations` self-completes once ERC8004_AGENT_ID is
 * set post-mint, with no redeploy of anything on-chain.
 */
export function erc8004Registration(cfg: TollWardenConfig): object {
  const agentIdNum = /^\d+$/.test(cfg.erc8004AgentId) ? Number(cfg.erc8004AgentId) : null;
  return {
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    name: "TollWarden",
    description:
      "Payment security firewall for x402 micropayments. Call TollWarden before settling any x402 payment to catch prompt-injection-triggered payments (attacker addresses planted in content the agent just read), replayed authorizations, overpayment, secrets leaking through payment metadata, fake/lookalike USDC contracts, and address poisoning. Returns allow/flag/block with machine-readable reasons and an Ed25519-signed, payment-bound verdict a wallet can enforce. Advisory and non-custodial — never touches keys or funds. Includes a shared counterparty reputation registry and a commitment-bound delivery-outcome ledger.",
    image: `${cfg.publicBaseUrl}/logo.svg`,
    services: [
      { name: "web", endpoint: cfg.publicBaseUrl },
      { name: "x402", endpoint: `${cfg.publicBaseUrl}/.well-known/x402`, version: "2" },
      { name: "A2A", endpoint: `${cfg.publicBaseUrl}/.well-known/agent-card.json`, version: "0.3.0" },
      { name: "OpenAPI", endpoint: `${cfg.publicBaseUrl}/openapi.json`, version: "3.1.0" },
      { name: "MCP", endpoint: "https://registry.modelcontextprotocol.io/v0/servers?search=com.tollwarden/tollwarden", version: VERSION },
    ],
    x402Support: true,
    active: true,
    // Trust models TollWarden itself supports as a provider today. Validator
    // wiring (validationResponse against the Validation Registry) lands once
    // that portion of the spec settles — see ROADMAP §6.
    supportedTrust: ["reputation"],
    registrations:
      agentIdNum !== null
        ? [{ agentId: agentIdNum, agentRegistry: `eip155:8453:${ERC8004_IDENTITY_REGISTRY}` }]
        : [],
    // The wallet that mints (and owns) the identity NFT. Decoupled from the
    // x402 receiving address (payTo) because a custodial deposit address has
    // no exportable key and can never sign; falls back to payTo for
    // deployments where the receiving wallet IS self-custody.
    ...(cfg.erc8004Wallet || cfg.payTo ? { agentWallet: cfg.erc8004Wallet || cfg.payTo } : {}),
  };
}

export function agentCard(cfg: TollWardenConfig): object {
  return {
    protocolVersion: "0.3.0",
    name: "TollWarden",
    description:
      "Call this before your agent settles any x402 payment to check it for fraud. TollWarden answers 'is this payment safe to send?' and 'is this 402 offer safe to pay?' — catching payments to attacker-controlled addresses injected into content the agent just read (prompt-injection-triggered payments), replayed authorizations, overpayment vs the quote, secrets leaking through payment metadata, fake/lookalike USDC contracts, and address poisoning. Returns allow/flag/block with machine-readable reasons and an Ed25519-signed verdict a wallet can enforce. Non-custodial: never holds keys or funds; wraps whatever wallet/facilitator the agent already uses.",
    url: cfg.publicBaseUrl,
    provider: { organization: "TollWarden", url: cfg.publicBaseUrl },
    version: VERSION,
    capabilities: { streaming: false, pushNotifications: false },
    defaultInputModes: ["application/json"],
    defaultOutputModes: ["application/json"],
    skills: [
      {
        id: "scan_outgoing_payment",
        name: "Check a payment before sending it",
        description:
          "Call before the agent settles an outgoing x402 payment. Answers 'is this safe to send?' — catches paying an address that came from injected content the agent just read, replayed nonces, overpayment vs the quote, secrets/PII in payment metadata, fake/lookalike USDC contracts, address poisoning, and reported counterparties. Returns allow/flag/block.",
        tags: ["security", "payments", "x402", "firewall", "fraud-detection", "prompt-injection", "scam-prevention", "wallet-security", "agent-safety"],
        examples: [
          "Before I pay this, is it safe?",
          "Check this $0.05 USDC payment to 0xabc… for fraud before I settle it",
          "Should I pay this address? It came from a webpage I just read.",
        ],
      },
      {
        id: "scan_incoming_payment",
        name: "Check a 402 offer before paying it",
        description:
          "Call before the agent pays a 402 offer / payment request it received. Answers 'is this offer safe to pay?' — checks the resource URL for spoofing (IP hosts, punycode, shorteners, credential demands), price sanity, replay, and counterparty reputation. Returns allow/flag/block.",
        tags: ["security", "payments", "x402", "firewall", "fraud-detection", "phishing", "scam-prevention"],
        examples: [
          "Is this 402 quote from api.example.com safe to pay?",
          "This site is asking me to pay — is it legit?",
        ],
      },
      {
        id: "counterparty_reputation",
        name: "Check or report a counterparty address",
        description:
          "Look up whether a counterparty address has been reported (scam, non-delivery, prompt injection, overcharge, impersonation, replay abuse), and file your own report for free after a bad experience.",
        tags: ["reputation", "payments", "x402", "fraud-detection", "scam-database", "blocklist"],
        examples: [
          "Has anyone reported 0xdef… for non-delivery?",
          "Is this address known to be a scam?",
          "Report 0xbad… — I paid and got nothing.",
        ],
      },
    ],
    payments: {
      protocol: "x402",
      network: cfg.network,
      pricing: {
        "POST /v1/scan/outgoing": `${cfg.priceScan} (less on a plan — see /v1/plans)`,
        "POST /v1/scan/incoming": `${cfg.priceScan} (less on a plan — see /v1/plans)`,
        "GET /v1/reputation/{address}": cfg.priceReputation,
        "POST /v1/reputation/report": "free",
        "GET /v1/plans": "free",
        "POST /v1/plans/subscribe": "x402-paid at the chosen plan's price",
      },
      freeTier: `first ${cfg.freeCalls} calls per API key`,
      plansCatalog: `${cfg.publicBaseUrl}/v1/plans`,
      manifest: `${cfg.publicBaseUrl}/.well-known/x402`,
    },
  };
}
