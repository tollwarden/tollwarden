// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Double pay on retry, reproduced with the reference x402 client.
 *
 * One purchase, two settlements. The seller settles the first authorization
 * and then loses the response (a 502, as a gateway timeout after broadcast
 * looks to the buyer). The agent retries the request, the seller answers with
 * a fresh 402, and @x402/fetch signs a second authorization with a new
 * EIP-3009 nonce. Both authorizations are valid, so both settle. TollWarden
 * scans each signed authorization and flags the second as
 * replay.duplicate_purchase.
 *
 * Run (offline, the default). Everything runs on this machine. A throwaway
 * key is generated in memory, the facilitator is a local fake that applies
 * USDC's transferWithAuthorization rules, and TollWarden is the dev server
 * started as a child process with no data dir.
 *   node --experimental-strip-types examples/double-pay-repro/repro.ts
 *
 * Add --guard to stop the second authorization from being sent when its scan
 * flags a duplicate. Add --sepolia to settle for real on Base Sepolia through
 * an x402 facilitator (see the README for the environment it reads).
 *
 * ┌─ SECURITY ────────────────────────────────────────────────────────────┐
 * │ --sepolia reads a TEST wallet key from EVM_PRIVATE_KEY at run time.    │
 * │ It is never printed, written to a file or sent anywhere but the local  │
 * │ signer. Testnet only. examples/gen-test-wallet.ts makes a throwaway.   │
 * └────────────────────────────────────────────────────────────────────────┘
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import {
  HTTPFacilitatorClient,
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
} from "@x402/core/http";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { getAddress, verifyTypedData } from "viem";

const args = new Set(process.argv.slice(2));
const SEPOLIA = args.has("--sepolia");
const GUARD = args.has("--guard");

const NETWORK = "eip155:84532"; // Base Sepolia, in both modes
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"; // Base Sepolia USDC
const AMOUNT = "1000"; // $0.001 USDC (6 decimals)
const RUN = Date.now().toString(36);

// ── Signer ──────────────────────────────────────────────────────────────────
// Offline, a fresh in-memory key that is never printed. --sepolia, Corbin's
// test key from the environment, read here and nowhere else.
let key: `0x${string}`;
if (SEPOLIA) {
  const k = process.env.EVM_PRIVATE_KEY;
  if (!k || !/^0x[0-9a-fA-F]{64}$/.test(k)) {
    console.error("--sepolia needs EVM_PRIVATE_KEY set to a TEST wallet key (0x + 64 hex). See examples/gen-test-wallet.ts.");
    process.exit(1);
  }
  key = k as `0x${string}`;
} else {
  key = generatePrivateKey();
}
const signer = privateKeyToAccount(key);
const PAY_TO = getAddress(process.env.PAY_TO ?? (SEPOLIA ? signer.address : "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"));

// ── Facilitator ─────────────────────────────────────────────────────────────
interface Facilitator {
  verify(payload: any, requirements: any): Promise<{ isValid: boolean; invalidReason?: string }>;
  settle(payload: any, requirements: any): Promise<{ success: boolean; transaction: string; network: string; errorReason?: string; payer?: string }>;
}

const authorizationTypes = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

/**
 * The rules USDC's transferWithAuthorization applies on chain. A valid
 * signature from `from`, inside [validAfter, validBefore), whose
 * (authorizer, nonce) pair has not been used. Nothing ties two authorizations
 * to one purchase, so two nonces are two transfers.
 */
class FakeFacilitator implements Facilitator {
  readonly usedNonces = new Set<string>();
  readonly settlements: string[] = [];

  async verify(payload: any, req: any): Promise<{ isValid: boolean; invalidReason?: string }> {
    const a = payload.payload?.authorization;
    if (!a) return { isValid: false, invalidReason: "missing authorization" };
    const now = Math.floor(Date.now() / 1000);
    if (getAddress(a.to) !== getAddress(req.payTo)) return { isValid: false, invalidReason: "wrong recipient" };
    if (BigInt(a.value) !== BigInt(req.amount)) return { isValid: false, invalidReason: "wrong amount" };
    if (!(now > Number(a.validAfter) && now < Number(a.validBefore))) return { isValid: false, invalidReason: "outside validity window" };
    if (this.usedNonces.has(`${getAddress(a.from)}:${a.nonce}`)) return { isValid: false, invalidReason: "authorization already used" };
    const ok = await verifyTypedData({
      address: getAddress(a.from),
      domain: { name: req.extra.name, version: req.extra.version, chainId: 84532, verifyingContract: getAddress(req.asset) },
      types: authorizationTypes,
      primaryType: "TransferWithAuthorization",
      message: {
        from: getAddress(a.from),
        to: getAddress(a.to),
        value: BigInt(a.value),
        validAfter: BigInt(a.validAfter),
        validBefore: BigInt(a.validBefore),
        nonce: a.nonce,
      },
      signature: payload.payload.signature,
    });
    return ok ? { isValid: true } : { isValid: false, invalidReason: "bad signature" };
  }

  async settle(payload: any, req: any) {
    const v = await this.verify(payload, req);
    const a = payload.payload.authorization;
    if (!v.isValid) return { success: false, transaction: "", network: NETWORK, errorReason: v.invalidReason };
    this.usedNonces.add(`${getAddress(a.from)}:${a.nonce}`);
    const tx = `fake-tx-${this.settlements.length + 1}`;
    this.settlements.push(tx);
    return { success: true, transaction: tx, network: NETWORK, payer: a.from };
  }
}

const fake = new FakeFacilitator();
const facilitator: Facilitator = SEPOLIA
  ? (new HTTPFacilitatorClient(process.env.FACILITATOR_URL ? { url: process.env.FACILITATOR_URL } : undefined) as unknown as Facilitator)
  : fake;

// ── Seller ──────────────────────────────────────────────────────────────────
// Settles every valid payment it receives. The first time, it then answers
// 502 with no PAYMENT-RESPONSE, so the buyer cannot tell the payment landed.
const settledTxs: string[] = [];
let lostOne = false;

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));
}

const seller = createServer(async (req, res) => {
  const url = `http://127.0.0.1:${sellerPort}${req.url}`;
  const requirements = {
    scheme: "exact",
    network: NETWORK,
    asset: USDC,
    amount: AMOUNT,
    payTo: PAY_TO,
    maxTimeoutSeconds: 300,
    extra: { name: "USDC", version: "2" },
  };
  const header = req.headers["payment-signature"];
  if (typeof header !== "string") {
    const paymentRequired = {
      x402Version: 2,
      resource: { url, description: "Premium market report", mimeType: "application/json" },
      accepts: [requirements],
    };
    res.writeHead(402, { "PAYMENT-REQUIRED": encodePaymentRequiredHeader(paymentRequired as any), "content-type": "application/json" });
    res.end("{}");
    return;
  }
  try {
    const payload = decodePaymentSignatureHeader(header);
    const verified = await facilitator.verify(payload, requirements);
    if (!verified.isValid) {
      res.writeHead(402, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: verified.invalidReason }));
      return;
    }
    const settled = await facilitator.settle(payload, requirements);
    if (!settled.success) {
      res.writeHead(402, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: settled.errorReason }));
      return;
    }
    settledTxs.push(settled.transaction);
    if (!lostOne) {
      lostOne = true;
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "upstream timeout" }));
      return;
    }
    res.writeHead(200, { "PAYMENT-RESPONSE": encodePaymentResponseHeader(settled as any), "content-type": "application/json" });
    res.end(JSON.stringify({ report: "ok" }));
  } catch (err) {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
  }
});
const sellerPort = await listen(seller);
const resourceUrl = `http://127.0.0.1:${sellerPort}/report?run=${RUN}`;

// ── TollWarden ──────────────────────────────────────────────────────────────
let tollwarden: ChildProcess | null = null;
let BASE = process.env.TOLLWARDEN_URL;
if (!BASE) {
  const probe = createServer();
  const port = await listen(probe);
  await new Promise((r) => probe.close(r));
  const devserver = fileURLToPath(new URL("../../src/devserver.ts", import.meta.url));
  tollwarden = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", devserver], {
    env: { PATH: process.env.PATH ?? "", PORT: String(port), DATA_DIR: "none" },
    stdio: ["ignore", "pipe", "inherit"],
  });
  await new Promise<void>((resolve, reject) => {
    tollwarden!.once("exit", (code) => reject(new Error(`TollWarden dev server exited (${code})`)));
    tollwarden!.stdout!.on("data", (d: Buffer) => {
      if (d.toString().includes("listening")) resolve();
    });
  });
  BASE = `http://127.0.0.1:${port}`;
}

interface Check { id: string; verdict: string; severity: string; reason: string }
interface Scan { scan_id: string; verdict: "allow" | "flag" | "block"; checks: Check[] }

async function scan(payload: any): Promise<Scan> {
  const a = payload.payload.authorization;
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (process.env.TOLLWARDEN_API_KEY) headers["x-api-key"] = process.env.TOLLWARDEN_API_KEY;
  const res = await fetch(`${BASE}/v1/scan/outgoing`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      agent_id: `double-pay-repro-${RUN}`,
      payment: {
        scheme: payload.accepted.scheme,
        network: payload.accepted.network,
        asset: payload.accepted.asset,
        amount: a.value,
        pay_to: a.to,
        payer: a.from,
        resource_url: payload.resource?.url ?? resourceUrl,
        description: "Premium market report",
        nonce: a.nonce,
      },
      expected_price_usd: 0.001,
      context: { origin: "planning", phase: "post_sign" },
    }),
  });
  if (res.status !== 200) throw new Error(`TollWarden scan failed (HTTP ${res.status}): ${await res.text()}`);
  return (await res.json()) as Scan;
}

// ── Buyer ───────────────────────────────────────────────────────────────────
const scans: Scan[] = [];
const client = new x402Client();
registerExactEvmScheme(client, { signer });
client.onAfterPaymentCreation(async ({ paymentPayload }: any) => {
  const r = await scan(paymentPayload);
  scans.push(r);
  const n = scans.length;
  console.log(`  signed authorization ${n}, nonce ${String(paymentPayload.payload.authorization.nonce).slice(0, 18)}...`);
  console.log(`  TollWarden scan ${n}: ${r.verdict.toUpperCase()}`);
  for (const c of r.checks) if (c.verdict !== "allow") console.log(`    [${c.verdict}/${c.severity}] ${c.id}: ${c.reason}`);
  if (GUARD && r.checks.some((c) => c.id === "replay.duplicate_purchase" && c.verdict !== "allow")) {
    throw new Error("TollWarden flagged a duplicate purchase. Not sending this authorization until the earlier attempt is resolved.");
  }
});
const fetchWithPayment = wrapFetchWithPayment(fetch, client);

console.log(`Double pay on retry (${SEPOLIA ? "Base Sepolia, real settlement" : "offline, fake facilitator"}${GUARD ? ", --guard" : ""})`);
console.log(`Seller ${resourceUrl}`);
console.log(`TollWarden ${BASE}`);
console.log(`Payer ${signer.address}, pay_to ${PAY_TO}, ${AMOUNT} atomic USDC per purchase\n`);

// An ordinary agent retry policy. Retry a 5xx once, which is what most HTTP
// clients and agent frameworks do by default.
let exitCode = 0;
try {
  for (let attempt = 1; attempt <= 2; attempt++) {
    console.log(`Attempt ${attempt}, GET /report`);
    let status: number;
    try {
      const res = await fetchWithPayment(resourceUrl);
      status = res.status;
      await res.text();
    } catch (err) {
      console.log(`  request aborted. ${err instanceof Error ? err.message : String(err)}`);
      break;
    }
    console.log(`  seller answered ${status}`);
    if (status < 500) break;
  }

  const settled = SEPOLIA ? settledTxs.length : fake.settlements.length;
  const flagged = scans.slice(1).some((s) => s.checks.some((c) => c.id === "replay.duplicate_purchase" && c.verdict === "flag"));
  console.log(`\nOne purchase. ${scans.length} authorizations signed, ${settled} settled.`);
  if (SEPOLIA) for (const tx of settledTxs) console.log(`  settled tx ${tx}`);
  console.log(`replay.duplicate_purchase on the second scan, ${flagged ? "flagged" : "not flagged"}.`);

  const expected = GUARD ? settled === 1 && flagged : settled === 2 && flagged;
  if (!expected) {
    console.error(GUARD ? "Expected one settlement and a flag on the second scan." : "Expected two settlements and a flag on the second scan.");
    exitCode = 1;
  }
} finally {
  seller.close();
  tollwarden?.kill();
}
process.exit(exitCode);
