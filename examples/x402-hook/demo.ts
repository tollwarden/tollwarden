// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * Runs the onBeforePaymentCreation hook in hook.ts against the real
 * @x402/fetch and @x402/evm clients, offline.
 *
 * A local seller answers 402s whose terms each scenario sets. TollWarden is
 * the dev server (src/devserver.ts) started as a child process with no data
 * dir. The signing key is generated in memory and never printed. The seller
 * does not settle, so nothing is paid even in principle. What the demo
 * measures is whether the client signed.
 *
 *   node --experimental-strip-types examples/x402-hook/demo.ts
 *
 * Exits 0 when every scenario ends as expected, 1 otherwise.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { encodePaymentRequiredHeader } from "@x402/core/http";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { tollwardenHook, tollwardenPrePaymentCheck, type HookOptions } from "./hook.ts";

const NETWORK = "eip155:84532"; // Base Sepolia
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"; // Base Sepolia USDC
const LISTED_PAY_TO = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const OTHER_PAY_TO = "0x5e11E5a1E0000000000000000000000000000b0b";
const LISTED_AMOUNT = "1000"; // $0.001 USDC (6 decimals)
const RUN = Date.now().toString(36);

const signer = privateKeyToAccount(generatePrivateKey());

function listen(server: Server): Promise<number> {
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r((server.address() as AddressInfo).port)));
}

// ── Seller ──────────────────────────────────────────────────────────────────
// Answers a 402 with the current live terms, and 200 to any paid retry. It
// never verifies or settles, because the demo only asks whether the client
// signed.
const live = { amount: LISTED_AMOUNT, payTo: LISTED_PAY_TO };
const requirementFor = (amount: string, payTo: string) => ({
  scheme: "exact",
  network: NETWORK,
  asset: USDC,
  amount,
  payTo,
  maxTimeoutSeconds: 300,
  extra: { name: "USDC", version: "2" },
});
let sellerPort = 0;
const seller = createServer((req, res) => {
  if (typeof req.headers["payment-signature"] === "string") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"report":"ok"}');
    return;
  }
  const paymentRequired = {
    x402Version: 2,
    resource: { url: `http://127.0.0.1:${sellerPort}${req.url}`, description: "Premium market report", mimeType: "application/json" },
    accepts: [requirementFor(live.amount, live.payTo)],
  };
  res.writeHead(402, { "PAYMENT-REQUIRED": encodePaymentRequiredHeader(paymentRequired as any), "content-type": "application/json" });
  res.end("{}");
});
sellerPort = await listen(seller);

// A TollWarden that accepts the connection and never answers, for the timeout.
const hung = createServer(() => {});
const hungPort = await listen(hung);

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

// The catalogue entry the agent chose this resource from, before any 402.
const listing = (url: string) => ({ resource: url, accepts: [requirementFor(LISTED_AMOUNT, LISTED_PAY_TO)] });

// ── Scenarios ───────────────────────────────────────────────────────────────
interface Scenario {
  name: string;
  amount: string;
  payTo: string;
  opts: Partial<HookOptions>;
  expectSigned: boolean;
}

const scenarios: Scenario[] = [
  { name: "live 402 matches the listing", amount: LISTED_AMOUNT, payTo: LISTED_PAY_TO, opts: { onFlag: "abort" }, expectSigned: true },
  { name: "price rose to $0.005 on retry, onFlag abort", amount: "5000", payTo: LISTED_PAY_TO, opts: { onFlag: "abort" }, expectSigned: false },
  { name: "price rose to $0.005 on retry, onFlag allow", amount: "5000", payTo: LISTED_PAY_TO, opts: { onFlag: "allow" }, expectSigned: true },
  { name: "price rose to $2.00, onFlag allow", amount: "2000000", payTo: LISTED_PAY_TO, opts: { onFlag: "allow" }, expectSigned: false },
  { name: "pay_to differs from the listing", amount: LISTED_AMOUNT, payTo: OTHER_PAY_TO, opts: { onFlag: "abort" }, expectSigned: false },
  { name: "TollWarden hangs, onUnavailable abort", amount: LISTED_AMOUNT, payTo: LISTED_PAY_TO, opts: { baseUrl: `http://127.0.0.1:${hungPort}`, timeoutMs: 300, onUnavailable: "abort" }, expectSigned: false },
  { name: "TollWarden hangs, onUnavailable allow", amount: LISTED_AMOUNT, payTo: LISTED_PAY_TO, opts: { baseUrl: `http://127.0.0.1:${hungPort}`, timeoutMs: 300, onUnavailable: "allow" }, expectSigned: true },
];

let failures = 0;
console.log(`x402 onBeforePaymentCreation hook, offline`);
console.log(`Seller http://127.0.0.1:${sellerPort}, TollWarden ${BASE}`);
console.log(`Listing $0.001 to ${LISTED_PAY_TO}\n`);

try {
  for (const [i, s] of scenarios.entries()) {
    live.amount = s.amount;
    live.payTo = s.payTo;
    const url = `http://127.0.0.1:${sellerPort}/report?run=${RUN}&s=${i + 1}`;
    let signed = 0;
    const client = new x402Client();
    registerExactEvmScheme(client, { signer });
    client.onBeforePaymentCreation(
      tollwardenHook({
        baseUrl: BASE,
        apiKey: process.env.TOLLWARDEN_API_KEY,
        agentId: `x402-hook-demo-${RUN}-${i + 1}`,
        payer: signer.address,
        onUnavailable: "abort",
        expectedPriceUsd: 0.001,
        offer: listing(url),
        ...s.opts,
      } as HookOptions),
    );
    client.onAfterPaymentCreation(async () => {
      signed++;
    });
    const pay = wrapFetchWithPayment(fetch, client);

    console.log(`${i + 1}. ${s.name}`);
    try {
      const res = await pay(url);
      await res.text();
      console.log(`   signed, seller answered ${res.status}`);
    } catch (err) {
      console.log(`   not signed. ${err instanceof Error ? err.message : String(err)}`);
    }
    const ok = (signed > 0) === s.expectSigned;
    if (!ok) failures++;
    console.log(`   expected ${s.expectSigned ? "signed" : "not signed"}, ${ok ? "ok" : "MISMATCH"}\n`);
  }

  // The agentkit#1550 shape, called directly as a provider would.
  const check = tollwardenPrePaymentCheck({
    baseUrl: BASE,
    apiKey: process.env.TOLLWARDEN_API_KEY,
    agentId: `x402-hook-demo-${RUN}-shape`,
    onFlag: "abort",
    onUnavailable: "abort",
    expectedPriceUsd: 0.001,
  });
  const verdict = await check({
    url: `http://127.0.0.1:${sellerPort}/report?run=${RUN}&s=shape`,
    method: "GET",
    requirement: requirementFor("2000000", LISTED_PAY_TO) as any,
  });
  console.log(`prePaymentCheck({ url, method, requirement }) at $2.00 returned allow ${verdict.allow}`);
  console.log(`   ${verdict.reason ?? ""}`);
  if (verdict.allow) failures++;

  console.log(`\n${scenarios.length + 1 - failures} of ${scenarios.length + 1} ended as expected.`);
} finally {
  seller.close();
  hung.closeAllConnections();
  hung.close();
  tollwarden?.kill();
}
process.exit(failures === 0 ? 0 : 1);
