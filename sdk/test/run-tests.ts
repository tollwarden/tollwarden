// Copyright (c) 2026 TollWarden, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * SDK test-suite. Zero dependencies; runs a mock TollWarden server on a local
 * port and — crucially — signs attestations with the REAL server signer
 * (../../src/verdictsign.ts), so SDK verification is cross-validated against
 * production crypto, not a reimplementation.
 *
 * Run: node --experimental-strip-types sdk/test/run-tests.ts
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { VerdictSigner } from "../../src/verdictsign.ts";
import { paymentCommitment } from "../../src/commitment.ts";
import {
  TollWardenClient,
  TollWardenBlockedError,
  TollWardenError,
  AttestationError,
  TollWardenEnforcer,
  TollWardenEnforcementError,
  paymentFromTypedData,
  computePaymentCommitment,
  verifyAttestation,
  wrapFetchWithTollWarden,
  type PaymentDetails,
  type ScanResponse,
  type TypedDataLike,
  type TypedDataSigner,
} from "../src/index.ts";

let passed = 0;
let failed = 0;
function check(name: string, cond: boolean, extra?: unknown): void {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.error(`  ✗ ${name}`, extra ?? "");
  }
}

// ---------------------------------------------------------------------------
// Mock server
// ---------------------------------------------------------------------------
const signer = new VerdictSigner(null);
const rogueSigner = new VerdictSigner(null); // for wrong-key tests

interface Seen {
  scans: Array<{ headers: Record<string, string | string[] | undefined>; body: any }>;
  subscribes: number;
}
const seen: Seen = { scans: [], subscribes: 0 };
const seenOutcomes: any[] = [];
const mockApprovals = new Map<string, { payment: PaymentDetails; scan: ScanResponse; polls: number; behavior: "approve" | "deny" | "stall" | "forge" }>();

function readBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(data || "{}"));
      } catch {
        resolve({});
      }
    });
  });
}

function makeScan(payment: PaymentDetails): ScanResponse {
  const payTo = (payment.pay_to ?? "").toLowerCase();
  const verdict = payTo.includes("bad") ? "block" : payTo.includes("iffy") ? "flag" : "allow";
  const scan: ScanResponse = {
    scan_id: `mock-${Math.random().toString(36).slice(2)}`,
    direction: "outgoing",
    verdict,
    risk_score: verdict === "block" ? 95 : verdict === "flag" ? 40 : 0,
    checks:
      verdict === "allow"
        ? []
        : [{ id: "mock.check", name: "Mock", verdict, severity: "high", reason: "mock reason" }],
    scanned_at: new Date().toISOString(),
    advisory: "mock",
  };
  // 0xreplay: attest a DIFFERENT payment's commitment (attestation replay attack)
  const commitment = payTo.includes("replay")
    ? paymentCommitment({ network: "eip155:8453", pay_to: "0xattacker", amount: "1", nonce: "0xother" })
    : paymentCommitment(payment);
  scan.attestation = signer.attest(scan, commitment);
  return scan;
}

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const path = (req.url ?? "/").split("?")[0];
  const send = (status: number, body: unknown, headers: Record<string, string> = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(body));
  };

  if (req.method === "POST" && path === "/v1/keys") {
    return send(201, { api_key: `psk_mock_${Math.random().toString(36).slice(2)}`, free_calls_remaining: 100 });
  }
  if (req.method === "GET" && path === "/.well-known/tollwarden-verdict-key") {
    return send(200, signer.publicKeyInfo());
  }
  if (req.method === "POST" && (path === "/v1/scan/outgoing" || path === "/v1/scan/incoming")) {
    const body = await readBody(req);
    seen.scans.push({ headers: req.headers as Record<string, string>, body });
    if ((body?.payment?.pay_to ?? "").includes("402trigger")) return send(402, {});
    const scan = makeScan(body.payment ?? {});
    scan.direction = path.endsWith("incoming") ? "incoming" : "outgoing";
    // Direction is part of the signed message, so re-attest after changing it.
    const payTo = (body?.payment?.pay_to ?? "").toLowerCase();
    const commitment = payTo.includes("replay")
      ? paymentCommitment({ network: "eip155:8453", pay_to: "0xattacker", amount: "1", nonce: "0xother" })
      : paymentCommitment(body.payment ?? {});
    // "pinned" marker: the attestation carries signed pin evidence, exactly as
    // the real server emits for an established, CDP-corroborated pin.
    const pin = payTo.includes("pinned")
      ? { domain: "seller.example.com", age_seconds: 7_776_000, corroboration: ["cdp_bazaar"] }
      : null;
    scan.attestation = signer.attest(scan, commitment, undefined, pin);
    // HITL: flags carry a pending approval (behavior encoded in pay_to markers).
    if (scan.verdict === "flag") {
      const id = `apr-${mockApprovals.size + 1}`;
      mockApprovals.set(id, { payment: body.payment ?? {}, scan, polls: 0, behavior: payTo.includes("deny") ? "deny" : payTo.includes("stall") ? "stall" : payTo.includes("forge") ? "forge" : "approve" });
      (scan as ScanResponse & { approval?: unknown }).approval = { approval_id: id, status: "pending", expires_at: new Date(Date.now() + 600_000).toISOString(), poll: `GET /v1/approvals/${id}`, note: "mock" };
    }
    return send(200, scan, { "x-free-calls-remaining": "97" });
  }
  if (req.method === "GET" && /^\/v1\/approvals\/[^/]+$/.test(path)) {
    const a = mockApprovals.get(path.split("/").pop() ?? "");
    if (!a) return send(404, { error: "Unknown approval." });
    a.polls++;
    const base = { approval_id: path.split("/").pop(), scan_id: a.scan.scan_id, created_at: a.scan.scanned_at, expires_at: new Date(Date.now() + 600_000).toISOString(), decided_at: new Date().toISOString() };
    if (a.behavior === "deny") return send(200, { ...base, status: "denied" });
    if (a.behavior === "stall") return send(200, { ...base, status: "pending", decided_at: null });
    if (a.polls < 2) return send(200, { ...base, status: "pending", decided_at: null }); // approve on the 2nd poll
    const approvedAt = new Date().toISOString();
    const mint = a.behavior === "forge" ? rogueSigner : signer; // forge = signed by the WRONG key
    const attestation = mint.attestOverride(
      { scan_id: a.scan.scan_id, direction: a.scan.direction, risk_score: a.scan.risk_score, approved_at: approvedAt },
      paymentCommitment(a.payment),
      300,
    );
    const override = { scan_id: a.scan.scan_id, direction: a.scan.direction, verdict: "override:allow", risk_score: a.scan.risk_score, checks: [], scanned_at: approvedAt, advisory: "mock override", attestation };
    return send(200, { ...base, status: "approved", override });
  }
  if (req.method === "POST" && path === "/v1/approvals/config") {
    const body = await readBody(req);
    if (body.webhook_url === null) return send(200, { enabled: false });
    return send(200, { enabled: true, webhook_url: body.webhook_url, format: body.format ?? "json", webhook_secret: "psw_mocksecret" });
  }
  if (req.method === "GET" && path === "/v1/plans") {
    return send(200, { plans: [{ id: "pro", name: "Pro", price: "$4.99", duration_days: 30, description: "", limits: {} }], hard_ceilings: {} });
  }
  if (req.method === "POST" && path === "/v1/plans/subscribe") {
    seen.subscribes++;
    const body = await readBody(req);
    return send(200, { plan: body.plan, expires_at: new Date(Date.now() + 30 * 86400_000).toISOString() });
  }
  if (req.method === "POST" && path === "/v1/reputation/report") {
    return send(201, { accepted: true });
  }
  if (req.method === "POST" && path === "/v1/outcomes") {
    const body = await readBody(req);
    seenOutcomes.push(body);
    return send(201, { recorded: true, scan_id: body.scan_id, outcome: body.outcome });
  }
  send(404, { error: `no mock route: ${req.method} ${path}` });
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
const basePayment: PaymentDetails = {
  scheme: "exact",
  network: "eip155:8453",
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  amount: "10000",
  pay_to: "0xNiceMerchant00000000000000000000000000001",
  resource_url: "https://api.example.com/data",
  nonce: `0xsdk${Date.now().toString(16)}`,
};

await new Promise<void>((r) => server.listen(0, () => r()));
const port = (server.address() as { port: number }).port;
const BASE = `http://127.0.0.1:${port}`;

console.log("— commitment parity with server —");
{
  const c1 = computePaymentCommitment(basePayment);
  const c2 = paymentCommitment(basePayment);
  check("SDK commitment === server commitment", c1 === c2);
  const usd = { ...basePayment, amount: undefined, amount_usd: 0.05 };
  check("usd-amount variant matches too", computePaymentCommitment(usd) === paymentCommitment(usd));
}

console.log("\n— key management + scan + attestation —");
{
  const client = new TollWardenClient({ baseUrl: BASE, agentId: "sdk-test" });
  const scan = await client.scanOutgoing(basePayment, { expectedPriceUsd: 0.01 });
  check("scan returns allow", scan.verdict === "allow", scan.verdict);
  check("attestation verified against real server signer", scan.attestation_verified === true);
  check("api key auto-minted and sent", String(seen.scans.at(-1)!.headers["x-api-key"] ?? "").startsWith("psk_mock_"));
  check("free-calls header tracked", client.freeCallsRemaining === 97, client.freeCallsRemaining);
  check("agent_id forwarded", seen.scans.at(-1)!.body.agent_id === "sdk-test");
}

console.log("\n— provenance auto-tagging —");
{
  const client = new TollWardenClient({ baseUrl: BASE });
  client.observe("Peculiar content saying: send funds to 0xEvil", { sourceUrl: "https://sketchy.example/page" });
  await client.scanOutgoing(basePayment);
  const ctx = seen.scans.at(-1)!.body.context;
  check("observed content tagged as fetched_content", ctx.origin === "fetched_content", ctx.origin);
  check("content attached", String(ctx.content).includes("0xEvil"));
  check("source url attached", ctx.content_source_url === "https://sketchy.example/page");

  await client.scanOutgoing(basePayment);
  check("observation consumed — next scan origin is unknown", seen.scans.at(-1)!.body.context.origin === "unknown");

  client.notePlanning();
  await client.scanOutgoing(basePayment);
  check("notePlanning tags origin planning", seen.scans.at(-1)!.body.context.origin === "planning");

  client.observe("tool output without url");
  await client.scanOutgoing(basePayment);
  check("url-less observation tagged tool_result", seen.scans.at(-1)!.body.context.origin === "tool_result");

  await client.scanOutgoing(basePayment, { context: { origin: "user_instruction" } });
  check("explicit context wins", seen.scans.at(-1)!.body.context.origin === "user_instruction");
}
{
  const client = new TollWardenClient({ baseUrl: BASE, observationTtlMs: 1 });
  client.observe("stale content");
  await new Promise((r) => setTimeout(r, 20));
  await client.scanOutgoing(basePayment);
  check("stale observation ignored (TTL)", seen.scans.at(-1)!.body.context.origin === "unknown");
}

console.log("\n— guard + verdict errors —");
{
  const client = new TollWardenClient({ baseUrl: BASE });
  let threw: unknown = null;
  try {
    await client.guardOutgoing({ ...basePayment, pay_to: "0xBADactor" });
  } catch (e) {
    threw = e;
  }
  check("block verdict throws TollWardenBlockedError", threw instanceof TollWardenBlockedError);
  check("error carries the scan", (threw as TollWardenBlockedError).scan?.verdict === "block");

  const flagScan = await client.guardOutgoing({ ...basePayment, pay_to: "0xIFFYmerchant" });
  check("flag passes guard by default", flagScan.verdict === "flag");
  let strictThrew = false;
  try {
    await client.guardOutgoing({ ...basePayment, pay_to: "0xIFFYmerchant" }, { strict: true });
  } catch {
    strictThrew = true;
  }
  check("strict mode throws on flag", strictThrew);
}

console.log("\n— attestation attack cases —");
{
  const client = new TollWardenClient({ baseUrl: BASE });
  let threw: unknown = null;
  try {
    await client.scanOutgoing({ ...basePayment, pay_to: "0xREPLAYmerchant" });
  } catch (e) {
    threw = e;
  }
  check("commitment mismatch (replayed attestation) rejected", threw instanceof AttestationError);
  check("replay error names the cause", String((threw as Error)?.message).includes("DIFFERENT payment"));
}
{
  const roguePub = (rogueSigner.publicKeyInfo() as { public_key_spki_hex: string }).public_key_spki_hex;
  const client = new TollWardenClient({ baseUrl: BASE, verdictKeyHex: roguePub });
  let threw: unknown = null;
  try {
    await client.scanOutgoing(basePayment);
  } catch (e) {
    threw = e;
  }
  check("signature from a different key rejected under pinned key", threw instanceof AttestationError);
}
{
  // Expired attestation: verify directly with a past `now`.
  const scan = makeScan(basePayment);
  const pub = (signer.publicKeyInfo() as { public_key_spki_hex: string }).public_key_spki_hex;
  let ok = true;
  try {
    verifyAttestation(scan, basePayment, pub, new Date(Date.now() + 10 * 60_000));
    ok = false;
  } catch (e) {
    ok = e instanceof AttestationError && String((e as Error).message).includes("expired");
  }
  check("expired attestation rejected", ok);
  verifyAttestation(scan, basePayment, pub); // fresh: should not throw
  check("fresh attestation verifies standalone", true);
}

console.log("\n— signed pin evidence (evidence-v1) —");
{
  const pub = (signer.publicKeyInfo() as { public_key_spki_hex: string }).public_key_spki_hex;

  // A pin-bearing scan surfaces verified pin facts on the response.
  const client = new TollWardenClient({ baseUrl: BASE });
  const pinnedScan = await client.scanOutgoing({ ...basePayment, pay_to: "0xPINNEDmerchant0000000000000000000000001" });
  check("verified pin evidence attached to the scan", pinnedScan.pin_evidence?.domain === "seller.example.com" && pinnedScan.pin_evidence?.age_seconds === 7_776_000, pinnedScan.pin_evidence);
  check("corroboration names the source, not a boolean", JSON.stringify(pinnedScan.pin_evidence?.corroboration) === JSON.stringify(["cdp_bazaar"]));

  // No pin applies → verified null (distinct from "no evidence record").
  const plainScan = await client.scanOutgoing(basePayment);
  check("no-pin evidence verifies to an explicit null", plainScan.pin_evidence === null && plainScan.attestation_verified === true);

  // Back-compat: an attestation WITHOUT an evidence record (older server /
  // override) verifies fine and returns null.
  const legacy = makeScan(basePayment);
  delete legacy.attestation!.evidence;
  check("legacy attestation without evidence still verifies", verifyAttestation(legacy, basePayment, pub) === null);

  // Tampered evidence: flip the signed age → signature must fail.
  const tampered = makeScan(basePayment);
  tampered.attestation = signer.attest(tampered, paymentCommitment(basePayment), undefined, { domain: "seller.example.com", age_seconds: 60, corroboration: [] });
  tampered.attestation.evidence!.message = tampered.attestation.evidence!.message.replace("|60|", "|15552000|");
  let threw: unknown = null;
  try { verifyAttestation(tampered, basePayment, pub); } catch (e) { threw = e; }
  check("tampered evidence message rejected", threw instanceof AttestationError && String((threw as Error).message).includes("evidence signature"));

  // Evidence lifted from a DIFFERENT scan: authentic signature, wrong binding.
  const scanA = makeScan(basePayment);
  scanA.attestation = signer.attest(scanA, paymentCommitment(basePayment), undefined, { domain: "seller.example.com", age_seconds: 60, corroboration: [] });
  const scanB = makeScan(basePayment);
  scanB.attestation!.evidence = scanA.attestation!.evidence;
  threw = null;
  try { verifyAttestation(scanB, basePayment, pub); } catch (e) { threw = e; }
  check("evidence bound to a different scan rejected (replay)", threw instanceof AttestationError && String((threw as Error).message).includes("DIFFERENT scan"));

  // A spoofed convenience mirror must not survive verification.
  const mirrored = makeScan(basePayment);
  mirrored.attestation = signer.attest(mirrored, paymentCommitment(basePayment), undefined, { domain: "seller.example.com", age_seconds: 60, corroboration: [] });
  mirrored.attestation.evidence!.pin = { domain: "seller.example.com", age_seconds: 15_552_000, corroboration: ["cdp_bazaar"] };
  threw = null;
  try { verifyAttestation(mirrored, basePayment, pub); } catch (e) { threw = e; }
  check("spoofed pin mirror rejected", threw instanceof AttestationError && String((threw as Error).message).includes("mirror"));

  // A future evidence version is authenticated but not parsed — no throw, no
  // pin. Hand-sign an evidence-v2 record under a local keypair to prove the
  // tag gate, not just record absence.
  const { privateKey: futPriv, publicKey: futPub } = generateKeyPairSync("ed25519");
  const futKeyHex = (futPub.export({ format: "der", type: "spki" }) as Buffer).toString("hex");
  const future = makeScan(basePayment);
  const futCommitment = paymentCommitment(basePayment);
  const futMessage = [future.scan_id, future.direction, future.verdict, future.risk_score, future.scanned_at, futCommitment, future.attestation!.expires_at].join("|");
  const futEvMessage = `evidence-v2|${future.scan_id}|${futCommitment}|something|new|here`;
  future.attestation = {
    alg: "ed25519",
    public_key_spki_hex: futKeyHex,
    message: futMessage,
    signature_hex: edSign(null, Buffer.from(futMessage, "utf8"), futPriv).toString("hex"),
    payment_commitment: futCommitment,
    expires_at: future.attestation!.expires_at,
    evidence: { message: futEvMessage, signature_hex: edSign(null, Buffer.from(futEvMessage, "utf8"), futPriv).toString("hex"), pin: null },
  };
  check("future evidence versions are tolerated (returns null)", verifyAttestation(future, basePayment, futKeyHex) === null);

  // Evidence for the SAME scan_id but a different payment commitment: graft
  // evidence minted for payment P1 onto the same scan's attestation for P2 —
  // must trip the commitment-binding branch, not just the scan_id branch.
  const p1 = { ...basePayment, nonce: "0xevA" };
  const p2 = { ...basePayment, nonce: "0xevB" };
  const scanC = makeScan(p2);
  const donor = signer.attest(scanC, paymentCommitment(p1), undefined, { domain: "seller.example.com", age_seconds: 60, corroboration: [] });
  scanC.attestation = signer.attest(scanC, paymentCommitment(p2), undefined, null);
  scanC.attestation.evidence = donor.evidence;
  threw = null;
  try { verifyAttestation(scanC, p2, pub); } catch (e) { threw = e; }
  check("evidence bound to a different payment commitment rejected", threw instanceof AttestationError && String((threw as Error).message).includes("DIFFERENT scan"));

  // Frozen grammar: a signed evidence-v1 with the wrong arity must throw, and
  // a non-ASCII-decimal age must throw — same rejects as the Python SDK.
  const { privateKey: localPriv, publicKey: localPub } = generateKeyPairSync("ed25519");
  const localKeyHex = (localPub.export({ format: "der", type: "spki" }) as Buffer).toString("hex");
  const localSignedScan = (evFields: string): ScanResponse => {
    const s = makeScan(basePayment);
    const c = paymentCommitment(basePayment);
    const msg7 = [s.scan_id, s.direction, s.verdict, s.risk_score, s.scanned_at, c, s.attestation!.expires_at].join("|");
    const evMsg = `evidence-v1|${s.scan_id}|${c}|${evFields}`;
    s.attestation = {
      alg: "ed25519",
      public_key_spki_hex: localKeyHex,
      message: msg7,
      signature_hex: edSign(null, Buffer.from(msg7, "utf8"), localPriv).toString("hex"),
      payment_commitment: c,
      expires_at: s.attestation!.expires_at,
      evidence: { message: evMsg, signature_hex: edSign(null, Buffer.from(evMsg, "utf8"), localPriv).toString("hex"), pin: null },
    };
    return s;
  };
  for (const c of [
    { name: "wrong-arity evidence-v1 (7 fields) rejected", fields: "seller.example.com|60|none|extra", includes: "malformed evidence-v1" },
    { name: "non-decimal pin age (1e3) rejected", fields: "seller.example.com|1e3|none", includes: "non-negative integer" },
  ]) {
    let err: unknown = null;
    try { verifyAttestation(localSignedScan(c.fields), basePayment, localKeyHex); } catch (e) { err = e; }
    check(c.name, err instanceof AttestationError && String((err as Error).message).includes(c.includes), String((err as Error)?.message));
  }

  // The mirror is EXACTLY the signed fields: an extra unsigned key must be
  // rejected (it would be unsigned data riding a verified attestation)…
  const extraKey = makeScan(basePayment);
  extraKey.attestation = signer.attest(extraKey, paymentCommitment(basePayment), undefined, { domain: "seller.example.com", age_seconds: 60, corroboration: [] });
  (extraKey.attestation.evidence!.pin as unknown as Record<string, unknown>).note = "TollWarden-verified merchant";
  threw = null;
  try { verifyAttestation(extraKey, basePayment, pub); } catch (e) { threw = e; }
  check("extra unsigned key in the pin mirror rejected", threw instanceof AttestationError && String((threw as Error).message).includes("mirror"));

  // …while key ORDER is meaningless: a reordered mirror must verify (guards
  // against regressing to serialization comparison).
  const reordered = makeScan(basePayment);
  reordered.attestation = signer.attest(reordered, paymentCommitment(basePayment), undefined, { domain: "seller.example.com", age_seconds: 60, corroboration: ["cdp_bazaar"] });
  const origPin = reordered.attestation.evidence!.pin!;
  reordered.attestation.evidence!.pin = { corroboration: [...origPin.corroboration], age_seconds: origPin.age_seconds, domain: origPin.domain };
  check("reordered mirror keys still verify", verifyAttestation(reordered, basePayment, pub)?.pin?.age_seconds === 60);
}

console.log("\n— 402 without payment-capable fetch —");
{
  const client = new TollWardenClient({ baseUrl: BASE });
  let threw: unknown = null;
  try {
    await client.scanOutgoing({ ...basePayment, pay_to: "0x402trigger" });
  } catch (e) {
    threw = e;
  }
  check("402 surfaces as TollWardenError with guidance", threw instanceof TollWardenError && (threw as TollWardenError).status === 402);
  check("guidance mentions payment-capable fetch", String((threw as Error).message).includes("payment-capable fetch"));
}

console.log("\n— plans + auto-renew —");
{
  const client = new TollWardenClient({ baseUrl: BASE, autoRenew: true });
  const plans = await client.getPlans();
  check("plan catalog fetched", plans.plans[0].id === "pro");
  const sub = await client.subscribe("pro");
  check("subscribe records plan state", client.plan?.id === "pro" && sub.plan === "pro");
  const before = seen.subscribes;
  client.plan = { id: "pro", expires_at: new Date(Date.now() + 60_000).toISOString() }; // expiring soon
  await client.scanOutgoing(basePayment);
  check("auto-renew fires when plan is near expiry", seen.subscribes === before + 1, seen.subscribes - before);
  const after = seen.subscribes;
  await client.scanOutgoing(basePayment); // renewed plan now 30d out
  check("no renewal when plan is far from expiry", seen.subscribes === after);
}
{
  const client = new TollWardenClient({ baseUrl: BASE }); // autoRenew off
  client.plan = { id: "pro", expires_at: new Date(Date.now() + 60_000).toISOString() };
  const before = seen.subscribes;
  await client.scanOutgoing(basePayment);
  check("autoRenew=false never re-subscribes", seen.subscribes === before);
}

console.log("\n— reporting —");
{
  const client = new TollWardenClient({ baseUrl: BASE, agentId: "sdk-test" });
  const r = (await client.report({ address: "0xbad", category: "scam", reason: "took the money and ran" })) as { accepted: boolean };
  check("report files successfully", r.accepted === true);
}

console.log("\n— wallet-side enforcement kit —");
const PINNED = (signer.publicKeyInfo() as { public_key_spki_hex: string }).public_key_spki_hex;

/** EIP-3009 typed data matching a PaymentDetails (what an x402 client asks the wallet to sign). */
function typedDataFor(p: PaymentDetails): TypedDataLike {
  return {
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: p.asset },
    primaryType: "TransferWithAuthorization",
    types: {
      TransferWithAuthorization: [
        { name: "from", type: "address" }, { name: "to", type: "address" },
        { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" },
        { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
      ],
    },
    message: { from: p.payer ?? "0xPayerAgent000000000000000000000000000001", to: p.pay_to, value: p.amount, validAfter: 0, validBefore: 9999999999, nonce: p.nonce },
  };
}

function fakeSigner(): { address: string; signed: TypedDataLike[]; signTypedData: (...a: unknown[]) => Promise<string>; signMessage: () => Promise<string> } {
  const signed: TypedDataLike[] = [];
  return {
    address: "0xWalletAddress",
    signed,
    async signTypedData(...args: unknown[]) { signed.push(args[0] as TypedDataLike); return "0xsigned"; },
    async signMessage() { return "0xmsg"; },
  };
}

{
  // typed-data → payment mapping produces the SAME commitment the server attests.
  const p = { ...basePayment, nonce: "0xenf1" };
  const mapped = paymentFromTypedData(typedDataFor(p))!;
  check("typed-data mapping matches the scanned payment's commitment", computePaymentCommitment(mapped) === paymentCommitment(p));
}
{
  // Happy path: scan → approve → wrapped signer signs.
  const p = { ...basePayment, nonce: "0xenf2" };
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  const wallet = fakeSigner();
  const guarded = enforcer.guardSigner(wallet);
  enforcer.approve(makeScan(p), p);
  const sig = await guarded.signTypedData(typedDataFor(p));
  check("approved payment signs", sig === "0xsigned" && wallet.signed.length === 1);
  check("other signer properties pass through", guarded.address === "0xWalletAddress" && (await guarded.signMessage()) === "0xmsg");

  // Single-use: the same approval cannot sign twice.
  let threw: unknown = null;
  try { await guarded.signTypedData(typedDataFor(p)); } catch (e) { threw = e; }
  check("approval is single-use by default", threw instanceof TollWardenEnforcementError && String((threw as Error).message).includes("already used"));
}
{
  // No approval → refuse. The unscanned payment never reaches the real signer.
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  const wallet = fakeSigner();
  const guarded = enforcer.guardSigner(wallet);
  let threw: unknown = null;
  try { await guarded.signTypedData(typedDataFor({ ...basePayment, nonce: "0xenf3" })); } catch (e) { threw = e; }
  check("unapproved payment refused", threw instanceof TollWardenEnforcementError && wallet.signed.length === 0);
}
{
  // The core attack: scan payment A, try to sign payment B (drain redirect).
  const a = { ...basePayment, nonce: "0xenf4" };
  const b = { ...a, pay_to: "0xAttackerDrainAddress0000000000000000001", amount: "999999999" };
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  const wallet = fakeSigner();
  const guarded = enforcer.guardSigner(wallet);
  enforcer.approve(makeScan(a), a);
  let threw: unknown = null;
  try { await guarded.signTypedData(typedDataFor(b)); } catch (e) { threw = e; }
  check("scan-A-sign-B (redirected recipient/amount) refused", threw instanceof TollWardenEnforcementError && wallet.signed.length === 0);
}
{
  // Verdict gates: block never approves; flag only with allowFlagged.
  const blocked = { ...basePayment, pay_to: "0xBADactor00000000000000000000000000000001", nonce: "0xenf5" };
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  let threw: unknown = null;
  try { enforcer.approve(makeScan(blocked), blocked); } catch (e) { threw = e; }
  check("block verdict refuses approval", threw instanceof TollWardenEnforcementError);

  const iffy = { ...basePayment, pay_to: "0xIFFYmerchant0000000000000000000000000001", nonce: "0xenf6" };
  let flagThrew: unknown = null;
  try { enforcer.approve(makeScan(iffy), iffy); } catch (e) { flagThrew = e; }
  check("flag verdict refuses approval by default", flagThrew instanceof TollWardenEnforcementError);
  const lenient = new TollWardenEnforcer({ trustedKeyHex: PINNED, allowFlagged: true });
  check("allowFlagged accepts a flag verdict", typeof lenient.approve(makeScan(iffy), iffy) === "string");
}
{
  // Crypto gates: rogue-signed and replayed attestations never approve.
  const p = { ...basePayment, nonce: "0xenf7" };
  const roguePinned = new TollWardenEnforcer({
    trustedKeyHex: (rogueSigner.publicKeyInfo() as { public_key_spki_hex: string }).public_key_spki_hex,
  });
  let threw: unknown = null;
  try { roguePinned.approve(makeScan(p), p); } catch (e) { threw = e; }
  check("attestation signed by the wrong key refuses approval", threw instanceof AttestationError);

  const replayP = { ...basePayment, pay_to: "0xREPLAYmerchant00000000000000000000000001", nonce: "0xenf8" };
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  let replayThrew: unknown = null;
  try { enforcer.approve(makeScan(replayP), replayP); } catch (e) { replayThrew = e; }
  check("attestation for a different payment refuses approval", replayThrew instanceof AttestationError);
}
{
  // Freshness: maxAgeMs bounds how long an approval can wait before signing.
  const p = { ...basePayment, nonce: "0xenf9" };
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED, maxAgeMs: 1 });
  const guarded = enforcer.guardSigner(fakeSigner());
  enforcer.approve(makeScan(p), p);
  await new Promise((r) => setTimeout(r, 25));
  let threw: unknown = null;
  try { await guarded.signTypedData(typedDataFor(p)); } catch (e) { threw = e; }
  check("stale approval (maxAgeMs) refused", threw instanceof TollWardenEnforcementError && String((threw as Error).message).includes("stale"));
}
{
  // Reusable mode + revoke.
  const p = { ...basePayment, nonce: "0xenf10" };
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED, reusable: true });
  const guarded = enforcer.guardSigner(fakeSigner());
  const commitment = enforcer.approve(makeScan(p), p);
  await guarded.signTypedData(typedDataFor(p));
  await guarded.signTypedData(typedDataFor(p));
  check("reusable approval signs repeatedly", true);
  enforcer.revoke(commitment);
  let threw: unknown = null;
  try { await guarded.signTypedData(typedDataFor(p)); } catch (e) { threw = e; }
  check("revoked approval refused", threw instanceof TollWardenEnforcementError);
}
{
  // Non-payment typed data: pass-through by default, refused under strictTypes.
  const mail: TypedDataLike = {
    domain: { name: "App", chainId: 8453 },
    primaryType: "Mail",
    types: { Mail: [{ name: "contents", type: "string" }] },
    message: { contents: "hi" },
  };
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  const wallet = fakeSigner();
  check("non-payment typed data passes through", (await enforcer.guardSigner(wallet).signTypedData(mail)) === "0xsigned");
  const strict = new TollWardenEnforcer({ trustedKeyHex: PINNED, strictTypes: true });
  let threw: unknown = null;
  try { await strict.guardSigner(fakeSigner()).signTypedData(mail); } catch (e) { threw = e; }
  check("strictTypes refuses unrecognized typed data", threw instanceof TollWardenEnforcementError);
}
{
  // ethers v6 shape: signTypedData(domain, types, message) with no primaryType.
  const p = { ...basePayment, nonce: "0xenf11" };
  const td = typedDataFor(p);
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  const wallet = fakeSigner();
  const guarded = enforcer.guardSigner(wallet);
  let threw: unknown = null;
  try { await guarded.signTypedData(td.domain, td.types, td.message); } catch (e) { threw = e; }
  check("ethers-shape call is recognized and gated", threw instanceof TollWardenEnforcementError && wallet.signed.length === 0);
  enforcer.approve(makeScan(p), p);
  check("ethers-shape call signs once approved", (await guarded.signTypedData(td.domain, td.types, td.message)) === "0xsigned");
}
{
  // ERC-2612 Permit is treated as a payment authorization.
  const spender = "0xSpenderContract000000000000000000000001";
  const permit: TypedDataLike = {
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: basePayment.asset },
    primaryType: "Permit",
    types: { Permit: [{ name: "owner", type: "address" }, { name: "spender", type: "address" }, { name: "value", type: "uint256" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] },
    message: { owner: "0xOwner", spender, value: "5000", nonce: 7, deadline: 9999999999 },
  };
  const asPayment = paymentFromTypedData(permit)!;
  check("Permit maps spender/value/nonce to payment fields", asPayment.pay_to === spender && asPayment.amount === "5000" && asPayment.nonce === "7");
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  const wallet = fakeSigner();
  let threw: unknown = null;
  try { await enforcer.guardSigner(wallet).signTypedData(permit); } catch (e) { threw = e; }
  check("unapproved Permit refused", threw instanceof TollWardenEnforcementError);
  enforcer.approve(makeScan(asPayment), asPayment);
  check("approved Permit signs", (await enforcer.guardSigner(wallet).signTypedData(permit)) === "0xsigned");
}
{
  // Pinning is mandatory.
  let threw: unknown = null;
  try { new TollWardenEnforcer({ trustedKeyHex: "" }); } catch (e) { threw = e; }
  check("enforcer refuses to construct without a pinned key", threw instanceof TollWardenEnforcementError);
}

console.log("\n— local policy (recipient allowlist + spend caps) —");
{
  // Allowlist: an APPROVED payment to an unlisted recipient is still refused —
  // the policy gate is independent of the verdict layer.
  const p = { ...basePayment, nonce: "0xpol1" };
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED, allowedRecipients: ["0xSomeoneElse0000000000000000000000000001"] });
  const wallet = fakeSigner();
  const guarded = enforcer.guardSigner(wallet);
  enforcer.approve(makeScan(p), p);
  let threw: unknown = null;
  try { await guarded.signTypedData(typedDataFor(p)); } catch (e) { threw = e; }
  check("approved payment to unlisted recipient refused", threw instanceof TollWardenEnforcementError && String((threw as Error).message).includes("allowlist") && wallet.signed.length === 0);
}
{
  // Allowlist match is case-insensitive; listed recipient signs normally.
  const p = { ...basePayment, nonce: "0xpol2" };
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED, allowedRecipients: [basePayment.pay_to!.toUpperCase()] });
  const guarded = enforcer.guardSigner(fakeSigner());
  enforcer.approve(makeScan(p), p);
  check("listed recipient signs (case-insensitive)", (await guarded.signTypedData(typedDataFor(p))) === "0xsigned");

  // An EMPTY allowlist is deny-all, not unrestricted.
  const denyAll = new TollWardenEnforcer({ trustedKeyHex: PINNED, allowedRecipients: [] });
  const p2 = { ...basePayment, nonce: "0xpol3" };
  denyAll.approve(makeScan(p2), p2);
  let threw: unknown = null;
  try { await denyAll.guardSigner(fakeSigner()).signTypedData(typedDataFor(p2)); } catch (e) { threw = e; }
  check("empty allowlist refuses all recipients", threw instanceof TollWardenEnforcementError);
}
{
  // Per-payment cap in atomic units, checked against the typed data's value.
  const p = { ...basePayment, nonce: "0xpol4" }; // amount 10000
  const capped = new TollWardenEnforcer({ trustedKeyHex: PINNED, maxAmountAtomic: 5000 });
  capped.approve(makeScan(p), p);
  let threw: unknown = null;
  try { await capped.guardSigner(fakeSigner()).signTypedData(typedDataFor(p)); } catch (e) { threw = e; }
  check("value above per-payment cap refused", threw instanceof TollWardenEnforcementError && String((threw as Error).message).includes("per-payment cap"));

  const roomy = new TollWardenEnforcer({ trustedKeyHex: PINNED, maxAmountAtomic: "10000" });
  const p2 = { ...basePayment, nonce: "0xpol5" };
  roomy.approve(makeScan(p2), p2);
  check("value at the per-payment cap signs", (await roomy.guardSigner(fakeSigner()).signTypedData(typedDataFor(p2))) === "0xsigned");
}
{
  // Cumulative cap: the running total of authorized value is bounded.
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED, maxTotalAtomic: 25000 });
  const guarded = enforcer.guardSigner(fakeSigner());
  for (const nonce of ["0xpol6", "0xpol7"]) {
    const p = { ...basePayment, nonce };
    enforcer.approve(makeScan(p), p);
    await guarded.signTypedData(typedDataFor(p)); // 10000 each
  }
  check("authorized total tracks signed value", enforcer.totalAuthorizedAtomic() === 20000n);
  const p3 = { ...basePayment, nonce: "0xpol8" };
  enforcer.approve(makeScan(p3), p3);
  let threw: unknown = null;
  try { await guarded.signTypedData(typedDataFor(p3)); } catch (e) { threw = e; }
  check("payment past the cumulative cap refused", threw instanceof TollWardenEnforcementError && String((threw as Error).message).includes("cumulative cap"));
  check("refused payment does not count toward the total", enforcer.totalAuthorizedAtomic() === 20000n);
}
{
  // Fail-closed: with caps configured, a non-integer value must not slip past.
  const p = { ...basePayment, amount: "0x2710", nonce: "0xpol9" };
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED, maxAmountAtomic: 1_000_000 });
  enforcer.approve(makeScan(p), p);
  let threw: unknown = null;
  try { await enforcer.guardSigner(fakeSigner()).signTypedData(typedDataFor(p)); } catch (e) { threw = e; }
  check("unparseable value under a spend cap is refused (fail-closed)", threw instanceof TollWardenEnforcementError && String((threw as Error).message).includes("not a plain integer"));

  // Malformed cap options are a construction-time error, not a silent no-op.
  let badCap: unknown = null;
  try { new TollWardenEnforcer({ trustedKeyHex: PINNED, maxAmountAtomic: "five dollars" }); } catch (e) { badCap = e; }
  check("non-integer cap option throws at construction", badCap instanceof TollWardenEnforcementError);
}
{
  // Override admission: a human-approved override:allow can admit ONE
  // commitment-bound payment past the allowlist — opt-in, and only on top of
  // acceptOverrides.
  const makeOverrideScan = (p: PaymentDetails): ScanResponse => {
    const scan = makeScan(p);
    scan.verdict = "override:allow";
    scan.attestation = signer.attest(scan, paymentCommitment(p));
    return scan;
  };

  // Dead-setting guard: the option without acceptOverrides is a construction error.
  let dead: unknown = null;
  try { new TollWardenEnforcer({ trustedKeyHex: PINNED, allowedRecipients: [], overrideAdmitsRecipient: true }); } catch (e) { dead = e; }
  check("overrideAdmitsRecipient without acceptOverrides throws at construction", dead instanceof TollWardenEnforcementError);

  // Default hard bound: even with acceptOverrides, an approved override to an
  // unlisted recipient is refused unless overrideAdmitsRecipient is on.
  const p1 = { ...basePayment, nonce: "0xova1" };
  const hard = new TollWardenEnforcer({ trustedKeyHex: PINNED, acceptOverrides: true, allowedRecipients: ["0xSomeoneElse0000000000000000000000000001"] });
  hard.approve(makeOverrideScan(p1), p1);
  let threw: unknown = null;
  try { await hard.guardSigner(fakeSigner()).signTypedData(typedDataFor(p1)); } catch (e) { threw = e; }
  check("override does NOT cross the allowlist by default", threw instanceof TollWardenEnforcementError && String((threw as Error).message).includes("allowlist"));

  // Opt-in: the override admits exactly the payment it binds.
  const p2 = { ...basePayment, nonce: "0xova2" };
  const lenient = new TollWardenEnforcer({ trustedKeyHex: PINNED, acceptOverrides: true, overrideAdmitsRecipient: true, allowedRecipients: ["0xSomeoneElse0000000000000000000000000001"] });
  lenient.approve(makeOverrideScan(p2), p2);
  const wallet = fakeSigner();
  check("human-approved override admits its one payment past the allowlist", (await lenient.guardSigner(wallet).signTypedData(typedDataFor(p2))) === "0xsigned");

  // The admission is per-payment, not per-recipient: the next payment to the
  // SAME recipient with a plain allow-verdict is refused again.
  const p3 = { ...basePayment, nonce: "0xova3" };
  lenient.approve(makeScan(p3), p3); // plain allow
  let again: unknown = null;
  try { await lenient.guardSigner(wallet).signTypedData(typedDataFor(p3)); } catch (e) { again = e; }
  check("admission does not stick to the recipient (plain allow refused after)", again instanceof TollWardenEnforcementError && String((again as Error).message).includes("allowlist"));

  // Spend caps still bound override-admitted payments.
  const p4 = { ...basePayment, nonce: "0xova4" }; // amount 10000
  const cappedOv = new TollWardenEnforcer({ trustedKeyHex: PINNED, acceptOverrides: true, overrideAdmitsRecipient: true, allowedRecipients: [], maxAmountAtomic: 5000 });
  cappedOv.approve(makeOverrideScan(p4), p4);
  let capped: unknown = null;
  try { await cappedOv.guardSigner(fakeSigner()).signTypedData(typedDataFor(p4)); } catch (e) { capped = e; }
  check("override admission never bypasses spend caps", capped instanceof TollWardenEnforcementError && String((capped as Error).message).includes("per-payment cap"));
}

console.log("\n— pre-sign approvals: the offer has no nonce, the authorization does —");
{
  // The default path scans the 402 OFFER; the x402 client mints the EIP-3009
  // nonce only when it signs. The enforcer must match the two (audit
  // 2026-09-19: they did not, so the shipped wrapper could never satisfy
  // guardSigner).
  const offer: PaymentDetails = { ...basePayment, nonce: undefined };
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  const wallet = fakeSigner();
  const guarded = enforcer.guardSigner(wallet);
  enforcer.approve(makeScan(offer), offer);
  const sig = await guarded.signTypedData(typedDataFor({ ...offer, nonce: "0xpre1" }));
  check("a nonce-less (pre-sign) approval admits the authorization once the nonce exists", sig === "0xsigned" && wallet.signed.length === 1);
  let threw: unknown = null;
  try { await guarded.signTypedData(typedDataFor({ ...offer, nonce: "0xpre2" })); } catch (e) { threw = e; }
  check("…and exactly once: a second nonce on the same facts is refused (single-use)", threw instanceof TollWardenEnforcementError && String((threw as Error).message).includes("already used") && wallet.signed.length === 1);

  // The pre-sign approval binds the FACTS: any other amount/recipient/asset is refused.
  const e2 = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  e2.approve(makeScan(offer), offer);
  const w2 = fakeSigner();
  threw = null;
  try { await e2.guardSigner(w2).signTypedData(typedDataFor({ ...offer, amount: "20000", nonce: "0xpre3" })); } catch (e) { threw = e; }
  check("a pre-sign approval does not admit a different amount", threw instanceof TollWardenEnforcementError && w2.signed.length === 0);
  threw = null;
  try { await e2.guardSigner(w2).signTypedData(typedDataFor({ ...offer, pay_to: "0xSomeoneElse0000000000000000000000000001", nonce: "0xpre4" })); } catch (e) { threw = e; }
  check("a pre-sign approval does not admit a different recipient", threw instanceof TollWardenEnforcementError && w2.signed.length === 0);

  // An approval registered WITH a nonce still binds that exact nonce.
  const e3 = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  const withNonce = { ...offer, nonce: "0xpre5" };
  e3.approve(makeScan(withNonce), withNonce);
  const w3 = fakeSigner();
  threw = null;
  try { await e3.guardSigner(w3).signTypedData(typedDataFor({ ...offer, nonce: "0xpre6" })); } catch (e) { threw = e; }
  check("a post-sign approval still requires its exact nonce", threw instanceof TollWardenEnforcementError && w3.signed.length === 0);
  check("…and signs when the nonce matches", (await e3.guardSigner(w3).signTypedData(typedDataFor(withNonce))) === "0xsigned");

  // assertApprovedFor reports which commitment it consumed.
  const e4 = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  const c = e4.approve(makeScan(offer), offer);
  check("assertApprovedFor resolves a nonce-bearing payment to its pre-sign commitment", e4.assertApprovedFor({ ...offer, nonce: "0xpre7" }) === c);
}

console.log("\n— wrapFetchWithTollWarden (default payment path) —");

// A mock x402 merchant: 402 with an offer unless X-PAYMENT is present.
const merchant = createServer((req: IncomingMessage, res: ServerResponse) => {
  const u = new URL(req.url ?? "/", "http://localhost");
  if (u.pathname === "/free") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ data: "free" }));
  }
  if (req.headers["x-payment"]) {
    if (u.pathname === "/paid-broken") {
      res.writeHead(500, { "content-type": "application/json" });
      return res.end(JSON.stringify({ error: "server exploded after taking your money" }));
    }
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ data: "premium" }));
  }
  if (u.pathname === "/broken402") {
    res.writeHead(402, { "content-type": "application/json" });
    return res.end(JSON.stringify({ error: "payment required" })); // no accepts[]
  }
  res.writeHead(402, { "content-type": "application/json" });
  res.end(
    JSON.stringify({
      x402Version: 2,
      accepts: [{
        scheme: "exact",
        network: "eip155:8453",
        maxAmountRequired: "10000",
        payTo: u.searchParams.get("payto") ?? "0xNiceMerchant00000000000000000000000000001",
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        resource: `http://localhost${u.pathname}`,
        description: "Premium data",
        extra: { decimals: 6 },
      }],
    }),
  );
});
await new Promise<void>((r) => merchant.listen(0, () => r()));
const MERCHANT = `http://127.0.0.1:${(merchant.address() as { port: number }).port}`;

let payments = 0;
const payingFetch: typeof fetch = async (input, init) => {
  payments++;
  return fetch(input, { ...init, headers: { ...(init?.headers as Record<string, string>), "x-payment": "mock-settled" } });
};

/** A paying fetch that does what a real x402 client does: read the 402,
 * mint a fresh nonce, ask the (possibly guarded) signer for the EIP-3009
 * signature, then retry with the payment header. */
function signingPayingFetch(signer: TypedDataSigner): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const probe = await fetch(input, init);
    if (probe.status !== 402) return probe;
    const body = (await probe.json()) as { accepts: Array<Record<string, string>> };
    const e = body.accepts[0]!;
    await signer.signTypedData(typedDataFor({ network: e.network, asset: e.asset, pay_to: e.payTo, amount: e.maxAmountRequired, nonce: `0xmint${Date.now().toString(16)}${Math.random().toString(16).slice(2, 8)}` }));
    payments++;
    return fetch(input, { ...init, headers: { ...(init?.headers as Record<string, string>), "x-payment": "mock-settled" } });
  }) as typeof fetch;
}

{
  // Composition: wrapper + enforcer + guarded signer. The wrapper registers
  // the offer's verdict; the client signs a nonce-bearing authorization; the
  // enforcer matches them. This is the enforced default path.
  const tollwarden = new TollWardenClient({ baseUrl: BASE, agentId: "wrap-enforced" });
  const enforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  const wallet = fakeSigner();
  const guardedFetch = wrapFetchWithTollWarden(signingPayingFetch(enforcer.guardSigner(wallet)), tollwarden, { enforcer });
  payments = 0;
  const res = await guardedFetch(`${MERCHANT}/paid`);
  check("wrapper + enforcer: the guarded signer signs the scanned offer's authorization", res.status === 200 && payments === 1 && wallet.signed.length === 1, { status: res.status, payments, signed: wallet.signed.length });
  const signedNonce = (wallet.signed[0]?.message as { nonce?: string })?.nonce ?? "";
  check("the signed authorization carried a nonce the offer never had", signedNonce.startsWith("0xmint"));

  // Without the enforcer option the wrapper is advisory only: the guarded
  // signer has no approval and refuses — nothing is paid.
  const advisoryOnly = wrapFetchWithTollWarden(signingPayingFetch(enforcer.guardSigner(fakeSigner())), tollwarden);
  payments = 0;
  let threw: unknown = null;
  try { await advisoryOnly(`${MERCHANT}/paid?payto=0xOtherMerchant0000000000000000000000000001`); } catch (e) { threw = e; }
  check("without `enforcer`, a guarded signer refuses the unapproved authorization and nothing is paid", threw instanceof TollWardenEnforcementError && payments === 0);

  // A block never reaches the enforcer: no approval is left behind.
  const w2 = fakeSigner();
  const blockedFetch = wrapFetchWithTollWarden(signingPayingFetch(enforcer.guardSigner(w2)), new TollWardenClient({ baseUrl: BASE }), { enforcer });
  payments = 0;
  threw = null;
  try { await blockedFetch(`${MERCHANT}/paid?payto=0xBADdrain`); } catch (e) { threw = e; }
  check("a blocked offer registers no approval and nothing is signed", threw instanceof TollWardenBlockedError && payments === 0 && w2.signed.length === 0);
  let stale: unknown = null;
  try { await enforcer.guardSigner(w2).signTypedData(typedDataFor({ ...basePayment, pay_to: "0xBADdrain", nonce: "0xafterblock" })); } catch (e) { stale = e; }
  check("…and the enforcer still refuses that recipient afterwards", stale instanceof TollWardenEnforcementError && w2.signed.length === 0);

  // A flag verdict with a strict enforcer: approve() refuses BEFORE any payment.
  const strictEnforcer = new TollWardenEnforcer({ trustedKeyHex: PINNED });
  const w3 = fakeSigner();
  const flaggedFetch = wrapFetchWithTollWarden(signingPayingFetch(strictEnforcer.guardSigner(w3)), new TollWardenClient({ baseUrl: BASE }), { enforcer: strictEnforcer });
  payments = 0;
  threw = null;
  try { await flaggedFetch(`${MERCHANT}/paid?payto=0xIFFYshop`); } catch (e) { threw = e; }
  check("a flagged offer with an allow-only enforcer throws before the paying fetch runs", threw instanceof TollWardenEnforcementError && payments === 0 && w3.signed.length === 0);
}

{
  // Allow path: probe → scan × 2 → pay → premium content.
  const tollwarden = new TollWardenClient({ baseUrl: BASE, agentId: "wrap-test" });
  const guardedFetch = wrapFetchWithTollWarden(payingFetch, tollwarden);
  const scansBefore = seen.scans.length;
  payments = 0;
  const res = await guardedFetch(`${MERCHANT}/paid`);
  const data = (await res.json()) as { data: string };
  check("allowed payment goes through and returns the paid content", res.status === 200 && data.data === "premium");
  check("exactly one payment was made", payments === 1, payments);
  check("both scans ran (outgoing + offer)", seen.scans.length === scansBefore + 2, seen.scans.length - scansBefore);
  const outgoingScan = seen.scans[scansBefore]!.body;
  check("offer fields mapped into the scan", outgoingScan.payment.pay_to?.startsWith("0xNiceMerchant") && outgoingScan.payment.amount === "10000" && outgoingScan.payment.asset_decimals === 6, outgoingScan.payment);
}
{
  // Block path: the paying fetch is NEVER invoked.
  const tollwarden = new TollWardenClient({ baseUrl: BASE });
  const guardedFetch = wrapFetchWithTollWarden(payingFetch, tollwarden);
  payments = 0;
  let threw: unknown = null;
  try { await guardedFetch(`${MERCHANT}/paid?payto=0xBADdrain`); } catch (e) { threw = e; }
  check("blocked payment throws TollWardenBlockedError", threw instanceof TollWardenBlockedError);
  check("no payment is ever made on block", payments === 0, payments);
}
{
  // Non-402 responses pass through with zero scans.
  const tollwarden = new TollWardenClient({ baseUrl: BASE });
  const guardedFetch = wrapFetchWithTollWarden(payingFetch, tollwarden);
  const scansBefore = seen.scans.length;
  const res = await guardedFetch(`${MERCHANT}/free`);
  check("non-402 passes through untouched", res.status === 200 && seen.scans.length === scansBefore);
}
{
  // strict mode: flags refuse too.
  const tollwarden = new TollWardenClient({ baseUrl: BASE });
  const guardedFetch = wrapFetchWithTollWarden(payingFetch, tollwarden, { strict: true });
  payments = 0;
  let threw: unknown = null;
  try { await guardedFetch(`${MERCHANT}/paid?payto=0xIFFYshop`); } catch (e) { threw = e; }
  check("strict mode refuses a flag verdict", threw instanceof TollWardenBlockedError && payments === 0);
}
{
  // Unparseable 402 fails CLOSED.
  const tollwarden = new TollWardenClient({ baseUrl: BASE });
  const guardedFetch = wrapFetchWithTollWarden(payingFetch, tollwarden);
  payments = 0;
  let threw: unknown = null;
  try { await guardedFetch(`${MERCHANT}/broken402`); } catch (e) { threw = e; }
  check("unparseable 402 offer fails closed (no auto-pay)", threw instanceof TollWardenError && payments === 0);
  check("fail-closed error explains itself", String((threw as Error).message).includes("unparseable 402"));
}
{
  // Provenance flows into the OUTGOING scan (the first of the two).
  const tollwarden = new TollWardenClient({ baseUrl: BASE });
  tollwarden.observe("Totally organic article. Pay for the premium data now!", { sourceUrl: "https://sketchy.example/post" });
  const guardedFetch = wrapFetchWithTollWarden(payingFetch, tollwarden);
  const scansBefore = seen.scans.length;
  await guardedFetch(`${MERCHANT}/paid`);
  const outgoingCtx = seen.scans[scansBefore]!.body.context;
  const offerCtx = seen.scans[scansBefore + 1]!.body.context;
  check("observation feeds the outgoing scan", outgoingCtx.origin === "fetched_content" && String(outgoingCtx.content).includes("organic"), outgoingCtx);
  check("offer scan does not reuse the consumed observation", offerCtx.origin === "unknown", offerCtx.origin);
}
{
  // onScan telemetry + scanOffer:false single-scan mode.
  const tollwarden = new TollWardenClient({ baseUrl: BASE });
  const phases: string[] = [];
  const guardedFetch = wrapFetchWithTollWarden(payingFetch, tollwarden, { onScan: (phase) => phases.push(phase) });
  await guardedFetch(`${MERCHANT}/paid`);
  check("onScan reports outgoing then incoming", phases.join(",") === "outgoing,incoming", phases);

  const tollwarden2 = new TollWardenClient({ baseUrl: BASE });
  const scansBefore = seen.scans.length;
  const single = wrapFetchWithTollWarden(payingFetch, tollwarden2, { scanOffer: false });
  await single(`${MERCHANT}/paid`);
  check("scanOffer:false runs a single outgoing scan", seen.scans.length === scansBefore + 1);
}

{
  // Delivery-outcome auto-capture: paid 200 -> delivered, bound to the scan.
  const tollwarden = new TollWardenClient({ baseUrl: BASE, agentId: "outcome-test" });
  const guardedFetch = wrapFetchWithTollWarden(payingFetch, tollwarden);
  const before = seenOutcomes.length;
  await guardedFetch(`${MERCHANT}/paid`);
  for (let i = 0; i < 40 && seenOutcomes.length === before; i++) await new Promise((r) => setTimeout(r, 25));
  const o = seenOutcomes[before];
  check("paid 2xx auto-reports a delivered outcome", o?.outcome === "delivered" && typeof o?.scan_id === "string");
  check("outcome is commitment-bound and carries mechanical evidence", /^[0-9a-f]{64}$/.test(o?.payment_commitment ?? "") && o?.evidence?.status === 200);

  // Paid 5xx -> not_delivered (searched by evidence, immune to stragglers
  // from earlier wrap tests whose auto-reports land asynchronously).
  await guardedFetch(`${MERCHANT}/paid-broken`);
  for (let i = 0; i < 40 && !seenOutcomes.some((x) => x?.evidence?.status === 500); i++) await new Promise((r) => setTimeout(r, 25));
  const broken = seenOutcomes.find((x) => x?.evidence?.status === 500);
  check("paid 5xx auto-reports not_delivered with the status", broken?.outcome === "not_delivered");

  // Opt-out: drain stragglers until quiet, then assert no growth.
  let quietLen = seenOutcomes.length;
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 100));
    if (seenOutcomes.length === quietLen) break;
    quietLen = seenOutcomes.length;
  }
  const silent = wrapFetchWithTollWarden(payingFetch, new TollWardenClient({ baseUrl: BASE }), { reportOutcomes: false });
  const before3 = seenOutcomes.length;
  await silent(`${MERCHANT}/paid`);
  await new Promise((r) => setTimeout(r, 400));
  check("reportOutcomes:false disables auto-capture", seenOutcomes.length === before3);

  // Manual reportOutcome for non-wrapper settlement paths.
  const scan = await tollwarden.scanOutgoing({ ...basePayment, nonce: "0xoutman1" });
  await tollwarden.reportOutcome(scan, "wrong_content", { status: 200, bytes: 12 });
  const manual = seenOutcomes[seenOutcomes.length - 1];
  check("manual reportOutcome posts the bound outcome", manual?.outcome === "wrong_content" && manual?.scan_id === scan.scan_id && manual?.payment_commitment === scan.attestation?.payment_commitment);
}

merchant.close();

console.log("\n— human-in-the-loop approvals —");
{
  const client = new TollWardenClient({ baseUrl: BASE, agentId: "hitl-agent" });

  // Config helper surfaces the one-time secret.
  const conf = await client.configureApprovals("https://hooks.example.com/tollwarden");
  check("configureApprovals returns the signing secret once", conf.enabled === true && conf.webhook_secret === "psw_mocksecret");

  // Flag scan carries the pending approval; waitForApproval polls to the override.
  const iffy: PaymentDetails = { ...basePayment, pay_to: "0xIffyMerchant0000000000000000000000000001", nonce: "0xhitl1" };
  const scan = await client.scanOutgoing(iffy, { context: { origin: "planning" } });
  check("flag scan exposes the pending approval", scan.verdict === "flag" && scan.approval?.status === "pending");
  const override = await client.waitForApproval(scan, { payment: iffy, intervalMs: 300 });
  check("waitForApproval returns the override verdict", override.verdict === "override:allow");
  check("override attestation verified against the pinned key + payment", override.attestation_verified === true);

  // waitForApproval with no approval attached fails fast.
  const clean = await client.scanOutgoing({ ...basePayment, nonce: "0xhitl2" }, { context: { origin: "planning" } });
  const noApproval = await client.waitForApproval(clean, { payment: basePayment }).then(() => null, (e) => e);
  check("waitForApproval without an approval throws immediately", noApproval instanceof TollWardenError && String(noApproval.message).includes("no approval"));

  // Denied and stalled paths.
  const denyScan = await client.scanOutgoing({ ...iffy, pay_to: "0xIffyDenyMerchant000000000000000000000001", nonce: "0xhitl3" }, { context: { origin: "planning" } });
  const denied = await client.waitForApproval(denyScan, { intervalMs: 100 }).then(() => null, (e) => e);
  check("operator denial throws with the denial state", denied instanceof TollWardenError && denied.status === 403);
  const stallScan = await client.scanOutgoing({ ...iffy, pay_to: "0xIffyStallMerchant00000000000000000000001", nonce: "0xhitl4" }, { context: { origin: "planning" } });
  const timedOut = await client.waitForApproval(stallScan, { timeoutMs: 400, intervalMs: 100 }).then(() => null, (e) => e);
  check("waitForApproval times out on an undecided approval", timedOut instanceof TollWardenError && timedOut.status === 408);

  // A FORGED override (signed by the wrong key) is rejected during the wait.
  const forgeScan = await client.scanOutgoing({ ...iffy, pay_to: "0xIffyForgeMerchant00000000000000000000001", nonce: "0xhitl5" }, { context: { origin: "planning" } });
  const forged = await client.waitForApproval(forgeScan, { payment: { ...iffy, pay_to: "0xIffyForgeMerchant00000000000000000000001", nonce: "0xhitl5" }, intervalMs: 100 }).then(() => null, (e) => e);
  check("forged override (wrong signing key) is rejected", forged instanceof AttestationError);

  // Enforcer: overrides are OPT-IN.
  const strictEnforcer = new TollWardenEnforcer({ trustedKeyHex: signer.publicKeySpkiHex });
  const refused = (() => { try { strictEnforcer.approve(override, iffy); return null; } catch (e) { return e; } })();
  check("enforcer refuses overrides by default (acceptOverrides opt-in)", refused instanceof TollWardenEnforcementError && String((refused as Error).message).includes("acceptOverrides"));

  const hitlEnforcer = new TollWardenEnforcer({ trustedKeyHex: signer.publicKeySpkiHex, acceptOverrides: true });
  const commitment = hitlEnforcer.approve(override, iffy);
  check("enforcer with acceptOverrides registers the override", commitment === computePaymentCommitment(iffy));
  let signed = false;
  hitlEnforcer.assertApproved(commitment);
  signed = true;
  check("override authorizes exactly one signature", signed);
  const reuse = (() => { try { hitlEnforcer.assertApproved(commitment); return null; } catch (e) { return e; } })();
  check("override approvals stay single-use", reuse instanceof TollWardenEnforcementError);

  // acceptOverrides must not loosen anything else: plain flags still refused.
  const flagScan = await client.scanOutgoing({ ...iffy, nonce: "0xhitl6" }, { context: { origin: "planning" } });
  const flagRefused = (() => { try { hitlEnforcer.approve(flagScan, { ...iffy, nonce: "0xhitl6" }); return null; } catch (e) { return e; } })();
  check("acceptOverrides does not accept plain flag verdicts", flagRefused instanceof TollWardenEnforcementError);
}

server.close();
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
