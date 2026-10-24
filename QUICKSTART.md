# Protect your x402 agent in 5 minutes

Agents that pay for things over [x402](https://x402.org) get drained in predictable ways: a poisoned webpage tells the agent to pay an attacker's address, a captured payment authorization gets replayed, a "$0.01" API quietly charges $0.15, a seller takes the money and never ships. [TollWarden](https://tollwarden.com) is a payment firewall that catches all of it — advisory, non-custodial, and wrapped around whatever wallet and facilitator you already use. Here's the whole integration, timed.

## Minute 1 — install

```bash
npm install @tollwarden/client    # TypeScript / Node
pip install tollwarden           # Python
```

No signup. The first call mints you a free API key automatically (100 free scans).

## Minute 2 — the one-line version

If your agent pays through the standard x402 buyer flow, wrap the paying fetch and you're done:

```ts
import { wrapFetchWithPayment } from "@x402/fetch";
import { TollWardenClient, wrapFetchWithTollWarden } from "@tollwarden/client";

const tollwarden = new TollWardenClient({ agentId: "my-agent" });
const fetchWithPay = wrapFetchWithTollWarden(wrapFetchWithPayment(fetch, x402Client), tollwarden);
```

Python:

```python
from tollwarden import TollWardenClient, wrap_transport_with_tollwarden

tollwarden = TollWardenClient(agent_id="my-agent")
guarded = wrap_transport_with_tollwarden(my_x402_transport, tollwarden)
```

Every payment now gets scanned **before it settles** — a block verdict throws before any payment is signed — and after settlement the wrapper automatically records whether the seller actually delivered, building the shared history that flags never-shipping sellers for everyone.

## Minute 3 — feed the injection detector

TollWarden's strongest check catches payments whose *decision* came from content your agent just read — the prompt-injected page that says "send payment to 0x… now". It needs to know what the agent read. One line, right after any web fetch or tool call:

```ts
tollwarden.observe(pageOrToolText, { sourceUrl });
```

```python
tollwarden.observe(page_or_tool_text, source_url=url)
```

That's it — the next scan is provenance-tagged and the injection check runs with real input. If the pay-to address appears in content the agent just read, the payment blocks.

## Minute 4 — see it work

```ts
const scan = await tollwarden.scanOutgoing({
  network: "eip155:8453",
  pay_to: "0xMerchant...",
  amount: "10000",          // $0.01 USDC
  nonce: "0xabc123",
  resource_url: "https://api.example.com/data",
});
```

A clean payment returns `verdict: "allow"` with an Ed25519-signed attestation. Here's a replayed authorization getting caught:

```json
{
  "verdict": "block",
  "risk_score": 95,
  "checks": [{
    "id": "replay.nonce_reuse",
    "verdict": "block",
    "severity": "critical",
    "reason": "Nonce reuse detected: this nonce was first seen 2026-07-14T09:32:50Z and has now appeared 2 times. A reused nonce means a stale or captured payment authorization is being replayed."
  }],
  "advisory": "Recommended action: DO NOT settle this payment. ..."
}
```

Machine-readable reasons, so your agent can act on them — not just a score.

## Retries, and the flag you may see

x402 clients sign a fresh authorization for every 402 they see. When a paid request times out and your code retries it, the retry is a second valid payment with a new nonce, and both can settle. TollWarden flags that second authorization as `replay.duplicate_purchase` when it matches your previous scan of the same purchase (payer, `pay_to`, asset, amount and `resource_url`) within 60 seconds. It flags and never blocks, because TollWarden sees scans, not settlements, and cannot know whether the first attempt settled.

When you see that flag, check whether the earlier payment settled before paying again. If you meant to buy the same thing twice (polling a paid feed, say), tell the scan which attempt you are repeating.

```python
first = tollwarden.scan_outgoing(payment)
# later, a deliberate second purchase of the same resource
again = tollwarden.scan_outgoing(next_payment, context={"origin": "planning", "repeat_of": first["scan_id"]})
```

`repeat_of` must name your latest scan of that purchase, and it clears that one repeat only, so the next repeat names the newest `scan_id`. Passing `context` replaces the automatic provenance tagging for that scan, so set `origin` yourself.

The other way to clear it is a delivery outcome. Once the earlier attempt is reported as delivered, a second purchase reads as a new decision rather than a retry. The minute 2 wrappers report outcomes automatically, so with them a repeat after a successful paid call does not flag, and a retry after a failed or timed-out call does, which is the case worth stopping for. If you settle some other way, report the outcome yourself, and only when the seller did deliver, since outcomes are final and feed that seller's history.

```ts
await tollwarden.reportOutcome(firstScan, "delivered");
```

The TypeScript client does not pass `context.repeat_of` through yet, so from TypeScript report the earlier outcome, or send `repeat_of` inside `context` on a direct `POST /v1/scan/outgoing`.

## Minute 5 — or skip all of the above if you're on a framework

Already building on an agent framework? One package gives your agent the tools *and* wires the provenance tagging automatically:

**LangChain / LangGraph** (`pip install langchain-tollwarden`):

```python
from langchain_tollwarden import tollwarden_tools, TollWardenProvenanceCallback

agent = create_agent(model, tools=[*tollwarden_tools(tollwarden), *your_tools],
                     callbacks=[TollWardenProvenanceCallback(tollwarden)])
```

**CrewAI** (`pip install crewai-tollwarden`):

```python
from crewai_tollwarden import tollwarden_tools, register_tollwarden_provenance

register_tollwarden_provenance(tollwarden)   # once at startup
agent = Agent(role="Purchasing agent", tools=tollwarden_tools(tollwarden), ...)
```

**Vercel AI SDK** (`npm install @tollwarden/ai-sdk`):

```ts
import { tollwardenTools, tollwardenProvenance } from "@tollwarden/ai-sdk";

await generateText({
  model,
  tools: { ...tollwardenTools(tollwarden), ...yourTools },
  onStepFinish: tollwardenProvenance(tollwarden),   // auto-tags every tool result
  prompt: "...",
});
```

**Coinbase AgentKit** (`pip install agentkit-tollwarden`): add `tollwarden_action_provider()` to your providers — scans auto-fill the payer from the agent's wallet. **NeMo Agent Toolkit** (`pip install nemo-tollwarden`): three config-driven functions via the `nat.plugins` entry point. **Claude / MCP agents**: zero code —

```jsonc
{ "mcpServers": { "tollwarden": { "command": "npx", "args": ["-y", "tollwarden"] } } }
```

## Leveling up (when you're ready)

- **Make blocks physically unsignable.** The enforcement kit wraps your signer so it refuses any x402 authorization without a fresh, payment-bound allow-verdict: `enforcer.guardSigner(account)` (viem/ethers) or `enforcer.guard_signer(account)` (eth-account). A compromised agent that skips scanning simply cannot sign.
- **Put a human between flag and block.** `POST /v1/approvals/config` with a webhook: every flag pauses, your ops channel gets the payment facts and a one-click decide link, and approval mints a ≤5-minute signed override bound to exactly that payment.
- **Key hygiene.** Leaked key? `POST /v1/keys/rotate` — fresh secret, same account, usage and plan carried over; the old secret dies on your schedule.
- **Check any counterparty first**: `GET /v1/reputation/{address}` returns community reports *and* measured delivery rates from commitment-bound outcomes.

Everything is documented for agents too: point any LLM at [tollwarden.com/llms.txt](https://tollwarden.com/llms.txt) and it can wire this up itself. OpenAPI at [/openapi.json](https://tollwarden.com/openapi.json). Source: [github.com/tollwarden/tollwarden](https://github.com/tollwarden/tollwarden) (source-available, BUSL 1.1). Non-custodial — TollWarden never touches your keys, wallet, or funds.
