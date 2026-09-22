# agentkit-tollwarden

[TollWarden](https://tollwarden.com) payment security for [Coinbase AgentKit](https://github.com/coinbase/agentkit) — a scan-before-you-pay action provider for x402 payments.

```bash
pip install agentkit-tollwarden
```

## Add the action provider

```python
from coinbase_agentkit import AgentKit, AgentKitConfig
from agentkit_tollwarden import tollwarden_action_provider

agent_kit = AgentKit(AgentKitConfig(
    wallet_provider=wallet_provider,
    action_providers=[
        tollwarden_action_provider(agent_id="my-agent"),   # free key auto-minted
        # ... your other providers
    ],
))
```

The agent gets three actions — `tollwarden_scan_payment`, `tollwarden_check_reputation`, `tollwarden_report_counterparty` — each described so the model calls them at the right moment. Verdicts come back **allow / flag / block** with machine-readable reasons: prompt-injection-triggered payments, replayed nonces, overpayment vs the quote, secrets/PII leaking in payment metadata, lookalike-token contracts, address poisoning, counterparty reputation.

## Two AgentKit-native touches

**Wallet payer auto-fill.** `tollwarden_scan_payment` receives AgentKit's `wallet_provider`, so when you don't supply a `payer` it fills in the agent's own wallet address, so every scan records which wallet is paying. Velocity and first-contact limits are scoped to your API key's account (the SDK mints one automatically); `payer` scopes them only for anonymous scans. Supply `payer` explicitly to override.

**Provenance for injection detection.** TollWarden's strongest check catches payments whose *decision* came from content the agent just read. Pass that text as the scan action's optional **`content`** argument; if the `pay_to` address appears in it, the payment is blocked.

## Non-custodial by design

TollWarden only reads payment *metadata* to produce a verdict — it never signs, holds, or routes funds, and the action provider never touches the AgentKit wallet's keys. The settle/refuse decision stays with your agent. Verdicts are Ed25519-signed and payment-bound; for wallet-level enforcement (the signer itself refuses unscanned payments), see `TollWardenEnforcer` in the [tollwarden SDK](https://pypi.org/project/tollwarden/).

MIT.
