# TollWarden

[TollWarden](https://tollwarden.com) is a payment security firewall for [x402](https://x402.org) micropayments. `agentkit-tollwarden` adds a scan-before-you-pay action provider to [Coinbase AgentKit](https://github.com/coinbase/agentkit).

## Install

```bash
pip install agentkit-tollwarden
```

## Add the provider

```python
from coinbase_agentkit import AgentKit, AgentKitConfig
from agentkit_tollwarden import tollwarden_action_provider

agent_kit = AgentKit(AgentKitConfig(
    wallet_provider=wallet_provider,
    action_providers=[tollwarden_action_provider(agent_id="my-agent")],
))
```

## Actions

- **`tollwarden_scan_payment`** screens a payment before your agent settles it (`direction="outgoing"`) or before it pays a received 402 offer (`direction="incoming"`). Returns `allow` / `flag` / `block`. Auto-fills `payer` from the agent's AgentKit wallet; pass optional `content` (page/tool text just read) to enable prompt-injection-triggered-payment detection.
- **`tollwarden_check_reputation`** checks community reports on a counterparty wallet before dealing with it.
- **`tollwarden_report_counterparty`** reports a bad counterparty (always free).

## Enforce the verdict

The actions rely on the model obeying the verdict. To make a blocked payment impossible instead, wrap your payment executor.

```python
from agentkit_tollwarden import guarded_payment

safe_pay = guarded_payment(execute_x402_payment, tollwarden, wallet_provider=wallet_provider)
safe_pay(payment, content=page_text)
# raises TollWardenBlockedError on a block verdict; the executor is never called
```

Pass `content` (the text the agent read before deciding to pay) so the prompt-injection check runs. `strict=True` refuses flags too.

## Non-custodial

TollWarden reads only payment metadata to produce a signed verdict; it never touches the AgentKit wallet's keys or funds.

## Reference

- The [agentkit-tollwarden package on PyPI](https://pypi.org/project/agentkit-tollwarden/) and its [source](https://github.com/tollwarden/tollwarden/tree/main/integrations/agentkit-tollwarden)
- The service's [integration guide](https://tollwarden.com/llms.txt) and [OpenAPI contract](https://tollwarden.com/openapi.json)
