# TollWarden

[TollWarden](https://tollwarden.com) is a payment security firewall for [x402](https://x402.org) micropayments. `nemo-tollwarden` registers three NeMo Agent Toolkit functions that let a workflow screen every x402 payment before it settles, with prompt-injection provenance detection and Ed25519-signed, payment-bound verdicts.

## Install

```bash
pip install nemo-tollwarden
```

Installing registers the functions via the `nat.plugins` entry point; no extra wiring needed.

## Use in a workflow

```yaml
functions:
  scan:
    _type: tollwarden_scan_payment
    agent_id: my-agent
  reputation:
    _type: tollwarden_check_reputation
  report:
    _type: tollwarden_report_counterparty
```

A free API key (100 free scans) is auto-minted on first use; set `api_key:` to pin one.

## Functions

- **`tollwarden_scan_payment`** screens a payment before the workflow settles it (`direction="outgoing"`) or before it pays a received 402 offer (`direction="incoming"`). Returns `allow` / `flag` / `block` with per-check reasons. Pass the optional **`content`** argument (the page/tool text the agent just read) to enable prompt-injection-triggered-payment detection.
- **`tollwarden_check_reputation`** checks community reports on a counterparty wallet before dealing with it.
- **`tollwarden_report_counterparty`** reports a bad counterparty (always free).

The three functions share one TollWarden client per `(base_url, api_key, agent_id)`.

## Enforce the verdict

The scan function returns a verdict the model can ignore. To make a blocked payment impossible instead, wrap the workflow's payment executor (sync or async).

```python
from nemo_tollwarden import guarded_payment

safe_pay = guarded_payment(execute_x402_payment, tollwarden)
await safe_pay(payment, content=page_text)
# raises TollWardenBlockedError on a block verdict; the executor is never called
```

Pass `content` (the text the agent read before deciding to pay) so the prompt-injection check runs. `strict=True` refuses flags too.

## Reference

- The [nemo-tollwarden package on PyPI](https://pypi.org/project/nemo-tollwarden/) and its [source](https://github.com/tollwarden/tollwarden/tree/main/integrations/nemo-tollwarden)
- The service's [integration guide](https://tollwarden.com/llms.txt) and [OpenAPI contract](https://tollwarden.com/openapi.json)
- TollWarden is advisory and non-custodial. It never touches keys, wallets, or funds.
