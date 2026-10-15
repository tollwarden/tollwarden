"""
agentkit-tollwarden — TollWarden payment security for Coinbase AgentKit.

Adds a TollWarden action provider so an AgentKit agent screens every x402 payment
before settling it:

    from coinbase_agentkit import AgentKit, AgentKitConfig
    from agentkit_tollwarden import tollwarden_action_provider

    agent_kit = AgentKit(AgentKitConfig(
        wallet_provider=wallet_provider,
        action_providers=[tollwarden_action_provider(agent_id="my-agent"), ...],
    ))

Actions:
  - tollwarden_scan_payment        (before you settle / before you pay a 402 offer)
  - tollwarden_check_reputation    (before dealing with a counterparty)
  - tollwarden_report_counterparty (after a bad experience — free)

The scan action auto-fills the `payer` from the agent's own AgentKit wallet
when you don't supply one (scopes velocity limits), and takes an optional
`content` argument — the page/tool text the agent just read — which lights up
TollWarden's strongest check: prompt-injection-triggered-payment detection.

To make a block stop the payment rather than relying on the model to obey
the verdict, wrap your payment executor:

    from agentkit_tollwarden import guarded_payment

    safe_pay = guarded_payment(execute_x402_payment, client, wallet_provider=wallet_provider)
    safe_pay(payment, content=page_text)  # raises TollWardenBlockedError on block

TollWarden is advisory and non-custodial — it never touches keys, wallets, or funds.
"""
from __future__ import annotations

from .provider import TollWardenActionProvider, guarded_payment, tollwarden_action_provider

__all__ = ["TollWardenActionProvider", "guarded_payment", "tollwarden_action_provider", "__version__"]

__version__ = "0.1.0"
