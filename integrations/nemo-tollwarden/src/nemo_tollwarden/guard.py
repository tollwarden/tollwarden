"""
Enforcement by construction for NeMo Agent Toolkit workflows.

The registered scan function returns a verdict to the model, and a model can
ignore it. guarded_payment wraps the workflow's own payment executor so a block
verdict stops the payment in code instead.
"""
from __future__ import annotations

import asyncio
import inspect
import json
from typing import Any, Callable, Dict, Optional

from tollwarden import TollWardenClient


def _provenance(content: Optional[str]) -> Optional[Dict[str, Any]]:
    """Scan context for the text the agent read before deciding to pay, if any."""
    return {"origin": "tool_result", "content": content} if content else None


def _receipt(scan: Dict[str, Any], result: Any) -> str:
    return json.dumps(
        {"paid": True, "verdict": scan["verdict"], "scan_id": scan["scan_id"], "result": result},
        default=str,
    )


def guarded_payment(
    pay_fn: Callable[[Dict[str, Any]], Any],
    client: TollWardenClient,
    strict: bool = False,
) -> Callable[..., Any]:
    """Wrap a payment executor so it scans BEFORE paying and refuses blocks.

    Returns a callable (payment, expected_price_usd=None, content=None) -> JSON
    string, or a coroutine function returning one when pay_fn is async (the
    usual case in a NeMo workflow). On a block verdict (or a flag with
    strict=True) it raises TollWardenBlockedError and pay_fn is NEVER invoked,
    so enforcement holds by construction rather than by prompt.

    NeMo has no global tool-output hook, so pass the text the agent read before
    deciding to pay as `content` to run the prompt-injection check.
    """
    name = getattr(pay_fn, "__name__", "payment") + "_tollwarden_guarded"

    if inspect.iscoroutinefunction(pay_fn):

        async def _guarded_async(
            payment: Dict[str, Any],
            expected_price_usd: Optional[float] = None,
            content: Optional[str] = None,
        ) -> str:
            # Client is sync (urllib); keep the event loop free, as register.py does.
            scan = await asyncio.to_thread(
                client.guard_outgoing,
                payment,
                strict=strict,
                expected_price_usd=expected_price_usd,
                context=_provenance(content),
            )
            return _receipt(scan, await pay_fn(payment))

        _guarded_async.__name__ = name
        return _guarded_async

    def _guarded(
        payment: Dict[str, Any],
        expected_price_usd: Optional[float] = None,
        content: Optional[str] = None,
    ) -> str:
        scan = client.guard_outgoing(
            payment, strict=strict, expected_price_usd=expected_price_usd, context=_provenance(content)
        )
        return _receipt(scan, pay_fn(payment))

    _guarded.__name__ = name
    return _guarded
