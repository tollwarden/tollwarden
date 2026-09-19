# Copyright (c) 2026 TollWarden, LLC. All rights reserved.
# SPDX-License-Identifier: BUSL-1.1
"""
The one-line diff: TollWarden in the default x402 payment path (Python parity
with the TypeScript SDK's wrap.ts).

Wrap your x402 payment-capable transport so every payment is scanned before
it settles:

    from tollwarden import TollWardenClient, wrap_transport_with_tollwarden

    tollwarden = TollWardenClient(agent_id="my-agent")
    guarded = wrap_transport_with_tollwarden(my_x402_transport, tollwarden)
    # use `guarded` anywhere a transport goes — e.g. TollWardenClient itself,
    # or your own HTTP layer. Non-402 responses pass through untouched.

Flow on a 402:
  1. The request is first sent WITHOUT payment (the probe).
  2. The payment about to be authorized is guarded as an OUTGOING payment —
     overpayment, poisoning, velocity, injection provenance (anything the
     client ``observe()``d feeds the injection detector here).
  3. The offer itself is scanned as an INCOMING payment request — resource-URL
     risk, credential demands, asset verification, counterparty reputation.
  4. Only on passing verdicts is the request re-sent through the paying
     transport, which performs the actual x402 pay-and-retry.

A block verdict raises TollWardenBlockedError BEFORE any payment is signed — the
paying transport is never invoked. Unparseable 402 offers fail CLOSED.

With ``enforcer`` set, the wrapper also registers each passing outgoing
verdict with a TollWardenEnforcer, so a signer wrapped by
``enforcer.guard_signer()`` inside the paying transport signs exactly the
authorization that was scanned — the offer has no nonce yet, and the enforcer
matches the later nonce-bearing authorization to the pre-sign approval (see
enforce.py). This is the composition that makes the default path enforced
rather than advisory:

    enforcer = TollWardenEnforcer(trusted_key_hex=PINNED)
    account  = enforcer.guard_signer(Account.from_key(KEY))
    guarded  = wrap_transport_with_tollwarden(paying_transport_for(account), tollwarden, enforcer=enforcer)
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional, Tuple

from . import (
    TollWardenBlockedError,
    TollWardenClient,
    TollWardenError,
    Transport,
    _urllib_transport,
)

__all__ = ["wrap_transport_with_tollwarden", "payment_from_offer"]


def payment_from_offer(entry: Dict[str, Any], request_url: str) -> Dict[str, Any]:
    """Defensive mapping from an x402 402 body's requirements entry to payment fields."""

    def s(v: Any) -> Optional[str]:
        if isinstance(v, str) and v:
            return v
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return str(v)
        return None

    extra = entry.get("extra") if isinstance(entry.get("extra"), dict) else {}
    payment: Dict[str, Any] = {
        "scheme": s(entry.get("scheme")),
        "network": s(entry.get("network")),
        "asset": s(entry.get("asset")),
        "amount": s(entry.get("maxAmountRequired")) or s(entry.get("amount")),
        "pay_to": s(entry.get("payTo")) or s(entry.get("pay_to")),
        "resource_url": s(entry.get("resource")) or request_url,
        "description": s(entry.get("description")),
    }
    if isinstance(extra.get("decimals"), int):
        payment["asset_decimals"] = extra["decimals"]
    return {k: v for k, v in payment.items() if v is not None}


def wrap_transport_with_tollwarden(
    payment_transport: Transport,
    tollwarden: TollWardenClient,
    base_transport: Optional[Transport] = None,
    strict: bool = False,
    scan_offer: bool = True,
    expected_price_usd: Optional[Any] = None,  # float or callable(offer)->float
    on_scan: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    report_outcomes: bool = True,
    enforcer: Optional[Any] = None,
) -> Transport:
    """Wrap an x402 payment-capable transport so every payment is scanned first.

    payment_transport: the paying transport (settles x402 challenges).
    tollwarden:           a TollWardenClient; its observe()/note_planning() state
                       feeds provenance into the outgoing scan.
    base_transport:    non-paying transport for the probe (default: stdlib urllib).
    strict:            also refuse "flag" verdicts (default: only "block").
    scan_offer:        scan the 402 offer as an incoming request too (default True).
    on_scan:           callable(phase, scan) for telemetry; phases "outgoing"/"incoming".
    report_outcomes:   automatically record the delivery outcome of every paid
                       request (default True): 2xx -> delivered; anything else
                       (incl. a second 402 after paying) -> not_delivered, with
                       mechanical evidence. Commitment-bound to the outgoing
                       scan; a reporting failure never affects the response.
    enforcer:          a TollWardenEnforcer (anything with ``approve(scan, payment)``).
                       Every passing outgoing verdict is registered as signing
                       authority with it, so a guard_signer()-wrapped signer in
                       the paying transport signs only what was scanned. A
                       verdict the enforcer refuses (e.g. a flag without
                       allow_flagged) raises TollWardenEnforcementError here,
                       before the paying transport runs.
    """
    probe_transport = base_transport or _urllib_transport

    def guarded_transport(
        method: str, url: str, headers: Dict[str, str], body: Optional[bytes]
    ) -> Tuple[int, Dict[str, str], bytes]:
        status, resp_headers, resp_body = probe_transport(method, url, headers, body)
        if status != 402:
            return status, resp_headers, resp_body  # free / authorized: zero overhead

        # Parse the offer. Unparseable 402s fail CLOSED: never hand an offer we
        # cannot inspect to a transport that pays automatically.
        try:
            parsed = json.loads(resp_body.decode("utf-8"))
            accepts = parsed.get("accepts")
            entry = accepts[0] if isinstance(accepts, list) and accepts else None
            if not isinstance(entry, dict):
                raise ValueError("no accepts[] in 402 body")
            offer = payment_from_offer(entry, url)
        except Exception as e:
            raise TollWardenError(
                f"refusing to auto-pay an unparseable 402 offer from {url} ({e}). "
                "Fail-closed: pass the request to your payment client manually if this endpoint is trusted.",
                402,
            ) from None

        expected = expected_price_usd(offer) if callable(expected_price_usd) else expected_price_usd

        # 1) Outgoing scan FIRST — it must consume the provenance observation.
        outgoing = tollwarden.scan_outgoing(offer, expected_price_usd=expected)
        if on_scan:
            on_scan("outgoing", outgoing)
        if outgoing["verdict"] == "block" or (strict and outgoing["verdict"] == "flag"):
            raise TollWardenBlockedError(outgoing)

        # 2) The offer itself, as an incoming payment request.
        if scan_offer:
            incoming = tollwarden.scan_incoming(offer, expected_price_usd=expected)
            if on_scan:
                on_scan("incoming", incoming)
            if incoming["verdict"] == "block" or (strict and incoming["verdict"] == "flag"):
                raise TollWardenBlockedError(incoming)

        # 3) Verdicts passed — hand signing authority to the enforcer (if any),
        #    then let the paying transport do the x402 dance. Registered only
        #    now, after BOTH scans, so an offer the incoming scan refused never
        #    leaves an approval behind.
        if enforcer is not None:
            enforcer.approve(outgoing, offer)
        import threading
        import time as _time

        started = _time.monotonic()
        paid_status, paid_headers, paid_body = payment_transport(method, url, headers, body)

        # 4) Delivery-outcome capture: x402 delivery is synchronous — the
        # resource arrives in this very response. Reported on a daemon thread;
        # a reporting failure never affects the response. Quality judgment
        # stays with report(): we only auto-judge what is mechanical.
        if report_outcomes:
            outcome = "delivered" if 200 <= paid_status < 300 else "not_delivered"
            latency = int((_time.monotonic() - started) * 1000)
            evidence = {
                "status": paid_status,
                "content_type": paid_headers.get("content-type"),
                "bytes_received": len(paid_body) if paid_body is not None else None,
                "latency_ms": latency,
            }

            def _report() -> None:
                try:
                    tollwarden.report_outcome(outgoing, outcome, **evidence)
                except Exception:
                    pass

            threading.Thread(target=_report, daemon=True).start()

        return paid_status, paid_headers, paid_body

    return guarded_transport
