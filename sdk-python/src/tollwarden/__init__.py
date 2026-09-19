# Copyright (c) 2026 TollWarden, LLC. All rights reserved.
# SPDX-License-Identifier: BUSL-1.1
"""
tollwarden — official Python SDK for TollWarden, the payment security firewall
for x402 micropayments (https://tollwarden.com).

Single dependency: `cryptography` (Ed25519 attestation verification).
Python 3.9+.

Quick start:
    from tollwarden import TollWardenClient, TollWardenBlockedError

    tollwarden = TollWardenClient(agent_id="my-agent")   # free API key auto-minted, 100 free scans
    tollwarden.observe(tool_result_text, source_url="https://api.example.com")
    try:
        scan = tollwarden.guard_outgoing(payment, expected_price_usd=0.01)
    except TollWardenBlockedError as e:
        print("blocked:", e.scan["checks"])        # machine-readable reasons

Feature parity with the TypeScript SDK (@tollwarden/client):
  - provenance auto-tagging (observe / note_planning / note_user_instruction)
  - automatic API key minting + free-quota tracking
  - Ed25519 attestation verification against a pinned server key, with local
    payment-commitment recomputation (replay defense) and expiry enforcement
  - plan catalog + subscribe (requires an x402 payment-capable transport)
  - counterparty reporting (free) and reputation lookup
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_der_public_key

__all__ = [
    "TollWardenClient",
    "TollWardenError",
    "TollWardenBlockedError",
    "AttestationError",
    "TollWardenEnforcer",
    "TollWardenEnforcementError",
    "payment_from_typed_data",
    "wrap_transport_with_tollwarden",
    "payment_from_offer",
    "compute_payment_commitment",
    "verify_attestation",
]

__version__ = "0.7.0"

DEFAULT_BASE_URL = "https://tollwarden.com"

# A transport is: (method, url, headers, body_bytes|None) -> (status, headers_dict, body_bytes)
Transport = Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, Dict[str, str], bytes]]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class TollWardenError(Exception):
    def __init__(self, message: str, status: Optional[int] = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


class TollWardenBlockedError(TollWardenError):
    """Raised by guard_outgoing/guard_incoming on a block verdict (or flag when strict)."""

    def __init__(self, scan: Dict[str, Any]):
        reasons = "; ".join(
            f"{c.get('id')}: {c.get('reason')}" for c in scan.get("checks", []) if c.get("verdict") != "allow"
        )
        super().__init__(f"TollWarden verdict: {scan.get('verdict')} (risk {scan.get('risk_score')}). {reasons}")
        self.scan = scan


class AttestationError(TollWardenError):
    pass


# ---------------------------------------------------------------------------
# Attestation verification (standalone)
# ---------------------------------------------------------------------------
def compute_payment_commitment(payment: Dict[str, Any]) -> str:
    """Recompute the server's payment commitment: sha256(network|pay_to.lower()|asset.lower()|amount|nonce)."""
    if payment.get("amount") is not None:
        amount = str(payment["amount"])
    elif payment.get("amount_usd") is not None:
        amount_usd = payment["amount_usd"]
        # Match JavaScript number formatting: integers render without a decimal point.
        if isinstance(amount_usd, float) and amount_usd.is_integer():
            amount_usd = int(amount_usd)
        amount = f"usd:{amount_usd}"
    else:
        amount = ""
    canonical = "|".join(
        [
            payment.get("network") or "",
            (payment.get("pay_to") or "").lower(),
            (payment.get("asset") or "").lower(),
            amount,
            payment.get("nonce") or "",
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_attestation(
    scan: Dict[str, Any],
    payment: Dict[str, Any],
    trusted_key_hex: str,
    now_ms: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Full attestation check; raises AttestationError with a specific reason on failure.

    Order: (1) Ed25519 signature over `message` under `trusted_key_hex` — the
    PINNED key, never the key embedded in the response; (2) message fields
    match the scan; (3) commitment matches one recomputed from `payment`;
    (4) not expired; (5) when a signed evidence record is present: its
    signature verifies under the same pinned key, it is bound to this same
    scan_id + commitment, and the `pin` convenience mirror matches the signed
    message.

    Returns the verified evidence ``{"pin": {...} | None}`` — merchant-pin age
    in seconds (0 = first sighting) and the NAMED out-of-band sources that
    corroborated the pin (e.g. "cdp_bazaar"; deliberately never a boolean or a
    score). Returns None when the attestation carries no evidence record this
    SDK version can parse (older server, override attestation, or a future
    evidence version). Whether a young or uncorroborated pin is acceptable is
    the caller's decision boundary — weigh it against the payment size.
    """
    att = scan.get("attestation")
    if not att:
        raise AttestationError("scan carries no attestation")

    try:
        key = load_der_public_key(bytes.fromhex(trusted_key_hex))
        key.verify(bytes.fromhex(att["signature_hex"]), att["message"].encode("utf-8"))  # type: ignore[union-attr]
    except InvalidSignature:
        raise AttestationError("Ed25519 signature invalid under the pinned server key") from None
    except AttestationError:
        raise
    except Exception as e:  # malformed key/signature hex etc.
        raise AttestationError(f"signature check failed to run: {e}") from None

    parts = att["message"].split("|")
    if len(parts) != 7:
        raise AttestationError("malformed attestation message")
    scan_id, direction, verdict, risk, scanned_at, commitment, expires_at = parts
    if (
        scan_id != scan.get("scan_id")
        or direction != scan.get("direction")
        or verdict != scan.get("verdict")
        or str(scan.get("risk_score")) != risk
        or scanned_at != scan.get("scanned_at")
    ):
        raise AttestationError("attested message does not match the scan response fields")

    if commitment != compute_payment_commitment(payment):
        raise AttestationError(
            "payment commitment mismatch — this attestation was issued for a DIFFERENT payment (possible attestation replay)"
        )

    now = now_ms if now_ms is not None else int(time.time() * 1000)
    if _parse_iso_ms(expires_at) <= now:
        raise AttestationError(f"attestation expired at {expires_at}")

    # --- signed evidence record (pin age + named corroboration sources) ---
    # Only a MISSING/None record means "absent" (older server or an override
    # attestation). An empty dict is malformed and fails below, exactly like
    # the TS SDK — lockstep on rejects, not just accepts.
    ev = att.get("evidence")
    if ev is None:
        return None
    try:
        key.verify(bytes.fromhex(ev["signature_hex"]), ev["message"].encode("utf-8"))  # type: ignore[union-attr]
    except InvalidSignature:
        raise AttestationError("evidence signature invalid under the pinned server key") from None
    except Exception as e:
        raise AttestationError(f"evidence signature check failed to run: {e}") from None

    ev_parts = ev["message"].split("|")
    if ev_parts[0] != "evidence-v1":
        return None  # authenticated but not a version this SDK parses
    if len(ev_parts) != 6:
        raise AttestationError("malformed evidence-v1 message")
    _, ev_scan_id, ev_commitment, domain, age, sources = ev_parts
    if ev_scan_id != scan.get("scan_id") or ev_commitment != commitment:
        raise AttestationError(
            "evidence record is bound to a DIFFERENT scan/payment (possible evidence replay)"
        )
    pin: Optional[Dict[str, Any]] = None
    if domain:
        # Explicit ASCII-digit check — str.isdigit() accepts Unicode digits.
        if not re.fullmatch(r"[0-9]+", age):
            raise AttestationError("malformed evidence-v1 message: pin_age_seconds is not a non-negative integer")
        pin = {
            "domain": domain,
            "age_seconds": int(age),
            "corroboration": sources.split(",") if sources and sources != "none" else [],
        }
    # The convenience mirror must be EXACTLY the signed-derived fields (or
    # None): the mirror is the one unsigned part of the attestation, so an
    # extra key here would be unsigned data riding a verified response into
    # code that lazily reads attestation["evidence"]["pin"]. Strict by
    # deliberate, documented choice, identically in TS/Python/MCP. Dict
    # equality is key-order-insensitive, which is exactly right.
    if "pin" in ev and ev["pin"] != pin:
        raise AttestationError("evidence `pin` mirror does not match the signed evidence message")
    return {"pin": pin}


def _parse_iso_ms(iso: str) -> int:
    from datetime import datetime, timezone

    s = iso.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


# ---------------------------------------------------------------------------
# Default transport (urllib, stdlib)
# ---------------------------------------------------------------------------
def _urllib_transport(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (https URLs only by default)
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
@dataclass
class _Observation:
    content: str
    source_url: Optional[str]
    kind: str  # "tool_result" | "fetched_content"
    at: float = field(default_factory=time.monotonic)


class TollWardenClient:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: Optional[str] = None,
        auto_key: bool = True,
        agent_id: Optional[str] = None,
        transport: Optional[Transport] = None,
        default_origin: str = "unknown",
        observation_ttl_s: float = 300.0,
        max_content_bytes: int = 8192,
        verify_attestations: bool = True,
        verdict_key_hex: Optional[str] = None,
        auto_renew: bool = False,
        renew_window_s: float = 24 * 3600.0,
    ):
        """transport: supply an x402 payment-capable transport to pay for scans
        beyond the free tier and for plan subscriptions. Signature:
        (method, url, headers, body_bytes|None) -> (status, headers, body_bytes)."""
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.auto_key = auto_key
        self.agent_id = agent_id
        self._transport = transport or _urllib_transport
        self.default_origin = default_origin
        self.observation_ttl_s = observation_ttl_s
        self.max_content_bytes = max_content_bytes
        self.should_verify = verify_attestations
        self._pinned_key_hex = verdict_key_hex
        self.auto_renew = auto_renew
        self.renew_window_s = renew_window_s

        self.free_calls_remaining: Optional[int] = None
        self.plan: Optional[Dict[str, str]] = None  # {"id": ..., "expires_at": ...}
        self._observation: Optional[_Observation] = None
        self._explicit_origin: Optional[str] = None
        self._renew_warned = False

    # -- provenance -----------------------------------------------------------
    def observe(self, content: str, source_url: Optional[str] = None, kind: Optional[str] = None) -> None:
        """Record that the agent just read external content (tool result / fetched
        page). The next scan within the TTL is tagged with it — this powers
        TollWarden's prompt-injection-triggered-payment detection."""
        self._observation = _Observation(
            content=content[: self.max_content_bytes],
            source_url=source_url,
            kind=kind or ("fetched_content" if source_url else "tool_result"),
        )
        self._explicit_origin = None

    def note_planning(self) -> None:
        """Mark that the NEXT payment decision came from the agent's own planning step."""
        self._explicit_origin = "planning"
        self._observation = None

    def note_user_instruction(self) -> None:
        """Mark that the NEXT payment decision came from an explicit human instruction."""
        self._explicit_origin = "user_instruction"
        self._observation = None

    def _build_context(self, explicit: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if explicit is not None:
            return {"origin": explicit.get("origin", self.default_origin), **{k: v for k, v in explicit.items() if k != "origin"}}
        if self._explicit_origin:
            return {"origin": self._explicit_origin}
        obs = self._observation
        if obs and (time.monotonic() - obs.at) <= self.observation_ttl_s:
            ctx: Dict[str, Any] = {"origin": obs.kind, "content": obs.content}
            if obs.source_url:
                ctx["content_source_url"] = obs.source_url
            return ctx
        return {"origin": self.default_origin}

    # -- plumbing ---------------------------------------------------------------
    def _request(self, method: str, path: str, body: Any = None) -> Any:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        raw = None if body is None else json.dumps(body).encode("utf-8")
        status, resp_headers, resp_body = self._transport(method, f"{self.base_url}{path}", headers, raw)
        if "x-free-calls-remaining" in resp_headers:
            try:
                self.free_calls_remaining = int(resp_headers["x-free-calls-remaining"])
            except ValueError:
                pass
        try:
            parsed = json.loads(resp_body.decode("utf-8")) if resp_body else None
        except json.JSONDecodeError:
            parsed = None
        if status >= 400:
            if status == 402:
                raise TollWardenError(
                    "Payment required and this client's transport cannot pay. Construct TollWardenClient "
                    "with an x402 payment-capable transport, supply an API key with free calls remaining, "
                    "or subscribe to a plan.",
                    402,
                    parsed,
                )
            msg = (parsed or {}).get("error") if isinstance(parsed, dict) else None
            raise TollWardenError(msg or f"HTTP {status}", status, parsed)
        return parsed

    def ensure_api_key(self) -> str:
        """Mint an API key if none is set (auto_key). Returns the active key."""
        if self.api_key:
            return self.api_key
        if not self.auto_key:
            raise TollWardenError("no API key set and auto_key is disabled")
        r = self._request("POST", "/v1/keys", {"agent_id": self.agent_id} if self.agent_id else {})
        self.api_key = r["api_key"]
        if isinstance(r.get("free_calls_remaining"), int):
            self.free_calls_remaining = r["free_calls_remaining"]
        return self.api_key

    def verdict_key(self) -> str:
        """The pinned verdict key (fetched once unless supplied at construction)."""
        if self._pinned_key_hex:
            return self._pinned_key_hex
        r = self._request("GET", "/.well-known/tollwarden-verdict-key")
        self._pinned_key_hex = r["public_key_spki_hex"]
        return self._pinned_key_hex

    # -- scans --------------------------------------------------------------------
    def _scan(
        self,
        direction: str,
        payment: Dict[str, Any],
        expected_price_usd: Optional[float],
        context: Optional[Dict[str, Any]],
        policy: Optional[Dict[str, Any]],
        agent_id: Optional[str],
    ) -> Dict[str, Any]:
        try:
            self.ensure_api_key()
        except TollWardenError:
            pass  # scanning without a key still works via an x402-paying transport
        self._maybe_renew()
        body: Dict[str, Any] = {
            "agent_id": agent_id or self.agent_id,
            "payment": payment,
            "context": self._build_context(context),
        }
        if expected_price_usd is not None:
            body["expected_price_usd"] = expected_price_usd
        if policy is not None:
            body["policy"] = policy
        scan = self._request("POST", f"/v1/scan/{direction}", body)
        if self.should_verify and scan.get("attestation"):
            evidence = verify_attestation(scan, payment, self.verdict_key())  # raises on tamper/replay/expiry
            scan["attestation_verified"] = True
            if evidence is not None:
                scan["pin_evidence"] = evidence["pin"]
        # A consumed observation must not leak provenance onto unrelated later scans.
        self._observation = None
        self._explicit_origin = None
        return scan

    def scan_outgoing(
        self,
        payment: Dict[str, Any],
        expected_price_usd: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None,
        policy: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Scan a payment the agent is about to make. Never raises on flag/block."""
        return self._scan("outgoing", payment, expected_price_usd, context, policy, agent_id)

    def scan_incoming(
        self,
        payment: Dict[str, Any],
        expected_price_usd: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None,
        policy: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Scan a 402 offer / payment request the agent received."""
        return self._scan("incoming", payment, expected_price_usd, context, policy, agent_id)

    def guard_outgoing(self, payment: Dict[str, Any], strict: bool = False, **kwargs: Any) -> Dict[str, Any]:
        """Scan and RAISE TollWardenBlockedError on block (and on flag when strict)."""
        scan = self._scan("outgoing", payment, kwargs.get("expected_price_usd"), kwargs.get("context"), kwargs.get("policy"), kwargs.get("agent_id"))
        if scan["verdict"] == "block" or (strict and scan["verdict"] == "flag"):
            raise TollWardenBlockedError(scan)
        return scan

    def guard_incoming(self, payment: Dict[str, Any], strict: bool = False, **kwargs: Any) -> Dict[str, Any]:
        scan = self._scan("incoming", payment, kwargs.get("expected_price_usd"), kwargs.get("context"), kwargs.get("policy"), kwargs.get("agent_id"))
        if scan["verdict"] == "block" or (strict and scan["verdict"] == "flag"):
            raise TollWardenBlockedError(scan)
        return scan

    # -- human-in-the-loop approvals ---------------------------------------------
    def wait_for_approval(
        self,
        scan_or_id: Any,
        payment: Optional[Dict[str, Any]] = None,
        timeout_s: float = 600.0,
        interval_s: float = 3.0,
    ) -> Dict[str, Any]:
        """Wait for a human decision on a flagged scan (the operator must have
        configured approvals via POST /v1/approvals/config). Polls until
        approved / denied / expired / timeout.

            scan = tollwarden.scan_outgoing(payment)
            if scan["verdict"] == "flag" and scan.get("approval"):
                override = tollwarden.wait_for_approval(scan, payment=payment)
                enforcer.approve(override, payment)  # needs accept_overrides=True

        Returns the override scan-shaped dict (verdict "override:allow", signed
        attestation bound to the payment commitment). Raises TollWardenError on
        deny/expiry/timeout. When `payment` is supplied (recommended) and this
        client verifies attestations, the override is verified against the
        pinned key and that exact payment before being returned.
        """
        if isinstance(scan_or_id, str):
            approval_id = scan_or_id
        else:
            approval_id = ((scan_or_id or {}).get("approval") or {}).get("approval_id", "")
        if not approval_id:
            raise TollWardenError(
                "no approval to wait for: the scan carries no `approval` (either the verdict was not "
                "flag, or the key has no approvals config - POST /v1/approvals/config first)"
            )
        from urllib.parse import quote

        interval = max(interval_s, 0.25)
        deadline = time.monotonic() + timeout_s
        while True:
            state = self._request("GET", f"/v1/approvals/{quote(approval_id, safe='')}")
            status = state.get("status")
            if status == "approved" and state.get("override"):
                override = state["override"]
                if self.should_verify and override.get("attestation") and payment is not None:
                    verify_attestation(override, payment, self.verdict_key())
                    override["attestation_verified"] = True
                return override
            if status == "denied":
                raise TollWardenError(f"approval {approval_id} was DENIED by the operator", 403, state)
            if status == "expired":
                raise TollWardenError(f"approval {approval_id} expired before a decision", 410, state)
            if time.monotonic() + interval > deadline:
                raise TollWardenError(f"timed out waiting for approval {approval_id}", 408, state)
            time.sleep(interval)

    def report_outcome(
        self,
        scan: Dict[str, Any],
        outcome: str,
        status: Optional[int] = None,
        content_type: Optional[str] = None,
        bytes_received: Optional[int] = None,
        latency_ms: Optional[int] = None,
        settlement_receipt: Optional[str] = None,
    ) -> Any:
        """Record whether a scanned, settled payment actually DELIVERED
        (outcome: delivered | not_delivered | partial | wrong_content).

        Bound to the scan (scan_id + payment_commitment), so delivery history
        can't be fabricated without real, scanned payments. One outcome per
        scan. The payment-path wrapper (wrap_transport_with_tollwarden) calls
        this automatically; call it yourself when you settle another way.

        settlement_receipt ("present" | "absent"): whether the paid response
        carried a settlement-receipt header. Pass "absent" when the transfer is
        visible on-chain but the seller returned no receipt — such calls read as
        FREE to a stock client, and future buyers get flagged to reconcile
        on-chain rather than pay twice."""
        commitment = (scan.get("attestation") or {}).get("payment_commitment")
        if not commitment:
            raise TollWardenError(
                "cannot report an outcome: the scan carries no attestation/payment_commitment (verdict signing disabled?)"
            )
        evidence: Dict[str, Any] = {}
        if status is not None:
            evidence["status"] = status
        if content_type is not None:
            evidence["content_type"] = content_type
        if bytes_received is not None:
            evidence["bytes"] = bytes_received
        if latency_ms is not None:
            evidence["latency_ms"] = latency_ms
        if settlement_receipt in ("present", "absent"):
            evidence["settlement_receipt"] = settlement_receipt
        return self._request(
            "POST",
            "/v1/outcomes",
            {
                "scan_id": scan.get("scan_id"),
                "payment_commitment": commitment,
                "outcome": outcome,
                "evidence": evidence or None,
            },
        )

    def configure_approvals(self, webhook_url: Optional[str], format: str = "json") -> Any:
        """Configure (or disable, with webhook_url=None) human-in-the-loop
        approvals for this key. Returns the webhook signing secret ONCE (header
        X-TollWarden-Signature: sha256=HMAC-SHA256(secret, body) on every
        delivery). SECURITY: the decide link each delivery carries is a bearer
        credential - point the webhook somewhere the agent itself cannot read."""
        self.ensure_api_key()
        return self._request("POST", "/v1/approvals/config", {"webhook_url": webhook_url, "format": format})

    # -- reputation ------------------------------------------------------------------
    def report(self, address: str, category: str, reason: str, reporter_agent_id: Optional[str] = None, evidence_url: Optional[str] = None) -> Any:
        """File a counterparty report (always free)."""
        return self._request(
            "POST",
            "/v1/reputation/report",
            {
                "address": address,
                "category": category,
                "reason": reason,
                "reporter_agent_id": reporter_agent_id or self.agent_id or "tollwarden-python",
                "evidence_url": evidence_url,
            },
        )

    def reputation(self, address: str) -> Any:
        """Counterparty report summary (paid / free-tier)."""
        try:
            self.ensure_api_key()
        except TollWardenError:
            pass
        from urllib.parse import quote

        return self._request("GET", f"/v1/reputation/{quote(address, safe='')}")

    # -- plans ------------------------------------------------------------------------
    def get_plans(self) -> Any:
        """Machine-readable plan catalog (free)."""
        return self._request("GET", "/v1/plans")

    def subscribe(self, plan_id: str) -> Dict[str, str]:
        """Subscribe/renew the current key on a plan. Requires an x402
        payment-capable transport — the endpoint is paid at the plan's price."""
        self.ensure_api_key()
        r = self._request("POST", "/v1/plans/subscribe", {"plan": plan_id, "agent_id": self.agent_id})
        if r.get("api_key"):
            self.api_key = r["api_key"]
        self.plan = {"id": r["plan"], "expires_at": r["expires_at"]}
        return {"plan": r["plan"], "expires_at": r["expires_at"]}

    def _maybe_renew(self) -> None:
        if not self.auto_renew or not self.plan:
            return
        ms_left = _parse_iso_ms(self.plan["expires_at"]) - int(time.time() * 1000)
        if ms_left > self.renew_window_s * 1000:
            return
        try:
            self.subscribe(self.plan["id"])
        except TollWardenError as e:
            if not self._renew_warned:
                self._renew_warned = True
                import warnings

                warnings.warn(f"tollwarden: plan auto-renewal failed ({e}); continuing on default tier after expiry.")


# ---------------------------------------------------------------------------
# Wallet-side enforcement kit. Imported at the END of the module on purpose:
# enforce.py imports names defined above, so this must follow the definitions.
# ---------------------------------------------------------------------------
from .enforce import (  # noqa: E402
    TollWardenEnforcementError,
    TollWardenEnforcer,
    payment_from_typed_data,
)

# Default-payment-path wrapper (same end-of-module reasoning as above).
from .wrap import (  # noqa: E402
    payment_from_offer,
    wrap_transport_with_tollwarden,
)
