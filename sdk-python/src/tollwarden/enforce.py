# Copyright (c) 2026 TollWarden, LLC. All rights reserved.
# SPDX-License-Identifier: BUSL-1.1
"""
Wallet-side enforcement kit (Python parity with the TypeScript SDK's enforce.ts).

Turns TollWarden from advisory into ENFORCED: a wrapped signer refuses to sign an
x402 payment authorization unless a fresh, Ed25519-verified TollWarden
allow-verdict exists for exactly that payment. The verdict's payment
commitment — sha256(network|pay_to|asset|amount|nonce) — is recomputed from
the EIP-712 typed data the wallet is being asked to sign, so a compromised
agent cannot scan one payment and settle another: any change to recipient,
amount, asset, chain, or nonce changes the commitment and the signature is
refused.

    from tollwarden import TollWardenClient, TollWardenEnforcer
    from eth_account import Account

    tollwarden  = TollWardenClient(agent_id="my-agent")
    enforcer = TollWardenEnforcer(trusted_key_hex=tollwarden.verdict_key())
    account  = enforcer.guard_signer(Account.from_key(PRIVATE_KEY))

    scan = tollwarden.guard_outgoing(payment)      # raises on block
    enforcer.approve(scan, payment)             # registers the verdict locally
    # ... hand `account` to your x402 client as usual. It will only ever sign
    # authorizations whose commitment carries a live allow-verdict.

Design notes (identical guarantees to the TS kit):
  - Signer-agnostic: anything with a ``sign_typed_data`` method works —
    eth-account LocalAccount (positional, keyword, or ``full_message=`` call
    shapes are all recognized), web3.py wrappers, custom signers. Every other
    attribute/method of the signer passes through untouched.
  - Recognized payment types: EIP-3009 TransferWithAuthorization /
    ReceiveWithAuthorization (the x402 "exact" scheme on EVM) and ERC-2612
    Permit. Other typed data passes through by default; ``strict_types=True``
    refuses everything unrecognized (deny-by-default).
  - Approvals are SINGLE-USE by default and expire with the attestation (plus
    an optional tighter ``max_age_s``), so a verdict can't be hoarded.
  - PRE-SIGN approvals: the default payment path scans the 402 OFFER, and an
    offer has no nonce — the x402 client mints the EIP-3009 nonce at signing
    time. An approval registered from a nonce-less payment binds (network,
    pay_to, asset, amount) and admits exactly ONE authorization carrying
    those facts, whatever nonce it ends up with; single-use is what stops it
    admitting a second. An approval registered WITH a nonce still requires
    that exact nonce. Combine ``reusable=True`` with pre-sign approvals only
    if you accept that any number of authorizations for the same facts may
    sign until expiry.
  - Enforcement never phones home: approval happens locally against the
    pinned key. If TollWarden is unreachable, nothing new can be approved —
    fail-closed, which is the point.
  - LOCAL POLICY (optional): ``allowed_recipients`` plus ``max_amount_atomic``
    / ``max_total_atomic`` spend caps, checked against the typed data at sign
    time with no server involved. Deliberately independent of the verdict
    layer: even a payment with a valid allow-verdict is refused if it exceeds
    the caps or pays an unlisted recipient, so a compromised advisory path can
    only move bounded amounts to known parties.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, Optional, Tuple

from . import (
    TollWardenError,
    _parse_iso_ms,
    compute_payment_commitment,
    verify_attestation,
)

__all__ = [
    "TollWardenEnforcer",
    "TollWardenEnforcementError",
    "payment_from_typed_data",
]

#: EIP-712 primary types treated as payment authorizations.
_PAYMENT_TYPES = ("TransferWithAuthorization", "ReceiveWithAuthorization", "Permit")


class TollWardenEnforcementError(TollWardenError):
    """Raised when a signature is refused (no/stale/used approval, strict mode)."""

    def __init__(self, message: str, commitment: Optional[str] = None, primary_type: Optional[str] = None):
        super().__init__(message)
        self.commitment = commitment
        self.primary_type = primary_type


def _s(v: Any) -> str:
    """Stringify typed-data scalar values the way the commitment expects."""
    if isinstance(v, str):
        return v
    if isinstance(v, bool):  # bool is an int subclass; exclude it explicitly
        return ""
    if isinstance(v, int):
        return str(v)
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    return ""


_ASCII_DIGITS = re.compile(r"^\d+$", re.ASCII)


def _to_atomic(v: Any, name: str) -> Optional[int]:
    """Parse a policy cap option into a non-negative int (None = not set).
    Raises on anything that isn't a plain integer — a cap that silently failed
    to parse would be a cap that silently doesn't exist."""
    if v is None:
        return None
    if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
        return v
    if isinstance(v, str) and _ASCII_DIGITS.match(v.strip()):
        return int(v.strip())
    raise TollWardenEnforcementError(f"{name} must be a non-negative integer amount in atomic units (got {v!r})")


def _parse_atomic_amount(amount: Any) -> Optional[int]:
    """Parse a typed-data value into a non-negative int, or None if it isn't
    a plain ASCII integer (callers with caps configured treat None as refuse)."""
    if isinstance(amount, str) and _ASCII_DIGITS.match(amount):
        return int(amount)
    return None


def _infer_primary_type(types: Any) -> Optional[str]:
    """eth-account's (domain, types, message) shape has no primaryType — infer
    it as the type no other type references (EIP-712 convention)."""
    if not isinstance(types, dict):
        return None
    names = [n for n in types.keys() if n != "EIP712Domain"]
    referenced = set()
    for n in names:
        fields = types.get(n)
        if not isinstance(fields, list):
            continue
        for f in fields:
            t = (f or {}).get("type", "") if isinstance(f, dict) else ""
            referenced.add(t.replace("[]", ""))
    for n in names:
        if n not in referenced:
            return n
    return names[0] if names else None


def payment_from_typed_data(td: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map an EIP-712 payload to the payment fields the commitment binds.

    Returns None for typed data that is not a recognized payment authorization.
    """
    if not isinstance(td, dict):
        return None
    primary = td.get("primaryType") or _infer_primary_type(td.get("types"))
    if primary not in _PAYMENT_TYPES:
        return None
    message = td.get("message") or {}
    domain = td.get("domain") or {}
    chain_id = _s(domain.get("chainId"))
    network = f"eip155:{chain_id}" if chain_id else ""
    asset = domain.get("verifyingContract") if isinstance(domain.get("verifyingContract"), str) else ""

    if primary in ("TransferWithAuthorization", "ReceiveWithAuthorization"):
        return {
            "network": network,
            "asset": asset,
            "pay_to": _s(message.get("to")),
            "payer": _s(message.get("from")),
            "amount": _s(message.get("value")),
            "nonce": _s(message.get("nonce")),
        }
    # ERC-2612 Permit — a spend approval is a payment authorization too.
    return {
        "network": network,
        "asset": asset,
        "pay_to": _s(message.get("spender")),
        "payer": _s(message.get("owner")),
        "amount": _s(message.get("value")),
        "nonce": _s(message.get("nonce")),
    }


def _typed_data_from_call(args: tuple, kwargs: dict) -> Optional[Dict[str, Any]]:
    """Normalize the sign_typed_data call shapes into one EIP-712 dict.

    Recognized shapes:
      sign_typed_data(full_message={...})                       (eth-account kwarg)
      sign_typed_data({...})                                    (single full dict)
      sign_typed_data(domain_data, message_types, message_data) (eth-account positional)
      sign_typed_data(domain_data=..., message_types=..., message_data=...)
    """
    full = kwargs.get("full_message")
    if isinstance(full, dict):
        return full
    if len(args) == 1 and isinstance(args[0], dict) and (
        "types" in args[0] or "primaryType" in args[0] or "message" in args[0]
    ):
        return args[0]
    domain = kwargs.get("domain_data")
    types = kwargs.get("message_types")
    message = kwargs.get("message_data")
    if len(args) >= 3:
        domain, types, message = args[0], args[1], args[2]
    if domain is None and types is None and message is None:
        return None
    return {
        "domain": domain or {},
        "types": types or {},
        "message": message or {},
        "primaryType": _infer_primary_type(types),
    }


class _Approval:
    __slots__ = ("attestation", "scan_id", "verdict", "approved_at", "used")

    def __init__(self, attestation: Dict[str, Any], scan_id: str, verdict: str):
        self.attestation = attestation
        self.scan_id = scan_id
        self.verdict = verdict
        self.approved_at = time.time()
        self.used = False


class _GuardedSigner:
    """Proxy around a signer: gates sign_typed_data, passes everything else through."""

    def __init__(self, signer: Any, enforcer: "TollWardenEnforcer"):
        object.__setattr__(self, "_tollwarden_signer", signer)
        object.__setattr__(self, "_tollwarden_enforcer", enforcer)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_tollwarden_signer"), name)

    def sign_typed_data(self, *args: Any, **kwargs: Any) -> Any:
        signer = object.__getattribute__(self, "_tollwarden_signer")
        enforcer: TollWardenEnforcer = object.__getattribute__(self, "_tollwarden_enforcer")
        td = _typed_data_from_call(args, kwargs)
        payment = payment_from_typed_data(td) if td is not None else None
        if payment is None:
            if enforcer.strict_types:
                primary = (td or {}).get("primaryType") if isinstance(td, dict) else None
                raise TollWardenEnforcementError(
                    f"strict_types: refusing to sign unrecognized typed data (primaryType {primary or 'unknown'})",
                    primary_type=primary,
                )
            return signer.sign_typed_data(*args, **kwargs)
        primary = (td or {}).get("primaryType") if isinstance(td, dict) else None
        # Local policy first (allowlist, caps — offline, approval-independent),
        # then the verdict/approval gate; count against the cumulative cap only
        # when both have passed and the signature is about to happen.
        enforcer.assert_policy(payment, primary)
        enforcer.assert_approved_for(payment, primary)
        enforcer._record_authorized(payment)
        return signer.sign_typed_data(*args, **kwargs)


class TollWardenEnforcer:
    """Local, fail-closed signing authority backed by TollWarden allow-verdicts."""

    def __init__(
        self,
        trusted_key_hex: str,
        allow_flagged: bool = False,
        accept_overrides: bool = False,
        max_age_s: Optional[float] = None,
        reusable: bool = False,
        strict_types: bool = False,
        allowed_recipients: Optional[list] = None,
        override_admits_recipient: bool = False,
        max_amount_atomic: Optional[Any] = None,
        max_total_atomic: Optional[Any] = None,
    ):
        if not trusted_key_hex:
            raise TollWardenEnforcementError(
                "trusted_key_hex is required: pin the TollWarden verdict key "
                "(GET /.well-known/tollwarden-verdict-key) — enforcement must never "
                "trust a key embedded in a response."
            )
        self.trusted_key_hex = trusted_key_hex
        self.allow_flagged = allow_flagged
        # OPT-IN: an agent that holds its own API key can point the approval
        # webhook at itself and "approve" its own flags; human-approved
        # "override:allow" verdicts are only trustworthy when the webhook
        # receiver is out of the agent's reach.
        self.accept_overrides = accept_overrides
        self.max_age_s = max_age_s
        self.reusable = reusable
        self.strict_types = strict_types
        # LOCAL POLICY — recipient allowlist (case-insensitive; an EMPTY list
        # refuses all recognized payments) and spend caps in atomic units of
        # the asset (USDC has 6 decimals, so 1_000_000 = $1). Checked at sign
        # time against the typed data, independent of the approval layer, so
        # even a fully approved payment stays inside the bounds. Atomic units
        # are only comparable within one asset — bound multi-asset flows with
        # separate enforcers.
        self.allowed_recipients = (
            {str(a).strip().lower() for a in allowed_recipients} if allowed_recipients is not None else None
        )
        # Escape hatch: a human-approved "override:allow" verdict satisfies the
        # allowlist for EXACTLY the payment it binds (the list never changes;
        # spend caps still apply; a plain allow never admits). Requires
        # accept_overrides — and inherits its security note: only meaningful
        # when the approval webhook receiver is out of the agent's reach.
        self.override_admits_recipient = override_admits_recipient
        if self.override_admits_recipient and not self.accept_overrides:
            raise TollWardenEnforcementError(
                "override_admits_recipient requires accept_overrides: an enforcer that refuses override "
                "verdicts could never admit one, so this combination is a dead setting, not a policy."
            )
        self.max_amount_atomic = _to_atomic(max_amount_atomic, "max_amount_atomic")
        self.max_total_atomic = _to_atomic(max_total_atomic, "max_total_atomic")
        #: Total atomic value of authorizations the gates have allowed to be
        #: signed (authorizations, not settlements).
        self.total_authorized_atomic = 0
        self._approvals: Dict[str, _Approval] = {}

    def assert_policy(self, payment: Dict[str, Any], primary_type: Optional[str] = None) -> None:
        """The LOCAL POLICY gate: recipient allowlist and spend caps, checked
        against the payment extracted from the typed data being signed.
        Deliberately independent of the verdict/approval layer — it bounds
        what even a fully approved payment can move, so a subverted advisory
        layer still can't exceed the caps or reach an unlisted recipient.
        ``guard_signer`` calls this before the approval gate; it is public so
        wallet authors can pre-check."""
        if self.allowed_recipients is not None:
            pay_to = str(payment.get("pay_to") or "").strip().lower()
            if pay_to not in self.allowed_recipients and not self._override_admits(payment):
                hint = (
                    "; a human-approved override:allow for this exact payment would admit it"
                    if self.override_admits_recipient
                    else ""
                )
                raise TollWardenEnforcementError(
                    f"recipient {payment.get('pay_to') or '(empty)'} is not on the local recipient allowlist "
                    f"({len(self.allowed_recipients)} allowed{hint}); refusing to sign",
                    primary_type=primary_type,
                )
        if self.max_amount_atomic is None and self.max_total_atomic is None:
            return
        amount = _parse_atomic_amount(payment.get("amount"))
        if amount is None:
            # Caps configured but the value isn't a plain non-negative integer:
            # fail closed — an unparseable amount must not slip past a spend cap.
            raise TollWardenEnforcementError(
                f"spend caps are configured but this authorization's value ({payment.get('amount') or 'missing'}) "
                "is not a plain integer in atomic units; refusing to sign",
                primary_type=primary_type,
            )
        if self.max_amount_atomic is not None and amount > self.max_amount_atomic:
            raise TollWardenEnforcementError(
                f"authorization value {amount} exceeds the local per-payment cap of "
                f"{self.max_amount_atomic} atomic units; refusing to sign",
                primary_type=primary_type,
            )
        if self.max_total_atomic is not None and self.total_authorized_atomic + amount > self.max_total_atomic:
            raise TollWardenEnforcementError(
                f"authorization value {amount} would take this enforcer's authorized total to "
                f"{self.total_authorized_atomic + amount}, past the local cumulative cap of "
                f"{self.max_total_atomic} atomic units ({self.total_authorized_atomic} already authorized); "
                "refusing to sign",
                primary_type=primary_type,
            )

    def _override_admits(self, payment: Dict[str, Any]) -> bool:
        """Does a registered, human-approved override admit this exact payment
        past the recipient allowlist? Matches on the payment COMMITMENT, so the
        admission cannot be transferred to any other payment — and only
        verdicts ``approve`` already vetted as "override:allow" against the
        pinned key count. Liveness (expiry, single-use) is still enforced by
        ``assert_approved``, which always runs after this gate."""
        if not self.override_admits_recipient:
            return False
        found = self._find_approval(payment)
        return found is not None and found[1].verdict == "override:allow"

    def _find_approval(self, payment: Dict[str, Any]) -> Optional[Tuple[str, _Approval]]:
        """Locate the approval for a payment: first by its exact commitment,
        then — when the payment carries a nonce — by the commitment of the
        same facts WITHOUT the nonce (a pre-sign approval, registered from the
        402 offer before any nonce existed). Never widens beyond that: an
        approval with a nonce only ever matches that nonce."""
        exact = compute_payment_commitment(payment)
        approval = self._approvals.get(exact)
        if approval is not None:
            return exact, approval
        if payment.get("nonce"):
            pre_sign = compute_payment_commitment({**payment, "nonce": None})
            approval = self._approvals.get(pre_sign)
            if approval is not None:
                return pre_sign, approval
        return None

    def assert_approved_for(self, payment: Dict[str, Any], primary_type: Optional[str] = None) -> str:
        """The sign-time gate keyed by PAYMENT rather than by commitment:
        resolves the approval (exact, else pre-sign) and runs
        ``assert_approved`` on it. Returns the commitment that was consumed."""
        found = self._find_approval(payment)
        commitment = found[0] if found is not None else compute_payment_commitment(payment)
        self.assert_approved(commitment, primary_type)
        return commitment

    def _record_authorized(self, payment: Dict[str, Any]) -> None:
        """Count an authorization against the cumulative cap — called by the
        guarded signer once BOTH gates (policy, approval) have passed."""
        amount = _parse_atomic_amount(payment.get("amount"))
        if amount is not None:
            self.total_authorized_atomic += amount

    def approve(self, scan: Dict[str, Any], payment: Dict[str, Any]) -> str:
        """Register a scan verdict as signing authority for its payment.

        Verifies the attestation against the PINNED key (signature, field
        match, commitment, expiry — raises AttestationError on any failure),
        then requires an allow verdict (or flag with allow_flagged). Returns
        the payment commitment.
        """
        verify_attestation(scan, payment, self.trusted_key_hex)
        verdict = scan.get("verdict")
        acceptable = (
            verdict == "allow"
            or (verdict == "flag" and self.allow_flagged)
            or (verdict == "override:allow" and self.accept_overrides)
        )
        if not acceptable:
            if verdict == "flag":
                hint = " (set allow_flagged=True to accept flags)"
            elif verdict == "override:allow":
                hint = " (human-approved overrides require the accept_overrides opt-in - see its security note)"
            else:
                hint = ""
            raise TollWardenEnforcementError(f'refusing to approve a "{verdict}" verdict for signing{hint}')
        commitment = compute_payment_commitment(payment)
        self._approvals[commitment] = _Approval(
            attestation=scan["attestation"], scan_id=scan.get("scan_id", ""), verdict=str(verdict)
        )
        return commitment

    def revoke(self, commitment: str) -> None:
        """Withdraw signing authority for a commitment."""
        self._approvals.pop(commitment, None)

    def clear(self) -> None:
        """Drop all approvals."""
        self._approvals.clear()

    def assert_approved(self, commitment: str, primary_type: Optional[str] = None) -> None:
        """The sign-time gate. Raises TollWardenEnforcementError unless a live,
        unexpired (and unused, unless reusable) approval exists for this
        commitment; consumes it on success."""
        approval = self._approvals.get(commitment)
        if approval is None:
            raise TollWardenEnforcementError(
                f"no TollWarden allow-verdict for this payment authorization (commitment {commitment[:16]}…). "
                "Scan the payment and call enforcer.approve(scan, payment) first. If the payment was scanned, "
                "its recipient/amount/asset/chain/nonce differs from what is now being signed — which is "
                "exactly what this gate exists to catch.",
                commitment=commitment,
                primary_type=primary_type,
            )
        if approval.used and not self.reusable:
            raise TollWardenEnforcementError(
                f"this allow-verdict was already used to sign once (scan {approval.scan_id}); "
                "approvals are single-use. Re-scan to sign again.",
                commitment=commitment,
                primary_type=primary_type,
            )
        expires_ms = _parse_iso_ms(approval.attestation["expires_at"])
        stale_ms = (approval.approved_at + self.max_age_s) * 1000 if self.max_age_s is not None else float("inf")
        deadline_ms = min(expires_ms, stale_ms)
        if time.time() * 1000 >= deadline_ms:
            del self._approvals[commitment]
            raise TollWardenEnforcementError(
                f"the allow-verdict for this payment is stale (scan {approval.scan_id}). "
                "Re-scan to obtain a fresh verdict.",
                commitment=commitment,
                primary_type=primary_type,
            )
        approval.used = True

    def guard_signer(self, signer: Any) -> Any:
        """Wrap a signer so sign_typed_data refuses x402/EIP-3009/Permit payment
        authorizations that lack a live approval. Every other attribute and
        method of the signer passes through untouched, so the wrapped signer
        is a drop-in replacement.

        Scope: this guards the typed-data path x402 uses. If your signer
        exposes other fund-moving paths (sign_transaction), gate those at your
        policy layer too.
        """
        return _GuardedSigner(signer, self)
