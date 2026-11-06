"""Proof that the caller is the browser that signed in (QA 2026-11-06, H1).

Before this, the session-mutating guest endpoints (``/set-password``,
``/set-pin``, ``/profile``, ``/session/disconnect`` ...) took
``guest_id`` + ``session_id`` as their only credential, and
``GET /guest/session/active`` handed both to anyone who knew a router id
(printed in every portal URL) and a device MAC (visible over the air). An
attacker could set a password on a guest's account within the 15-minute
window after their OTP login, then sign in as them.

The token is an HMAC over ``guest_id``, ``session_id`` and an expiry,
issued only in the response of a real login (``/guest/login/*``) -- never by
``/session/active``, which anyone can call. It is stateless: nothing is
stored, so issuing one costs nothing on the login path.

Signed with ``jwt_secret_key`` under a domain-separation prefix, so a token
can never be confused with, or forged from, a dashboard JWT.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import time
import uuid

from app.core.config import get_settings

_logger = logging.getLogger(__name__)

_PREFIX = b"wyfy-guest-session-token:v1:"


def _sign(body: bytes) -> bytes:
    key = get_settings().jwt_secret_key.encode()
    return hmac.new(key, _PREFIX + body, hashlib.sha256).digest()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_guest_session_token(
    guest_id: uuid.UUID, session_id: uuid.UUID, *, now: float | None = None
) -> str:
    """A token valid for ``guest_session_token_ttl_seconds`` from ``now``."""
    issued = time.time() if now is None else now
    expires = int(issued) + get_settings().guest_session_token_ttl_seconds
    body = f"{guest_id}.{session_id}.{expires}".encode()
    return f"{_b64(body)}.{_b64(_sign(body))}"


def verify_guest_session_token(
    token: str | None,
    *,
    guest_id: uuid.UUID,
    session_id: uuid.UUID,
    now: float | None = None,
) -> bool:
    """True only for an unexpired token this platform signed for exactly
    this ``guest_id`` and ``session_id``. Never raises."""
    if not token or token.count(".") != 1:
        return False
    body_part, sig_part = token.split(".")
    try:
        body = _unb64(body_part)
        sig = _unb64(sig_part)
    except (ValueError, TypeError):
        return False
    if not hmac.compare_digest(sig, _sign(body)):
        return False
    try:
        token_guest, token_session, expires = body.decode().split(".")
        expired = int(expires) < (time.time() if now is None else now)
    except (UnicodeDecodeError, ValueError):
        return False
    return (
        not expired
        and token_guest == str(guest_id)
        and token_session == str(session_id)
    )


def require_guest_session_proof(
    *,
    guest_id: uuid.UUID,
    session_id: uuid.UUID,
    session_token: str | None,
    sensitive: bool,
) -> None:
    """Raise ``GuestSessionProofRequiredError`` unless the caller proved it
    owns ``session_id``.

    A token that is sent is always checked, whatever the enforcement mode,
    so a forged or stale one is never silently accepted. A missing token is
    refused per ``guest_session_token_enforcement``: on ``sensitive``
    endpoints in ``sensitive`` mode, everywhere in ``all`` mode, nowhere in
    ``off`` mode (logged, so the switch to ``all`` can be timed on data)."""
    from app.domains.guest.exceptions import GuestSessionProofRequiredError

    if session_token is not None:
        if not verify_guest_session_token(
            session_token, guest_id=guest_id, session_id=session_id
        ):
            raise GuestSessionProofRequiredError()
        return
    mode = get_settings().guest_session_token_enforcement
    if mode == "all" or (mode == "sensitive" and sensitive):
        raise GuestSessionProofRequiredError()
    _logger.info(
        "guest_session_token_missing",
        extra={"event_session_id": str(session_id), "event_sensitive": sensitive},
    )
