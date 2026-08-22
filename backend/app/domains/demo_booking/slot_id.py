"""Opaque, server-issued slot identifiers.

Every slot in the availability response carries a ``slot_id``, and booking
or rescheduling names a slot by that id rather than by a wall-clock time
the client picked. The frontend never constructs one; it echoes back what
the server issued.

## Why an id at all, when the instant is right there

Three reasons, in order of how much they matter:

1. **The set of bookable times is the server's to define.** A client that
   sends a raw ``starts_at`` is asserting a time exists; a client that
   sends a ``slot_id`` is quoting one the server published. The former
   invites "we changed the slot length and the old page kept booking
   17:45"; the latter cannot express a time the server did not offer.
2. **It is tamper-evident.** The id is the instant plus a truncated
   HMAC-SHA256 over it, keyed on ``Settings.jwt_secret_key``. A forged or
   edited id fails verification and is rejected with a named error, rather
   than falling through to the availability guards and producing a
   confusing "not one of the published slot times".
3. **It is stable and comparable.** The same instant always yields the
   same id, so a client can match a slot across two availability calls
   without parsing timestamps.

## What it is NOT

It is **not** a reservation, a hold, or a capacity token. Issuing a
``slot_id`` reserves nothing -- ten visitors can hold the same id for the
same 11:00 slot, and exactly one of them will win, decided by
``uq_demo_bookings_active_slot`` at insert time and by nothing else. It is
also not an authorization token: possessing one grants no rights, which is
why truncating the HMAC to 128 bits is comfortable here.

It is also not a substitute for the availability guards. A verified id is
turned straight back into an instant and then run through the *same*
``BookingWindow.is_bookable`` checks as anything else -- an id issued
yesterday for a slot that has since passed, or that now falls on a
newly-added blackout date, is refused exactly like any other stale time.
The signature says "the server published this"; it does not say "the
server will still honour it".

## Format

``v1.<base64url(epoch_seconds)>.<base64url(hmac[:16])>``

The version prefix is there so a future change of payload or algorithm can
reject old ids explicitly instead of mis-decoding them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import UTC, datetime

_VERSION = "v1"
#: 128 bits of tag. This authenticates a public, non-secret timestamp
#: against forgery; it is not protecting a credential.
_TAG_BYTES = 16


class InvalidSlotIdError(ValueError):
    """The slot id was malformed, used an unknown version, or failed
    signature verification."""


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except Exception as exc:  # noqa: BLE001 -- any decode failure is the same
        raise InvalidSlotIdError("slot_id is not valid base64url") from exc


def _tag(payload: bytes, secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()[
        :_TAG_BYTES
    ]


def encode_slot_id(starts_at: datetime, *, secret: str) -> str:
    """Issue the id for a slot start. Deterministic: the same instant and
    secret always produce the same id."""
    if starts_at.tzinfo is None:
        raise InvalidSlotIdError(
            "a slot id can only be issued for an aware instant -- see "
            "availability.py's module docstring."
        )
    seconds = int(starts_at.astimezone(UTC).timestamp())
    payload = str(seconds).encode("ascii")
    return f"{_VERSION}.{_b64(payload)}.{_b64(_tag(payload, secret))}"


def decode_slot_id(slot_id: str, *, secret: str) -> datetime:
    """Recover the UTC instant a slot id names.

    Raises :class:`InvalidSlotIdError` on anything that is not an
    unmodified id this deployment issued. Comparison uses
    ``hmac.compare_digest`` -- not because a timing attack on a public
    timestamp would be worth anyone's afternoon, but because writing the
    comparison the safe way costs nothing and the unsafe spelling tends to
    get copied into places where it does matter.
    """
    parts = slot_id.split(".")
    if len(parts) != 3:
        raise InvalidSlotIdError("slot_id is malformed")
    version, payload_text, tag_text = parts
    if version != _VERSION:
        raise InvalidSlotIdError(f"unsupported slot_id version: {version!r}")

    payload = _unb64(payload_text)
    if not hmac.compare_digest(_unb64(tag_text), _tag(payload, secret)):
        raise InvalidSlotIdError("slot_id signature does not verify")

    try:
        seconds = int(payload.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise InvalidSlotIdError("slot_id payload is not an instant") from exc
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise InvalidSlotIdError("slot_id names an impossible instant") from exc


__all__ = ["InvalidSlotIdError", "decode_slot_id", "encode_slot_id"]
