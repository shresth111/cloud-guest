"""Enumerations and small constants for the OTP domain.

Stored as plain ``String`` columns on the ORM model
(``OtpRequest.channel``/``OtpRequest.purpose``), never a native PostgreSQL
enum type -- the same reason every other domain in this codebase documents
(``app.domains.wireguard.constants``, ``app.domains.rbac.enums``): adding a
new channel/purpose value never requires an ``ALTER TYPE`` migration, only
a new additive ``StrEnum`` member.
"""

from __future__ import annotations

from enum import StrEnum


class OtpChannel(StrEnum):
    """How the OTP code is delivered to the guest.

    ``WHATSAPP`` is a genuine third delivery channel, additive alongside
    ``SMS``/``EMAIL`` -- not a variant of either. It shares ``SMS``'s
    identifier shape (a phone number, validated the same way by
    ``validators.validate_identifier``) but is dispatched through its own
    ``WhatsAppProviderProtocol`` in ``service.py``, since WhatsApp Business
    API delivery is a materially different integration (template-approval
    requirement, separate sender identity) from a plain SMS send -- see
    that module's docstring for the full write-up."""

    SMS = "sms"
    EMAIL = "email"
    WHATSAPP = "whatsapp"


class OtpPurpose(StrEnum):
    """Why an OTP was requested.

    Originally minimal (``GUEST_LOGIN`` only -- BE-010 Part 1, OTP built
    before the ``guest`` domain that first consumed it). The enum is
    designed so a future purpose can be added as a pure additive member
    with no migration -- mirrors ``app.domains.rbac.enums.PermissionModule``'s
    own "additive enum, never renumbered" convention.

    ``ACCOUNT_DATA_MASKING`` is the first such addition: a step-up
    verification an already-authenticated account holder completes against
    their own email before their dashboard's guest-data masking preference
    (``app.domains.user.schemas``'s ``data_masking_enabled``) is flipped.
    Unlike ``GUEST_LOGIN``, both the request and verify calls for this
    purpose are made from authenticated ``/users/me/...`` endpoints
    (``app.domains.user.router``) with the identifier taken from the
    caller's own session, never client-supplied -- see that router's
    docstring for why reusing the guest-facing, unauthenticated
    ``/otp/request``/``/otp/verify`` endpoints directly would have let any
    caller "verify" an OTP for an arbitrary email.
    """

    GUEST_LOGIN = "guest_login"
    ACCOUNT_DATA_MASKING = "account_data_masking"


# Redis key template for request-rate-limiting (see
# ``service.OtpRateLimiter``). Scoped by identifier alone -- see that
# class's docstring for why purpose/channel are deliberately not part of
# the key.
OTP_REQUEST_RATE_LIMIT_KEY_TEMPLATE = "otp:request_count:{identifier}"

__all__ = [
    "OtpChannel",
    "OtpPurpose",
    "OTP_REQUEST_RATE_LIMIT_KEY_TEMPLATE",
]
