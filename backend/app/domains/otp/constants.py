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
    """How the OTP code is delivered to the guest."""

    SMS = "sms"
    EMAIL = "email"


class OtpPurpose(StrEnum):
    """Why an OTP was requested.

    Deliberately minimal today: only ``GUEST_LOGIN`` is needed by this
    module's own scope (BE-010 Part 1 -- OTP is self-contained and built
    before the ``guest`` domain that will consume it for guest login). The
    enum is designed so a future purpose (e.g. re-verifying an existing
    guest session, or a step in voucher redemption) can be added as a pure
    additive member with no migration -- mirrors
    ``app.domains.rbac.enums.PermissionModule``'s own "additive enum,
    never renumbered" convention.
    """

    GUEST_LOGIN = "guest_login"


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
