"""SQLAlchemy ORM model for the OTP domain.

One model, extending ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does -- Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all
keep working uniformly.

## Why ``identifier`` is a plain string, not a foreign key

This module is built *before* the ``guest`` domain in this same BE-010
sequence -- there is no ``Guest`` table yet for a guest login/verification
code to belong to. ``OtpRequest.identifier`` is therefore just the raw
phone number or email address the guest presented, exactly the same
"self-contained, no FK to a not-yet-existing table" posture this codebase
already establishes elsewhere (e.g. ``app.domains.router_provisioning
.models.RouterEnrollmentRequest`` exists, and is queried by
``serial_number``/``mac_address``, entirely before any ``Router`` row is
bound to it). The future ``guest`` module composes with this one purely
through ``OtpService.verify_otp``'s return value (a verified
``OtpRequest`` for a known identifier) -- never a shared table or FK.

## Why ``organization_id``/``location_id`` are real, nullable FKs

Unlike ``identifier``, ``Organization``/``Location`` already exist (Modules
005/006) -- there is no deferred-FK situation here. A captive portal is
always scoped to a specific organization/location's guest WiFi, so
carrying that context on the OTP row itself (rather than only on whatever
downstream entity eventually consumes it) lets rate limiting, audit
filtering, and admin visibility (``GET /otp/requests``) all be scoped by
tenant without a join through a table that doesn't exist yet. Both are
nullable because this module does not itself validate that a caller-
supplied id resolves to a real row (see ``service.py``'s module docstring)
-- an invalid id is caught by the database's own FK constraint, not a
cross-domain lookup this genuinely self-contained module deliberately does
not perform.

## Why the code is stored hashed, and why SHA-256 rather than Argon2id

See ``service.py``'s module docstring for the full reasoning -- in short,
an OTP code is a short-lived, narrowly-guessable value already protected by
expiry (``expires_at``) and a hard per-code attempt cap
(``attempt_count``/``max_attempts``), the same posture
``app.domains.router.models.RouterProvisioningToken.token_hash`` and
``app.domains.router_agent.models.RouterAgentCredential.credential_hash``
already established for their own short-lived, hashed bearer credentials.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class OtpRequest(BaseModel):
    """A single generated OTP code and its verification lifecycle.

    ``is_consumed`` is one-way: once ``True`` (set together with
    ``verified_at`` by ``OtpService.verify_otp`` on success), this row can
    never be presented successfully again -- see
    ``exceptions.OtpAlreadyConsumedError``. ``attempt_count``/
    ``max_attempts`` enforce a distinct, per-code brute-force lockout,
    separate from the Redis-backed, per-identifier *request* rate limit
    ``OtpService``/``OtpRateLimiter`` enforce before a row is even created
    -- see ``service.py``'s module docstring for the full two-dimension
    write-up.
    """

    __tablename__ = "otp_requests"

    identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    purpose: Mapped[str] = mapped_column(String(30), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    is_consumed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_otp_requests_identifier", "identifier"),
        Index("ix_otp_requests_purpose", "purpose"),
        Index("ix_otp_requests_identifier_purpose", "identifier", "purpose"),
        Index("ix_otp_requests_expires_at", "expires_at"),
        Index("ix_otp_requests_organization_id", "organization_id"),
        Index("ix_otp_requests_location_id", "location_id"),
    )

    def is_expired(self, *, now: datetime) -> bool:
        return now > self.expires_at

    def is_locked_out(self) -> bool:
        return self.attempt_count >= self.max_attempts

    def __repr__(self) -> str:
        return (
            f"<OtpRequest(id={self.id}, channel={self.channel}, "
            f"purpose={self.purpose}, is_consumed={self.is_consumed})>"
        )


__all__ = ["OtpRequest"]
