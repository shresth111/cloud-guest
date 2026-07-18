"""SQLAlchemy ORM models for the Guest domain (BE-010 Part 4) -- the final
domain in BE-010, which composes ``app.domains.otp``, ``app.domains
.voucher``, ``app.domains.captive_portal``, and ``app.domains.router`` into
the actual guest WiFi login journey.

All six models extend ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does -- Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all
keep working uniformly.

## Model overview

* :class:`Guest` -- a returning-guest identity, recognized across visits by
  ``identifier`` (the same phone/email value presented to
  ``app.domains.otp``/``app.domains.voucher``), unique per
  ``organization_id``.
* :class:`GuestDevice` -- a physical device (recognized by MAC address) seen
  logging in as some ``Guest``. See "MAC address uniqueness" below for the
  scoping decision.
* :class:`GuestSession` -- one continuous guest WiFi connection interval on
  one router. Append-only: see "Sessions are append-only" below.
* :class:`GuestLoginHistory` -- every login attempt (success or failure),
  including ones that never resolve to a real ``Guest`` row. See
  "``guest_id`` nullability" below.
* :class:`GuestConsent` -- a record of a guest accepting a captive portal's
  terms and conditions.
* :class:`RadiusNasClient` -- a router's registered FreeRADIUS NAS identity
  for the ``rlm_rest``-style integration (see ``service.py``'s module
  docstring for the full architectural write-up).

## MAC address uniqueness: globally unique, guest_id reassignable

A MAC address is a real-world hardware identifier for one physical device,
independent of which guest identifier happens to be presented alongside it
at any given login. This module deliberately makes
``GuestDevice.mac_address`` **globally unique** (not unique per
``(guest_id, mac_address)``) and treats ``guest_id`` as reassignable: if the
same MAC is later presented alongside a *different* identifier (e.g. a
shared family phone used first by a parent's number, later by a child's),
``GuestService.get_or_create_device`` re-points the existing row's
``guest_id`` at the new owner rather than creating a second row for the same
physical device.

The alternative (`unique per (guest_id, mac_address)`) was considered and
rejected: it would let the same physical phone accumulate an unbounded
number of ``GuestDevice`` rows, one per identifier ever used with it,
fragmenting "top devices" analytics (a phone that logged in with 3 different
numbers would count as 3 devices, undermining
``GuestAnalyticsService.get_top_devices``) and offering no real benefit --
nothing in this module's scope needs to remember "this MAC was once
associated with guest X" after guest Y has since claimed it; the device
belongs to whoever most recently authenticated with it, exactly like how a
real captive portal's MAC-based device recognition works (a `GuestDevice`
row is a statement about a device, not about a guest-device pairing).

## Sessions are append-only, not mutably reused (see also ``service.py``)

``GuestSession`` rows are never resurrected: ``disconnect_session``/
``terminate_session``/timeout detection all move a session from ``ACTIVE``
to a terminal status (``DISCONNECTED``/``TERMINATED``/``EXPIRED``) and
``GuestService.reconnect`` always creates a **new** row rather than
flipping an old one back to ``ACTIVE``. A session's ``started_at``/
``ended_at``/``bytes_uploaded``/``bytes_downloaded`` describe one
continuous, monotonic connection interval -- exactly the shape a real
RADIUS accounting trail (Accounting-Start/Interim-Update/Stop) produces.
Reusing a row across two different physical connection intervals would
corrupt that interval's own historical accounting (session duration,
per-interval bandwidth) and would misrepresent the actual connect/
disconnect event history analytics/audit needs to reconstruct. This mirrors
``app.domains.voucher.models.Voucher``'s own append-only-per-code
convention and ``OtpRequest.is_consumed``'s one-way state -- see
``constants.GUEST_SESSION_STATUS_TRANSITIONS``.

## ``GuestLoginHistory.guest_id`` nullability

A failed login attempt (wrong OTP code, expired/revoked voucher, blocked
guest, disabled auth method) must still be logged for audit/analytics
visibility, but the identifier presented may not correspond to any real,
already-created ``Guest`` row yet (e.g. someone typing a nonsense phone
number that never got past OTP verification). Mirrors
``app.domains.otp.models.OtpRequest``'s own "self-contained, no forced FK"
posture: ``guest_id`` is populated whenever a real ``Guest`` row for that
identifier+organization already exists (win or lose -- a *known* guest's
failed attempt is still attributed to them), but a failure never
force-creates a ``Guest`` row purely to have something to attach the
history row to. Only a *successful* login (via
``GuestService.get_or_create_guest``) ever creates a new ``Guest`` row.
``identifier`` is therefore always present (the raw presented value),
``guest_id`` is best-effort.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import GuestSessionStatus


class Guest(BaseModel):
    """A returning-guest identity, recognized across visits by
    ``identifier`` -- see module docstring."""

    __tablename__ = "guests"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # "Home" location -- where this guest was first seen. A guest may visit
    # other locations under the same organization over time (see module
    # brief); GuestSession.location_id is never constrained to match this.
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    total_visit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    blocked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_guests_organization_id", "organization_id"),
        Index("ix_guests_location_id", "location_id"),
        Index("ix_guests_identifier", "identifier"),
        Index("ix_guests_is_blocked", "is_blocked"),
        Index(
            "uq_guests_organization_id_identifier",
            "organization_id",
            "identifier",
            unique=True,
        ),
    )

    def __repr__(self) -> str:
        return f"<Guest(id={self.id}, identifier={self.identifier})>"


class GuestDevice(BaseModel):
    """A physical device (by MAC address) seen logging in as some
    ``Guest`` -- see module docstring's "MAC address uniqueness" write-up
    for why ``mac_address`` is globally unique with ``guest_id``
    reassignable."""

    __tablename__ = "guest_devices"

    guest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("guests.id", ondelete="CASCADE"), nullable=False
    )
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False, unique=True)
    device_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index("ix_guest_devices_guest_id", "guest_id"),
        Index("ix_guest_devices_mac_address", "mac_address", unique=True),
    )

    def __repr__(self) -> str:
        return f"<GuestDevice(id={self.id}, mac_address={self.mac_address})>"


class GuestSession(BaseModel):
    """One continuous guest WiFi connection interval on one router -- see
    module docstring's "Sessions are append-only" write-up."""

    __tablename__ = "guest_sessions"

    guest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("guests.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guest_devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    location_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Denormalized from location_id at session-start time -- mirrors
    # app.domains.router.models.Router.organization_id's identical
    # denormalization rationale (see docs/router/ROUTER_ARCHITECTURE.md §1):
    # this module's own analytics queries (GuestAnalyticsService) are
    # tenant-scoped by organization_id on every call, and this column lets
    # them filter directly instead of joining through locations every time.
    # Immutable after creation, like Router's own copy.
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    auth_method: Mapped[str] = mapped_column(String(30), nullable=False)
    voucher_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vouchers.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(20), default=GuestSessionStatus.ACTIVE.value, nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    bytes_uploaded: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    bytes_downloaded: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    # Copied from the redeemed voucher's batch (or a portal/location
    # default) at session-start time -- never a live reference. See
    # service.py's module docstring for the "copied, not referenced"
    # write-up (mirrors Voucher.expires_at's identical reasoning).
    data_limit_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    session_timeout_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    disconnect_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_guest_sessions_guest_id", "guest_id"),
        Index("ix_guest_sessions_device_id", "device_id"),
        Index("ix_guest_sessions_router_id", "router_id"),
        Index("ix_guest_sessions_location_id", "location_id"),
        Index("ix_guest_sessions_organization_id", "organization_id"),
        Index("ix_guest_sessions_voucher_id", "voucher_id"),
        Index("ix_guest_sessions_status", "status"),
        Index("ix_guest_sessions_started_at", "started_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<GuestSession(id={self.id}, guest_id={self.guest_id}, "
            f"status={self.status})>"
        )

    def is_active(self) -> bool:
        return self.status == GuestSessionStatus.ACTIVE.value

    def total_bytes(self) -> int:
        return self.bytes_uploaded + self.bytes_downloaded


class GuestLoginHistory(BaseModel):
    """Every guest login attempt, success or failure -- see module
    docstring's "``guest_id`` nullability" write-up.

    ``organization_id``/``location_id`` are additive beyond the module
    brief's literal field list, nullable FKs, populated whenever a login
    attempt resolved far enough to know its location (which is every
    attempt this module's own ``login_via_otp``/``login_via_voucher``
    ever logs, since ``location_id`` is a required input to both) --
    mirrors ``app.domains.otp.models.OtpRequest.organization_id``/
    ``location_id``'s identical reasoning: carrying tenant scope directly on
    the row lets ``GuestAnalyticsService``'s tenant-scoped queries (e.g.
    OTP success rate) filter without a join through the nullable ``guest_id``
    FK, which failed attempts for an as-yet-unknown identifier never
    populate.
    """

    __tablename__ = "guest_login_history"

    guest_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("guests.id", ondelete="SET NULL"), nullable=True
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_method: Mapped[str] = mapped_column(String(30), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    __table_args__ = (
        Index("ix_guest_login_history_guest_id", "guest_id"),
        Index("ix_guest_login_history_organization_id", "organization_id"),
        Index("ix_guest_login_history_location_id", "location_id"),
        Index("ix_guest_login_history_identifier", "identifier"),
        Index("ix_guest_login_history_auth_method", "auth_method"),
        Index("ix_guest_login_history_success", "success"),
        Index("ix_guest_login_history_attempted_at", "attempted_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<GuestLoginHistory(id={self.id}, identifier={self.identifier}, "
            f"success={self.success})>"
        )


class GuestConsent(BaseModel):
    """A record of a guest accepting a captive portal's terms and
    conditions -- one row per acceptance (a guest may accept more than once
    over time, e.g. after ``terms_version`` changes)."""

    __tablename__ = "guest_consents"

    guest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("guests.id", ondelete="CASCADE"), nullable=False
    )
    captive_portal_config_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("captive_portal_configs.id", ondelete="SET NULL"),
        nullable=True,
    )
    consented_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    terms_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    __table_args__ = (
        Index("ix_guest_consents_guest_id", "guest_id"),
        Index("ix_guest_consents_captive_portal_config_id", "captive_portal_config_id"),
        Index("ix_guest_consents_consented_at", "consented_at"),
    )

    def __repr__(self) -> str:
        return f"<GuestConsent(id={self.id}, guest_id={self.guest_id})>"


class RadiusNasClient(BaseModel):
    """A router's registered FreeRADIUS NAS identity -- a router *is* a
    RADIUS NAS (Network Access Server), one-to-one. See ``service.py``'s
    module docstring for the full ``rlm_rest`` architectural write-up.

    ``shared_secret_encrypted`` is Fernet-encrypted via
    ``app.domains.router.crypto.encrypt_secret`` (reused, not
    reimplemented) rather than hashed: unlike a bearer token/OTP code, a
    RADIUS shared secret must be recoverable in plaintext to compare
    against what FreeRADIUS's ``rlm_rest`` presents on every single
    authorize/accounting call -- the identical reasoning
    ``app.domains.router.models.Router.api_credentials_encrypted`` already
    established for RouterOS API credentials (a live connection needs the
    plaintext back, not just a yes/no hash comparison).
    """

    __tablename__ = "radius_nas_clients"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    nas_identifier: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True
    )
    shared_secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_radius_nas_clients_router_id", "router_id", unique=True),
        Index("ix_radius_nas_clients_nas_identifier", "nas_identifier", unique=True),
        Index("ix_radius_nas_clients_is_active", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<RadiusNasClient(id={self.id}, nas_identifier={self.nas_identifier})>"


__all__ = [
    "Guest",
    "GuestDevice",
    "GuestSession",
    "GuestLoginHistory",
    "GuestConsent",
    "RadiusNasClient",
]
