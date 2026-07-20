"""SQLAlchemy ORM models for the Guest Access Control domain (Phase 1).

Two tables, deliberately independent of ``app.domains.guest``'s own
``Guest``/``GuestDevice`` tables -- no foreign key to either:

* :class:`GuestAccessRule` -- keyed by the guest's login ``identifier``
  (phone/email/etc., the same string ``Guest.identifier`` already holds),
  not by ``guest_id``. This is a deliberate choice, not an oversight: a
  rule needs to exist and take effect *before* a ``Guest`` row is ever
  created (e.g. "always deny this email" for someone who has never tried to
  connect, or "grant VIP access to this phone number" ahead of a guest's
  first visit) -- ``Guest`` rows are only ever created lazily, on first
  login (see ``app.domains.guest.service`` module docstring). Keying by
  identifier also means a rule survives independently of whatever
  ``Guest.id`` this platform eventually assigns, and needs no join to be
  evaluated.
* :class:`DeviceAccessRule` -- keyed by ``mac_address``, the identical
  "identifier, not a foreign key" reasoning, mirroring
  ``app.domains.guest.models.GuestDevice.mac_address``'s own global
  uniqueness (a MAC is a real-world identity that outlives any one
  ``GuestDevice`` row).

Both share a ``rule_type`` (see ``constants.AccessRuleType``) covering four
of the roadmap's five "Guest Access Control" concepts in one column:
``WHITELIST``/``BLOCKLIST`` (permanent allow/deny), ``TEMPORARY`` (a
bounded-window allow, via ``expires_at``), and ``VIP`` (an unconditional,
highest-precedence allow). See ``service.AccessDecisionResolver`` for the
precedence order these four are resolved in. There is no separate table per
rule type -- exactly the same "one column, not one table per variant"
judgment call ``app.domains.guest.constants.GuestSessionStatus`` already
makes for session lifecycle status.

Both extend ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version) for the same reason every other domain does --
``GenericRepository``/Alembic autogenerate/cross-domain FKs all keep
working uniformly.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class GuestAccessRule(BaseModel):
    """An allow/deny rule keyed by a guest login ``identifier`` -- see
    module docstring for why this is identifier-keyed, not
    ``guest_id``-keyed."""

    __tablename__ = "guest_access_rules"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # NULL == organization-wide (every location). Non-NULL scopes the rule
    # to one location -- mirrors app.domains.voucher.models.VoucherBatch
    # .location_id's identical "NULL means org-wide" convention.
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=True,
    )
    identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_type: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # NULL == never expires (permanent WHITELIST/BLOCKLIST/VIP). Required,
    # in practice, for TEMPORARY -- enforced by
    # validators.validate_rule_expiry, not a DB constraint (mirrors
    # app.domains.voucher's own application-level, not CHECK-constraint,
    # validation posture for similarly conditional fields).
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_guest_access_rules_organization_id", "organization_id"),
        Index("ix_guest_access_rules_location_id", "location_id"),
        Index("ix_guest_access_rules_identifier", "identifier"),
        Index("ix_guest_access_rules_rule_type", "rule_type"),
        Index("ix_guest_access_rules_is_active", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<GuestAccessRule(id={self.id}, identifier={self.identifier}, "
            f"rule_type={self.rule_type})>"
        )


class DeviceAccessRule(BaseModel):
    """An allow/deny rule keyed by a device's ``mac_address`` -- see module
    docstring for why this is MAC-keyed, not ``device_id``-keyed."""

    __tablename__ = "device_access_rules"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=True,
    )
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    rule_type: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_device_access_rules_organization_id", "organization_id"),
        Index("ix_device_access_rules_location_id", "location_id"),
        Index("ix_device_access_rules_mac_address", "mac_address"),
        Index("ix_device_access_rules_rule_type", "rule_type"),
        Index("ix_device_access_rules_is_active", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<DeviceAccessRule(id={self.id}, mac_address={self.mac_address}, "
            f"rule_type={self.rule_type})>"
        )
