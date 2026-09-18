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

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

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
    # Contact email captured on the customer dashboard's Whitelist form
    # (WhiteList.tsx) -- previously collected client-side, validated, and
    # then silently dropped before the API call. Nullable: guest/device
    # rules created any other way (API, future bulk import) never required
    # one.
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # NULL == never expires (permanent WHITELIST/BLOCKLIST/VIP). Required,
    # in practice, for TEMPORARY -- enforced by
    # validators.validate_rule_expiry, not a DB constraint (mirrors
    # app.domains.voucher's own application-level, not CHECK-constraint,
    # validation posture for similarly conditional fields).
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # -- block enforcement -------------------------------------------------
    #
    # Blocking a guest is not a database fact. The customer dashboard's own
    # copy promises that a block "takes effect immediately, ending any
    # session these users currently have", and until these four columns
    # existed nothing recorded whether that had happened, because nothing
    # attempted it. They mirror ``Vlan.device_push_status``/
    # ``device_push_error``/``device_pushed_at`` field for field, and for
    # the same reason: an operator must be able to tell a block that
    # reached the router from one that only reached Postgres.
    #
    # See ``constants.BlockEnforcementStatus`` for the four values and why
    # "not applicable" and "unenforced" are deliberately not the same one.
    enforcement_status: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )
    enforcement_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    enforced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # How many live sessions were confirmed ended -- confirmed against the
    # router's own active table, never counted from what was attempted.
    sessions_ended: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # -- controller-side device blocks -------------------------------------
    #
    # Populated only at a venue whose network is run from a vendor
    # controller, and only for ``BLOCKLIST`` rules. Loaded eagerly because
    # the one screen that reads a rule is the one that must render what
    # happened to each device, and a per-row lazy load there is N+1 on a
    # list endpoint.
    #
    # **Not** ``cascade="all, delete-orphan"``. These rows are the only
    # record of what this platform asked a controller to hold, and the
    # controller offers no readable list of blocked clients
    # (``providers/omada.py::_BLOCKED_LIST_REASON``), so a row deleted
    # alongside its rule would strand a real customer's device with nothing
    # anywhere able to find it again. The service releases the blocks
    # *before* it deletes the rule; see ``GuestAccessService
    # .delete_guest_rule``.
    controller_blocks: Mapped[list[GuestAccessControllerBlock]] = relationship(
        "GuestAccessControllerBlock",
        lazy="selectin",
        order_by="GuestAccessControllerBlock.mac_address",
        viewonly=False,
    )

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
    # See GuestAccessRule.email's docstring -- identical "captured on the
    # dashboard form, previously dropped before the API call" fix.
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
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


class GuestAccessControllerBlock(BaseModel):
    """One device MAC this platform asked a venue's controller to block on
    behalf of a :class:`GuestAccessRule`, and what the controller said.

    ## Why this table exists at all

    A ``BLOCKLIST`` rule names a *person* -- a phone number or an email.
    A controller blocks a *MAC*. Bridging the two means resolving the
    guest's known devices and issuing one write per device, which produces
    a result that is genuinely per-device: three of five blocked, one the
    controller has never seen, one it refused. A single status column on
    the rule cannot hold that, and rounding it to one value is how a venue
    ends up believing five devices are blocked when three are.

    ## Why it is persisted rather than reported and forgotten

    **There is no readable list of blocked clients through the connection
    this platform holds.** Measured, not assumed: the controller's own
    ``filters.blocked`` parameter is silently ignored, and the Open API
    client grid carries no block field at all (see
    ``network_integration.providers.omada.OmadaProvider._BLOCKED_LIST_REASON``
    and CAPABILITY-MATRIX §4.4). So a MAC blocked and then forgotten is a
    device nobody can find again from the controller, on a venue's own
    network, with no row anywhere explaining why it cannot associate.

    That is the same defect class as the stale ``/queue simple`` rows a
    RouterOS venue accumulated, and strictly worse: a randomized MAC that
    comes back blocked has no trace at all. So every block this platform
    writes is recorded here before it is reported to anyone, and
    ``cleared_at`` is what says the controller has been told to let it go.

    A row with ``status == ENFORCED`` and ``cleared_at IS NULL`` is this
    platform's standing claim that the venue's controller is still holding
    a block it put there. Those rows -- and only those -- are what an
    unblock, a rule deletion and the expiry sweep read.

    ## Keyed by (rule, location, MAC)

    ``location_id`` is not derivable from the rule: an organization-wide
    rule has none, and the venue is then the one the guest's live session
    was on. A controller block is per-site, so the venue has to be on the
    row or a later unblock cannot name the site to clear it at.
    """

    __tablename__ = "guest_access_controller_blocks"

    # Stored rather than joined through ``rule_id``, for the reason
    # ``network_integration_events.organization_id`` documents: every read
    # here is tenant-scoped, and a tenant filter that depends on a join is
    # one a future query can silently omit while still returning another
    # tenant's rows.
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guest_access_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    # NOT NULL, unlike the rule's own: a controller block is per-site, so
    # "every location" is not a thing this row can mean.
    location_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Canonical uppercase colon form -- the same spelling
    # ``network_integration.validators.normalize_client_mac`` produces, so
    # this table can be compared against that domain's own rows without a
    # second normalizer.
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    # One of ``constants.BlockEnforcementStatus``. Deliberately the *same*
    # enum the rule carries rather than a second vocabulary -- see that
    # enum's docstring for how each of its values reads per device.
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    # The vendor's own normalized code, kept because ``performed: false``
    # conflates two different facts. ``OMADA_CLIENT_NOT_FOUND`` means the
    # controller has no record of this device (there was nothing to block);
    # any other code means it had one and refused.
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: When the controller confirmed the block. ``None`` unless
    #: ``status`` is ``ENFORCED``.
    blocked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: When this platform confirmed the controller had released it.
    #: ``NULL`` on an ``ENFORCED`` row means the block is still out there.
    cleared_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Why the release failed, when one was attempted and did not land.
    #: A row can be un-cleared *and* carry this: that is a device this
    #: platform believes is still blocked and could not free.
    release_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_guest_access_controller_blocks_rule_id", "rule_id"),
        Index(
            "ix_guest_access_controller_blocks_organization_id", "organization_id"
        ),
        Index("ix_guest_access_controller_blocks_location_id", "location_id"),
        # The sweep's own query: "blocks still believed to be held". Leading
        # with ``cleared_at`` keeps it useful as the table grows, since the
        # uncleared rows are the small end of it.
        Index(
            "ix_guest_access_controller_blocks_open",
            "cleared_at",
            "rule_id",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<GuestAccessControllerBlock(id={self.id}, "
            f"mac_address={self.mac_address}, status={self.status})>"
        )
