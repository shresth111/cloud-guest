"""SQLAlchemy ORM models for the Guest Teams domain.

Both tables extend ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does -- Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all
keep working uniformly.

## ``GuestTeam.location_id``: nullable, ``ondelete="SET NULL"``

A team belongs to exactly one organization (real FK, ``NOT NULL``,
``ondelete="CASCADE"`` -- deleting an organization is a genuine tenant
teardown, and its teams should not survive it) and *optionally* to one
location (an org-wide team -- e.g. a company-wide conference cohort visiting
several sites -- vs. a location-specific one -- e.g. one wedding party at one
venue). ``ondelete="SET NULL"`` (not ``CASCADE``) mirrors
``app.domains.guest.models.Guest.location_id``'s identical reasoning, not
``app.domains.voucher.models.VoucherBatch.location_id``'s ``CASCADE``: a
guest team's whole reason to exist is tracking a *group of people* as a
durable unit across a potentially long-lived event; losing precision about
which location record it was originally scoped to (falling back to org-wide)
is a much smaller, more honest consequence than silently deleting the team
--  and, transitively, its entire membership/join-code history -- as a side
effect of an unrelated location housekeeping decision. A voucher batch, by
contrast, is inherently tied to *that* location's own printed-code
inventory, so cascading its deletion is the more honest choice there.

## Why ``created_by_user_id``/``revoked_at``/``revoked_reason`` are not FKs

``created_by_user_id`` is a plain, nullable ``UUID`` column, not a foreign
key to ``users`` -- mirrors ``app.domains.voucher.models.VoucherBatch
.created_by_user_id``/``approved_by_user_id``'s identical, already-
established convention in this same codebase (this module's own directory
boundary means it composes with ``app.domains.user``/``app.domains.auth``
only through the actor id already resolved by RBAC's ``CurrentUser``, never
a new cross-domain FK).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import GuestTeamStatus


class GuestTeam(BaseModel):
    """A named group of guests sharing one access grant -- see module
    docstring and ``constants.GuestTeamStatus`` for the full status-lifecycle
    write-up."""

    __tablename__ = "guest_teams"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # Shareable join code -- reuses app.domains.voucher.constants
    # .VOUCHER_CODE_ALPHABET's exact print-friendly alphabet/generation
    # approach (see constants.py's own docstring). Globally unique, like
    # Voucher.code.
    team_code: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(
        String(20), default=GuestTeamStatus.ACTIVE.value, nullable=False
    )
    # Null means unlimited membership.
    max_members: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # A pooled quota shared across every active member's own sessions --
    # distinct from, and never derived from, any individual GuestSession's
    # own data_limit_mb. Null means no team-level pooling: members simply use
    # their own individual per-session quotas, if any.
    shared_data_limit_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_guest_teams_organization_id", "organization_id"),
        Index("ix_guest_teams_location_id", "location_id"),
        Index("ix_guest_teams_status", "status"),
        Index("ix_guest_teams_team_code", "team_code", unique=True),
        Index("ix_guest_teams_expires_at", "expires_at"),
    )

    def is_team_expired(self, *, now: datetime) -> bool:
        return self.expires_at is not None and now > self.expires_at

    def __repr__(self) -> str:
        return f"<GuestTeam(id={self.id}, name={self.name}, status={self.status})>"


class GuestTeamMember(BaseModel):
    """One membership stint of a :class:`~app.domains.guest.models.Guest` in
    a :class:`GuestTeam`.

    Deliberately append-only-per-stint, mirroring
    ``app.domains.guest.models.GuestSession``'s own "append-only, never
    resurrected" convention (see that module's docstring): rejoining a team
    after being removed creates a **new** row rather than reactivating the
    old one, so each join/leave cycle keeps its own, permanent
    ``joined_at``/``left_at``/``removal_reason`` history instead of a single
    mutable row overwriting its own past. The partial unique index below is
    what makes this safe -- at most one *active* row may exist per
    ``(team_id, guest_id)`` pair at any given time, even though the table may
    hold several terminal (``is_active=False``) rows for that same pair over
    the team's lifetime.
    """

    __tablename__ = "guest_team_members"

    team_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guest_teams.id", ondelete="CASCADE"),
        nullable=False,
    )
    guest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("guests.id", ondelete="CASCADE"), nullable=False
    )
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    left_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    removal_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    __table_args__ = (
        Index("ix_guest_team_members_team_id", "team_id"),
        Index("ix_guest_team_members_guest_id", "guest_id"),
        Index("ix_guest_team_members_is_active", "is_active"),
        # Real, DB-level constraint: a guest cannot be an ACTIVE member of
        # the same team twice -- mirrors the partial-unique-index precedent
        # already established in this codebase (e.g. migration 0026's
        # `uq_locations_location_code`, `organization_members`' own
        # membership-uniqueness index): a plain (non-partial) unique
        # constraint on (team_id, guest_id) would be wrong here, since it
        # would also block the deliberate, documented "rejoin creates a new
        # row" behavior above for a guest who has already left and come back.
        Index(
            "uq_guest_team_members_team_guest_active",
            "team_id",
            "guest_id",
            unique=True,
            postgresql_where=text("is_active = true AND is_deleted = false"),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<GuestTeamMember(id={self.id}, team_id={self.team_id}, "
            f"guest_id={self.guest_id}, is_active={self.is_active})>"
        )


__all__ = ["GuestTeam", "GuestTeamMember"]
