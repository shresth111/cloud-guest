"""SQLAlchemy ORM models for the Organization domain.

Both tables extend ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does -- Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all
keep working uniformly.

Two models:

* :class:`Organization` -- a tenant. ``org_type`` (see ``enums.py``)
  discriminates a plain ``STANDARD`` tenant from an ``MSP`` container; per
  ``docs/rbac/RBAC_ARCHITECTURE.md``'s MSP-modeling note, there is no
  separate MSP table -- an MSP is just an ``Organization`` row that owns
  other ``Organization`` rows via ``parent_organization_id``.
* :class:`OrganizationMember` -- "does this user belong to this
  organization at all", deliberately distinct from RBAC's ``user_roles``
  ("what can this user do"). An invited-but-not-yet-accepted member has no
  roles.

Billing/subscription boundary: this domain intentionally does **not** model
billing plans, invoices, or payment state -- ``PermissionModule.BILLING`` /
``INVOICES`` / ``SUBSCRIPTIONS`` are separate, already-seeded permission
modules reserved for a future Billing domain. ``subscription_tier`` is kept
as a lightweight, nullable *label* only (e.g. ``"starter"``, ``"enterprise"``)
so a future Billing domain has something to key off of; it carries no
pricing/entitlement logic itself.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import BaseModel

from .enums import MembershipStatus, OrganizationType


class Organization(BaseModel):
    """A tenant on the platform -- a plain customer, or an MSP container
    that owns a portfolio of other organizations."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    legal_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    org_type: Mapped[str] = mapped_column(
        String(20), default=OrganizationType.STANDARD.value, nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)

    # Self-FK: an MSP-type organization owns child organizations. NULL for a
    # top-level/direct-customer organization or a top-level MSP.
    parent_organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )

    contact_email: Mapped[str] = mapped_column(String(255), nullable=False)
    contact_phone: Mapped[str | None] = mapped_column(String(20), nullable=True)

    timezone: Mapped[str] = mapped_column(String(50), default="UTC", nullable=False)
    default_locale: Mapped[str] = mapped_column(
        String(10), default="en", nullable=False
    )

    # Extension point: per-org config that does not warrant its own column
    # (e.g. feature flags, branding preferences, notification defaults).
    # Deliberately not modeled as individual columns -- see module docstring.
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )

    # Lightweight label only -- see module docstring's billing boundary note.
    subscription_tier: Mapped[str | None] = mapped_column(String(50), nullable=True)

    parent_organization: Mapped[Organization | None] = relationship(
        "Organization",
        remote_side="Organization.id",
        back_populates="child_organizations",
    )
    child_organizations: Mapped[list[Organization]] = relationship(
        "Organization", back_populates="parent_organization"
    )
    members: Mapped[list[OrganizationMember]] = relationship(
        "OrganizationMember",
        back_populates="organization",
        cascade="all, delete-orphan",
        foreign_keys="OrganizationMember.organization_id",
    )

    __table_args__ = (
        Index("ix_organizations_name", "name"),
        Index("ix_organizations_slug", "slug"),
        Index("ix_organizations_status", "status"),
        Index("ix_organizations_org_type", "org_type"),
        Index("ix_organizations_parent_organization_id", "parent_organization_id"),
        Index("ix_organizations_contact_email", "contact_email"),
    )

    def __repr__(self) -> str:
        return f"<Organization(id={self.id}, slug={self.slug}, type={self.org_type})>"

    def is_msp(self) -> bool:
        return self.org_type == OrganizationType.MSP.value


class OrganizationMember(BaseModel):
    """A user's membership record in an organization.

    Distinct from RBAC's ``user_roles`` -- see module docstring. A partial
    unique index (Postgres-only, see migration ``0003``) enforces that a
    user can hold at most one ``ACTIVE`` membership row per organization at
    a time; the same (organization, user) pair may have multiple rows over
    time (invited -> active -> removed -> re-invited), preserving history.
    """

    __tablename__ = "organization_members"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    status: Mapped[str] = mapped_column(
        String(20), default=MembershipStatus.INVITED.value, nullable=False
    )
    invited_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    invited_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    joined_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_primary_contact: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    organization: Mapped[Organization] = relationship(
        "Organization", back_populates="members", foreign_keys=[organization_id]
    )

    __table_args__ = (
        Index("ix_organization_members_organization_id", "organization_id"),
        Index("ix_organization_members_user_id", "user_id"),
        Index("ix_organization_members_status", "status"),
        Index("ix_organization_members_invited_by_user_id", "invited_by_user_id"),
        Index(
            "ix_organization_members_org_user",
            "organization_id",
            "user_id",
        ),
        Index(
            "uq_organization_members_active_org_user",
            "organization_id",
            "user_id",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<OrganizationMember(organization_id={self.organization_id}, "
            f"user_id={self.user_id}, status={self.status})>"
        )

    def is_active(self) -> bool:
        return self.status == MembershipStatus.ACTIVE.value
