"""SQLAlchemy ORM models for the Policy domain.

Three tables, matching ``docs/ARCHITECTURE_DESIGN.md`` §6.1's ``policy``
module profile exactly:

* :class:`Policy` -- the aggregate root. One row per named policy
  definition: a ``policy_type`` discriminator (``constants.PolicyType``) and
  a pointer (``current_version_id``) at whichever :class:`PolicyVersion` is
  currently active. ``organization_id`` is **nullable**: ``NULL`` means a
  platform-wide policy definition (available to every organization as a
  resolution candidate); non-``NULL`` means an organization's own custom
  policy of that type. This mirrors ``notification_templates
  .organization_id``'s identical "nullable FK signals platform default"
  convention already named in ``docs/ARCHITECTURE_DESIGN.md`` §15.
* :class:`PolicyVersion` -- an immutable, append-only snapshot of a policy's
  ``rules`` (a validated JSONB payload -- see ``schemas.POLICY_RULE_SCHEMAS``)
  at a point in time. Mirrors ``GuestSession``'s own "sessions are
  append-only" precedent: editing a policy's rules never mutates an existing
  ``PolicyVersion`` row, it creates a new one (see ``service.py``'s
  docstring).
* :class:`PolicyAssignment` -- attaches a :class:`Policy` to a scope
  (``organization`` or ``location``, reusing ``app.domains.rbac.enums
  .ScopeType`` rather than inventing a parallel enum -- see this module's own
  docstring in ``rbac.enums`` for the identical broad/narrow scope shape this
  reuses) with a ``priority`` for tie-breaking multiple assignments at the
  same scope. ``scope_id`` is ``NULL`` iff ``scope_type`` is ``GLOBAL``
  (there is no narrower id for a platform-wide assignment).

## The ``Policy.current_version_id`` <-> ``PolicyVersion.policy_id`` cycle

These two FKs point at each other's tables. This is intentional (an explicit
"current version" pointer is what makes ``rollback`` a real, one-column
operation rather than an inferred "highest version_number" query that could
never point backwards -- see ``service.PolicyService.rollback``'s
docstring) and is handled the same way any two mutually-referencing tables
are: the migration creates both tables first, then adds
``Policy.current_version_id``'s foreign key constraint via a separate
``op.create_foreign_key`` call once both tables exist (see
``alembic/versions/0029_create_policy_tables.py``). SQLAlchemy's own mapper
configuration has no trouble with this at the ORM layer since both classes
exist in this same module by the time mappers are configured.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import PolicyVersionStatus


class Policy(BaseModel):
    """A named policy definition -- see module docstring."""

    __tablename__ = "policies"

    # NULL == platform-wide policy definition, available as a resolution
    # candidate to every organization. Non-NULL == this organization's own
    # custom policy. See module docstring.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    policy_type: Mapped[str] = mapped_column(String(30), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # NULL until the first PolicyVersion is published -- see
    # PolicyAssignmentRequiresPublishedVersionError: a Policy with no
    # published version cannot be assigned to any scope.
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policy_versions.id", ondelete="SET NULL", use_alter=True),
        nullable=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index("ix_policies_organization_id", "organization_id"),
        Index("ix_policies_policy_type", "policy_type"),
        Index("ix_policies_is_active", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<Policy(id={self.id}, name={self.name}, type={self.policy_type})>"


class PolicyVersion(BaseModel):
    """An immutable, append-only snapshot of a :class:`Policy`'s rules -- see
    module docstring and ``constants.PolicyVersionStatus`` for the full
    lifecycle write-up."""

    __tablename__ = "policy_versions"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    # 1, 2, 3, ... per policy_id -- see repository.py's
    # get_next_version_number.
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default=PolicyVersionStatus.DRAFT.value, nullable=False
    )
    # The validated policy configuration itself -- see
    # schemas.POLICY_RULE_SCHEMAS for the per-PolicyType Pydantic shape this
    # is validated against before being persisted.
    rules: Mapped[dict[str, object]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index("ix_policy_versions_policy_id", "policy_id"),
        Index("ix_policy_versions_status", "status"),
        Index(
            "uq_policy_versions_policy_id_version_number",
            "policy_id",
            "version_number",
            unique=True,
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<PolicyVersion(id={self.id}, policy_id={self.policy_id}, "
            f"version_number={self.version_number}, status={self.status})>"
        )


class PolicyAssignment(BaseModel):
    """Attaches a :class:`Policy` to a scope -- see module docstring for why
    this reuses ``app.domains.rbac.enums.ScopeType`` rather than a parallel
    enum, and why ``scope_id`` is nullable.

    ``target_type``/``target_id`` (Enterprise SaaS Phase F) are a second,
    orthogonal WHO axis layered on top of the existing WHERE axis above --
    see ``constants.PolicyAssignmentTargetType``'s own docstring for why
    this is a new, ``policy``-local enum rather than added to
    ``ScopeType`` itself. ``target_type`` defaults to ``NONE`` so every
    pre-Phase-F row (and every new row that doesn't set it) behaves
    identically to before this axis existed: "applies to everyone within
    the WHERE scope"."""

    __tablename__ = "policy_assignments"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    # One of app.domains.rbac.enums.ScopeType's values ("global" /
    # "organization" / "location"), stored as plain String for the same
    # "additive StrEnum member, no migration" reason every other domain's
    # status/type column already is.
    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # NULL iff scope_type == "global". Points at an organizations.id or
    # locations.id row depending on scope_type -- deliberately not a real FK
    # (a single column cannot FK two different tables conditionally; this is
    # the same polymorphic-scope shape app.domains.rbac's own role
    # assignments already use for an identical reason).
    scope_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    # WHO this assignment additionally targets -- one of
    # constants.PolicyAssignmentTargetType's values. NULL-equivalent default
    # is "none" (untargeted), not a nullable column, so every row always has
    # an explicit, queryable WHO-tier.
    target_type: Mapped[str] = mapped_column(
        String(20), default="none", server_default="none", nullable=False
    )
    # NULL iff target_type == "none". Points at a users.id or roles.id row
    # depending on target_type -- deliberately not a real FK, the same
    # polymorphic-column reasoning scope_id's own docstring above gives.
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    # Tie-breaker when more than one active assignment matches the same
    # resolved scope (see service.PolicyResolver.resolve) -- higher wins.
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index("ix_policy_assignments_policy_id", "policy_id"),
        Index("ix_policy_assignments_scope_type", "scope_type"),
        Index("ix_policy_assignments_scope_id", "scope_id"),
        Index("ix_policy_assignments_is_active", "is_active"),
        Index("ix_policy_assignments_target_type", "target_type"),
        Index("ix_policy_assignments_target_id", "target_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<PolicyAssignment(id={self.id}, policy_id={self.policy_id}, "
            f"scope_type={self.scope_type}, scope_id={self.scope_id}, "
            f"target_type={self.target_type})>"
        )


__all__ = ["Policy", "PolicyVersion", "PolicyAssignment"]
