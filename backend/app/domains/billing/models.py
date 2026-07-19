"""SQLAlchemy ORM models for the Billing domain (BE-013 Part 1: Plan +
License + Usage Core).

All tables extend ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does -- Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all
keep working uniformly.

Five tables:

* :class:`Plan` -- the pricing/entitlement catalog. A row a Super Admin
  (unlimited plans, per the spec) creates; ``is_public`` controls whether it
  appears on a general pricing listing or is only reachable by an org whose
  ``License`` already points at it (a negotiated, private plan).
* :class:`PlanFeature` -- one entitlement/limit row per ``(plan_id,
  feature_key)`` pair. See its own docstring for the three-typed-column
  value-storage decision.
* :class:`License` -- what one organization is actually entitled to, right
  now. **One row per organization, ever** (``organization_id`` unique) --
  see its own docstring for why this mirrors
  ``app.domains.wireguard.models.WireGuardPeer.router_id``'s identical
  one-to-one, mutated-in-place cardinality rather than an append-only
  history table.
* :class:`LicenseChangeLog` -- the real, multi-hop upgrade/downgrade/assign
  audit history a single ``previous_plan_id`` column on ``License`` could
  never fully capture (see ``License``'s own docstring for the full
  decision write-up).
* :class:`UsageMetric` -- one row per ``(organization_id, metric_key,
  period_start)`` snapshot of real, composed usage (see
  ``service.UsageService.record_current_usage`` for exactly how each value
  is computed -- never fabricated).

## ``Organization.subscription_tier`` relationship (read this first)

``app.domains.organization.models.Organization.subscription_tier`` has
existed since Module 005 as a deliberately lightweight, unpopulated,
nullable *label*, with that module's own docstring explicitly reserving it
for "a future Billing domain" and disclaiming "no pricing/entitlement logic
behind it". This module is that reserved Billing domain arriving, and the
decision made here is explicit: **``License``/``Plan`` become the real
source of truth for what an organization is entitled to; ``subscription_tier``
becomes a denormalized, best-effort convenience label kept in sync**, not a
second, independent concept a caller could set out of step with the real
license. Concretely: every ``LicenseService`` call that changes which plan
backs an organization's license (``assign_license``/``upgrade_license``/
``downgrade_license``) calls a new, narrow, additive method this module adds
to ``OrganizationService`` -- ``sync_subscription_tier`` -- which does
nothing but write ``Organization.subscription_tier = plan.slug`` (see
``app.domains.organization.service.OrganizationService.sync_subscription_tier``
for the exact, minimal edit, and ``docs/billing/FLOW.md`` §1 for why this is
judged a narrow, additive, well-justified exception to "never touch other
domains' internals" rather than a violation of it: this module's entire
purpose is to give that reserved field real meaning, and every other reader
of ``subscription_tier`` across the existing BE-012 Analytics module
continues to work completely unmodified -- it just now reads a real,
billing-backed value instead of a hand-set approximation). Nothing in this
module ever reads ``subscription_tier`` back -- ``License``/``Plan`` are
always the read-side source of truth; the organization column is
write-only from this module's perspective, purely for any existing reader
(e.g. Analytics' own ``Plan Distribution`` ``GROUP BY``) that still expects
it to be populated.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import BaseModel

from .constants import DEFAULT_PLAN_CURRENCY


class Plan(BaseModel):
    """One row in the pricing/entitlement catalog.

    ``base_price`` is a real ``Numeric(12, 2)`` -- never ``Float`` -- the
    same non-negotiable correctness rule every real billing system follows
    (binary floating point cannot represent most decimal currency amounts
    exactly; see ``docs/billing/FLOW.md`` §2). ``created_by_user_id`` is a
    plain, unconstrained ``UUID`` column with **no** SQL foreign key --
    mirrors this codebase's established "who did this" convention for
    cross-domain actor columns (e.g.
    ``app.domains.monitoring.models.Alert.acknowledged_by_user_id``,
    ``app.domains.router_provisioning.models.RouterEnrollmentRequest
    .reviewed_by_user_id``) -- ``NULL`` for a system-seeded standard plan,
    set for a Super-Admin-created custom/negotiated one.
    """

    __tablename__ = "plans"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    plan_type: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # NOT nullable -- BillingCycle.NONE (see constants.py) is the explicit
    # "no fixed cadence" member, so this column is always a real, queryable
    # value, never an ambiguous NULL.
    billing_cycle: Mapped[str] = mapped_column(String(20), nullable=False)
    base_price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    currency: Mapped[str] = mapped_column(
        String(3), default=DEFAULT_PLAN_CURRENCY, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Public pricing-page visibility -- see module docstring. A private
    # plan is still fully usable (a License can reference it), just not
    # returned by the general, unauthenticated-scope plan listing.
    is_public: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    sort_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    features: Mapped[list[PlanFeature]] = relationship(
        "PlanFeature",
        back_populates="plan",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_plans_slug", "slug"),
        Index("ix_plans_plan_type", "plan_type"),
        Index("ix_plans_is_active", "is_active"),
        Index("ix_plans_is_public", "is_public"),
        Index("ix_plans_sort_order", "sort_order"),
    )

    def __repr__(self) -> str:
        return f"<Plan(id={self.id}, slug={self.slug}, plan_type={self.plan_type})>"


class PlanFeature(BaseModel):
    """One entitlement/limit row for a :class:`Plan`, keyed by
    ``constants.PlanFeatureKey``.

    ## Value-storage decision: three typed, nullable columns -- not one JSONB blob

    ``constants.PlanFeatureType`` gives every feature key exactly one of
    three value shapes: a numeric ceiling (``LIMIT`` -- e.g.
    ``MAX_GUESTS``), an on/off switch (``BOOLEAN`` -- e.g.
    ``WHITE_LABEL``), or a closed small-string tier (``TIER`` -- the one
    ``SUPPORT_LEVEL`` feature, ``constants.SupportTier``). Rather than
    cramming all three shapes into one JSONB ``value`` column (which would
    require every reader to know, out of band, which shape to expect and
    how to parse it, and would make "give me every plan whose
    ``MAX_GUESTS`` limit is >= 500" an un-indexable JSON-path query), this
    model uses three plain, nullable, precisely-typed columns --
    ``limit_value`` (``Numeric``, so a limit can be fractional if a future
    feature key needs that, e.g. a rate), ``is_enabled`` (``Boolean``), and
    ``tier_value`` (``String``) -- with exactly one populated per row,
    determined entirely by ``feature_type``. This is more verbose than one
    JSONB column but is directly queryable/indexable and self-documenting:
    reading a row never requires knowing anything beyond its own
    ``feature_type`` to know which column to read.

    A ``UniqueConstraint`` on ``(plan_id, feature_key)`` prevents two
    conflicting rows for the same feature on the same plan.
    """

    __tablename__ = "plan_features"

    plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("plans.id", ondelete="CASCADE"), nullable=False
    )
    feature_key: Mapped[str] = mapped_column(String(50), nullable=False)
    feature_type: Mapped[str] = mapped_column(String(20), nullable=False)
    limit_value: Mapped[Decimal | None] = mapped_column(Numeric(18, 2), nullable=True)
    is_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    tier_value: Mapped[str | None] = mapped_column(String(20), nullable=True)

    plan: Mapped[Plan] = relationship("Plan", back_populates="features")

    __table_args__ = (
        UniqueConstraint(
            "plan_id", "feature_key", name="uq_plan_features_plan_feature"
        ),
        Index("ix_plan_features_plan_id", "plan_id"),
        Index("ix_plan_features_feature_key", "feature_key"),
    )

    def __repr__(self) -> str:
        return (
            f"<PlanFeature(plan_id={self.plan_id}, feature_key={self.feature_key}, "
            f"feature_type={self.feature_type})>"
        )


class License(BaseModel):
    """What one organization is actually entitled to, right now.

    ## Cardinality decision: one row per organization, ever

    ``organization_id`` is **unique** -- an organization has at most one
    ``License`` row for its entire lifetime, mutated in place through
    ``constants.LicenseStatus``'s transition graph and re-pointed at a new
    ``plan_id`` on upgrade/downgrade. This mirrors
    ``app.domains.wireguard.models.WireGuardPeer.router_id``'s identical
    one-to-one, mutated-in-place design (see that model's own docstring for
    the "previous state has no standalone value once superseded" reasoning)
    rather than an append-only history-of-licenses table: an organization's
    *previous* license state is not itself independently meaningful the way
    e.g. a router config version is -- what matters is (a) what the
    organization is entitled to *now* and (b) a full record of *when it
    changed and to what*, which is exactly what :class:`LicenseChangeLog`
    provides without a second, redundant "current license" row to keep in
    sync.

    ## No ``previous_plan_id`` column (a deliberate non-decision)

    A single ``previous_plan_id`` column was considered and rejected: it
    can only ever record the *one* most recent hop, silently losing every
    earlier upgrade/downgrade the moment a second change happens -- exactly
    the "half-done" history the spec warns against. Since
    :class:`LicenseChangeLog` already records every hop in full (from-plan,
    to-plan, when, by whom, why), a redundant single-column shortcut on
    this table would either drift out of sync with the log or be pure
    duplication of its own most-recent row -- neither is worth the column.
    Anyone needing "what was this org's plan before the last change" reads
    the log's most recent row instead.

    ``expires_at`` is nullable -- ``NULL`` means no fixed term (an ongoing
    MSP arrangement, or a plan with ``billing_cycle = NONE``).
    """

    __tablename__ = "licenses"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("plans.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    suspended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    suspended_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    change_logs: Mapped[list[LicenseChangeLog]] = relationship(
        "LicenseChangeLog",
        back_populates="license",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_licenses_organization_id", "organization_id", unique=True),
        Index("ix_licenses_plan_id", "plan_id"),
        Index("ix_licenses_status", "status"),
        Index("ix_licenses_expires_at", "expires_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<License(organization_id={self.organization_id}, "
            f"plan_id={self.plan_id}, status={self.status})>"
        )


class LicenseChangeLog(BaseModel):
    """One row per assign/upgrade/downgrade of a :class:`License` -- the
    real, multi-hop audit history ``License`` itself deliberately does not
    keep (see that model's own docstring). ``from_plan_id`` is ``NULL`` only
    for the very first row (the initial ``assign_license`` call, which has
    no prior plan); every subsequent row always has both ends populated.
    ``changed_by_user_id`` is a plain, unconstrained ``UUID`` column with no
    SQL foreign key, mirroring ``Plan.created_by_user_id``'s identical
    convention.
    """

    __tablename__ = "license_change_logs"

    license_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("licenses.id", ondelete="CASCADE"),
        nullable=False,
    )
    from_plan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("plans.id", ondelete="SET NULL"), nullable=True
    )
    to_plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("plans.id", ondelete="RESTRICT"), nullable=False
    )
    change_type: Mapped[str] = mapped_column(String(20), nullable=False)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    license: Mapped[License] = relationship("License", back_populates="change_logs")

    __table_args__ = (
        Index("ix_license_change_logs_license_id", "license_id"),
        Index("ix_license_change_logs_changed_at", "changed_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<LicenseChangeLog(license_id={self.license_id}, "
            f"change_type={self.change_type})>"
        )


class UsageMetric(BaseModel):
    """One recorded value of one ``constants.UsageMetricKey`` for one
    organization over ``[period_start, period_end]``.

    ``value`` is ``Numeric(18, 2)``, not ``Float`` -- consistent with this
    module's own "never float for a number that feeds a billing decision"
    rule (a usage count directly gates limit enforcement, the same
    correctness bar as money). See
    ``service.UsageService.record_current_usage`` for exactly how each
    metric key's value is computed (real composed aggregates, never
    fabricated), and ``docs/billing/FLOW.md`` §6 for the two honestly-
    unavailable metrics (``STORAGE_USAGE_MB``/``API_REQUESTS``) recorded as
    ``0`` with no real data source anywhere in this codebase yet.
    """

    __tablename__ = "usage_metrics"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    metric_key: Mapped[str] = mapped_column(String(30), nullable=False)
    period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    value: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index("ix_usage_metrics_organization_id", "organization_id"),
        Index("ix_usage_metrics_metric_key", "metric_key"),
        Index("ix_usage_metrics_period_start", "period_start"),
        Index(
            "ix_usage_metrics_org_metric_period",
            "organization_id",
            "metric_key",
            "period_start",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<UsageMetric(organization_id={self.organization_id}, "
            f"metric_key={self.metric_key}, value={self.value})>"
        )


__all__ = [
    "Plan",
    "PlanFeature",
    "License",
    "LicenseChangeLog",
    "UsageMetric",
]
