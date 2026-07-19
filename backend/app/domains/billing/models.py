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


# ============================================================================
# BE-013 Part 2: Subscription + Coupon
# ============================================================================


class Subscription(BaseModel):
    """What one organization's *billing arrangement* looks like, right now.

    ## Cardinality decision: one row per organization, ever

    Exactly mirrors :class:`License`'s own decision (see that model's
    docstring for the full write-up): ``organization_id`` is **unique**.
    ``Subscription`` is mutated in place through
    ``constants.SubscriptionStatus``'s transition graph -- there is no
    append-only "subscription history" table, because (like ``License``)
    what matters is "what is this organization's billing arrangement *now*"
    plus a full record of *when it changed* (here, that record is spread
    across ``LicenseChangeLog`` (plan changes), ``CouponUsage`` (coupon
    redemptions), and this module's own structured log lines/events for
    every lifecycle transition -- no single append-only table was judged to
    carry enough independent value to justify a sixth table for it).

    ## ``plan_id`` denormalization -- justified, not just copied for
    ## convenience

    ``plan_id`` duplicates what ``license_id`` -> ``License.plan_id``
    already tells you. It is kept anyway, deliberately, for two concrete
    reasons: (1) every subscription-list/renewal-sweep query in this module
    (``renewal_service.RenewalService.process_renewal``,
    ``list_due_for_renewal``) needs the plan's ``base_price``/
    ``billing_cycle``/``currency`` on every single row it touches, and
    joining through ``license_id`` -> ``licenses.plan_id`` -> ``plans`` on
    every renewal-sweep tick is real, avoidable query overhead for a value
    that is 1:1 with the license at read time anyway; (2) a subscription's
    plan and a license's plan are **kept in lockstep by this module's own
    service methods** (``SubscriptionService`` never changes a license's
    plan without also updating the owning subscription's ``plan_id`` in the
    same operation), so the duplication cannot silently drift the way an
    uncoordinated cache could. This is the same judgment call
    ``Subscription.billing_cycle`` makes below, just for a foreign key
    instead of a scalar.

    ## ``billing_cycle`` -- a snapshot copy, not a live read of ``Plan``

    Copied from ``Plan.billing_cycle`` at subscription-creation time (never
    re-read from ``Plan`` afterward), for the same "copy, not reference"
    principle ``CouponUsage.discount_amount_applied`` documents below: if a
    Super Admin later edits the referenced ``Plan``'s ``billing_cycle``,
    an already-running subscription's own billing cadence should not
    silently change out from under it mid-term.

    ## Status transition graph -- see ``constants.SubscriptionStatus``'s own
    docstring for the full write-up (mirrors ``License``'s identical
    "define every legal transition, reject everything else" rigor via
    ``service._SUBSCRIPTION_TRANSITIONS``/``_assert_subscription_transition``).

    ## Three additive bookkeeping columns beyond the literal spec list

    ``past_due_at``, ``last_renewal_reminder_sent_at``, and
    ``last_expiry_reminder_sent_at`` are not in BE-013 Part 2's own bullet
    list of ``Subscription`` columns, but each is a genuine correctness
    requirement, not a nice-to-have:

    * ``past_due_at`` -- when this subscription *most recently* entered
      ``PAST_DUE`` (cleared the moment it recovers to ``ACTIVE``). Without
      it, "how long has this subscription been unpaid" -- the entire basis
      for the configurable grace period before
      ``renewal_service.RenewalService.expire_lapsed_subscriptions`` calls
      ``LicenseService.expire_license`` -- could not be computed at all.
    * ``last_renewal_reminder_sent_at`` / ``last_expiry_reminder_sent_at``
      -- idempotency markers so an hourly Beat sweep sends each reminder
      **once** per billing period / per past-due episode, not once per
      hourly tick for the entire multi-day reminder window. Mirrors
      ``app.domains.analytics.models.ScheduledReport.last_run_at``'s
      identical "a periodic sweep needs its own bookkeeping to avoid
      re-firing" reasoning.
    """

    __tablename__ = "subscriptions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    license_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("licenses.id", ondelete="RESTRICT"),
        nullable=False,
    )
    # Denormalized from the owning License -- see module docstring.
    plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("plans.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    # Snapshot copy of Plan.billing_cycle at creation time -- see module
    # docstring.
    billing_cycle: Mapped[str] = mapped_column(String(20), nullable=False)
    current_period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    current_period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    trial_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    cancel_at_period_end: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    applied_coupon_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("coupons.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Additive bookkeeping columns -- see module docstring.
    past_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_renewal_reminder_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_expiry_reminder_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_subscriptions_organization_id", "organization_id", unique=True),
        Index("ix_subscriptions_license_id", "license_id"),
        Index("ix_subscriptions_plan_id", "plan_id"),
        Index("ix_subscriptions_status", "status"),
        Index("ix_subscriptions_current_period_end", "current_period_end"),
        Index("ix_subscriptions_applied_coupon_id", "applied_coupon_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<Subscription(organization_id={self.organization_id}, "
            f"plan_id={self.plan_id}, status={self.status})>"
        )


class Coupon(BaseModel):
    """A discount code -- global (``organization_id IS NULL``, usable by any
    organization) or organization-specific.

    ## ``applicable_plan_ids`` storage shape: a real join table, not a
    ## JSONB list

    The spec's own suggested shape was a nullable JSONB list of plan UUIDs.
    This module instead uses a real join table, :class:`CouponPlan`
    (``coupon_id``, ``plan_id``, unique together) -- the exact same
    "typed, referentially-integral columns over an untyped blob" judgment
    call ``PlanFeature``'s own docstring already makes for this domain (see
    that model's "three typed columns, not one JSONB blob" write-up). A
    JSONB list of plan UUIDs cannot be declared as a real foreign key: a
    plan referenced by a coupon could later be hard-deleted (this domain
    never does that today, but nothing would stop a future change from
    doing so) with no database-level protection or cascade, and "does this
    coupon apply to plan X" would be an un-indexable JSON-containment
    query instead of a plain, indexed join. An empty/no-rows
    ``CouponPlan`` set for a coupon means "applicable to all plans" (see
    ``service.CouponService.validate_coupon``), exactly the same "empty ==
    unrestricted" semantics the spec's own JSONB suggestion described.
    """

    __tablename__ = "coupons"

    code: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    discount_type: Mapped[str] = mapped_column(String(20), nullable=False)
    discount_value: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    # Only meaningful for FLAT-shaped coupons; NULL for PERCENTAGE.
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    # NULL = a GLOBAL coupon, usable by any organization. Non-NULL = usable
    # only by that one organization.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    max_uses: Mapped[int | None] = mapped_column(Integer, nullable=True)
    current_uses: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    plan_associations: Mapped[list[CouponPlan]] = relationship(
        "CouponPlan",
        back_populates="coupon",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_coupons_code", "code"),
        Index("ix_coupons_organization_id", "organization_id"),
        Index("ix_coupons_is_active", "is_active"),
        Index("ix_coupons_valid_until", "valid_until"),
    )

    def __repr__(self) -> str:
        return (
            f"<Coupon(id={self.id}, code={self.code}, "
            f"discount_type={self.discount_type})>"
        )


class CouponPlan(BaseModel):
    """One ``(coupon_id, plan_id)`` association row -- see :class:`Coupon`'s
    docstring for why this is a real join table, not a JSONB list."""

    __tablename__ = "coupon_plans"

    coupon_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("coupons.id", ondelete="CASCADE"), nullable=False
    )
    plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("plans.id", ondelete="CASCADE"), nullable=False
    )

    coupon: Mapped[Coupon] = relationship("Coupon", back_populates="plan_associations")

    __table_args__ = (
        UniqueConstraint("coupon_id", "plan_id", name="uq_coupon_plans_coupon_plan"),
        Index("ix_coupon_plans_coupon_id", "coupon_id"),
        Index("ix_coupon_plans_plan_id", "plan_id"),
    )

    def __repr__(self) -> str:
        return f"<CouponPlan(coupon_id={self.coupon_id}, plan_id={self.plan_id})>"


class CouponUsage(BaseModel):
    """One redemption of one :class:`Coupon` -- ``discount_amount_applied``
    is the **real, computed discount at the moment of use**, never
    re-derived later from the coupon's own (possibly since-edited)
    ``discount_value`` -- the identical "copy not reference" principle
    ``guest``'s voucher-derived session quotas already establish for this
    codebase (a redemption's historical record must not silently change
    meaning if the coupon it referenced is edited afterward).
    ``subscription_id`` is nullable: a coupon is redeemed against a
    ``Subscription`` in this part, but the column stays nullable for a
    future part where a coupon might apply outside a subscription context
    entirely (e.g. a one-off invoice discount)."""

    __tablename__ = "coupon_usages"

    coupon_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("coupons.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("subscriptions.id", ondelete="SET NULL"),
        nullable=True,
    )
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    discount_amount_applied: Mapped[Decimal] = mapped_column(
        Numeric(12, 2), nullable=False
    )

    __table_args__ = (
        Index("ix_coupon_usages_coupon_id", "coupon_id"),
        Index("ix_coupon_usages_organization_id", "organization_id"),
        Index("ix_coupon_usages_subscription_id", "subscription_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<CouponUsage(coupon_id={self.coupon_id}, "
            f"organization_id={self.organization_id})>"
        )


# ============================================================================
# BE-013 Part 3: Payment Service + Real Stripe/Razorpay Integration + Webhooks
# ============================================================================


class Payment(BaseModel):
    """One real (or honestly-failed) charge attempt -- and, per this part's
    own explicit "Payment History" decision, the entire query surface for
    an organization's payment history. There is no second, append-only
    ``PaymentHistory`` table: every ``Payment`` row already is a permanent,
    timestamped, status-tracked record of one charge attempt (created once,
    mutated only by its own real lifecycle -- refund/retry -- never
    deleted), so "payment history" is simply
    ``PaymentRepository.list_payments(organization_id=...)`` ordered by
    ``created_at`` -- the identical "a query surface over existing rows,
    not a second table" judgment call ``UsageMetric``/``LicenseChangeLog``
    already establish elsewhere in this domain for their own read
    surfaces. See ``payment_gateways.py``'s module docstring for exactly
    how a row moves through ``constants.PaymentStatus``'s transition graph.

    ## Idempotency: a real, DB-unique-constraint-backed guarantee

    ``idempotency_key`` is **unique, not nullable** -- this is the actual
    enforcement mechanism, not a comment: ``service.PaymentService
    .initiate_payment`` checks for an existing row with the same key
    first (the common-case fast path), and if a concurrent request racing
    against it also passes that check before either commits, the *second*
    ``INSERT`` collides with this real unique constraint, is translated by
    ``GenericRepository._flush_or_raise`` into
    ``app.database.exceptions.DuplicateRecordError``, and
    ``PaymentService.initiate_payment`` catches exactly that to re-read and
    return the winning row instead of ever attempting a second charge --
    see that method's own docstring for the full write-up. The same
    ``idempotency_key`` presented twice therefore always resolves to the
    same ``Payment`` row, enforced at the database level, not merely an
    application-level check that a race could still slip past.

    ``provider_payment_id`` is nullable until the provider assigns one (it
    is unknown at ``PENDING`` row-creation time, before the real SDK call
    returns). ``refunded_amount`` defaults to ``0`` and is the running
    total of every ``refund_payment`` call against this row -- never reset,
    never re-derived from a second table.
    """

    __tablename__ = "payments"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("subscriptions.id", ondelete="SET NULL"),
        nullable=True,
    )
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    provider: Mapped[str] = mapped_column(String(20), nullable=False)
    provider_payment_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True
    )
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    refunded_amount: Mapped[Decimal] = mapped_column(
        Numeric(12, 2), default=Decimal("0"), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_payments_idempotency_key"),
        Index("ix_payments_organization_id", "organization_id"),
        Index("ix_payments_subscription_id", "subscription_id"),
        Index("ix_payments_status", "status"),
        Index("ix_payments_provider", "provider"),
        Index("ix_payments_provider_payment_id", "provider_payment_id"),
        Index("ix_payments_idempotency_key", "idempotency_key", unique=True),
    )

    def __repr__(self) -> str:
        return (
            f"<Payment(id={self.id}, organization_id={self.organization_id}, "
            f"status={self.status}, provider={self.provider})>"
        )


class PaymentMethod(BaseModel):
    """A tokenized reference to a payment instrument -- **never** a raw
    card number/CVV/full payment credential. ``provider_payment_method_id``
    is the provider's own opaque token (e.g. a Stripe ``pm_...`` id, or a
    Razorpay saved-card token id) -- this table stores only what the
    provider hands back after its own (client-side, PCI-scoped) tokenization
    flow, exactly the discipline this codebase's real secrets already
    follow one level over: ``app.domains.router.crypto`` at least
    encrypts a real, recoverable secret at rest because this platform must
    open a live RouterOS connection with it; this table does not even need
    that, since it stores no recoverable secret at all, only an opaque
    reference the provider itself resolves. ``last4`` is nullable,
    display-only (never used for any charge decision).

    ``is_default`` is enforced as **at most one per organization** by
    ``repository.PaymentMethodRepository.set_as_default`` (unsets every
    sibling row in the same transaction) -- see that method's own
    docstring."""

    __tablename__ = "payment_methods"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(String(20), nullable=False)
    provider_payment_method_id: Mapped[str] = mapped_column(String(255), nullable=False)
    method_type: Mapped[str] = mapped_column(String(20), nullable=False)
    last4: Mapped[str | None] = mapped_column(String(4), nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "provider",
            "provider_payment_method_id",
            name="uq_payment_methods_org_provider_token",
        ),
        Index("ix_payment_methods_organization_id", "organization_id"),
        Index("ix_payment_methods_provider", "provider"),
        Index("ix_payment_methods_is_default", "is_default"),
        Index("ix_payment_methods_is_active", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<PaymentMethod(id={self.id}, organization_id="
            f"{self.organization_id}, provider={self.provider})>"
        )


__all__ = [
    "Plan",
    "PlanFeature",
    "License",
    "LicenseChangeLog",
    "UsageMetric",
    "Subscription",
    "Coupon",
    "CouponPlan",
    "CouponUsage",
    "Payment",
    "PaymentMethod",
]
