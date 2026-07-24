"""Billing business logic: Plan/PlanFeature catalog CRUD, License lifecycle
(assign/activate/suspend/upgrade/downgrade/expire/cancel), and real, composed
Usage tracking + limit validation.

Design notes worth calling out (see ``docs/billing/FLOW.md`` for the full
write-up):

* ``Organization.subscription_tier`` relationship: ``License``/``Plan`` are
  the real source of truth for what an organization is entitled to;
  ``subscription_tier`` is a denormalized convenience label
  ``LicenseService`` keeps in sync via a narrow, additive
  ``OrganizationService.sync_subscription_tier`` hook -- see
  ``models.py``'s module docstring for the full decision, and
  ``app.domains.organization.service.OrganizationService
  .sync_subscription_tier`` for the exact edit.
* License status transition graph: ``_LICENSE_TRANSITIONS`` below is the
  full, explicit graph (mirrors ``app.domains.router.service.RouterService
  ._validate_transition``'s identical rigor) -- every method that changes
  ``License.status`` goes through ``_assert_transition`` first; there is no
  implicit/derived transition anywhere in this service.
* Upgrade/downgrade history: every plan change writes a real
  ``LicenseChangeLog`` row (not a lossy single ``previous_plan_id`` column
  -- see ``models.License``'s own docstring for why).
* License-expiry sweep: **out of scope for this part, by design.**
  ``expire_license`` is a real, callable state-transition method (the spec
  explicitly names "License Expiration" as a first-class feature), but no
  Celery Beat task calls it automatically here. Expiry and renewal are
  tightly coupled -- what should happen the moment a license expires (a
  grace period? an automatic downgrade to a free tier? blocking every
  write?) is a policy question that belongs to the Renewal engine (a later
  BE-013 part, not this one), and wiring an automatic sweep now, ahead of
  that policy existing, risks prematurely cutting off an organization with
  no product-defined recovery path. ``expire_license`` is fully built,
  tested, and ready for that future part's Beat schedule to call.
* Usage composition sources -- see ``UsageService.record_current_usage``'s
  own docstring for exactly which existing domain's data backs each metric
  key, and which two are honest, undisguised placeholders.
* Downgrade-vs-usage validation: ``LicenseService.downgrade_license`` calls
  ``UsageService.check_usage_against_plan`` (a fresh, real recomputation,
  never a possibly-stale read) against the *target* plan's own limits
  before allowing the change, raising ``DowngradeBelowUsageError`` if
  current real usage already exceeds any of the target plan's ``LIMIT``
  features.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Protocol

from redis.asyncio import Redis

from app.database.exceptions import DuplicateRecordError
from app.database.utils.pagination import PaginationMeta
from app.domains.otp.constants import OtpChannel
from app.domains.rbac.enums import AuditAction

from .constants import (
    AUDIT_ACTION_DASHBOARD_CUSTOMER_VIEWED,
    AUDIT_ACTION_DASHBOARD_SUPER_ADMIN_VIEWED,
    AUDIT_ACTION_SUBSCRIPTION_RENEWAL_SETTINGS_UPDATED,
    BILLING_DASHBOARD_AUDIT_THROTTLE_KEY_TEMPLATE,
    BILLING_DASHBOARD_AUDIT_THROTTLE_MINUTES,
    BYTES_PER_MB,
    CUSTOMER_DASHBOARD_RECENT_INVOICES_LIMIT,
    CUSTOMER_DASHBOARD_RECENT_PAYMENTS_LIMIT,
    MAX_DASHBOARD_REVENUE_TREND_MONTHS,
    MIN_DASHBOARD_REVENUE_TREND_MONTHS,
    USAGE_METRIC_TO_LIMIT_FEATURE,
    BillingCycle,
    DiscountType,
    InvoiceStatus,
    LicenseChangeType,
    LicenseStatus,
    NoteType,
    PaymentStatus,
    PlanFeatureKey,
    PlanFeatureType,
    PlanType,
    SubscriptionStatus,
    TaxType,
    UsageMetricKey,
)
from .events import (
    BillingProfileUpdated,
    CouponApplied,
    CouponValidationFailed,
    CreditNoteIssued,
    DebitNoteIssued,
    InvoiceGenerated,
    InvoiceMarkedOverdue,
    InvoiceMarkedPaid,
    InvoiceVoided,
    LicenseActivated,
    LicenseAssigned,
    LicenseCancelled,
    LicenseDowngraded,
    LicenseExpired,
    LicenseSuspended,
    LicenseUpgraded,
    PaymentFailed,
    PaymentMethodRegistered,
    PaymentMethodRemoved,
    PaymentRefunded,
    PaymentRetried,
    PaymentSucceeded,
    SubscriptionCancelled,
    SubscriptionCreated,
    SubscriptionPaused,
    SubscriptionReactivated,
    SubscriptionResumed,
    TaxRateCreated,
    TaxRateUpdated,
)
from .exceptions import (
    BillingProfileNotFoundError,
    CouponExhaustedError,
    CouponExpiredError,
    CouponInactiveError,
    CouponNotApplicableToOrganizationError,
    CouponNotApplicableToPlanError,
    CouponNotFoundError,
    CouponNotYetValidError,
    DowngradeBelowUsageError,
    DuplicateCouponCodeError,
    DuplicateLicenseError,
    DuplicatePlanFeatureError,
    DuplicatePlanSlugError,
    DuplicateSubscriptionError,
    InvalidInvoiceStatusTransitionError,
    InvalidLicenseStatusTransitionError,
    InvalidNoteAmountError,
    InvalidSubscriptionStatusTransitionError,
    InvalidTaxRateError,
    InvoiceNotFoundError,
    LicenseNotActiveError,
    LicenseNotFoundError,
    PaymentMethodNotFoundError,
    PaymentNotFoundError,
    PaymentNotRefundableError,
    PaymentNotRetryableError,
    PlanInactiveError,
    PlanNotFoundError,
    RefundExceedsRefundableAmountError,
    SamePlanError,
    SubscriptionNotFoundError,
    SubscriptionReactivationNotAllowedError,
    TaxRateNotFoundError,
    UnsupportedPaymentProviderError,
)
from .models import (
    BillingProfile,
    Coupon,
    CreditDebitNote,
    Invoice,
    InvoiceItem,
    License,
    LicenseChangeLog,
    Payment,
    PaymentMethod,
    Plan,
    PlanFeature,
    Subscription,
    TaxRate,
    UsageMetric,
)
from .number_generator import (
    NumberCounterRepositoryProtocol,
    generate_credit_note_number,
    generate_debit_note_number,
    generate_invoice_number,
)
from .repository import (
    BillingDashboardRepositoryProtocol,
    BillingProfileRepositoryProtocol,
    CouponRepositoryProtocol,
    CreditDebitNoteRepositoryProtocol,
    InvoiceRepositoryProtocol,
    LicenseRepositoryProtocol,
    PaymentMethodRepositoryProtocol,
    PaymentRepositoryProtocol,
    PlanRepositoryProtocol,
    SubscriptionRepositoryProtocol,
    TaxRateRepositoryProtocol,
    UsageRepositoryProtocol,
)
from .validators import (
    add_billing_cycle,
    compute_discount_amount,
    compute_renewal_charge_amount,
    compute_tax_breakdown,
    current_month_period,
    is_payment_retry_eligible,
    normalize_coupon_code,
    normalize_slug,
    subtract_months,
    validate_discount_value,
    validate_feature_value,
)

logger = logging.getLogger(__name__)


class AuditLogWriter(Protocol):
    """The minimal surface this module needs to write into RBAC's shared
    ``audit_log_entries`` table -- mirrors every other domain's own
    identical narrow protocol (see ``app.domains.organization.service
    .AuditLogWriter``)."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


class OrganizationSyncProtocol(Protocol):
    """The single, narrow method this module needs from
    ``app.domains.organization.service.OrganizationService`` -- satisfied by
    that class's own new, additive ``sync_subscription_tier`` method. See
    ``models.py``'s module docstring for the full write-up of why this sync
    exists and why it is judged an acceptable, narrow exception to "never
    touch other domains' internals"."""

    async def sync_subscription_tier(
        self, *, organization_id: uuid.UUID, subscription_tier: str | None
    ) -> object: ...


class OrganizationLookupProtocol(Protocol):
    """Satisfied by the real ``app.domains.organization.service
    .OrganizationService`` directly -- reused, never reimplemented, for the
    ``ORGANIZATIONS`` usage metric (an MSP's own child-organization count)."""

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> object: ...

    async def list_children(self, organization_id: uuid.UUID) -> list[object]: ...


class GuestAnalyticsLookupProtocol(Protocol):
    """The single method this module needs from
    ``app.domains.guest.service.GuestAnalyticsService`` -- reused directly
    for ``GUESTS``/``GUEST_SESSIONS``/``BANDWIDTH_USAGE_MB``, the exact same
    composition ``app.domains.analytics.aggregation`` already establishes
    for these same figures (see this module's own docstring)."""

    async def get_summary(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> object: ...


class ActiveSessionLookupProtocol(Protocol):
    """Satisfied by ``app.domains.analytics.repository.AnalyticsRepository``
    directly -- reuses that domain's own already-built
    ``count_active_guest_sessions`` real aggregate query for the
    ``ACTIVE_DEVICES`` metric, rather than a fourth independent
    computation of "how many guest sessions are open right now"."""

    async def count_active_guest_sessions(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> int: ...


# ============================================================================
# Plan / PlanFeature
# ============================================================================


class PlanService:
    """Plan/PlanFeature catalog CRUD. Unlimited plans per the spec -- no
    per-organization or per-caller limit is enforced here; scope-gating
    (who may create/update/deactivate) is entirely RBAC's job at the router
    layer (``GLOBAL``-scoped ``billing.*`` permissions -- see ``router.py``).
    """

    def __init__(
        self,
        repository: PlanRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer

    async def get_plan(
        self, plan_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Plan:
        plan = await self.repository.get_by_id(plan_id, include_deleted=include_deleted)
        if plan is None:
            raise PlanNotFoundError(plan_id)
        return plan

    async def get_by_slug(self, slug: str) -> Plan:
        plan = await self.repository.get_by_slug(normalize_slug(slug))
        if plan is None:
            raise PlanNotFoundError(slug)
        return plan

    async def list_features(self, plan_id: uuid.UUID) -> list[PlanFeature]:
        return await self.repository.list_plan_features(plan_id)

    async def list_plans(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        include_private: bool = False,
        is_active: bool | None = True,
        plan_type: str | None = None,
    ):
        is_public = None if include_private else True
        return await self.repository.list_plans(
            page=page,
            page_size=page_size,
            is_public=is_public,
            is_active=is_active,
            plan_type=plan_type,
        )

    async def create_plan(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        name: str,
        slug: str,
        plan_type: str,
        description: str | None,
        billing_cycle: str,
        base_price: Decimal,
        currency: str,
        is_active: bool,
        is_public: bool,
        sort_order: int,
        features: list[dict[str, object]],
    ) -> Plan:
        normalized_slug = normalize_slug(slug)
        if await self.repository.get_by_slug(normalized_slug) is not None:
            raise DuplicatePlanSlugError(normalized_slug)

        for feature in features:
            validate_feature_value(
                feature_key=feature["feature_key"],
                feature_type=feature["feature_type"],
                limit_value=feature.get("limit_value"),
                is_enabled=feature.get("is_enabled"),
                tier_value=feature.get("tier_value"),
            )

        plan = await self.repository.create_plan(
            name=name,
            slug=normalized_slug,
            plan_type=plan_type,
            description=description,
            billing_cycle=billing_cycle,
            base_price=base_price,
            currency=currency,
            is_active=is_active,
            is_public=is_public,
            created_by_user_id=actor_user_id,
            sort_order=sort_order,
            created_by=actor_user_id,
        )
        await self._create_features(plan.id, features)
        await self._audit(
            actor_user_id,
            AuditAction.PLAN_CREATED,
            entity_id=plan.id,
            description=f"Plan '{plan.name}' created",
        )
        return plan

    async def update_plan(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        plan_id: uuid.UUID,
        data: dict[str, object],
        features: list[dict[str, object]] | None,
    ) -> Plan:
        plan = await self.get_plan(plan_id)
        updated = await self.repository.update_plan(
            plan, {**data, "updated_by": actor_user_id}
        )
        if features is not None:
            for feature in features:
                validate_feature_value(
                    feature_key=feature["feature_key"],
                    feature_type=feature["feature_type"],
                    limit_value=feature.get("limit_value"),
                    is_enabled=feature.get("is_enabled"),
                    tier_value=feature.get("tier_value"),
                )
            await self.repository.delete_plan_features(plan_id)
            await self._create_features(plan_id, features)
        await self._audit(
            actor_user_id,
            AuditAction.PLAN_UPDATED,
            entity_id=updated.id,
            description=f"Plan '{updated.name}' updated",
        )
        return updated

    async def deactivate_plan(
        self, *, actor_user_id: uuid.UUID | None, plan_id: uuid.UUID
    ) -> Plan:
        plan = await self.get_plan(plan_id)
        updated = await self.repository.update_plan(
            plan, {"is_active": False, "updated_by": actor_user_id}
        )
        updated = await self.repository.soft_delete_plan(updated)
        await self._audit(
            actor_user_id,
            AuditAction.PLAN_DEACTIVATED,
            entity_id=updated.id,
            description=f"Plan '{updated.name}' deactivated",
        )
        return updated

    async def _create_features(
        self, plan_id: uuid.UUID, features: list[dict[str, object]]
    ) -> None:
        seen_keys: set[str] = set()
        for feature in features:
            feature_key = feature["feature_key"]
            key_value = (
                feature_key.value if hasattr(feature_key, "value") else feature_key
            )
            if key_value in seen_keys:
                raise DuplicatePlanFeatureError(plan_id, key_value)
            seen_keys.add(key_value)
            feature_type = feature["feature_type"]
            await self.repository.create_plan_feature(
                plan_id=plan_id,
                feature_key=key_value,
                feature_type=(
                    feature_type.value
                    if hasattr(feature_type, "value")
                    else feature_type
                ),
                limit_value=feature.get("limit_value"),
                is_enabled=feature.get("is_enabled"),
                tier_value=feature.get("tier_value"),
            )

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID,
        description: str,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="plan",
                entity_id=entity_id,
                description=description,
                event_metadata={},
                organization_id=None,
                location_id=None,
            )
        logger.info("billing_plan_audit_event", extra={"action": action.value})


# ============================================================================
# License
# ============================================================================

# The full, explicit License.status transition graph -- see
# constants.LicenseStatus's own docstring for what each state means. Every
# method below that changes ``status`` calls ``_assert_transition`` first;
# there is no implicit/derived transition anywhere in this service.
_LICENSE_TRANSITIONS: dict[LicenseStatus, frozenset[LicenseStatus]] = {
    LicenseStatus.PENDING_ACTIVATION: frozenset(
        {LicenseStatus.ACTIVE, LicenseStatus.CANCELLED}
    ),
    LicenseStatus.ACTIVE: frozenset(
        {LicenseStatus.SUSPENDED, LicenseStatus.EXPIRED, LicenseStatus.CANCELLED}
    ),
    LicenseStatus.SUSPENDED: frozenset(
        {LicenseStatus.ACTIVE, LicenseStatus.EXPIRED, LicenseStatus.CANCELLED}
    ),
    LicenseStatus.EXPIRED: frozenset(),
    LicenseStatus.CANCELLED: frozenset(),
}


def _assert_transition(current: str, target: LicenseStatus) -> None:
    current_status = LicenseStatus(current)
    if target not in _LICENSE_TRANSITIONS[current_status]:
        raise InvalidLicenseStatusTransitionError(current_status.value, target.value)


class UsageValidatorProtocol(Protocol):
    """The single method ``LicenseService.downgrade_license`` needs from
    ``UsageService`` -- kept as a narrow protocol (rather than a direct
    ``UsageService`` type dependency) so ``UsageService`` itself never needs
    to depend back on ``LicenseService``, avoiding any construction cycle."""

    async def check_usage_against_plan(
        self, organization_id: uuid.UUID, plan_id: uuid.UUID
    ) -> list[str]: ...


class LicenseLifecycleProtocol(Protocol):
    """The narrow surface ``SubscriptionService`` (this file) and
    ``renewal_service.RenewalService`` both need from the real
    ``LicenseService`` -- satisfied by that class directly. Kept as a
    ``Protocol`` (rather than importing ``LicenseService`` as a concrete
    dependency type into ``renewal_service.py``) for the same "avoid a
    construction cycle / keep the dependency structural" reasoning
    ``UsageValidatorProtocol`` above already establishes for the identical
    ``LicenseService`` <-> ``UsageService`` relationship. Every method here
    already exists on ``LicenseService``, unmodified -- this part composes
    with Part 1's License lifecycle rather than duplicating any of it (per
    this part's own explicit instruction)."""

    async def assign_license(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        plan_id: uuid.UUID,
        expires_at: datetime | None = None,
    ) -> License: ...

    async def activate_license(
        self, *, actor_user_id: uuid.UUID | None, license_id: uuid.UUID
    ) -> License: ...

    async def suspend_license(
        self, *, actor_user_id: uuid.UUID | None, license_id: uuid.UUID, reason: str
    ) -> License: ...

    async def get_license(self, license_id: uuid.UUID) -> License: ...

    async def expire_license(self, *, license_id: uuid.UUID) -> License: ...


# ============================================================================
# Entitlement snapshot -- request-time license/feature enforcement
# ============================================================================


@dataclass(frozen=True)
class EntitlementSnapshot:
    """What one organization is currently entitled to, composed from its
    ``License`` + that license's ``Plan``'s ``PlanFeature`` rows -- the read
    model ``dependencies.RequireActiveLicense``/``RequireFeature`` gate
    requests against. Never fabricated: every field is read straight off
    real ``License``/``PlanFeature`` rows (see
    ``LicenseService.get_entitlement_snapshot``), the same "no synthetic
    data" rule the rest of this codebase follows.

    Serialized to/from a plain ``dict`` for ``cache.EntitlementCache``
    (mirrors ``app.domains.rbac.cache.PermissionCache``'s identical
    serialize-for-Redis shape)."""

    organization_id: uuid.UUID
    plan_id: uuid.UUID
    license_status: str
    expires_at: datetime | None
    enabled_features: frozenset[str]
    limits: dict[str, Decimal]
    tiers: dict[str, str]

    @property
    def is_active(self) -> bool:
        if self.license_status != LicenseStatus.ACTIVE.value:
            return False
        return self.expires_at is None or self.expires_at > datetime.now(UTC)

    def has_feature(self, feature_key: PlanFeatureKey) -> bool:
        return feature_key.value in self.enabled_features

    def to_cache_payload(self) -> dict[str, object]:
        return {
            "organization_id": str(self.organization_id),
            "plan_id": str(self.plan_id),
            "license_status": self.license_status,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "enabled_features": sorted(self.enabled_features),
            "limits": {key: str(value) for key, value in self.limits.items()},
            "tiers": dict(self.tiers),
        }

    @classmethod
    def from_cache_payload(cls, payload: dict[str, object]) -> EntitlementSnapshot:
        expires_at_raw = payload.get("expires_at")
        return cls(
            organization_id=uuid.UUID(str(payload["organization_id"])),
            plan_id=uuid.UUID(str(payload["plan_id"])),
            license_status=str(payload["license_status"]),
            expires_at=(
                datetime.fromisoformat(str(expires_at_raw))
                if expires_at_raw
                else None
            ),
            enabled_features=frozenset(payload.get("enabled_features", [])),
            limits={
                key: Decimal(str(value))
                for key, value in dict(payload.get("limits", {})).items()
            },
            tiers=dict(payload.get("tiers", {})),
        )


class EntitlementCacheProtocol(Protocol):
    """The minimal surface ``EntitlementChecker`` needs from
    ``cache.EntitlementCache`` -- kept structural so ``service.py`` never
    imports the concrete Redis-backed class (mirrors this module's own
    ``AuditLogWriter``/``OrganizationSyncProtocol`` narrow-Protocol
    convention)."""

    async def get(self, organization_id: uuid.UUID) -> dict[str, object] | None: ...

    async def set(
        self, organization_id: uuid.UUID, payload: dict[str, object]
    ) -> None: ...

    async def invalidate(self, organization_id: uuid.UUID) -> None: ...


class EntitlementSnapshotSource(Protocol):
    """Satisfied by ``LicenseService`` directly."""

    async def get_entitlement_snapshot(
        self, organization_id: uuid.UUID
    ) -> EntitlementSnapshot: ...


class EntitlementChecker:
    """Cache-or-fetch resolver of an organization's current
    :class:`EntitlementSnapshot` -- mirrors
    ``app.domains.rbac.authorization.AccessValidator``'s identical
    cache-or-fetch shape. This is the single object
    ``dependencies.RequireActiveLicense``/``dependencies.RequireFeature``
    depend on; neither dependency touches ``LicenseService`` or Redis
    directly."""

    def __init__(
        self,
        snapshot_source: EntitlementSnapshotSource,
        cache: EntitlementCacheProtocol,
    ) -> None:
        self._snapshot_source = snapshot_source
        self._cache = cache

    async def get_snapshot(self, organization_id: uuid.UUID) -> EntitlementSnapshot:
        cached = await self._cache.get(organization_id)
        if cached is not None:
            return EntitlementSnapshot.from_cache_payload(cached)
        snapshot = await self._snapshot_source.get_entitlement_snapshot(
            organization_id
        )
        await self._cache.set(organization_id, snapshot.to_cache_payload())
        return snapshot


class LicenseService:
    """License lifecycle: assign, activate, suspend, upgrade/downgrade
    (with real ``LicenseChangeLog`` history), expire, cancel, and
    validate."""

    def __init__(
        self,
        repository: LicenseRepositoryProtocol,
        plan_repository: PlanRepositoryProtocol,
        *,
        organization_sync: OrganizationSyncProtocol | None = None,
        usage_validator: UsageValidatorProtocol | None = None,
        audit_writer: AuditLogWriter | None = None,
        entitlement_cache: EntitlementCacheProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.plan_repository = plan_repository
        self.organization_sync = organization_sync
        self.usage_validator = usage_validator
        self.audit_writer = audit_writer
        self.entitlement_cache = entitlement_cache

    async def get_license(self, license_id: uuid.UUID) -> License:
        license_ = await self.repository.get_by_id(license_id)
        if license_ is None:
            raise LicenseNotFoundError(license_id)
        return license_

    async def get_license_for_organization(self, organization_id: uuid.UUID) -> License:
        license_ = await self.repository.get_by_organization_id(organization_id)
        if license_ is None:
            raise LicenseNotFoundError(organization_id)
        return license_

    async def get_entitlement_snapshot(
        self, organization_id: uuid.UUID
    ) -> EntitlementSnapshot:
        """The read model ``EntitlementChecker`` composes into a cache --
        see that class's own docstring. Always a fresh read off the real
        ``License``/``PlanFeature`` rows; never fabricated."""
        license_ = await self.get_license_for_organization(organization_id)
        features = await self.plan_repository.list_plan_features(license_.plan_id)
        enabled_features = frozenset(
            feature.feature_key
            for feature in features
            if feature.feature_type == PlanFeatureType.BOOLEAN.value
            and feature.is_enabled
        )
        limits = {
            feature.feature_key: feature.limit_value
            for feature in features
            if feature.feature_type == PlanFeatureType.LIMIT.value
            and feature.limit_value is not None
        }
        tiers = {
            feature.feature_key: feature.tier_value
            for feature in features
            if feature.feature_type == PlanFeatureType.TIER.value
            and feature.tier_value is not None
        }
        return EntitlementSnapshot(
            organization_id=organization_id,
            plan_id=license_.plan_id,
            license_status=license_.status,
            expires_at=license_.expires_at,
            enabled_features=enabled_features,
            limits=limits,
            tiers=tiers,
        )

    async def _invalidate_entitlement_cache(self, organization_id: uuid.UUID) -> None:
        if self.entitlement_cache is not None:
            await self.entitlement_cache.invalidate(organization_id)

    async def list_change_history(
        self, license_id: uuid.UUID
    ) -> list[LicenseChangeLog]:
        await self.get_license(license_id)
        return await self.repository.list_change_logs(license_id)

    async def assign_license(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        plan_id: uuid.UUID,
        expires_at: datetime | None = None,
    ) -> License:
        existing = await self.repository.get_by_organization_id(organization_id)
        if existing is not None:
            raise DuplicateLicenseError(organization_id)
        plan = await self._get_active_plan(plan_id)

        license_ = await self.repository.create_license(
            organization_id=organization_id,
            plan_id=plan.id,
            status=LicenseStatus.PENDING_ACTIVATION.value,
            expires_at=expires_at,
            created_by=actor_user_id,
        )
        await self.repository.create_change_log(
            license_id=license_.id,
            from_plan_id=None,
            to_plan_id=plan.id,
            change_type=LicenseChangeType.ASSIGNED.value,
            changed_at=datetime.now(UTC),
            changed_by_user_id=actor_user_id,
            reason=None,
        )
        await self._sync_subscription_tier(organization_id, plan.slug)
        await self._invalidate_entitlement_cache(organization_id)
        event = LicenseAssigned(
            license_id=license_.id, organization_id=organization_id, plan_id=plan.id
        )
        await self._audit(
            actor_user_id,
            AuditAction.LICENSE_ASSIGNED,
            license_,
            description=f"License assigned to organization {organization_id}",
        )
        logger.info("billing_license_assigned", extra=_event_extra(event))
        return license_

    async def activate_license(
        self, *, actor_user_id: uuid.UUID | None, license_id: uuid.UUID
    ) -> License:
        license_ = await self.get_license(license_id)
        _assert_transition(license_.status, LicenseStatus.ACTIVE)
        now = datetime.now(UTC)
        data: dict[str, object] = {
            "status": LicenseStatus.ACTIVE.value,
            "updated_by": actor_user_id,
        }
        if license_.activated_at is None:
            data["activated_at"] = now
        if license_.status == LicenseStatus.SUSPENDED.value:
            data["suspended_at"] = None
            data["suspended_reason"] = None
        updated = await self.repository.update_license(license_, data)
        await self._invalidate_entitlement_cache(updated.organization_id)
        event = LicenseActivated(
            license_id=updated.id, organization_id=updated.organization_id
        )
        await self._audit(
            actor_user_id,
            AuditAction.LICENSE_ACTIVATED,
            updated,
            description=f"License {updated.id} activated",
        )
        logger.info("billing_license_activated", extra=_event_extra(event))
        return updated

    async def suspend_license(
        self, *, actor_user_id: uuid.UUID | None, license_id: uuid.UUID, reason: str
    ) -> License:
        license_ = await self.get_license(license_id)
        _assert_transition(license_.status, LicenseStatus.SUSPENDED)
        updated = await self.repository.update_license(
            license_,
            {
                "status": LicenseStatus.SUSPENDED.value,
                "suspended_at": datetime.now(UTC),
                "suspended_reason": reason,
                "updated_by": actor_user_id,
            },
        )
        await self._invalidate_entitlement_cache(updated.organization_id)
        event = LicenseSuspended(
            license_id=updated.id,
            organization_id=updated.organization_id,
            reason=reason,
        )
        await self._audit(
            actor_user_id,
            AuditAction.LICENSE_SUSPENDED,
            updated,
            description=f"License {updated.id} suspended: {reason}",
        )
        logger.info("billing_license_suspended", extra=_event_extra(event))
        return updated

    async def cancel_license(
        self, *, actor_user_id: uuid.UUID | None, license_id: uuid.UUID
    ) -> License:
        license_ = await self.get_license(license_id)
        _assert_transition(license_.status, LicenseStatus.CANCELLED)
        updated = await self.repository.update_license(
            license_,
            {
                "status": LicenseStatus.CANCELLED.value,
                "cancelled_at": datetime.now(UTC),
                "updated_by": actor_user_id,
            },
        )
        await self._invalidate_entitlement_cache(updated.organization_id)
        event = LicenseCancelled(
            license_id=updated.id, organization_id=updated.organization_id
        )
        await self._audit(
            actor_user_id,
            AuditAction.LICENSE_CANCELLED,
            updated,
            description=f"License {updated.id} cancelled",
        )
        logger.info("billing_license_cancelled", extra=_event_extra(event))
        return updated

    async def expire_license(self, *, license_id: uuid.UUID) -> License:
        """Pure state-transition -- see module docstring for why no
        automatic Celery Beat sweep calls this in this part."""
        license_ = await self.get_license(license_id)
        _assert_transition(license_.status, LicenseStatus.EXPIRED)
        updated = await self.repository.update_license(
            license_, {"status": LicenseStatus.EXPIRED.value}
        )
        await self._invalidate_entitlement_cache(updated.organization_id)
        event = LicenseExpired(
            license_id=updated.id, organization_id=updated.organization_id
        )
        await self._audit(
            None,
            AuditAction.LICENSE_EXPIRED,
            updated,
            description=f"License {updated.id} expired",
        )
        logger.info("billing_license_expired", extra=_event_extra(event))
        return updated

    async def upgrade_license(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        license_id: uuid.UUID,
        new_plan_id: uuid.UUID,
        reason: str | None = None,
    ) -> License:
        return await self._change_plan(
            actor_user_id=actor_user_id,
            license_id=license_id,
            new_plan_id=new_plan_id,
            reason=reason,
            change_type=LicenseChangeType.UPGRADED,
        )

    async def downgrade_license(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        license_id: uuid.UUID,
        new_plan_id: uuid.UUID,
        reason: str | None = None,
    ) -> License:
        return await self._change_plan(
            actor_user_id=actor_user_id,
            license_id=license_id,
            new_plan_id=new_plan_id,
            reason=reason,
            change_type=LicenseChangeType.DOWNGRADED,
        )

    async def validate_license(self, organization_id: uuid.UUID) -> License:
        """Is this organization's license currently usable -- active, not
        expired, not suspended? Raises ``LicenseNotActiveError`` (never
        returns a falsy value) so callers cannot forget to check a return
        code, mirroring this codebase's own "raise, don't return a bool"
        convention for the same kind of hard gate (e.g.
        ``OrganizationService.archive_organization``'s
        ``OrganizationArchivedError``)."""
        license_ = await self.get_license_for_organization(organization_id)
        if license_.status != LicenseStatus.ACTIVE.value:
            raise LicenseNotActiveError(
                organization_id, f"status is '{license_.status}'"
            )
        if license_.expires_at is not None and license_.expires_at <= datetime.now(UTC):
            raise LicenseNotActiveError(organization_id, "license has expired")
        return license_

    async def _change_plan(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        license_id: uuid.UUID,
        new_plan_id: uuid.UUID,
        reason: str | None,
        change_type: LicenseChangeType,
    ) -> License:
        license_ = await self.get_license(license_id)
        if license_.status != LicenseStatus.ACTIVE.value:
            raise InvalidLicenseStatusTransitionError(license_.status, "plan_change")
        if license_.plan_id == new_plan_id:
            raise SamePlanError(new_plan_id)
        new_plan = await self._get_active_plan(new_plan_id)

        if (
            change_type == LicenseChangeType.DOWNGRADED
            and self.usage_validator is not None
        ):
            exceeded = await self.usage_validator.check_usage_against_plan(
                license_.organization_id, new_plan_id
            )
            if exceeded:
                raise DowngradeBelowUsageError(exceeded)

        old_plan_id = license_.plan_id
        updated = await self.repository.update_license(
            license_, {"plan_id": new_plan.id, "updated_by": actor_user_id}
        )
        await self.repository.create_change_log(
            license_id=license_.id,
            from_plan_id=old_plan_id,
            to_plan_id=new_plan.id,
            change_type=change_type.value,
            changed_at=datetime.now(UTC),
            changed_by_user_id=actor_user_id,
            reason=reason,
        )
        await self._sync_subscription_tier(updated.organization_id, new_plan.slug)
        await self._invalidate_entitlement_cache(updated.organization_id)

        if change_type == LicenseChangeType.UPGRADED:
            event: object = LicenseUpgraded(
                license_id=updated.id,
                organization_id=updated.organization_id,
                from_plan_id=old_plan_id,
                to_plan_id=new_plan.id,
            )
            action = AuditAction.LICENSE_UPGRADED
        else:
            event = LicenseDowngraded(
                license_id=updated.id,
                organization_id=updated.organization_id,
                from_plan_id=old_plan_id,
                to_plan_id=new_plan.id,
            )
            action = AuditAction.LICENSE_DOWNGRADED
        await self._audit(
            actor_user_id,
            action,
            updated,
            description=(
                f"License {updated.id} {change_type.value} to plan {new_plan.id}"
            ),
        )
        logger.info(f"billing_{action.value}", extra=_event_extra(event))
        return updated

    async def _get_active_plan(self, plan_id: uuid.UUID) -> Plan:
        plan = await self.plan_repository.get_by_id(plan_id)
        if plan is None:
            raise PlanNotFoundError(plan_id)
        if not plan.is_active:
            raise PlanInactiveError(plan_id)
        return plan

    async def _sync_subscription_tier(
        self, organization_id: uuid.UUID, plan_slug: str
    ) -> None:
        if self.organization_sync is not None:
            await self.organization_sync.sync_subscription_tier(
                organization_id=organization_id, subscription_tier=plan_slug
            )

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        license_: License,
        *,
        description: str,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="license",
                entity_id=license_.id,
                description=description,
                event_metadata={},
                organization_id=license_.organization_id,
                location_id=None,
            )
        logger.info("billing_license_audit_event", extra={"action": action.value})


# ============================================================================
# Usage
# ============================================================================


@dataclass(frozen=True, slots=True)
class UsageLimitCheck:
    metric_key: str
    current_value: Decimal
    limit_value: Decimal
    exceeded: bool


@dataclass(frozen=True, slots=True)
class UsageValidationResult:
    organization_id: uuid.UUID
    metrics: list[UsageMetric]
    limit_checks: list[UsageLimitCheck] = field(default_factory=list)

    @property
    def any_limit_exceeded(self) -> bool:
        return any(check.exceeded for check in self.limit_checks)


class UsageService:
    """Real, composed usage tracking -- every metric is computed from
    existing domains' own real data, never fabricated.

    ## Composition sources (one per metric key)

    * ``ORGANIZATIONS`` -- ``OrganizationLookupProtocol`` (the real
      ``app.domains.organization.service.OrganizationService``): ``1 +
      len(list_children(...))`` for an MSP organization, ``1`` otherwise.
    * ``LOCATIONS`` -- ``UsageRepository.count_locations`` (a narrow,
      read-only ``SELECT`` against ``app.domains.location.models.Location``,
      the same "read another domain's model directly" precedent
      ``app.domains.analytics.repository`` already establishes -- see
      ``repository.py``'s module docstring).
    * ``ROUTERS`` -- ``UsageRepository.count_routers`` (same precedent,
      against ``app.domains.router.models.Router``).
    * ``ACTIVE_DEVICES`` -- ``ActiveSessionLookupProtocol
      .count_active_guest_sessions`` -- reuses
      ``app.domains.analytics.repository.AnalyticsRepository``'s own
      already-built real aggregate query (the exact one
      ``app.domains.analytics.aggregation.compute_org_daily_summary``
      itself calls for ``session_count_active``), not a fourth independent
      computation of the same number.
    * ``GUESTS`` / ``GUEST_SESSIONS`` / ``BANDWIDTH_USAGE_MB`` --
      ``GuestAnalyticsLookupProtocol.get_summary`` -- reuses
      ``app.domains.guest.service.GuestAnalyticsService.get_summary``
      directly, the exact same real ``SUM(bytes_uploaded + bytes_downloaded)``
      aggregate ``app.domains.analytics.aggregation`` itself already
      composes with for ``total_bandwidth_bytes`` -- never recomputed a
      third way.
    * ``OTP_REQUESTS`` / ``SMS_USAGE`` / ``EMAIL_USAGE`` --
      ``UsageRepository.count_otp_requests_by_channel`` (a narrow,
      read-only, channel-grouped, date-ranged ``SELECT`` against
      ``app.domains.otp.models.OtpRequest`` -- the real usage-tracking
      source the spec itself names for these three counters).
    * ``STORAGE_USAGE_MB`` / ``API_REQUESTS`` -- **honest placeholders,
      recorded as ``0``.** No file-storage domain and no API-request-
      logging table exists anywhere in this codebase (mirrors
      ``app.domains.analytics``'s own well-established "available: false"/
      honest-placeholder convention for figures with no real backing data
      source, e.g. Revenue/ARR/MRR).
    """

    def __init__(
        self,
        repository: UsageRepositoryProtocol,
        plan_repository: PlanRepositoryProtocol,
        license_repository: LicenseRepositoryProtocol,
        organization_lookup: OrganizationLookupProtocol,
        guest_analytics: GuestAnalyticsLookupProtocol,
        active_session_lookup: ActiveSessionLookupProtocol,
    ) -> None:
        self.repository = repository
        self.plan_repository = plan_repository
        self.license_repository = license_repository
        self.organization_lookup = organization_lookup
        self.guest_analytics = guest_analytics
        self.active_session_lookup = active_session_lookup

    async def record_current_usage(
        self, organization_id: uuid.UUID
    ) -> list[UsageMetric]:
        """Computes and persists (upserting the current calendar-month
        bucket -- see ``validators.current_month_period``) every ``UsageMetricKey``
        for this organization from real, composed data. See module
        docstring for the exact source of each metric."""
        now = datetime.now(UTC)
        period_start, period_end = current_month_period(now)

        organization = await self.organization_lookup.get_organization(organization_id)
        children: list[object] = []
        if organization.is_msp():
            children = await self.organization_lookup.list_children(organization_id)
        organizations_count = Decimal(1 + len(children))

        locations_count = Decimal(
            await self.repository.count_locations(organization_id)
        )
        routers_count = Decimal(await self.repository.count_routers(organization_id))
        active_devices_count = Decimal(
            await self.active_session_lookup.count_active_guest_sessions(
                organization_id=organization_id, location_id=None
            )
        )

        guest_summary = await self.guest_analytics.get_summary(
            organization_id=organization_id,
            location_id=None,
            start=period_start,
            end=period_end,
        )
        guests_count = Decimal(guest_summary.unique_guests)
        guest_sessions_count = Decimal(guest_summary.visitors)
        bandwidth_mb = (
            Decimal(guest_summary.total_bandwidth_bytes) / Decimal(BYTES_PER_MB)
        ).quantize(Decimal("0.01"))

        channel_counts = dict(
            await self.repository.count_otp_requests_by_channel(
                organization_id, start=period_start, end=period_end
            )
        )
        sms_count = Decimal(channel_counts.get(OtpChannel.SMS.value, 0))
        email_count = Decimal(channel_counts.get(OtpChannel.EMAIL.value, 0))
        otp_total = sms_count + email_count

        values: dict[UsageMetricKey, Decimal] = {
            UsageMetricKey.ORGANIZATIONS: organizations_count,
            UsageMetricKey.LOCATIONS: locations_count,
            UsageMetricKey.ROUTERS: routers_count,
            UsageMetricKey.ACTIVE_DEVICES: active_devices_count,
            UsageMetricKey.GUESTS: guests_count,
            UsageMetricKey.GUEST_SESSIONS: guest_sessions_count,
            UsageMetricKey.OTP_REQUESTS: otp_total,
            UsageMetricKey.SMS_USAGE: sms_count,
            UsageMetricKey.EMAIL_USAGE: email_count,
            # Honest placeholders -- see module docstring.
            UsageMetricKey.STORAGE_USAGE_MB: Decimal(0),
            UsageMetricKey.API_REQUESTS: Decimal(0),
            UsageMetricKey.BANDWIDTH_USAGE_MB: bandwidth_mb,
        }

        results: list[UsageMetric] = []
        for metric_key, value in values.items():
            existing = await self.repository.get_current_period_metric(
                organization_id, metric_key.value, period_start
            )
            if existing is not None:
                updated = await self.repository.update_usage_metric(
                    existing,
                    {"value": value, "period_end": period_end, "recorded_at": now},
                )
                results.append(updated)
            else:
                created = await self.repository.create_usage_metric(
                    organization_id=organization_id,
                    metric_key=metric_key.value,
                    period_start=period_start,
                    period_end=period_end,
                    value=value,
                    recorded_at=now,
                )
                results.append(created)
        return results

    async def get_current_usage(self, organization_id: uuid.UUID) -> list[UsageMetric]:
        """Reads the current month's already-recorded usage, computing it
        fresh (via ``record_current_usage``) only if nothing has been
        recorded yet this period."""
        period_start, _ = current_month_period(datetime.now(UTC))
        existing = await self.repository.list_current_period_metrics(
            organization_id, period_start
        )
        if existing:
            return existing
        return await self.record_current_usage(organization_id)

    async def check_usage_against_plan(
        self, organization_id: uuid.UUID, plan_id: uuid.UUID
    ) -> list[str]:
        """Fresh (never stale) usage recomputation, compared against
        ``plan_id``'s own ``LIMIT`` features. Returns the list of
        ``UsageMetricKey`` values (as strings) whose current value exceeds
        that plan's limit -- used by ``LicenseService.downgrade_license``
        to reject a downgrade that would immediately violate a limit."""
        metrics = await self.record_current_usage(organization_id)
        limit_by_key = await self._limit_values_for_plan(plan_id)
        exceeded: list[str] = []
        for metric in metrics:
            limit_feature_key = USAGE_METRIC_TO_LIMIT_FEATURE.get(
                UsageMetricKey(metric.metric_key)
            )
            if limit_feature_key is None:
                continue
            limit_value = limit_by_key.get(limit_feature_key.value)
            if limit_value is not None and metric.value > limit_value:
                exceeded.append(metric.metric_key)
        return exceeded

    async def validate_usage_against_license(
        self, organization_id: uuid.UUID
    ) -> UsageValidationResult:
        """The real enforcement hook a later part's API-gating middleware
        or Subscription engine can call: which of this organization's
        current usage figures (if any) exceed its active license's plan
        limits."""
        license_ = await self.license_repository.get_by_organization_id(organization_id)
        if license_ is None:
            raise LicenseNotFoundError(organization_id)

        metrics = await self.get_current_usage(organization_id)
        limit_by_key = await self._limit_values_for_plan(license_.plan_id)

        checks: list[UsageLimitCheck] = []
        for metric in metrics:
            limit_feature_key = USAGE_METRIC_TO_LIMIT_FEATURE.get(
                UsageMetricKey(metric.metric_key)
            )
            if limit_feature_key is None:
                continue
            limit_value = limit_by_key.get(limit_feature_key.value)
            if limit_value is None:
                continue
            checks.append(
                UsageLimitCheck(
                    metric_key=metric.metric_key,
                    current_value=metric.value,
                    limit_value=limit_value,
                    exceeded=metric.value > limit_value,
                )
            )
        return UsageValidationResult(
            organization_id=organization_id, metrics=metrics, limit_checks=checks
        )

    async def _limit_values_for_plan(self, plan_id: uuid.UUID) -> dict[str, Decimal]:
        features = await self.plan_repository.list_plan_features(plan_id)
        return {
            feature.feature_key: feature.limit_value
            for feature in features
            if feature.feature_type == PlanFeatureType.LIMIT.value
            and feature.limit_value is not None
        }


# ============================================================================
# Coupon (BE-013 Part 2)
# ============================================================================


class CouponService:
    """Coupon CRUD, validation (side-effect free), and application
    (records a real ``CouponUsage`` row + atomically increments
    ``Coupon.current_uses``).

    ## Coupon-applies-once-vs-every-renewal: applies **once**, at signup

    A coupon is redeemed (``apply_coupon``, ``CouponUsage`` row written,
    ``current_uses`` incremented) exactly once, at the moment
    ``SubscriptionService.create_subscription`` creates the subscription it
    is attached to. ``renewal_service.RenewalService.process_renewal``
    charges the plan's full ``base_price`` on every subsequent renewal --
    it never re-applies ``Subscription.applied_coupon_id``'s discount.

    This mirrors the most common real-world coupon semantics ("50% off your
    first month", not "50% off forever") and was chosen over the
    alternative (re-applying the same coupon's discount on every renewal)
    for two concrete reasons: (1) it avoids a second, harder correctness
    question this part would otherwise have to answer honestly -- does a
    recurring discount count against ``max_uses`` once per subscription or
    once per renewal, and what happens when a coupon that granted a
    recurring discount is later deactivated mid-subscription -- neither of
    which the spec resolves; (2) ``CouponUsage`` (one row per redemption,
    ``discount_amount_applied`` frozen at the moment of use) models a single
    discrete redemption event cleanly; a recurring discount would need an
    entirely different, ongoing "active discount" concept this part does
    not build. ``Subscription.applied_coupon_id`` is kept purely for
    attribution/reporting ("which coupon led to this subscription"), not as
    a live, re-evaluated discount source.
    """

    def __init__(
        self,
        repository: CouponRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer

    async def get_coupon(self, coupon_id: uuid.UUID) -> Coupon:
        coupon = await self.repository.get_by_id(coupon_id)
        if coupon is None:
            raise CouponNotFoundError(coupon_id)
        return coupon

    async def get_by_code(self, code: str) -> Coupon:
        coupon = await self.repository.get_by_code(normalize_coupon_code(code))
        if coupon is None:
            raise CouponNotFoundError(code)
        return coupon

    async def list_applicable_plan_ids(self, coupon_id: uuid.UUID) -> list[uuid.UUID]:
        return await self.repository.list_applicable_plan_ids(coupon_id)

    async def list_coupons(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        organization_id: uuid.UUID | None = None,
        is_active: bool | None = None,
    ):
        return await self.repository.list_coupons(
            page=page,
            page_size=page_size,
            organization_id=organization_id,
            is_active=is_active,
        )

    async def create_coupon(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        code: str,
        discount_type: str,
        discount_value: Decimal,
        currency: str | None,
        organization_id: uuid.UUID | None,
        max_uses: int | None,
        valid_from: datetime,
        valid_until: datetime | None,
        is_active: bool,
        applicable_plan_ids: list[uuid.UUID],
    ) -> Coupon:
        normalized_code = normalize_coupon_code(code)
        if await self.repository.get_by_code(normalized_code) is not None:
            raise DuplicateCouponCodeError(normalized_code)
        validate_discount_value(
            discount_type=DiscountType(discount_type), discount_value=discount_value
        )

        coupon = await self.repository.create_coupon(
            code=normalized_code,
            discount_type=discount_type,
            discount_value=discount_value,
            currency=currency,
            organization_id=organization_id,
            max_uses=max_uses,
            current_uses=0,
            valid_from=valid_from,
            valid_until=valid_until,
            is_active=is_active,
            created_by=actor_user_id,
        )
        if applicable_plan_ids:
            await self.repository.set_applicable_plans(coupon.id, applicable_plan_ids)
        await self._audit(
            actor_user_id,
            AuditAction.COUPON_CREATED,
            coupon,
            description=f"Coupon '{coupon.code}' created",
        )
        return coupon

    async def update_coupon(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        coupon_id: uuid.UUID,
        data: dict[str, object],
        applicable_plan_ids: list[uuid.UUID] | None,
    ) -> Coupon:
        coupon = await self.get_coupon(coupon_id)
        if "discount_type" in data or "discount_value" in data:
            discount_type = DiscountType(
                data.get("discount_type", coupon.discount_type)
            )
            discount_value = data.get("discount_value", coupon.discount_value)
            validate_discount_value(
                discount_type=discount_type, discount_value=discount_value
            )
        updated = await self.repository.update_coupon(
            coupon, {**data, "updated_by": actor_user_id}
        )
        if applicable_plan_ids is not None:
            await self.repository.set_applicable_plans(updated.id, applicable_plan_ids)
        await self._audit(
            actor_user_id,
            AuditAction.COUPON_UPDATED,
            updated,
            description=f"Coupon '{updated.code}' updated",
        )
        return updated

    async def deactivate_coupon(
        self, *, actor_user_id: uuid.UUID | None, coupon_id: uuid.UUID
    ) -> Coupon:
        coupon = await self.get_coupon(coupon_id)
        updated = await self.repository.update_coupon(
            coupon, {"is_active": False, "updated_by": actor_user_id}
        )
        updated = await self.repository.soft_delete_coupon(updated)
        await self._audit(
            actor_user_id,
            AuditAction.COUPON_DEACTIVATED,
            updated,
            description=f"Coupon '{updated.code}' deactivated",
        )
        return updated

    async def validate_coupon(
        self, *, code: str, organization_id: uuid.UUID, plan_id: uuid.UUID
    ) -> Coupon:
        """Real-time, side-effect-free eligibility check -- no ``CouponUsage``
        row is written and ``current_uses`` is not touched (see
        ``apply_coupon`` for the mutating counterpart). Backs the
        no-side-effect ``POST /coupons/validate`` endpoint a checkout UI
        calls before actually committing to a coupon."""
        normalized_code = normalize_coupon_code(code)
        coupon = await self.repository.get_by_code(normalized_code)
        if coupon is None:
            await self._log_validation_failure(
                normalized_code, organization_id, "not_found"
            )
            raise CouponNotFoundError(normalized_code)

        now = datetime.now(UTC)
        if not coupon.is_active:
            await self._log_validation_failure(
                normalized_code, organization_id, "inactive"
            )
            raise CouponInactiveError(normalized_code)
        if coupon.valid_from > now:
            await self._log_validation_failure(
                normalized_code, organization_id, "not_yet_valid"
            )
            raise CouponNotYetValidError(normalized_code)
        if coupon.valid_until is not None and coupon.valid_until <= now:
            await self._log_validation_failure(
                normalized_code, organization_id, "expired"
            )
            raise CouponExpiredError(normalized_code)
        if coupon.max_uses is not None and coupon.current_uses >= coupon.max_uses:
            await self._log_validation_failure(
                normalized_code, organization_id, "exhausted"
            )
            raise CouponExhaustedError(normalized_code)
        if (
            coupon.organization_id is not None
            and coupon.organization_id != organization_id
        ):
            await self._log_validation_failure(
                normalized_code, organization_id, "wrong_organization"
            )
            raise CouponNotApplicableToOrganizationError(
                normalized_code, organization_id
            )

        applicable_plan_ids = await self.repository.list_applicable_plan_ids(coupon.id)
        if applicable_plan_ids and plan_id not in applicable_plan_ids:
            await self._log_validation_failure(
                normalized_code, organization_id, "wrong_plan"
            )
            raise CouponNotApplicableToPlanError(normalized_code, plan_id)

        return coupon

    async def apply_coupon(
        self,
        *,
        code: str,
        organization_id: uuid.UUID,
        subscription_id: uuid.UUID | None,
        plan_id: uuid.UUID,
        base_amount: Decimal,
    ) -> Decimal:
        """Re-validates ``code`` (never trusts a caller's earlier
        ``validate_coupon`` result -- state may have changed in between,
        e.g. another request just exhausted ``max_uses``), computes the
        real discount, writes a ``CouponUsage`` row (``discount_amount_
        applied`` frozen at this exact value -- see ``models.CouponUsage``'s
        own "copy not reference" docstring), and atomically increments
        ``current_uses``. Returns the computed discount amount."""
        coupon = await self.validate_coupon(
            code=code, organization_id=organization_id, plan_id=plan_id
        )
        discount_amount = compute_discount_amount(
            discount_type=DiscountType(coupon.discount_type),
            discount_value=coupon.discount_value,
            base_amount=base_amount,
        )
        await self.repository.create_coupon_usage(
            coupon_id=coupon.id,
            organization_id=organization_id,
            subscription_id=subscription_id,
            used_at=datetime.now(UTC),
            discount_amount_applied=discount_amount,
        )
        await self.repository.increment_current_uses(coupon.id)

        event = CouponApplied(
            coupon_id=coupon.id,
            organization_id=organization_id,
            subscription_id=subscription_id,
            discount_amount=str(discount_amount),
        )
        logger.info("billing_coupon_applied", extra=_event_extra(event))
        await self._audit(
            None,
            AuditAction.COUPON_APPLIED,
            coupon,
            description=f"Coupon '{coupon.code}' applied for organization "
            f"{organization_id} (discount={discount_amount})",
        )
        return discount_amount

    async def _log_validation_failure(
        self, code: str, organization_id: uuid.UUID, reason: str
    ) -> None:
        event = CouponValidationFailed(
            code=code, organization_id=organization_id, reason=reason
        )
        logger.info("billing_coupon_validation_failed", extra=_event_extra(event))

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        coupon: Coupon,
        *,
        description: str,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="coupon",
                entity_id=coupon.id,
                description=description,
                event_metadata={},
                organization_id=coupon.organization_id,
                location_id=None,
            )
        logger.info("billing_coupon_audit_event", extra={"action": action.value})


# ============================================================================
# Subscription (BE-013 Part 2)
# ============================================================================

# The full, explicit Subscription.status transition graph -- see
# constants.SubscriptionStatus's own docstring for what each state means and
# the PAUSED-vs-CANCELLED distinction. Every method below that changes
# ``status`` calls ``_assert_subscription_transition`` first.
_SUBSCRIPTION_TRANSITIONS: dict[SubscriptionStatus, frozenset[SubscriptionStatus]] = {
    SubscriptionStatus.TRIALING: frozenset(
        {
            SubscriptionStatus.ACTIVE,
            SubscriptionStatus.PAST_DUE,
            SubscriptionStatus.CANCELLED,
        }
    ),
    SubscriptionStatus.ACTIVE: frozenset(
        {
            SubscriptionStatus.PAST_DUE,
            SubscriptionStatus.PAUSED,
            SubscriptionStatus.CANCELLED,
        }
    ),
    SubscriptionStatus.PAST_DUE: frozenset(
        {SubscriptionStatus.ACTIVE, SubscriptionStatus.CANCELLED}
    ),
    SubscriptionStatus.PAUSED: frozenset(
        {SubscriptionStatus.ACTIVE, SubscriptionStatus.CANCELLED}
    ),
    # Reactivation only -- see SubscriptionService.reactivate_subscription
    # and SubscriptionReactivationNotAllowedError for the additional
    # "license must not have already expired" guard this transition alone
    # is not sufficient to enforce.
    SubscriptionStatus.CANCELLED: frozenset({SubscriptionStatus.ACTIVE}),
}


def _assert_subscription_transition(current: str, target: SubscriptionStatus) -> None:
    current_status = SubscriptionStatus(current)
    if target not in _SUBSCRIPTION_TRANSITIONS[current_status]:
        raise InvalidSubscriptionStatusTransitionError(
            current_status.value, target.value
        )


class SubscriptionService:
    """Subscription lifecycle: create (composing ``LicenseService``'s own
    assign/activate rather than duplicating license assignment), cancel
    (immediate or at-period-end), reactivate, pause/resume.

    See ``constants.SubscriptionStatus``'s docstring for the full status
    transition graph and the ``PAUSED``-vs-``CANCELLED`` design decision.
    """

    def __init__(
        self,
        repository: SubscriptionRepositoryProtocol,
        plan_repository: PlanRepositoryProtocol,
        license_service: LicenseLifecycleProtocol,
        *,
        coupon_service: CouponService | None = None,
        trial_period_days: int = 14,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.plan_repository = plan_repository
        self.license_service = license_service
        self.coupon_service = coupon_service
        self.trial_period_days = trial_period_days
        self.audit_writer = audit_writer

    async def get_subscription(self, subscription_id: uuid.UUID) -> Subscription:
        subscription = await self.repository.get_by_id(subscription_id)
        if subscription is None:
            raise SubscriptionNotFoundError(subscription_id)
        return subscription

    async def get_subscription_for_organization(
        self, organization_id: uuid.UUID
    ) -> Subscription:
        subscription = await self.repository.get_by_organization_id(organization_id)
        if subscription is None:
            raise SubscriptionNotFoundError(organization_id)
        return subscription

    async def create_subscription(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        plan_id: uuid.UUID,
        coupon_code: str | None = None,
    ) -> Subscription:
        existing = await self.repository.get_by_organization_id(organization_id)
        if existing is not None:
            raise DuplicateSubscriptionError(organization_id)

        plan = await self.plan_repository.get_by_id(plan_id)
        if plan is None:
            raise PlanNotFoundError(plan_id)
        if not plan.is_active:
            raise PlanInactiveError(plan_id)

        applied_coupon: Coupon | None = None
        if coupon_code is not None:
            if self.coupon_service is None:
                raise CouponNotFoundError(coupon_code)
            applied_coupon = await self.coupon_service.validate_coupon(
                code=coupon_code, organization_id=organization_id, plan_id=plan.id
            )

        license_ = await self.license_service.assign_license(
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            plan_id=plan.id,
        )
        license_ = await self.license_service.activate_license(
            actor_user_id=actor_user_id, license_id=license_.id
        )

        now = datetime.now(UTC)
        is_trial = plan.plan_type == PlanType.FREE_TRIAL.value
        if is_trial:
            status = SubscriptionStatus.TRIALING
            trial_end = now + timedelta(days=self.trial_period_days)
            period_end = trial_end
        else:
            status = SubscriptionStatus.ACTIVE
            trial_end = None
            period_end = add_billing_cycle(now, plan.billing_cycle)

        subscription = await self.repository.create_subscription(
            organization_id=organization_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=status.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now,
            current_period_end=period_end,
            trial_end=trial_end,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now,
            applied_coupon_id=applied_coupon.id if applied_coupon else None,
            created_by=actor_user_id,
        )

        if applied_coupon is not None and self.coupon_service is not None:
            await self.coupon_service.apply_coupon(
                code=applied_coupon.code,
                organization_id=organization_id,
                subscription_id=subscription.id,
                plan_id=plan.id,
                base_amount=plan.base_price,
            )

        event = SubscriptionCreated(
            subscription_id=subscription.id,
            organization_id=organization_id,
            plan_id=plan.id,
            status=status.value,
        )
        logger.info("billing_subscription_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.SUBSCRIPTION_CREATED,
            subscription,
            description=f"Subscription {subscription.id} created on plan {plan.id}",
        )
        return subscription

    async def cancel_subscription(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        subscription_id: uuid.UUID,
        immediate: bool,
    ) -> Subscription:
        subscription = await self.get_subscription(subscription_id)
        current_status = SubscriptionStatus(subscription.status)
        if current_status not in (
            SubscriptionStatus.TRIALING,
            SubscriptionStatus.ACTIVE,
            SubscriptionStatus.PAST_DUE,
            SubscriptionStatus.PAUSED,
        ):
            raise InvalidSubscriptionStatusTransitionError(
                subscription.status, SubscriptionStatus.CANCELLED.value
            )

        if immediate:
            _assert_subscription_transition(
                subscription.status, SubscriptionStatus.CANCELLED
            )
            now = datetime.now(UTC)
            updated = await self.repository.update_subscription(
                subscription,
                {
                    "status": SubscriptionStatus.CANCELLED.value,
                    "cancelled_at": now,
                    "auto_renew": False,
                    "cancel_at_period_end": False,
                    "past_due_at": None,
                    "updated_by": actor_user_id,
                },
            )
            await self.license_service.suspend_license(
                actor_user_id=actor_user_id,
                license_id=subscription.license_id,
                reason="Subscription cancelled",
            )
        else:
            # Scheduled cancellation -- status does not change yet;
            # renewal_service.RenewalService.process_renewal finalizes it
            # (transition to CANCELLED + license suspension) once
            # current_period_end is actually reached.
            updated = await self.repository.update_subscription(
                subscription,
                {"cancel_at_period_end": True, "updated_by": actor_user_id},
            )

        event = SubscriptionCancelled(
            subscription_id=updated.id,
            organization_id=updated.organization_id,
            immediate=immediate,
        )
        logger.info("billing_subscription_cancelled", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.SUBSCRIPTION_CANCELLED,
            updated,
            description=f"Subscription {updated.id} cancelled "
            f"({'immediate' if immediate else 'at period end'})",
        )
        return updated

    async def reactivate_subscription(
        self, *, actor_user_id: uuid.UUID | None, subscription_id: uuid.UUID
    ) -> Subscription:
        subscription = await self.get_subscription(subscription_id)
        _assert_subscription_transition(subscription.status, SubscriptionStatus.ACTIVE)

        license_ = await self.license_service.get_license(subscription.license_id)
        if license_.status == LicenseStatus.EXPIRED.value:
            raise SubscriptionReactivationNotAllowedError(subscription.id)
        if license_.status == LicenseStatus.SUSPENDED.value:
            await self.license_service.activate_license(
                actor_user_id=actor_user_id, license_id=license_.id
            )

        now = datetime.now(UTC)
        updated = await self.repository.update_subscription(
            subscription,
            {
                "status": SubscriptionStatus.ACTIVE.value,
                "cancelled_at": None,
                "cancel_at_period_end": False,
                "auto_renew": True,
                "current_period_start": now,
                "current_period_end": add_billing_cycle(
                    now, subscription.billing_cycle
                ),
                "updated_by": actor_user_id,
            },
        )
        event = SubscriptionReactivated(
            subscription_id=updated.id, organization_id=updated.organization_id
        )
        logger.info("billing_subscription_reactivated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.SUBSCRIPTION_REACTIVATED,
            updated,
            description=f"Subscription {updated.id} reactivated",
        )
        return updated

    async def pause_subscription(
        self, *, actor_user_id: uuid.UUID | None, subscription_id: uuid.UUID
    ) -> Subscription:
        subscription = await self.get_subscription(subscription_id)
        _assert_subscription_transition(subscription.status, SubscriptionStatus.PAUSED)
        updated = await self.repository.update_subscription(
            subscription,
            {"status": SubscriptionStatus.PAUSED.value, "updated_by": actor_user_id},
        )
        event = SubscriptionPaused(
            subscription_id=updated.id, organization_id=updated.organization_id
        )
        logger.info("billing_subscription_paused", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.SUBSCRIPTION_PAUSED,
            updated,
            description=f"Subscription {updated.id} paused",
        )
        return updated

    async def resume_subscription(
        self, *, actor_user_id: uuid.UUID | None, subscription_id: uuid.UUID
    ) -> Subscription:
        subscription = await self.get_subscription(subscription_id)
        _assert_subscription_transition(subscription.status, SubscriptionStatus.ACTIVE)
        now = datetime.now(UTC)
        data: dict[str, object] = {
            "status": SubscriptionStatus.ACTIVE.value,
            "updated_by": actor_user_id,
        }
        # If the current period already elapsed while paused, begin a fresh
        # one from the moment of resume -- no backdated renewal attempt for
        # time spent paused. If it hasn't elapsed yet, leave it unchanged
        # (see module docstring / FLOW.md for the full write-up).
        if subscription.current_period_end <= now:
            data["current_period_start"] = now
            data["current_period_end"] = add_billing_cycle(
                now, subscription.billing_cycle
            )
        updated = await self.repository.update_subscription(subscription, data)
        event = SubscriptionResumed(
            subscription_id=updated.id, organization_id=updated.organization_id
        )
        logger.info("billing_subscription_resumed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.SUBSCRIPTION_RESUMED,
            updated,
            description=f"Subscription {updated.id} resumed",
        )
        return updated

    async def update_renewal_settings(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        subscription_id: uuid.UUID,
        organization_id: uuid.UUID,
        auto_renew: bool,
    ) -> Subscription:
        """BE-013 Part 5's "Renewal Settings" customer feature: updates
        ``Subscription.auto_renew`` post-creation -- confirmed genuinely
        missing from Parts 1-4 (no ``PATCH``/``PUT`` on ``/subscriptions/
        {id}`` existed beyond the state-transition actions
        cancel/reactivate/pause/resume).

        ## A deliberate exception to this file's own "no tenant check"
        ## precedent for subscription mutators

        Every other ``Subscription`` mutator above (``cancel_subscription``/
        ``reactivate_subscription``/``pause_subscription``/
        ``resume_subscription``) operates directly on ``subscription_id``
        with no ``organization_id`` cross-check -- the same "an admin action
        operating on the entity by id" precedent
        ``PaymentService.refund_payment``/``retry_failed_payment`` and
        ``InvoiceService.void_invoice``/``issue_credit_note`` already
        establish (see ``router.py``'s own Part 4 module docstring for the
        explicit write-up of that precedent). This method deliberately
        breaks from it: it is the one subscription mutator this part frames
        as **customer self-service** (the spec's own "Renewal Settings"
        feature, gated behind ``RequireOrganization`` at the router), so a
        real tenant check is required here specifically -- otherwise a
        caller holding ``subscriptions.update`` at their own organization's
        scope could toggle a *different* organization's auto-renewal
        setting merely by guessing/enumerating its ``subscription_id``.
        Mirrors ``PaymentService.get_payment``'s own "not found, never a
        leak" convention on mismatch.
        """
        subscription = await self.get_subscription(subscription_id)
        if subscription.organization_id != organization_id:
            raise SubscriptionNotFoundError(subscription_id)
        updated = await self.repository.update_subscription(
            subscription, {"auto_renew": auto_renew, "updated_by": actor_user_id}
        )
        logger.info(
            "billing_subscription_renewal_settings_updated",
            extra={
                "subscription_id": str(updated.id),
                "organization_id": str(updated.organization_id),
                "auto_renew": updated.auto_renew,
            },
        )
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=AUDIT_ACTION_SUBSCRIPTION_RENEWAL_SETTINGS_UPDATED,
                entity_type="subscription",
                entity_id=updated.id,
                description=f"Subscription {updated.id} renewal settings updated "
                f"(auto_renew={updated.auto_renew})",
                event_metadata={},
                organization_id=updated.organization_id,
                location_id=None,
            )
        return updated

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        subscription: Subscription,
        *,
        description: str,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="subscription",
                entity_id=subscription.id,
                description=description,
                event_metadata={},
                organization_id=subscription.organization_id,
                location_id=None,
            )
        logger.info("billing_subscription_audit_event", extra={"action": action.value})


# ============================================================================
# Payment / PaymentMethod (BE-013 Part 3)
# ============================================================================


class PaymentGatewayAdminProtocol(Protocol):
    """The narrow surface ``PaymentService`` needs from each concrete
    gateway (``payment_gateways.StripePaymentGateway``/
    ``RazorpayPaymentGateway``) -- kept as a locally-defined ``Protocol``
    (rather than importing ``payment_gateways.PaymentGatewayAdminProtocol``
    as a concrete dependency type) for the exact same "avoid a construction
    cycle / keep the dependency structural" reasoning
    ``LicenseLifecycleProtocol`` above already establishes for the
    identical ``SubscriptionService`` <-> ``LicenseService`` relationship:
    ``payment_gateways.py`` imports ``renewal_service.PaymentGatewayProtocol``,
    and ``renewal_service.py`` imports this module's own
    ``LicenseLifecycleProtocol``/``AuditLogWriter`` -- importing
    ``payment_gateways`` back into this module would close that import
    cycle. Every method here already exists on both concrete gateway
    classes, unmodified -- this is a structural typing seam, not a second
    implementation of anything."""

    async def charge_via_provider(self, payment: Payment) -> Payment: ...

    async def refund(self, payment: Payment, amount: Decimal | None) -> Payment: ...

    async def retry(self, payment: Payment) -> Payment: ...


class PaymentService:
    """Payment initiation (real idempotency-key enforcement), refund,
    retry, and "payment history" (see ``models.Payment``'s own "doubles as
    history" docstring for why this is a query surface, not a second
    table).

    ## Real idempotency enforcement -- see ``initiate_payment``

    ``models.Payment.idempotency_key`` is unique, not nullable. This class
    checks for an existing row first (the fast path for the overwhelming
    majority of calls -- no two concurrent requests), then relies on the
    real database unique constraint as the backstop against a genuine
    race: if two concurrent requests both pass that initial check before
    either commits, the loser's ``INSERT`` collides with the constraint,
    ``GenericRepository._flush_or_raise`` translates it into
    ``app.database.exceptions.DuplicateRecordError``, and this class
    catches exactly that to re-read and return the winning row -- the same
    ``idempotency_key`` presented twice always resolves to the same
    ``Payment`` row, never a double charge, enforced at the database
    level.
    """

    def __init__(
        self,
        payment_repository: PaymentRepositoryProtocol,
        payment_method_repository: PaymentMethodRepositoryProtocol,
        *,
        gateways: dict[str, PaymentGatewayAdminProtocol],
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.payment_repository = payment_repository
        self.payment_method_repository = payment_method_repository
        self.gateways = gateways
        self.audit_writer = audit_writer

    def _gateway_for(self, provider: str) -> PaymentGatewayAdminProtocol:
        gateway = self.gateways.get(provider)
        if gateway is None:
            raise UnsupportedPaymentProviderError(provider)
        return gateway

    async def get_payment(
        self, payment_id: uuid.UUID, *, organization_id: uuid.UUID | None = None
    ) -> Payment:
        """``organization_id``, when supplied, enforces tenant isolation --
        a payment that exists but belongs to a different organization is
        reported as not-found, never leaking its existence."""
        payment = await self.payment_repository.get_by_id(payment_id)
        if payment is None or (
            organization_id is not None and payment.organization_id != organization_id
        ):
            raise PaymentNotFoundError(payment_id)
        return payment

    async def list_payments(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
        provider: str | None = None,
    ):
        return await self.payment_repository.list_payments(
            page=page,
            page_size=page_size,
            organization_id=organization_id,
            status=status,
            provider=provider,
        )

    async def list_failed_payments(
        self, organization_id: uuid.UUID | None = None
    ) -> list[Payment]:
        return await self.payment_repository.list_failed_payments(organization_id)

    async def initiate_payment(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        subscription_id: uuid.UUID | None,
        amount: Decimal,
        currency: str,
        provider: str,
        idempotency_key: str,
    ) -> Payment:
        existing = await self.payment_repository.get_by_idempotency_key(idempotency_key)
        if existing is not None:
            return existing

        gateway = self._gateway_for(provider)
        try:
            payment = await self.payment_repository.create_payment(
                organization_id=organization_id,
                subscription_id=subscription_id,
                amount=amount,
                currency=currency,
                status=PaymentStatus.PENDING.value,
                provider=provider,
                provider_payment_id=None,
                idempotency_key=idempotency_key,
                refunded_amount=Decimal("0"),
                created_by=actor_user_id,
            )
        except DuplicateRecordError:
            # A concurrent request raced this one and won -- see class
            # docstring for the full write-up of why this is the real
            # enforcement backstop, not the primary check.
            winner = await self.payment_repository.get_by_idempotency_key(
                idempotency_key
            )
            if winner is None:  # pragma: no cover - defensive
                raise
            return winner

        await self._audit(
            actor_user_id,
            AuditAction.PAYMENT_INITIATED,
            payment,
            description=f"Payment {payment.id} initiated for organization "
            f"{organization_id} ({amount} {currency} via {provider})",
        )

        payment = await gateway.charge_via_provider(payment)

        if payment.status == PaymentStatus.SUCCEEDED.value:
            event = PaymentSucceeded(
                payment_id=payment.id,
                organization_id=organization_id,
                provider=provider,
                amount=str(payment.amount),
            )
            logger.info("billing_payment_succeeded", extra=_event_extra(event))
            await self._audit(
                actor_user_id,
                AuditAction.PAYMENT_SUCCEEDED,
                payment,
                description=f"Payment {payment.id} succeeded",
            )
        elif payment.status == PaymentStatus.FAILED.value:
            event = PaymentFailed(
                payment_id=payment.id,
                organization_id=organization_id,
                provider=provider,
                reason=payment.failure_reason or "unknown",
            )
            logger.warning("billing_payment_failed", extra=_event_extra(event))
            await self._audit(
                actor_user_id,
                AuditAction.PAYMENT_FAILED,
                payment,
                description=f"Payment {payment.id} failed: {payment.failure_reason}",
            )
        return payment

    async def refund_payment(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        payment_id: uuid.UUID,
        amount: Decimal | None = None,
    ) -> Payment:
        payment = await self.get_payment(payment_id)
        if payment.status not in (
            PaymentStatus.SUCCEEDED.value,
            PaymentStatus.PARTIALLY_REFUNDED.value,
        ):
            raise PaymentNotRefundableError(payment_id, payment.status)

        refundable = payment.amount - payment.refunded_amount
        refund_amount = amount if amount is not None else refundable
        if refund_amount <= 0 or refund_amount > refundable:
            raise RefundExceedsRefundableAmountError(
                payment_id, refund_amount, refundable
            )

        gateway = self._gateway_for(payment.provider)
        updated = await gateway.refund(payment, refund_amount)

        full = updated.status == PaymentStatus.REFUNDED.value
        event = PaymentRefunded(
            payment_id=updated.id,
            organization_id=updated.organization_id,
            refunded_amount=str(updated.refunded_amount),
            full=full,
        )
        logger.info("billing_payment_refunded", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PAYMENT_REFUNDED,
            updated,
            description=f"Payment {updated.id} refunded {refund_amount} "
            f"({'full' if full else 'partial'})",
        )
        return updated

    async def retry_failed_payment(
        self, *, actor_user_id: uuid.UUID | None, payment_id: uuid.UUID
    ) -> Payment:
        payment = await self.get_payment(payment_id)
        if not is_payment_retry_eligible(payment.status):
            raise PaymentNotRetryableError(payment_id, payment.status)

        gateway = self._gateway_for(payment.provider)
        updated = await gateway.retry(payment)

        succeeded = updated.status == PaymentStatus.SUCCEEDED.value
        event = PaymentRetried(
            payment_id=updated.id,
            organization_id=updated.organization_id,
            succeeded=succeeded,
        )
        logger.info("billing_payment_retried", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PAYMENT_RETRIED,
            updated,
            description=f"Payment {updated.id} retried "
            f"({'succeeded' if succeeded else 'failed again'})",
        )
        return updated

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        payment: Payment,
        *,
        description: str,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="payment",
                entity_id=payment.id,
                description=description,
                event_metadata={},
                organization_id=payment.organization_id,
                location_id=None,
            )
        logger.info("billing_payment_audit_event", extra={"action": action.value})


class PaymentMethodService:
    """Registration/listing/removal of tokenized payment-method references
    -- see ``models.PaymentMethod``'s own docstring for the "token only,
    never raw card data" discipline this class never deviates from (it has
    no code path that accepts or stores anything but an opaque
    ``provider_payment_method_id`` string)."""

    def __init__(
        self,
        repository: PaymentMethodRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer

    async def register_payment_method(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        provider: str,
        provider_payment_method_id: str,
        method_type: str,
        last4: str | None,
        is_default: bool,
    ) -> PaymentMethod:
        payment_method = await self.repository.create_payment_method(
            organization_id=organization_id,
            provider=provider,
            provider_payment_method_id=provider_payment_method_id,
            method_type=method_type,
            last4=last4,
            is_default=False,
            is_active=True,
            created_by=actor_user_id,
        )
        if is_default:
            payment_method = await self.repository.set_as_default(payment_method)

        event = PaymentMethodRegistered(
            payment_method_id=payment_method.id,
            organization_id=organization_id,
            provider=provider,
        )
        logger.info("billing_payment_method_registered", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PAYMENT_METHOD_REGISTERED,
            payment_method,
            description=f"Payment method {payment_method.id} registered for "
            f"organization {organization_id}",
        )
        return payment_method

    async def list_payment_methods(
        self, organization_id: uuid.UUID
    ) -> list[PaymentMethod]:
        return await self.repository.list_for_organization(organization_id)

    async def get_payment_method(
        self,
        payment_method_id: uuid.UUID,
        *,
        organization_id: uuid.UUID | None = None,
    ) -> PaymentMethod:
        payment_method = await self.repository.get_by_id(payment_method_id)
        if payment_method is None or (
            organization_id is not None
            and payment_method.organization_id != organization_id
        ):
            raise PaymentMethodNotFoundError(payment_method_id)
        return payment_method

    async def remove_payment_method(
        self, *, actor_user_id: uuid.UUID | None, payment_method_id: uuid.UUID
    ) -> PaymentMethod:
        payment_method = await self.get_payment_method(payment_method_id)
        updated = await self.repository.update_payment_method(
            payment_method,
            {
                "is_active": False,
                "is_default": False,
                "updated_by": actor_user_id,
            },
        )
        updated = await self.repository.soft_delete_payment_method(updated)

        event = PaymentMethodRemoved(
            payment_method_id=updated.id, organization_id=updated.organization_id
        )
        logger.info("billing_payment_method_removed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.PAYMENT_METHOD_REMOVED,
            updated,
            description=f"Payment method {updated.id} removed",
        )
        return updated

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        payment_method: PaymentMethod,
        *,
        description: str,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="payment_method",
                entity_id=payment_method.id,
                description=description,
                event_metadata={},
                organization_id=payment_method.organization_id,
                location_id=None,
            )
        logger.info(
            "billing_payment_method_audit_event", extra={"action": action.value}
        )


# ============================================================================
# BE-013 Part 4: Invoice Engine + Tax/GST
# ============================================================================

# The full, explicit Invoice.status transition graph -- see
# constants.InvoiceStatus's own docstring for what each state means. Every
# method below that changes ``status`` is checked against this graph first
# (directly, or via ``_assert_invoice_transition``); there is no implicit/
# derived transition anywhere in this service.
_INVOICE_TRANSITIONS: dict[InvoiceStatus, frozenset[InvoiceStatus]] = {
    InvoiceStatus.DRAFT: frozenset({InvoiceStatus.ISSUED, InvoiceStatus.CANCELLED}),
    InvoiceStatus.ISSUED: frozenset(
        {InvoiceStatus.PAID, InvoiceStatus.OVERDUE, InvoiceStatus.VOID}
    ),
    InvoiceStatus.OVERDUE: frozenset({InvoiceStatus.PAID, InvoiceStatus.VOID}),
    InvoiceStatus.PAID: frozenset(),
    InvoiceStatus.CANCELLED: frozenset(),
    InvoiceStatus.VOID: frozenset(),
}


def _assert_invoice_transition(current: str, target: InvoiceStatus) -> None:
    current_status = InvoiceStatus(current)
    if target not in _INVOICE_TRANSITIONS[current_status]:
        raise InvalidInvoiceStatusTransitionError(current_status.value, target.value)


class TaxRateService:
    """Super-Admin "Manage Taxes" CRUD -- composable per-organization
    based on billing jurisdiction (``InvoiceService.generate_invoice_for_
    subscription`` looks up the active rate for an organization's own
    ``BillingProfile.billing_country`` -- see that method's own
    docstring)."""

    def __init__(
        self,
        repository: TaxRateRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer

    async def get_tax_rate(self, tax_rate_id: uuid.UUID) -> TaxRate:
        tax_rate = await self.repository.get_by_id(tax_rate_id)
        if tax_rate is None:
            raise TaxRateNotFoundError(tax_rate_id)
        return tax_rate

    async def list_tax_rates(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        country_code: str | None = None,
        is_active: bool | None = None,
    ):
        return await self.repository.list_tax_rates(
            page=page,
            page_size=page_size,
            country_code=country_code.upper() if country_code else None,
            is_active=is_active,
        )

    async def create_tax_rate(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        name: str,
        tax_type: str,
        rate_percentage: Decimal,
        country_code: str,
        is_active: bool,
    ) -> TaxRate:
        if rate_percentage < 0 or rate_percentage > 100:
            raise InvalidTaxRateError("rate_percentage must be between 0 and 100")
        tax_rate = await self.repository.create_tax_rate(
            name=name,
            tax_type=tax_type,
            rate_percentage=rate_percentage,
            country_code=country_code.upper(),
            is_active=is_active,
            created_by=actor_user_id,
        )
        event = TaxRateCreated(
            tax_rate_id=tax_rate.id,
            country_code=tax_rate.country_code,
            rate_percentage=str(tax_rate.rate_percentage),
        )
        logger.info("billing_tax_rate_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.TAX_RATE_CREATED,
            tax_rate.id,
            description=f"Tax rate '{tax_rate.name}' created for "
            f"{tax_rate.country_code}",
        )
        return tax_rate

    async def update_tax_rate(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        tax_rate_id: uuid.UUID,
        data: dict[str, object],
    ) -> TaxRate:
        tax_rate = await self.get_tax_rate(tax_rate_id)
        rate_percentage = data.get("rate_percentage")
        rate_out_of_range = rate_percentage is not None and (
            rate_percentage < 0 or rate_percentage > 100
        )
        if rate_out_of_range:
            raise InvalidTaxRateError("rate_percentage must be between 0 and 100")
        if "country_code" in data and data["country_code"]:
            data = {**data, "country_code": str(data["country_code"]).upper()}
        updated = await self.repository.update_tax_rate(
            tax_rate, {**data, "updated_by": actor_user_id}
        )
        event = TaxRateUpdated(tax_rate_id=updated.id)
        logger.info("billing_tax_rate_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.TAX_RATE_UPDATED,
            updated.id,
            description=f"Tax rate {updated.id} updated",
        )
        return updated

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        entity_id: uuid.UUID,
        *,
        description: str,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="tax_rate",
                entity_id=entity_id,
                description=description,
                event_metadata={},
                organization_id=None,
                location_id=None,
            )
        logger.info("billing_tax_rate_audit_event", extra={"action": action.value})


class BillingProfileService:
    """An organization's own billing address/GSTIN -- one profile per
    organization, ever (upserted in place); see ``models.BillingProfile``'s
    own docstring for the full "why a billing-owned table, not an
    ``Organization`` column extension" write-up."""

    def __init__(
        self,
        repository: BillingProfileRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer

    async def get_billing_profile(self, organization_id: uuid.UUID) -> BillingProfile:
        profile = await self.repository.get_by_organization_id(organization_id)
        if profile is None:
            raise BillingProfileNotFoundError(organization_id)
        return profile

    async def upsert_billing_profile(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        billing_name: str,
        billing_address_line1: str,
        billing_address_line2: str | None,
        billing_city: str,
        billing_state: str,
        billing_country: str,
        billing_postal_code: str,
        gst_identifier: str | None,
        tax_exempt: bool,
    ) -> BillingProfile:
        """Creates the organization's one ``BillingProfile`` row the first
        time this is called, mutates it in place on every subsequent call --
        the identical one-row-per-organization cardinality
        ``License``/``Subscription`` already establish for this domain.
        Never retroactively changes any already-issued ``Invoice``'s own
        ``billing_snapshot`` -- see that column's own "copy, not reference"
        docstring."""
        existing = await self.repository.get_by_organization_id(organization_id)
        fields: dict[str, object] = {
            "billing_name": billing_name,
            "billing_address_line1": billing_address_line1,
            "billing_address_line2": billing_address_line2,
            "billing_city": billing_city,
            "billing_state": billing_state,
            "billing_country": billing_country.upper(),
            "billing_postal_code": billing_postal_code,
            "gst_identifier": gst_identifier,
            "tax_exempt": tax_exempt,
        }
        if existing is None:
            profile = await self.repository.create_billing_profile(
                organization_id=organization_id, created_by=actor_user_id, **fields
            )
        else:
            profile = await self.repository.update_billing_profile(
                existing, {**fields, "updated_by": actor_user_id}
            )
        event = BillingProfileUpdated(
            billing_profile_id=profile.id, organization_id=organization_id
        )
        logger.info("billing_profile_updated", extra=_event_extra(event))
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=AuditAction.BILLING_PROFILE_UPDATED.value,
                entity_type="billing_profile",
                entity_id=profile.id,
                description=f"Billing profile updated for organization "
                f"{organization_id}",
                event_metadata={},
                organization_id=organization_id,
                location_id=None,
            )
        logger.info(
            "billing_profile_audit_event",
            extra={"action": AuditAction.BILLING_PROFILE_UPDATED.value},
        )
        return profile


class InvoiceService:
    """Invoice generation (composing -- never recomputing --
    ``renewal_service.compute_renewal_charge_amount`` and
    ``validators.compute_tax_breakdown``), payment-webhook-triggered
    mark-paid, void, overdue detection, and credit/debit note issuance.
    """

    def __init__(
        self,
        repository: InvoiceRepositoryProtocol,
        *,
        subscription_repository: SubscriptionRepositoryProtocol,
        plan_repository: PlanRepositoryProtocol,
        billing_profile_repository: BillingProfileRepositoryProtocol,
        tax_rate_repository: TaxRateRepositoryProtocol,
        number_counter_repository: NumberCounterRepositoryProtocol,
        note_repository: CreditDebitNoteRepositoryProtocol,
        platform_gst_state: str,
        platform_gst_country: str,
        invoice_due_days: int = 15,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.subscription_repository = subscription_repository
        self.plan_repository = plan_repository
        self.billing_profile_repository = billing_profile_repository
        self.tax_rate_repository = tax_rate_repository
        self.number_counter_repository = number_counter_repository
        self.note_repository = note_repository
        self.platform_gst_state = platform_gst_state
        self.platform_gst_country = platform_gst_country
        self.invoice_due_days = invoice_due_days
        self.audit_writer = audit_writer

    async def get_invoice(
        self, invoice_id: uuid.UUID, *, organization_id: uuid.UUID | None = None
    ) -> Invoice:
        """``organization_id``, when supplied, enforces tenant isolation --
        mirrors ``PaymentService.get_payment``'s identical "not-found, never
        a leak" convention."""
        invoice = await self.repository.get_by_id(invoice_id)
        if invoice is None or (
            organization_id is not None and invoice.organization_id != organization_id
        ):
            raise InvoiceNotFoundError(invoice_id)
        return invoice

    async def list_invoices(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
    ):
        return await self.repository.list_invoices(
            page=page,
            page_size=page_size,
            organization_id=organization_id,
            status=status,
        )

    async def list_items(self, invoice_id: uuid.UUID) -> list[InvoiceItem]:
        return await self.repository.list_items(invoice_id)

    async def list_notes(self, invoice_id: uuid.UUID) -> list[CreditDebitNote]:
        return await self.note_repository.list_for_invoice(invoice_id)

    async def generate_invoice_for_subscription(
        self, subscription_id: uuid.UUID
    ) -> Invoice:
        """Generates one real, issued ``Invoice`` (+ its one ``InvoiceItem``
        line) for a subscription's current plan.

        ## Reuses, never recomputes, the renewal engine's own charge amount

        ``subtotal`` is exactly ``renewal_service
        .compute_renewal_charge_amount(plan)`` -- the identical, single real
        computation ``RenewalService.process_renewal``/
        ``confirm_renewal_payment_succeeded`` themselves call. This
        function never independently derives "how much does this
        subscription cost" a second way.

        ## Real GST/tax computation, applied via the organization's own
        ## ``BillingProfile``

        The organization must have a ``BillingProfile`` on file (billing
        address is a real, required prerequisite for issuing a legal
        invoice -- ``BillingProfileNotFoundError`` if not, never a silently
        blank/fabricated address). Unless ``tax_exempt``, the active
        ``TaxRate`` for the profile's own ``billing_country`` is looked up
        and applied via ``validators.compute_tax_breakdown`` -- the real
        CGST/SGST/IGST split for GST, comparing this platform's own
        registered jurisdiction (``Settings.platform_gst_state``/
        ``platform_gst_country``) against the organization's billing
        jurisdiction. No active rate for the country is an honest "no tax
        configured" outcome (zero tax), never a fabricated charge.

        ## Frozen ``billing_snapshot``

        A plain-dict copy of the ``BillingProfile``'s own fields *at this
        exact moment* is stored on the created ``Invoice`` -- see that
        column's own "copy, not reference" docstring for why a later
        billing-address edit must never retroactively alter this invoice.

        The created invoice is issued directly (``InvoiceStatus.ISSUED``,
        never ``DRAFT``) -- this method is the real trigger tied to an
        actual renewal/charge event, not a preparatory draft a human still
        needs to review before sending.
        """
        subscription = await self.subscription_repository.get_by_id(subscription_id)
        if subscription is None:
            raise SubscriptionNotFoundError(subscription_id)
        plan = await self.plan_repository.get_by_id(subscription.plan_id)
        if plan is None:
            raise PlanNotFoundError(subscription.plan_id)
        billing_profile = await self.billing_profile_repository.get_by_organization_id(
            subscription.organization_id
        )
        if billing_profile is None:
            raise BillingProfileNotFoundError(subscription.organization_id)

        subtotal = compute_renewal_charge_amount(plan)

        tax_rate: TaxRate | None = None
        if not billing_profile.tax_exempt:
            tax_rate = await self.tax_rate_repository.get_active_for_country(
                billing_profile.billing_country
            )

        breakdown = compute_tax_breakdown(
            subtotal=subtotal,
            tax_type=TaxType(tax_rate.tax_type) if tax_rate is not None else None,
            rate_percentage=(
                tax_rate.rate_percentage if tax_rate is not None else Decimal("0")
            ),
            tax_exempt=billing_profile.tax_exempt,
            platform_state=self.platform_gst_state,
            platform_country=self.platform_gst_country,
            billing_state=billing_profile.billing_state,
            billing_country=billing_profile.billing_country,
        )
        total_amount = (subtotal + breakdown.tax_amount).quantize(Decimal("0.01"))

        now = datetime.now(UTC)
        invoice_number = await generate_invoice_number(
            self.number_counter_repository, at=now
        )
        snapshot: dict[str, object] = {
            "billing_name": billing_profile.billing_name,
            "billing_address_line1": billing_profile.billing_address_line1,
            "billing_address_line2": billing_profile.billing_address_line2,
            "billing_city": billing_profile.billing_city,
            "billing_state": billing_profile.billing_state,
            "billing_country": billing_profile.billing_country,
            "billing_postal_code": billing_profile.billing_postal_code,
            "gst_identifier": billing_profile.gst_identifier,
            "tax_exempt": billing_profile.tax_exempt,
        }

        invoice = await self.repository.create_invoice(
            organization_id=subscription.organization_id,
            subscription_id=subscription.id,
            payment_id=None,
            invoice_number=invoice_number,
            status=InvoiceStatus.ISSUED.value,
            issue_date=now,
            due_date=now + timedelta(days=self.invoice_due_days),
            subtotal=subtotal,
            cgst_amount=breakdown.cgst_amount,
            sgst_amount=breakdown.sgst_amount,
            igst_amount=breakdown.igst_amount,
            tax_amount=breakdown.tax_amount,
            tax_rate_percentage=(
                tax_rate.rate_percentage if tax_rate is not None else Decimal("0")
            ),
            total_amount=total_amount,
            currency=plan.currency,
            billing_snapshot=snapshot,
        )
        await self.repository.create_invoice_item(
            invoice_id=invoice.id,
            description=f"{plan.name} subscription ({plan.billing_cycle})",
            quantity=Decimal("1"),
            unit_price=subtotal,
            amount=subtotal,
        )

        event = InvoiceGenerated(
            invoice_id=invoice.id,
            organization_id=invoice.organization_id,
            invoice_number=invoice.invoice_number,
            total_amount=str(invoice.total_amount),
        )
        logger.info("billing_invoice_generated", extra=_event_extra(event))
        await self._audit(
            None,
            AuditAction.INVOICE_GENERATED,
            invoice,
            description=f"Invoice {invoice.invoice_number} generated for "
            f"subscription {subscription.id}",
        )
        return invoice

    async def mark_invoice_paid(
        self, *, invoice_id: uuid.UUID, payment_id: uuid.UUID
    ) -> Invoice:
        """Marks a real, previously-``ISSUED``/``OVERDUE`` invoice ``PAID``
        against ``payment_id`` -- called directly (a manual reconciliation)
        or via ``mark_invoice_paid_for_payment`` (the real webhook-driven
        composition path -- see that method's own docstring)."""
        invoice = await self.get_invoice(invoice_id)
        _assert_invoice_transition(invoice.status, InvoiceStatus.PAID)
        updated = await self.repository.update_invoice(
            invoice, {"status": InvoiceStatus.PAID.value, "payment_id": payment_id}
        )
        event = InvoiceMarkedPaid(
            invoice_id=updated.id,
            organization_id=updated.organization_id,
            payment_id=payment_id,
        )
        logger.info("billing_invoice_marked_paid", extra=_event_extra(event))
        await self._audit(
            None,
            AuditAction.INVOICE_MARKED_PAID,
            updated,
            description=f"Invoice {updated.invoice_number} marked paid via "
            f"payment {payment_id}",
        )
        return updated

    async def mark_invoice_paid_for_payment(self, payment: Payment) -> Invoice | None:
        """The natural continuation of a successful payment webhook --
        composed from ``webhooks.py``'s existing success-handling code (an
        additive call into this method, never a new payment-side
        reimplementation of "what does a successful payment mean for
        billing"). Finds the most recently issued unpaid (``ISSUED``/
        ``OVERDUE``) invoice for the payment's own ``subscription_id`` and
        marks it paid via ``mark_invoice_paid``. Returns ``None`` -- a safe,
        deliberate no-op -- when the payment carries no ``subscription_id``
        at all, or no matching unpaid invoice is found: a real payment not
        tied to any invoice is a legitimate outcome (e.g. a manual, one-off
        ``POST /payments`` charge with no invoice ever generated for it),
        never an error."""
        if payment.subscription_id is None:
            return None
        candidates = await self.repository.list_unpaid_for_subscription(
            payment.subscription_id
        )
        if not candidates:
            return None
        return await self.mark_invoice_paid(
            invoice_id=candidates[0].id, payment_id=payment.id
        )

    async def void_invoice(
        self, *, actor_user_id: uuid.UUID | None, invoice_id: uuid.UUID
    ) -> Invoice:
        """Voids an invoice -- a ``DRAFT`` (never sent) becomes
        ``CANCELLED``; an ``ISSUED``/``OVERDUE`` (already sent) becomes
        ``VOID`` -- see ``constants.InvoiceStatus``'s own docstring for the
        real accounting distinction between the two terminal outcomes. A
        ``PAID`` invoice cannot be voided through this method -- correct it
        via ``issue_credit_note`` instead (voiding a paid invoice directly
        would silently discard the fact that real money changed hands)."""
        invoice = await self.get_invoice(invoice_id)
        current_status = InvoiceStatus(invoice.status)
        if current_status == InvoiceStatus.DRAFT:
            target = InvoiceStatus.CANCELLED
        elif current_status in (InvoiceStatus.ISSUED, InvoiceStatus.OVERDUE):
            target = InvoiceStatus.VOID
        else:
            raise InvalidInvoiceStatusTransitionError(invoice.status, "void")
        _assert_invoice_transition(invoice.status, target)
        updated = await self.repository.update_invoice(
            invoice, {"status": target.value, "updated_by": actor_user_id}
        )
        event = InvoiceVoided(
            invoice_id=updated.id,
            organization_id=updated.organization_id,
            previous_status=current_status.value,
        )
        logger.info("billing_invoice_voided", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.INVOICE_VOIDED,
            updated,
            description=f"Invoice {updated.invoice_number} {target.value} "
            f"(was {current_status.value})",
        )
        return updated

    async def mark_overdue_invoices(self) -> list[uuid.UUID]:
        """The real, Beat-scheduled sweep (``tasks.run_invoice_overdue_
        sweep``) that keeps ``OVERDUE`` a real, reachable, automatically-
        detected state rather than dead enum member -- every ``ISSUED``
        invoice whose ``due_date`` has passed transitions to ``OVERDUE``,
        with real per-invoice failure isolation (mirrors
        ``RenewalService.process_due_renewals``'s identical resilience
        pattern)."""
        now = datetime.now(UTC)
        due = await self.repository.list_issued_past_due(now=now)
        overdue_ids: list[uuid.UUID] = []
        for invoice in due:
            try:
                updated = await self.repository.update_invoice(
                    invoice, {"status": InvoiceStatus.OVERDUE.value}
                )
            except Exception:  # noqa: BLE001 -- per-invoice isolation
                logger.exception(
                    "billing_invoice_overdue_sweep_item_failed",
                    extra={"invoice_id": str(invoice.id)},
                )
                continue
            overdue_ids.append(updated.id)
            event = InvoiceMarkedOverdue(
                invoice_id=updated.id, organization_id=updated.organization_id
            )
            logger.info("billing_invoice_marked_overdue", extra=_event_extra(event))
            await self._audit(
                None,
                AuditAction.INVOICE_MARKED_OVERDUE,
                updated,
                description=f"Invoice {updated.invoice_number} marked overdue",
            )
        return overdue_ids

    async def issue_credit_note(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        invoice_id: uuid.UUID,
        amount: Decimal,
        reason: str,
    ) -> CreditDebitNote:
        """A credit note reduces what the customer owes/was charged --
        legal only against an invoice that was actually sent
        (``ISSUED``/``OVERDUE``/``PAID``), and its own amount can never
        exceed the invoice's own ``total_amount`` (a credit note cannot
        credit more than was ever charged)."""
        invoice = await self.get_invoice(invoice_id)
        if InvoiceStatus(invoice.status) not in (
            InvoiceStatus.ISSUED,
            InvoiceStatus.OVERDUE,
            InvoiceStatus.PAID,
        ):
            raise InvalidInvoiceStatusTransitionError(invoice.status, "credit_note")
        if amount <= 0:
            raise InvalidNoteAmountError("Credit note amount must be positive")
        if amount > invoice.total_amount:
            raise InvalidNoteAmountError(
                f"Credit note amount {amount} exceeds invoice total "
                f"{invoice.total_amount}"
            )
        now = datetime.now(UTC)
        note_number = await generate_credit_note_number(
            self.number_counter_repository, at=now
        )
        note = await self.note_repository.create_note(
            invoice_id=invoice.id,
            note_type=NoteType.CREDIT.value,
            note_number=note_number,
            amount=amount,
            reason=reason,
            issued_at=now,
            created_by=actor_user_id,
        )
        event = CreditNoteIssued(
            note_id=note.id,
            invoice_id=invoice.id,
            organization_id=invoice.organization_id,
            amount=str(amount),
        )
        logger.info("billing_credit_note_issued", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CREDIT_NOTE_ISSUED,
            invoice,
            description=f"Credit note {note.note_number} issued against "
            f"invoice {invoice.invoice_number} ({amount})",
        )
        return note

    async def issue_debit_note(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        invoice_id: uuid.UUID,
        amount: Decimal,
        reason: str,
    ) -> CreditDebitNote:
        """A debit note increases what the customer owes (e.g. an
        under-billed correction) -- legal against the same set of invoice
        statuses a credit note is (``ISSUED``/``OVERDUE``/``PAID``), with
        its own, entirely independent number sequence (never the credit
        note's, never the invoice's -- see ``number_generator.py``)."""
        invoice = await self.get_invoice(invoice_id)
        if InvoiceStatus(invoice.status) not in (
            InvoiceStatus.ISSUED,
            InvoiceStatus.OVERDUE,
            InvoiceStatus.PAID,
        ):
            raise InvalidInvoiceStatusTransitionError(invoice.status, "debit_note")
        if amount <= 0:
            raise InvalidNoteAmountError("Debit note amount must be positive")
        now = datetime.now(UTC)
        note_number = await generate_debit_note_number(
            self.number_counter_repository, at=now
        )
        note = await self.note_repository.create_note(
            invoice_id=invoice.id,
            note_type=NoteType.DEBIT.value,
            note_number=note_number,
            amount=amount,
            reason=reason,
            issued_at=now,
            created_by=actor_user_id,
        )
        event = DebitNoteIssued(
            note_id=note.id,
            invoice_id=invoice.id,
            organization_id=invoice.organization_id,
            amount=str(amount),
        )
        logger.info("billing_debit_note_issued", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DEBIT_NOTE_ISSUED,
            invoice,
            description=f"Debit note {note.note_number} issued against "
            f"invoice {invoice.invoice_number} ({amount})",
        )
        return note

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        invoice: Invoice,
        *,
        description: str,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="invoice",
                entity_id=invoice.id,
                description=description,
                event_metadata={},
                organization_id=invoice.organization_id,
                location_id=None,
            )
        logger.info("billing_invoice_audit_event", extra={"action": action.value})


# ============================================================================
# BE-013 Part 5: Super Admin + Customer Billing Dashboards
#
# ## This domain's own Revenue Dashboard vs. Analytics' RevenueMetricsResponse
#
# ``app.domains.analytics.dashboard_schemas.RevenueMetricsResponse`` is a
# separate, PRE-EXISTING, still-honest placeholder (``available=False``,
# every figure ``None``) that BE-012 Part 5 built at a time when no billing
# domain existed anywhere in this codebase to compute real revenue/MRR/ARR
# from. That module, and every one of its own files, is explicitly untouched
# by this part (this module's own directory rule forbids editing anything
# under ``app.domains.analytics``). The ``SuperAdminBillingDashboardService``
# below is a DISTINCT, new capability that lives entirely inside this
# domain, composing exclusively this domain's own ``Payment``/
# ``Subscription``/``Plan``/``Invoice`` tables -- it is not a fix to
# Analytics' placeholder (a future part/module, working inside
# ``app.domains.analytics`` itself, could wire that placeholder up to call
# into this domain's own public service methods -- that is explicitly out
# of THIS part's scope, and is not attempted here).
#
# ## Dashboard-view audit-throttling decision
#
# These are read-heavy, pollable dashboard endpoints -- the identical shape
# ``app.domains.analytics.dashboard_audit``'s own module docstring already
# reasons about at length (a routine, repeatable, no-state-change read that
# a real admin UI is expected to refresh/poll, not click once). This module
# applies the same middle-ground judgment, re-implemented locally (see
# ``constants.BILLING_DASHBOARD_AUDIT_THROTTLE_MINUTES``'s own docstring for
# why a fresh, domain-local copy was chosen over importing analytics' class
# directly): every dashboard view is logged via the structured logger
# unconditionally; at most one row is written into RBAC's shared
# ``audit_log_entries`` table per ``(user_id, dashboard_kind, scope_key)``
# per ``BILLING_DASHBOARD_AUDIT_THROTTLE_MINUTES`` window, via a real,
# Redis-backed ``SET ... NX EX`` dedup (``_should_write_dashboard_audit``
# below) -- not a fabricated "always audit" nor a "never audit" default.
# ============================================================================


class DashboardAuditLogWriter(Protocol):
    """Identical shape to ``AuditLogWriter`` above -- kept as its own named
    ``Protocol`` purely so the two dashboard services' own constructors read
    self-documentingly without implying they share ``PlanService``'s/
    ``LicenseService``'s etc. broader audit conventions."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


async def _should_write_dashboard_audit(
    redis: Redis,
    *,
    user_id: uuid.UUID,
    dashboard_kind: str,
    scope_key: str,
    window_minutes: int = BILLING_DASHBOARD_AUDIT_THROTTLE_MINUTES,
) -> bool:
    """Returns ``True`` (and marks the window consumed) the first time this
    exact ``(user_id, dashboard_kind, scope_key)`` combination is seen
    within the current window; ``False`` on every subsequent call inside
    that same window. See module section docstring above for the full
    volume-tiering write-up."""
    key = BILLING_DASHBOARD_AUDIT_THROTTLE_KEY_TEMPLATE.format(
        key=f"{user_id}:{dashboard_kind}:{scope_key}"
    )
    was_set = await redis.set(key, "1", nx=True, ex=window_minutes * 60)
    return bool(was_set)


@dataclass(frozen=True, slots=True)
class RevenueTrendPoint:
    """One calendar month's real, computed net revenue -- ``month`` is an
    ``"YYYY-MM"`` label."""

    month: str
    gross_amount: Decimal
    refunded_amount: Decimal
    net_amount: Decimal


@dataclass(frozen=True, slots=True)
class RevenueDashboardResult:
    """The Super Admin Revenue Dashboard's real, computed figures -- see
    ``SuperAdminBillingDashboardService.get_revenue_dashboard``'s own
    docstring for the exact MRR/ARR formula."""

    total_revenue: Decimal
    total_refunded: Decimal
    mrr: Decimal
    arr: Decimal
    active_paying_subscription_count: int
    trend: list[RevenueTrendPoint]
    currency_note: str


@dataclass(frozen=True, slots=True)
class ChurnRateResult:
    """The real, computed churn-rate figures for one period -- see
    ``get_subscription_dashboard``'s own docstring for the exact formula
    and its honest "cannot be computed" (``None``) case."""

    period_start: datetime
    period_end: datetime
    active_at_period_start: int
    cancelled_this_period: int
    churn_rate: float | None


@dataclass(frozen=True, slots=True)
class SubscriptionDashboardResult:
    counts_by_status: dict[str, int]
    counts_by_plan_type: dict[str, int]
    churn: ChurnRateResult


@dataclass(frozen=True, slots=True)
class CustomerBillingSummaryRow:
    """One organization's summary row on the Customer Billing Dashboard."""

    organization_id: uuid.UUID
    organization_name: str
    plan_id: uuid.UUID
    plan_name: str
    plan_slug: str
    subscription_status: str
    lifetime_revenue: Decimal
    outstanding_invoice_count: int


@dataclass(frozen=True, slots=True)
class FailedPaymentRow:
    """One failed ``Payment``, with its real retry-eligibility flag (see
    ``validators.is_payment_retry_eligible``'s own docstring for why this
    is the *same* rule ``PaymentService.retry_failed_payment`` itself
    enforces, not a second, independently-maintained copy of it)."""

    payment: Payment
    retry_eligible: bool


@dataclass(frozen=True, slots=True)
class FailedPaymentsDashboardResult:
    items: list[FailedPaymentRow]
    total_items: int
    counts_by_provider: dict[str, int]


class SuperAdminBillingDashboardService:
    """The Super Admin Revenue / Subscription / Customer Billing / Failed
    Payments dashboards -- ``GLOBAL``-scope-only (enforced by the router's
    own ``RequirePermission(..., scope=ScopeType.GLOBAL)``, mirroring every
    other platform-wide dashboard already built in this codebase).

    Every figure here is a real, composed aggregate over this domain's own
    ``Payment``/``Subscription``/``Plan``/``Invoice`` tables -- reused via
    ``BillingDashboardRepositoryProtocol`` (new aggregate queries this part
    adds) and ``PaymentService.list_failed_payments`` (Part 3's own,
    already-built method, reused verbatim here rather than re-queried a
    second way).
    """

    def __init__(
        self,
        repository: BillingDashboardRepositoryProtocol,
        payment_service: PaymentService,
        invoice_service: InvoiceService,
        *,
        redis: Redis | None = None,
        audit_writer: DashboardAuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.payment_service = payment_service
        self.invoice_service = invoice_service
        self.redis = redis
        self.audit_writer = audit_writer

    async def get_license_status_breakdown(self) -> dict[str, int]:
        """Real ``License.status`` counts across every organization on the
        platform -- e.g. ``{"active": 42, "suspended": 3, "expired": 1}``.
        Every key is a real ``constants.LicenseStatus`` value; a status
        with zero licenses simply does not appear (never a fabricated
        zero)."""
        rows = await self.repository.count_licenses_by_status()
        return {status: count for status, count in rows}

    async def get_revenue_dashboard(
        self, *, user_id: uuid.UUID, months: int = 12
    ) -> RevenueDashboardResult:
        """Real total revenue, real MRR/ARR, and a real month-by-month
        trend.

        ## Total revenue

        ``SUM(Payment.amount) - SUM(Payment.refunded_amount)`` over every
        ``Payment`` in ``constants.DASHBOARD_CAPTURED_PAYMENT_STATUSES``
        (see that constant's own docstring for exactly why this status set,
        not a literal ``status = SUCCEEDED`` reading of the module brief).

        ## MRR / ARR formula

        ``MRR = sum, over every currently-ACTIVE Subscription, of
        validators.compute_renewal_charge_amount(plan)`` normalized to a
        monthly figure by that subscription's own ``billing_cycle``
        (``MONTHLY`` -> unchanged; ``YEARLY`` -> divided by 12; ``NONE`` --
        a cycle-less trial/bespoke arrangement, see ``BillingCycle.NONE``'s
        own docstring -- excluded, since it has no fixed recurring cadence
        to annualize). ``ARR = MRR * 12``. Only ``ACTIVE`` subscriptions
        count -- deliberately excludes ``TRIALING`` (never yet actually
        billed) and ``PAST_DUE`` (its most recent renewal attempt already
        failed to collect this period's charge -- counting it would
        overstate *realized* recurring revenue). This mirrors the standard
        SaaS "MRR = revenue from currently active, paying subscriptions"
        definition, applied conservatively.

        ## Multi-currency honesty note

        This platform supports more than one ``Plan.currency``/
        ``Payment.currency`` (e.g. USD/INR, for GST support) and has no
        FX-conversion table or service anywhere in this codebase. Every sum
        here is a raw, un-converted sum across whatever currencies are
        present -- meaningful at face value only if the platform's real
        payment activity is effectively single-currency in practice. This
        is surfaced honestly via ``currency_note`` rather than silently
        blended, the same "honest caveat over a fabricated precise number"
        discipline this domain already applies elsewhere (e.g.
        ``TaxRateRepository.get_active_for_country``'s "no active rate ==
        honest zero tax" outcome).
        """
        gross, refunded = await self.repository.sum_captured_payments()

        plan_cycle_pairs = await self.repository.list_active_subscription_plans()
        mrr = Decimal("0.00")
        for plan, billing_cycle in plan_cycle_pairs:
            charge = compute_renewal_charge_amount(plan)
            if billing_cycle == BillingCycle.MONTHLY.value:
                mrr += charge
            elif billing_cycle == BillingCycle.YEARLY.value:
                mrr += (charge / Decimal(12)).quantize(Decimal("0.01"))
            # BillingCycle.NONE -- no fixed cadence, excluded (see docstring).
        arr = (mrr * Decimal(12)).quantize(Decimal("0.01"))

        now = datetime.now(UTC)
        clamped_months = max(
            MIN_DASHBOARD_REVENUE_TREND_MONTHS,
            min(months, MAX_DASHBOARD_REVENUE_TREND_MONTHS),
        )
        window_start = subtract_months(now, clamped_months - 1).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        monthly_rows = await self.repository.revenue_by_month(
            start=window_start, end=now
        )
        trend = [
            RevenueTrendPoint(
                month=month_start.strftime("%Y-%m"),
                gross_amount=gross_month,
                refunded_amount=refunded_month,
                net_amount=(gross_month - refunded_month).quantize(Decimal("0.01")),
            )
            for month_start, gross_month, refunded_month in monthly_rows
        ]

        await self._maybe_audit(
            user_id,
            dashboard_kind="super_admin_revenue",
            scope_key="global",
            description="Super Admin Revenue Dashboard viewed",
        )

        return RevenueDashboardResult(
            total_revenue=(gross - refunded).quantize(Decimal("0.01")),
            total_refunded=refunded.quantize(Decimal("0.01")),
            mrr=mrr,
            arr=arr,
            active_paying_subscription_count=len(plan_cycle_pairs),
            trend=trend,
            currency_note=(
                "Figures are a raw sum across every Plan/Payment currency in "
                "use on this platform -- no FX-conversion table or service "
                "exists anywhere in this codebase. Meaningful at face value "
                "only if real payment activity is effectively single-currency."
            ),
        )

    async def get_subscription_dashboard(
        self, *, user_id: uuid.UUID
    ) -> SubscriptionDashboardResult:
        """Counts by ``Subscription.status`` / ``Plan.plan_type``, and a
        real churn-rate computation.

        ## Churn-rate formula (define-and-document, per this part's own
        ## instruction)

        For the **current calendar month** (``validators.current_month_
        period`` -- the same "start of this month" definition
        ``UsageService`` already uses elsewhere in this domain):

        ``churn_rate = cancelled_this_period / active_at_period_start``

        * ``active_at_period_start`` -- every ``Subscription`` that had
          already ``started_at <= period_start`` and had not yet been
          cancelled as of that moment (``cancelled_at IS NULL`` or later
          than ``period_start``) -- see ``BillingDashboardRepository
          .count_subscriptions_active_before``'s own docstring for why this
          is an honest, real heuristic (this domain keeps no historical
          per-day subscription-status-snapshot table), the same
          "judgment-based but real, not fabricated" rigor
          ``app.domains.analytics.health_score`` already establishes for a
          similarly judgment-based metric elsewhere in this codebase.
        * ``cancelled_this_period`` -- every ``Subscription`` whose
          ``cancelled_at`` falls within ``[period_start, period_end]``.
        * ``churn_rate`` is ``None`` (never a fabricated ``0.0``) when
          ``active_at_period_start == 0`` -- there is no honest rate to
          report for a period with no active base to measure churn
          against.
        """
        status_rows = await self.repository.count_subscriptions_by_status()
        plan_type_rows = await self.repository.count_subscriptions_by_plan_type()

        now = datetime.now(UTC)
        period_start, period_end = current_month_period(now)
        active_at_start = await self.repository.count_subscriptions_active_before(
            period_start
        )
        cancelled_this_period = (
            await self.repository.count_subscriptions_cancelled_between(
                period_start, period_end
            )
        )
        churn_rate = (
            cancelled_this_period / active_at_start if active_at_start > 0 else None
        )

        await self._maybe_audit(
            user_id,
            dashboard_kind="super_admin_subscriptions",
            scope_key="global",
            description="Super Admin Subscription Dashboard viewed",
        )

        return SubscriptionDashboardResult(
            counts_by_status=dict(status_rows),
            counts_by_plan_type=dict(plan_type_rows),
            churn=ChurnRateResult(
                period_start=period_start,
                period_end=period_end,
                active_at_period_start=active_at_start,
                cancelled_this_period=cancelled_this_period,
                churn_rate=churn_rate,
            ),
        )

    async def get_customer_billing_dashboard(
        self, *, user_id: uuid.UUID, page: int = 1, page_size: int = 25
    ) -> tuple[list[CustomerBillingSummaryRow], PaginationMeta]:
        """Paginated per-organization summary rows -- see
        ``BillingDashboardRepository
        .paginate_subscriptions_with_org_and_plan``'s own docstring for the
        real, joined driving query. Each row's ``lifetime_revenue``/
        ``outstanding_invoice_count`` are computed by reusing this same
        module's existing aggregate/list methods (never a hand-rolled
        second query per row)."""
        rows, meta = await self.repository.paginate_subscriptions_with_org_and_plan(
            page=page, page_size=page_size
        )
        summary_rows: list[CustomerBillingSummaryRow] = []
        for subscription, organization, plan in rows:
            gross, refunded = await self.repository.sum_captured_payments(
                organization_id=organization.id
            )
            outstanding = 0
            for invoice_status in (InvoiceStatus.ISSUED, InvoiceStatus.OVERDUE):
                _, invoice_meta = await self.invoice_service.list_invoices(
                    page=1,
                    page_size=1,
                    organization_id=organization.id,
                    status=invoice_status.value,
                )
                outstanding += invoice_meta.total_items
            summary_rows.append(
                CustomerBillingSummaryRow(
                    organization_id=organization.id,
                    organization_name=organization.name,
                    plan_id=plan.id,
                    plan_name=plan.name,
                    plan_slug=plan.slug,
                    subscription_status=subscription.status,
                    lifetime_revenue=(gross - refunded).quantize(Decimal("0.01")),
                    outstanding_invoice_count=outstanding,
                )
            )

        await self._maybe_audit(
            user_id,
            dashboard_kind="super_admin_customers",
            scope_key="global",
            description="Super Admin Customer Billing Dashboard viewed",
        )
        return summary_rows, meta

    async def get_failed_payments_dashboard(
        self,
        *,
        user_id: uuid.UUID,
        page: int = 1,
        page_size: int = 25,
        organization_id: uuid.UUID | None = None,
    ) -> FailedPaymentsDashboardResult:
        """Reuses ``PaymentService.list_failed_payments`` (Part 3's own,
        already-built query -- never re-queried a second way here), sliced
        in Python for this dashboard's own page/page_size (that existing
        method was not itself built with repository-level pagination, and
        widening its signature is out of this part's own narrow scope).
        Each row's ``retry_eligible`` flag reuses
        ``validators.is_payment_retry_eligible`` -- the exact same rule
        ``PaymentService.retry_failed_payment`` itself enforces."""
        all_failed = await self.payment_service.list_failed_payments(
            organization_id=organization_id
        )
        counts_by_provider: dict[str, int] = {}
        for payment in all_failed:
            counts_by_provider[payment.provider] = (
                counts_by_provider.get(payment.provider, 0) + 1
            )

        start = (max(page, 1) - 1) * max(page_size, 1)
        page_items = all_failed[start : start + page_size]
        rows = [
            FailedPaymentRow(
                payment=payment,
                retry_eligible=is_payment_retry_eligible(payment.status),
            )
            for payment in page_items
        ]

        await self._maybe_audit(
            user_id,
            dashboard_kind="super_admin_failed_payments",
            scope_key=str(organization_id) if organization_id else "global",
            description="Super Admin Failed Payments Dashboard viewed",
        )
        return FailedPaymentsDashboardResult(
            items=rows,
            total_items=len(all_failed),
            counts_by_provider=counts_by_provider,
        )

    async def _maybe_audit(
        self,
        user_id: uuid.UUID,
        *,
        dashboard_kind: str,
        scope_key: str,
        description: str,
    ) -> None:
        logger.info(
            "billing_dashboard_viewed",
            extra={"dashboard_kind": dashboard_kind, "scope_key": scope_key},
        )
        if self.redis is None:
            return
        should_write = await _should_write_dashboard_audit(
            self.redis,
            user_id=user_id,
            dashboard_kind=dashboard_kind,
            scope_key=scope_key,
        )
        if not should_write or self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=user_id,
            action=AUDIT_ACTION_DASHBOARD_SUPER_ADMIN_VIEWED,
            entity_type="billing_dashboard",
            entity_id=user_id,
            description=description,
            event_metadata={"dashboard_kind": dashboard_kind},
            organization_id=None,
            location_id=None,
        )


@dataclass(frozen=True, slots=True)
class CustomerBillingDashboardResult:
    """The unified customer billing summary -- see
    ``CustomerBillingDashboardService.get_dashboard``'s own docstring for
    exactly which existing service method backs each field (nothing here
    is recomputed a second way)."""

    license: License
    plan: Plan
    plan_features: list[PlanFeature]
    subscription: Subscription
    usage: UsageValidationResult
    recent_invoices: list[Invoice]
    payment_methods: list[PaymentMethod]
    recent_payments: list[Payment]


class CustomerBillingDashboardService:
    """The tenant-scoped, customer-facing "unified billing summary" -- pure
    composition over six already-built services from Parts 1-4, never a
    second, independent recomputation of any figure they already provide."""

    def __init__(
        self,
        *,
        license_service: LicenseService,
        plan_service: PlanService,
        subscription_service: SubscriptionService,
        usage_service: UsageService,
        invoice_service: InvoiceService,
        payment_service: PaymentService,
        payment_method_service: PaymentMethodService,
        audit_writer: DashboardAuditLogWriter | None = None,
    ) -> None:
        self.license_service = license_service
        self.plan_service = plan_service
        self.subscription_service = subscription_service
        self.usage_service = usage_service
        self.invoice_service = invoice_service
        self.payment_service = payment_service
        self.payment_method_service = payment_method_service
        self.audit_writer = audit_writer

    async def get_dashboard(
        self, organization_id: uuid.UUID
    ) -> CustomerBillingDashboardResult:
        """Composes -- never recomputes:

        * current ``License``/``Plan`` status -- ``LicenseService
          .get_license_for_organization`` + ``PlanService.get_plan``.
        * active ``Subscription`` details (period, ``auto_renew``, next
          renewal date) -- ``SubscriptionService
          .get_subscription_for_organization``.
        * a real usage-vs-limit snapshot -- ``UsageService
          .validate_usage_against_license`` (Part 1's own existing method,
          called here verbatim).
        * recent invoices/payments -- ``InvoiceService.list_invoices``/
          ``PaymentService.list_payments``, each capped to this module's
          own dashboard-summary limit (``constants
          .CUSTOMER_DASHBOARD_RECENT_INVOICES_LIMIT``/
          ``_RECENT_PAYMENTS_LIMIT`` -- a summary, not the full paginated
          history already available at ``GET /invoices``/``GET
          /payments``).
        * registered payment methods -- ``PaymentMethodService
          .list_payment_methods``.
        """
        license_ = await self.license_service.get_license_for_organization(
            organization_id
        )
        plan = await self.plan_service.get_plan(license_.plan_id)
        plan_features = await self.plan_service.list_features(plan.id)
        subscription = (
            await self.subscription_service.get_subscription_for_organization(
                organization_id
            )
        )
        usage = await self.usage_service.validate_usage_against_license(organization_id)
        invoices, _ = await self.invoice_service.list_invoices(
            organization_id=organization_id,
            page=1,
            page_size=CUSTOMER_DASHBOARD_RECENT_INVOICES_LIMIT,
        )
        payment_methods = await self.payment_method_service.list_payment_methods(
            organization_id
        )
        payments, _ = await self.payment_service.list_payments(
            organization_id=organization_id,
            page=1,
            page_size=CUSTOMER_DASHBOARD_RECENT_PAYMENTS_LIMIT,
        )

        logger.info(
            "billing_dashboard_viewed",
            extra={
                "dashboard_kind": "customer",
                "organization_id": str(organization_id),
            },
        )
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=None,
                action=AUDIT_ACTION_DASHBOARD_CUSTOMER_VIEWED,
                entity_type="billing_dashboard",
                entity_id=organization_id,
                description=f"Customer billing dashboard viewed for organization "
                f"{organization_id}",
                event_metadata={},
                organization_id=organization_id,
                location_id=None,
            )

        return CustomerBillingDashboardResult(
            license=license_,
            plan=plan,
            plan_features=plan_features,
            subscription=subscription,
            usage=usage,
            recent_invoices=invoices,
            payment_methods=payment_methods,
            recent_payments=payments,
        )


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick to ``app.domains.otp.service``/
    ``app.domains.wireguard.service``'s own ``_event_extra`` (``vars()``
    doesn't work on slotted dataclasses)."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


__all__ = [
    "AuditLogWriter",
    "OrganizationSyncProtocol",
    "OrganizationLookupProtocol",
    "GuestAnalyticsLookupProtocol",
    "ActiveSessionLookupProtocol",
    "UsageValidatorProtocol",
    "LicenseLifecycleProtocol",
    "PlanService",
    "LicenseService",
    "UsageService",
    "UsageLimitCheck",
    "UsageValidationResult",
    "CouponService",
    "SubscriptionService",
    "PaymentService",
    "PaymentMethodService",
    "TaxRateService",
    "BillingProfileService",
    "InvoiceService",
    "DashboardAuditLogWriter",
    "RevenueTrendPoint",
    "RevenueDashboardResult",
    "ChurnRateResult",
    "SubscriptionDashboardResult",
    "CustomerBillingSummaryRow",
    "FailedPaymentRow",
    "FailedPaymentsDashboardResult",
    "SuperAdminBillingDashboardService",
    "CustomerBillingDashboardResult",
    "CustomerBillingDashboardService",
]
