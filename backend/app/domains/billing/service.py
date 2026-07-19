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

from app.domains.otp.constants import OtpChannel
from app.domains.rbac.enums import AuditAction

from .constants import (
    BYTES_PER_MB,
    USAGE_METRIC_TO_LIMIT_FEATURE,
    DiscountType,
    LicenseChangeType,
    LicenseStatus,
    PlanFeatureType,
    PlanType,
    SubscriptionStatus,
    UsageMetricKey,
)
from .events import (
    CouponApplied,
    CouponValidationFailed,
    LicenseActivated,
    LicenseAssigned,
    LicenseCancelled,
    LicenseDowngraded,
    LicenseExpired,
    LicenseSuspended,
    LicenseUpgraded,
    SubscriptionCancelled,
    SubscriptionCreated,
    SubscriptionPaused,
    SubscriptionReactivated,
    SubscriptionResumed,
)
from .exceptions import (
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
    InvalidLicenseStatusTransitionError,
    InvalidSubscriptionStatusTransitionError,
    LicenseNotActiveError,
    LicenseNotFoundError,
    PlanInactiveError,
    PlanNotFoundError,
    SamePlanError,
    SubscriptionNotFoundError,
    SubscriptionReactivationNotAllowedError,
)
from .models import (
    Coupon,
    License,
    LicenseChangeLog,
    Plan,
    PlanFeature,
    Subscription,
    UsageMetric,
)
from .repository import (
    CouponRepositoryProtocol,
    LicenseRepositoryProtocol,
    PlanRepositoryProtocol,
    SubscriptionRepositoryProtocol,
    UsageRepositoryProtocol,
)
from .validators import (
    add_billing_cycle,
    compute_discount_amount,
    normalize_coupon_code,
    normalize_slug,
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
    ) -> None:
        self.repository = repository
        self.plan_repository = plan_repository
        self.organization_sync = organization_sync
        self.usage_validator = usage_validator
        self.audit_writer = audit_writer

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


def _current_month_period(now: datetime) -> tuple[datetime, datetime]:
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return period_start, now


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
        bucket -- see ``_current_month_period``) every ``UsageMetricKey``
        for this organization from real, composed data. See module
        docstring for the exact source of each metric."""
        now = datetime.now(UTC)
        period_start, period_end = _current_month_period(now)

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
        period_start, _ = _current_month_period(datetime.now(UTC))
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
]
