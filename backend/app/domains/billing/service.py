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
from datetime import UTC, datetime
from decimal import Decimal
from typing import Protocol

from app.domains.otp.constants import OtpChannel
from app.domains.rbac.enums import AuditAction

from .constants import (
    BYTES_PER_MB,
    USAGE_METRIC_TO_LIMIT_FEATURE,
    LicenseChangeType,
    LicenseStatus,
    PlanFeatureType,
    UsageMetricKey,
)
from .events import (
    LicenseActivated,
    LicenseAssigned,
    LicenseCancelled,
    LicenseDowngraded,
    LicenseExpired,
    LicenseSuspended,
    LicenseUpgraded,
)
from .exceptions import (
    DowngradeBelowUsageError,
    DuplicateLicenseError,
    DuplicatePlanFeatureError,
    DuplicatePlanSlugError,
    InvalidLicenseStatusTransitionError,
    LicenseNotActiveError,
    LicenseNotFoundError,
    PlanInactiveError,
    PlanNotFoundError,
    SamePlanError,
)
from .models import License, LicenseChangeLog, Plan, PlanFeature, UsageMetric
from .repository import (
    LicenseRepositoryProtocol,
    PlanRepositoryProtocol,
    UsageRepositoryProtocol,
)
from .validators import normalize_slug, validate_feature_value

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
    "PlanService",
    "LicenseService",
    "UsageService",
    "UsageLimitCheck",
    "UsageValidationResult",
]
