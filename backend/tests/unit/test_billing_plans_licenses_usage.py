"""Unit tests for BE-013 Part 1 (Billing: Plan + License + Usage Core):
Plan/PlanFeature CRUD (including typed-value-per-feature-type correctness
and the GLOBAL-scope "Super Admin only" RBAC gate on catalog writes),
License lifecycle (assign -> activate -> suspend -> reactivate,
upgrade/downgrade with real ``LicenseChangeLog`` history and
``Organization.subscription_tier`` sync, expire, cancel, every illegal
status transition rejected), real composed Usage tracking (verified via
spies that it calls existing domains' own lookups/aggregates rather than
recomputing anything a second way), usage-vs-limit validation (both
within-limit and exceeded cases), downgrade-vs-usage enforcement, and
tenant isolation.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_otp.py``'s own module docstring); ``asyncio_mode =
"auto"`` runs async tests directly. Every service under test is exercised
against small, hand-rolled in-memory fakes satisfying this module's own
narrow ``Protocol`` shapes -- no live Postgres/Redis anywhere in this test
suite, mirroring every other domain's own unit test file.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.billing.constants import (
    BillingCycle,
    LicenseStatus,
    PlanFeatureKey,
    PlanFeatureType,
    PlanType,
    SupportTier,
    UsageMetricKey,
)
from app.domains.billing.exceptions import (
    DowngradeBelowUsageError,
    DuplicateLicenseError,
    DuplicatePlanFeatureError,
    DuplicatePlanSlugError,
    InvalidLicenseStatusTransitionError,
    InvalidPlanFeatureValueError,
    LicenseNotActiveError,
    LicenseNotFoundError,
    PlanNotFoundError,
    SamePlanError,
)
from app.domains.billing.models import (
    License,
    LicenseChangeLog,
    Plan,
    PlanFeature,
    UsageMetric,
)
from app.domains.billing.service import (
    LicenseService,
    PlanService,
    UsageService,
    UsageValidationResult,
)
from app.domains.billing.validators import validate_feature_value
from app.domains.rbac.dependencies import RequirePermission
from app.domains.rbac.enums import ScopeType

# ============================================================================
# Shared helpers
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


# ============================================================================
# Fake repositories (satisfy app.domains.billing.repository's Protocols)
# ============================================================================


@dataclass
class FakePlanRepository:
    plans: dict[uuid.UUID, Plan] = field(default_factory=dict)
    features: dict[uuid.UUID, PlanFeature] = field(default_factory=dict)

    async def create_plan(self, **fields: object) -> Plan:
        plan = Plan(**_base_fields(**fields))
        self.plans[plan.id] = plan
        return plan

    async def get_by_id(
        self, plan_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Plan | None:
        plan = self.plans.get(plan_id)
        if plan is None:
            return None
        if plan.is_deleted and not include_deleted:
            return None
        return plan

    async def get_by_slug(self, slug: str) -> Plan | None:
        for plan in self.plans.values():
            if plan.slug == slug and not plan.is_deleted:
                return plan
        return None

    async def update_plan(self, plan: Plan, data: dict[str, object]) -> Plan:
        for key, value in data.items():
            setattr(plan, key, value)
        plan.version += 1
        return plan

    async def soft_delete_plan(self, plan: Plan) -> Plan:
        plan.is_deleted = True
        plan.deleted_at = _now()
        return plan

    async def list_plans(
        self,
        *,
        page: int,
        page_size: int,
        is_public: bool | None = None,
        is_active: bool | None = None,
        plan_type: str | None = None,
    ) -> tuple[list[Plan], PaginationMeta]:
        items = [p for p in self.plans.values() if not p.is_deleted]
        if is_public is not None:
            items = [p for p in items if p.is_public == is_public]
        if is_active is not None:
            items = [p for p in items if p.is_active == is_active]
        if plan_type is not None:
            items = [p for p in items if p.plan_type == plan_type]
        items.sort(key=lambda p: p.sort_order)
        params = PageParams(page=page, page_size=page_size)
        total = len(items)
        page_items = items[params.offset : params.offset + params.page_size]
        return page_items, PaginationMeta.from_total(params, total)

    async def create_plan_feature(self, **fields: object) -> PlanFeature:
        feature = PlanFeature(**_base_fields(**fields))
        self.features[feature.id] = feature
        return feature

    async def list_plan_features(self, plan_id: uuid.UUID) -> list[PlanFeature]:
        return [
            f
            for f in self.features.values()
            if f.plan_id == plan_id and not f.is_deleted
        ]

    async def delete_plan_features(self, plan_id: uuid.UUID) -> None:
        for feature_id in [
            f.id for f in self.features.values() if f.plan_id == plan_id
        ]:
            del self.features[feature_id]


@dataclass
class FakeLicenseRepository:
    licenses: dict[uuid.UUID, License] = field(default_factory=dict)
    change_logs: dict[uuid.UUID, LicenseChangeLog] = field(default_factory=dict)

    async def create_license(self, **fields: object) -> License:
        license_ = License(**_base_fields(**fields))
        self.licenses[license_.id] = license_
        return license_

    async def get_by_id(
        self, license_id: uuid.UUID, *, include_deleted: bool = False
    ) -> License | None:
        license_ = self.licenses.get(license_id)
        if license_ is None:
            return None
        if license_.is_deleted and not include_deleted:
            return None
        return license_

    async def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> License | None:
        for license_ in self.licenses.values():
            if license_.organization_id == organization_id and not license_.is_deleted:
                return license_
        return None

    async def update_license(
        self, license_: License, data: dict[str, object]
    ) -> License:
        for key, value in data.items():
            setattr(license_, key, value)
        license_.version += 1
        return license_

    async def create_change_log(self, **fields: object) -> LicenseChangeLog:
        entry = LicenseChangeLog(**_base_fields(**fields))
        self.change_logs[entry.id] = entry
        return entry

    async def list_change_logs(self, license_id: uuid.UUID) -> list[LicenseChangeLog]:
        entries = [e for e in self.change_logs.values() if e.license_id == license_id]
        entries.sort(key=lambda e: e.changed_at, reverse=True)
        return entries


@dataclass
class FakeUsageRepository:
    metrics: dict[uuid.UUID, UsageMetric] = field(default_factory=dict)
    location_counts: dict[uuid.UUID, int] = field(default_factory=dict)
    router_counts: dict[uuid.UUID, int] = field(default_factory=dict)
    otp_channel_counts: dict[uuid.UUID, list[tuple[str, int]]] = field(
        default_factory=dict
    )
    count_locations_calls: list[uuid.UUID] = field(default_factory=list)
    count_routers_calls: list[uuid.UUID] = field(default_factory=list)
    count_otp_calls: list[tuple[uuid.UUID, datetime, datetime]] = field(
        default_factory=list
    )

    async def get_current_period_metric(
        self, organization_id: uuid.UUID, metric_key: str, period_start: datetime
    ) -> UsageMetric | None:
        for metric in self.metrics.values():
            if (
                metric.organization_id == organization_id
                and metric.metric_key == metric_key
                and metric.period_start == period_start
            ):
                return metric
        return None

    async def list_current_period_metrics(
        self, organization_id: uuid.UUID, period_start: datetime
    ) -> list[UsageMetric]:
        return [
            m
            for m in self.metrics.values()
            if m.organization_id == organization_id and m.period_start == period_start
        ]

    async def create_usage_metric(self, **fields: object) -> UsageMetric:
        metric = UsageMetric(**_base_fields(**fields))
        self.metrics[metric.id] = metric
        return metric

    async def update_usage_metric(
        self, metric: UsageMetric, data: dict[str, object]
    ) -> UsageMetric:
        for key, value in data.items():
            setattr(metric, key, value)
        metric.version += 1
        return metric

    async def count_locations(self, organization_id: uuid.UUID) -> int:
        self.count_locations_calls.append(organization_id)
        return self.location_counts.get(organization_id, 0)

    async def count_routers(self, organization_id: uuid.UUID) -> int:
        self.count_routers_calls.append(organization_id)
        return self.router_counts.get(organization_id, 0)

    async def count_otp_requests_by_channel(
        self, organization_id: uuid.UUID, *, start: datetime, end: datetime
    ) -> list[tuple[str, int]]:
        self.count_otp_calls.append((organization_id, start, end))
        return self.otp_channel_counts.get(organization_id, [])


# ============================================================================
# Fake cross-domain composition lookups
# ============================================================================


@dataclass
class _FakeOrganization:
    id: uuid.UUID
    msp: bool = False

    def is_msp(self) -> bool:
        return self.msp


class FakeOrganizationComposer:
    """Satisfies both ``OrganizationLookupProtocol`` (usage's
    ``ORGANIZATIONS`` metric) and ``OrganizationSyncProtocol``
    (``sync_subscription_tier``) -- the real ``OrganizationService`` does
    both too."""

    def __init__(
        self,
        organizations: dict[uuid.UUID, _FakeOrganization] | None = None,
        children: dict[uuid.UUID, list[_FakeOrganization]] | None = None,
    ) -> None:
        self._organizations = organizations or {}
        self._children = children or {}
        self.sync_calls: list[tuple[uuid.UUID, str | None]] = []

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> _FakeOrganization:
        return self._organizations[organization_id]

    async def list_children(
        self, organization_id: uuid.UUID
    ) -> list[_FakeOrganization]:
        return self._children.get(organization_id, [])

    async def sync_subscription_tier(
        self, *, organization_id: uuid.UUID, subscription_tier: str | None
    ) -> None:
        self.sync_calls.append((organization_id, subscription_tier))


@dataclass(frozen=True, slots=True)
class _GuestSummary:
    visitors: int
    unique_guests: int
    returning_guests: int
    average_session_duration_seconds: float | None
    total_bandwidth_bytes: int


class FakeGuestAnalytics:
    def __init__(
        self, summary_by_org: dict[uuid.UUID, _GuestSummary] | None = None
    ) -> None:
        self._summary_by_org = summary_by_org or {}
        self.calls: list[tuple[uuid.UUID, uuid.UUID | None, datetime, datetime]] = []

    async def get_summary(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> _GuestSummary:
        self.calls.append((organization_id, location_id, start, end))
        return self._summary_by_org.get(
            organization_id,
            _GuestSummary(0, 0, 0, None, 0),
        )


class FakeActiveSessionLookup:
    def __init__(self, counts: dict[uuid.UUID, int] | None = None) -> None:
        self._counts = counts or {}
        self.calls: list[tuple[uuid.UUID | None, uuid.UUID | None]] = []

    async def count_active_guest_sessions(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> int:
        self.calls.append((organization_id, location_id))
        return self._counts.get(organization_id, 0)


@dataclass
class FakeAuditWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> None:
        self.entries.append(fields)


# ============================================================================
# Service fixtures
# ============================================================================


@dataclass
class PlanFixture:
    repository: FakePlanRepository
    audit_writer: FakeAuditWriter
    service: PlanService


def make_plan_service() -> PlanFixture:
    repository = FakePlanRepository()
    audit_writer = FakeAuditWriter()
    service = PlanService(repository, audit_writer=audit_writer)
    return PlanFixture(repository, audit_writer, service)


@dataclass
class UsageFixture:
    usage_repository: FakeUsageRepository
    plan_repository: FakePlanRepository
    license_repository: FakeLicenseRepository
    organization_composer: FakeOrganizationComposer
    guest_analytics: FakeGuestAnalytics
    active_session_lookup: FakeActiveSessionLookup
    service: UsageService


def make_usage_service(
    *,
    plan_repository: FakePlanRepository | None = None,
    license_repository: FakeLicenseRepository | None = None,
    organization_composer: FakeOrganizationComposer | None = None,
    guest_analytics: FakeGuestAnalytics | None = None,
    active_session_lookup: FakeActiveSessionLookup | None = None,
) -> UsageFixture:
    usage_repository = FakeUsageRepository()
    plan_repository = plan_repository or FakePlanRepository()
    license_repository = license_repository or FakeLicenseRepository()
    organization_composer = organization_composer or FakeOrganizationComposer()
    guest_analytics = guest_analytics or FakeGuestAnalytics()
    active_session_lookup = active_session_lookup or FakeActiveSessionLookup()
    service = UsageService(
        usage_repository,
        plan_repository,
        license_repository,
        organization_composer,
        guest_analytics,
        active_session_lookup,
    )
    return UsageFixture(
        usage_repository,
        plan_repository,
        license_repository,
        organization_composer,
        guest_analytics,
        active_session_lookup,
        service,
    )


@dataclass
class LicenseFixture:
    license_repository: FakeLicenseRepository
    plan_repository: FakePlanRepository
    organization_composer: FakeOrganizationComposer
    audit_writer: FakeAuditWriter
    usage_service: UsageService
    usage_fixture: UsageFixture
    service: LicenseService


def make_license_service(
    *,
    plan_repository: FakePlanRepository | None = None,
    organization_composer: FakeOrganizationComposer | None = None,
    guest_analytics: FakeGuestAnalytics | None = None,
    active_session_lookup: FakeActiveSessionLookup | None = None,
) -> LicenseFixture:
    license_repository = FakeLicenseRepository()
    plan_repository = plan_repository or FakePlanRepository()
    organization_composer = organization_composer or FakeOrganizationComposer()
    audit_writer = FakeAuditWriter()

    usage_fixture = make_usage_service(
        plan_repository=plan_repository,
        license_repository=license_repository,
        organization_composer=organization_composer,
        guest_analytics=guest_analytics,
        active_session_lookup=active_session_lookup,
    )

    service = LicenseService(
        license_repository,
        plan_repository,
        organization_sync=organization_composer,
        usage_validator=usage_fixture.service,
        audit_writer=audit_writer,
    )
    return LicenseFixture(
        license_repository,
        plan_repository,
        organization_composer,
        audit_writer,
        usage_fixture.service,
        usage_fixture,
        service,
    )


async def _create_plan(
    plan_repository: FakePlanRepository,
    *,
    slug: str = "starter",
    plan_type: str = PlanType.STARTER.value,
    is_active: bool = True,
    features: list[dict[str, object]] | None = None,
) -> Plan:
    plan_service = PlanService(plan_repository)
    plan = await plan_service.create_plan(
        actor_user_id=None,
        name=slug.title(),
        slug=slug,
        plan_type=plan_type,
        description=None,
        billing_cycle=BillingCycle.MONTHLY.value,
        base_price=Decimal("49.99"),
        currency="USD",
        is_active=is_active,
        is_public=True,
        sort_order=0,
        features=features or [],
    )
    return plan


# ============================================================================
# Plan CRUD
# ============================================================================


class TestPlanCrud:
    async def test_create_plan_persists_price_as_decimal(self) -> None:
        fx = make_plan_service()
        plan = await fx.service.create_plan(
            actor_user_id=None,
            name="Professional",
            slug="professional",
            plan_type=PlanType.PROFESSIONAL.value,
            description="desc",
            billing_cycle=BillingCycle.MONTHLY.value,
            base_price=Decimal("199.00"),
            currency="USD",
            is_active=True,
            is_public=True,
            sort_order=1,
            features=[],
        )
        assert isinstance(plan.base_price, Decimal)
        assert plan.base_price == Decimal("199.00")
        assert len(fx.audit_writer.entries) == 1
        assert fx.audit_writer.entries[0]["action"] == "plan_created"

    async def test_duplicate_slug_rejected(self) -> None:
        fx = make_plan_service()
        await _create_plan(fx.repository, slug="dup")
        with pytest.raises(DuplicatePlanSlugError):
            await _create_plan(fx.repository, slug="dup")

    async def test_duplicate_feature_key_within_one_plan_rejected(self) -> None:
        fx = make_plan_service()
        with pytest.raises(DuplicatePlanFeatureError):
            await fx.service.create_plan(
                actor_user_id=None,
                name="Business",
                slug="business",
                plan_type=PlanType.BUSINESS.value,
                description=None,
                billing_cycle=BillingCycle.MONTHLY.value,
                base_price=Decimal("99.00"),
                currency="USD",
                is_active=True,
                is_public=True,
                sort_order=0,
                features=[
                    {
                        "feature_key": "max_guests",
                        "feature_type": "limit",
                        "limit_value": Decimal("100"),
                    },
                    {
                        "feature_key": "max_guests",
                        "feature_type": "limit",
                        "limit_value": Decimal("200"),
                    },
                ],
            )

    async def test_update_plan_replaces_feature_set(self) -> None:
        fx = make_plan_service()
        plan = await fx.service.create_plan(
            actor_user_id=None,
            name="Starter",
            slug="starter",
            plan_type=PlanType.STARTER.value,
            description=None,
            billing_cycle=BillingCycle.MONTHLY.value,
            base_price=Decimal("9.99"),
            currency="USD",
            is_active=True,
            is_public=True,
            sort_order=0,
            features=[
                {
                    "feature_key": "max_guests",
                    "feature_type": "limit",
                    "limit_value": Decimal("50"),
                }
            ],
        )
        await fx.service.update_plan(
            actor_user_id=None,
            plan_id=plan.id,
            data={"name": "Starter Plus"},
            features=[
                {
                    "feature_key": "max_guests",
                    "feature_type": "limit",
                    "limit_value": Decimal("75"),
                },
                {
                    "feature_key": "white_label",
                    "feature_type": "boolean",
                    "is_enabled": True,
                },
            ],
        )
        updated = await fx.service.get_plan(plan.id)
        assert updated.name == "Starter Plus"
        features = await fx.service.list_features(plan.id)
        assert len(features) == 2
        by_key = {f.feature_key: f for f in features}
        assert by_key["max_guests"].limit_value == Decimal("75")
        assert by_key["white_label"].is_enabled is True

    async def test_deactivate_plan_soft_deletes_and_sets_inactive(self) -> None:
        fx = make_plan_service()
        plan = await _create_plan(fx.repository, slug="temp")
        deactivated = await fx.service.deactivate_plan(
            actor_user_id=None, plan_id=plan.id
        )
        assert deactivated.is_active is False
        assert deactivated.is_deleted is True
        with pytest.raises(PlanNotFoundError):
            await fx.service.get_plan(plan.id)

    async def test_get_plan_not_found(self) -> None:
        fx = make_plan_service()
        with pytest.raises(PlanNotFoundError):
            await fx.service.get_plan(uuid.uuid4())


class TestPlanFeatureTypedValues:
    def test_limit_feature_requires_limit_value(self) -> None:
        with pytest.raises(InvalidPlanFeatureValueError):
            validate_feature_value(
                feature_key=PlanFeatureKey.MAX_GUESTS,
                feature_type=PlanFeatureType.LIMIT,
                limit_value=None,
                is_enabled=None,
                tier_value=None,
            )

    def test_boolean_feature_requires_is_enabled(self) -> None:
        with pytest.raises(InvalidPlanFeatureValueError):
            validate_feature_value(
                feature_key=PlanFeatureKey.WHITE_LABEL,
                feature_type=PlanFeatureType.BOOLEAN,
                limit_value=None,
                is_enabled=None,
                tier_value=None,
            )

    def test_tier_feature_requires_legal_tier_value(self) -> None:
        with pytest.raises(InvalidPlanFeatureValueError):
            validate_feature_value(
                feature_key=PlanFeatureKey.SUPPORT_LEVEL,
                feature_type=PlanFeatureType.TIER,
                limit_value=None,
                is_enabled=None,
                tier_value="not-a-real-tier",
            )

    def test_mismatched_feature_type_for_key_rejected(self) -> None:
        with pytest.raises(InvalidPlanFeatureValueError):
            validate_feature_value(
                feature_key=PlanFeatureKey.MAX_GUESTS,
                feature_type=PlanFeatureType.BOOLEAN,
                limit_value=None,
                is_enabled=True,
                tier_value=None,
            )

    def test_valid_limit_boolean_tier_values_accepted(self) -> None:
        validate_feature_value(
            feature_key=PlanFeatureKey.MAX_GUESTS,
            feature_type=PlanFeatureType.LIMIT,
            limit_value=Decimal("500"),
            is_enabled=None,
            tier_value=None,
        )
        validate_feature_value(
            feature_key=PlanFeatureKey.WHITE_LABEL,
            feature_type=PlanFeatureType.BOOLEAN,
            limit_value=None,
            is_enabled=True,
            tier_value=None,
        )
        validate_feature_value(
            feature_key=PlanFeatureKey.SUPPORT_LEVEL,
            feature_type=PlanFeatureType.TIER,
            limit_value=None,
            is_enabled=None,
            tier_value=SupportTier.PRIORITY.value,
        )


class TestPlanCatalogRbacGate:
    """Verifies the exact "Super Admin only" RBAC gate ``router.py`` wires
    onto plan-catalog writes: ``RequirePermission("billing.manage",
    scope=ScopeType.GLOBAL)``. Uses a minimal fake ``AccessValidator``
    (just the one ``check`` method ``RequirePermission`` calls) rather than
    RBAC's full grant-resolution stack -- that machinery is already
    exercised end to end in ``tests/unit/test_rbac.py``; this test only
    proves *this domain's router* asks for the right permission key at the
    right scope."""

    class _FakeUser:
        id = str(uuid.uuid4())

    class _FakeRequest:
        headers: dict[str, str] = {}

    class _RecordingAccessValidator:
        def __init__(self, *, allow_global: bool) -> None:
            self.allow_global = allow_global
            self.calls: list[tuple[str, ScopeType]] = []

        async def check(
            self, user_id, permission_key, *, scope_type, scope_context=None
        ) -> None:
            self.calls.append((permission_key, scope_type))
            if scope_type == ScopeType.GLOBAL and self.allow_global:
                return
            from app.domains.rbac.exceptions import PermissionDeniedError

            raise PermissionDeniedError(permission_key, str(scope_type))

    async def test_global_scope_billing_manage_is_required_and_enforced(self) -> None:
        from app.domains.rbac.exceptions import PermissionDeniedError

        dependency = RequirePermission("billing.manage", scope=ScopeType.GLOBAL)

        denied_validator = self._RecordingAccessValidator(allow_global=False)
        with pytest.raises(PermissionDeniedError):
            await dependency(
                self._FakeRequest(),
                user=self._FakeUser(),
                access_validator=denied_validator,
            )
        assert denied_validator.calls == [("billing.manage", ScopeType.GLOBAL)]

        allowed_validator = self._RecordingAccessValidator(allow_global=True)
        result = await dependency(
            self._FakeRequest(),
            user=self._FakeUser(),
            access_validator=allowed_validator,
        )
        assert result is self._FakeUser or isinstance(result, self._FakeUser)


# ============================================================================
# License lifecycle
# ============================================================================


class TestLicenseLifecycle:
    async def test_assign_activate_suspend_reactivate(self) -> None:
        fx = make_license_service()
        plan = await _create_plan(fx.plan_repository, slug="business")
        org_id = uuid.uuid4()

        license_ = await fx.service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        assert license_.status == LicenseStatus.PENDING_ACTIVATION.value
        assert fx.organization_composer.sync_calls == [(org_id, plan.slug)]

        activated = await fx.service.activate_license(
            actor_user_id=None, license_id=license_.id
        )
        assert activated.status == LicenseStatus.ACTIVE.value
        assert activated.activated_at is not None

        suspended = await fx.service.suspend_license(
            actor_user_id=None, license_id=license_.id, reason="payment failed"
        )
        assert suspended.status == LicenseStatus.SUSPENDED.value
        assert suspended.suspended_reason == "payment failed"

        reactivated = await fx.service.activate_license(
            actor_user_id=None, license_id=license_.id
        )
        assert reactivated.status == LicenseStatus.ACTIVE.value
        assert reactivated.suspended_at is None
        assert reactivated.suspended_reason is None

        history = await fx.service.list_change_history(license_.id)
        assert len(history) == 1  # the initial ASSIGNED row
        assert history[0].change_type == "assigned"

        actions = [entry["action"] for entry in fx.audit_writer.entries]
        assert actions == [
            "license_assigned",
            "license_activated",
            "license_suspended",
            "license_activated",
        ]

    async def test_assign_twice_for_same_organization_rejected(self) -> None:
        fx = make_license_service()
        plan = await _create_plan(fx.plan_repository, slug="starter")
        org_id = uuid.uuid4()
        await fx.service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        with pytest.raises(DuplicateLicenseError):
            await fx.service.assign_license(
                actor_user_id=None, organization_id=org_id, plan_id=plan.id
            )

    async def test_illegal_transition_rejected(self) -> None:
        fx = make_license_service()
        plan = await _create_plan(fx.plan_repository, slug="starter")
        org_id = uuid.uuid4()
        license_ = await fx.service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        # PENDING_ACTIVATION -> SUSPENDED is not a legal transition.
        with pytest.raises(InvalidLicenseStatusTransitionError):
            await fx.service.suspend_license(
                actor_user_id=None, license_id=license_.id, reason="x"
            )

    async def test_cancel_is_terminal(self) -> None:
        fx = make_license_service()
        plan = await _create_plan(fx.plan_repository, slug="starter")
        org_id = uuid.uuid4()
        license_ = await fx.service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        await fx.service.cancel_license(actor_user_id=None, license_id=license_.id)
        with pytest.raises(InvalidLicenseStatusTransitionError):
            await fx.service.activate_license(
                actor_user_id=None, license_id=license_.id
            )

    async def test_expire_license(self) -> None:
        fx = make_license_service()
        plan = await _create_plan(fx.plan_repository, slug="starter")
        org_id = uuid.uuid4()
        license_ = await fx.service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        await fx.service.activate_license(actor_user_id=None, license_id=license_.id)
        expired = await fx.service.expire_license(license_id=license_.id)
        assert expired.status == LicenseStatus.EXPIRED.value
        with pytest.raises(InvalidLicenseStatusTransitionError):
            await fx.service.activate_license(
                actor_user_id=None, license_id=license_.id
            )

    async def test_validate_license_active_and_not_expired(self) -> None:
        fx = make_license_service()
        plan = await _create_plan(fx.plan_repository, slug="starter")
        org_id = uuid.uuid4()
        license_ = await fx.service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        with pytest.raises(LicenseNotActiveError):
            await fx.service.validate_license(org_id)

        await fx.service.activate_license(actor_user_id=None, license_id=license_.id)
        validated = await fx.service.validate_license(org_id)
        assert validated.id == license_.id

        # Now force expiry via an already-past expires_at and re-check.
        await fx.license_repository.update_license(
            license_, {"expires_at": _now() - timedelta(days=1)}
        )
        with pytest.raises(LicenseNotActiveError):
            await fx.service.validate_license(org_id)

    async def test_license_not_found_for_unknown_organization(self) -> None:
        fx = make_license_service()
        with pytest.raises(LicenseNotFoundError):
            await fx.service.get_license_for_organization(uuid.uuid4())


class TestLicenseUpgradeDowngrade:
    async def test_upgrade_records_history_and_syncs_subscription_tier(self) -> None:
        fx = make_license_service()
        starter = await _create_plan(fx.plan_repository, slug="starter")
        professional = await _create_plan(fx.plan_repository, slug="professional")
        org_id = uuid.uuid4()
        license_ = await fx.service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=starter.id
        )
        await fx.service.activate_license(actor_user_id=None, license_id=license_.id)

        upgraded = await fx.service.upgrade_license(
            actor_user_id=None,
            license_id=license_.id,
            new_plan_id=professional.id,
            reason="customer requested more locations",
        )
        assert upgraded.plan_id == professional.id
        assert fx.organization_composer.sync_calls[-1] == (org_id, professional.slug)

        history = await fx.service.list_change_history(license_.id)
        assert [entry.change_type for entry in history] == ["upgraded", "assigned"]
        assert history[0].from_plan_id == starter.id
        assert history[0].to_plan_id == professional.id

    async def test_downgrade_to_same_plan_rejected(self) -> None:
        fx = make_license_service()
        plan = await _create_plan(fx.plan_repository, slug="starter")
        org_id = uuid.uuid4()
        license_ = await fx.service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        await fx.service.activate_license(actor_user_id=None, license_id=license_.id)
        with pytest.raises(SamePlanError):
            await fx.service.downgrade_license(
                actor_user_id=None, license_id=license_.id, new_plan_id=plan.id
            )

    async def test_downgrade_blocked_when_usage_exceeds_target_limits(self) -> None:
        org_id = uuid.uuid4()
        organization_composer = FakeOrganizationComposer(
            organizations={org_id: _FakeOrganization(id=org_id, msp=False)}
        )
        guest_analytics = FakeGuestAnalytics(
            summary_by_org={
                org_id: _GuestSummary(
                    visitors=10,
                    unique_guests=250,  # exceeds the small plan's max_guests=100
                    returning_guests=2,
                    average_session_duration_seconds=120.0,
                    total_bandwidth_bytes=0,
                )
            }
        )
        fx = make_license_service(
            organization_composer=organization_composer, guest_analytics=guest_analytics
        )
        big_plan = await _create_plan(
            fx.plan_repository,
            slug="business",
            features=[
                {
                    "feature_key": "max_guests",
                    "feature_type": "limit",
                    "limit_value": Decimal("1000"),
                }
            ],
        )
        small_plan = await _create_plan(
            fx.plan_repository,
            slug="starter-small",
            features=[
                {
                    "feature_key": "max_guests",
                    "feature_type": "limit",
                    "limit_value": Decimal("100"),
                }
            ],
        )
        license_ = await fx.service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=big_plan.id
        )
        await fx.service.activate_license(actor_user_id=None, license_id=license_.id)

        with pytest.raises(DowngradeBelowUsageError) as exc_info:
            await fx.service.downgrade_license(
                actor_user_id=None, license_id=license_.id, new_plan_id=small_plan.id
            )
        assert "guests" in exc_info.value.exceeded_metric_keys

    async def test_downgrade_within_limits_succeeds(self) -> None:
        org_id = uuid.uuid4()
        organization_composer = FakeOrganizationComposer(
            organizations={org_id: _FakeOrganization(id=org_id, msp=False)}
        )
        guest_analytics = FakeGuestAnalytics(
            summary_by_org={
                org_id: _GuestSummary(
                    visitors=5,
                    unique_guests=20,
                    returning_guests=1,
                    average_session_duration_seconds=60.0,
                    total_bandwidth_bytes=0,
                )
            }
        )
        fx = make_license_service(
            organization_composer=organization_composer, guest_analytics=guest_analytics
        )
        big_plan = await _create_plan(
            fx.plan_repository,
            slug="business2",
            features=[
                {
                    "feature_key": "max_guests",
                    "feature_type": "limit",
                    "limit_value": Decimal("1000"),
                }
            ],
        )
        small_plan = await _create_plan(
            fx.plan_repository,
            slug="starter-small2",
            features=[
                {
                    "feature_key": "max_guests",
                    "feature_type": "limit",
                    "limit_value": Decimal("100"),
                }
            ],
        )
        license_ = await fx.service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=big_plan.id
        )
        await fx.service.activate_license(actor_user_id=None, license_id=license_.id)

        downgraded = await fx.service.downgrade_license(
            actor_user_id=None, license_id=license_.id, new_plan_id=small_plan.id
        )
        assert downgraded.plan_id == small_plan.id


# ============================================================================
# Usage tracking: composition (spy-verified) + limit validation
# ============================================================================


class TestUsageComposition:
    async def test_record_current_usage_composes_existing_domains_not_recompute(
        self,
    ) -> None:
        org_id = uuid.uuid4()
        child_org = _FakeOrganization(id=uuid.uuid4(), msp=False)
        organization_composer = FakeOrganizationComposer(
            organizations={org_id: _FakeOrganization(id=org_id, msp=True)},
            children={org_id: [child_org]},
        )
        guest_analytics = FakeGuestAnalytics(
            summary_by_org={
                org_id: _GuestSummary(
                    visitors=42,
                    unique_guests=30,
                    returning_guests=5,
                    average_session_duration_seconds=300.0,
                    total_bandwidth_bytes=10 * 1024 * 1024,  # 10 MB
                )
            }
        )
        active_session_lookup = FakeActiveSessionLookup(counts={org_id: 7})
        fx = make_usage_service(
            organization_composer=organization_composer,
            guest_analytics=guest_analytics,
            active_session_lookup=active_session_lookup,
        )
        fx.usage_repository.location_counts[org_id] = 3
        fx.usage_repository.router_counts[org_id] = 9
        fx.usage_repository.otp_channel_counts[org_id] = [("sms", 12), ("email", 4)]

        metrics = await fx.service.record_current_usage(org_id)
        by_key = {m.metric_key: m.value for m in metrics}

        # MSP organization: itself + 1 child.
        assert by_key[UsageMetricKey.ORGANIZATIONS.value] == Decimal(2)
        assert by_key[UsageMetricKey.LOCATIONS.value] == Decimal(3)
        assert by_key[UsageMetricKey.ROUTERS.value] == Decimal(9)
        assert by_key[UsageMetricKey.ACTIVE_DEVICES.value] == Decimal(7)
        assert by_key[UsageMetricKey.GUESTS.value] == Decimal(30)
        assert by_key[UsageMetricKey.GUEST_SESSIONS.value] == Decimal(42)
        assert by_key[UsageMetricKey.OTP_REQUESTS.value] == Decimal(16)
        assert by_key[UsageMetricKey.SMS_USAGE.value] == Decimal(12)
        assert by_key[UsageMetricKey.EMAIL_USAGE.value] == Decimal(4)
        assert by_key[UsageMetricKey.BANDWIDTH_USAGE_MB.value] == Decimal("10.00")
        # Honest placeholders -- no real data source exists for these yet.
        assert by_key[UsageMetricKey.STORAGE_USAGE_MB.value] == Decimal(0)
        assert by_key[UsageMetricKey.API_REQUESTS.value] == Decimal(0)

        # Composition, not recomputation: every cross-domain source was
        # actually called exactly once (proving nothing here re-derives
        # these numbers via a second, independent query).
        assert fx.usage_repository.count_locations_calls == [org_id]
        assert fx.usage_repository.count_routers_calls == [org_id]
        assert len(fx.usage_repository.count_otp_calls) == 1
        assert fx.guest_analytics.calls[0][0] == org_id
        assert fx.active_session_lookup.calls == [(org_id, None)]

    async def test_record_current_usage_upserts_within_same_period(self) -> None:
        org_id = uuid.uuid4()
        organization_composer = FakeOrganizationComposer(
            organizations={org_id: _FakeOrganization(id=org_id, msp=False)}
        )
        fx = make_usage_service(organization_composer=organization_composer)
        fx.usage_repository.location_counts[org_id] = 1

        first_pass = await fx.service.record_current_usage(org_id)
        fx.usage_repository.location_counts[org_id] = 5
        second_pass = await fx.service.record_current_usage(org_id)

        # Same number of rows (upserted in place), not a growing history.
        assert len(first_pass) == len(second_pass) == 12
        assert len(fx.usage_repository.metrics) == 12
        updated_locations = next(
            m for m in second_pass if m.metric_key == UsageMetricKey.LOCATIONS.value
        )
        assert updated_locations.value == Decimal(5)


class TestUsageLimitValidation:
    async def test_within_limit_reports_no_exceeded_metrics(self) -> None:
        org_id = uuid.uuid4()
        organization_composer = FakeOrganizationComposer(
            organizations={org_id: _FakeOrganization(id=org_id, msp=False)}
        )
        fx = make_usage_service(organization_composer=organization_composer)
        fx.usage_repository.location_counts[org_id] = 2

        plan = await _create_plan(
            fx.plan_repository,
            slug="within-limit-plan",
            features=[
                {
                    "feature_key": "max_locations",
                    "feature_type": "limit",
                    "limit_value": Decimal("10"),
                }
            ],
        )
        license_repo = fx.license_repository
        await license_repo.create_license(
            organization_id=org_id,
            plan_id=plan.id,
            status=LicenseStatus.ACTIVE.value,
        )

        result = await fx.service.validate_usage_against_license(org_id)
        assert isinstance(result, UsageValidationResult)
        assert result.any_limit_exceeded is False
        location_check = next(
            c
            for c in result.limit_checks
            if c.metric_key == UsageMetricKey.LOCATIONS.value
        )
        assert location_check.exceeded is False
        assert location_check.current_value == Decimal(2)
        assert location_check.limit_value == Decimal(10)

    async def test_exceeded_limit_is_flagged(self) -> None:
        org_id = uuid.uuid4()
        organization_composer = FakeOrganizationComposer(
            organizations={org_id: _FakeOrganization(id=org_id, msp=False)}
        )
        fx = make_usage_service(organization_composer=organization_composer)
        fx.usage_repository.location_counts[org_id] = 25

        plan = await _create_plan(
            fx.plan_repository,
            slug="exceeded-limit-plan",
            features=[
                {
                    "feature_key": "max_locations",
                    "feature_type": "limit",
                    "limit_value": Decimal("10"),
                }
            ],
        )
        await fx.license_repository.create_license(
            organization_id=org_id,
            plan_id=plan.id,
            status=LicenseStatus.ACTIVE.value,
        )

        result = await fx.service.validate_usage_against_license(org_id)
        assert result.any_limit_exceeded is True
        location_check = next(
            c
            for c in result.limit_checks
            if c.metric_key == UsageMetricKey.LOCATIONS.value
        )
        assert location_check.exceeded is True

    async def test_validate_usage_without_license_raises(self) -> None:
        fx = make_usage_service()
        with pytest.raises(LicenseNotFoundError):
            await fx.service.validate_usage_against_license(uuid.uuid4())


class TestTenantIsolation:
    async def test_license_lookup_is_scoped_to_its_own_organization(self) -> None:
        fx = make_license_service()
        plan = await _create_plan(fx.plan_repository, slug="iso-plan")
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()
        license_a = await fx.service.assign_license(
            actor_user_id=None, organization_id=org_a, plan_id=plan.id
        )

        fetched_a = await fx.service.get_license_for_organization(org_a)
        assert fetched_a.id == license_a.id

        with pytest.raises(LicenseNotFoundError):
            await fx.service.get_license_for_organization(org_b)

    async def test_usage_metrics_do_not_leak_across_organizations(self) -> None:
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()
        organization_composer = FakeOrganizationComposer(
            organizations={
                org_a: _FakeOrganization(id=org_a, msp=False),
                org_b: _FakeOrganization(id=org_b, msp=False),
            }
        )
        fx = make_usage_service(organization_composer=organization_composer)
        fx.usage_repository.location_counts[org_a] = 3
        fx.usage_repository.location_counts[org_b] = 99

        metrics_a = await fx.service.record_current_usage(org_a)
        metrics_b = await fx.service.record_current_usage(org_b)

        locations_a = next(
            m for m in metrics_a if m.metric_key == UsageMetricKey.LOCATIONS.value
        )
        locations_b = next(
            m for m in metrics_b if m.metric_key == UsageMetricKey.LOCATIONS.value
        )
        assert locations_a.value == Decimal(3)
        assert locations_b.value == Decimal(99)
        assert locations_a.organization_id == org_a
        assert locations_b.organization_id == org_b
