"""Unit tests for Phase A of the Enterprise SaaS initiative: request-time
license/feature entitlement enforcement.

Covers: ``EntitlementSnapshot`` (active/expired computation, cache
serialization round-trip), ``LicenseService.get_entitlement_snapshot``
(composes real ``License``/``PlanFeature`` rows, never fabricated),
``EntitlementCache`` (Redis-backed, against a minimal in-memory fake --
mirrors ``tests/unit/test_rbac.py``'s own ``PermissionCache`` test
pattern), ``EntitlementChecker`` (cache-or-fetch), cache invalidation on
every ``LicenseService`` mutation that can change an org's entitlements,
and the ``RequireActiveLicense``/``RequireFeature`` dependency factories'
actual gating logic (called directly, the same way
``app.domains.rbac.dependencies.RequirePermission`` itself has no direct
FastAPI-wiring test in this codebase -- the underlying logic is what's
exercised, not Starlette's DI resolution).

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from app.domains.billing.cache import EntitlementCache
from app.domains.billing.constants import (
    BillingCycle,
    LicenseStatus,
    PlanFeatureKey,
    PlanFeatureType,
    PlanType,
)
from app.domains.billing.dependencies import RequireActiveLicense, RequireFeature
from app.domains.billing.exceptions import (
    FeatureNotEntitledError,
    LicenseNotActiveError,
    LicenseNotFoundError,
)
from app.domains.billing.models import License, Plan, PlanFeature
from app.domains.billing.service import (
    EntitlementChecker,
    EntitlementSnapshot,
    LicenseService,
)

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


def _make_plan(**overrides: object) -> Plan:
    fields: dict[str, object] = {
        "name": "Business",
        "slug": f"business-{uuid.uuid4().hex[:8]}",
        "plan_type": PlanType.BUSINESS.value,
        "description": None,
        "billing_cycle": BillingCycle.MONTHLY.value,
        "base_price": Decimal("99.00"),
        "currency": "USD",
        "is_active": True,
        "is_public": True,
        "created_by_user_id": None,
        "sort_order": 0,
    }
    fields.update(overrides)
    return Plan(**_base_fields(**fields))


def _make_feature(plan_id: uuid.UUID, **overrides: object) -> PlanFeature:
    fields: dict[str, object] = {
        "plan_id": plan_id,
        "feature_key": PlanFeatureKey.AUDIT_LOGS.value,
        "feature_type": PlanFeatureType.BOOLEAN.value,
        "limit_value": None,
        "is_enabled": True,
        "tier_value": None,
    }
    fields.update(overrides)
    return PlanFeature(**_base_fields(**fields))


def _make_license(
    organization_id: uuid.UUID, plan_id: uuid.UUID, **overrides: object
) -> License:
    fields: dict[str, object] = {
        "organization_id": organization_id,
        "plan_id": plan_id,
        "status": LicenseStatus.ACTIVE.value,
        "activated_at": _now(),
        "expires_at": None,
        "suspended_at": None,
        "suspended_reason": None,
        "cancelled_at": None,
    }
    fields.update(overrides)
    return License(**_base_fields(**fields))


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeLicenseRepository:
    licenses: dict[uuid.UUID, License] = field(default_factory=dict)
    change_logs: list[dict[str, object]] = field(default_factory=list)

    async def get_by_id(self, license_id: uuid.UUID) -> License | None:
        return self.licenses.get(license_id)

    async def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> License | None:
        for lic in self.licenses.values():
            if lic.organization_id == organization_id:
                return lic
        return None

    async def create_license(self, **fields: object) -> License:
        lic = License(**_base_fields(**fields))
        self.licenses[lic.id] = lic
        return lic

    async def update_license(self, lic: License, data: dict[str, object]) -> License:
        for key, value in data.items():
            setattr(lic, key, value)
        lic.version += 1
        return lic

    async def create_change_log(self, **fields: object) -> object:
        self.change_logs.append(fields)
        return fields

    async def list_change_logs(self, license_id: uuid.UUID) -> list[object]:
        return [log for log in self.change_logs if log["license_id"] == license_id]


@dataclass
class FakePlanRepository:
    plans: dict[uuid.UUID, Plan] = field(default_factory=dict)
    features: dict[uuid.UUID, list[PlanFeature]] = field(default_factory=dict)

    async def get_by_id(self, plan_id: uuid.UUID) -> Plan | None:
        return self.plans.get(plan_id)

    async def list_plan_features(self, plan_id: uuid.UUID) -> list[PlanFeature]:
        return list(self.features.get(plan_id, []))


@dataclass
class FakeEntitlementCacheBackend:
    """A minimal in-memory stand-in for Redis, satisfying exactly the
    subset of the ``redis.asyncio.Redis`` interface ``EntitlementCache``
    calls -- mirrors this codebase's own precedent of faking Redis at the
    narrowest possible surface (see ``tests/unit/test_rbac.py``'s
    ``FakeRedis``)."""

    store: dict[str, str] = field(default_factory=dict)

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def set(self, key: str, value: str, *, ex: int | None = None) -> None:
        self.store[key] = value

    async def delete(self, key: str) -> None:
        self.store.pop(key, None)


@dataclass
class FakeEntitlementCache:
    """Spy-capable fake satisfying ``service.EntitlementCacheProtocol``
    directly (bypasses Redis serialization entirely) -- used to assert
    ``LicenseService`` invalidates the right organization on every
    mutation."""

    snapshots: dict[uuid.UUID, dict[str, object]] = field(default_factory=dict)
    invalidated: list[uuid.UUID] = field(default_factory=list)

    async def get(self, organization_id: uuid.UUID) -> dict[str, object] | None:
        return self.snapshots.get(organization_id)

    async def set(self, organization_id: uuid.UUID, payload: dict[str, object]) -> None:
        self.snapshots[organization_id] = payload

    async def invalidate(self, organization_id: uuid.UUID) -> None:
        self.invalidated.append(organization_id)
        self.snapshots.pop(organization_id, None)


@dataclass
class FakeSnapshotSource:
    snapshot: EntitlementSnapshot
    calls: int = 0

    async def get_entitlement_snapshot(
        self, organization_id: uuid.UUID
    ) -> EntitlementSnapshot:
        self.calls += 1
        return self.snapshot


def make_license_service(
    *, entitlement_cache: FakeEntitlementCache | None = None
) -> tuple[LicenseService, FakeLicenseRepository, FakePlanRepository]:
    license_repo = FakeLicenseRepository()
    plan_repo = FakePlanRepository()
    service = LicenseService(
        license_repo, plan_repo, entitlement_cache=entitlement_cache
    )
    return service, license_repo, plan_repo


# ============================================================================
# EntitlementSnapshot
# ============================================================================


class TestEntitlementSnapshot:
    def test_is_active_true_for_active_unexpired(self) -> None:
        snapshot = EntitlementSnapshot(
            organization_id=uuid.uuid4(),
            plan_id=uuid.uuid4(),
            license_status=LicenseStatus.ACTIVE.value,
            expires_at=None,
            enabled_features=frozenset(),
            limits={},
            tiers={},
        )
        assert snapshot.is_active is True

    def test_is_active_false_for_suspended(self) -> None:
        snapshot = EntitlementSnapshot(
            organization_id=uuid.uuid4(),
            plan_id=uuid.uuid4(),
            license_status=LicenseStatus.SUSPENDED.value,
            expires_at=None,
            enabled_features=frozenset(),
            limits={},
            tiers={},
        )
        assert snapshot.is_active is False

    def test_is_active_false_when_expires_at_in_past(self) -> None:
        snapshot = EntitlementSnapshot(
            organization_id=uuid.uuid4(),
            plan_id=uuid.uuid4(),
            license_status=LicenseStatus.ACTIVE.value,
            expires_at=_now() - timedelta(days=1),
            enabled_features=frozenset(),
            limits={},
            tiers={},
        )
        assert snapshot.is_active is False

    def test_has_feature(self) -> None:
        snapshot = EntitlementSnapshot(
            organization_id=uuid.uuid4(),
            plan_id=uuid.uuid4(),
            license_status=LicenseStatus.ACTIVE.value,
            expires_at=None,
            enabled_features=frozenset({PlanFeatureKey.AUDIT_LOGS.value}),
            limits={},
            tiers={},
        )
        assert snapshot.has_feature(PlanFeatureKey.AUDIT_LOGS) is True
        assert snapshot.has_feature(PlanFeatureKey.WHITE_LABEL) is False

    def test_cache_payload_round_trip(self) -> None:
        org_id = uuid.uuid4()
        plan_id = uuid.uuid4()
        expires_at = _now() + timedelta(days=30)
        snapshot = EntitlementSnapshot(
            organization_id=org_id,
            plan_id=plan_id,
            license_status=LicenseStatus.ACTIVE.value,
            expires_at=expires_at,
            enabled_features=frozenset({PlanFeatureKey.AUDIT_LOGS.value}),
            limits={PlanFeatureKey.MAX_GUESTS.value: Decimal("500")},
            tiers={PlanFeatureKey.SUPPORT_LEVEL.value: "priority"},
        )
        restored = EntitlementSnapshot.from_cache_payload(snapshot.to_cache_payload())
        assert restored.organization_id == org_id
        assert restored.plan_id == plan_id
        assert restored.license_status == LicenseStatus.ACTIVE.value
        assert restored.expires_at == expires_at
        assert restored.enabled_features == frozenset({PlanFeatureKey.AUDIT_LOGS.value})
        assert restored.limits == {PlanFeatureKey.MAX_GUESTS.value: Decimal("500")}
        assert restored.tiers == {PlanFeatureKey.SUPPORT_LEVEL.value: "priority"}


# ============================================================================
# EntitlementCache (against a fake Redis backend)
# ============================================================================


class TestEntitlementCache:
    async def test_get_returns_none_on_miss(self) -> None:
        cache = EntitlementCache(FakeEntitlementCacheBackend(), ttl_seconds=60)
        assert await cache.get(uuid.uuid4()) is None

    async def test_set_then_get_round_trips(self) -> None:
        cache = EntitlementCache(FakeEntitlementCacheBackend(), ttl_seconds=60)
        org_id = uuid.uuid4()
        await cache.set(org_id, {"license_status": "active"})
        assert await cache.get(org_id) == {"license_status": "active"}

    async def test_invalidate_clears_entry(self) -> None:
        cache = EntitlementCache(FakeEntitlementCacheBackend(), ttl_seconds=60)
        org_id = uuid.uuid4()
        await cache.set(org_id, {"license_status": "active"})
        await cache.invalidate(org_id)
        assert await cache.get(org_id) is None

    async def test_corrupt_payload_treated_as_miss(self) -> None:
        backend = FakeEntitlementCacheBackend()
        cache = EntitlementCache(backend, ttl_seconds=60)
        org_id = uuid.uuid4()
        backend.store[cache._key(org_id)] = "not-json{"
        assert await cache.get(org_id) is None


# ============================================================================
# LicenseService.get_entitlement_snapshot
# ============================================================================


class TestGetEntitlementSnapshot:
    async def test_composes_boolean_limit_and_tier_features(self) -> None:
        service, license_repo, plan_repo = make_license_service()
        org_id = uuid.uuid4()
        plan = _make_plan()
        plan_repo.plans[plan.id] = plan
        plan_repo.features[plan.id] = [
            _make_feature(
                plan.id,
                feature_key=PlanFeatureKey.AUDIT_LOGS.value,
                feature_type=PlanFeatureType.BOOLEAN.value,
                is_enabled=True,
            ),
            _make_feature(
                plan.id,
                feature_key=PlanFeatureKey.WHITE_LABEL.value,
                feature_type=PlanFeatureType.BOOLEAN.value,
                is_enabled=False,
            ),
            _make_feature(
                plan.id,
                feature_key=PlanFeatureKey.MAX_GUESTS.value,
                feature_type=PlanFeatureType.LIMIT.value,
                is_enabled=None,
                limit_value=Decimal("500"),
            ),
            _make_feature(
                plan.id,
                feature_key=PlanFeatureKey.SUPPORT_LEVEL.value,
                feature_type=PlanFeatureType.TIER.value,
                is_enabled=None,
                tier_value="priority",
            ),
        ]
        lic = _make_license(org_id, plan.id)
        license_repo.licenses[lic.id] = lic

        snapshot = await service.get_entitlement_snapshot(org_id)

        assert snapshot.enabled_features == frozenset({PlanFeatureKey.AUDIT_LOGS.value})
        assert snapshot.limits == {PlanFeatureKey.MAX_GUESTS.value: Decimal("500")}
        assert snapshot.tiers == {PlanFeatureKey.SUPPORT_LEVEL.value: "priority"}
        assert snapshot.is_active is True

    async def test_raises_when_no_license_exists(self) -> None:
        service, _, _ = make_license_service()
        with pytest.raises(LicenseNotFoundError):
            await service.get_entitlement_snapshot(uuid.uuid4())


# ============================================================================
# EntitlementChecker (cache-or-fetch)
# ============================================================================


class TestEntitlementChecker:
    async def test_cache_miss_fetches_and_populates(self) -> None:
        org_id = uuid.uuid4()
        snapshot = EntitlementSnapshot(
            organization_id=org_id,
            plan_id=uuid.uuid4(),
            license_status=LicenseStatus.ACTIVE.value,
            expires_at=None,
            enabled_features=frozenset(),
            limits={},
            tiers={},
        )
        source = FakeSnapshotSource(snapshot)
        cache = FakeEntitlementCache()
        checker = EntitlementChecker(source, cache)

        result = await checker.get_snapshot(org_id)

        assert result.organization_id == org_id
        assert source.calls == 1
        assert org_id in cache.snapshots

    async def test_cache_hit_skips_source(self) -> None:
        org_id = uuid.uuid4()
        snapshot = EntitlementSnapshot(
            organization_id=org_id,
            plan_id=uuid.uuid4(),
            license_status=LicenseStatus.ACTIVE.value,
            expires_at=None,
            enabled_features=frozenset(),
            limits={},
            tiers={},
        )
        source = FakeSnapshotSource(snapshot)
        cache = FakeEntitlementCache()
        cache.snapshots[org_id] = snapshot.to_cache_payload()
        checker = EntitlementChecker(source, cache)

        result = await checker.get_snapshot(org_id)

        assert result.organization_id == org_id
        assert source.calls == 0


# ============================================================================
# Cache invalidation on every LicenseService mutation
# ============================================================================


class TestLicenseServiceInvalidatesEntitlementCache:
    async def test_assign_license_invalidates(self) -> None:
        cache = FakeEntitlementCache()
        service, _, plan_repo = make_license_service(entitlement_cache=cache)
        plan = _make_plan()
        plan_repo.plans[plan.id] = plan
        org_id = uuid.uuid4()

        await service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )

        assert org_id in cache.invalidated

    async def test_activate_suspend_cancel_invalidate(self) -> None:
        cache = FakeEntitlementCache()
        service, license_repo, plan_repo = make_license_service(
            entitlement_cache=cache
        )
        plan = _make_plan()
        plan_repo.plans[plan.id] = plan
        org_id = uuid.uuid4()
        lic = _make_license(
            org_id, plan.id, status=LicenseStatus.PENDING_ACTIVATION.value
        )
        license_repo.licenses[lic.id] = lic

        await service.activate_license(actor_user_id=None, license_id=lic.id)
        assert cache.invalidated.count(org_id) == 1

        await service.suspend_license(
            actor_user_id=None, license_id=lic.id, reason="payment failed"
        )
        assert cache.invalidated.count(org_id) == 2

        await service.cancel_license(actor_user_id=None, license_id=lic.id)
        assert cache.invalidated.count(org_id) == 3

    async def test_expire_license_invalidates(self) -> None:
        cache = FakeEntitlementCache()
        service, license_repo, plan_repo = make_license_service(
            entitlement_cache=cache
        )
        plan = _make_plan()
        plan_repo.plans[plan.id] = plan
        org_id = uuid.uuid4()
        lic = _make_license(org_id, plan.id)
        license_repo.licenses[lic.id] = lic

        await service.expire_license(license_id=lic.id)

        assert org_id in cache.invalidated

    async def test_upgrade_license_invalidates(self) -> None:
        cache = FakeEntitlementCache()
        service, license_repo, plan_repo = make_license_service(
            entitlement_cache=cache
        )
        old_plan = _make_plan()
        new_plan = _make_plan()
        plan_repo.plans[old_plan.id] = old_plan
        plan_repo.plans[new_plan.id] = new_plan
        org_id = uuid.uuid4()
        lic = _make_license(org_id, old_plan.id)
        license_repo.licenses[lic.id] = lic

        await service.upgrade_license(
            actor_user_id=None, license_id=lic.id, new_plan_id=new_plan.id
        )

        assert org_id in cache.invalidated


# ============================================================================
# RequireActiveLicense / RequireFeature dependency logic
# ============================================================================


class TestRequireActiveLicense:
    async def test_none_organization_passes_through(self) -> None:
        dependency = RequireActiveLicense()
        cache = FakeEntitlementCache()
        checker = EntitlementChecker(
            FakeSnapshotSource(
                EntitlementSnapshot(
                    organization_id=uuid.uuid4(),
                    plan_id=uuid.uuid4(),
                    license_status=LicenseStatus.ACTIVE.value,
                    expires_at=None,
                    enabled_features=frozenset(),
                    limits={},
                    tiers={},
                )
            ),
            cache,
        )
        result = await dependency(organization_id=None, checker=checker)
        assert result is None

    async def test_active_license_passes(self) -> None:
        org_id = uuid.uuid4()
        dependency = RequireActiveLicense()
        source = FakeSnapshotSource(
            EntitlementSnapshot(
                organization_id=org_id,
                plan_id=uuid.uuid4(),
                license_status=LicenseStatus.ACTIVE.value,
                expires_at=None,
                enabled_features=frozenset(),
                limits={},
                tiers={},
            )
        )
        checker = EntitlementChecker(source, FakeEntitlementCache())
        result = await dependency(organization_id=org_id, checker=checker)
        assert result == org_id

    async def test_suspended_license_raises(self) -> None:
        org_id = uuid.uuid4()
        dependency = RequireActiveLicense()
        source = FakeSnapshotSource(
            EntitlementSnapshot(
                organization_id=org_id,
                plan_id=uuid.uuid4(),
                license_status=LicenseStatus.SUSPENDED.value,
                expires_at=None,
                enabled_features=frozenset(),
                limits={},
                tiers={},
            )
        )
        checker = EntitlementChecker(source, FakeEntitlementCache())
        with pytest.raises(LicenseNotActiveError):
            await dependency(organization_id=org_id, checker=checker)

    async def test_expired_license_raises(self) -> None:
        org_id = uuid.uuid4()
        dependency = RequireActiveLicense()
        source = FakeSnapshotSource(
            EntitlementSnapshot(
                organization_id=org_id,
                plan_id=uuid.uuid4(),
                license_status=LicenseStatus.ACTIVE.value,
                expires_at=_now() - timedelta(days=1),
                enabled_features=frozenset(),
                limits={},
                tiers={},
            )
        )
        checker = EntitlementChecker(source, FakeEntitlementCache())
        with pytest.raises(LicenseNotActiveError):
            await dependency(organization_id=org_id, checker=checker)


class TestRequireFeature:
    async def test_none_organization_passes_through(self) -> None:
        dependency = RequireFeature(PlanFeatureKey.AUDIT_LOGS)
        checker = EntitlementChecker(
            FakeSnapshotSource(
                EntitlementSnapshot(
                    organization_id=uuid.uuid4(),
                    plan_id=uuid.uuid4(),
                    license_status=LicenseStatus.ACTIVE.value,
                    expires_at=None,
                    enabled_features=frozenset(),
                    limits={},
                    tiers={},
                )
            ),
            FakeEntitlementCache(),
        )
        result = await dependency(organization_id=None, checker=checker)
        assert result is None

    async def test_enabled_feature_passes(self) -> None:
        org_id = uuid.uuid4()
        dependency = RequireFeature(PlanFeatureKey.AUDIT_LOGS)
        source = FakeSnapshotSource(
            EntitlementSnapshot(
                organization_id=org_id,
                plan_id=uuid.uuid4(),
                license_status=LicenseStatus.ACTIVE.value,
                expires_at=None,
                enabled_features=frozenset({PlanFeatureKey.AUDIT_LOGS.value}),
                limits={},
                tiers={},
            )
        )
        checker = EntitlementChecker(source, FakeEntitlementCache())
        result = await dependency(organization_id=org_id, checker=checker)
        assert result == org_id

    async def test_disabled_feature_raises(self) -> None:
        org_id = uuid.uuid4()
        dependency = RequireFeature(PlanFeatureKey.WHITE_LABEL)
        source = FakeSnapshotSource(
            EntitlementSnapshot(
                organization_id=org_id,
                plan_id=uuid.uuid4(),
                license_status=LicenseStatus.ACTIVE.value,
                expires_at=None,
                enabled_features=frozenset({PlanFeatureKey.AUDIT_LOGS.value}),
                limits={},
                tiers={},
            )
        )
        checker = EntitlementChecker(source, FakeEntitlementCache())
        with pytest.raises(FeatureNotEntitledError):
            await dependency(organization_id=org_id, checker=checker)

    async def test_inactive_license_raises_before_feature_check(self) -> None:
        """``RequireFeature``'s ``organization_id`` param is wired as
        ``Depends(RequireActiveLicense())`` (see ``dependencies.py``), so at
        request time FastAPI evaluates that sub-dependency first and never
        reaches ``RequireFeature``'s own body at all on an inactive license.
        Simulate that resolution order directly (a straight call bypasses
        Starlette's DI, so it can't be exercised through ``RequireFeature``
        itself here) by asserting the exact sub-dependency it declares
        raises for this snapshot."""
        org_id = uuid.uuid4()
        active_license_dependency = RequireActiveLicense()
        source = FakeSnapshotSource(
            EntitlementSnapshot(
                organization_id=org_id,
                plan_id=uuid.uuid4(),
                license_status=LicenseStatus.SUSPENDED.value,
                expires_at=None,
                enabled_features=frozenset({PlanFeatureKey.AUDIT_LOGS.value}),
                limits={},
                tiers={},
            )
        )
        checker = EntitlementChecker(source, FakeEntitlementCache())
        with pytest.raises(LicenseNotActiveError):
            await active_license_dependency(organization_id=org_id, checker=checker)
