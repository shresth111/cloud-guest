"""Unit tests for the System Settings domain: the platform-wide (GLOBAL-
scope) new-customer defaults store.

Covers the read/validate/persist/audit service pattern end-to-end against a
small, hand-rolled in-memory fake repository (mirroring
``test_channel_partner.py``'s own fake-repository shape) plus a fake plan
reader and audit writer -- there is no live Postgres in this environment.
Also asserts the RBAC gating: both routes require ``system_settings.read``/
``.update`` explicitly at ``ScopeType.GLOBAL``.

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly.
"""

from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest

from app.domains.rbac.enums import (
    AuditAction,
    PermissionModule,
    ScopeType,
)
from app.domains.rbac.seed import MODULE_ACTIONS, MODULE_NARROWEST_SCOPE
from app.domains.system_settings.constants import SystemSettingKey
from app.domains.system_settings.exceptions import (
    DefaultPlanNotFoundError,
    UnknownFeatureOverrideError,
)
from app.domains.system_settings.router import (
    get_platform_settings,
    router,
    update_platform_settings,
)
from app.domains.system_settings.schemas import (
    FeatureOverride,
    PlatformSettingsUpdateRequest,
)
from app.domains.system_settings.service import SystemSettingsService

# ============================================================================
# Test doubles
# ============================================================================


@dataclass
class FakeSystemSettingsRepository:
    values: dict[str, Any] = field(default_factory=dict)
    upsert_calls: list[tuple[str, Any, Any]] = field(default_factory=list)

    async def get_all_values(self) -> dict[str, Any]:
        return dict(self.values)

    async def get_value(self, key: str) -> Any | None:
        return self.values.get(key)

    async def upsert(
        self, key: str, value: Any | None, *, actor_user_id: object | None = None
    ) -> object:
        self.values[key] = value
        self.upsert_calls.append((key, value, actor_user_id))
        return object()


@dataclass
class _FakePlan:
    id: uuid.UUID


@dataclass
class FakePlanReader:
    """Resolves only the plan ids explicitly registered as existing."""

    existing: set[uuid.UUID] = field(default_factory=set)

    async def get_by_id(
        self, plan_id: uuid.UUID, *, include_deleted: bool = False
    ) -> object | None:
        return _FakePlan(id=plan_id) if plan_id in self.existing else None


@dataclass
class FakeAuditWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> object:
        self.entries.append(fields)
        return fields


def _make_service(
    *,
    values: dict[str, Any] | None = None,
    existing_plans: set[uuid.UUID] | None = None,
) -> tuple[SystemSettingsService, FakeSystemSettingsRepository, FakeAuditWriter]:
    repository = FakeSystemSettingsRepository(values=dict(values or {}))
    audit = FakeAuditWriter()
    service = SystemSettingsService(
        repository,
        plan_reader=FakePlanReader(existing=set(existing_plans or set())),
        audit_writer=audit,
    )
    return service, repository, audit


_PLAN_KEY = SystemSettingKey.NEW_CUSTOMER_DEFAULT_PLAN_ID.value
_OVERRIDES_KEY = SystemSettingKey.NEW_CUSTOMER_DEFAULT_FEATURE_OVERRIDES.value


# ============================================================================
# Read
# ============================================================================


class TestGetPlatformSettings:
    async def test_empty_store_reads_as_defaults_not_an_error(self) -> None:
        service, _, _ = _make_service()
        result = await service.get_platform_settings()
        assert result.new_customer_default_plan_id is None
        assert result.new_customer_default_feature_overrides == []

    async def test_reads_back_stored_plan_and_overrides(self) -> None:
        plan_id = str(uuid.uuid4())
        service, _, _ = _make_service(
            values={
                _PLAN_KEY: plan_id,
                _OVERRIDES_KEY: [{"feature_key": "analytics", "enabled": True}],
            }
        )
        result = await service.get_platform_settings()
        assert result.new_customer_default_plan_id == plan_id
        assert len(result.new_customer_default_feature_overrides) == 1
        assert result.new_customer_default_feature_overrides[0].feature_key == (
            "analytics"
        )
        assert result.new_customer_default_feature_overrides[0].enabled is True

    async def test_malformed_override_rows_are_skipped_not_fatal(self) -> None:
        service, _, _ = _make_service(
            values={_OVERRIDES_KEY: [{"nonsense": 1}, "garbage"]}
        )
        result = await service.get_platform_settings()
        assert result.new_customer_default_feature_overrides == []


# ============================================================================
# Write / validation
# ============================================================================


class TestUpdatePlatformSettings:
    async def test_sets_default_plan_when_plan_exists(self) -> None:
        plan_id = uuid.uuid4()
        service, repo, _ = _make_service(existing_plans={plan_id})
        result = await service.update_platform_settings(
            actor_user_id=uuid.uuid4(),
            body=PlatformSettingsUpdateRequest(
                new_customer_default_plan_id=str(plan_id)
            ),
        )
        assert result.new_customer_default_plan_id == str(plan_id)
        assert repo.values[_PLAN_KEY] == str(plan_id)

    async def test_unknown_plan_is_rejected_and_nothing_persisted(self) -> None:
        service, repo, _ = _make_service()
        with pytest.raises(DefaultPlanNotFoundError):
            await service.update_platform_settings(
                actor_user_id=uuid.uuid4(),
                body=PlatformSettingsUpdateRequest(
                    new_customer_default_plan_id=str(uuid.uuid4())
                ),
            )
        assert repo.upsert_calls == []

    async def test_malformed_plan_id_is_rejected(self) -> None:
        service, _, _ = _make_service()
        with pytest.raises(DefaultPlanNotFoundError):
            await service.update_platform_settings(
                actor_user_id=uuid.uuid4(),
                body=PlatformSettingsUpdateRequest(
                    new_customer_default_plan_id="not-a-uuid"
                ),
            )

    async def test_empty_string_clears_the_default_plan(self) -> None:
        plan_id = str(uuid.uuid4())
        service, repo, _ = _make_service(values={_PLAN_KEY: plan_id})
        result = await service.update_platform_settings(
            actor_user_id=uuid.uuid4(),
            body=PlatformSettingsUpdateRequest(new_customer_default_plan_id=""),
        )
        assert result.new_customer_default_plan_id is None
        assert repo.values[_PLAN_KEY] is None

    async def test_unset_field_is_a_noop_not_a_clear(self) -> None:
        plan_id = str(uuid.uuid4())
        service, repo, audit = _make_service(values={_PLAN_KEY: plan_id})
        result = await service.update_platform_settings(
            actor_user_id=uuid.uuid4(),
            body=PlatformSettingsUpdateRequest(),  # nothing set
        )
        assert result.new_customer_default_plan_id == plan_id
        assert repo.upsert_calls == []
        assert audit.entries == []  # no change -> no audit row

    async def test_valid_feature_overrides_stored_normalized(self) -> None:
        service, repo, _ = _make_service()
        result = await service.update_platform_settings(
            actor_user_id=uuid.uuid4(),
            body=PlatformSettingsUpdateRequest(
                new_customer_default_feature_overrides=[
                    FeatureOverride(feature_key="analytics", enabled=True),
                    FeatureOverride(feature_key="monitoring", enabled=False),
                ]
            ),
        )
        assert repo.values[_OVERRIDES_KEY] == [
            {"feature_key": "analytics", "enabled": True},
            {"feature_key": "monitoring", "enabled": False},
        ]
        keys = {o.feature_key for o in result.new_customer_default_feature_overrides}
        assert keys == {"analytics", "monitoring"}

    async def test_unknown_feature_key_is_rejected(self) -> None:
        service, repo, _ = _make_service()
        with pytest.raises(UnknownFeatureOverrideError):
            await service.update_platform_settings(
                actor_user_id=uuid.uuid4(),
                body=PlatformSettingsUpdateRequest(
                    new_customer_default_feature_overrides=[
                        FeatureOverride(feature_key="not_a_real_feature", enabled=True)
                    ]
                ),
            )
        assert repo.upsert_calls == []

    async def test_duplicate_override_keys_last_write_wins(self) -> None:
        service, repo, _ = _make_service()
        await service.update_platform_settings(
            actor_user_id=uuid.uuid4(),
            body=PlatformSettingsUpdateRequest(
                new_customer_default_feature_overrides=[
                    FeatureOverride(feature_key="analytics", enabled=True),
                    FeatureOverride(feature_key="analytics", enabled=False),
                ]
            ),
        )
        assert repo.values[_OVERRIDES_KEY] == [
            {"feature_key": "analytics", "enabled": False}
        ]


# ============================================================================
# Audit
# ============================================================================


class TestAudit:
    async def test_real_change_writes_one_audit_entry_with_old_and_new(self) -> None:
        plan_id = uuid.uuid4()
        actor = uuid.uuid4()
        service, _, audit = _make_service(existing_plans={plan_id})
        await service.update_platform_settings(
            actor_user_id=actor,
            body=PlatformSettingsUpdateRequest(
                new_customer_default_plan_id=str(plan_id)
            ),
        )
        assert len(audit.entries) == 1
        entry = audit.entries[0]
        assert entry["action"] == AuditAction.SYSTEM_SETTINGS_UPDATED.value
        assert entry["actor_user_id"] == actor
        assert entry["entity_type"] == "system_setting"
        assert entry["organization_id"] is None
        changes = entry["event_metadata"]["changes"]  # type: ignore[index]
        assert _PLAN_KEY in changes
        assert changes[_PLAN_KEY] == {"old": None, "new": str(plan_id)}

    async def test_noop_update_writes_no_audit_entry(self) -> None:
        plan_id = uuid.uuid4()
        service, _, audit = _make_service(
            values={_PLAN_KEY: str(plan_id)}, existing_plans={plan_id}
        )
        await service.update_platform_settings(
            actor_user_id=uuid.uuid4(),
            body=PlatformSettingsUpdateRequest(
                new_customer_default_plan_id=str(plan_id)  # same value
            ),
        )
        assert audit.entries == []

    async def test_service_without_audit_writer_still_updates(self) -> None:
        plan_id = uuid.uuid4()
        repo = FakeSystemSettingsRepository()
        service = SystemSettingsService(
            repo,
            plan_reader=FakePlanReader(existing={plan_id}),
            audit_writer=None,
        )
        result = await service.update_platform_settings(
            actor_user_id=uuid.uuid4(),
            body=PlatformSettingsUpdateRequest(
                new_customer_default_plan_id=str(plan_id)
            ),
        )
        assert result.new_customer_default_plan_id == str(plan_id)


# ============================================================================
# RBAC gating
# ============================================================================


def _permission_dep_meta(route: object) -> list[tuple[str, ScopeType | None]]:
    """The (permission_key, scope) pairs a route's ``RequirePermission``
    dependencies enforce -- ``RequirePermission`` is a closure factory, so
    both live in ``_dependency``'s nonlocals (mirrors
    ``test_channel_partner.py``'s ``_permission_keys`` helper)."""
    out: list[tuple[str, ScopeType | None]] = []
    for dependency in route.dependencies:  # type: ignore[attr-defined]
        nonlocals = inspect.getclosurevars(dependency.dependency).nonlocals
        out.append((nonlocals["permission_key"], nonlocals.get("scope")))
    return out


def _route_for(endpoint: object) -> object:
    for route in router.routes:
        if getattr(route, "endpoint", None) is endpoint:
            return route
    raise AssertionError("route not found")


class TestRbacGating:
    def test_system_settings_is_global_scope(self) -> None:
        assert (
            MODULE_NARROWEST_SCOPE[PermissionModule.SYSTEM_SETTINGS] == ScopeType.GLOBAL
        )

    def test_read_route_requires_system_settings_read_at_global(self) -> None:
        meta = _permission_dep_meta(_route_for(get_platform_settings))
        assert ("system_settings.read", ScopeType.GLOBAL) in meta

    def test_update_route_requires_system_settings_update_at_global(self) -> None:
        meta = _permission_dep_meta(_route_for(update_platform_settings))
        assert ("system_settings.update", ScopeType.GLOBAL) in meta

    def test_actions_seeded_for_the_module(self) -> None:
        from app.domains.rbac.enums import PermissionAction

        actions = MODULE_ACTIONS[PermissionModule.SYSTEM_SETTINGS]
        assert PermissionAction.READ in actions
        assert PermissionAction.UPDATE in actions
