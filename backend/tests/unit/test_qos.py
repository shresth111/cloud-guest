"""Unit tests for the QoS & VOIP Priority domain: rule CRUD (tenant
isolation), traffic-match validation (exactly one of port-range/DSCP
required, port-range ordering/bounds, DSCP 0-63 bounds), priority bounds
(reusing ``app.domains.queue_management``'s own 1-8 range), the
unpaginated ``list_rules_for_router`` read path Network Configuration
Management composes, and a structural RBAC check that every route
carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_hotspot.py``); ``asyncio_mode = "auto"`` runs async
tests directly. ``QosService`` is exercised against small, hand-rolled
in-memory fakes for its own repository and the composed
``RouterLookupProtocol`` -- mirrors ``test_hotspot.py``'s own identical
"fake the narrow Protocol boundary" precedent. This domain has no device
I/O to test (see ``service.py``'s own module docstring -- a pure
rules/inventory domain, no ``device_adapters.py`` in this pass).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.qos.constants import MAX_PRIORITY, MIN_PRIORITY
from app.domains.qos.exceptions import (
    AmbiguousTrafficMatchError,
    CrossOrganizationQosTrafficRuleAccessError,
    InvalidDscpValueError,
    InvalidPortRangeError,
    InvalidPriorityError,
    NoTrafficMatchError,
    QosTrafficRuleNotFoundError,
)
from app.domains.qos.models import QosTrafficRule
from app.domains.qos.router import router as qos_router
from app.domains.qos.service import QosService
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router

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


def _make_router(
    *, organization_id: uuid.UUID | None = None, location_id: uuid.UUID | None = None
) -> Router:
    return Router(
        **_base_fields(
            organization_id=organization_id or uuid.uuid4(),
            location_id=location_id or uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="RB4011",
            vendor="mikrotik",
            routeros_version=None,
            management_ip_address="10.0.0.1",
            public_ip_address=None,
            status="online",
            last_seen_at=None,
            last_health_check_at=None,
            health_status=None,
            api_username="admin",
            api_credentials_encrypted="encrypted-placeholder",
            settings={},
        )
    )


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeQosRepository:
    rules: dict[uuid.UUID, QosTrafficRule] = field(default_factory=dict)

    async def create_rule(self, **fields: object) -> QosTrafficRule:
        rule = QosTrafficRule(**_base_fields(**fields))
        self.rules[rule.id] = rule
        return rule

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> QosTrafficRule | None:
        rule = self.rules.get(rule_id)
        if rule is None or (rule.is_deleted and not include_deleted):
            return None
        return rule

    async def update_rule(
        self, rule: QosTrafficRule, data: dict[str, object]
    ) -> QosTrafficRule:
        for key, value in data.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        rule.version += 1
        return rule

    async def soft_delete_rule(self, rule: QosTrafficRule) -> QosTrafficRule:
        rule.is_deleted = True
        rule.deleted_at = _now()
        return rule

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        **_kw: object,
    ):
        values = [v for v in self.rules.values() if not v.is_deleted]
        if requesting_organization_id is not None:
            values = [
                v for v in values if v.organization_id == requesting_organization_id
            ]
        if router_id is not None:
            values = [v for v in values if v.router_id == router_id]
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_rules_for_router(self, router_id: uuid.UUID) -> list[QosTrafficRule]:
        return [
            v
            for v in self.rules.values()
            if v.router_id == router_id and not v.is_deleted
        ]


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)

    def add(self, router: Router) -> Router:
        self.routers[router.id] = router
        return router

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router:
        router = self.routers.get(router_id)
        if router is None:
            raise RouterNotFoundError(router_id)
        if (
            requesting_organization_id is not None
            and router.organization_id != requesting_organization_id
        ):
            raise RouterNotFoundError(router_id)
        return router


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: QosService
    repository: FakeQosRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeQosRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    service = QosService(repository, router_lookup, audit_writer=audit_writer)
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        audit_writer=audit_writer,
    )


async def _create_rule(
    h: Harness,
    router: Router,
    *,
    name: str = "SIP Signaling",
    protocol: str | None = "udp",
    port_range_start: int | None = 5060,
    port_range_end: int | None = 5061,
    dscp_value: int | None = None,
    priority: int = 1,
) -> QosTrafficRule:
    return await h.service.create_rule(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        name=name,
        protocol=protocol,
        port_range_start=port_range_start,
        port_range_end=port_range_end,
        dscp_value=dscp_value,
        priority=priority,
    )


# ============================================================================
# Rule CRUD
# ============================================================================


class TestQosTrafficRuleCrud:
    async def test_create_rule_succeeds(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)

        rule = await _create_rule(h, router)

        assert rule.router_id == router.id
        assert rule.organization_id == router.organization_id
        assert rule.location_id == router.location_id
        assert rule.name == "SIP Signaling"
        assert rule.protocol == "udp"
        assert rule.port_range_start == 5060
        assert rule.port_range_end == 5061
        assert rule.dscp_value is None
        assert rule.priority == 1
        assert rule.is_enabled is True
        assert len(h.audit_writer.entries) == 1

    async def test_create_rule_for_unknown_router_raises(self) -> None:
        h = make_harness()
        with pytest.raises(RouterNotFoundError):
            await _create_rule(h, _make_router())

    async def test_get_rule_returns_created_rule(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        fetched = await h.service.get_rule(
            rule.id, requesting_organization_id=router.organization_id
        )
        assert fetched.id == rule.id

    async def test_get_rule_not_found_raises(self) -> None:
        h = make_harness()
        with pytest.raises(QosTrafficRuleNotFoundError):
            await h.service.get_rule(uuid.uuid4())

    async def test_get_rule_cross_organization_raises(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        with pytest.raises(CrossOrganizationQosTrafficRuleAccessError):
            await h.service.get_rule(rule.id, requesting_organization_id=uuid.uuid4())

    async def test_list_rules_filters_by_router(self) -> None:
        h = make_harness()
        router_a = _make_router()
        router_b = _make_router()
        h.router_lookup.add(router_a)
        h.router_lookup.add(router_b)
        rule_a = await _create_rule(h, router_a)
        await _create_rule(h, router_b)

        rules, meta = await h.service.list_rules(
            requesting_organization_id=None, router_id=router_a.id
        )
        assert meta.total_items == 1
        assert rules[0].id == rule_a.id

    async def test_update_rule_changes_fields(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        updated = await h.service.update_rule(
            rule.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            priority=3,
            is_enabled=False,
        )
        assert updated.priority == 3
        assert updated.is_enabled is False
        assert len(h.audit_writer.entries) == 2

    async def test_delete_rule_soft_deletes(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        deleted = await h.service.delete_rule(
            rule.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True
        with pytest.raises(QosTrafficRuleNotFoundError):
            await h.service.get_rule(rule.id)


# ============================================================================
# Traffic-match validation
# ============================================================================


class TestTrafficMatchValidation:
    async def test_accepts_a_port_range_match(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(
            h, router, port_range_start=10000, port_range_end=20000, dscp_value=None
        )
        assert rule.port_range_start == 10000
        assert rule.dscp_value is None

    async def test_accepts_a_dscp_match(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(
            h,
            router,
            protocol=None,
            port_range_start=None,
            port_range_end=None,
            dscp_value=46,
        )
        assert rule.dscp_value == 46
        assert rule.port_range_start is None

    async def test_rejects_both_port_range_and_dscp(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(AmbiguousTrafficMatchError):
            await _create_rule(h, router, dscp_value=46)

    async def test_rejects_neither_port_range_nor_dscp(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(NoTrafficMatchError):
            await _create_rule(
                h,
                router,
                protocol=None,
                port_range_start=None,
                port_range_end=None,
                dscp_value=None,
            )

    async def test_rejects_a_reversed_port_range(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(InvalidPortRangeError):
            await _create_rule(h, router, port_range_start=20000, port_range_end=10000)

    async def test_rejects_dscp_out_of_range(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(InvalidDscpValueError):
            await _create_rule(
                h,
                router,
                protocol=None,
                port_range_start=None,
                port_range_end=None,
                dscp_value=64,
            )

    async def test_update_revalidates_traffic_match(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        with pytest.raises(AmbiguousTrafficMatchError):
            await h.service.update_rule(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                dscp_value=10,
            )


# ============================================================================
# Priority validation
# ============================================================================


class TestPriorityValidation:
    async def test_accepts_priority_within_bounds(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router, priority=MIN_PRIORITY)
        assert rule.priority == MIN_PRIORITY

    async def test_rejects_priority_below_minimum(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(InvalidPriorityError):
            await _create_rule(h, router, priority=MIN_PRIORITY - 1)

    async def test_rejects_priority_above_maximum(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(InvalidPriorityError):
            await _create_rule(h, router, priority=MAX_PRIORITY + 1)

    async def test_update_revalidates_priority(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        with pytest.raises(InvalidPriorityError):
            await h.service.update_rule(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                priority=MAX_PRIORITY + 1,
            )


# ============================================================================
# list_rules_for_router -- the real read source Network Configuration
# Management composes to render a router's full QoS mangle config
# ============================================================================


class TestListRulesForRouter:
    async def test_returns_every_non_deleted_rule_for_the_router(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule_a = await _create_rule(h, router, name="Rule A")
        rule_b = await _create_rule(
            h, router, name="Rule B", port_range_start=6000, port_range_end=6001
        )
        await h.service.delete_rule(
            rule_b.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        rules = await h.service.list_rules_for_router(
            router.id, requesting_organization_id=router.organization_id
        )

        assert [r.id for r in rules] == [rule_a.id]

    async def test_raises_for_a_router_outside_the_requesting_organization(
        self,
    ) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)

        with pytest.raises(RouterNotFoundError):
            await h.service.list_rules_for_router(
                router.id, requesting_organization_id=uuid.uuid4()
            )


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_qos_route_has_a_permission_dependency(self) -> None:
        assert len(qos_router.routes) == 5
        for route in qos_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
