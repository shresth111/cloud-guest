"""Unit tests for the Port Forwarding Management domain: rule CRUD
(tenant isolation), port-range validation, address validation
(source/destination CIDR-or-IP, internal single-host-only), conflict
detection (overlap rejected when protocol+destination_address+
destination_port overlap on the same router, allowed across different
ports/protocols/addresses or different routers, re-checked on update
excluding the rule itself), and a structural RBAC check that every route
carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_dhcp.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``PortForwardingService`` is exercised against small,
hand-rolled in-memory fakes for its own repository and the composed
``RouterLookupProtocol`` -- mirrors ``test_dhcp.py``'s own identical "fake
the narrow Protocol boundary" precedent. This domain has no device I/O to
test (see ``service.py``'s own module docstring -- a pure rules/inventory
domain, no ``device_adapters.py`` in this pass).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.port_forwarding.constants import PortForwardingProtocol
from app.domains.port_forwarding.exceptions import (
    CrossOrganizationPortForwardingRuleAccessError,
    InvalidAddressError,
    InvalidPortError,
    PortForwardingConflictError,
    PortForwardingRuleNotFoundError,
)
from app.domains.port_forwarding.models import PortForwardingRule
from app.domains.port_forwarding.router import router as port_forwarding_router
from app.domains.port_forwarding.service import PortForwardingService
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
class FakePortForwardingRepository:
    rules: dict[uuid.UUID, PortForwardingRule] = field(default_factory=dict)

    async def create_rule(self, **fields: object) -> PortForwardingRule:
        rule = PortForwardingRule(**_base_fields(**fields))
        self.rules[rule.id] = rule
        return rule

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> PortForwardingRule | None:
        rule = self.rules.get(rule_id)
        if rule is None or (rule.is_deleted and not include_deleted):
            return None
        return rule

    async def update_rule(
        self, rule: PortForwardingRule, data: dict[str, object]
    ) -> PortForwardingRule:
        for key, value in data.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        rule.version += 1
        return rule

    async def soft_delete_rule(self, rule: PortForwardingRule) -> PortForwardingRule:
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

    async def list_rules_for_router(
        self, router_id: uuid.UUID
    ) -> list[PortForwardingRule]:
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
    service: PortForwardingService
    repository: FakePortForwardingRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakePortForwardingRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    service = PortForwardingService(
        repository, router_lookup, audit_writer=audit_writer
    )
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
    destination_port: int = 8080,
    protocol: PortForwardingProtocol = PortForwardingProtocol.TCP,
    destination_address: str | None = None,
) -> PortForwardingRule:
    return await h.service.create_rule(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        name="Web Server",
        protocol=protocol,
        destination_address=destination_address,
        destination_port=destination_port,
        internal_address="192.168.1.10",
        internal_port=80,
    )


# ============================================================================
# Rule CRUD
# ============================================================================


class TestPortForwardingRuleCrud:
    async def test_create_rule(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        assert rule.destination_port == 8080
        assert rule.internal_address == "192.168.1.10"
        assert rule.organization_id == router.organization_id
        assert rule.location_id == router.location_id
        assert len(h.audit_writer.entries) == 1

    async def test_create_with_invalid_destination_port_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidPortError):
            await h.service.create_rule(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                name="Bad Rule",
                destination_port=70000,
                internal_address="192.168.1.10",
                internal_port=80,
            )

    async def test_create_with_invalid_internal_address_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidAddressError):
            await h.service.create_rule(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                name="Bad Rule",
                destination_port=8080,
                internal_address="bogus",
                internal_port=80,
            )

    async def test_create_with_cidr_internal_address_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidAddressError):
            await h.service.create_rule(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                name="Bad Rule",
                destination_port=8080,
                internal_address="192.168.1.0/24",
                internal_port=80,
            )

    async def test_cross_organization_read_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        with pytest.raises(CrossOrganizationPortForwardingRuleAccessError):
            await h.service.get_rule(rule.id, requesting_organization_id=uuid.uuid4())

    async def test_get_missing_rule_raises(self) -> None:
        h = make_harness()
        with pytest.raises(PortForwardingRuleNotFoundError):
            await h.service.get_rule(uuid.uuid4())

    async def test_list_rules_scoped_to_router(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_rule(h, router_a, destination_port=8080)
        await _create_rule(h, router_b, destination_port=8081)
        rules, meta = await h.service.list_rules(
            requesting_organization_id=router_a.organization_id, router_id=router_a.id
        )
        assert meta.total_items == 1
        assert rules[0].router_id == router_a.id

    async def test_delete_soft_deletes(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        deleted = await h.service.delete_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True


# ============================================================================
# Conflict detection
# ============================================================================


class TestPortForwardingConflict:
    async def test_same_port_and_protocol_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(
            h, router, destination_port=8080, protocol=PortForwardingProtocol.TCP
        )
        with pytest.raises(PortForwardingConflictError):
            await _create_rule(
                h, router, destination_port=8080, protocol=PortForwardingProtocol.TCP
            )

    async def test_different_port_is_allowed(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, destination_port=8080)
        second = await _create_rule(h, router, destination_port=8081)
        assert second.destination_port == 8081

    async def test_different_protocol_is_allowed(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(
            h, router, destination_port=8080, protocol=PortForwardingProtocol.TCP
        )
        second = await _create_rule(
            h, router, destination_port=8080, protocol=PortForwardingProtocol.UDP
        )
        assert second.protocol == PortForwardingProtocol.UDP.value

    async def test_both_protocol_conflicts_with_tcp(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(
            h, router, destination_port=8080, protocol=PortForwardingProtocol.TCP
        )
        with pytest.raises(PortForwardingConflictError):
            await _create_rule(
                h, router, destination_port=8080, protocol=PortForwardingProtocol.BOTH
            )

    async def test_different_destination_address_is_allowed(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(
            h, router, destination_port=8080, destination_address="203.0.113.10"
        )
        second = await _create_rule(
            h, router, destination_port=8080, destination_address="203.0.113.20"
        )
        assert second.destination_address == "203.0.113.20"

    async def test_none_destination_address_conflicts_with_specific_address(
        self,
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, destination_port=8080, destination_address=None)
        with pytest.raises(PortForwardingConflictError):
            await _create_rule(
                h, router, destination_port=8080, destination_address="203.0.113.10"
            )

    async def test_different_router_is_allowed(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_rule(h, router_a, destination_port=8080)
        second = await _create_rule(h, router_b, destination_port=8080)
        assert second.router_id == router_b.id

    async def test_update_port_rechecks_conflict_excluding_self(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router, destination_port=8080)
        updated = await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            destination_port=8080,
        )
        assert updated.destination_port == 8080

    async def test_update_port_to_conflict_with_another_rule_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, destination_port=8080)
        second = await _create_rule(h, router, destination_port=9090)
        with pytest.raises(PortForwardingConflictError):
            await h.service.update_rule(
                second.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                destination_port=8080,
            )


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_port_forwarding_route_has_a_permission_dependency(self) -> None:
        assert len(port_forwarding_router.routes) == 5
        for route in port_forwarding_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
