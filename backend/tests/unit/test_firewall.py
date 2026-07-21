"""Unit tests for the Firewall Rule Management domain: rule CRUD (tenant
isolation), port/address validation, priority-ordered listing, and a
structural RBAC check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_dhcp.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``FirewallService`` is exercised against small, hand-rolled
in-memory fakes for its own repository and the composed
``RouterLookupProtocol``. This domain has no device I/O to test (a pure
rules/inventory domain, no ``device_adapters.py`` in this pass), and no
conflict detection -- overlapping rules are valid, intentional policy
(see ``models.FirewallRule``'s own module docstring).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.firewall.constants import (
    DEFAULT_PRIORITY,
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
)
from app.domains.firewall.exceptions import (
    CrossOrganizationFirewallRuleAccessError,
    FirewallRuleNotFoundError,
    InvalidFirewallAddressError,
    InvalidFirewallPortError,
)
from app.domains.firewall.models import FirewallRule
from app.domains.firewall.router import router as firewall_router
from app.domains.firewall.service import FirewallService
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
class FakeFirewallRepository:
    rules: dict[uuid.UUID, FirewallRule] = field(default_factory=dict)

    async def create_rule(self, **fields: object) -> FirewallRule:
        rule = FirewallRule(**_base_fields(**fields))
        self.rules[rule.id] = rule
        return rule

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> FirewallRule | None:
        rule = self.rules.get(rule_id)
        if rule is None or (rule.is_deleted and not include_deleted):
            return None
        return rule

    async def update_rule(
        self, rule: FirewallRule, data: dict[str, object]
    ) -> FirewallRule:
        for key, value in data.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        rule.version += 1
        return rule

    async def soft_delete_rule(self, rule: FirewallRule) -> FirewallRule:
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
        values.sort(key=lambda v: v.priority)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_rules_for_router(self, router_id: uuid.UUID) -> list[FirewallRule]:
        values = [
            v
            for v in self.rules.values()
            if v.router_id == router_id and not v.is_deleted
        ]
        values.sort(key=lambda v: v.priority)
        return values


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
    service: FirewallService
    repository: FakeFirewallRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeFirewallRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    service = FirewallService(repository, router_lookup, audit_writer=audit_writer)
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
    name: str = "Block Telnet",
    priority: int = DEFAULT_PRIORITY,
    **kwargs: object,
) -> FirewallRule:
    return await h.service.create_rule(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        name=name,
        priority=priority,
        **kwargs,
    )


# ============================================================================
# Rule CRUD
# ============================================================================


class TestFirewallRuleCrud:
    async def test_create_rule_defaults(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        assert rule.chain == FirewallChain.FORWARD.value
        assert rule.action == FirewallAction.ACCEPT.value
        assert rule.protocol == FirewallProtocol.ALL.value
        assert rule.organization_id == router.organization_id
        assert rule.location_id == router.location_id
        assert len(h.audit_writer.entries) == 1

    async def test_create_with_invalid_source_address_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidFirewallAddressError):
            await _create_rule(h, router, source_address="not-an-ip")

    async def test_create_with_invalid_port_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidFirewallPortError):
            await _create_rule(h, router, destination_port=70000)

    async def test_create_accepts_cidr_addresses(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router, source_address="10.0.0.0/24")
        assert rule.source_address == "10.0.0.0/24"

    async def test_create_raises_for_unknown_router(self) -> None:
        h = make_harness()
        with pytest.raises(RouterNotFoundError):
            await _create_rule(h, _make_router())

    async def test_overlapping_rules_are_allowed(self) -> None:
        """Unlike DHCP/port-forwarding, no conflict detection exists --
        two rules matching the same destination_port are valid, ordered
        policy (see models.FirewallRule's own module docstring)."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, name="Drop Telnet", destination_port=23)
        rule_b = await _create_rule(h, router, name="Also Telnet", destination_port=23)
        assert rule_b.destination_port == 23

    async def test_get_rule_cross_organization_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        with pytest.raises(CrossOrganizationFirewallRuleAccessError):
            await h.service.get_rule(rule.id, requesting_organization_id=uuid.uuid4())

    async def test_get_rule_not_found_raises(self) -> None:
        h = make_harness()
        with pytest.raises(FirewallRuleNotFoundError):
            await h.service.get_rule(uuid.uuid4())

    async def test_update_rule_revalidates_new_port(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        with pytest.raises(InvalidFirewallPortError):
            await h.service.update_rule(
                rule.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=router.organization_id,
                destination_port=99999,
            )

    async def test_update_rule_success(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        updated = await h.service.update_rule(
            rule.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            action=FirewallAction.DROP,
        )
        assert updated.action == FirewallAction.DROP.value
        assert len(h.audit_writer.entries) == 2

    async def test_delete_rule(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        deleted = await h.service.delete_rule(
            rule.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True

    async def test_list_rules_for_router_sorted_by_priority(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, name="Low priority", priority=200)
        await _create_rule(h, router, name="High priority", priority=10)
        rules = await h.service.list_rules_for_router(
            router.id, requesting_organization_id=router.organization_id
        )
        assert [r.name for r in rules] == ["High priority", "Low priority"]

    async def test_list_rules_scopes_to_organization(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_rule(h, router_a)
        await _create_rule(h, router_b)
        rules, meta = await h.service.list_rules(
            requesting_organization_id=router_a.organization_id
        )
        assert meta.total_items == 1
        assert rules[0].organization_id == router_a.organization_id


# ============================================================================
# Structural RBAC check
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_firewall_route_has_a_permission_dependency(self) -> None:
        assert len(firewall_router.routes) == 5
        for route in firewall_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
