"""Unit tests for the ISP Routing domain: traffic-steering rule CRUD
(tenant isolation), per-rule-type match-field validation (on create and on
update, including a rule_type change that invalidates the previously-set
match field), isp_link/router mismatch rejection, and a structural RBAC
check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_isp.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``IspRoutingService`` is exercised against small, hand-rolled
in-memory fakes for its own repository and every composed cross-domain
protocol (``RouterLookupProtocol``/``IspLinkLookupProtocol``) -- mirrors
``test_isp.py``'s own identical "fake the narrow Protocol boundary"
precedent. This domain has no device I/O to test (see ``service.py``'s own
module docstring -- a pure rules/inventory domain, no ``device_adapters.py``
in this pass).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.isp.exceptions import CrossOrganizationIspLinkAccessError
from app.domains.isp.exceptions import IspLinkNotFoundError as IspLinkNotFoundErrorIsp
from app.domains.isp.models import IspLink
from app.domains.isp_routing.constants import IspRoutingRuleType
from app.domains.isp_routing.exceptions import (
    CrossOrganizationIspRoutingRuleAccessError,
    IspRoutingLinkRouterMismatchError,
    IspRoutingRuleInvalidMatchFieldsError,
    IspRoutingRuleNotFoundError,
)
from app.domains.isp_routing.models import IspRoutingRule
from app.domains.isp_routing.router import router as isp_routing_router
from app.domains.isp_routing.service import IspRoutingService
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


def _make_isp_link(router: Router) -> IspLink:
    return IspLink(
        **_base_fields(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            provider_name="Acme Fiber",
            link_type="fiber",
            role="primary",
            is_active_uplink=True,
            auto_failback=True,
            is_enabled=True,
            priority=0,
            interface=None,
            gateway_ip_address="203.0.113.1",
            dns_primary=None,
            dns_secondary=None,
            download_bandwidth_mbps=None,
            upload_bandwidth_mbps=None,
            health_status="unknown",
            latency_ms=None,
            packet_loss_percentage=None,
            last_checked_at=None,
            consecutive_unhealthy_count=0,
        )
    )


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeIspRoutingRepository:
    rules: dict[uuid.UUID, IspRoutingRule] = field(default_factory=dict)

    async def create_rule(self, **fields: object) -> IspRoutingRule:
        rule = IspRoutingRule(**_base_fields(**fields))
        self.rules[rule.id] = rule
        return rule

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> IspRoutingRule | None:
        rule = self.rules.get(rule_id)
        if rule is None or (rule.is_deleted and not include_deleted):
            return None
        return rule

    async def update_rule(
        self, rule: IspRoutingRule, data: dict[str, object]
    ) -> IspRoutingRule:
        for key, value in data.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        rule.version += 1
        return rule

    async def soft_delete_rule(self, rule: IspRoutingRule) -> IspRoutingRule:
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

    async def list_rules_for_router(self, router_id: uuid.UUID) -> list[IspRoutingRule]:
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


@dataclass
class FakeIspLinkLookup:
    links: dict[uuid.UUID, IspLink] = field(default_factory=dict)

    def add(self, link: IspLink) -> IspLink:
        self.links[link.id] = link
        return link

    async def get_link(
        self,
        link_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> IspLink:
        link = self.links.get(link_id)
        if link is None:
            raise IspLinkNotFoundErrorIsp(link_id)
        if (
            requesting_organization_id is not None
            and link.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationIspLinkAccessError()
        return link


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: IspRoutingService
    repository: FakeIspRoutingRepository
    router_lookup: FakeRouterLookup
    isp_link_lookup: FakeIspLinkLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeIspRoutingRepository()
    router_lookup = FakeRouterLookup()
    isp_link_lookup = FakeIspLinkLookup()
    audit_writer = FakeAuditLogWriter()
    service = IspRoutingService(
        repository, router_lookup, isp_link_lookup, audit_writer=audit_writer
    )
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        isp_link_lookup=isp_link_lookup,
        audit_writer=audit_writer,
    )


def _setup_router_and_link(h: Harness) -> tuple[Router, IspLink]:
    router = h.router_lookup.add(_make_router())
    link = h.isp_link_lookup.add(_make_isp_link(router))
    return router, link


async def _create_vlan_rule(
    h: Harness, router: Router, link: IspLink
) -> IspRoutingRule:
    return await h.service.create_rule(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        isp_link_id=link.id,
        rule_type=IspRoutingRuleType.VLAN,
        name="Guest VLAN over Fiber",
        vlan_id=100,
    )


# ============================================================================
# Rule CRUD
# ============================================================================


class TestIspRoutingRuleCrud:
    async def test_create_vlan_rule(self) -> None:
        h = make_harness()
        router, link = _setup_router_and_link(h)
        rule = await _create_vlan_rule(h, router, link)
        assert rule.rule_type == IspRoutingRuleType.VLAN.value
        assert rule.vlan_id == 100
        assert rule.organization_id == router.organization_id
        assert rule.location_id == router.location_id
        assert len(h.audit_writer.entries) == 1

    async def test_create_with_link_on_different_router_raises(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        router_a = h.router_lookup.add(_make_router(organization_id=org_id))
        router_b = h.router_lookup.add(_make_router(organization_id=org_id))
        link_on_b = h.isp_link_lookup.add(_make_isp_link(router_b))
        with pytest.raises(IspRoutingLinkRouterMismatchError):
            await h.service.create_rule(
                actor_user_id=None,
                requesting_organization_id=router_a.organization_id,
                router_id=router_a.id,
                isp_link_id=link_on_b.id,
                rule_type=IspRoutingRuleType.VLAN,
                name="Bad rule",
                vlan_id=50,
            )

    async def test_create_with_wrong_match_field_raises(self) -> None:
        h = make_harness()
        router, link = _setup_router_and_link(h)
        with pytest.raises(IspRoutingRuleInvalidMatchFieldsError):
            await h.service.create_rule(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                isp_link_id=link.id,
                rule_type=IspRoutingRuleType.VLAN,
                name="Bad rule",
                # vlan_id missing, ip_address set instead
                ip_address="10.0.0.5",
            )

    async def test_create_with_extra_match_field_raises(self) -> None:
        h = make_harness()
        router, link = _setup_router_and_link(h)
        with pytest.raises(IspRoutingRuleInvalidMatchFieldsError):
            await h.service.create_rule(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                isp_link_id=link.id,
                rule_type=IspRoutingRuleType.VLAN,
                name="Bad rule",
                vlan_id=100,
                ip_address="10.0.0.5",
            )

    async def test_cross_organization_read_raises(self) -> None:
        h = make_harness()
        router, link = _setup_router_and_link(h)
        rule = await _create_vlan_rule(h, router, link)
        with pytest.raises(CrossOrganizationIspRoutingRuleAccessError):
            await h.service.get_rule(rule.id, requesting_organization_id=uuid.uuid4())

    async def test_get_missing_rule_raises(self) -> None:
        h = make_harness()
        with pytest.raises(IspRoutingRuleNotFoundError):
            await h.service.get_rule(uuid.uuid4())

    async def test_list_rules_scoped_to_router(self) -> None:
        h = make_harness()
        router_a, link_a = _setup_router_and_link(h)
        router_b, link_b = _setup_router_and_link(h)
        await _create_vlan_rule(h, router_a, link_a)
        await _create_vlan_rule(h, router_b, link_b)
        rules, meta = await h.service.list_rules(
            requesting_organization_id=router_a.organization_id, router_id=router_a.id
        )
        assert meta.total_items == 1
        assert rules[0].router_id == router_a.id

    async def test_update_name_only_does_not_touch_match_fields(self) -> None:
        h = make_harness()
        router, link = _setup_router_and_link(h)
        rule = await _create_vlan_rule(h, router, link)
        updated = await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="Renamed",
        )
        assert updated.name == "Renamed"
        assert updated.vlan_id == 100

    async def test_update_isp_link_to_different_router_raises(self) -> None:
        h = make_harness()
        org_id = uuid.uuid4()
        router_a = h.router_lookup.add(_make_router(organization_id=org_id))
        link_a = h.isp_link_lookup.add(_make_isp_link(router_a))
        router_b = h.router_lookup.add(_make_router(organization_id=org_id))
        link_b = h.isp_link_lookup.add(_make_isp_link(router_b))
        rule = await _create_vlan_rule(h, router_a, link_a)
        with pytest.raises(IspRoutingLinkRouterMismatchError):
            await h.service.update_rule(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router_a.organization_id,
                isp_link_id=link_b.id,
            )

    async def test_update_rule_type_without_new_match_field_raises(self) -> None:
        h = make_harness()
        router, link = _setup_router_and_link(h)
        rule = await _create_vlan_rule(h, router, link)
        with pytest.raises(IspRoutingRuleInvalidMatchFieldsError):
            await h.service.update_rule(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                rule_type=IspRoutingRuleType.IP.value,
            )

    async def test_update_rule_type_with_new_match_field_succeeds(self) -> None:
        h = make_harness()
        router, link = _setup_router_and_link(h)
        rule = await _create_vlan_rule(h, router, link)
        updated = await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            rule_type=IspRoutingRuleType.IP.value,
            vlan_id=None,
            ip_address="10.0.0.9",
        )
        assert updated.rule_type == IspRoutingRuleType.IP.value
        assert updated.ip_address == "10.0.0.9"
        assert updated.vlan_id is None

    async def test_delete_soft_deletes(self) -> None:
        h = make_harness()
        router, link = _setup_router_and_link(h)
        rule = await _create_vlan_rule(h, router, link)
        deleted = await h.service.delete_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_isp_routing_route_has_a_permission_dependency(self) -> None:
        assert len(isp_routing_router.routes) == 5
        for route in isp_routing_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
