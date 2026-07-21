"""Unit tests for the Network Configuration Management domain: RouterOS
renderers (DHCP pool / VLAN / Port Forwarding -> real script text) and
``NetworkConfigService``'s composition of ``app.domains.dhcp``/``app.domains
.vlan``/``app.domains.port_forwarding``/``app.domains.router_provisioning``
via small, hand-rolled in-memory fakes -- mirrors ``test_device_sync.py``'s
own identical "fake the narrow Protocol boundary" precedent. A structural
RBAC check confirms every route carries a permission dependency.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.domains.dhcp.models import DhcpPool
from app.domains.network_config.constants import (
    DHCP_SECTION_HEADER,
    PORT_FORWARDING_SECTION_HEADER,
    VLAN_SECTION_HEADER,
)
from app.domains.network_config.exceptions import EmptyNetworkConfigError
from app.domains.network_config.renderers import (
    render_dhcp_pool,
    render_network_config,
    render_port_forwarding_rule,
    render_vlan,
)
from app.domains.network_config.router import router as network_config_router
from app.domains.network_config.service import NetworkConfigService
from app.domains.port_forwarding.constants import PortForwardingProtocol
from app.domains.port_forwarding.models import PortForwardingRule
from app.domains.router_provisioning.constants import ConfigVersionStatus
from app.domains.router_provisioning.models import ConfigVersion, ProvisioningJob
from app.domains.vlan.models import Vlan


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


def _make_pool(**overrides: object) -> DhcpPool:
    fields = {
        "router_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "name": "Guest Pool",
        "interface": "ether2",
        "address_range_start": "192.168.10.100",
        "address_range_end": "192.168.10.200",
        "gateway_ip_address": "192.168.10.1",
        "dns_primary": "8.8.8.8",
        "dns_secondary": "8.8.4.4",
        "lease_time_seconds": 3600,
        "is_enabled": True,
    }
    fields.update(overrides)
    return DhcpPool(**_base_fields(**fields))


def _make_vlan(**overrides: object) -> Vlan:
    fields = {
        "router_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "vlan_id": 100,
        "name": "Guest VLAN",
        "gateway_ip_address": "10.0.100.1",
        "cidr": "10.0.100.0/24",
        "interface": "ether1",
        "description": None,
        "is_enabled": True,
    }
    fields.update(overrides)
    return Vlan(**_base_fields(**fields))


def _make_rule(**overrides: object) -> PortForwardingRule:
    fields = {
        "router_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "name": "Web Server",
        "protocol": PortForwardingProtocol.TCP,
        "source_address": None,
        "destination_address": None,
        "destination_port": 8080,
        "internal_address": "192.168.1.10",
        "internal_port": 80,
        "description": None,
        "is_enabled": True,
    }
    fields.update(overrides)
    return PortForwardingRule(**_base_fields(**fields))


# ============================================================================
# Renderers
# ============================================================================


class TestRenderDhcpPool:
    def test_renders_pool_dhcp_server_and_network_lines(self) -> None:
        lines = render_dhcp_pool(_make_pool())
        joined = "\n".join(lines)
        assert "/ip pool add" in joined
        assert "ranges=192.168.10.100-192.168.10.200" in joined
        assert "/ip dhcp-server add" in joined
        assert "interface=ether2" in joined
        assert "/ip dhcp-server network add address=192.168.10.0/24" in joined
        assert "gateway=192.168.10.1" in joined
        assert "dns-server=8.8.8.8,8.8.4.4" in joined
        assert "lease-time=3600s" in joined

    def test_skips_dhcp_server_binding_without_an_interface(self) -> None:
        lines = render_dhcp_pool(_make_pool(interface=None))
        joined = "\n".join(lines)
        assert "/ip pool add" in joined
        assert "/ip dhcp-server add" not in joined
        assert "/ip dhcp-server network" not in joined

    def test_two_pools_with_the_same_name_get_distinct_identifiers(self) -> None:
        pool_a = _make_pool(name="Guest Pool")
        pool_b = _make_pool(name="Guest Pool")
        lines_a = render_dhcp_pool(pool_a)
        lines_b = render_dhcp_pool(pool_b)
        assert lines_a[0] != lines_b[0]


class TestRenderVlan:
    def test_renders_interface_and_address_lines(self) -> None:
        lines = render_vlan(_make_vlan())
        joined = "\n".join(lines)
        assert "/interface vlan add name=vlan100 vlan-id=100 interface=ether1" in joined
        assert "/ip address add address=10.0.100.1/24 interface=vlan100" in joined

    def test_skips_address_line_without_a_cidr(self) -> None:
        lines = render_vlan(_make_vlan(cidr=None, gateway_ip_address=None))
        joined = "\n".join(lines)
        assert "/interface vlan add" in joined
        assert "/ip address add" not in joined

    def test_skips_entirely_without_a_parent_interface(self) -> None:
        lines = render_vlan(_make_vlan(interface=None))
        joined = "\n".join(lines)
        assert "/interface vlan add" not in joined
        assert "vlan100" in joined  # explanatory comment still names it


class TestRenderPortForwardingRule:
    def test_renders_a_tcp_rule_with_explicit_protocol(self) -> None:
        (line,) = render_port_forwarding_rule(_make_rule())
        assert "protocol=tcp" in line
        assert "dst-port=8080" in line
        assert "to-addresses=192.168.1.10" in line
        assert "to-ports=80" in line
        assert 'comment="Web Server"' in line

    def test_both_protocol_omits_the_protocol_parameter(self) -> None:
        (line,) = render_port_forwarding_rule(
            _make_rule(protocol=PortForwardingProtocol.BOTH)
        )
        assert "protocol=" not in line

    def test_includes_source_and_destination_address_when_present(self) -> None:
        (line,) = render_port_forwarding_rule(
            _make_rule(source_address="10.0.0.0/24", destination_address="203.0.113.5")
        )
        assert "src-address=10.0.0.0/24" in line
        assert "dst-address=203.0.113.5" in line


class TestRenderNetworkConfig:
    def test_combines_all_three_categories_with_section_headers(self) -> None:
        rendered = render_network_config(
            dhcp_pools=[_make_pool()],
            vlans=[_make_vlan()],
            port_forwarding_rules=[_make_rule()],
        )
        assert DHCP_SECTION_HEADER in rendered
        assert VLAN_SECTION_HEADER in rendered
        assert PORT_FORWARDING_SECTION_HEADER in rendered

    def test_returns_empty_string_for_no_input(self) -> None:
        assert (
            render_network_config(dhcp_pools=[], vlans=[], port_forwarding_rules=[])
            == ""
        )

    def test_omits_a_section_header_for_an_empty_category(self) -> None:
        rendered = render_network_config(
            dhcp_pools=[_make_pool()], vlans=[], port_forwarding_rules=[]
        )
        assert DHCP_SECTION_HEADER in rendered
        assert VLAN_SECTION_HEADER not in rendered
        assert PORT_FORWARDING_SECTION_HEADER not in rendered


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeDhcpLookup:
    pools: list[DhcpPool] = field(default_factory=list)
    calls: list[dict[str, object]] = field(default_factory=list)

    async def list_pools_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[DhcpPool]:
        self.calls.append(
            {
                "router_id": router_id,
                "requesting_organization_id": requesting_organization_id,
            }
        )
        return [p for p in self.pools if p.router_id == router_id]


@dataclass
class FakeVlanLookup:
    vlans: list[Vlan] = field(default_factory=list)

    async def list_vlans_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[Vlan]:
        return [v for v in self.vlans if v.router_id == router_id]


@dataclass
class FakePortForwardingLookup:
    rules: list[PortForwardingRule] = field(default_factory=list)

    async def list_rules_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[PortForwardingRule]:
        return [r for r in self.rules if r.router_id == router_id]


@dataclass
class FakeRouterProvisioningLookup:
    versions: dict[uuid.UUID, ConfigVersion] = field(default_factory=dict)
    jobs: dict[uuid.UUID, ProvisioningJob] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    def _next_version_number(self, router_id: uuid.UUID) -> int:
        existing = [v for v in self.versions.values() if v.router_id == router_id]
        return len(existing) + 1

    async def create_version_from_content(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        rendered_content: str,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion:
        self.calls.append("create_version_from_content")
        version = ConfigVersion(
            **_base_fields(
                router_id=router_id,
                profile_id=None,
                version_number=self._next_version_number(router_id),
                rendered_content=rendered_content,
                status=ConfigVersionStatus.DRAFT.value,
                created_by_user_id=actor_user_id,
                applied_at=None,
                rollback_of_version_id=None,
                is_backup=False,
            )
        )
        self.versions[version.id] = version
        return version

    async def apply_version(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigVersion, ProvisioningJob]:
        self.calls.append("apply_version")
        version = self.versions[version_id]
        version.status = ConfigVersionStatus.PENDING_APPLY.value
        job = ProvisioningJob(
            **_base_fields(
                router_id=router_id,
                job_type="config_push",
                status="queued",
                payload={"config_version_id": str(version.id)},
                attempts=0,
                max_attempts=3,
                scheduled_at=_now(),
                started_at=None,
                completed_at=None,
                error_message=None,
                requested_by_user_id=actor_user_id,
            )
        )
        self.jobs[job.id] = job
        return version, job

    async def get_version(
        self,
        *,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion:
        self.calls.append("get_version")
        return self.versions[version_id]

    async def list_versions(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ConfigVersion], object]:
        self.calls.append("list_versions")
        versions = [v for v in self.versions.values() if v.router_id == router_id]
        return versions, object()

    async def diff_versions(
        self,
        *,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        other_version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigVersion, ConfigVersion, list[str]]:
        self.calls.append("diff_versions")
        return (
            self.versions[version_id],
            self.versions[other_version_id],
            ["- old", "+ new"],
        )

    async def rollback_to_version(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        target_version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion:
        self.calls.append("rollback_to_version")
        target = self.versions[target_version_id]
        new_version = ConfigVersion(
            **_base_fields(
                router_id=router_id,
                profile_id=target.profile_id,
                version_number=self._next_version_number(router_id),
                rendered_content=target.rendered_content,
                status=ConfigVersionStatus.DRAFT.value,
                created_by_user_id=actor_user_id,
                applied_at=None,
                rollback_of_version_id=target.id,
                is_backup=False,
            )
        )
        self.versions[new_version.id] = new_version
        return new_version


def _make_service(
    *,
    pools: list[DhcpPool] | None = None,
    vlans: list[Vlan] | None = None,
    rules: list[PortForwardingRule] | None = None,
) -> tuple[NetworkConfigService, FakeRouterProvisioningLookup]:
    provisioning_lookup = FakeRouterProvisioningLookup()
    service = NetworkConfigService(
        FakeDhcpLookup(pools or []),
        FakeVlanLookup(vlans or []),
        FakePortForwardingLookup(rules or []),
        provisioning_lookup,
    )
    return service, provisioning_lookup


# ============================================================================
# NetworkConfigService.preview_config
# ============================================================================


class TestPreviewConfig:
    async def test_returns_rendered_content_and_counts(self) -> None:
        router_id = uuid.uuid4()
        service, _ = _make_service(
            pools=[_make_pool(router_id=router_id)],
            vlans=[_make_vlan(router_id=router_id)],
            rules=[_make_rule(router_id=router_id)],
        )
        preview = await service.preview_config(
            router_id, requesting_organization_id=uuid.uuid4()
        )
        assert preview.dhcp_pool_count == 1
        assert preview.vlan_count == 1
        assert preview.port_forwarding_rule_count == 1
        assert DHCP_SECTION_HEADER in preview.rendered_content

    async def test_excludes_disabled_rows(self) -> None:
        router_id = uuid.uuid4()
        service, _ = _make_service(
            pools=[
                _make_pool(router_id=router_id, is_enabled=True),
                _make_pool(router_id=router_id, is_enabled=False),
            ]
        )
        preview = await service.preview_config(
            router_id, requesting_organization_id=uuid.uuid4()
        )
        assert preview.dhcp_pool_count == 1

    async def test_empty_router_returns_empty_preview_without_raising(self) -> None:
        service, _ = _make_service()
        preview = await service.preview_config(
            uuid.uuid4(), requesting_organization_id=uuid.uuid4()
        )
        assert preview.rendered_content == ""
        assert preview.dhcp_pool_count == 0


# ============================================================================
# NetworkConfigService.push_config
# ============================================================================


class TestPushConfig:
    async def test_creates_and_applies_a_version(self) -> None:
        router_id = uuid.uuid4()
        service, provisioning_lookup = _make_service(
            pools=[_make_pool(router_id=router_id)]
        )
        version, job = await service.push_config(
            router_id, actor_user_id=uuid.uuid4(), requesting_organization_id=None
        )
        assert version.status == ConfigVersionStatus.PENDING_APPLY.value
        assert job.payload["config_version_id"] == str(version.id)
        assert provisioning_lookup.calls == [
            "create_version_from_content",
            "apply_version",
        ]

    async def test_raises_for_a_router_with_nothing_enabled(self) -> None:
        service, _ = _make_service()
        with pytest.raises(EmptyNetworkConfigError):
            await service.push_config(
                uuid.uuid4(), actor_user_id=None, requesting_organization_id=None
            )

    async def test_raises_when_every_row_is_disabled(self) -> None:
        router_id = uuid.uuid4()
        service, _ = _make_service(
            pools=[_make_pool(router_id=router_id, is_enabled=False)]
        )
        with pytest.raises(EmptyNetworkConfigError):
            await service.push_config(
                router_id, actor_user_id=None, requesting_organization_id=None
            )


# ============================================================================
# NetworkConfigService: version reads + rollback delegate to
# router_provisioning
# ============================================================================


class TestVersionReadsDelegate:
    async def test_get_version_delegates(self) -> None:
        service, provisioning_lookup = _make_service()
        version = await provisioning_lookup.create_version_from_content(
            actor_user_id=None,
            router_id=uuid.uuid4(),
            rendered_content="x",
            requesting_organization_id=None,
        )
        result = await service.get_version(
            version.router_id, version.id, requesting_organization_id=None
        )
        assert result.id == version.id

    async def test_list_versions_delegates(self) -> None:
        service, provisioning_lookup = _make_service()
        router_id = uuid.uuid4()
        await provisioning_lookup.create_version_from_content(
            actor_user_id=None,
            router_id=router_id,
            rendered_content="x",
            requesting_organization_id=None,
        )
        versions, _meta = await service.list_versions(
            router_id, requesting_organization_id=None
        )
        assert len(versions) == 1

    async def test_diff_versions_delegates(self) -> None:
        service, provisioning_lookup = _make_service()
        router_id = uuid.uuid4()
        v1 = await provisioning_lookup.create_version_from_content(
            actor_user_id=None,
            router_id=router_id,
            rendered_content="a",
            requesting_organization_id=None,
        )
        v2 = await provisioning_lookup.create_version_from_content(
            actor_user_id=None,
            router_id=router_id,
            rendered_content="b",
            requesting_organization_id=None,
        )
        _a, _b, diff_lines = await service.diff_versions(
            router_id, v1.id, v2.id, requesting_organization_id=None
        )
        assert diff_lines


class TestRollbackAndApply:
    async def test_rolls_back_then_applies_the_new_version(self) -> None:
        service, provisioning_lookup = _make_service()
        router_id = uuid.uuid4()
        target = await provisioning_lookup.create_version_from_content(
            actor_user_id=None,
            router_id=router_id,
            rendered_content="original",
            requesting_organization_id=None,
        )
        version, job = await service.rollback_and_apply(
            router_id,
            target.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
        )
        assert version.rollback_of_version_id == target.id
        assert version.status == ConfigVersionStatus.PENDING_APPLY.value
        assert job.payload["config_version_id"] == str(version.id)


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_network_config_route_has_a_permission_dependency(self) -> None:
        assert len(network_config_router.routes) == 6
        for route in network_config_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
