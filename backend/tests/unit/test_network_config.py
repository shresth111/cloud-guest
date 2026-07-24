"""Unit tests for the Network Configuration Management domain: RouterOS
renderers (DHCP pool / VLAN / Port Forwarding / Hotspot / QoS -> real
script text) and ``NetworkConfigService``'s composition of
``app.domains.dhcp``/``app.domains.vlan``/``app.domains
.port_forwarding``/``app.domains.hotspot``/``app.domains.qos``/
``app.domains.router_provisioning`` via small, hand-rolled in-memory
fakes -- mirrors ``test_device_sync.py``'s own identical "fake the
narrow Protocol boundary" precedent. A structural RBAC check confirms
every route carries a permission dependency.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.domains.dhcp.models import DhcpPool
from app.domains.dns.constants import DnsRecordType
from app.domains.dns.models import DnsRecord
from app.domains.firewall.constants import (
    FirewallAction,
    FirewallChain,
    FirewallProtocol,
)
from app.domains.firewall.models import FirewallRule
from app.domains.hotspot.models import HotspotProfile
from app.domains.network_config.constants import (
    DHCP_SECTION_HEADER,
    DNS_SECTION_HEADER,
    FIREWALL_SECTION_HEADER,
    HOTSPOT_SECTION_HEADER,
    PORT_FORWARDING_SECTION_HEADER,
    QOS_SECTION_HEADER,
    VLAN_SECTION_HEADER,
)
from app.domains.network_config.exceptions import EmptyNetworkConfigError
from app.domains.network_config.renderers import (
    render_agent_heartbeat_scheduler,
    render_bootstrap_script,
    render_dhcp_pool,
    render_dns_record,
    render_firewall_rule,
    render_hotspot_profile,
    render_network_config,
    render_port_forwarding_rule,
    render_qos_traffic_rule,
    render_vlan,
    render_wireguard_peer,
)
from app.domains.network_config.router import router as network_config_router
from app.domains.network_config.service import NetworkConfigService
from app.domains.port_forwarding.constants import PortForwardingProtocol
from app.domains.port_forwarding.models import PortForwardingRule
from app.domains.qos.models import QosTrafficRule
from app.domains.router.crypto import encrypt_secret
from app.domains.router_provisioning.constants import ConfigVersionStatus
from app.domains.router_provisioning.models import ConfigVersion, ProvisioningJob
from app.domains.vlan.models import Vlan
from app.domains.wireguard.constants import PeerStatus
from app.domains.wireguard.models import WireGuardPeer, WireGuardServer
from app.domains.wireguard.service import EXTERNALLY_MANAGED_KEY_SENTINEL


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


def _make_hotspot_profile(**overrides: object) -> HotspotProfile:
    fields = {
        "router_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "name": "Guest Hotspot",
        "session_timeout_minutes": 240,
        "idle_timeout_minutes": 15,
        "upload_limit_kbps": 1024,
        "download_limit_kbps": 4096,
        "walled_garden_hosts": ["example.com"],
        "is_enabled": True,
    }
    fields.update(overrides)
    return HotspotProfile(**_base_fields(**fields))


def _make_qos_rule(**overrides: object) -> QosTrafficRule:
    fields = {
        "router_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "name": "SIP Signaling",
        "protocol": "udp",
        "port_range_start": 5060,
        "port_range_end": 5061,
        "dscp_value": None,
        "priority": 1,
        "is_enabled": True,
    }
    fields.update(overrides)
    return QosTrafficRule(**_base_fields(**fields))


def _make_dns_record(**overrides: object) -> DnsRecord:
    fields = {
        "router_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "name": "printer.local",
        "record_type": DnsRecordType.A.value,
        "address": "192.168.1.50",
        "ttl_seconds": 3600,
        "comment": None,
        "is_enabled": True,
    }
    fields.update(overrides)
    return DnsRecord(**_base_fields(**fields))


def _make_firewall_rule(**overrides: object) -> FirewallRule:
    fields = {
        "router_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "name": "Block Telnet",
        "chain": FirewallChain.INPUT.value,
        "action": FirewallAction.DROP.value,
        "protocol": FirewallProtocol.TCP.value,
        "source_address": None,
        "destination_address": None,
        "source_port": None,
        "destination_port": 23,
        "in_interface": None,
        "priority": 10,
        "comment": None,
        "is_enabled": True,
    }
    fields.update(overrides)
    return FirewallRule(**_base_fields(**fields))


def _make_wireguard_server(**overrides: object) -> WireGuardServer:
    fields = {
        "name": "Primary Hub",
        "endpoint_host": "hub.cloudguest.example",
        "endpoint_port": 51820,
        "public_key": "hub-public-key-base64==",
        "private_key_encrypted": encrypt_secret("hub-private-key"),
        "tunnel_network_cidr": "10.100.0.0/16",
        "is_active": True,
    }
    fields.update(overrides)
    return WireGuardServer(**_base_fields(**fields))


def _make_wireguard_peer(**overrides: object) -> WireGuardPeer:
    fields = {
        "router_id": uuid.uuid4(),
        "server_id": uuid.uuid4(),
        "tunnel_ip_address": "10.100.0.5",
        "public_key": "peer-public-key-base64==",
        "private_key_encrypted": encrypt_secret("peer-private-key"),
        "status": PeerStatus.ACTIVE.value,
        "rotation_count": 0,
        "last_handshake_at": None,
        "revoked_at": None,
    }
    fields.update(overrides)
    return WireGuardPeer(**_base_fields(**fields))


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


class TestRenderHotspotProfile:
    def test_renders_user_profile_and_walled_garden_lines(self) -> None:
        lines = render_hotspot_profile(_make_hotspot_profile())
        joined = "\n".join(lines)
        assert "/ip hotspot user profile add" in joined
        assert "session-timeout=240m" in joined
        assert "idle-timeout=15m" in joined
        assert "rate-limit=1024k/4096k" in joined
        assert "/ip hotspot walled-garden add dst-host=example.com" in joined
        assert 'comment="Guest Hotspot"' in joined

    def test_omits_unset_timeout_and_rate_limit_fields(self) -> None:
        (line,) = render_hotspot_profile(
            _make_hotspot_profile(
                session_timeout_minutes=None,
                idle_timeout_minutes=None,
                upload_limit_kbps=None,
                download_limit_kbps=None,
                walled_garden_hosts=[],
            )
        )
        assert "session-timeout=" not in line
        assert "idle-timeout=" not in line
        assert "rate-limit=" not in line

    def test_rate_limit_defaults_unset_half_to_zero(self) -> None:
        (line, *_rest) = render_hotspot_profile(
            _make_hotspot_profile(
                upload_limit_kbps=512, download_limit_kbps=None, walled_garden_hosts=[]
            )
        )
        assert "rate-limit=512k/0k" in line

    def test_two_profiles_with_the_same_name_get_distinct_identifiers(self) -> None:
        profile_a = _make_hotspot_profile(name="Guest Hotspot")
        profile_b = _make_hotspot_profile(name="Guest Hotspot")
        line_a = render_hotspot_profile(profile_a)[0]
        line_b = render_hotspot_profile(profile_b)[0]
        assert line_a != line_b


class TestRenderQosTrafficRule:
    def test_renders_a_port_range_match(self) -> None:
        (line,) = render_qos_traffic_rule(_make_qos_rule())
        assert "/ip firewall mangle add chain=prerouting" in line
        assert "protocol=udp" in line
        assert "dst-port=5060-5061" in line
        assert "action=mark-packet" in line
        assert "passthrough=no" in line
        assert 'comment="SIP Signaling (priority=1)"' in line

    def test_renders_a_dscp_match(self) -> None:
        (line,) = render_qos_traffic_rule(
            _make_qos_rule(
                protocol=None, port_range_start=None, port_range_end=None, dscp_value=46
            )
        )
        assert "dscp=46" in line
        assert "dst-port=" not in line
        assert "protocol=" not in line

    def test_two_rules_with_the_same_name_get_distinct_identifiers(self) -> None:
        rule_a = _make_qos_rule(name="SIP Signaling")
        rule_b = _make_qos_rule(name="SIP Signaling")
        line_a = render_qos_traffic_rule(rule_a)[0]
        line_b = render_qos_traffic_rule(rule_b)[0]
        assert line_a != line_b


class TestRenderDnsRecord:
    def test_renders_an_a_record(self) -> None:
        (line,) = render_dns_record(_make_dns_record())
        assert "/ip dns static add name=printer.local" in line
        assert "address=192.168.1.50" in line
        assert "ttl=3600s" in line
        assert "cname=" not in line

    def test_renders_a_cname_record(self) -> None:
        (line,) = render_dns_record(
            _make_dns_record(
                record_type=DnsRecordType.CNAME.value, address="host.local"
            )
        )
        assert "cname=host.local" in line
        assert "type=CNAME" in line
        assert "address=" not in line

    def test_includes_comment_when_present(self) -> None:
        (line,) = render_dns_record(_make_dns_record(comment="office printer"))
        assert 'comment="office printer"' in line


class TestRenderFirewallRule:
    def test_renders_a_drop_rule(self) -> None:
        (line,) = render_firewall_rule(_make_firewall_rule())
        assert "/ip firewall filter add chain=input" in line
        assert "protocol=tcp" in line
        assert "dst-port=23" in line
        assert "action=drop" in line
        assert 'comment="Block Telnet (priority=10)"' in line

    def test_all_protocol_omits_protocol_parameter(self) -> None:
        (line,) = render_firewall_rule(
            _make_firewall_rule(protocol=FirewallProtocol.ALL.value)
        )
        assert "protocol=" not in line

    def test_addresses_and_interface_included_when_present(self) -> None:
        (line,) = render_firewall_rule(
            _make_firewall_rule(
                source_address="10.0.0.0/24",
                destination_address="192.168.1.1",
                in_interface="ether1",
            )
        )
        assert "src-address=10.0.0.0/24" in line
        assert "dst-address=192.168.1.1" in line
        assert "in-interface=ether1" in line

    def test_own_comment_overrides_name_default(self) -> None:
        (line,) = render_firewall_rule(_make_firewall_rule(comment="custom note"))
        assert 'comment="custom note (priority=10)"' in line


class TestRenderWireGuardPeerExternallyManagedKeyGuard:
    """Module 009 Part 3 addition: ``render_wireguard_peer`` must skip the
    ``private-key=`` line for a peer whose key material is device-managed
    -- see that function's own docstring."""

    def test_platform_generated_peer_renders_private_key_line(self) -> None:
        server = _make_wireguard_server()
        peer = _make_wireguard_peer(server_id=server.id)
        lines = render_wireguard_peer(peer, server)
        assert any(line.startswith("/interface wireguard add") for line in lines)
        assert len(lines) == 3

    def test_externally_managed_peer_omits_private_key_line(self) -> None:
        server = _make_wireguard_server()
        peer = _make_wireguard_peer(
            server_id=server.id,
            private_key_encrypted=encrypt_secret(EXTERNALLY_MANAGED_KEY_SENTINEL),
        )
        lines = render_wireguard_peer(peer, server)
        assert not any(line.startswith("/interface wireguard add") for line in lines)
        assert not any("private-key=" in line for line in lines)
        # The address + hub peer entry still render -- no secret material
        # in either.
        assert len(lines) == 2
        assert any(line.startswith("/ip address add") for line in lines)
        assert any(line.startswith("/interface wireguard peers add") for line in lines)


class TestRenderBootstrapScript:
    def test_rejects_non_https_base_url(self) -> None:
        with pytest.raises(ValueError, match="https://"):
            render_bootstrap_script(
                location_code="HQ-001",
                provisioning_token="tok",
                api_base_url="http://api.cloudguest.example",
            )

    def test_renders_identity_keypair_enrollment_and_config_pull(self) -> None:
        lines = render_bootstrap_script(
            location_code="HQ-001",
            provisioning_token="one-time-token-abc",
            api_base_url="https://api.cloudguest.example",
        )
        script = "\n".join(lines)

        # Roughly 15 lines, not a full config dump -- see module docstring.
        assert len(lines) <= 15

        assert '/system identity set name="HQ-001"' in lines
        assert any(
            line.startswith("/interface wireguard add name=wg-cloudguard")
            for line in lines
        )
        # The device's own public key is read locally, never a
        # platform-generated one.
        assert ":local pub [/interface wireguard get" in script
        # The provisioning token is embedded, the private key never is.
        assert "one-time-token-abc" in script
        assert "private-key" not in script
        # Enrollment POST hits the real check-in endpoint over HTTPS.
        assert (
            "https://api.cloudguest.example/api/v1/routers/provisioning/check-in"
            in script
        )
        assert "http-method=post" in script
        # Idempotent remove-then-add, comment-tagged.
        assert '/ip address remove [find comment="CGBOOT"]' in lines
        assert '/interface wireguard peers remove [find comment="CGBOOT"]' in lines
        assert script.count('comment="CGBOOT"') >= 2
        # Full config pull over HTTPS + import -- the real config-pull
        # endpoint, not an invented one.
        assert "https://api.cloudguest.example/api/v1/agent/config" in script
        assert "/import file-name=cloudguest.rsc" in lines

    def test_default_wireguard_port_used_unless_overridden(self) -> None:
        lines = render_bootstrap_script(
            location_code="HQ-001",
            provisioning_token="tok",
            api_base_url="https://api.cloudguest.example",
        )
        assert any("listen-port=51820" in line for line in lines)

        lines = render_bootstrap_script(
            location_code="HQ-001",
            provisioning_token="tok",
            api_base_url="https://api.cloudguest.example",
            wireguard_listen_port=13231,
        )
        assert any("listen-port=13231" in line for line in lines)


class TestRenderAgentHeartbeatScheduler:
    def test_rejects_non_https_base_url(self) -> None:
        with pytest.raises(ValueError, match="https://"):
            render_agent_heartbeat_scheduler("cred123", "http://api.cloudguest.example")

    def test_renders_idempotent_scheduler_calling_real_heartbeat_endpoint(
        self,
    ) -> None:
        lines = render_agent_heartbeat_scheduler(
            "cred123", "https://api.cloudguest.example", interval="5m"
        )
        script = "\n".join(lines)
        assert '/system scheduler remove [find comment="CGBOOT-hb"]' in lines
        assert any(line.startswith("/system scheduler add") for line in lines)
        assert "interval=5m" in script
        assert "https://api.cloudguest.example/api/v1/agent/heartbeat" in script
        assert "X-Agent-Credential: cred123" in script
        assert 'comment="CGBOOT-hb"' in script


class TestRenderNetworkConfig:
    def test_combines_all_seven_categories_with_section_headers(self) -> None:
        rendered = render_network_config(
            dhcp_pools=[_make_pool()],
            vlans=[_make_vlan()],
            port_forwarding_rules=[_make_rule()],
            hotspot_profiles=[_make_hotspot_profile()],
            qos_traffic_rules=[_make_qos_rule()],
            dns_records=[_make_dns_record()],
            firewall_rules=[_make_firewall_rule()],
        )
        assert DHCP_SECTION_HEADER in rendered
        assert VLAN_SECTION_HEADER in rendered
        assert PORT_FORWARDING_SECTION_HEADER in rendered
        assert HOTSPOT_SECTION_HEADER in rendered
        assert QOS_SECTION_HEADER in rendered
        assert DNS_SECTION_HEADER in rendered
        assert FIREWALL_SECTION_HEADER in rendered

    def test_returns_empty_string_for_no_input(self) -> None:
        assert (
            render_network_config(
                dhcp_pools=[],
                vlans=[],
                port_forwarding_rules=[],
                hotspot_profiles=[],
                qos_traffic_rules=[],
                dns_records=[],
                firewall_rules=[],
            )
            == ""
        )

    def test_omits_a_section_header_for_an_empty_category(self) -> None:
        rendered = render_network_config(
            dhcp_pools=[_make_pool()],
            vlans=[],
            port_forwarding_rules=[],
            hotspot_profiles=[],
            qos_traffic_rules=[],
            dns_records=[],
            firewall_rules=[],
        )
        assert DHCP_SECTION_HEADER in rendered
        assert VLAN_SECTION_HEADER not in rendered
        assert PORT_FORWARDING_SECTION_HEADER not in rendered
        assert HOTSPOT_SECTION_HEADER not in rendered
        assert QOS_SECTION_HEADER not in rendered
        assert DNS_SECTION_HEADER not in rendered
        assert FIREWALL_SECTION_HEADER not in rendered


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
class FakeHotspotLookup:
    profiles: list[HotspotProfile] = field(default_factory=list)

    async def list_profiles_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[HotspotProfile]:
        return [p for p in self.profiles if p.router_id == router_id]


@dataclass
class FakeQosLookup:
    rules: list[QosTrafficRule] = field(default_factory=list)

    async def list_rules_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[QosTrafficRule]:
        return [r for r in self.rules if r.router_id == router_id]


@dataclass
class FakeDnsLookup:
    records: list[DnsRecord] = field(default_factory=list)

    async def list_records_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[DnsRecord]:
        return [r for r in self.records if r.router_id == router_id]


@dataclass
class FakeFirewallLookup:
    rules: list[FirewallRule] = field(default_factory=list)

    async def list_rules_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[FirewallRule]:
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
    hotspot_profiles: list[HotspotProfile] | None = None,
    qos_traffic_rules: list[QosTrafficRule] | None = None,
    dns_records: list[DnsRecord] | None = None,
    firewall_rules: list[FirewallRule] | None = None,
) -> tuple[NetworkConfigService, FakeRouterProvisioningLookup]:
    provisioning_lookup = FakeRouterProvisioningLookup()
    service = NetworkConfigService(
        FakeDhcpLookup(pools or []),
        FakeVlanLookup(vlans or []),
        FakePortForwardingLookup(rules or []),
        FakeHotspotLookup(hotspot_profiles or []),
        FakeQosLookup(qos_traffic_rules or []),
        provisioning_lookup,
        dns_lookup=FakeDnsLookup(dns_records or []),
        firewall_lookup=FakeFirewallLookup(firewall_rules or []),
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
            hotspot_profiles=[_make_hotspot_profile(router_id=router_id)],
            qos_traffic_rules=[_make_qos_rule(router_id=router_id)],
            dns_records=[_make_dns_record(router_id=router_id)],
            firewall_rules=[_make_firewall_rule(router_id=router_id)],
        )
        preview = await service.preview_config(
            router_id, requesting_organization_id=uuid.uuid4()
        )
        assert preview.dhcp_pool_count == 1
        assert preview.vlan_count == 1
        assert preview.port_forwarding_rule_count == 1
        assert preview.hotspot_profile_count == 1
        assert preview.qos_traffic_rule_count == 1
        assert preview.dns_record_count == 1
        assert preview.firewall_rule_count == 1
        assert DHCP_SECTION_HEADER in preview.rendered_content
        assert HOTSPOT_SECTION_HEADER in preview.rendered_content
        assert QOS_SECTION_HEADER in preview.rendered_content
        assert DNS_SECTION_HEADER in preview.rendered_content
        assert FIREWALL_SECTION_HEADER in preview.rendered_content

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
