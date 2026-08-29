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

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.domains.content_filtering.constants import ContentFilterValueType
from app.domains.content_filtering.models import ContentFilterRule
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
from app.domains.isp.constants import IspConnectionMode
from app.domains.isp.models import IspLink
from app.domains.network_config.constants import (
    CONTENT_FILTER_SECTION_HEADER,
    DHCP_SECTION_HEADER,
    DNS_SECTION_HEADER,
    FIREWALL_SECTION_HEADER,
    HOTSPOT_SECTION_HEADER,
    NETWATCH_SECTION_HEADER,
    PORT_FORWARDING_SECTION_HEADER,
    QOS_SECTION_HEADER,
    REMOTE_BOOTSTRAP_CONFIRM_ATTEMPTS,
    REMOTE_BOOTSTRAP_CONFIRM_DELAY_SECONDS,
    REMOTE_BOOTSTRAP_CUTOVER_DELAY_SECONDS,
    REMOTE_BOOTSTRAP_REVERT_WINDOW_MINUTES,
    VLAN_SECTION_HEADER,
    BootstrapMode,
)
from app.domains.network_config.exceptions import (
    EmptyNetworkConfigError,
    NetwatchIntegrationUnavailableError,
    NoNetwatchTargetsError,
)
from app.domains.network_config.renderers import (
    HOTSPOT_DNS_NAME,
    MANAGED_WALLED_GARDEN_COMMENT,
    render_agent_heartbeat_scheduler,
    render_bootstrap_script,
    render_content_filter_enforcement,
    render_content_filter_rule,
    render_dhcp_pool,
    render_dns_record,
    render_firewall_rule,
    render_guest_data_path,
    render_guest_data_path_verification,
    render_hotspot_profile,
    render_hotspot_walled_garden,
    render_isp_netwatch_config,
    render_isp_netwatch_entry,
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
from app.domains.router.models import Router
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


def _make_content_filter_rule(**overrides: object) -> ContentFilterRule:
    fields = {
        "router_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "name": "Block Facebook",
        "category": "social_media",
        "value_type": ContentFilterValueType.DOMAIN.value,
        "value": "facebook.com",
        "comment": None,
        "is_enabled": True,
    }
    fields.update(overrides)
    return ContentFilterRule(**_base_fields(**fields))


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


def _make_isp_link(**overrides: object) -> IspLink:
    fields = {
        "router_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "provider_name": "Airtel",
        "link_type": "fiber",
        "connection_mode": IspConnectionMode.STATIC.value,
        "role": "primary",
        "is_active_uplink": True,
        "auto_failback": True,
        "is_enabled": True,
        "priority": 0,
        "interface": "ether1",
        "gateway_ip_address": "203.0.113.1",
        "dns_primary": None,
        "dns_secondary": None,
        "download_bandwidth_mbps": None,
        "upload_bandwidth_mbps": None,
        "health_status": "unknown",
        "health_status_source": "automated",
        "latency_ms": None,
        "packet_loss_percentage": None,
        "last_checked_at": None,
        "consecutive_unhealthy_count": 0,
    }
    fields.update(overrides)
    return IspLink(**_base_fields(**fields))


def _make_router(**overrides: object) -> Router:
    fields = {
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "name": "Front Desk AP",
        "serial_number": f"SN-{uuid.uuid4().hex[:8]}",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "model": "hAP ac2",
        "vendor": "mikrotik",
        "routeros_version": None,
        "management_ip_address": "10.0.0.1",
        "public_ip_address": None,
        "status": "online",
        "last_seen_at": None,
        "last_health_check_at": None,
        "health_status": None,
        "api_username": "admin",
        "api_credentials_encrypted": "encrypted-placeholder",
        "settings": {},
    }
    fields.update(overrides)
    return Router(**_base_fields(**fields))


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


class TestRenderVlanHotspot:
    """``render_vlan(..., enable_hotspot=True)`` -- see renderers.py module
    docstring's "Hotspot dns-name" section for why both a ``dns-name`` on
    the hotspot profile and a matching ``/ip dns static`` record are
    rendered together, and why the name is per-VLAN rather than one fixed
    global literal."""

    def test_renders_dns_name_and_matching_static_dns_record(self) -> None:
        vlan = _make_vlan(vlan_id=100, enable_hotspot=True)
        lines = render_vlan(vlan)
        joined = "\n".join(lines)
        assert f"dns-name=vlan100.{HOTSPOT_DNS_NAME}" in joined
        assert (
            f"/ip dns static add name=vlan100.{HOTSPOT_DNS_NAME} "
            "address=10.0.100.1" in joined
        )
        assert "/ip hotspot profile add" in joined
        assert "/ip hotspot add name=vlan100-hotspot" in joined

    def test_two_hotspot_vlans_get_distinct_dns_names(self) -> None:
        vlan_a = _make_vlan(vlan_id=100, enable_hotspot=True)
        vlan_b = _make_vlan(
            vlan_id=200,
            enable_hotspot=True,
            gateway_ip_address="10.0.200.1",
            cidr="10.0.200.0/24",
        )
        joined_a = "\n".join(render_vlan(vlan_a))
        joined_b = "\n".join(render_vlan(vlan_b))
        assert f"vlan100.{HOTSPOT_DNS_NAME}" in joined_a
        assert f"vlan200.{HOTSPOT_DNS_NAME}" in joined_b
        assert f"vlan200.{HOTSPOT_DNS_NAME}" not in joined_a

    def test_skips_entirely_without_cidr_or_gateway(self) -> None:
        vlan = _make_vlan(enable_hotspot=True, cidr=None, gateway_ip_address=None)
        lines = render_vlan(vlan)
        joined = "\n".join(lines)
        assert "dns-name" not in joined
        assert "needs both cidr and gateway_ip_address" in joined

    def test_disabled_by_default(self) -> None:
        lines = render_vlan(_make_vlan())
        joined = "\n".join(lines)
        assert "/ip hotspot profile add" not in joined
        assert "dns-name" not in joined


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


class TestRenderContentFilterRule:
    def test_domain_rule_renders_exact_and_subdomain_sinkhole_entries(self) -> None:
        lines = render_content_filter_rule(_make_content_filter_rule())
        assert len(lines) == 2
        assert "/ip dns static add name=facebook.com type=A" in lines[0]
        assert "address=127.0.0.1" in lines[0]
        assert 'comment="social_media: Block Facebook"' in lines[0]
        assert 'regexp="^.*\\.facebook\\.com$"' in lines[1]
        assert "address=127.0.0.1" in lines[1]
        assert "(subdomains)" in lines[1]

    def test_ip_cidr_rule_renders_only_address_list_membership(self) -> None:
        (line,) = render_content_filter_rule(
            _make_content_filter_rule(
                name="Block Bad Range",
                category="gambling",
                value_type=ContentFilterValueType.IP_CIDR.value,
                value="203.0.113.0/24",
            )
        )
        assert "/ip firewall address-list add" in line
        assert "list=wyfyguest-content-filter-blocked" in line
        assert "address=203.0.113.0/24" in line
        assert 'comment="gambling: Block Bad Range"' in line
        assert "/ip firewall filter" not in line

    def test_defaults_category_label_to_custom_when_unset(self) -> None:
        (line, _regexp_line) = render_content_filter_rule(
            _make_content_filter_rule(category=None)
        )
        assert 'comment="custom: Block Facebook"' in line


class TestRenderContentFilterEnforcement:
    def test_renders_one_shared_drop_rule_matching_the_address_list(self) -> None:
        (line,) = render_content_filter_enforcement()
        assert "/ip firewall filter add chain=forward" in line
        assert "dst-address-list=wyfyguest-content-filter-blocked" in line
        assert "action=drop" in line


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

    # The six check-in response fields the rendered script must refuse to
    # proceed without -- mirrors renderers._CHECK_IN_REQUIRED_FIELDS, spelled
    # out here so a renderer-side edit to that tuple breaks this test loudly.
    CHECK_IN_FIELDS = (
        "agent_credential",
        "tunnel_ip_address",
        "wireguard_server_public_key",
        "wireguard_endpoint_host",
        "wireguard_endpoint_port",
        "wireguard_hub_tunnel_address",
    )

    @staticmethod
    def _render() -> list[str]:
        return render_bootstrap_script(
            location_code="LOC-2026-000039",
            provisioning_token="one-time-token-abc",
            api_base_url="https://api.cloudguest.example",
        )

    def test_renders_identity_enrollment_and_key_pull(self) -> None:
        lines = self._render()
        script = "\n".join(lines)

        # Still a thin paste, not a config dump -- see module docstring.
        # Raised 30 -> 36 on 2026-08-27 for the clock/NTP block (5 lines):
        # set time-zone, enable NTP, and a bounded sync wait that `:error`s
        # if the clock never syncs. Not optional padding -- every platform
        # call in this script is HTTPS, and TLS validation fails closed
        # against the wrong date a battery-less MikroTik boots with, which
        # is what leaves a router serving guests while showing OFFLINE
        # forever. The cap exists to stop this becoming a config dump, not
        # to stop it being correct.
        #
        # Raised 36 -> 38 on 2026-08-29 for the captive-portal walled
        # garden (2 lines, one per platform host). Same character as the
        # clock block above: not padding, but the thing without which the
        # feature it serves cannot work at all. Production had *zero*
        # `hotspot_profiles` rows fleet-wide, so the only path that ever
        # rendered a walled-garden entry never ran, and a guest redirected
        # to the portal's real hostname would be intercepted before
        # reaching it. Held to one line per host deliberately -- the
        # renderer inlines its `find` instead of binding a `:local` per
        # host, which would have cost 4 lines for the same behaviour.
        assert len(lines) <= 38

        assert lines[0] == '/system identity set name="LOC-2026-000039"'
        # The provisioning token is embedded (the one deliberate, one-time,
        # short-TTL secret); the private key is fetched at run time from
        # the real device-facing endpoint, never read from a local keypair.
        assert "one-time-token-abc" in script
        assert ":local pub" not in script
        assert (
            "https://api.cloudguest.example/api/v1/routers/provisioning/check-in"
            in script
        )
        assert "http-method=post" in script
        assert (
            "https://api.cloudguest.example/api/v1/agent/wireguard-config" in script
        )
        assert '"X-Agent-Credential: " . ($enroll->"agent_credential")' in script
        # The interface is created from the platform-delivered key, tagged
        # like everything else this script creates.
        add_line = next(
            line
            for line in lines
            if line.startswith("/interface wireguard add name=wg-cloudguard")
        )
        assert 'private-key=($wgcfg->"peer_private_key")' in add_line
        assert 'comment="CGBOOT"' in add_line
        # The old fetch-and-import handoff is gone from Step 1.
        assert "/import" not in script
        assert "cloudguest.rsc" not in script

    def test_cleanup_is_comment_based_ordered_and_before_check_in(self) -> None:
        lines = self._render()

        ip_remove = lines.index('/ip address remove [find where comment="CGBOOT"]')
        peers_remove = lines.index(
            '/interface wireguard peers remove [find where comment="CGBOOT"]'
        )
        iface_remove = lines.index(
            '/interface wireguard remove [find where name="wg-cloudguard"]'
        )
        check_in = next(
            i
            for i, line in enumerate(lines)
            if "/routers/provisioning/check-in" in line
        )
        # Address first (an orphaned row on a deleted interface is only
        # findable by comment), then peers, then the interface itself --
        # and all of it before any network call.
        assert ip_remove < peers_remove < iface_remove < check_in
        # Removal is NEVER keyed by interface name for /ip address or peers:
        # a deleted interface leaves rows pointing at an internal id (*10)
        # an interface-name match cannot see.
        assert "interface=" not in lines[ip_remove]
        assert "interface=" not in lines[peers_remove]

    def test_check_in_fields_are_each_presence_checked(self) -> None:
        lines = self._render()
        script = "\n".join(lines)
        deserialize = lines.index(
            ':local enroll [:deserialize from=json value=($resp->"data")]'
        )
        wg_fetch = next(
            i for i, line in enumerate(lines) if "wireguard-config" in line
        )
        for field_name in self.CHECK_IN_FIELDS:
            check = next(
                i
                for i, line in enumerate(lines)
                if f"check-in response missing {field_name}" in line
            )
            assert deserialize < check < wg_fetch
            assert f'[:typeof ($enroll->"{field_name}")]' in lines[check]
        # An HTTP-failure guard precedes the deserialize.
        assert ':if (($resp->"http-code") != "200")' in script
        assert "on-error={" in lines[deserialize - 2]

    def test_private_key_is_validated_before_use(self) -> None:
        lines = self._render()
        missing = next(
            i
            for i, line in enumerate(lines)
            if "wireguard-config response missing peer_private_key" in line
        )
        empty = next(
            i for i, line in enumerate(lines) if "empty peer_private_key" in line
        )
        add = next(
            i
            for i, line in enumerate(lines)
            if line.startswith("/interface wireguard add")
        )
        assert missing < add
        assert empty < add
        assert '[:len ($wgcfg->"peer_private_key")] = 0' in lines[empty]

    def test_verification_asserts_attachment_not_mere_existence(self) -> None:
        lines = self._render()
        peer_add = next(
            i
            for i, line in enumerate(lines)
            if line.startswith("/interface wireguard peers add")
        )
        iface_check = next(
            i
            for i, line in enumerate(lines)
            if "verification failed: interface wg-cloudguard does not exist" in line
        )
        addr_check = next(
            i
            for i, line in enumerate(lines)
            if "verification failed: tunnel address is not attached" in line
        )
        peer_check = next(
            i
            for i, line in enumerate(lines)
            if "verification failed: hub peer is missing" in line
        )
        # All verification runs after every create.
        assert peer_add < iface_check < addr_check < peer_check
        # The address check requires the address ON wg-cloudguard, not
        # anywhere -- the exact regression the orphaned interface=*10 row
        # produced in production.
        assert (
            '/ip address find where interface="wg-cloudguard" && address=$tunaddr'
            in lines[addr_check]
        )
        # The success line is gated on the same three re-queries (console
        # pastes execute line by line, so an unconditional final :put could
        # otherwise fire after an earlier :error).
        success = lines[-1]
        assert "CloudGuest bootstrap successful" in success
        assert success.startswith(":if (")
        for fragment in (
            '/interface wireguard find where name="wg-cloudguard"',
            '/ip address find where interface="wg-cloudguard" && address=$tunaddr',
            '/interface wireguard peers find where interface="wg-cloudguard"',
        ):
            assert fragment in success

    def test_no_literal_ips_keys_or_comment_lines(self) -> None:
        lines = self._render()
        script = "\n".join(lines)
        # Nothing hardcoded: no IP literals, no key material -- every
        # device-specific value dereferences the JSON the platform returned.
        # NARROWED 2026-08-27, deliberately and narrowly. The invariant
        # here is "no PLATFORM/DEVICE-specific address is ever baked into a
        # script" -- the rule whose violation put the old hub's literal
        # 20.219.72.235 onto 64 field routers and stranded every one when
        # that host was deleted.
        #
        # The two public NTP anycast addresses are categorically outside
        # it: not device-specific, not Wyfy infrastructure, global
        # constants owned by Google and Cloudflare that nothing this
        # platform does can move. They are deliberately literals rather
        # than hostnames -- "internet fine, DNS broken" is a confirmed live
        # state on this hardware, and an NTP server that cannot be resolved
        # is one that never syncs, which is the exact failure the clock
        # block exists to prevent.
        #
        # Allow-listed by exact value, not by pattern, so this still fails
        # on any OTHER literal -- a hub address included.
        # WIDENED 2026-08-28, on the same "categorically outside the rule"
        # test: 0.0.0.0 appears only as `dst-address="0.0.0.0/0"`, the
        # default-route selector `render_guest_data_path` uses to ask the
        # device which interface is actually carrying the internet. It is
        # not an address of anything -- it is the literal opposite of
        # baking in an address, since it is how the script discovers the
        # uplink instead of being told one. Still allow-listed by exact
        # value, so a real hub address would still fail this.
        allowed_literals = {"216.239.35.0", "162.159.200.1", "0.0.0.0"}
        found = set(
            re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", script)
        )
        assert not (found - allowed_literals), (
            f"unexpected IP literal(s): {found - allowed_literals}"
        )
        for needle in ("tunnel_ip_address", "wireguard_server_public_key"):
            for line in lines:
                if needle in line and "missing" not in line:
                    assert f'($enroll->"{needle}")' in line
        assert 'private-key=($wgcfg->"peer_private_key")' in script
        # No '#' comment lines: the dashboard's single-line ';'-joined copy
        # export would silently swallow every command after one.
        assert not any(line.lstrip().startswith("#") for line in lines)

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


class TestRenderRemoteBootstrapScript:
    """Remote mode: validate-first, scheduler-staged cutover with a timed
    revert -- the two hard properties under test are (a) nothing is ever
    torn down before every replacement value validated, and (b) no teardown
    executes in the delivering session at all (it is all staged into
    detached ``/system scheduler`` jobs)."""

    @staticmethod
    def _render() -> list[str]:
        return render_bootstrap_script(
            location_code="LOC-2026-000039",
            provisioning_token="one-time-token-abc",
            api_base_url="https://api.cloudguest.example",
            mode=BootstrapMode.REMOTE,
        )

    @staticmethod
    def _onsite() -> list[str]:
        return render_bootstrap_script(
            location_code="LOC-2026-000039",
            provisioning_token="one-time-token-abc",
            api_base_url="https://api.cloudguest.example",
        )

    def _cut_line(self) -> str:
        return next(
            line for line in self._render() if line.startswith(":local cut ")
        )

    def _rvt_line(self) -> str:
        return next(
            line for line in self._render() if line.startswith(":local rvt ")
        )

    def test_rejects_non_https_base_url(self) -> None:
        with pytest.raises(ValueError, match="https://"):
            render_bootstrap_script(
                location_code="HQ-001",
                provisioning_token="tok",
                api_base_url="http://api.cloudguest.example",
                mode=BootstrapMode.REMOTE,
            )

    def test_default_mode_is_onsite(self) -> None:
        default = render_bootstrap_script(
            location_code="LOC-2026-000039",
            provisioning_token="one-time-token-abc",
            api_base_url="https://api.cloudguest.example",
        )
        explicit = render_bootstrap_script(
            location_code="LOC-2026-000039",
            provisioning_token="one-time-token-abc",
            api_base_url="https://api.cloudguest.example",
            mode=BootstrapMode.ONSITE,
        )
        assert default == explicit

    def test_the_two_orders_are_actually_different(self) -> None:
        onsite = self._onsite()
        remote = self._render()
        assert onsite != remote

        # On-site: teardown BEFORE the first network call (cleanup-first).
        onsite_iface_remove = onsite.index(
            '/interface wireguard remove [find where name="wg-cloudguard"]'
        )
        onsite_check_in = next(
            i for i, line in enumerate(onsite) if "provisioning/check-in" in line
        )
        assert onsite_iface_remove < onsite_check_in

        # Remote: the same teardown command NEVER executes in-session -- no
        # top-level line removes the interface, its addresses, or its
        # peers. (The teardown text exists only inside the two staged
        # scheduler strings.)
        for line in remote:
            assert not line.startswith("/interface wireguard remove")
            assert not line.startswith("/interface wireguard peers remove")
            assert not line.startswith("/ip address remove")

    def test_shared_enrollment_block_is_identical_across_modes(self) -> None:
        onsite = self._onsite()
        remote = self._render()

        def block(lines: list[str]) -> list[str]:
            start = next(
                i for i, line in enumerate(lines) if line.startswith(":local body")
            )
            end = next(
                i
                for i, line in enumerate(lines)
                if "empty peer_private_key" in line
            )
            return lines[start : end + 1]

        assert block(onsite) == block(remote)

    def test_guards_and_capture_precede_check_in_and_spend_no_token(self) -> None:
        remote = self._render()
        check_in = next(
            i for i, line in enumerate(remote) if "provisioning/check-in" in line
        )
        # All three refuse-unless-intact guards direct to the on-site
        # script and run before the one-time token is ever spent.
        guard_indexes = [
            i
            for i, line in enumerate(remote)
            if "use the on-site script instead" in line
        ]
        assert len(guard_indexes) == 3
        assert all(i < check_in for i in guard_indexes)
        # Every captured revert value is read before check-in too, so a
        # capture failure can never burn the token either.
        for capture in (
            ":local oldkey ",
            ":local oldport ",
            ":local oldaddr ",
            ":local oldpub ",
            ":local oldephost ",
            ":local oldepport ",
            ":local oldallowed ",
            ":local oldka ",
        ):
            index = next(
                i for i, line in enumerate(remote) if line.startswith(capture)
            )
            assert index < check_in

    def test_no_removal_before_successful_validation(self) -> None:
        """Hard property (a): a stale token, unreachable platform, or
        missing/empty field must fail with the live tunnel untouched --
        so no line up to and including the last validation line may
        remove anything."""
        remote = self._render()
        last_validation = next(
            i for i, line in enumerate(remote) if "empty peer_private_key" in line
        )
        for line in remote[: last_validation + 1]:
            assert " remove " not in line
        # The staged-script builders and every scheduler mutation come
        # strictly after validation.
        for prefix in (":local cut ", ":local rvt ", "/system scheduler"):
            index = next(
                i for i, line in enumerate(remote) if line.startswith(prefix)
            )
            assert index > last_validation

    def test_revert_is_armed_before_cutover_is_staged(self) -> None:
        remote = self._render()
        revert_add = next(
            i
            for i, line in enumerate(remote)
            if line.startswith("/system scheduler add name=cloudguest-bootstrap-revert")
        )
        cutover_add = next(
            i
            for i, line in enumerate(remote)
            if line.startswith(
                "/system scheduler add name=cloudguest-bootstrap-cutover"
            )
        )
        assert revert_add < cutover_add
        assert (
            f"interval={REMOTE_BOOTSTRAP_REVERT_WINDOW_MINUTES}m"
            in remote[revert_add]
        )
        assert 'comment="CGBOOT-revert"' in remote[revert_add]
        assert "on-event=$rvt" in remote[revert_add]
        assert (
            f"interval={REMOTE_BOOTSTRAP_CUTOVER_DELAY_SECONDS}s"
            in remote[cutover_add]
        )
        assert 'comment="CGBOOT-cutover"' in remote[cutover_add]
        assert "on-event=$cut" in remote[cutover_add]
        # Stale entries from a previous failed attempt are cleared first.
        stale_removes = [
            i
            for i, line in enumerate(remote)
            if line.startswith("/system scheduler remove")
        ]
        assert len(stale_removes) == 2
        assert all(i < revert_add for i in stale_removes)

    def test_cutover_script_construction(self) -> None:
        cut = self._cut_line()
        # Run-once: self-removal is the very first staged command, and the
        # cutover aborts if the revert window has already closed.
        self_remove = cut.index(
            '/system scheduler remove [find where comment=\\"CGBOOT-cutover\\"]'
        )
        revert_guard = cut.index("revert window closed")
        first_teardown = cut.index('/ip address remove')
        assert self_remove < revert_guard < first_teardown
        # Teardown is a superset of on-site\'s: by CGBOOT comment (orphaned
        # rows) AND by interface (live rows predating the tag).
        for fragment in (
            '/ip address remove [find where comment=\\"CGBOOT\\"]',
            '/ip address remove [find where interface=\\"wg-cloudguard\\"]',
            '/interface wireguard peers remove [find where comment=\\"CGBOOT\\"]',
            '/interface wireguard peers remove '
            '[find where interface=\\"wg-cloudguard\\"]',
            '/interface wireguard remove [find where name=\\"wg-cloudguard\\"]',
        ):
            assert fragment in cut
        # The replacement is built from the validated staged values --
        # runtime concatenation splices, never literals.
        for splice in (
            'private-key=\\"" . ($wgcfg->"peer_private_key") . "\\"',
            'address=\\"" . $tunaddr . "\\"',
            'public-key=\\"" . ($enroll->"wireguard_server_public_key") . "\\"',
            'endpoint-address=\\"" . ($enroll->"wireguard_endpoint_host") . "\\"',
            'endpoint-port=" . ($enroll->"wireguard_endpoint_port") . "',
            'allowed-address=\\"" . ($enroll->"wireguard_hub_tunnel_address")'
            ' . "/32\\"',
        ):
            assert splice in cut
        # Create -> verify -> confirm ordering inside the staged script.
        create = cut.index("/interface wireguard add name=wg-cloudguard")
        verify_addr = cut.index("tunnel address is not attached")
        ping = cut.index(":set ok [/ping")
        assert create < verify_addr < ping

    def test_cutover_confirms_end_to_end_before_disarming_revert(self) -> None:
        cut = self._cut_line()
        # Confirmation is a real round-trip to the hub over the new
        # tunnel, polled within the revert window -- local existence never
        # disarms the revert.
        assert (
            f"\\$tries < {REMOTE_BOOTSTRAP_CONFIRM_ATTEMPTS}" in cut
        )
        assert f":delay {REMOTE_BOOTSTRAP_CONFIRM_DELAY_SECONDS}s" in cut
        assert (
            ':set ok [/ping \\"" . ($enroll->"wireguard_hub_tunnel_address") . "\\"'
            " count=2]" in cut
        )
        success = cut.index(
            ':if (\\$ok > 0) do={ /system scheduler remove '
            '[find where comment=\\"CGBOOT-revert\\"]'
        )
        assert success > cut.index(":set ok [/ping")
        assert "automatic revert stays armed" in cut
        # Poll budget stays well inside the revert window.
        poll_seconds = (
            REMOTE_BOOTSTRAP_CONFIRM_ATTEMPTS
            * REMOTE_BOOTSTRAP_CONFIRM_DELAY_SECONDS
        )
        assert (
            REMOTE_BOOTSTRAP_CUTOVER_DELAY_SECONDS + poll_seconds
            < (REMOTE_BOOTSTRAP_REVERT_WINDOW_MINUTES * 60) // 2
        )

    def test_revert_script_construction(self) -> None:
        rvt = self._rvt_line()
        # NO self-removal up front: a failed revert stays scheduled and
        # retries; it disarms only after the restored state re-verifies.
        restore = rvt.index("/interface wireguard add name=wg-cloudguard")
        disarm_cutover = rvt.index(
            '/system scheduler remove [find where comment=\\"CGBOOT-cutover\\"]'
        )
        disarm_self = rvt.index(
            '/system scheduler remove [find where comment=\\"CGBOOT-revert\\"]'
        )
        verify = rvt.index("previous tunnel address is not attached")
        assert restore < verify < disarm_cutover < disarm_self
        # Every captured value is restored -- the previous tunnel comes
        # back exactly as it was.
        for splice in (
            'private-key=\\"" . $oldkey . "\\"',
            'listen-port=" . $oldport . "',
            'address=\\"" . $oldaddr . "\\"',
            'public-key=\\"" . $oldpub . "\\"',
            'endpoint-address=\\"" . $oldephost . "\\"',
            'endpoint-port=" . $oldepport . "',
            'allowed-address=\\"" . $oldallowed . "\\"',
            'persistent-keepalive=" . $oldka . "',
        ):
            assert splice in rvt
        assert "previous tunnel configuration restored" in rvt

    def test_staged_message_is_gated_on_both_schedulers(self) -> None:
        remote = self._render()
        final = remote[-1]
        assert final.startswith(":if (")
        assert '/system scheduler find where comment="CGBOOT-cutover"' in final
        assert '/system scheduler find where comment="CGBOOT-revert"' in final
        assert "CloudGuest remote bootstrap staged" in final
        assert f"~{REMOTE_BOOTSTRAP_CUTOVER_DELAY_SECONDS}s" in final
        assert f"{REMOTE_BOOTSTRAP_REVERT_WINDOW_MINUTES}m" in final

    def test_no_literals_comment_lines_or_newlines(self) -> None:
        remote = self._render()
        script = "\n".join(remote)
        # Same narrow allow-list as TestRenderBootstrapScript's copy of
        # this invariant -- see the long note there.
        # WIDENED 2026-08-28, on the same "categorically outside the rule"
        # test: 0.0.0.0 appears only as `dst-address="0.0.0.0/0"`, the
        # default-route selector `render_guest_data_path` uses to ask the
        # device which interface is actually carrying the internet. It is
        # not an address of anything -- it is the literal opposite of
        # baking in an address, since it is how the script discovers the
        # uplink instead of being told one. Still allow-listed by exact
        # value, so a real hub address would still fail this.
        allowed_literals = {"216.239.35.0", "162.159.200.1", "0.0.0.0"}
        found = set(
            re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", script)
        )
        assert not (found - allowed_literals), (
            f"unexpected IP literal(s): {found - allowed_literals}"
        )
        assert not any(line.lstrip().startswith("#") for line in remote)
        assert not any("\n" in line for line in remote)
        assert "one-time-token-abc" in script
        assert remote[0] == '/system identity set name="LOC-2026-000039"'
        # Staged-script variables are escaped for storage (\\$) so they
        # execute at cutover/revert time, not at staging time.
        cut = self._cut_line()
        assert "\\$ok" in cut and "\\$tries" in cut


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


class TestRenderIspNetwatchEntry:
    def test_rejects_non_https_base_url(self) -> None:
        with pytest.raises(ValueError, match="https://"):
            render_isp_netwatch_entry(
                _make_isp_link(),
                api_base_url="http://api.cloudguest.example",
                agent_credential="cred123",
            )

    def test_renders_a_real_netwatch_entry_for_a_static_link(self) -> None:
        link = _make_isp_link(gateway_ip_address="203.0.113.1")
        lines = render_isp_netwatch_entry(
            link,
            api_base_url="https://api.cloudguest.example",
            agent_credential="cred123",
        )
        script = "\n".join(lines)
        tag = f"isp-netwatch-{link.id}"
        # Explicit remove-then-add, not wrapped by :do {} on-error={} --
        # see the renderer's own docstring for why.
        assert f'/tool netwatch remove [find comment="{tag}"]' in lines
        assert any(line.startswith("/tool netwatch add") for line in lines)
        assert "host=203.0.113.1" in script
        assert f'comment="{tag}"' in script
        # Both scripts hit the real, already-mounted callback endpoint,
        # authenticated with the real supplied credential, carrying this
        # link's own real id and the up/down status as a render-time
        # literal JSON payload.
        assert "https://api.cloudguest.example/api/v1/agent/netwatch-event" in script
        assert "X-Agent-Credential: cred123" in script
        assert f'\\"isp_link_id\\":\\"{link.id}\\"' in script
        assert '\\"status\\":\\"up\\"' in script
        assert '\\"status\\":\\"down\\"' in script
        assert "up-script={" in script
        assert "down-script={" in script

    def test_skips_dhcp_mode_link_with_explanatory_comment(self) -> None:
        link = _make_isp_link(
            connection_mode=IspConnectionMode.DHCP.value, gateway_ip_address=None
        )
        lines = render_isp_netwatch_entry(
            link,
            api_base_url="https://api.cloudguest.example",
            agent_credential="cred123",
        )
        joined = "\n".join(lines)
        assert "/tool netwatch add" not in joined
        assert "netwatch needs a STATIC-mode link" in joined

    def test_skips_pppoe_mode_link_with_explanatory_comment(self) -> None:
        link = _make_isp_link(
            connection_mode=IspConnectionMode.PPPOE.value, gateway_ip_address=None
        )
        lines = render_isp_netwatch_entry(
            link,
            api_base_url="https://api.cloudguest.example",
            agent_credential="cred123",
        )
        joined = "\n".join(lines)
        assert "/tool netwatch add" not in joined

    def test_skips_static_link_missing_a_gateway(self) -> None:
        link = _make_isp_link(
            connection_mode=IspConnectionMode.STATIC.value, gateway_ip_address=None
        )
        lines = render_isp_netwatch_entry(
            link,
            api_base_url="https://api.cloudguest.example",
            agent_credential="cred123",
        )
        joined = "\n".join(lines)
        assert "/tool netwatch add" not in joined

    def test_two_links_get_distinct_comment_tags(self) -> None:
        link_a = _make_isp_link()
        link_b = _make_isp_link()
        lines_a = render_isp_netwatch_entry(
            link_a, api_base_url="https://api.cloudguest.example", agent_credential="c"
        )
        lines_b = render_isp_netwatch_entry(
            link_b, api_base_url="https://api.cloudguest.example", agent_credential="c"
        )
        assert lines_a[0] != lines_b[0]


class TestRenderIspNetwatchConfig:
    def test_combines_multiple_links_under_one_section_header(self) -> None:
        links = [_make_isp_link(), _make_isp_link()]
        rendered = render_isp_netwatch_config(
            links,
            api_base_url="https://api.cloudguest.example",
            agent_credential="cred123",
        )
        assert rendered.count(NETWATCH_SECTION_HEADER) == 1
        assert rendered.count("/tool netwatch add") == 2

    def test_returns_empty_string_for_no_links(self) -> None:
        assert (
            render_isp_netwatch_config(
                [],
                api_base_url="https://api.cloudguest.example",
                agent_credential="cred123",
            )
            == ""
        )


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

    def test_includes_content_filter_section_for_domain_rules_only(self) -> None:
        rendered = render_network_config(
            dhcp_pools=[],
            vlans=[],
            port_forwarding_rules=[],
            content_filter_rules=[_make_content_filter_rule()],
        )
        assert CONTENT_FILTER_SECTION_HEADER in rendered
        assert "/ip dns static add name=facebook.com" in rendered
        # No IP/CIDR rule present -- the shared enforcement DROP rule
        # must not be rendered at all.
        assert "/ip firewall filter add chain=forward" not in rendered

    def test_includes_enforcement_rule_once_for_ip_cidr_rules(self) -> None:
        rendered = render_network_config(
            dhcp_pools=[],
            vlans=[],
            port_forwarding_rules=[],
            content_filter_rules=[
                _make_content_filter_rule(
                    name="Block A",
                    value_type=ContentFilterValueType.IP_CIDR.value,
                    value="203.0.113.0/24",
                ),
                _make_content_filter_rule(
                    name="Block B",
                    value_type=ContentFilterValueType.IP_CIDR.value,
                    value="198.51.100.0/24",
                ),
            ],
        )
        assert rendered.count("wyfyguest-content-filter-blocked") == 3
        assert rendered.count("dst-address-list=wyfyguest-content-filter-blocked") == 1
        assert rendered.count("action=drop") == 1
        assert rendered.count("/ip firewall filter add chain=forward") == 1

    def test_omits_content_filter_section_without_any_rules(self) -> None:
        rendered = render_network_config(
            dhcp_pools=[_make_pool()],
            vlans=[],
            port_forwarding_rules=[],
        )
        assert CONTENT_FILTER_SECTION_HEADER not in rendered


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
class FakeContentFilterLookup:
    rules: list[ContentFilterRule] = field(default_factory=list)

    async def list_rules_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[ContentFilterRule]:
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


@dataclass
class FakeIspLinkLookup:
    links: list[IspLink] = field(default_factory=list)

    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[IspLink], object]:
        links = [
            link
            for link in self.links
            if router_id is None or link.router_id == router_id
        ]
        return links, object()


@dataclass
class FakeAgentCredentialIssuer:
    issued_for: list[uuid.UUID] = field(default_factory=list)
    rotation_counts: dict[uuid.UUID, int] = field(default_factory=dict)

    async def issue_credential_for_router(self, router: Router) -> tuple[object, str]:
        self.issued_for.append(router.id)
        count = self.rotation_counts.get(router.id, 0) + 1
        self.rotation_counts[router.id] = count
        # A fresh, distinct plaintext every call -- mirrors the real
        # RouterAgentService.issue_credential_for_router's own rotate-in-
        # place behavior (a new plaintext every issuance, never repeated).
        return object(), f"plaintext-{router.id}-{count}"


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router:
        return self.routers[router_id]


def _make_service(
    *,
    pools: list[DhcpPool] | None = None,
    vlans: list[Vlan] | None = None,
    rules: list[PortForwardingRule] | None = None,
    hotspot_profiles: list[HotspotProfile] | None = None,
    qos_traffic_rules: list[QosTrafficRule] | None = None,
    dns_records: list[DnsRecord] | None = None,
    firewall_rules: list[FirewallRule] | None = None,
    content_filter_rules: list[ContentFilterRule] | None = None,
    isp_link_lookup: FakeIspLinkLookup | None = None,
    agent_credential_issuer: FakeAgentCredentialIssuer | None = None,
    router_lookup: FakeRouterLookup | None = None,
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
        content_filter_lookup=FakeContentFilterLookup(content_filter_rules or []),
        isp_link_lookup=isp_link_lookup,
        agent_credential_issuer=agent_credential_issuer,
        router_lookup=router_lookup,
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
        assert preview.content_filter_rule_count == 0

    async def test_includes_content_filter_rules_in_preview(self) -> None:
        router_id = uuid.uuid4()
        service, _ = _make_service(
            content_filter_rules=[_make_content_filter_rule(router_id=router_id)]
        )
        preview = await service.preview_config(
            router_id, requesting_organization_id=uuid.uuid4()
        )
        assert preview.content_filter_rule_count == 1
        assert CONTENT_FILTER_SECTION_HEADER in preview.rendered_content

    async def test_excludes_disabled_content_filter_rules(self) -> None:
        router_id = uuid.uuid4()
        service, _ = _make_service(
            content_filter_rules=[
                _make_content_filter_rule(router_id=router_id, is_enabled=True),
                _make_content_filter_rule(
                    router_id=router_id, value="other.com", is_enabled=False
                ),
            ]
        )
        preview = await service.preview_config(
            router_id, requesting_organization_id=uuid.uuid4()
        )
        assert preview.content_filter_rule_count == 1


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
# NetworkConfigService.push_isp_netwatch_config
# ============================================================================


_NetwatchServiceFixture = tuple[
    NetworkConfigService, FakeRouterProvisioningLookup, FakeAgentCredentialIssuer
]


def _make_netwatch_service(
    *, links: list[IspLink], router: Router
) -> _NetwatchServiceFixture:
    credential_issuer = FakeAgentCredentialIssuer()
    service, provisioning_lookup = _make_service(
        isp_link_lookup=FakeIspLinkLookup(links),
        agent_credential_issuer=credential_issuer,
        router_lookup=FakeRouterLookup({router.id: router}),
    )
    return service, provisioning_lookup, credential_issuer


class TestPushIspNetwatchConfig:
    async def test_creates_and_applies_a_version_watching_static_links(self) -> None:
        router = _make_router()
        link = _make_isp_link(router_id=router.id)
        service, provisioning_lookup, credential_issuer = _make_netwatch_service(
            links=[link], router=router
        )
        result = await service.push_isp_netwatch_config(
            router.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            api_base_url="https://api.cloudguest.example",
        )
        assert result.watched_link_count == 1
        assert result.version.status == ConfigVersionStatus.PENDING_APPLY.value
        assert "/tool netwatch add" in result.version.rendered_content
        assert NETWATCH_SECTION_HEADER in result.version.rendered_content
        assert provisioning_lookup.calls == [
            "create_version_from_content",
            "apply_version",
        ]
        # The router's own agent credential was rotated exactly once, and
        # the resulting fresh plaintext is what actually got embedded.
        assert credential_issuer.issued_for == [router.id]
        assert f"plaintext-{router.id}-1" in result.version.rendered_content

    async def test_only_watches_enabled_static_links_with_a_gateway(self) -> None:
        router = _make_router()
        watched = _make_isp_link(router_id=router.id, provider_name="Airtel")
        disabled = _make_isp_link(
            router_id=router.id, provider_name="Jio", is_enabled=False
        )
        dhcp_mode = _make_isp_link(
            router_id=router.id,
            provider_name="ACT",
            connection_mode=IspConnectionMode.DHCP.value,
            gateway_ip_address=None,
        )
        other_router_link = _make_isp_link(router_id=uuid.uuid4())
        service, _, _ = _make_netwatch_service(
            links=[watched, disabled, dhcp_mode, other_router_link], router=router
        )
        result = await service.push_isp_netwatch_config(
            router.id,
            actor_user_id=None,
            requesting_organization_id=None,
            api_base_url="https://api.cloudguest.example",
        )
        assert result.watched_link_count == 1
        assert result.version.rendered_content.count("/tool netwatch add") == 1

    async def test_raises_when_no_qualifying_links(self) -> None:
        router = _make_router()
        service, _, _ = _make_netwatch_service(links=[], router=router)
        with pytest.raises(NoNetwatchTargetsError):
            await service.push_isp_netwatch_config(
                router.id,
                actor_user_id=None,
                requesting_organization_id=None,
                api_base_url="https://api.cloudguest.example",
            )

    async def test_raises_when_integration_not_composed(self) -> None:
        service, _ = _make_service()
        with pytest.raises(NetwatchIntegrationUnavailableError):
            await service.push_isp_netwatch_config(
                uuid.uuid4(),
                actor_user_id=None,
                requesting_organization_id=None,
                api_base_url="https://api.cloudguest.example",
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


class TestConfigAgentBridgeRetirement:
    """Regression guards for the retired config-agent HTTP bridge (router-
    fleet plan section A1). Live pushes now go through wyfy_device_gateway."""

    async def test_apply_live_reports_missing_connection_details(self) -> None:
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, MagicMock

        from app.domains.network_config.router import apply_network_config_live

        fake_request = SimpleNamespace(state=SimpleNamespace(request_id="req-1"))
        version = SimpleNamespace(rendered_content="/ip address add ...")
        provisioning_service = AsyncMock()
        provisioning_service.get_version = AsyncMock(return_value=version)
        router_service = MagicMock()
        router_service.reveal_credentials = AsyncMock(
            return_value=SimpleNamespace(
                management_ip_address=None,
                public_ip_address=None,
                api_username=None,
            )
        )
        router_service.get_decrypted_api_secret.return_value = None

        result = await apply_network_config_live(
            request=fake_request,  # type: ignore[arg-type]
            router_id=uuid.uuid4(),
            version_id=uuid.uuid4(),
            user=SimpleNamespace(id=str(uuid.uuid4())),  # type: ignore[arg-type]
            requesting_organization_id=None,
            provisioning_service=provisioning_service,
            router_service=router_service,
        )
        assert result["success"] is True
        assert result["data"]["applied"] is False
        assert "connection details" in (result["data"]["detail"] or "")

    async def test_apply_live_pushes_via_gateway(self, monkeypatch) -> None:  # noqa: ANN001
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, MagicMock

        from app.domains.network_config.router import apply_network_config_live

        pushed: list[dict[str, str]] = []

        async def fake_push_live_config(**kwargs: str) -> None:
            pushed.append(kwargs)

        monkeypatch.setattr(
            "app.domains.network_config.router.push_live_config",
            fake_push_live_config,
        )

        fake_request = SimpleNamespace(state=SimpleNamespace(request_id="req-1"))
        version = SimpleNamespace(rendered_content="/ip address add ...")
        provisioning_service = AsyncMock()
        provisioning_service.get_version = AsyncMock(return_value=version)
        router_service = MagicMock()
        router_service.reveal_credentials = AsyncMock(
            return_value=SimpleNamespace(
                management_ip_address="10.20.0.41",
                public_ip_address=None,
                api_username="cloudguest-api",
            )
        )
        router_service.get_decrypted_api_secret.return_value = "secret-123"

        result = await apply_network_config_live(
            request=fake_request,  # type: ignore[arg-type]
            router_id=uuid.uuid4(),
            version_id=uuid.uuid4(),
            user=SimpleNamespace(id=str(uuid.uuid4())),  # type: ignore[arg-type]
            requesting_organization_id=None,
            provisioning_service=provisioning_service,
            router_service=router_service,
        )
        assert result["success"] is True
        assert result["data"]["applied"] is True
        assert pushed == [
            {
                "host": "10.20.0.41",
                "username": "cloudguest-api",
                "password": "secret-123",
                "config_content": "/ip address add ...",
            }
        ]

    def test_no_hardcoded_bridge_coordinates_in_source(self) -> None:
        """Regression guard for the leaked ``configagent-*`` secret: no
        bridge URL/secret literal may reappear in either module that used
        to hardcode them."""
        import inspect

        from app.domains.guest import router as guest_router_module
        from app.domains.network_config import router as nc_router
        from app.domains.router import device_credential_rotator
        from app.domains.wireguard import router as wg_router_module

        for module in (
            nc_router,
            device_credential_rotator,
            # Added after the hub migration: these two hardcoded the 9091 /
            # 9092 bridge URLs AND their shared secrets in cleartext until
            # both moved to Settings. The secrets have been rotated, so the
            # committed ones are dead -- this stops a new one appearing.
            wg_router_module,
            guest_router_module,
        ):
            source = inspect.getsource(module)
            assert "configagent-" not in source
            assert "20.219.72.235" not in source
            assert "wgagent-" not in source
            assert "radiusagent-" not in source


class TestEveryRouteRequiresPermission:
    def test_every_network_config_route_has_a_permission_dependency(self) -> None:
        # 6 pre-existing routes + POST netwatch/push + POST apply-live
        # + GET/POST wan/basic preview/apply (Wave 1 Step 5).
        assert len(network_config_router.routes) == 10
        for route in network_config_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"


class TestBootstrapSetsTheClock:
    """The bootstrap script is the Fleet Wizard's path, and it did not
    touch the clock at all -- while the Master console's own generator has
    set it since 2026-08-23. Two generators, two repos, one silently
    missing the fix.

    Every platform call in this script is HTTPS (``_require_https``
    guarantees it). A MikroTik has no battery-backed clock and boots at its
    firmware build date, and TLS validation fails closed against a wrong
    date -- so the check-in fetch is rejected BEFORE it is sent, with
    RouterOS's own generic failure text and nothing naming the clock. The
    router then serves guests perfectly and shows OFFLINE in Master console
    forever.
    """

    def _onsite(self) -> list[str]:
        return render_bootstrap_script(
            location_code="LOC-2026-000039",
            provisioning_token="tok",
            api_base_url="https://api.cloudguest.example",
        )

    def _remote(self) -> list[str]:
        return render_bootstrap_script(
            location_code="LOC-2026-000039",
            provisioning_token="tok",
            api_base_url="https://api.cloudguest.example",
            mode=BootstrapMode.REMOTE,
        )

    def test_both_modes_enable_ntp_and_set_the_timezone(self) -> None:
        for lines in (self._onsite(), self._remote()):
            script = "\n".join(lines)
            assert "/system ntp client set enabled=yes" in script
            assert "time-zone-name=Asia/Kolkata" in script

    def test_the_clock_is_set_before_the_first_https_call(self) -> None:
        """Ordering is the whole point -- NTP configured after the fetch
        that it exists to make possible would be decorative."""
        for lines in (self._onsite(), self._remote()):
            first_ntp = next(i for i, ln in enumerate(lines) if "ntp client set" in ln)
            first_fetch = next(i for i, ln in enumerate(lines) if "/tool fetch" in ln)
            assert first_ntp < first_fetch, (
                "NTP is configured after the first HTTPS call -- the call it was "
                "supposed to make possible has already failed by then"
            )

    def test_it_refuses_to_continue_on_an_unsynced_clock(self) -> None:
        """``:error``, not a printed warning. This script is delivered
        non-interactively -- pasted whole or pushed through the gateway --
        so a warning has no reader, and continuing produces a router that
        looks enrolled and silently never reports."""
        for lines in (self._onsite(), self._remote()):
            script = "\n".join(lines)
            assert ':if ($cgClk != "synchronized") do={ :error ' in script

    def test_the_sync_wait_is_bounded(self) -> None:
        """An unbounded ``:while`` on a venue with UDP 123 blocked would
        hang the provisioning session forever instead of failing it."""
        for lines in (self._onsite(), self._remote()):
            script = "\n".join(lines)
            assert "$cgTries < 15" in script and ":delay 2s" in script


# ============================================================================
# Guest data path -- the NAT rule whose absence let a fully-provisioned
# venue authenticate every guest and give none of them internet.
# ============================================================================


class TestRenderGuestDataPath:
    def _script(self) -> str:
        return "\n".join(render_guest_data_path())

    def test_the_out_interface_is_discovered_never_named(self) -> None:
        """This ships to every enrolled router, so a masquerade pointed at
        a name the platform merely believes is a worse outcome than no
        masquerade at all. The target is resolved from the device's own
        active default route."""
        script = self._script()
        assert 'dst-address="0.0.0.0/0" active=yes' in script
        assert "action=masquerade" in script
        # The out-interface is a variable resolved on-device, never a
        # literal interface name interpolated by the platform.
        assert "out-interface=$cgDataPathIf" in script
        for guessed in ("ether1", "sfp1", "pppoe-out1", "bridge"):
            assert f"out-interface={guessed}" not in script

    def test_nothing_untagged_is_ever_read_or_written(self) -> None:
        """A venue's own masquerade, port forwards and hairpin rules are
        the operator's. Every NAT statement here is filtered on our marker,
        and nothing is removed at all."""
        script = self._script()
        for statement in script.split("; "):
            if "/ip firewall nat" not in statement:
                continue
            assert (
                "cloudguest-nat-live" in statement
                or "$cgDataPathNat" in statement
            ), statement
        assert "/ip firewall nat remove" not in script

    def test_it_cannot_match_tunnel_bound_traffic(self) -> None:
        """RADIUS sources from the router's tunnel address and must keep
        doing so. Scoping by out-interface rather than by source address is
        what makes that true by construction: traffic to the hub egresses
        wg-cloudguard, which is never the discovered default-route
        interface. A src-address-scoped rule would have needed an explicit
        tunnel exclusion to be equally safe."""
        script = self._script()
        assert "src-address=" not in script
        assert "wg-cloudguard" not in script

    def test_an_unresolved_uplink_changes_nothing_and_says_so(self) -> None:
        """Every write is gated on the discovery having succeeded, so the
        degraded outcome is 'nothing was guessed', not a plausible-looking
        wrong interface."""
        script = self._script()
        assert 'no uplink interface resolved' in script
        for statement in script.split("; "):
            if "/ip firewall nat add" in statement or "/interface list member add" in (
                statement
            ):
                assert '$cgDataPathIf != ""' in statement, statement

    def test_re_running_converges_rather_than_duplicating(self) -> None:
        script = self._script()
        assert "[:len $cgDataPathNat] = 0" in script  # absent -> add
        assert "[:len $cgDataPathNat] > 0" in script  # present -> re-point

    def test_verification_fails_loudly_rather_than_reporting_success(
        self,
    ) -> None:
        """The whole lesson of 2026-08-27: a router that finishes enrollment
        without a NAT rule is a venue where every guest authenticates and
        none gets online, silently, with the platform reporting success."""
        line = "\n".join(render_guest_data_path_verification())
        assert ":error" in line
        assert "no guest NAT rule was established" in line


class TestRenderHotspotWalledGarden:
    API_URL = "https://app.wyfyguest.com/agent/check-in"

    def _script(self, api_url: str | None = None) -> str:
        return "\n".join(
            render_hotspot_walled_garden(api_url=api_url or self.API_URL)
        )

    def test_allows_the_portal_and_the_api_and_nothing_else(self) -> None:
        """A hotspot intercepts everything until the guest authenticates,
        so the portal they are redirected to has to be punched through
        explicitly -- and only it, plus the API that portal calls."""
        script = self._script()
        assert 'dst-host="portal.wyfyguest.com"' in script
        assert 'dst-host="app.wyfyguest.com"' in script
        assert script.count("walled-garden add") == 2
        assert "action=allow" in script

    def test_the_portal_host_is_the_same_constant_the_redirect_uses(self) -> None:
        """`_render_vlan_hotspot` puts HOTSPOT_DNS_NAME in `dns-name` and
        `/ip dns static`. If the allowed host were spelled separately the
        two could drift, and a guest would be redirected to a name they are
        not permitted to reach -- which fails as a hang, not an error."""
        assert f'dst-host="{HOTSPOT_DNS_NAME}"' in self._script()

    def test_the_api_host_is_derived_not_hardcoded(self) -> None:
        """So a staging deployment walls in its own API rather than
        production's."""
        script = self._script("https://api.staging.example.net/agent/check-in")
        assert 'dst-host="api.staging.example.net"' in script
        assert "app.wyfyguest.com" not in script

    def test_only_the_host_of_the_url_is_used_never_the_path(self) -> None:
        """The bootstrap renderers pass the `check_in_url` they already
        hold rather than carrying the same host twice."""
        script = self._script()
        assert "/agent/check-in" not in script

    def test_it_is_idempotent_and_never_removes(self) -> None:
        """Bootstraps re-run, including against a live router already
        serving guests. Adding a duplicate allow rule is harmless; removing
        one out from under an in-flight request is not."""
        script = self._script()
        assert script.count("= 0) do=") == 2
        assert "walled-garden remove" not in script

    def test_it_only_ever_matches_its_own_rows(self) -> None:
        """An operator's hand-added walled-garden entries carry a different
        comment (or none) and must never be found by this section."""
        script = self._script()
        assert script.count(f'comment="{MANAGED_WALLED_GARDEN_COMMENT}"') == 4

    def test_a_host_that_is_also_the_portal_is_not_duplicated(self) -> None:
        """RouterOS would accept two identical rows; the guard that keeps
        this section to one line per host should not be defeated by a
        deployment that serves portal and API from one name."""
        script = self._script(f"https://{HOTSPOT_DNS_NAME}/agent/check-in")
        assert script.count("walled-garden add") == 1


class TestBootstrapRendersTheWalledGarden:
    """The walled garden ships on the bootstrap, not on a config push,
    for the same reason the guest data path does: it is gated on an
    optional table (`hotspot_profiles`) that production has none of, so
    the only path that reliably runs is the one every enrolled router
    executes."""

    def _script(self) -> str:
        return "\n".join(
            render_bootstrap_script(
                location_code="LOC-2026-000053",
                provisioning_token="tok",
                api_base_url="https://api.example.com",
            )
        )

    def test_onsite_bootstrap_carries_it(self) -> None:
        script = self._script()
        assert MANAGED_WALLED_GARDEN_COMMENT in script
        assert f'dst-host="{HOTSPOT_DNS_NAME}"' in script

    def test_the_api_host_comes_from_the_callers_own_base_url(self) -> None:
        """Not from a literal baked into the renderer -- otherwise a
        non-production deployment would allow production's API through and
        wall in nothing useful of its own."""
        script = self._script()
        assert 'dst-host="api.example.com"' in script
        assert "app.wyfyguest.com" not in script


class TestBootstrapAssertsTheGuestDataPath:
    def test_onsite_asserts_and_gates_success_on_it(self) -> None:
        lines = render_bootstrap_script(
            location_code="LOC-2026-000053",
            provisioning_token="tok",
            api_base_url="https://api.example.com",
        )
        script = "\n".join(lines)
        assert "cloudguest-nat-live" in script
        # The success line no longer means only "the tunnel is up".
        assert "no guest NAT rule was established" in script
        success = [line for line in lines if "bootstrap successful" in line]
        assert success and "guest data path" in success[0]

    def test_the_assertion_precedes_the_verification(self) -> None:
        """Asserting and verifying are different claims and the order
        matters -- verifying first would always fail on a fresh box."""
        lines = render_bootstrap_script(
            location_code="L",
            provisioning_token="t",
            api_base_url="https://api.example.com",
        )
        assert_at = next(
            i for i, line in enumerate(lines) if "/ip firewall nat add" in line
        )
        verify_at = next(
            i
            for i, line in enumerate(lines)
            if "no guest NAT rule was established" in line
        )
        assert assert_at < verify_at

    def test_remote_asserts_without_a_hard_failure(self) -> None:
        """Remote re-provisions a live, already-serving router. Aborting
        that over a missing NAT rule would be a worse outcome than the
        missing rule; the on-site path is where failing loudly is right."""
        lines = render_bootstrap_script(
            location_code="L",
            provisioning_token="t",
            api_base_url="https://api.example.com",
            mode=BootstrapMode.REMOTE,
        )
        script = "\n".join(lines)
        assert "cloudguest-nat-live" in script
        assert "no guest NAT rule was established" not in script


class TestGuestDataPathOnThePushPath:
    def test_a_real_config_carries_the_nat_assertion(self) -> None:
        rendered = render_network_config(
            dhcp_pools=[_make_pool()],
            vlans=[],
            port_forwarding_rules=[],
        )
        assert "cloudguest-nat-live" in rendered

    def test_an_empty_config_stays_empty(self) -> None:
        """Emitting the data path unconditionally here would mean this
        function never returns "", silently retiring push_config's
        EmptyNetworkConfigError guard. Nothing is lost by the restraint:
        the bootstrap script asserts it on every enrolled router."""
        assert (
            render_network_config(dhcp_pools=[], vlans=[], port_forwarding_rules=[])
            == ""
        )
