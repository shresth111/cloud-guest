"""FastAPI dependencies for the Network Configuration Management domain.

Composes ``app.domains.dhcp``/``app.domains.vlan``/``app.domains
.port_forwarding``/``app.domains.hotspot``/``app.domains.qos``/
``app.domains.router_provisioning``/``app.domains.wireguard``/
``app.domains.guest`` entirely through their own existing, already-wired
FastAPI dependency functions -- exactly the same real service graph the
live API already builds for each of those domains, never a second,
parallel construction path.
"""

from __future__ import annotations

from fastapi import Depends

from app.domains.dhcp.dependencies import get_dhcp_service
from app.domains.dhcp.service import DhcpService
from app.domains.dns.dependencies import get_dns_service
from app.domains.dns.service import DnsService
from app.domains.firewall.dependencies import get_firewall_service
from app.domains.firewall.service import FirewallService
from app.domains.guest.dependencies import get_radius_service
from app.domains.guest.service import RadiusService
from app.domains.hotspot.dependencies import get_hotspot_service
from app.domains.hotspot.service import HotspotService
from app.domains.port_forwarding.dependencies import get_port_forwarding_service
from app.domains.port_forwarding.service import PortForwardingService
from app.domains.qos.dependencies import get_qos_service
from app.domains.qos.service import QosService
from app.domains.router_provisioning.dependencies import get_router_provisioning_service
from app.domains.router_provisioning.service import RouterProvisioningService
from app.domains.vlan.dependencies import get_vlan_service
from app.domains.vlan.service import VlanService
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.service import WireGuardService

from .service import NetworkConfigService


def get_network_config_service(
    dhcp_service: DhcpService = Depends(get_dhcp_service),
    vlan_service: VlanService = Depends(get_vlan_service),
    port_forwarding_service: PortForwardingService = Depends(
        get_port_forwarding_service
    ),
    hotspot_service: HotspotService = Depends(get_hotspot_service),
    qos_service: QosService = Depends(get_qos_service),
    router_provisioning_service: RouterProvisioningService = Depends(
        get_router_provisioning_service
    ),
    dns_service: DnsService = Depends(get_dns_service),
    firewall_service: FirewallService = Depends(get_firewall_service),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
    radius_service: RadiusService = Depends(get_radius_service),
) -> NetworkConfigService:
    return NetworkConfigService(
        dhcp_service,
        vlan_service,
        port_forwarding_service,
        hotspot_service,
        qos_service,
        router_provisioning_service,
        dns_lookup=dns_service,
        firewall_lookup=firewall_service,
        # Real integration point for the device-config-generation layer
        # (``renderers.render_wireguard_peer``/``render_radius_client``):
        # the identical, already-wired ``WireGuardService``/``RadiusService``
        # instances every other WireGuard/RADIUS endpoint in this
        # application already composes -- never a second, parallel one.
        wireguard_lookup=wireguard_service,
        radius_nas_lookup=radius_service,
    )


__all__ = ["get_network_config_service"]
