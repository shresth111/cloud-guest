"""FastAPI dependencies for the Network Configuration Management domain.

Composes ``app.domains.dhcp``/``app.domains.vlan``/``app.domains
.port_forwarding``/``app.domains.hotspot``/``app.domains
.router_provisioning`` entirely through their own existing, already-wired
FastAPI dependency functions -- exactly the same real service graph the
live API already builds for each of those domains, never a second,
parallel construction path.
"""

from __future__ import annotations

from fastapi import Depends

from app.domains.dhcp.dependencies import get_dhcp_service
from app.domains.dhcp.service import DhcpService
from app.domains.hotspot.dependencies import get_hotspot_service
from app.domains.hotspot.service import HotspotService
from app.domains.port_forwarding.dependencies import get_port_forwarding_service
from app.domains.port_forwarding.service import PortForwardingService
from app.domains.router_provisioning.dependencies import get_router_provisioning_service
from app.domains.router_provisioning.service import RouterProvisioningService
from app.domains.vlan.dependencies import get_vlan_service
from app.domains.vlan.service import VlanService

from .service import NetworkConfigService


def get_network_config_service(
    dhcp_service: DhcpService = Depends(get_dhcp_service),
    vlan_service: VlanService = Depends(get_vlan_service),
    port_forwarding_service: PortForwardingService = Depends(
        get_port_forwarding_service
    ),
    hotspot_service: HotspotService = Depends(get_hotspot_service),
    router_provisioning_service: RouterProvisioningService = Depends(
        get_router_provisioning_service
    ),
) -> NetworkConfigService:
    return NetworkConfigService(
        dhcp_service,
        vlan_service,
        port_forwarding_service,
        hotspot_service,
        router_provisioning_service,
    )


__all__ = ["get_network_config_service"]
