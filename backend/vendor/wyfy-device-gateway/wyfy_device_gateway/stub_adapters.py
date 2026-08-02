"""Stub ``DeviceGatewayAdapter`` implementations for every vendor that does
not yet have a real integration (PRD section 3's vendor-landscape research
-- TP-Link Omada, Ruckus, Ubiquiti UniFi, Aruba, Cisco Meraki).

Every method raises ``NotImplementedError`` with a message pointing back at
PRD section 3, and ``capabilities()`` reports every operation as
unsupported. This makes the ``DeviceGatewayAdapter`` Protocol shape
checkable (a missing method is a real static-typing error) without
pretending any of these vendors work today -- see PRD section 4.2.
"""

from __future__ import annotations

from .contract import (
    ConnectedDevice,
    DeviceCredentials,
    DeviceVendor,
    DhcpPoolConfig,
    InterfaceInfo,
    PortForwardConfig,
    ProvisionResult,
    RadiusClientConfig,
    VlanConfig,
    WanHealth,
)

_NOT_IMPLEMENTED_SUFFIX = "adapter not yet implemented -- see PRD section 3 for API research status"


class _StubAdapter:
    """Shared stub implementation. Every vendor-specific subclass only
    needs to set ``vendor`` and a human-readable ``_display_name`` -- the
    method bodies (raise + report no capabilities) are identical across
    every stub, mirroring how the six real adapters this Protocol was
    extracted from all raised the identical shape of connection error for
    the identical reason (an unreachable/unimplemented device), just for a
    different root cause here (no real client code exists yet, not "the
    device didn't answer")."""

    vendor: DeviceVendor
    _display_name: str

    def _not_implemented(self) -> NotImplementedError:
        return NotImplementedError(f"{self._display_name} {_NOT_IMPLEMENTED_SUFFIX}")

    async def get_interface_list(self, creds: DeviceCredentials) -> list[InterfaceInfo]:
        raise self._not_implemented()

    async def get_wan_health(self, creds: DeviceCredentials, *, target_ip: str) -> WanHealth:
        raise self._not_implemented()

    async def list_connected_devices(self, creds: DeviceCredentials) -> list[ConnectedDevice]:
        raise self._not_implemented()

    async def provision_device(
        self, creds: DeviceCredentials, *, rendered_config: str, content_type: str
    ) -> ProvisionResult:
        raise self._not_implemented()

    async def reboot_device(self, creds: DeviceCredentials) -> None:
        raise self._not_implemented()

    async def configure_vlan(self, creds: DeviceCredentials, *, vlan: VlanConfig) -> None:
        raise self._not_implemented()

    async def configure_dhcp_pool(
        self, creds: DeviceCredentials, *, pool: DhcpPoolConfig
    ) -> None:
        raise self._not_implemented()

    async def configure_port_forward(
        self, creds: DeviceCredentials, *, rule: PortForwardConfig
    ) -> None:
        raise self._not_implemented()

    async def set_radius_client_config(
        self, creds: DeviceCredentials, *, config: RadiusClientConfig
    ) -> None:
        raise self._not_implemented()

    async def disconnect_device(
        self, creds: DeviceCredentials, *, mac_address: str, interface: str | None
    ) -> None:
        raise self._not_implemented()

    def capabilities(self) -> dict[str, bool]:
        return {
            "get_interface_list": False,
            "get_wan_health": False,
            "list_connected_devices": False,
            "provision_device": False,
            "reboot_device": False,
            "configure_vlan": False,
            "configure_dhcp_pool": False,
            "configure_port_forward": False,
            "set_radius_client_config": False,
            "disconnect_device": False,
        }


class TpLinkAdapter(_StubAdapter):
    vendor = DeviceVendor.TPLINK_OMADA
    _display_name = "TP-Link Omada"


class RuckusAdapter(_StubAdapter):
    vendor = DeviceVendor.RUCKUS
    _display_name = "Ruckus"


class UnifiAdapter(_StubAdapter):
    vendor = DeviceVendor.UNIFI
    _display_name = "Ubiquiti UniFi"


class ArubaAdapter(_StubAdapter):
    vendor = DeviceVendor.ARUBA
    _display_name = "Aruba"


class CiscoMerakiAdapter(_StubAdapter):
    vendor = DeviceVendor.CISCO_MERAKI
    _display_name = "Cisco Meraki"


__all__ = [
    "TpLinkAdapter",
    "RuckusAdapter",
    "UnifiAdapter",
    "ArubaAdapter",
    "CiscoMerakiAdapter",
]
