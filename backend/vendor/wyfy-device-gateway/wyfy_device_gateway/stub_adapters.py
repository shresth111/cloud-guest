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
    ContentFilterRuleConfig,
    DeviceCredentials,
    DeviceDiscoveryResult,
    DeviceHealthResult,
    DeviceVendor,
    DhcpPoolConfig,
    HotspotDisconnectResult,
    HotspotSessionControl,
    InterfaceInfo,
    PingResult,
    PortForwardConfig,
    ProvisionResult,
    QueueDeviceStatus,
    RadiusClientConfig,
    RawCommandResult,
    SpeedTestResult,
    TracerouteResult,
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

    async def configure_content_filter_rule(
        self, creds: DeviceCredentials, *, rule: ContentFilterRuleConfig
    ) -> None:
        raise self._not_implemented()

    async def disconnect_device(
        self, creds: DeviceCredentials, *, mac_address: str, interface: str | None
    ) -> None:
        raise self._not_implemented()

    async def read_hotspot_session_control(
        self, creds: DeviceCredentials
    ) -> HotspotSessionControl:
        raise self._not_implemented()

    async def end_hotspot_sessions(
        self,
        creds: DeviceCredentials,
        *,
        mac_address: str | None,
        username: str | None,
    ) -> HotspotDisconnectResult:
        raise self._not_implemented()

    async def ping(
        self, creds: DeviceCredentials, *, target: str, count: int, timeout_seconds: int
    ) -> PingResult:
        raise self._not_implemented()

    async def traceroute(
        self,
        creds: DeviceCredentials,
        *,
        target: str,
        max_hops: int,
        timeout_seconds: int,
    ) -> TracerouteResult:
        raise self._not_implemented()

    async def get_active_default_gateway(self, creds: DeviceCredentials) -> str | None:
        raise self._not_implemented()

    async def get_pppoe_interface_status(
        self, creds: DeviceCredentials, *, interface_name: str
    ) -> bool:
        raise self._not_implemented()

    async def get_interface_traffic_counters(
        self, creds: DeviceCredentials, *, interface_name: str
    ) -> tuple[int, int] | None:
        raise self._not_implemented()

    async def run_speed_test(
        self, creds: DeviceCredentials, *, download_url: str
    ) -> SpeedTestResult:
        raise self._not_implemented()

    async def create_simple_queue(
        self,
        creds: DeviceCredentials,
        *,
        name: str,
        target: str,
        download_rate_kbps: int,
        upload_rate_kbps: int,
        burst_download_kbps: int | None = None,
        burst_upload_kbps: int | None = None,
        burst_threshold_kbps: int | None = None,
        burst_time_seconds: int | None = None,
        priority: int = 8,
    ) -> str:
        raise self._not_implemented()

    async def update_simple_queue(
        self,
        creds: DeviceCredentials,
        *,
        device_queue_id: str,
        download_rate_kbps: int,
        upload_rate_kbps: int,
        burst_download_kbps: int | None = None,
        burst_upload_kbps: int | None = None,
        burst_threshold_kbps: int | None = None,
        burst_time_seconds: int | None = None,
        priority: int = 8,
    ) -> None:
        raise self._not_implemented()

    async def delete_simple_queue(
        self, creds: DeviceCredentials, *, device_queue_id: str
    ) -> None:
        raise self._not_implemented()

    async def create_queue_tree(
        self,
        creds: DeviceCredentials,
        *,
        name: str,
        parent: str,
        packet_mark: str | None,
        max_limit_kbps: int,
        priority: int = 8,
        queue_type_name: str | None = None,
    ) -> str:
        raise self._not_implemented()

    async def apply_pcq(
        self,
        creds: DeviceCredentials,
        *,
        name: str,
        rate_kbps: int,
        classifier: str = "dst-address",
    ) -> str:
        raise self._not_implemented()

    async def set_priority(
        self,
        creds: DeviceCredentials,
        *,
        device_queue_id: str,
        priority: int,
        queue_kind: str = "simple",
    ) -> None:
        raise self._not_implemented()

    async def assign_queue_to_target(
        self, creds: DeviceCredentials, *, device_queue_id: str, target: str
    ) -> None:
        raise self._not_implemented()

    async def remove_queue(
        self,
        creds: DeviceCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> None:
        raise self._not_implemented()

    async def read_queue_status(
        self,
        creds: DeviceCredentials,
        *,
        device_queue_id: str,
        queue_kind: str = "simple",
    ) -> QueueDeviceStatus:
        raise self._not_implemented()

    async def discover(self, creds: DeviceCredentials) -> DeviceDiscoveryResult:
        raise self._not_implemented()

    async def push_config(self, creds: DeviceCredentials, *, config_content: str) -> None:
        raise self._not_implemented()

    async def verify_config(
        self, creds: DeviceCredentials, *, expected_content: str
    ) -> bool:
        raise self._not_implemented()

    async def health_check(self, creds: DeviceCredentials) -> DeviceHealthResult:
        raise self._not_implemented()

    async def backup(self, creds: DeviceCredentials) -> bytes:
        raise self._not_implemented()

    async def restore(self, creds: DeviceCredentials, *, backup_content: bytes) -> None:
        raise self._not_implemented()

    async def upload_file(
        self, creds: DeviceCredentials, *, filename: str, content: bytes
    ) -> None:
        raise self._not_implemented()

    async def execute_raw_command(
        self, creds: DeviceCredentials, *, command: str
    ) -> RawCommandResult:
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
            "configure_content_filter_rule": False,
            "disconnect_device": False,
            "ping": False,
            "traceroute": False,
            "get_active_default_gateway": False,
            "get_pppoe_interface_status": False,
            "get_interface_traffic_counters": False,
            "run_speed_test": False,
            "create_simple_queue": False,
            "update_simple_queue": False,
            "delete_simple_queue": False,
            "create_queue_tree": False,
            "apply_pcq": False,
            "set_priority": False,
            "assign_queue_to_target": False,
            "remove_queue": False,
            "read_queue_status": False,
            "discover": False,
            "push_config": False,
            "verify_config": False,
            "health_check": False,
            "backup": False,
            "restore": False,
            "upload_file": False,
            "execute_raw_command": False,
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
