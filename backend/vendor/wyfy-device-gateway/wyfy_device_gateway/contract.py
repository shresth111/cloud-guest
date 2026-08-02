"""The ONE stable contract the main cloud-guest-repo backend depends on.

Nothing in cloud-guest-repo should ever import a vendor-specific adapter
directly -- only this module's types and ``get_adapter()`` (in
``wyfy_device_gateway.registry``).

This is a near-verbatim implementation of PRD section 4.1's illustrative
contract. ``StrEnum`` requires Python 3.11+; this package (like
cloud-guest-repo's own backend) targets Python 3.13+ (see pyproject.toml),
so no compatibility shim is needed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable


class DeviceVendor(StrEnum):
    MIKROTIK = "mikrotik"
    TPLINK_OMADA = "tplink_omada"
    RUCKUS = "ruckus"
    UNIFI = "unifi"
    ARUBA = "aruba"
    CISCO_MERAKI = "cisco_meraki"
    # add here as real adapters land; UnsupportedVendorError otherwise


class UnsupportedVendorError(Exception):
    """Raised by ``get_adapter`` when no adapter is registered for a
    vendor. Mirrors the ``UnsupportedXVendorError`` exceptions already
    raised six times over in cloud-guest-repo (PRD section 2.1) --
    consolidated here into the one real copy."""

    def __init__(self, vendor: object) -> None:
        self.vendor = vendor
        super().__init__(f"no device gateway adapter registered for vendor: {vendor!r}")


@dataclass(frozen=True, slots=True)
class DeviceCredentials:
    """Resolved, already-decrypted per-device connection material. Built by
    the CALLER (cloud-guest-repo) from Router.management_ip_address /
    api_username / decrypted api_credentials_encrypted -- the Gateway never
    touches Fernet or the DB directly. See PRD section 6."""

    vendor: DeviceVendor
    host: str
    username: str
    secret: str  # password, API key, or token depending on vendor
    port: int | None = None          # vendor-specific default if None
    timeout_seconds: int = 10
    extra: dict[str, str] = field(default_factory=dict)  # e.g. Omada site id,
    # UniFi controller base URL, Meraki org/network id -- whatever a given
    # vendor's connection needs beyond host/user/secret. Kept generic and
    # opaque to the caller on purpose: cloud-guest-repo should never need to
    # know what's inside `extra` for a vendor it isn't actively using.


@dataclass(frozen=True, slots=True)
class InterfaceInfo:
    name: str
    type: str | None
    running: bool
    disabled: bool
    bridge: str | None
    has_ip_address: bool


@dataclass(frozen=True, slots=True)
class WanHealth:
    reachable: bool
    dynamic_gateway: str | None
    ppp_status: bool | None
    rx_bytes: int | None
    tx_bytes: int | None
    latency_ms: float | None
    packet_loss_percent: float | None


@dataclass(frozen=True, slots=True)
class ConnectedDevice:
    mac_address: str
    ip_address: str | None
    hostname: str | None
    interface: str | None
    is_wireless: bool
    signal_strength_dbm: int | None


@dataclass(frozen=True, slots=True)
class VlanConfig:
    vlan_id: int
    name: str
    interface: str
    ip_cidr: str | None


@dataclass(frozen=True, slots=True)
class DhcpPoolConfig:
    interface: str
    range_start: str
    range_end: str
    gateway: str
    dns_servers: list[str]
    lease_time_seconds: int


@dataclass(frozen=True, slots=True)
class PortForwardConfig:
    protocol: str          # "tcp" | "udp"
    external_port: int
    internal_ip: str
    internal_port: int


@dataclass(frozen=True, slots=True)
class RadiusClientConfig:
    radius_server_host: str
    radius_secret: str
    auth_port: int = 1812
    acct_port: int = 1813


@dataclass(frozen=True, slots=True)
class ProvisionResult:
    success: bool
    applied_content_summary: str | None
    error_message: str | None


@runtime_checkable
class DeviceGatewayAdapter(Protocol):
    """One Adapter per vendor. Every method mirrors a REAL operation this
    platform performs today (see PRD section 2.1) -- ported, not invented.
    A stubbed vendor may raise NotImplementedError from any method; the
    Protocol shape must still be fully implemented (or explicitly declared
    partial via `capabilities()`, see below) so callers can branch on
    capability rather than getting a surprise exception deep in a task."""

    vendor: DeviceVendor

    # -- discovery / telemetry (read-only) -----------------------------
    async def get_interface_list(self, creds: DeviceCredentials) -> list[InterfaceInfo]: ...
    async def get_wan_health(self, creds: DeviceCredentials, *, target_ip: str) -> WanHealth: ...
    async def list_connected_devices(self, creds: DeviceCredentials) -> list[ConnectedDevice]: ...

    # -- lifecycle -------------------------------------------------------
    async def provision_device(
        self, creds: DeviceCredentials, *, rendered_config: str, content_type: str
    ) -> ProvisionResult:
        """`rendered_config` is vendor-specific config text/JSON already
        rendered by the caller (or, longer-term, by this adapter itself --
        see PRD section 9 Phase 3 note on renderer ownership). `content_type`
        mirrors router_provisioning.adapters' existing
        `build_job_payload`'s `content_type` field (e.g. "routeros_script")."""
        ...

    async def reboot_device(self, creds: DeviceCredentials) -> None: ...

    # -- network config push ---------------------------------------------
    async def configure_vlan(self, creds: DeviceCredentials, *, vlan: VlanConfig) -> None: ...
    async def configure_dhcp_pool(self, creds: DeviceCredentials, *, pool: DhcpPoolConfig) -> None: ...
    async def configure_port_forward(
        self, creds: DeviceCredentials, *, rule: PortForwardConfig
    ) -> None: ...
    async def set_radius_client_config(
        self, creds: DeviceCredentials, *, config: RadiusClientConfig
    ) -> None: ...

    # -- disconnect / kick -------------------------------------------------
    async def disconnect_device(
        self, creds: DeviceCredentials, *, mac_address: str, interface: str | None
    ) -> None: ...

    # -- capability introspection -----------------------------------------
    def capabilities(self) -> dict[str, bool]:
        """Which of the above this vendor's adapter genuinely implements
        today, e.g. {"get_wan_health": True, "configure_port_forward": False}.
        Mirrors router_provisioning.adapters.describe_capabilities's existing
        precedent. Callers (cloud-guest-repo) should check this before
        calling an operation on a non-MikroTik router in Phase 1/2, rather
        than catching NotImplementedError as control flow."""
        ...


__all__ = [
    "DeviceVendor",
    "UnsupportedVendorError",
    "DeviceCredentials",
    "InterfaceInfo",
    "WanHealth",
    "ConnectedDevice",
    "VlanConfig",
    "DhcpPoolConfig",
    "PortForwardConfig",
    "RadiusClientConfig",
    "ProvisionResult",
    "DeviceGatewayAdapter",
]
