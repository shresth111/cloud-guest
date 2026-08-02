"""``get_adapter(vendor)`` / ``list_supported_vendors()`` -- the ONE real
copy of the registry pattern independently reinvented six times over in
cloud-guest-repo (PRD section 2.1: ``get_isp_health_adapter``,
``get_connected_device_adapter``, ``get_device_adapter``,
``get_queue_adapter``, ``get_diagnostics_adapter``, plus the bare-function
pair in ``router/device_adapters.py``).

cloud-guest-repo should only ever import from here (and from
``wyfy_device_gateway.contract`` for types) -- never a vendor-specific
adapter module directly (see ``contract.py``'s own module docstring).
"""

from __future__ import annotations

from .contract import DeviceGatewayAdapter, DeviceVendor, UnsupportedVendorError
from .mikrotik_adapter import MikroTikAdapter
from .stub_adapters import (
    ArubaAdapter,
    CiscoMerakiAdapter,
    RuckusAdapter,
    TpLinkAdapter,
    UnifiAdapter,
)

_ADAPTERS: dict[DeviceVendor, DeviceGatewayAdapter] = {
    DeviceVendor.MIKROTIK: MikroTikAdapter(),
    DeviceVendor.TPLINK_OMADA: TpLinkAdapter(),
    DeviceVendor.RUCKUS: RuckusAdapter(),
    DeviceVendor.UNIFI: UnifiAdapter(),
    DeviceVendor.ARUBA: ArubaAdapter(),
    DeviceVendor.CISCO_MERAKI: CiscoMerakiAdapter(),
}


def get_adapter(vendor: DeviceVendor) -> DeviceGatewayAdapter:
    """Raises ``UnsupportedVendorError`` if unregistered. Exactly the
    registry pattern already used six times over in cloud-guest-repo
    (PRD section 2.1) -- consolidated here into the one real copy."""
    adapter = _ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedVendorError(vendor)
    return adapter


def list_supported_vendors() -> list[DeviceVendor]:
    return sorted(_ADAPTERS, key=lambda v: v.value)


__all__ = ["get_adapter", "list_supported_vendors"]
