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
from .controller_contract import ControllerAdapter, ControllerVendor
from .mikrotik_adapter import MikroTikAdapter
from .omada.adapter import OmadaControllerAdapter
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


# -- controller adapters ---------------------------------------------------
#
# A second, parallel registry for controller-mediated vendors. It is separate
# from ``_ADAPTERS`` above for the same reason ``ControllerAdapter`` is
# separate from ``DeviceGatewayAdapter``: the two Protocols are not
# interchangeable, so one registry returning either type would force every
# caller to narrow the result before it could use it (see
# ``controller_contract.py``'s module docstring).
#
# Note that ``DeviceVendor.TPLINK_OMADA`` and ``ControllerVendor.TPLINK_OMADA``
# have the same string value but mean different things:
# ``get_adapter(DeviceVendor.TPLINK_OMADA)`` still returns the unimplemented
# per-device ``TpLinkAdapter`` stub, exactly as before. The real Omada
# integration is controller-level and is reached only through
# ``get_controller_adapter``.
#
# A single shared instance per vendor, deliberately: ``OmadaControllerAdapter``
# holds a session cache, and handing out a new instance per call would throw
# away every cached login and re-authenticate on every guest.
_CONTROLLER_ADAPTERS: dict[ControllerVendor, ControllerAdapter] = {
    ControllerVendor.TPLINK_OMADA: OmadaControllerAdapter(),
}


def get_controller_adapter(vendor: ControllerVendor) -> ControllerAdapter:
    """Raises ``UnsupportedVendorError`` if unregistered.

    The controller-side twin of ``get_adapter``. Reuses
    ``UnsupportedVendorError`` rather than defining a near-identical second
    exception, so a caller that handles "we do not support that vendor" keeps
    working across both registries.
    """
    adapter = _CONTROLLER_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedVendorError(vendor)
    return adapter


def list_supported_controller_vendors() -> list[ControllerVendor]:
    return sorted(_CONTROLLER_ADAPTERS, key=lambda v: v.value)


__all__ = [
    "get_adapter",
    "get_controller_adapter",
    "list_supported_controller_vendors",
    "list_supported_vendors",
]
