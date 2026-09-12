"""Constants for the VLAN Management domain.

``MIN_VLAN_ID``/``MAX_VLAN_ID`` are plain module constants, not
``Settings``/``Organization.settings`` fields -- these are IEEE 802.1Q's
own protocol-level bounds, not a per-organization tunable (mirrors
``app.domains.isp.constants``'s own "no new Settings fields" discipline,
applied here to a value that is a real protocol constant rather than a
business-tunable threshold).
"""

from __future__ import annotations

from enum import StrEnum

# IEEE 802.1Q reserves VLAN ID 0 ("priority-tagged, no VLAN") and 4095
# ("reserved for implementation use") -- 1-4094 is the real, usable range
# every RouterOS/switch VLAN interface actually accepts.
MIN_VLAN_ID = 1
MAX_VLAN_ID = 4094


__all__ = ["MIN_VLAN_ID", "MAX_VLAN_ID", "DEVICE_CARRIED_FIELDS"]


class VlanDevicePushStatus(StrEnum):
    """Lifecycle of a :class:`~.models.Vlan`'s own device push.

    Distinct from ``is_enabled`` (whether the VLAN *should* exist) and
    independent of ``network_config``'s ``ConfigVersion`` status -- that
    pipeline renders a script and ships it over SSH, this is a direct
    RouterOS-API push. A row can be enabled, rendered into a config version,
    and still never have reached a device.

    * ``PENDING`` -- created, never pushed.
    * ``PROVISIONING`` -- a push is in flight right now. Written and
      committed before the first socket is opened, so a customer watching
      the row sees the work happening instead of the previous outcome. It
      also makes an interrupted push visible: a process killed mid-write
      leaves ``PROVISIONING`` rather than a stale ``ACTIVE`` that claims
      device state nobody confirmed.
    * ``ACTIVE`` -- a real device object for this VLAN exists now. Only
      ever written after the device has accepted every write, never
      optimistically.
    * ``FAILED`` -- the last push attempt raised; ``device_push_error``
      holds why, verbatim, and is what the customer is shown.
    """

    PENDING = "pending"
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    FAILED = "failed"


# Every column ``VlanService.push_vlan_to_device`` actually puts on the
# router: ``vlan_id`` and ``interface`` and ``port_mode`` decide which
# interface is created and on what, ``cidr``/``gateway_ip_address`` become
# the ``/ip address`` line (see ``VlanService._device_address``),
# ``enable_hotspot`` creates or deletes the portal, and ``nat_enabled``
# creates or deletes the masquerade rule. Changing any of them makes an
# ``ACTIVE`` row describe something the device is not carrying -- see
# ``app.common.device_push``.
#
# ``name`` is not here: the gateway reaches the interface by the
# deterministic ``vlan{vlan_id}`` and carries ``name`` only as the
# interface's own RouterOS comment (``mikrotik_adapter._configure_vlan_trunk``),
# so a rename changes a label, not the network. Nor is ``description``
# (never leaves the database) or ``is_enabled`` (intent -- see
# ``app.common.device_push``'s own note).
DEVICE_CARRIED_FIELDS = frozenset(
    {
        "vlan_id",
        "interface",
        "port_mode",
        "cidr",
        "gateway_ip_address",
        "enable_hotspot",
        "nat_enabled",
    }
)
