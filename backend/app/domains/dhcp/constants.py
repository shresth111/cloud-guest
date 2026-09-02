"""Constants for the DHCP Pool Management domain.

``DEFAULT_LEASE_TIME_SECONDS`` is a plain module constant, not a
``Settings``/``Organization.settings`` field -- mirrors
``app.domains.isp.constants``'s own "no new Settings fields" discipline;
per-organization tunability is a real future seam, not implemented in
this first pass.
"""

from __future__ import annotations

from enum import StrEnum

# RouterOS's own default DHCP lease time is 1 day -- used as this domain's
# own default when a caller doesn't supply one.
DEFAULT_LEASE_TIME_SECONDS = 86_400

__all__ = ["DEFAULT_LEASE_TIME_SECONDS", "DhcpDevicePushStatus"]


class DhcpDevicePushStatus(StrEnum):
    """Lifecycle of a :class:`~.models.DhcpPool`'s own device push.

    Distinct from ``is_enabled``, which is intent ("this pool should
    exist"), and independent of ``network_config``'s ``ConfigVersion``
    status -- that pipeline renders a script and ships it over SSH on port
    22, which is filtered on the fleet; this is a direct RouterOS-API push
    on 8728. A pool can be enabled, rendered into a config version, and
    still never have reached a device.

    * ``PENDING`` -- created, never pushed. The state every pre-existing
      row is backfilled to, truthfully: until now no code path could push
      one.
    * ``ACTIVE`` -- a real ``/ip pool`` + ``/ip dhcp-server`` +
      ``/ip dhcp-server network`` triple for this row exists on the router.
    * ``FAILED`` -- the last push attempt raised; ``device_push_error``
      holds the device's own words.
    """

    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"
