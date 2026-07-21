"""Constants for the VLAN Management domain.

``MIN_VLAN_ID``/``MAX_VLAN_ID`` are plain module constants, not
``Settings``/``Organization.settings`` fields -- these are IEEE 802.1Q's
own protocol-level bounds, not a per-organization tunable (mirrors
``app.domains.isp.constants``'s own "no new Settings fields" discipline,
applied here to a value that is a real protocol constant rather than a
business-tunable threshold).
"""

from __future__ import annotations

# IEEE 802.1Q reserves VLAN ID 0 ("priority-tagged, no VLAN") and 4095
# ("reserved for implementation use") -- 1-4094 is the real, usable range
# every RouterOS/switch VLAN interface actually accepts.
MIN_VLAN_ID = 1
MAX_VLAN_ID = 4094


__all__ = ["MIN_VLAN_ID", "MAX_VLAN_ID"]
