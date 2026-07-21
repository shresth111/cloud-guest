"""Constants for the DHCP Pool Management domain.

``DEFAULT_LEASE_TIME_SECONDS`` is a plain module constant, not a
``Settings``/``Organization.settings`` field -- mirrors
``app.domains.isp.constants``'s own "no new Settings fields" discipline;
per-organization tunability is a real future seam, not implemented in
this first pass.
"""

from __future__ import annotations

# RouterOS's own default DHCP lease time is 1 day -- used as this domain's
# own default when a caller doesn't supply one.
DEFAULT_LEASE_TIME_SECONDS = 86_400

__all__ = ["DEFAULT_LEASE_TIME_SECONDS"]
