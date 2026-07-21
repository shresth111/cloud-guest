"""Constants for the Hotspot Settings domain.

Plain module constants, not ``Settings``/``Organization.settings``
fields -- mirrors ``app.domains.isp.constants``'s own "no new Settings
fields" discipline; per-organization tunability is a real future seam,
not implemented in this first pass.
"""

from __future__ import annotations

# A generous but real bound on how many walled-garden hosts one profile
# may list -- a real, documented limit (never a silent, unbounded list)
# guarding against an accidental multi-megabyte JSONB payload.
MAX_WALLED_GARDEN_HOSTS = 200

__all__ = ["MAX_WALLED_GARDEN_HOSTS"]
