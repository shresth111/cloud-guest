"""Every table-driven ISP twin, in mount order.

New batches add their tuple here (and nowhere else), so the guard, gate,
body-id and seam tests -- which all iterate ``ALL_TWINS`` -- cover them by
construction.
"""

from __future__ import annotations

from .monitor_support import MONITOR_TWINS
from .twins import TwinSpec
from .twins_access import ACCESS_TWINS
from .twins_addons import ADDON_TWINS
from .twins_engage import ENGAGE_TWINS
from .twins_keys import with_aligned_key
from .twins_marketing import MARKETING_TWINS
from .twins_portal import PORTAL_TWINS
from .twins_reports import with_report_location
from .twins_security_ops import SECURITY_OPS_TWINS
from .twins_venue import VENUE_TWINS

__all__ = ["ALL_TWINS"]

ALL_TWINS: tuple[TwinSpec, ...] = tuple(
    with_aligned_key(with_report_location(spec))
    for spec in (
        VENUE_TWINS
        + PORTAL_TWINS
        + ACCESS_TWINS
        + ENGAGE_TWINS
        + SECURITY_OPS_TWINS
        + MONITOR_TWINS
        + ADDON_TWINS
        + MARKETING_TWINS
    )
)
