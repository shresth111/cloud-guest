"""Every table-driven ISP twin, in mount order.

New batches add their tuple here (and nowhere else), so the guard, gate,
body-id and seam tests -- which all iterate ``ALL_TWINS`` -- cover them by
construction.
"""

from __future__ import annotations

from .monitor_support import MONITOR_TWINS
from .twins import TwinSpec
from .twins_portal import PORTAL_TWINS
from .twins_security_ops import SECURITY_OPS_TWINS
from .twins_venue import VENUE_TWINS

__all__ = ["ALL_TWINS"]

ALL_TWINS: tuple[TwinSpec, ...] = (
    VENUE_TWINS + PORTAL_TWINS + SECURITY_OPS_TWINS + MONITOR_TWINS
)
