"""Pure, side-effect-free validation for the Monitoring domain.

Mirrors ``app.domains.guest.validators``/``app.domains.wireguard
.validators``'s identical discipline: no I/O, just "is this a legal input"
checks (or, for ``classify_storage_health``, a pure classification
function) the service layer calls before/around touching the database or
filesystem.
"""

from __future__ import annotations

from datetime import datetime

from .constants import (
    STORAGE_DEGRADED_USED_PERCENT,
    STORAGE_UNHEALTHY_USED_PERCENT,
    HealthStatus,
)
from .exceptions import InvalidEventDateRangeError


def validate_date_range(start: datetime | None, end: datetime | None) -> None:
    """Raises ``InvalidEventDateRangeError`` if both bounds are supplied and
    ``start`` is after ``end`` -- a no-op (no error) if either bound is
    absent, since an open-ended range is always legal."""
    if start is not None and end is not None and start > end:
        raise InvalidEventDateRangeError()


def classify_storage_health(*, percent_used: float, writable: bool) -> HealthStatus:
    """Pure percent-used/writability -> ``HealthStatus`` classification for
    ``service.MonitoringService.check_storage_health`` -- kept separate from
    the ``shutil.disk_usage``/``os.access`` I/O itself so the threshold
    logic can be tested deterministically without depending on the actual
    disk the test happens to run on (see ``tests/unit/test_monitoring.py``).

    An unwritable log directory is always ``UNHEALTHY`` regardless of free
    space -- a full disk and a permissions problem both mean the same thing
    in practice (structured logging can no longer be written), so there is
    no useful ``DEGRADED`` distinction to draw for the not-writable case."""
    if not writable:
        return HealthStatus.UNHEALTHY
    if percent_used >= STORAGE_UNHEALTHY_USED_PERCENT:
        return HealthStatus.UNHEALTHY
    if percent_used >= STORAGE_DEGRADED_USED_PERCENT:
        return HealthStatus.DEGRADED
    return HealthStatus.HEALTHY


__all__ = [
    "validate_date_range",
    "classify_storage_health",
]
