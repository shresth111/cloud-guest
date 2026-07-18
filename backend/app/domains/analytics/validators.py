"""Pure, side-effect-free validation for the Analytics domain.

Mirrors ``app.domains.monitoring.validators``/``app.domains.guest
.validators``'s identical discipline: no I/O, just "is this a legal input"
checks the service layer calls before touching the database.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .exceptions import InvalidAnalyticsDateRangeError


def validate_date_range(start: datetime | None, end: datetime | None) -> None:
    """Raises ``InvalidAnalyticsDateRangeError`` if both bounds are supplied
    and ``start`` is after ``end`` -- a no-op (no error) if either bound is
    absent, since an open-ended range is always legal."""
    if start is not None and end is not None and start > end:
        raise InvalidAnalyticsDateRangeError()


def day_bounds_utc(
    *, target_date_iso: str | None = None, days_ago: int = 0
) -> tuple[datetime, datetime]:
    """Returns the ``[period_start, period_end)`` UTC window for one
    "day" of aggregation.

    * ``target_date_iso`` (an ISO ``YYYY-MM-DD`` string), when given, pins
      the window to that exact calendar day's ``[00:00:00, 24:00:00)`` UTC
      bounds -- the daily Beat schedule's own "finalize yesterday" call uses
      this indirectly via ``days_ago`` (see below); a manual/on-demand
      trigger may also pass one explicitly to backfill a specific past day.
    * ``days_ago`` (default ``0``), used only when ``target_date_iso`` is
      ``None``, shifts "today" back by that many whole UTC days before
      computing the window -- ``0`` (the default, and what the 15-minute
      rolling schedule uses) means "today so far": ``period_start`` is
      today's UTC midnight, ``period_end`` is the current moment (a
      deliberately **partial**, still-open window, re-computed on every
      15-minute tick so the same ``(organization_id, snapshot_type)`` row
      keeps advancing throughout the day). ``1`` (what the daily 00:10 UTC
      schedule uses) means "yesterday, in full": a **closed**
      ``[midnight, next midnight)`` window that never changes once
      computed, the authoritative "final" snapshot for that day.
    """
    now = datetime.now(UTC)
    if target_date_iso is not None:
        target = datetime.fromisoformat(target_date_iso).replace(
            hour=0, minute=0, second=0, microsecond=0, tzinfo=UTC
        )
        return target, target + timedelta(days=1)

    today_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if days_ago <= 0:
        # "Today so far" -- a partial, still-open window.
        return today_midnight, now
    day_start = today_midnight - timedelta(days=days_ago)
    return day_start, day_start + timedelta(days=1)


__all__ = ["validate_date_range", "day_bounds_utc"]
