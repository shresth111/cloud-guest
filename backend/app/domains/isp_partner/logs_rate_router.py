"""NetLogs, events per second, across an ISP's customers (founder ask 2026-10-23).

``GET /isp/logs/netlogs/per-second`` counts ``device_log_events`` per second
of ``received_at`` for one window, with the SAME scope and filters as
``GET /isp/logs/netlogs``: ``_netlog_filters`` resolves customer / location /
router through ``IspScope`` (and the caller's confinement), and
``isp_conditions`` supplies ``organization_id = ANY(children)`` plus the
mandatory ``received_at`` window -- the partition key -- so Postgres prunes to
the one or two monthly partitions the window touches.

WHAT "PER SECOND" MEANS HERE (measured on origin/main)
------------------------------------------------------
- ``received_at`` is Vector's own receive timestamp per UDP datagram
  (``format_timestamp!(.timestamp, format: "%+")`` in
  ``deploy/device-logs/vector.yaml``): sub-second, one per line. The HTTP sink's
  2-second batching delays delivery, not the stamp.
- ``device_time`` is the router's clock in BSD-syslog form
  (``syslog-time-format=bsd-syslog``): whole seconds, no year. The series uses
  ``received_at`` (always present, one clock for every router).
- The ONE place capture is coarser than "every line": Vector's
  ``throttle_index`` keeps at most ``VECTOR_THROTTLE_PER_MINUTE`` lines per
  router per 60 s for the API index (the raw archive keeps everything). A
  minute at that ceiling is reported in ``throttled_minutes`` so a flat top in
  the chart is never read as the real rate.

Bounds: 1-second buckets, at most ``MAX_WINDOW`` (3 hours = 10,800 points).
The response is dense (zero-filled), so the chart never interpolates gaps.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.device_logs.models import DeviceLogEvent

from .constants import ISP_LOGS_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspBadRequestError
from .http import ok
from .logs_repository import isp_conditions
from .logs_router import _LIST_HELP, _netlog_filters

__all__ = ["logs_rate_router", "MAX_WINDOW", "VECTOR_THROTTLE_PER_MINUTE"]

logs_rate_router = APIRouter(prefix="/logs", tags=["ISP Partner: logs"])

#: Largest window one request may chart at 1-second resolution.
MAX_WINDOW = timedelta(hours=3)
#: Presets the console offers.
PRESET_MINUTES = (5, 15, 60)
#: ``throttle_index.threshold`` / ``window_secs`` in deploy/device-logs/vector.yaml.
VECTOR_THROTTLE_PER_MINUTE = 3000
#: A minute counts as "at the ceiling" from 98 % of it (Vector's window is
#: rolling, ours is the calendar minute).
_CEILING = int(VECTOR_THROTTLE_PER_MINUTE * 0.98)


def _window(
    minutes: int | None, since: datetime | None, until: datetime | None, now: datetime
) -> tuple[datetime, datetime]:
    if since is None and until is None:
        m = minutes or 15
        if m not in PRESET_MINUTES:
            raise IspBadRequestError("minutes must be 5, 15 or 60")
        end = now.replace(microsecond=0) + timedelta(seconds=1)
        return end - timedelta(minutes=m), end
    if since is None or until is None:
        raise IspBadRequestError("give both since and until, or neither")
    since = since if since.tzinfo else since.replace(tzinfo=UTC)
    until = until if until.tzinfo else until.replace(tzinfo=UTC)
    since = since.replace(microsecond=0)
    if until.microsecond:
        until = until.replace(microsecond=0) + timedelta(seconds=1)
    if until <= since:
        raise IspBadRequestError("until must be after since")
    if until - since > MAX_WINDOW:
        raise IspBadRequestError("a per-second chart covers at most 3 hours")
    return since, until


@logs_rate_router.get("/netlogs/per-second", dependencies=isp_guards(ISP_LOGS_READ))
async def netlogs_per_second(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp_location_id: uuid.UUID | None = Query(default=None),
    isp_router_id: uuid.UUID | None = Query(default=None),
    minutes: int | None = Query(default=None, description="5, 15 or 60 (preset)"),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    severity: list[str] | None = Query(default=None, description=_LIST_HELP),
    category: list[str] | None = Query(default=None, description=_LIST_HELP),
    protocol: list[str] | None = Query(default=None, description=_LIST_HELP),
    status: list[str] | None = Query(default=None, description=_LIST_HELP),
    q: str | None = Query(default=None, max_length=200),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    start, end = _window(minutes, since, until, datetime.now(UTC))
    service, filters, org_ids = await _netlog_filters(
        isp,
        db,
        isp_customer_id=isp_customer_id,
        isp_location_id=isp_location_id,
        isp_router_id=isp_router_id,
        since=start,
        until=end,
        severity=severity,
        category=category,
        protocol=protocol,
        status=status,
        q=q,
    )
    seconds = int((end - start).total_seconds())
    counts = [0] * seconds
    throttled: list[dict] = []
    if service.enabled and org_ids:
        conditions = isp_conditions(filters, org_ids)
        bucket = func.date_trunc("second", DeviceLogEvent.received_at).label("s")
        rows = await db.execute(
            select(bucket, func.count()).where(*conditions).group_by(bucket)
        )
        for at, n in rows.all():
            i = int((at - start).total_seconds())
            if 0 <= i < seconds:
                counts[i] = int(n)
        minute = func.date_trunc("minute", DeviceLogEvent.received_at).label("m")
        capped = await db.execute(
            select(DeviceLogEvent.router_id, minute, func.count())
            .where(*conditions)
            .group_by(DeviceLogEvent.router_id, minute)
            .having(func.count() >= _CEILING)
        )
        throttled = [
            {"router_id": str(r), "minute": m.isoformat(), "count": int(n)}
            for r, m, n in capped.all()
        ]
    total = sum(counts)
    return ok(
        request,
        {
            "feature_enabled": service.enabled,
            "since": start.isoformat(),
            "until": end.isoformat(),
            "step_seconds": 1,
            "counts": counts,
            "total": total,
            "peak": max(counts) if counts else 0,
            "clock": "received_at",
            "throttle_per_router_per_minute": VECTOR_THROTTLE_PER_MINUTE,
            "throttled_minutes": throttled,
        },
        "Network logs per second",
    )
