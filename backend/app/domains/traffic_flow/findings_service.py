"""Findings: the reads behind ``findings.py`` and the service that runs the
five rules for one venue and period.

Computed on read, from tables that already exist. This module adds **no
table, no column, no migration and no write** -- not even an audit row or a
cache -- and it raises nothing through the alerting domain. Reasons:

* a finding is a pure function of rollups that are already retained for
  seven days, so there is nothing to store that could go stale or drift;
* a stored finding that names a device, next to a stored finding that names
  a destination, with the same venue and window on both, would be the
  beginning of the pairing the product does not keep;
* the alerting domain is rule-per-organisation with its own evaluator and
  channels. A notification version would need: an evaluator pass per venue
  with the add-on (never fleet-wide), one **organisation-scoped**
  ``alert_rules`` row per rule (a NULL organisation there means
  platform-wide, which these must never be), an open-alert key of
  (rule, venue, finding id) for de-duplication and auto-resolve, a decision
  on whether a channel message may name a destination at all (the
  small-venue rule cannot be re-applied once a message has left), and a
  scheduled refresh of the threat list. None of that is in this version.

Four statements, all venue-scoped, none of which selects a device:

* hours -- ``traffic_flow_windows`` summed per hour (byte counts and how
  many windows; no list of the window is read);
* service history -- ``traffic_flow_service_buckets`` per day for the few
  candidate services;
* addresses -- ``traffic_flow_dest_buckets`` summed per outside address,
  under the Destinations small-venue condition for a customer caller;
* window counts -- the Destinations statement itself.

The device finding is read from the venue summary (``build_summary``), the
same lower-bound list the page already shows.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol

from fastapi import status
from sqlalchemy import func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings

from .constants import (
    CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS,
    MAX_LIST_LIMIT,
    OTHER_SERVICE_PORT,
)
from .destination_buckets import TrafficFlowDestinationBucket
from .destinations import (
    DestinationRepository,
    DestinationScope,
    WindowStats,
)
from .findings import (
    BASELINE_DAYS,
    AddressRow,
    HourRow,
    Reason,
    ServiceDay,
    build_findings,
    unusual_service_candidates,
)
from .models import TrafficFlowServiceBucket, TrafficFlowWindow
from .service import TrafficFlowError, TrafficFlowSummaryService
from .threat_list import ThreatList

__all__ = [
    "CustomerFindingsService",
    "FindingsRepository",
    "TrafficFlowFindingsService",
    "address_rows_statement",
    "hour_rows_statement",
    "service_history_statement",
]

_HOUR = 3600
_DAY = 86400


def _floor(column: Any, seconds: int) -> Any:
    """Epoch floor, the grid ``findings.hour_start_of`` uses."""
    return func.to_timestamp(
        func.floor(func.extract("epoch", column) / seconds) * seconds
    )


def _in_range(model: Any, since: datetime, until: datetime) -> list[Any]:
    return [model.window_start >= since, model.window_start < until]


def hour_rows_statement(
    scope: DestinationScope, *, since: datetime, until: datetime
) -> Any:
    """The venue's client traffic per hour: two byte sums and two counts of
    windows. Reads no list of a window -- not its devices, not its
    destinations."""
    window = TrafficFlowWindow
    hour = _floor(window.window_start, _HOUR).label("hour_start")
    return (
        select(
            hour,
            func.coalesce(func.sum(window.bytes_up), 0),
            func.coalesce(func.sum(window.bytes_down), 0),
            func.count(func.distinct(window.window_start)),
            func.count(func.distinct(window.window_start)).filter(
                window.services_measured.is_(True)
            ),
        )
        .where(*_in_range(window, since, until), *scope.conditions(window))
        .group_by(hour)
        .order_by(hour)
    )


def service_history_statement(
    scope: DestinationScope,
    services: Sequence[tuple[int, int]],
    *,
    since: datetime,
    until: datetime,
) -> Any:
    """The given services' traffic at the venue per day. A service bucket
    holds no address of any kind."""
    bucket = TrafficFlowServiceBucket
    day = _floor(bucket.window_start, _DAY).label("day_start")
    return (
        select(
            day,
            bucket.protocol,
            bucket.remote_port,
            func.coalesce(func.sum(bucket.bytes_up + bucket.bytes_down), 0),
        )
        .where(
            *_in_range(bucket, since, until),
            *scope.conditions(bucket),
            tuple_(bucket.protocol, bucket.remote_port).in_(list(services)),
        )
        .group_by(day, bucket.protocol, bucket.remote_port)
    )


def address_rows_statement(
    scope: DestinationScope, *, since: datetime, until: datetime
) -> Any:
    """The venue's outside addresses in range with their sums. The
    Destinations conditions exactly: the venue (and the organisation for a
    customer), the small-venue rule (``scope.visible``), and never an
    "other" row. The table has no device column to select."""
    bucket = TrafficFlowDestinationBucket
    return (
        select(
            bucket.remote_address,
            func.coalesce(func.sum(bucket.bytes_up), 0),
            func.coalesce(func.sum(bucket.bytes_down), 0),
            func.coalesce(func.sum(bucket.flows), 0),
            func.count(func.distinct(bucket.window_start)),
        )
        .where(
            *_in_range(bucket, since, until),
            *scope.conditions(bucket),
            *scope.visible(bucket),
            bucket.remote_port != OTHER_SERVICE_PORT,
        )
        .group_by(bucket.remote_address)
    )


class FindingsRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self._destinations = DestinationRepository(session)

    async def venue_exists(self, location_id: uuid.UUID) -> bool:
        return await self._destinations.venue(location_id) is not None

    async def hour_rows(
        self, scope: DestinationScope, *, since: datetime, until: datetime
    ) -> list[HourRow]:
        rows = (
            await self.session.execute(
                hour_rows_statement(scope, since=since, until=until)
            )
        ).all()
        return [
            HourRow(start, int(up), int(down), int(windows), int(measured))
            for start, up, down, windows, measured in rows
        ]

    async def service_history(
        self,
        scope: DestinationScope,
        services: Sequence[tuple[int, int]],
        *,
        since: datetime,
        until: datetime,
    ) -> list[ServiceDay]:
        if not services:
            return []
        rows = (
            await self.session.execute(
                service_history_statement(scope, services, since=since, until=until)
            )
        ).all()
        return [
            ServiceDay(_as_day(day), int(protocol), int(port), int(nbytes))
            for day, protocol, port, nbytes in rows
        ]

    async def address_rows(
        self, scope: DestinationScope, *, since: datetime, until: datetime
    ) -> list[AddressRow]:
        rows = (
            await self.session.execute(
                address_rows_statement(scope, since=since, until=until)
            )
        ).all()
        return [
            AddressRow(str(address), int(up), int(down), int(flows), int(windows))
            for address, up, down, flows, windows in rows
        ]

    async def window_stats(
        self, scope: DestinationScope, *, since: datetime, until: datetime
    ) -> WindowStats:
        return await self._destinations.window_stats(scope, since=since, until=until)


def _as_day(value: Any) -> date:
    if isinstance(value, datetime):
        return value.astimezone(UTC).date()
    return value


class _Repository(Protocol):
    async def venue_exists(self, location_id: uuid.UUID) -> bool: ...

    async def hour_rows(
        self, scope: DestinationScope, *, since: datetime, until: datetime
    ) -> list[HourRow]: ...

    async def service_history(
        self,
        scope: DestinationScope,
        services: Sequence[tuple[int, int]],
        *,
        since: datetime,
        until: datetime,
    ) -> list[ServiceDay]: ...

    async def address_rows(
        self, scope: DestinationScope, *, since: datetime, until: datetime
    ) -> list[AddressRow]: ...

    async def window_stats(
        self, scope: DestinationScope, *, since: datetime, until: datetime
    ) -> WindowStats: ...


class _Summaries(Protocol):
    async def summary(self, **kwargs: Any) -> dict[str, Any]: ...


class TrafficFlowFindingsService:
    """The five findings for one venue and period (default the last hour,
    at most 7 days; the range rules and errors are ``/summary``'s, because
    the summary resolves the range)."""

    def __init__(
        self,
        repository: _Repository,
        summaries: _Summaries | TrafficFlowSummaryService,
        settings: Settings,
        threat: ThreatList,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.summaries = summaries
        self.settings = settings
        self.threat = threat
        self.now = now

    async def findings(
        self,
        *,
        location_id: uuid.UUID,
        since: datetime | None,
        until: datetime | None,
        organization_id: uuid.UUID | None = None,
        min_devices: int = 0,
        venue_checked: bool = False,
    ) -> dict[str, Any]:
        """``organization_id``, ``min_devices`` and ``venue_checked`` are a
        customer caller's: set by ``CustomerFindingsService``, never by a
        route."""
        if not venue_checked and not await self.repository.venue_exists(location_id):
            raise TrafficFlowError(
                "Venue not found.",
                code="TRAFFIC_FLOW_LOCATION_NOT_FOUND",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        rule = max(0, int(min_devices))
        # The same summary the venue page shows: the device finding uses its
        # lower-bound list as it is, the service finding its exact sums.
        summary = await self.summaries.summary(
            router_id=None,
            location_id=location_id,
            since=since,
            until=until,
            limit=MAX_LIST_LIMIT,
            series=1,
            min_devices_for_destinations=rule,
        )
        start = datetime.fromisoformat(summary["since"])
        end = datetime.fromisoformat(summary["until"])
        baseline_since = end - timedelta(days=BASELINE_DAYS)
        now = self.now()
        common: dict[str, Any] = {
            "location_id": str(location_id),
            "threat": self.threat,
            "now": now,
            "since": start,
            "until": end,
            "baseline_since": baseline_since,
            "min_devices": rule,
        }
        if not summary.get("feature_enabled", True) or not summary.get("measured"):
            # Flag off, or nothing in the period: nothing else is read.
            return build_findings(
                feature_enabled=bool(summary.get("feature_enabled", True)),
                summary=summary,
                hours=[],
                service_history=[],
                addresses=[],
                **common,
            )
        scope = DestinationScope(
            location_id=location_id,
            organization_id=organization_id,
            min_devices=rule,
        )
        hours = await self.repository.hour_rows(scope, since=baseline_since, until=end)
        candidates = [
            (int(item["protocol"]), int(item["port"]))
            for item in unusual_service_candidates(summary)
        ]
        history = await self.repository.service_history(
            scope, candidates, since=baseline_since, until=end
        )
        stats = await self.repository.window_stats(scope, since=start, until=end)
        usable = (
            self.threat.available
            and not self.threat.is_stale(now)
            and stats.measured > 0
        )
        addresses = (
            await self.repository.address_rows(scope, since=start, until=end)
            if usable
            else []
        )
        return build_findings(
            feature_enabled=True,
            summary=summary,
            hours=hours,
            service_history=history,
            addresses=addresses,
            windows_measured=stats.measured,
            windows_withheld=stats.withheld,
            **common,
        )


class VenueCheck(Protocol):
    async def own_location(
        self, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> uuid.UUID: ...


#: Never sent to a customer: the platform switch is not theirs to know about.
_MASTER_ONLY_FIELDS = ("feature_enabled",)


class CustomerFindingsService:
    """Findings for a customer caller.

    What a customer route must never be able to leave out is fixed here, as
    in ``CustomerDestinationService`` and ``CustomerGeoService``: the venue
    check (organisation and the caller's venue grants), the organisation on
    every statement, and the small-venue rule on the one finding that names
    a destination."""

    def __init__(
        self, findings: TrafficFlowFindingsService, venues: VenueCheck
    ) -> None:
        self._findings = findings
        self.venues = venues

    async def findings(
        self,
        location_id: uuid.UUID,
        *,
        organization_id: uuid.UUID,
        since: datetime | None,
        until: datetime | None,
    ) -> dict[str, Any]:
        own = await self.venues.own_location(location_id, organization_id)
        data = await self._findings.findings(
            location_id=own,
            since=since,
            until=until,
            organization_id=organization_id,
            min_devices=CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS,
            venue_checked=True,
        )
        for field in _MASTER_ONLY_FIELDS:
            data.pop(field, None)
        for finding in data["findings"]:
            if finding["reason"] == Reason.FEATURE_OFF.value:
                finding["reason"] = Reason.NOT_MEASURED.value
        return data
