"""Analytics business logic (BE-012 Part 1): persisting
``AnalyticsSnapshot`` rows computed by ``aggregation.py``, the batch
aggregation pipeline (with per-organization failure isolation), the
manual/on-demand trigger, and read methods the (not-yet-built) dashboard
endpoints in later BE-012 parts will call.
"""

from __future__ import annotations

import dataclasses
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.core.logging import get_logger
from app.database.utils.pagination import PaginationMeta

from .aggregation import (
    GuestAnalyticsLookupProtocol,
    compute_location_daily_summary,
    compute_org_daily_summary,
    compute_platform_daily_summary,
)
from .constants import AnalyticsGranularity, AnalyticsSnapshotType
from .events import (
    AnalyticsAggregationBatchCompleted,
    AnalyticsAggregationForOrganizationFailed,
    AnalyticsSnapshotComputed,
)
from .exceptions import AnalyticsOrganizationNotFoundError
from .models import AnalyticsSnapshot
from .repository import AnalyticsRepositoryProtocol
from .validators import day_bounds_utc, validate_date_range

logger = get_logger(__name__)


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick to ``app.domains.monitoring.service``/``app.domains
    .guest.service``'s own ``_event_extra``."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


@dataclass(frozen=True, slots=True)
class AggregationBatchResult:
    """The outcome of one ``AnalyticsService.run_daily_aggregation_for_all_
    organizations`` pass -- one organization's aggregation failing is
    recorded here (and logged), never allowed to abort the rest of the
    batch (see that method's own docstring)."""

    total_organizations: int
    succeeded_organizations: int
    failed_organizations: list[tuple[uuid.UUID, str]] = field(default_factory=list)


class AnalyticsService:
    """Core Analytics business logic: computing + persisting snapshots
    (composing ``aggregation.py``'s pure computation with
    ``AnalyticsRepositoryProtocol``'s persistence), the batch pipeline, and
    read-side queries."""

    def __init__(
        self,
        repository: AnalyticsRepositoryProtocol,
        guest_analytics: GuestAnalyticsLookupProtocol,
    ) -> None:
        self.repository = repository
        self.guest_analytics = guest_analytics

    # ========================================================================
    # Compute + persist one snapshot
    # ========================================================================

    async def compute_and_store_org_daily_summary(
        self,
        *,
        organization_id: uuid.UUID,
        period_start: datetime,
        period_end: datetime,
    ) -> AnalyticsSnapshot:
        started = time.perf_counter()
        metrics = await compute_org_daily_summary(
            organization_id=organization_id,
            period_start=period_start,
            period_end=period_end,
            guest_analytics=self.guest_analytics,
            repository=self.repository,
        )
        return await self._persist_snapshot(
            organization_id=organization_id,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY,
            period_start=period_start,
            period_end=period_end,
            metrics=metrics,
            started=started,
        )

    async def compute_and_store_location_daily_summary(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        period_start: datetime,
        period_end: datetime,
    ) -> AnalyticsSnapshot:
        started = time.perf_counter()
        metrics = await compute_location_daily_summary(
            organization_id=organization_id,
            location_id=location_id,
            period_start=period_start,
            period_end=period_end,
            guest_analytics=self.guest_analytics,
            repository=self.repository,
        )
        return await self._persist_snapshot(
            organization_id=organization_id,
            location_id=location_id,
            snapshot_type=AnalyticsSnapshotType.LOCATION_DAILY_SUMMARY,
            period_start=period_start,
            period_end=period_end,
            metrics=metrics,
            started=started,
        )

    async def compute_and_store_platform_daily_summary(
        self, *, period_start: datetime, period_end: datetime
    ) -> AnalyticsSnapshot:
        started = time.perf_counter()
        metrics = await compute_platform_daily_summary(
            period_start=period_start,
            period_end=period_end,
            repository=self.repository,
        )
        return await self._persist_snapshot(
            organization_id=None,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.PLATFORM_DAILY_SUMMARY,
            period_start=period_start,
            period_end=period_end,
            metrics=metrics,
            started=started,
        )

    async def _persist_snapshot(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        snapshot_type: AnalyticsSnapshotType,
        period_start: datetime,
        period_end: datetime,
        metrics: dict[str, object],
        started: float,
    ) -> AnalyticsSnapshot:
        computation_duration_ms = round((time.perf_counter() - started) * 1000, 3)
        snapshot = await self.repository.create_snapshot(
            organization_id=organization_id,
            location_id=location_id,
            snapshot_type=snapshot_type.value,
            period_start=period_start,
            period_end=period_end,
            granularity=AnalyticsGranularity.DAILY.value,
            metrics=metrics,
            computed_at=datetime.now(UTC),
            computation_duration_ms=computation_duration_ms,
        )
        event = AnalyticsSnapshotComputed(
            snapshot_id=snapshot.id,
            snapshot_type=snapshot_type.value,
            organization_id=organization_id,
            location_id=location_id,
            computation_duration_ms=computation_duration_ms,
        )
        logger.info("analytics_snapshot_computed", extra=_event_extra(event))
        return snapshot

    # ========================================================================
    # Batch pipeline (Beat-scheduled / manual trigger)
    # ========================================================================

    async def run_daily_aggregation_for_organization(
        self,
        organization_id: uuid.UUID,
        *,
        target_date_iso: str | None = None,
        days_ago: int = 0,
    ) -> list[AnalyticsSnapshot]:
        """Computes and persists one organization's ``ORG_DAILY_SUMMARY``
        plus every one of its active locations' ``LOCATION_DAILY_SUMMARY``
        for one day's window. Callable individually -- useful for
        on-demand/manual triggering (``trigger_aggregation``) and for
        tests, not just as part of the platform-wide batch below."""
        period_start, period_end = day_bounds_utc(
            target_date_iso=target_date_iso, days_ago=days_ago
        )
        snapshots = [
            await self.compute_and_store_org_daily_summary(
                organization_id=organization_id,
                period_start=period_start,
                period_end=period_end,
            )
        ]
        location_ids = await self.repository.list_active_location_ids_for_organization(
            organization_id
        )
        for location_id in location_ids:
            snapshots.append(
                await self.compute_and_store_location_daily_summary(
                    organization_id=organization_id,
                    location_id=location_id,
                    period_start=period_start,
                    period_end=period_end,
                )
            )
        return snapshots

    async def run_daily_aggregation_for_all_organizations(
        self,
        *,
        target_date_iso: str | None = None,
        days_ago: int = 0,
    ) -> AggregationBatchResult:
        """The Beat-scheduled periodic task's actual work: iterates every
        active organization (and each one's active locations), computing
        and persisting snapshots, then computes the one platform-wide
        snapshot for the same window.

        **Per-organization failure isolation**: one organization's
        aggregation raising (a bad row, a transient DB hiccup scoped to
        that tenant's data) is caught, logged, and recorded in the returned
        result's ``failed_organizations`` -- it never aborts the rest of
        the batch. This mirrors the exact resilience posture
        ``app.domains.monitoring.service.NotificationService
        .dispatch_notification`` already establishes for BE-011 Part 2's
        alert notifications (one channel's delivery failure is logged, not
        propagated, and never blocks any other channel's delivery) --
        the identical principle applied to aggregation-over-many-tenants
        instead of dispatch-to-many-channels. The platform-wide snapshot is
        still computed even if some organizations failed, since it is an
        independent, whole-table aggregate query, not a sum of the
        per-organization results.
        """
        period_start, period_end = day_bounds_utc(
            target_date_iso=target_date_iso, days_ago=days_ago
        )
        organization_ids = await self.repository.list_active_organization_ids()
        succeeded = 0
        failed: list[tuple[uuid.UUID, str]] = []
        for organization_id in organization_ids:
            try:
                await self.run_daily_aggregation_for_organization(
                    organization_id,
                    target_date_iso=target_date_iso,
                    days_ago=days_ago,
                )
                succeeded += 1
            except Exception as exc:  # noqa: BLE001 -- per-org isolation, see docstring
                logger.error(
                    "analytics_aggregation_failed_for_organization",
                    extra=_event_extra(
                        AnalyticsAggregationForOrganizationFailed(
                            organization_id=organization_id, error=str(exc)
                        )
                    ),
                )
                failed.append((organization_id, str(exc)))

        await self.compute_and_store_platform_daily_summary(
            period_start=period_start, period_end=period_end
        )

        result = AggregationBatchResult(
            total_organizations=len(organization_ids),
            succeeded_organizations=succeeded,
            failed_organizations=failed,
        )
        batch_event = AnalyticsAggregationBatchCompleted(
            total_organizations=result.total_organizations,
            succeeded_organizations=result.succeeded_organizations,
            failed_organizations=len(result.failed_organizations),
        )
        logger.info(
            "analytics_aggregation_batch_completed", extra=_event_extra(batch_event)
        )
        return result

    async def trigger_aggregation(
        self, organization_id: uuid.UUID, *, target_date_iso: str | None = None
    ) -> list[AnalyticsSnapshot]:
        """On-demand, manual recomputation for one organization (used by
        ``POST /analytics/snapshots/trigger``). Validates the organization
        actually exists first -- a manual trigger for a bogus id should
        fail loudly, not silently persist an empty-metrics snapshot.
        ``target_date_iso`` (``YYYY-MM-DD``) optionally backfills a specific
        past day instead of computing today's still-partial window."""
        if not await self.repository.organization_exists(organization_id):
            raise AnalyticsOrganizationNotFoundError(organization_id)
        return await self.run_daily_aggregation_for_organization(
            organization_id, target_date_iso=target_date_iso
        )

    # ========================================================================
    # Read-side queries
    # ========================================================================

    async def get_latest_snapshot(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        snapshot_type: AnalyticsSnapshotType,
    ) -> AnalyticsSnapshot | None:
        return await self.repository.get_latest_snapshot(
            organization_id=organization_id,
            location_id=location_id,
            snapshot_type=snapshot_type.value,
        )

    async def list_snapshots(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        snapshot_type: AnalyticsSnapshotType | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[AnalyticsSnapshot], PaginationMeta]:
        validate_date_range(start, end)
        return await self.repository.list_snapshots(
            organization_id=organization_id,
            location_id=location_id,
            snapshot_type=snapshot_type.value if snapshot_type is not None else None,
            start=start,
            end=end,
            page=page,
            page_size=page_size,
        )


__all__ = ["AnalyticsService", "AggregationBatchResult"]
