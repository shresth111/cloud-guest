"""SQLAlchemy ORM models for the Analytics domain (BE-012 Part 1: Analytics
Core Infrastructure).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does --
Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all keep
working uniformly.

One table: :class:`AnalyticsSnapshot` -- a pre-computed, persisted rollup
over a time window, the answer to "how do we query analytics fast across
millions of underlying ``GuestSession``/``GuestLoginHistory``/``Router``
rows without re-aggregating them on every dashboard request." This is
**not** a duplicate of ``app.domains.router_provisioning.models
.RouterHealthSnapshot`` -- that table is a per-router, point-in-time
metrics reading (CPU/memory/uptime/connected-clients for *one device*);
this table is a higher-level, organization/location/platform-scoped rollup
*across many routers and guests* for a time window. Nothing here
duplicates a single router's own health history, and nothing in
``router_provisioning`` is touched by this domain.

## Why Redis, not a second ``analytics_cache`` table

The module brief that inspired this part named ``analytics_cache`` as an
example table. This codebase already has an established, working pattern
for exactly this need -- "cache a computed result behind a TTL so a hot
read path doesn't repeat expensive work" -- in
``app.domains.rbac.cache.PermissionCache``, a Redis-backed cache with no
backing SQL table at all. A **second**, SQL-backed cache table here would
duplicate that pattern for no benefit: it would need its own TTL/eviction
logic (Postgres has no native per-row TTL), an index-maintenance cost this
table's write-heavy nature (busy dashboards re-warming a cache on every
near-miss) would make a real problem in practice, and would leave two
different "cache expiry" idioms in the same codebase to keep straight. This
domain therefore has **no** ``analytics_cache`` table: any future BE-012
part that wants request-scoped read-through caching in front of
``AnalyticsSnapshot`` queries should reuse Redis directly (the same TTL'd
key pattern ``PermissionCache`` already establishes), not add a redundant
table. See ``docs/analytics/FLOW.md`` for the full write-up of this
decision.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class AnalyticsSnapshot(BaseModel):
    """A pre-computed rollup over ``[period_start, period_end]`` for one
    ``snapshot_type`` (:class:`~.constants.AnalyticsSnapshotType`).

    ``organization_id``/``location_id`` are both nullable real foreign keys:
    ``NULL``/``NULL`` means a platform-wide snapshot
    (``PLATFORM_DAILY_SUMMARY``); ``organization_id`` set, ``location_id``
    ``NULL`` means an organization-wide snapshot (``ORG_DAILY_SUMMARY``);
    both set means a location-scoped snapshot (``LOCATION_DAILY_SUMMARY``).
    ``ondelete="SET NULL"`` on both mirrors
    ``app.domains.monitoring.models.PlatformEvent``'s identical convention
    for an optional-scope analytics/event row -- a deleted organization/
    location does not need its historical snapshots hard-deleted along with
    it, it only loses the (no-longer-resolvable) scope pointer.

    ``metrics`` (JSONB) is the actual computed numbers -- shape varies by
    ``snapshot_type``:

    * ``ORG_DAILY_SUMMARY`` / ``LOCATION_DAILY_SUMMARY`` (identical shape,
      the latter additionally scoped by ``location_id``)::

        {
          "guest_count_unique": int,
          "guest_count_new": int,
          "guest_count_returning": int,
          "session_count_total": int,
          "session_count_active": int,
          "average_session_duration_seconds": float | null,
          "total_bandwidth_bytes": int,
          "router_count_online": int,
          "router_count_offline": int,
          "router_count_total": int
        }

    * ``PLATFORM_DAILY_SUMMARY``::

        {
          "organization_count_total": int,
          "location_count_total": int,
          "router_count_online": int,
          "router_count_offline": int,
          "router_count_total": int,
          "guest_count_unique_today": int,
          "session_count_total_today": int
        }

    See ``app.domains.analytics.aggregation`` for exactly how each field is
    computed and ``docs/analytics/DATABASE.md`` for this table's full
    reference.

    ``computed_at``/``computation_duration_ms`` are the aggregation
    pipeline's own self-monitoring: when a row was actually produced (which
    may lag ``period_end`` by the Beat schedule's own cadence -- see
    ``app.core.celery_app``'s module docstring) and how long the real SQL
    aggregate queries behind it took to run, useful for noticing an
    aggregation job that is starting to slow down as data volume grows.

    ## Indexing rationale

    This table is explicitly the answer to "how do we query analytics fast
    across millions of underlying rows" -- so its own query pattern must
    itself stay fast regardless of how large it grows. The dashboard read
    path (both this part's own ``GET /analytics/snapshots`` and every later
    BE-012 part's per-domain dashboards) is always "give me the latest (or a
    date-ranged history of) snapshots for one organization/location and one
    snapshot_type" -- so
    ``(organization_id, snapshot_type, period_start)`` is indexed together
    as this table's primary query pattern (a composite index lets Postgres
    satisfy an equality-on-the-first-two-columns, range-on-the-third query
    with a single index scan instead of a full table scan or a
    bitmap-AND of two separate single-column indexes). ``location_id`` gets
    its own index for the location-scoped read path (a location is always
    also naturally scoped by its owning ``organization_id``, but is
    additionally indexed alone since ``GET /analytics/snapshots?location_id=``
    without an explicit ``organization_id`` is a legal, tenant-validated
    query -- see ``router.py``). ``period_start``/``period_end`` each get
    their own index too, for a date-range query that spans every
    organization (e.g. a future platform-wide historical trend view).
    """

    __tablename__ = "analytics_snapshots"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    snapshot_type: Mapped[str] = mapped_column(String(30), nullable=False)
    period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    granularity: Mapped[str] = mapped_column(String(20), nullable=False)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    computation_duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    __table_args__ = (
        # Primary query pattern -- see docstring's indexing rationale.
        Index(
            "ix_analytics_snapshots_org_type_period_start",
            "organization_id",
            "snapshot_type",
            "period_start",
        ),
        Index("ix_analytics_snapshots_location_id", "location_id"),
        Index("ix_analytics_snapshots_snapshot_type", "snapshot_type"),
        Index("ix_analytics_snapshots_period_start", "period_start"),
        Index("ix_analytics_snapshots_period_end", "period_end"),
    )

    def __repr__(self) -> str:
        return (
            f"<AnalyticsSnapshot(snapshot_type={self.snapshot_type}, "
            f"organization_id={self.organization_id}, "
            f"location_id={self.location_id}, period_start={self.period_start})>"
        )


__all__ = ["AnalyticsSnapshot"]
