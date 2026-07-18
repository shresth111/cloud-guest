"""Enumerations and small constants for the Analytics domain (BE-012 Part 1:
Analytics Core Infrastructure).

Stored as plain ``String`` columns on the ORM model (mirroring every other
domain's own convention -- e.g. ``app.domains.monitoring.constants``) rather
than native PostgreSQL enum types, so adding a new snapshot type in a later
BE-012 part never requires an ``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum


class AnalyticsSnapshotType(StrEnum):
    """The kind of rollup a :class:`~.models.AnalyticsSnapshot` row
    represents.

    This part deliberately seeds a small, real set that this part actually
    populates -- ``ORG_DAILY_SUMMARY``/``LOCATION_DAILY_SUMMARY``/
    ``PLATFORM_DAILY_SUMMARY`` -- rather than pre-enumerating every future
    dashboard's snapshot type (per-domain analytics, forecasting, and
    reporting/export snapshot types are later BE-012 parts' job to add,
    additively, to this same enum). See ``models.AnalyticsSnapshot``'s
    docstring for the exact ``metrics`` JSONB schema per type.

    * ``ORG_DAILY_SUMMARY`` -- one organization's guest/session/router
      rollup for one day. ``organization_id`` populated, ``location_id``
      ``NULL``.
    * ``LOCATION_DAILY_SUMMARY`` -- the same shape, scoped to one location.
      Both ``organization_id`` (the location's owning organization) and
      ``location_id`` populated.
    * ``PLATFORM_DAILY_SUMMARY`` -- platform-wide totals across every
      organization/location/router. Both ``organization_id`` and
      ``location_id`` ``NULL`` (the "platform-wide" convention this
      domain's own ``AnalyticsSnapshot.organization_id``/``location_id``
      docstring establishes).
    """

    ORG_DAILY_SUMMARY = "org_daily_summary"
    LOCATION_DAILY_SUMMARY = "location_daily_summary"
    PLATFORM_DAILY_SUMMARY = "platform_daily_summary"


class AnalyticsGranularity(StrEnum):
    """The time-bucket width a snapshot's ``[period_start, period_end]``
    window represents. This part only ever populates ``DAILY`` rows (see
    ``AnalyticsSnapshotType``'s docstring) -- ``HOURLY``/``WEEKLY``/
    ``MONTHLY`` are defined now, ready for a later part's rollup without a
    migration, the same "defined, not yet produced" posture
    ``app.domains.monitoring.constants.HeartbeatComponentType.WIREGUARD_PEER``
    already establishes for an enum member with no current writer.
    """

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


DEFAULT_LIST_PAGE = 1
DEFAULT_LIST_PAGE_SIZE = 25

# Celery task names -- kept as constants (rather than re-deriving the string
# in more than one place) so `app.core.celery_app`'s `beat_schedule` and
# `app.domains.analytics.tasks`'s `@celery_app.task(name=...)` decorators
# can never silently drift apart.
TASK_RUN_DAILY_AGGREGATION_FOR_ALL_ORGANIZATIONS = (
    "app.domains.analytics.tasks.run_daily_aggregation_for_all_organizations"
)
TASK_RUN_DAILY_AGGREGATION_FOR_ORGANIZATION = (
    "app.domains.analytics.tasks.run_daily_aggregation_for_organization"
)

__all__ = [
    "AnalyticsSnapshotType",
    "AnalyticsGranularity",
    "DEFAULT_LIST_PAGE",
    "DEFAULT_LIST_PAGE_SIZE",
    "TASK_RUN_DAILY_AGGREGATION_FOR_ALL_ORGANIZATIONS",
    "TASK_RUN_DAILY_AGGREGATION_FOR_ORGANIZATION",
]
