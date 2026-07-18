"""Prometheus metrics for the CloudGuest backend (BE-011 Part 4:
Observability).

Two, deliberately different, architectures are used here, chosen per
metric based on where its data genuinely lives:

1. **HTTP-level metrics** (``cloudguest_http_requests_total``,
   ``cloudguest_http_request_duration_seconds``) are updated **inline**, by
   :class:`PrometheusMiddleware`, at the moment each request completes.
   There is no other honest way to measure per-request latency/outcome --
   nothing in the database records "a request happened", so an inline ASGI
   middleware hook is the only correct architecture for these two, and a
   ~30-line pure-ASGI middleware (stdlib ``time.perf_counter``, no
   third-party instrumentator) is all a request-counter/latency-histogram
   needs -- see ``PrometheusMiddleware``'s own docstring for why a heavier
   dependency (e.g. ``prometheus-fastapi-instrumentator``) was not added
   for this.

2. **Business metrics** (``cloudguest_health_check_status``,
   ``cloudguest_alerts_triggered_total``, ``cloudguest_guest_sessions_active``,
   ``cloudguest_provisioning_jobs_total``) are **on-scrape collectors**:
   every value is a fresh read of current database state, computed inside
   ``refresh_business_metrics`` and set onto module-level ``Gauge``s the
   moment ``GET /metrics`` is hit -- never incremented inline from within
   ``app.domains.monitoring``/``app.domains.guest``/
   ``app.domains.router_provisioning``'s own business logic. This is the
   strongly-preferred architecture per this module's own directory rule:
   it requires **zero edits** to any of those three domains' files, the
   same "read another domain's table directly, read-only, compose instead
   of duplicate" precedent ``app.domains.monitoring.repository`` already
   established for ``Router``/``ProvisioningJob``/``RadiusNasClient``/
   ``WireGuardPeer`` (see that module's own docstring). An inline
   increment-on-event hook was considered for
   ``cloudguest_alerts_triggered_total`` specifically (increment a Counter
   from inside ``AlertService``'s alert-creation method) and rejected: it
   is not needed (an on-scrape ``COUNT(*) ... GROUP BY severity`` query
   against the already-indexed ``alerts.severity`` column is cheap and
   exactly as accurate as an inline increment, with no risk of the metric
   drifting from the database if a scrape is ever missed or the process
   restarts), and it would have spent this part's one permitted
   cross-domain edit for zero real benefit. **No file inside
   ``app.domains.monitoring``/``app.domains.guest``/
   ``app.domains.router_provisioning`` is edited by this module.**

## Why business metrics are ``Gauge``s, not ``Counter``s, despite the
   ``_total`` suffix on two of their names

``cloudguest_alerts_triggered_total`` and ``cloudguest_provisioning_jobs_total``
keep the ``_total`` names the module brief specified (so the Grafana
dashboard/any external consumer can rely on them), but both are
implemented as Prometheus ``Gauge``s, not ``Counter``s:

* ``prometheus_client.Counter`` only exposes ``.inc()`` -- there is no
  public API to set it to an arbitrary absolute value on every scrape (the
  private ``_value.set(...)`` escape hatch exists, but reaching for a
  private API to mimic a public one is not worth it here).
* ``cloudguest_provisioning_jobs_total`` is a **current** breakdown by
  status (queued/running/succeeded/failed) -- a job moving from ``queued``
  to ``running`` makes the ``queued`` count go *down*, which is a ``Gauge``
  by definition, not a monotonic counter, regardless of the name.
* ``cloudguest_alerts_triggered_total`` *is* effectively monotonic in
  practice (rows are soft-deleted, never hard-deleted, so the all-time
  count per severity only grows) -- but a ``Gauge`` re-``set()`` to the
  same fresh ``COUNT(*)`` result on every scrape is observably identical
  to a ``Counter`` for every real consumer (``rate()``/``increase()`` over
  a monotonically-non-decreasing ``Gauge`` behave exactly as they would
  over a ``Counter``; Grafana panels in the provided dashboard use
  ``sum by (severity) (...)`` , which is agnostic to the distinction).

Every reader of this module (this file, the Grafana dashboard JSON, and
``docs/monitoring/OBSERVABILITY.md``) is consistent about this, so nothing
here is a hidden surprise.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Protocol

from fastapi import APIRouter, Depends, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.database.session import get_db_session
from app.domains.guest.constants import GuestSessionStatus
from app.domains.guest.models import GuestSession
from app.domains.monitoring.constants import AlertSeverity, HealthStatus
from app.domains.monitoring.models import ServiceHealth
from app.domains.monitoring.repository import MonitoringRepository
from app.domains.router_provisioning.constants import ProvisioningJobStatus
from app.domains.router_provisioning.models import ProvisioningJob

# ============================================================================
# HTTP-level metrics (inline, via PrometheusMiddleware)
# ============================================================================

HTTP_REQUESTS_TOTAL = Counter(
    "cloudguest_http_requests_total",
    "Total HTTP requests processed, by method/path/status code.",
    ["method", "path", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "cloudguest_http_request_duration_seconds",
    "HTTP request latency in seconds, by method/path.",
    ["method", "path"],
)


class PrometheusMiddleware:
    """A minimal, dependency-free ASGI middleware timing every HTTP
    request and recording its outcome.

    Deliberately a ~30-line pure-ASGI class (``time.perf_counter`` plus two
    module-level ``prometheus_client`` metrics) rather than a third-party
    instrumentator package (e.g. ``prometheus-fastapi-instrumentator``):
    the only two things this needs -- "how long did the request take" and
    "what status code did it finish with" -- are both directly observable
    from the ASGI ``send`` callable's ``http.response.start`` message with
    no framework-specific magic required, so a heavier dependency would add
    surface area for zero functional gain.

    ``path`` is taken from ``scope["route"].path`` (the matched route's
    *template*, e.g. ``/api/v1/guest/sessions/{session_id}``) rather than
    the raw request path, read *after* ``self.app(...)`` returns (Starlette
    populates ``scope["route"]`` during routing, before the endpoint runs,
    and ``scope`` is mutated in place) -- this keeps label cardinality
    bounded to the fixed set of registered routes instead of exploding with
    one label value per distinct UUID/path segment ever requested. Falls
    back to the raw path for genuinely unmatched routes (e.g. a 404), where
    no route was ever matched.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "UNKNOWN")
        status_code = 500
        start_time = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_seconds = time.perf_counter() - start_time
            route = scope.get("route")
            path = getattr(route, "path", None) or scope.get("path", "unknown")
            HTTP_REQUESTS_TOTAL.labels(
                method=method, path=path, status_code=str(status_code)
            ).inc()
            HTTP_REQUEST_DURATION_SECONDS.labels(method=method, path=path).observe(
                duration_seconds
            )


# ============================================================================
# Business metrics (on-scrape collectors -- see module docstring)
# ============================================================================

HEALTH_CHECK_STATUS = Gauge(
    "cloudguest_health_check_status",
    (
        "Current rolled-up health status per platform component "
        "(1=healthy, 0=degraded, -1=unhealthy, -2=unknown), from "
        "app.domains.monitoring's ServiceHealth rollup table."
    ),
    ["component"],
)

# healthy/degraded/unhealthy map onto the module brief's literal 1/0/-1;
# `unknown` (app.domains.monitoring.constants.HealthStatus.UNKNOWN -- an
# honestly-not-fabricated result, e.g. celery/websocket before any real
# infrastructure exists) gets its own distinct sentinel rather than being
# folded into `unhealthy`, so a dashboard can tell "known bad" from
# "nothing to judge from yet" apart.
_HEALTH_STATUS_VALUES: dict[str, float] = {
    HealthStatus.HEALTHY.value: 1.0,
    HealthStatus.DEGRADED.value: 0.0,
    HealthStatus.UNHEALTHY.value: -1.0,
    HealthStatus.UNKNOWN.value: -2.0,
}

ALERTS_TRIGGERED_TOTAL = Gauge(
    "cloudguest_alerts_triggered_total",
    (
        "All-time count of alerts ever triggered, by severity, from "
        "app.domains.monitoring's Alert table (see module docstring for "
        "why this is a Gauge re-set from a fresh COUNT(*) on every scrape, "
        "not an inline-incremented Counter)."
    ),
    ["severity"],
)

GUEST_SESSIONS_ACTIVE = Gauge(
    "cloudguest_guest_sessions_active",
    (
        "Current count of guest sessions with status=active, from "
        "app.domains.guest's GuestSession table."
    ),
)

PROVISIONING_JOBS_TOTAL = Gauge(
    "cloudguest_provisioning_jobs_total",
    (
        "Current count of provisioning jobs by status, from "
        "app.domains.router_provisioning's ProvisioningJob table."
    ),
    ["status"],
)

# A fixed lower bound for the "all-time" alert window
# ``compute_alert_counts_by_severity`` is called with -- see
# ``ObservabilityMetricsRepository.compute_alert_counts_by_severity``.
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class ObservabilityRepositoryProtocol(Protocol):
    """The narrow, read-only surface ``refresh_business_metrics`` needs.
    Mirrors every other domain's own ``*RepositoryProtocol`` pattern
    (``app.domains.monitoring.repository.MonitoringRepositoryProtocol``,
    etc.) so unit tests can exercise ``refresh_business_metrics`` against a
    small hand-rolled fake, the same style already used throughout
    ``tests/unit/test_monitoring*.py``, with no live Postgres required."""

    async def list_service_health(self) -> list[ServiceHealth]: ...

    async def compute_alert_counts_by_severity(self) -> list[tuple[str, int]]: ...

    async def count_active_guest_sessions(self) -> int: ...

    async def count_provisioning_jobs_by_status(self) -> list[tuple[str, int]]: ...


class ObservabilityMetricsRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``ObservabilityRepositoryProtocol``.

    ``list_service_health``/``compute_alert_counts_by_severity`` **reuse**
    ``app.domains.monitoring.repository.MonitoringRepository`` directly --
    that module already owns ``ServiceHealth``/``Alert`` and already
    exposes exactly these two read methods, so this composes with it
    rather than re-implementing the same queries.

    ``count_active_guest_sessions``/``count_provisioning_jobs_by_status``
    query ``app.domains.guest.models.GuestSession``/
    ``app.domains.router_provisioning.models.ProvisioningJob`` directly,
    read-only -- neither domain's own repository exposes a *platform-wide*
    (not organization-scoped) count, because neither has ever needed one
    for its own per-tenant dashboards. This is the identical "read another
    domain's table directly" precedent
    ``app.domains.monitoring.repository`` itself already establishes for
    ``Router``/``ProvisioningJob``/``RadiusNasClient``/``WireGuardPeer`` --
    no file inside ``app.domains.guest``/``app.domains.router_provisioning``
    is edited to make this work.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._monitoring_repository = MonitoringRepository(session)

    async def list_service_health(self) -> list[ServiceHealth]:
        return await self._monitoring_repository.list_service_health()

    async def compute_alert_counts_by_severity(self) -> list[tuple[str, int]]:
        return await self._monitoring_repository.compute_alert_counts_by_severity(
            start=_EPOCH, end=datetime.now(UTC)
        )

    async def count_active_guest_sessions(self) -> int:
        statement = (
            select(func.count())
            .select_from(GuestSession)
            .where(
                GuestSession.status == GuestSessionStatus.ACTIVE.value,
                GuestSession.is_deleted.is_(False),
            )
        )
        result = await self._session.execute(statement)
        return int(result.scalar_one())

    async def count_provisioning_jobs_by_status(self) -> list[tuple[str, int]]:
        statement = (
            select(ProvisioningJob.status, func.count())
            .where(ProvisioningJob.is_deleted.is_(False))
            .group_by(ProvisioningJob.status)
        )
        result = await self._session.execute(statement)
        return [(row[0], int(row[1])) for row in result.all()]


async def refresh_business_metrics(repository: ObservabilityRepositoryProtocol) -> None:
    """Query current database state through ``repository`` and set every
    business ``Gauge`` to a fresh value. Called once per ``GET /metrics``
    scrape (see ``get_metrics`` below) -- see module docstring for why this
    is the preferred architecture for DB-backed metrics over inline
    increments."""
    unknown_value = _HEALTH_STATUS_VALUES[HealthStatus.UNKNOWN]
    for row in await repository.list_service_health():
        HEALTH_CHECK_STATUS.labels(component=row.component).set(
            _HEALTH_STATUS_VALUES.get(row.status, unknown_value)
        )

    severity_counts = dict(await repository.compute_alert_counts_by_severity())
    for severity in AlertSeverity:
        ALERTS_TRIGGERED_TOTAL.labels(severity=severity.value).set(
            severity_counts.get(severity.value, 0)
        )

    GUEST_SESSIONS_ACTIVE.set(await repository.count_active_guest_sessions())

    job_status_counts = dict(await repository.count_provisioning_jobs_by_status())
    for job_status in ProvisioningJobStatus:
        PROVISIONING_JOBS_TOTAL.labels(status=job_status.value).set(
            job_status_counts.get(job_status.value, 0)
        )


async def get_observability_repository(
    db: AsyncSession = Depends(get_db_session),
) -> ObservabilityRepositoryProtocol:
    return ObservabilityMetricsRepository(db)


# ============================================================================
# GET /metrics -- the standard Prometheus scrape endpoint
# ============================================================================
#
# Registered directly on the app (app.main.create_app), not under
# app_settings.api_v1_prefix and not behind any RBAC dependency -- Prometheus
# scrapers are not platform users, they never carry a JWT, and gating this
# route behind app.domains.rbac would mean either (a) provisioning a
# service-account JWT for every scrape config in existence, which no
# Prometheus deployment anywhere actually does, or (b) silently exempting it
# from auth in a way that isn't visible from this file. This is standard
# practice for Prometheus exporters -- see docs/monitoring/OBSERVABILITY.md
# for the explicit note that a production deployment MUST restrict
# /metrics at the network/ingress layer (a scrape-only security group,
# Kubernetes NetworkPolicy, or a reverse-proxy allowlist), not rely on any
# application-layer check.

router = APIRouter()


@router.get("/metrics", include_in_schema=False)
async def get_metrics(
    repository: ObservabilityRepositoryProtocol = Depends(get_observability_repository),
) -> Response:
    await refresh_business_metrics(repository)
    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


__all__ = [
    "HTTP_REQUESTS_TOTAL",
    "HTTP_REQUEST_DURATION_SECONDS",
    "HEALTH_CHECK_STATUS",
    "ALERTS_TRIGGERED_TOTAL",
    "GUEST_SESSIONS_ACTIVE",
    "PROVISIONING_JOBS_TOTAL",
    "PrometheusMiddleware",
    "ObservabilityRepositoryProtocol",
    "ObservabilityMetricsRepository",
    "refresh_business_metrics",
    "get_observability_repository",
    "router",
]
