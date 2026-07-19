"""BE-012 Part 3: Router + Network + Guest + Authentication Analytics
business logic.

``DomainAnalyticsService`` mirrors ``dashboard_service.DashboardService``'s
own composition discipline exactly: every number here comes from either (a)
``app.domains.guest.service.GuestAnalyticsService``'s existing real
aggregate queries (composed, never re-derived), (b) a new, narrow, read-only
cross-domain aggregate added to this domain's own ``repository.py``
(following the identical "read another domain's table directly for a
narrow composition" precedent that module already establishes), or (c) one
other domain's own already-public service method composed through a narrow,
duck-typed ``Protocol`` (``app.domains.wireguard.service.WireGuardService
.compute_health_status``, reused directly rather than re-deriving its
staleness-threshold arithmetic a second time).

Every endpoint enforces the exact same two-layer check Part 2 already
established (see ``dashboard_scope.py``'s own module docstring): RBAC's
``RequirePermission(..., scope=ScopeType.ORGANIZATION)`` at the route, *and*
this service's own ``DashboardScope.require_organization`` (resolved from
the caller's real, active RBAC role assignments via the same
``DashboardScopeResolver`` Part 2 built -- reused directly, never
reimplemented). Dashboard-view auditing reuses the exact same
``DashboardAuditThrottle`` Redis-backed once-per-window mechanism Part 2
built (``dashboard_audit.py``), not a second one.

## Bandwidth: from ``GuestSession``, never from ``RouterHealthSnapshot``

``app.domains.router_provisioning.models.RouterHealthSnapshot`` captures
only ``health_status``/``cpu_usage_percent``/``memory_usage_percent``/
``uptime_seconds``/``connected_clients_count`` -- there has never been a
real MikroTik device in this sandbox to report anything else, and
inventing a byte-counter field on that table with no real writer would be
exactly the kind of fabrication this part's honesty mandate forbids. Every
guest session, however, already records which router it connected through
(``GuestSession.router_id``) and how many bytes it moved
(``bytes_uploaded``/``bytes_downloaded``) -- Router/Network Analytics'
"Bandwidth"/"Download/Upload Usage" figures are therefore real,
``GROUP BY router_id``-aggregated sums over ``GuestSession``, not a
fabricated per-router counter.

## Hotspot Sessions == Guest Sessions

There is no separate "hotspot session" concept anywhere in this codebase.
Every guest WiFi connection *is* a ``GuestSession`` row -- "Hotspot
Sessions" per router is simply that router's ``GuestSession`` count within
the window, documented on the response itself
(``RouterAnalyticsItem.hotspot_sessions_note``) rather than silently implied.

## Internet Availability: a documented proxy signal

See ``router_availability.compute_internet_availability``'s own module
docstring for the full write-up -- ``Router.status == ONLINE`` *and* a
recent ``last_seen_at`` heartbeat, reusing
``app.domains.monitoring.constants.ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES``
directly (the same threshold ``app.domains.monitoring.validators
.compute_lifecycle_stage`` already uses for its own ``ONLINE -> OFFLINE``
staleness rule) rather than inventing a second, possibly-inconsistent
number. This mirrors ``app.domains.monitoring.service.MonitoringService
.check_freeradius_health``/``check_wireguard_health``'s own documented
"proxy signal, not a live daemon ping" posture, applied here to a router's
own internet/uplink connectivity rather than FreeRADIUS/WireGuard.

## RADIUS Requests/Success/Failure: per-router success, location-proxy failure

``GuestLoginHistory`` (where every login attempt, success or failure, is
recorded) carries ``organization_id``/``location_id`` but **no**
``router_id`` column at all (confirmed by reading
``app.domains.guest.models.GuestLoginHistory`` in full) -- only
``GuestSession`` (created only on a *successful* login/reconnect) carries
``router_id``. This part's design, made honest rather than silently
approximate:

* **RADIUS Success** (per router): an exact, real count --
  ``GuestSession`` rows for that router within the window. Every guest
  session is, definitionally, the result of one successful authentication
  (OTP, voucher, or a reconnect grant), so this is precisely "successful
  auth requests attributable to this router," identical to (not merely
  correlated with) "Hotspot Sessions" for that same router -- documented as
  the same underlying number on the response, not a coincidence.
* **RADIUS Failure** (per router): a *location-level proxy* --
  ``GuestLoginHistory`` failures grouped by ``location_id``, attributed to
  every router at that router's own location. Documented explicitly
  (``RouterAnalyticsItem.radius_failure_scope_note``) as coarser than a true
  per-device figure whenever more than one router shares a location -- this
  is the honest, precise boundary of what the existing schema can answer
  without a schema change this part's directory rule does not permit.
* **Authentication Requests Total** (per router) =
  ``radius_success_count + radius_failure_count``.

## Guest Retention: exact formula

See ``dashboard_aggregation.compute_guest_retention_rate``'s own docstring
for the exact formula: the percentage of guests seen in the immediately
preceding period (of equal length to the caller's own window) who were
*also* seen again in the current period. Computed from two real, bounded
``SELECT DISTINCT`` guest-id sets (``AnalyticsRepository
.get_distinct_guest_ids``) -- the SQL narrows each period to its own
already-small set of distinct guest identities; the pure Python
set-intersection over those two id sets is a mathematical operation over
primary keys, not the "Python-side loop over bulk-fetched business rows"
this codebase's coding rules warn against (the identical justification
``peak_concurrency.py`` already documents for its own real-SQL-narrows,
pure-function-computes split).

## Peak Bandwidth: exact formula

See ``dashboard_aggregation.compute_peak_bandwidth``'s own docstring: the
single highest-``total_bandwidth_bytes`` bucket among recent
``ORG_DAILY_SUMMARY`` ``AnalyticsSnapshot`` history (one bucket = one
already-computed daily rollup) -- bytes transferred within the busiest
already-computed bucket, never an instantaneous bits-per-second rate (no
such rate exists anywhere in this codebase's real data). Reported honestly
unavailable (never a fabricated zero) when no snapshot history exists yet
(e.g. before Celery's aggregation pipeline has ever run for this
organization).

## Composing with BE-010's own Guest Analytics, not re-deriving it

Per this part's explicit "check first" mandate:
``app.domains.guest.service.GuestAnalyticsService`` already exposes
``get_summary`` (visitors/unique/returning guests, average session
duration, total bandwidth), ``get_top_devices``, ``get_top_locations``,
``get_otp_success_rate``, and ``get_voucher_usage`` -- all real, tenant-
scoped SQL aggregates. Guest Analytics (this part's own
``GET /analytics/guests``) calls **into these same methods** via
``GuestAnalyticsCompositionProtocol`` below (verified in
``tests/unit/test_analytics_router_network_guest_auth.py`` with a spy
fake that records every call) rather than re-deriving "New Guests"/
"Returning Guests"/"Unique Guests"/"Top Devices"/"Top Locations" with a
second, possibly-inconsistent definition. "New Guests" reuses
``aggregation.new_guest_count`` -- the exact same
``max(unique - returning, 0)`` formula Part 1's own daily snapshot
aggregation already established, pulled out as a small, named, shared
function specifically so this part does not re-derive it inline a second
time.

## Honest placeholders in this part

* **Router disk usage/temperature/packet loss/latency** -- ``NEVER``
  captured by ``RouterHealthSnapshot`` (see that model's own docstring);
  no real device has ever reported them.
* **Network "Top Applications"** -- no deep packet inspection / application-
  layer traffic classification exists (or could exist without new
  infrastructure this part should not invent).
* **Authentication "PMS Login"** -- no Property Management System
  integration exists anywhere in this codebase.
* **Authentication "Social Login"** -- ``app.domains.captive_portal
  .models.CaptivePortalConfig.social_login_enabled`` is a schema-only
  readiness flag (that model's own docstring); no real social-login flow
  has ever executed.
* **Country Statistics** (Guest Analytics) -- reuses Part 2's exact
  ``CountryStatisticsResponse`` placeholder and reasoning verbatim (no
  GeoIP data source exists anywhere in this sandbox) -- not re-litigated.

All five follow the identical ``available: bool = False`` + explanatory
``message`` shape Part 2's ``RevenueMetricsResponse``/
``CountryStatisticsResponse`` already established.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from redis.asyncio import Redis

from app.domains.wireguard.constants import HealthStatus as WireGuardHealthStatus
from app.domains.wireguard.models import WireGuardPeer

from .aggregation import new_guest_count
from .constants import (
    AUDIT_ACTION_AUTHENTICATION_ANALYTICS_VIEWED,
    AUDIT_ACTION_GUEST_ANALYTICS_VIEWED,
    AUDIT_ACTION_NETWORK_ANALYTICS_VIEWED,
    AUDIT_ACTION_ROUTER_ANALYTICS_VIEWED,
    ROUTER_HEALTH_TREND_WINDOW_DAYS,
    TOP_N_DEFAULT,
    AnalyticsSnapshotType,
)
from .dashboard_aggregation import (
    build_auth_method_breakdown,
    compute_average_speed_bytes_per_second,
    compute_guest_retention_rate,
    compute_peak_bandwidth,
    device_breakdown_response,
)
from .dashboard_audit import DashboardAuditThrottle
from .dashboard_schemas import CountryStatisticsResponse, GrowthPointResponse
from .dashboard_scope import DashboardScopeResolver
from .domain_analytics_schemas import (
    AuthenticationAnalyticsResponse,
    AuthTrendPointItem,
    FailureReasonItem,
    GuestAnalyticsResponse,
    GuestRetentionResponse,
    LanguageStatisticsResponse,
    NetworkAnalyticsResponse,
    NetworkAvailabilityResponse,
    OtpAuthStatsResponse,
    PeakBandwidthResponse,
    RouterAnalyticsItem,
    RouterAnalyticsResponse,
    TopConsumerItem,
    TopDeviceItem,
    TopLocationBandwidthItem,
    TopLocationItem,
    TopRouterBandwidthItem,
    UnavailableMetricResponse,
    VoucherAuthStatsResponse,
    WireGuardStatusItem,
)
from .models import AnalyticsSnapshot
from .repository import (
    AnalyticsRepositoryProtocol,
    LanguageBreakdown,
    RouterBandwidthRow,
    RouterHealthSnapshotRow,
    RouterSummaryRow,
    UserAgentBreakdown,
)
from .router_availability import compute_internet_availability
from .trends import build_growth_trend
from .trends import growth_point_response as _growth_response

logger = logging.getLogger(__name__)

# Reused verbatim from Part 2 -- see module docstring's "Honest placeholders"
# section for why Country Statistics is not re-litigated here.
_NO_GEOIP_MESSAGE = (
    "Not available: no GeoIP database or IP-geolocation service exists in "
    "this environment, and no billing/payment data exists to derive a "
    "guest's country from another source."
)

_DISK_USAGE_MESSAGE = (
    "Not available: app.domains.router_provisioning.models.RouterHealthSnapshot "
    "captures only health_status/cpu_usage_percent/memory_usage_percent/"
    "uptime_seconds/connected_clients_count -- no disk-usage column exists, "
    "because no real MikroTik device has ever reported one in this sandbox."
)
_TEMPERATURE_MESSAGE = (
    "Not available: RouterHealthSnapshot has no temperature column -- no "
    "real device has ever reported one."
)
_PACKET_LOSS_MESSAGE = (
    "Not available: RouterHealthSnapshot has no packet-loss column -- no "
    "real device has ever reported one."
)
_LATENCY_MESSAGE = (
    "Not available: RouterHealthSnapshot has no latency column -- no real "
    "device has ever reported one."
)
_TOP_APPLICATIONS_MESSAGE = (
    "Not available: no deep packet inspection / application-layer traffic "
    "classification exists (or could exist without new network "
    "infrastructure this part's scope does not license inventing)."
)
_PMS_LOGIN_MESSAGE = (
    "Not available: no Property Management System integration exists "
    "anywhere in this codebase."
)
_SOCIAL_LOGIN_MESSAGE = (
    "Not available: app.domains.captive_portal.models.CaptivePortalConfig"
    ".social_login_enabled is a schema-only readiness flag (see that "
    "model's own module docstring) -- no real social-login flow has ever "
    "executed in this sandbox."
)


class GuestSummaryLike(Protocol):
    visitors: int
    unique_guests: int
    returning_guests: int
    average_session_duration_seconds: float | None
    total_bandwidth_bytes: int


class TopDeviceLike(Protocol):
    device_id: uuid.UUID
    mac_address: str
    session_count: int
    unique_guest_count: int


class TopLocationLike(Protocol):
    location_id: uuid.UUID
    location_name: str
    session_count: int


class GuestAnalyticsCompositionProtocol(Protocol):
    """The exact real, already-public surface of
    ``app.domains.guest.service.GuestAnalyticsService`` this module
    composes with -- reused directly, never reimplemented. See module
    docstring's "Composing with BE-010's own Guest Analytics" section."""

    async def get_summary(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> GuestSummaryLike: ...

    async def get_top_devices(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int = 10,
    ) -> list[TopDeviceLike]: ...

    async def get_top_locations(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int = 10,
    ) -> list[TopLocationLike]: ...


class WireGuardHealthProtocol(Protocol):
    """The single ``WireGuardService`` method this module needs -- reused
    directly (never re-deriving its staleness-threshold arithmetic)."""

    def compute_health_status(
        self, peer: WireGuardPeer, *, now: datetime | None = None
    ) -> WireGuardHealthStatus: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


class DomainAnalyticsService:
    def __init__(
        self,
        repository: AnalyticsRepositoryProtocol,
        guest_analytics: GuestAnalyticsCompositionProtocol,
        scope_resolver: DashboardScopeResolver,
        wireguard_health: WireGuardHealthProtocol,
        redis: Redis,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.guest_analytics = guest_analytics
        self.scope_resolver = scope_resolver
        self.wireguard_health = wireguard_health
        self.redis = redis
        self.audit_writer = audit_writer

    # ========================================================================
    # Router Analytics
    # ========================================================================

    async def get_router_analytics(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> RouterAnalyticsResponse:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_organization(organization_id)

        now = datetime.now(UTC)
        routers = await self.repository.list_routers_for_scope(
            organization_id=organization_id, location_id=location_id
        )
        router_ids = [row.router_id for row in routers]
        location_ids = list({row.location_id for row in routers})

        latest_health = await self.repository.get_latest_router_health_snapshots(
            router_ids
        )
        trend_window_start = now - timedelta(days=ROUTER_HEALTH_TREND_WINDOW_DAYS)
        health_averages = await self.repository.get_router_health_snapshot_averages(
            router_ids, start=trend_window_start, end=now
        )
        bandwidth_rows = {
            row.router_id: row
            for row in await self.repository.get_bandwidth_by_router(
                organization_id=organization_id,
                location_id=location_id,
                start=start,
                end=end,
            )
        }
        wireguard_peers = await self.repository.get_wireguard_peers_by_router_ids(
            router_ids
        )
        failure_by_location = (
            await self.repository.get_login_failure_counts_by_location(
                location_ids, start=start, end=end
            )
        )

        items = [
            self._build_router_item(
                router,
                latest_health.get(router.router_id),
                health_averages.get(router.router_id, (None, None)),
                bandwidth_rows.get(router.router_id),
                wireguard_peers.get(router.router_id),
                failure_by_location.get(router.location_id, 0),
                now=now,
            )
            for router in routers
        ]

        await self._maybe_audit(
            user_id,
            action=AUDIT_ACTION_ROUTER_ANALYTICS_VIEWED,
            dashboard_kind="router_analytics",
            scope_key=f"{organization_id}:{location_id}",
            organization_id=organization_id,
            location_id=location_id,
            description=f"Router analytics viewed for organization {organization_id}",
        )

        return RouterAnalyticsResponse(
            organization_id=organization_id,
            location_id=location_id,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
            routers=items,
            disk_usage=UnavailableMetricResponse(message=_DISK_USAGE_MESSAGE),
            temperature=UnavailableMetricResponse(message=_TEMPERATURE_MESSAGE),
            packet_loss=UnavailableMetricResponse(message=_PACKET_LOSS_MESSAGE),
            latency=UnavailableMetricResponse(message=_LATENCY_MESSAGE),
        )

    def _build_router_item(
        self,
        router: RouterSummaryRow,
        health: RouterHealthSnapshotRow | None,
        health_averages: tuple[float | None, float | None],
        bandwidth: RouterBandwidthRow | None,
        peer: WireGuardPeer | None,
        radius_failure_count: int,
        *,
        now: datetime,
    ) -> RouterAnalyticsItem:
        avg_cpu, avg_memory = health_averages
        cpu_current = health.cpu_usage_percent if health else None
        memory_current = health.memory_usage_percent if health else None

        cpu_trend = (
            _growth_response("cpu_usage_percent", cpu_current, avg_cpu)
            if cpu_current is not None
            else None
        )
        memory_trend = (
            _growth_response("memory_usage_percent", memory_current, avg_memory)
            if memory_current is not None
            else None
        )

        bytes_uploaded = bandwidth.bytes_uploaded if bandwidth else 0
        bytes_downloaded = bandwidth.bytes_downloaded if bandwidth else 0
        hotspot_sessions = bandwidth.session_count if bandwidth else 0

        internet_available = compute_internet_availability(
            status=router.status, last_seen_at=router.last_seen_at, now=now
        )

        wireguard = self._build_wireguard_status(peer, now=now)

        radius_success_count = hotspot_sessions

        return RouterAnalyticsItem(
            router_id=router.router_id,
            router_name=router.router_name,
            location_id=router.location_id,
            status=router.status,
            cpu_usage_percent_current=cpu_current,
            cpu_usage_trend=cpu_trend,
            memory_usage_percent_current=memory_current,
            memory_usage_trend=memory_trend,
            uptime_seconds=health.uptime_seconds if health else None,
            connected_clients_count=health.connected_clients_count if health else None,
            health_snapshot_available=health is not None,
            health_snapshot_recorded_at=_iso(health.recorded_at) if health else None,
            bandwidth_uploaded_bytes=bytes_uploaded,
            bandwidth_downloaded_bytes=bytes_downloaded,
            bandwidth_total_bytes=bytes_uploaded + bytes_downloaded,
            internet_available=internet_available,
            last_seen_at=_iso(router.last_seen_at),
            wireguard=wireguard,
            hotspot_sessions=hotspot_sessions,
            authentication_requests_total=radius_success_count + radius_failure_count,
            radius_success_count=radius_success_count,
            radius_failure_count=radius_failure_count,
        )

    def _build_wireguard_status(
        self, peer: WireGuardPeer | None, *, now: datetime
    ) -> WireGuardStatusItem:
        if peer is None:
            return WireGuardStatusItem(
                available=False,
                message=(
                    "No WireGuard tunnel has ever been provisioned for this " "router."
                ),
            )
        status = self.wireguard_health.compute_health_status(peer, now=now)
        return WireGuardStatusItem(
            available=True,
            status=status.value,
            last_handshake_at=_iso(peer.last_handshake_at),
        )

    # ========================================================================
    # Network Analytics
    # ========================================================================

    async def get_network_analytics(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        limit: int = TOP_N_DEFAULT,
    ) -> NetworkAnalyticsResponse:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_organization(organization_id)

        (
            upload_bytes,
            download_bytes,
        ) = await self.repository.get_network_bandwidth_totals(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        total_bytes = upload_bytes + download_bytes

        average_speed = compute_average_speed_bytes_per_second(
            total_bytes=total_bytes, window_start=start, window_end=end
        )

        snapshots, _ = await self.repository.list_snapshots(
            organization_id=organization_id,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value,
            start=start,
            end=end,
            page=1,
            page_size=max((end - start).days + 1, 1),
        )
        ordered_snapshots = sorted(snapshots, key=lambda snap: snap.period_start)
        peak_bandwidth = self._compute_peak_bandwidth_response(ordered_snapshots)
        traffic_trend = self._compute_traffic_trend(ordered_snapshots)

        routers = await self.repository.list_routers_for_scope(
            organization_id=organization_id, location_id=location_id
        )
        now = datetime.now(UTC)
        available_count = sum(
            1
            for router in routers
            if compute_internet_availability(
                status=router.status, last_seen_at=router.last_seen_at, now=now
            )
        )
        total_router_count = len(routers)
        availability_percent = (
            (available_count / total_router_count) * 100.0
            if total_router_count
            else None
        )

        top_consumers = await self.repository.get_top_guests_by_bandwidth(
            organization_id=organization_id, start=start, end=end, limit=limit
        )
        top_locations = await self.repository.get_top_locations_by_bandwidth(
            organization_id=organization_id, start=start, end=end, limit=limit
        )
        top_routers = await self.repository.get_top_routers_by_bandwidth(
            organization_id=organization_id, start=start, end=end, limit=limit
        )

        await self._maybe_audit(
            user_id,
            action=AUDIT_ACTION_NETWORK_ANALYTICS_VIEWED,
            dashboard_kind="network_analytics",
            scope_key=f"{organization_id}:{location_id}",
            organization_id=organization_id,
            location_id=location_id,
            description=f"Network analytics viewed for organization {organization_id}",
        )

        return NetworkAnalyticsResponse(
            organization_id=organization_id,
            location_id=location_id,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
            download_bytes=download_bytes,
            upload_bytes=upload_bytes,
            total_bytes=total_bytes,
            peak_bandwidth=peak_bandwidth,
            average_speed_bytes_per_second=average_speed,
            network_availability=NetworkAvailabilityResponse(
                available_router_count=available_count,
                total_router_count=total_router_count,
                availability_percent=availability_percent,
            ),
            top_consumers=[
                TopConsumerItem(
                    guest_id=row.entity_id,
                    identifier=row.label,
                    total_bytes=row.total_bytes,
                )
                for row in top_consumers
            ],
            top_locations=[
                TopLocationBandwidthItem(
                    location_id=row.entity_id,
                    location_name=row.label,
                    total_bytes=row.total_bytes,
                )
                for row in top_locations
            ],
            top_routers=[
                TopRouterBandwidthItem(
                    router_id=row.entity_id,
                    router_name=row.label,
                    total_bytes=row.total_bytes,
                )
                for row in top_routers
            ],
            traffic_trend=traffic_trend,
            top_applications=UnavailableMetricResponse(
                message=_TOP_APPLICATIONS_MESSAGE
            ),
        )

    def _compute_peak_bandwidth_response(
        self, snapshots: list[AnalyticsSnapshot]
    ) -> PeakBandwidthResponse:
        buckets = [
            (
                snap.period_start,
                snap.period_end,
                float(snap.metrics.get("total_bandwidth_bytes", 0) or 0),
            )
            for snap in snapshots
        ]
        point = compute_peak_bandwidth(buckets)
        if point is None:
            return PeakBandwidthResponse(
                available=False,
                message=(
                    "No ORG_DAILY_SUMMARY snapshot history exists yet for this "
                    "window (e.g. the aggregation pipeline has not run for "
                    "this organization yet)."
                ),
            )
        return PeakBandwidthResponse(
            available=True,
            peak_bytes=int(point.bytes_total),
            bucket_start=point.bucket_start.isoformat(),
            bucket_end=point.bucket_end.isoformat(),
            granularity="daily",
        )

    def _compute_traffic_trend(
        self, snapshots: list[AnalyticsSnapshot]
    ) -> list[GrowthPointResponse]:
        """Composes ``trends.build_growth_trend`` (BE-012 Part 4) -- see
        that module's own docstring for why this method and
        ``dashboard_service._compute_org_traffic_trend`` no longer each
        define their own copy of this loop."""
        return build_growth_trend(snapshots, "total_bandwidth_bytes")

    # ========================================================================
    # Guest Analytics
    # ========================================================================

    async def get_guest_analytics(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        limit: int = TOP_N_DEFAULT,
    ) -> GuestAnalyticsResponse:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_organization(organization_id)

        summary = await self.guest_analytics.get_summary(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        new_guests = new_guest_count(
            unique_guests=summary.unique_guests,
            returning_guests=summary.returning_guests,
        )
        repeat_visits = max(summary.visitors - summary.unique_guests, 0)
        average_data_usage = (
            summary.total_bandwidth_bytes / summary.unique_guests
            if summary.unique_guests
            else None
        )

        retention = await self._compute_guest_retention(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )

        top_devices = await self.guest_analytics.get_top_devices(
            organization_id=organization_id, start=start, end=end, limit=limit
        )
        top_locations = await self.guest_analytics.get_top_locations(
            organization_id=organization_id, start=start, end=end, limit=limit
        )

        device_breakdown: UserAgentBreakdown = (
            await self.repository.get_user_agent_breakdown(
                organization_id=organization_id,
                location_id=location_id,
                start=start,
                end=end,
            )
        )
        language_breakdown: LanguageBreakdown = (
            await self.repository.get_language_breakdown(
                organization_id=organization_id,
                location_id=location_id,
                start=start,
                end=end,
            )
        )

        await self._maybe_audit(
            user_id,
            action=AUDIT_ACTION_GUEST_ANALYTICS_VIEWED,
            dashboard_kind="guest_analytics",
            scope_key=f"{organization_id}:{location_id}",
            organization_id=organization_id,
            location_id=location_id,
            description=f"Guest analytics viewed for organization {organization_id}",
        )

        return GuestAnalyticsResponse(
            organization_id=organization_id,
            location_id=location_id,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
            new_guests=new_guests,
            returning_guests=summary.returning_guests,
            unique_guests=summary.unique_guests,
            repeat_visits=repeat_visits,
            guest_retention=retention,
            average_data_usage_bytes=average_data_usage,
            average_session_duration_seconds=summary.average_session_duration_seconds,
            top_devices=[
                TopDeviceItem(
                    device_id=item.device_id,
                    mac_address=item.mac_address,
                    session_count=item.session_count,
                    unique_guest_count=item.unique_guest_count,
                )
                for item in top_devices
            ],
            top_locations=[
                TopLocationItem(
                    location_id=item.location_id,
                    location_name=item.location_name,
                    session_count=item.session_count,
                )
                for item in top_locations
            ],
            devices=device_breakdown_response(device_breakdown),
            languages=_language_breakdown_response(language_breakdown),
            country_statistics=CountryStatisticsResponse(message=_NO_GEOIP_MESSAGE),
        )

    async def _compute_guest_retention(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> GuestRetentionResponse:
        period_length = end - start
        previous_start = start - period_length
        previous_end = start

        current_ids = await self.repository.get_distinct_guest_ids(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        previous_ids = await self.repository.get_distinct_guest_ids(
            organization_id=organization_id,
            location_id=location_id,
            start=previous_start,
            end=previous_end,
        )
        rate, retained_count = compute_guest_retention_rate(
            current_guest_ids=current_ids, previous_guest_ids=previous_ids
        )
        message = (
            None
            if previous_ids
            else "No guests were seen in the previous period to compare against."
        )
        return GuestRetentionResponse(
            available=rate is not None,
            retention_rate_percent=rate,
            retained_guest_count=retained_count,
            current_period_guest_count=len(current_ids),
            previous_period_guest_count=len(previous_ids),
            period_days=max(period_length.days, 1),
            message=message,
        )

    # ========================================================================
    # Authentication Analytics
    # ========================================================================

    async def get_authentication_analytics(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> AuthenticationAnalyticsResponse:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_organization(organization_id)

        otp_stats = await self.repository.get_otp_stats(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        otp_failed = otp_stats.total_requests - otp_stats.verified_count
        otp_rate = (
            otp_stats.verified_count / otp_stats.total_requests
            if otp_stats.total_requests
            else 0.0
        )

        voucher_redeemed = await self.repository.get_voucher_redeemed_count(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        voucher_failed_recorded = (
            await self.repository.get_voucher_redemption_failed_audit_count(
                organization_id=organization_id, start=start, end=end
            )
        )

        outcome_totals = await self.repository.get_login_history_outcome_totals(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        failure_reasons = await self.repository.get_login_history_failure_reasons(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        daily_trend = await self.repository.get_login_history_daily_trend(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        auth_method_rows = await self.repository.get_auth_method_breakdown(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )

        await self._maybe_audit(
            user_id,
            action=AUDIT_ACTION_AUTHENTICATION_ANALYTICS_VIEWED,
            dashboard_kind="authentication_analytics",
            scope_key=f"{organization_id}:{location_id}",
            organization_id=organization_id,
            location_id=location_id,
            description=(
                f"Authentication analytics viewed for organization {organization_id}"
            ),
        )

        return AuthenticationAnalyticsResponse(
            organization_id=organization_id,
            location_id=location_id,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
            otp=OtpAuthStatsResponse(
                total_requests=otp_stats.total_requests,
                successful_count=otp_stats.verified_count,
                failed_count=max(otp_failed, 0),
                success_rate=otp_rate,
            ),
            voucher=VoucherAuthStatsResponse(
                redeemed_count=voucher_redeemed,
                failed_attempts_recorded=voucher_failed_recorded,
            ),
            authentication_success_total=outcome_totals.successful_attempts,
            authentication_failure_total=outcome_totals.failed_attempts,
            authentication_trends=[
                AuthTrendPointItem(
                    date=day.isoformat(), success_count=success, failure_count=failure
                )
                for day, success, failure in daily_trend
            ],
            failed_login_reasons=[
                FailureReasonItem(reason=reason, count=count)
                for reason, count in failure_reasons
            ],
            auth_methods=build_auth_method_breakdown(auth_method_rows),
            pms_login=UnavailableMetricResponse(message=_PMS_LOGIN_MESSAGE),
            social_login=UnavailableMetricResponse(message=_SOCIAL_LOGIN_MESSAGE),
        )

    # ========================================================================
    # Internal helpers
    # ========================================================================

    async def _maybe_audit(
        self,
        user_id: uuid.UUID,
        *,
        action: str,
        dashboard_kind: str,
        scope_key: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        description: str,
    ) -> None:
        logger.info(
            "dashboard_viewed",
            extra={
                "user_id": str(user_id),
                "dashboard_kind": dashboard_kind,
                "scope_key": scope_key,
            },
        )
        if self.audit_writer is None:
            return
        should_write = await DashboardAuditThrottle.should_write_audit_entry(
            self.redis, user_id=user_id, dashboard_kind=dashboard_kind, scope=scope_key
        )
        if not should_write:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=user_id,
            action=action,
            entity_type="dashboard",
            entity_id=None,
            description=description,
            event_metadata={"dashboard_kind": dashboard_kind},
            organization_id=organization_id,
            location_id=location_id,
        )


def _language_breakdown_response(
    breakdown: LanguageBreakdown,
) -> LanguageStatisticsResponse:
    message = None
    if breakdown.sessions_total and not breakdown.sessions_with_language:
        message = (
            "No sessions in this window captured an Accept-Language header "
            "(all predate this capture, or every guest device omitted it)."
        )
    elif not breakdown.sessions_total:
        message = "No guest sessions in this window."
    return LanguageStatisticsResponse(
        available=True,
        sessions_total=breakdown.sessions_total,
        sessions_with_data=breakdown.sessions_with_language,
        by_language=[
            {"language": label, "session_count": count}
            for label, count in breakdown.by_language
        ],
        message=message,
    )


__all__ = [
    "DomainAnalyticsService",
    "GuestAnalyticsCompositionProtocol",
    "WireGuardHealthProtocol",
    "AuditLogWriter",
]
