"""ISP Management business logic: WAN/ISP link CRUD, real RouterOS-backed
health checks (latency/packet loss), and automatic primary/backup
failover/failback.

## Composition, not duplication, with ``app.domains.router``

This module never opens a device connection or decrypts a credential
itself -- ``RouterLookupProtocol`` (a narrow, duck-typed Protocol
satisfied structurally by the real ``app.domains.router.service
.RouterService``, the identical composition-over-duplication pattern
every prior domain in this codebase establishes) supplies both the
router's own connection fields and its already-decrypted API secret
(``get_decrypted_api_secret``, reused directly -- never re-decrypted
here). Which vendor adapter actually issues the ping is resolved
per-router from ``Router.vendor`` via ``device_adapter_resolver``
(default ``device_adapters.get_isp_health_adapter``), mirroring
``app.domains.queue_management.service.QueueManagementService``'s own
"resolve per-router at the point of use, never fix one adapter at
construction time" convention exactly -- injectable purely for tests.

## ``role`` vs. ``is_active_uplink``: static assignment vs. live state

See ``models.IspLink``'s own docstring for the full distinction. In normal
operation the ``PRIMARY`` link is also the active uplink; a real failover
flips ``is_active_uplink`` onto a ``BACKUP`` link without ever touching
``role`` -- "which link is primary" is an admin decision, "which link is
currently live" is an operational one this module manages.

## Failover: real, threshold-gated, never on a single blip

``trigger_failover``/the module-level ``run_health_check_sweep`` never act
on one bad ping -- ``IspLink.consecutive_unhealthy_count`` must reach
``constants.DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER`` (default 3)
*consecutive* ``UNHEALTHY`` readings first (see
``validators.is_failover_threshold_reached``). A guest network's live WAN
uplink flapping back and forth on transient packet loss would be strictly
worse than staying on a briefly-degraded primary.

## Audit-volume judgment call

Mirrors ``app.domains.guest.service``'s own tiering exactly: every
individual health-check reading (potentially one per link per minute,
platform-wide) is **not** audited -- it is recorded in the dedicated,
high-volume ``IspHealthCheck`` table and logged via the structured logger
only. A real state change that actually matters operationally --
link create/update/delete, and especially a failover/failback (a guest
network's live uplink just changed) -- **is** always audited, the
identical "moderate-volume, admin-relevant" profile every other domain's
own lifecycle events already carry.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import (
    DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER,
    ISP_PING_COUNT,
    ISP_PING_TIMEOUT_SECONDS,
    SPEED_TEST_ACTIVE_REDIS_KEY_TEMPLATE,
    SPEED_TEST_ACTIVE_REDIS_TTL_SECONDS,
    SPEED_TEST_COOLDOWN_REDIS_KEY_TEMPLATE,
    SPEED_TEST_DOWNLOAD_URL,
    SPEED_TEST_MIN_INTERVAL_SECONDS,
    SPEED_TEST_TIMEOUT_SECONDS,
    UNHEALTHY_SINCE_LOOKBACK_LIMIT,
    HealthStatus,
    HealthStatusSource,
    IspConnectionMode,
    IspLinkRole,
    WanRoutingMode,
)
from .device_adapters import IspCredentials, PingResult, get_isp_health_adapter
from .events import (
    IspFailbackTriggered,
    IspFailoverTriggered,
    IspHealthCheckRecorded,
    IspLinkCreated,
    IspLinkDeleted,
    IspLinkManualStatusSet,
    IspLinkUpdated,
)
from .exceptions import (
    CrossOrganizationIspLinkAccessError,
    IspDeviceConnectionError,
    IspDeviceOperationError,
    IspHealthCheckTargetUnavailableError,
    IspLinkDisabledError,
    IspLinkInterfaceRequiredError,
    IspLinkNotFoundError,
    IspMissingCredentialsError,
    IspNoBackupLinkAvailableError,
    IspPrimaryLinkAlreadyExistsError,
    IspSpeedTestCooldownError,
)
from .models import IspHealthCheck, IspLink
from .repository import IspRepositoryProtocol
from .validators import (
    classify_health_status,
    is_failover_threshold_reached,
    validate_wan_routing_weights,
)


# Narrow, duck-typed Protocol for the one Redis surface this module needs
# (a real client -- ``app.database.redis.redis_client`` -- in production,
# `None` in every test that doesn't care about cooldown/self-congestion
# suppression). Avoids importing ``redis.asyncio.Redis`` directly just for
# a type hint, mirroring this module's own existing
# ``RouterLookupProtocol``/``AuditLogWriter`` "narrow Protocol, not the
# concrete third-party type" convention.
class _RedisProtocol(Protocol):
    async def set(
        self, name: str, value: object, *, nx: bool = False, ex: int | None = None
    ) -> object: ...
    async def ttl(self, name: str) -> int: ...
    async def delete(self, *names: str) -> object: ...

logger = logging.getLogger(__name__)


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick every other domain's own ``_event_extra`` uses."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class RouterLookupProtocol(Protocol):
    """The two ``RouterService`` methods this module needs -- reused
    directly, never reimplemented. Mirrors
    ``app.domains.queue_management.service.RouterLookupProtocol``
    exactly."""

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...

    def get_decrypted_api_secret(self, router: Router) -> str | None: ...

    async def update_router(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> Router: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Read models
# ============================================================================


@dataclass(frozen=True, slots=True)
class HealthCheckSweepSummary:
    checked: int
    failovers: int
    failbacks: int
    skipped: int
    errors: int


@dataclass(frozen=True, slots=True)
class TrafficCounters:
    """One real, raw snapshot of a link's own interface byte counters --
    see ``IspService.sample_link_traffic``. Deliberately not a rate: the
    caller (``record_health_check_result``, which already owns ``now``
    and the link's *previous* reading) computes the Mbps delta, the same
    "counter now, delta computed against the previous reading" split
    ``app.domains.guest.service`` already establishes."""

    rx_bytes: int
    tx_bytes: int


@dataclass(frozen=True, slots=True)
class SpeedTestOutcome:
    """The real, on-demand result ``IspService.run_speed_test`` returns --
    combines a fresh real ``/tool/ping`` (latency/packet loss) with a fresh
    real ``/tool/fetch`` download (throughput) against the link's own
    router. Deliberately never persisted as an ``IspHealthCheck`` row --
    see ``run_speed_test``'s own docstring for why. ``upload_mbps`` is
    always ``None`` -- no genuine method to measure real upload throughput
    against the public internet exists for this hardware class; never
    fabricated to fill the gap."""

    isp_link_id: uuid.UUID
    tested_at: datetime
    download_mbps: float
    upload_mbps: float | None
    latency_ms: float | None
    packet_loss_percentage: float | None
    downloaded_bytes: int
    duration_seconds: float


@dataclass(frozen=True, slots=True)
class HealthCheckBucket:
    """One aggregated time bucket from ``IspRepository
    .bucketed_health_checks_for_link`` -- the "Internet Connection"
    history dialog's uptime-chart row. ``uptime_percentage`` mirrors
    ``compute_availability_percentage``'s own "HEALTHY or DEGRADED counts
    as up" definition, just computed per bucket instead of over the whole
    fetched page.

    ``avg_download_mbps``/``avg_upload_mbps``/``max_download_mbps`` are
    the same bandwidth-history view's Mbps aggregates -- ``None`` for any
    bucket where every health check in that window failed to produce a
    traffic sample (never a fabricated ``0``), exactly like
    ``IspHealthCheck.download_mbps``/``upload_mbps`` themselves."""

    bucket_start: datetime
    total_checks: int
    healthy_count: int
    degraded_count: int
    unhealthy_count: int
    uptime_percentage: float | None
    avg_latency_ms: float | None
    avg_packet_loss_percentage: float | None
    avg_download_mbps: float | None
    avg_upload_mbps: float | None
    max_download_mbps: float | None


# ============================================================================
# Service
# ============================================================================


class IspService:
    """Core ISP Management business logic."""

    def __init__(
        self,
        repository: IspRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        device_adapter_resolver=get_isp_health_adapter,
        redis: _RedisProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        self._get_device_adapter = device_adapter_resolver
        # Optional: backs run_speed_test's real per-link cooldown/in-flight
        # marker (see that method's own docstring) and
        # record_health_check_result's self-congestion suppression. `None`
        # in any test/construction path that doesn't wire a real Redis
        # client -- both features degrade to their pre-existing "always
        # allowed / always counted" behavior rather than erroring, since
        # neither is a correctness-critical dependency the rest of this
        # service needs to function.
        self._redis = redis

    # ========================================================================
    # Link CRUD
    # ========================================================================

    async def create_link(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID,
        provider_name: str,
        link_type: str,
        connection_mode: str = IspConnectionMode.STATIC.value,
        role: IspLinkRole,
        priority: int = 0,
        interface: str | None = None,
        gateway_ip_address: str | None = None,
        dns_primary: str | None = None,
        dns_secondary: str | None = None,
        download_bandwidth_mbps: int | None = None,
        upload_bandwidth_mbps: int | None = None,
        auto_failback: bool = True,
    ) -> IspLink:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        if role == IspLinkRole.PRIMARY:
            existing_primary = await self.repository.get_primary_link_for_router(
                router.id
            )
            if existing_primary is not None:
                raise IspPrimaryLinkAlreadyExistsError(router.id)

        # The very first link a router ever gets is immediately the active
        # uplink, regardless of role -- there is nothing else it could be
        # failing over *from*. Every subsequent link (a genuine second
        # uplink) starts inactive; an admin promotes it via
        # trigger_failover, or it takes over automatically once real
        # health checks warrant it.
        existing_links = await self.repository.list_links_for_router(router.id)
        is_first_link = len(existing_links) == 0

        link = await self.repository.create_link(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            provider_name=provider_name,
            link_type=link_type,
            connection_mode=connection_mode,
            role=role.value,
            is_active_uplink=is_first_link,
            auto_failback=auto_failback,
            is_enabled=True,
            priority=priority,
            interface=interface,
            gateway_ip_address=gateway_ip_address,
            dns_primary=dns_primary,
            dns_secondary=dns_secondary,
            download_bandwidth_mbps=download_bandwidth_mbps,
            upload_bandwidth_mbps=upload_bandwidth_mbps,
            health_status=HealthStatus.UNKNOWN.value,
            latency_ms=None,
            packet_loss_percentage=None,
            last_checked_at=None,
            consecutive_unhealthy_count=0,
            created_by=actor_user_id,
        )
        event = IspLinkCreated(link_id=link.id, router_id=router.id, role=role.value)
        logger.info("isp_link_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.ISP_LINK_CREATED,
            entity_id=link.id,
            organization_id=link.organization_id,
            description=f"ISP link '{provider_name}' ({role.value}) created "
            f"for router {router.id}",
        )
        return link

    async def get_or_create_link_for_interface(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID,
        provider_name: str,
        link_type: str,
        connection_mode: str = IspConnectionMode.STATIC.value,
        role: IspLinkRole,
        priority: int = 0,
        interface: str | None,
        gateway_ip_address: str | None = None,
        dns_primary: str | None = None,
        dns_secondary: str | None = None,
        download_bandwidth_mbps: int | None = None,
        upload_bandwidth_mbps: int | None = None,
        auto_failback: bool = True,
    ) -> tuple[IspLink, bool]:
        """Idempotent front door for automated callers (router provisioning
        first among them) that may legitimately run the same "register this
        WAN as an ISP link" step more than once -- an admin regenerating an
        already-provisioned router's setup script, a retried request after a
        dropped connection, etc. Plain ``create_link`` has no such guard
        (see its own docstring reference in ``exceptions
        .IspPrimaryLinkAlreadyExistsError`` -- it only ever rejected a
        second *primary*), so calling it directly from an automated,
        possibly-repeated flow risks a real duplicate ``BACKUP`` row per
        re-run, each with its own health-check history and dashboard tile.

        Dedupes purely by ``(router_id, interface)`` -- deliberately not by
        ``provider_name`` (a placeholder like "WAN 1" the caller may not
        even set consistently) or by ``role`` (a re-run might legitimately
        want to promote what it thinks is the same physical uplink). A
        RouterOS interface name is the one field that genuinely, stably
        identifies "the same real WAN uplink" across repeated calls -- it is
        also the exact field every caller of this method already has
        (``WanEntry.iface`` on the FE side), which is why
        ``IspLinkInterfaceRequiredError`` is raised rather than silently
        falling back to an always-create path when it's missing: a caller
        with no interface has nothing to be idempotent against and should
        use ``create_link`` directly instead (matching today's one caller of
        that method, the manual "Add ISP Link" dialog, where a human can
        freely leave the interface blank until it's wired).

        Returns ``(link, created)`` -- ``created`` is ``False`` when an
        existing link on this interface was found and returned as-is
        (deliberately never updated in place; a link a human has since
        customized -- renamed, re-prioritized -- should not be silently
        overwritten by a stale re-run of the original provisioning
        payload). Callers that want a real update path already have
        ``update_link`` for that.
        """
        if not interface:
            raise IspLinkInterfaceRequiredError(router_id)

        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        existing_links = await self.repository.list_links_for_router(router.id)
        existing = next(
            (link for link in existing_links if link.interface == interface), None
        )
        if existing is not None:
            logger.info(
                "isp_link_get_or_create_idempotent_skip",
                extra={
                    "link_id": str(existing.id),
                    "router_id": str(router.id),
                    "interface": interface,
                },
            )
            return existing, False

        link = await self.create_link(
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
            router_id=router.id,
            provider_name=provider_name,
            link_type=link_type,
            connection_mode=connection_mode,
            role=role,
            priority=priority,
            interface=interface,
            gateway_ip_address=gateway_ip_address,
            dns_primary=dns_primary,
            dns_secondary=dns_secondary,
            download_bandwidth_mbps=download_bandwidth_mbps,
            upload_bandwidth_mbps=upload_bandwidth_mbps,
            auto_failback=auto_failback,
        )
        return link, True

    async def get_link(
        self,
        link_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> IspLink:
        link = await self.repository.get_link_by_id(link_id)
        if link is None:
            raise IspLinkNotFoundError(link_id)
        if (
            requesting_organization_id is not None
            and link.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationIspLinkAccessError()
        return link

    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[IspLink], object]:
        return await self.repository.list_links(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=page,
            page_size=page_size,
        )

    async def update_link(
        self,
        link_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> IspLink:
        link = await self.get_link(
            link_id, requesting_organization_id=requesting_organization_id
        )
        if fields.get("role") == IspLinkRole.PRIMARY.value and link.role != (
            IspLinkRole.PRIMARY.value
        ):
            existing_primary = await self.repository.get_primary_link_for_router(
                link.router_id
            )
            if existing_primary is not None and existing_primary.id != link.id:
                raise IspPrimaryLinkAlreadyExistsError(link.router_id)
        # Deliberately NOT cross-link-validated here (unlike
        # set_wan_routing_mode, which does enforce "every enabled link or
        # none" via validate_wan_routing_weights): an admin sets one
        # link's weight per call, the same one-link-per-PUT shape this
        # whole endpoint already has, so validating "every other enabled
        # link is *also* weighted" on the very first call would make it
        # impossible to ever weight links one at a time -- the first
        # weighted link would always conflict with its still-unweighted
        # siblings. A transient partial-weighting is harmless: the script
        # generator only ever applies weights once every enabled link
        # has one, silently falling back to the existing even split
        # otherwise (see IspLink.load_balance_weight's own docstring) --
        # set_wan_routing_mode is the real "commit" point this gets
        # validated at.
        updated = await self.repository.update_link(
            link, {**fields, "updated_by": actor_user_id}
        )
        event = IspLinkUpdated(link_id=updated.id)
        logger.info("isp_link_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.ISP_LINK_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"ISP link '{updated.provider_name}' updated",
        )
        return updated

    async def set_wan_routing_mode(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        mode: WanRoutingMode,
    ) -> Router:
        """Sets a router's own ``wan_routing_mode`` -- the RouterOS script
        generator (frontend) reads this (alongside every enabled link's
        ``load_balance_weight``) to decide between the plain
        distance-ordered failover-only routes and the GCD-reduced weighted
        PCC mangle rules; see ``WanRoutingMode``'s own docstring for why
        these are structurally different code paths, not one path with a
        parameter. Switching *to* ``FAILOVER_ONLY`` never validates or
        touches existing weights (see that enum's own docstring on why
        they're left alone, not cleared, for a possible switch back)."""
        # Existence/org-access check only -- the returned Router isn't
        # otherwise needed in this method.
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        if mode is WanRoutingMode.LOAD_BALANCE:
            siblings = await self.repository.list_links_for_router(router_id)
            validate_wan_routing_weights(
                router_id=router_id,
                mode=mode,
                enabled_link_weights=[
                    s.load_balance_weight for s in siblings if s.is_enabled
                ],
            )
        updated = await self.router_lookup.update_router(
            actor_user_id=actor_user_id,
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
            data={"wan_routing_mode": mode.value},
        )
        # Not this module's own `_audit` helper -- that one hardcodes
        # `entity_type="isp_link"` (correct for every other audit call in
        # this file, all genuine isp_link mutations); this one is a
        # router-level change, so it writes directly with the correct
        # entity_type instead of mislabeling it.
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=AuditAction.ROUTER_WAN_ROUTING_MODE_CHANGED.value,
                entity_type="router",
                entity_id=router_id,
                description=(
                    f"Router '{updated.name}' WAN routing mode set to '{mode.value}'"
                ),
                organization_id=updated.organization_id,
            )
        return updated

    async def delete_link(
        self,
        link_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> IspLink:
        link = await self.get_link(
            link_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_link(link)
        event = IspLinkDeleted(link_id=deleted.id, router_id=deleted.router_id)
        logger.info("isp_link_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.ISP_LINK_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"ISP link '{deleted.provider_name}' deleted",
        )
        return deleted

    # ========================================================================
    # Health checks
    # ========================================================================

    async def list_health_checks(
        self,
        link_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> tuple[list[IspHealthCheck], object]:
        """Verifies tenant ownership of the link first (via ``get_link``),
        then returns its paginated health-check history, optionally
        scoped to ``[start, end]``. Both filters are additive and default
        to ``None`` (no range restriction) so every existing caller keeps
        its current "just the most recent page" behavior unchanged."""
        await self.get_link(
            link_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_health_checks_for_link(
            link_id, page=page, page_size=page_size, start=start, end=end
        )

    # Hourly buckets stay legible through a full week (<=168 bars);
    # anything longer than that (up to the history dialog's 30-day cap)
    # switches to daily buckets (<=31 bars) instead of rendering
    # 168-720+ bars for a "30 days" selection.
    _HOURLY_BUCKET_MAX_SPAN = timedelta(days=7)

    async def get_health_check_summary(
        self,
        link_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        start: datetime,
        end: datetime,
    ) -> tuple[str, list[HealthCheckBucket]]:
        """Time-bucketed uptime/latency summary for the history dialog's
        chart -- real SQL-side aggregation
        (``IspRepository.bucketed_health_checks_for_link``), never
        individual rows, so a 30-day window at the sweep's real 60-second
        cadence (~43k rows per link) comes back as ~30 aggregated rows."""
        await self.get_link(
            link_id, requesting_organization_id=requesting_organization_id
        )
        bucket_unit = "hour" if (end - start) <= self._HOURLY_BUCKET_MAX_SPAN else "day"
        rows = await self.repository.bucketed_health_checks_for_link(
            link_id, start=start, end=end, bucket_unit=bucket_unit
        )
        buckets = [
            HealthCheckBucket(
                bucket_start=bucket_start,
                total_checks=total,
                healthy_count=healthy,
                degraded_count=degraded,
                unhealthy_count=unhealthy,
                uptime_percentage=(
                    round(100.0 * (total - unhealthy) / total, 2) if total else None
                ),
                avg_latency_ms=(
                    round(avg_latency, 2) if avg_latency is not None else None
                ),
                avg_packet_loss_percentage=(
                    round(avg_loss, 2) if avg_loss is not None else None
                ),
                avg_download_mbps=(
                    round(avg_download, 2) if avg_download is not None else None
                ),
                avg_upload_mbps=(
                    round(avg_upload, 2) if avg_upload is not None else None
                ),
                max_download_mbps=(
                    round(max_download, 2) if max_download is not None else None
                ),
            )
            for (
                bucket_start,
                total,
                healthy,
                degraded,
                unhealthy,
                avg_latency,
                avg_loss,
                avg_download,
                avg_upload,
                max_download,
            ) in rows
        ]
        return bucket_unit, buckets

    async def check_link_health(
        self,
        link_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> IspLink:
        """Admin-triggered, on-demand health check -- issues one real
        ``/tool/ping`` immediately, rather than waiting for the next
        scheduled sweep tick. Shares ``record_health_check_result``'s
        exact same recording/failover-evaluation logic the sweep itself
        uses, so a manual check can trigger a real failover exactly like a
        scheduled one would."""
        link = await self.get_link(
            link_id, requesting_organization_id=requesting_organization_id
        )
        if not link.is_enabled:
            raise IspLinkDisabledError(link.id)
        ping_result = await self.ping_link(link)
        traffic = await self.safe_sample_link_traffic(link)
        return await self.record_health_check_result(
            link, ping_result=ping_result, traffic=traffic
        )

    async def run_speed_test(
        self,
        link_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> SpeedTestOutcome:
        """Admin-triggered, on-demand "Run Speed Test" action -- like
        ``check_link_health``, but additionally issues a real RouterOS
        ``/tool/fetch`` download of ``SPEED_TEST_DOWNLOAD_URL`` against the
        router's own real WAN uplink to measure genuine current download
        throughput (see ``device_adapters.py``'s ``run_speed_test``
        docstring for exactly how, and its one real precision caveat).
        Latency/packet loss reuse ``ping_link``'s existing, connection-
        mode-aware real ping -- "free" per the founder's own framing, not
        a second invented metric.

        **Deliberately never written into the ``IspHealthCheck`` table.**
        That table's own ``download_mbps``/``upload_mbps`` columns already
        carry a distinct meaning -- ambient traffic-load *rate*, computed
        from successive interface-counter deltas at each routine health
        check (see ``record_health_check_result``) -- and folding a
        synthetic-download-test result into that same series would corrupt
        the "Traffic Load" graph's own meaning for whichever tick this
        landed on. This result is reported directly to the caller and
        recorded only as an audit-log entry
        (``AuditAction.ISP_LINK_SPEED_TEST_RUN``) -- the same "operator
        explicitly triggers something with real side effects" posture
        ``RouterService.reveal_credentials``/router reboot already carry
        elsewhere in this codebase, since this genuinely generates real
        traffic against a real, possibly metered ISP link, not a passive
        read.

        No ``upload_mbps`` is ever returned -- see ``SpeedTestOutcome``'s
        own docstring.

        **Real per-link cooldown + in-flight marker (both Redis-backed,
        both no-ops if this service was constructed without a real
        ``redis`` client).** Unlike every other RBAC-gated action in this
        domain, this one genuinely consumes real, possibly-metered
        customer bandwidth and briefly saturates a low-power router each
        time it runs -- repeating it back-to-back (two admins racing each
        other, a double-submit, or deliberate abuse by anyone holding
        ``isp.execute``) has a real external cost plain RBAC gating
        doesn't address. ``SPEED_TEST_COOLDOWN_REDIS_KEY_TEMPLATE`` (``SET
        NX EX``, the same atomic pattern ``OtpRateLimiter`` already
        establishes for OTP requests) rejects a second test on the same
        link within ``SPEED_TEST_MIN_INTERVAL_SECONDS`` with a real,
        honest ``IspSpeedTestCooldownError`` carrying the live remaining
        TTL -- never a silent queue/wait. Separately,
        ``SPEED_TEST_ACTIVE_REDIS_KEY_TEMPLATE`` is set for the real
        duration of the on-router fetch below and read by
        ``record_health_check_result`` -- see that method's own docstring
        for why the automated sweep's own concurrent ping against this
        same link must never let a purely self-induced-congestion reading
        advance this link toward a real failover."""
        link = await self.get_link(
            link_id, requesting_organization_id=requesting_organization_id
        )
        if not link.is_enabled:
            raise IspLinkDisabledError(link.id)

        if self._redis is not None:
            cooldown_key = SPEED_TEST_COOLDOWN_REDIS_KEY_TEMPLATE.format(
                link_id=link.id
            )
            acquired = await self._redis.set(
                cooldown_key, "1", nx=True, ex=SPEED_TEST_MIN_INTERVAL_SECONDS
            )
            if not acquired:
                ttl = await self._redis.ttl(cooldown_key)
                raise IspSpeedTestCooldownError(
                    link.id,
                    ttl if ttl and ttl > 0 else SPEED_TEST_MIN_INTERVAL_SECONDS,
                )

        router = await self.router_lookup.get_router(link.router_id)
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise IspMissingCredentialsError(router.id)
        adapter = self._get_device_adapter(router.vendor)

        # Latency/packet loss: the exact same real, connection-mode-aware
        # ping ping_link already performs for routine health checks.
        ping_result = await self.ping_link(link)

        # Download throughput: a real, slow, on-demand fetch. Its own
        # credentials object carries a much larger timeout
        # (SPEED_TEST_TIMEOUT_SECONDS) than the fast ping above -- a real
        # multi-megabyte download over a real WAN link genuinely needs
        # more than ISP_PING_TIMEOUT_SECONDS to complete.
        speed_credentials = IspCredentials(
            host=host,
            username=router.api_username,
            password=secret,
            timeout_seconds=SPEED_TEST_TIMEOUT_SECONDS,
        )
        active_key = SPEED_TEST_ACTIVE_REDIS_KEY_TEMPLATE.format(link_id=link.id)
        if self._redis is not None:
            await self._redis.set(
                active_key, "1", ex=SPEED_TEST_ACTIVE_REDIS_TTL_SECONDS
            )
        try:
            speed_result = await adapter.run_speed_test(
                speed_credentials, download_url=SPEED_TEST_DOWNLOAD_URL
            )
        finally:
            # Cleared the moment the real fetch finishes/fails, well before
            # the TTL safety net above would expire it on its own -- a
            # failed/slow test shouldn't keep suppressing the sweep's own
            # failover evaluation on this link any longer than the real
            # congestion actually lasted.
            if self._redis is not None:
                await self._redis.delete(active_key)

        outcome = SpeedTestOutcome(
            isp_link_id=link.id,
            tested_at=datetime.now(UTC),
            download_mbps=speed_result.download_mbps,
            upload_mbps=None,
            latency_ms=ping_result.avg_rtt_ms,
            packet_loss_percentage=ping_result.packet_loss_percentage,
            downloaded_bytes=speed_result.downloaded_bytes,
            duration_seconds=speed_result.duration_seconds,
        )
        logger.info(
            "isp_link_speed_test_run",
            extra={
                "isp_link_id": str(link.id),
                "download_mbps": outcome.download_mbps,
                "latency_ms": outcome.latency_ms,
                "downloaded_bytes": outcome.downloaded_bytes,
                "duration_seconds": outcome.duration_seconds,
            },
        )
        await self._audit(
            actor_user_id,
            AuditAction.ISP_LINK_SPEED_TEST_RUN,
            entity_id=link.id,
            organization_id=link.organization_id,
            description=(
                f"Speed test run on ISP link '{link.provider_name}': "
                f"{outcome.download_mbps} Mbps down"
                + (
                    f", {outcome.latency_ms:.1f}ms latency"
                    if outcome.latency_ms is not None
                    else ""
                )
            ),
        )
        return outcome

    async def ping_link(self, link: IspLink) -> PingResult:
        """Resolves this link's own real health-check target and executes
        it -- the resolution strategy itself is driven entirely by the
        link's own ``connection_mode`` (never anything hardcoded to a
        particular link/router), so every ISP link platform-wide, on
        every router, gets the strategy that actually matches how its own
        WAN connection is configured:

        * ``STATIC`` -- pings ``gateway_ip_address`` (the historical,
          only-ever-supported behavior, unchanged).
        * ``DHCP`` -- never trusts a manually-typed value (there isn't
          one); resolves the router's own *live* default gateway via
          ``get_active_default_gateway`` at check time, then pings that,
          so a mid-lease ISP-side gateway change is always reflected on
          the very next check, never stale. That lookup prefers a
          genuinely dynamic default route but falls back to an active
          static one -- required because this platform's own Setup
          Script generator deliberately provisions a *static* default
          route (not a dynamic one) for every dhcp-client it creates, to
          avoid it fighting the routing-mark/failover mangle rules (see
          ``device_adapters.py``'s own module docstring for the full,
          fleet-wide-production-bug write-up); a route that exists but
          is currently inactive (a real ``check-gateway`` failure) is
          still correctly treated as "no usable target."
        * ``PPPOE`` -- no gateway/ping involved at all; the link's own
          ``interface`` PPPoE client's real up/down state *is* the health
          signal, synthesized into a ``PingResult`` shape (0%
          loss/0ms for up, 100% loss/``None`` latency for down) purely so
          ``record_health_check_result``'s existing classification/
          recording pipeline keeps working completely unchanged for this
          mode too -- one recording path, three ways to arrive at it.
        """
        router = await self.router_lookup.get_router(link.router_id)
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise IspMissingCredentialsError(router.id)
        credentials = IspCredentials(
            host=host, username=router.api_username, password=secret
        )
        adapter = self._get_device_adapter(router.vendor)

        if link.connection_mode == IspConnectionMode.PPPOE.value:
            if not link.interface:
                raise IspHealthCheckTargetUnavailableError(
                    link.id, "PPPOE mode but no interface configured on this link"
                )
            is_up = await adapter.get_pppoe_interface_status(
                credentials, interface_name=link.interface
            )
            return (
                PingResult(
                    sent=1, received=1, packet_loss_percentage=0.0, avg_rtt_ms=0.0
                )
                if is_up
                else PingResult(
                    sent=1, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
                )
            )

        if link.connection_mode == IspConnectionMode.DHCP.value:
            target_ip = await adapter.get_active_default_gateway(credentials)
            if not target_ip:
                raise IspHealthCheckTargetUnavailableError(
                    link.id,
                    "DHCP mode but no active default route (dynamic or "
                    "static) currently present on the router",
                )
        else:
            target_ip = link.gateway_ip_address or host

        return await adapter.ping(
            credentials,
            target_ip=target_ip,
            count=ISP_PING_COUNT,
            timeout_seconds=ISP_PING_TIMEOUT_SECONDS,
        )

    async def sample_link_traffic(self, link: IspLink) -> TrafficCounters | None:
        """Real, best-effort traffic-load sample for the "how much
        traffic is flowing on this link right now" graph -- connection-
        mode-independent (unlike ``ping_link``): a link's own interface
        byte counters exist regardless of whether its IP is static/DHCP/
        PPPoE, so this always reads ``link.interface`` directly, on every
        mode uniformly. For a PPPOE link this is the same interface
        ``ping_link`` already checks for up/down state -- RouterOS gives
        that virtual interface its own real counters (see
        ``device_adapters.py``'s own module docstring).

        Returns ``None`` (never a fabricated ``0``) whenever there is
        nothing real to attribute a counter to: no interface configured
        on this link, no router credentials, or the router doesn't
        recognize that interface name. Never raises on a *device*
        failure either -- callers use ``safe_sample_link_traffic`` to turn
        any real connection error into the same honest ``None``, since a
        traffic-sampling failure is a value-add feature going dark for
        one tick, never a reason to fail an otherwise-successful health
        check."""
        if not link.interface:
            return None
        router = await self.router_lookup.get_router(link.router_id)
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            return None
        credentials = IspCredentials(
            host=host, username=router.api_username, password=secret
        )
        adapter = self._get_device_adapter(router.vendor)
        counters = await adapter.get_interface_traffic_counters(
            credentials, interface_name=link.interface
        )
        if counters is None:
            return None
        rx_bytes, tx_bytes = counters
        return TrafficCounters(rx_bytes=rx_bytes, tx_bytes=tx_bytes)

    async def safe_sample_link_traffic(self, link: IspLink) -> TrafficCounters | None:
        try:
            return await self.sample_link_traffic(link)
        except Exception as exc:  # noqa: BLE001 -- see sample_link_traffic's own docstring
            logger.warning(
                "isp_traffic_sample_failed",
                extra={"isp_link_id": str(link.id), "error": str(exc)},
            )
            return None

    async def record_health_check_result(
        self,
        link: IspLink,
        *,
        ping_result: PingResult,
        traffic: TrafficCounters | None = None,
    ) -> IspLink:
        """Records one real health-check reading and advances this link's
        current state accordingly.

        **Real row lock against a concurrent writer on the exact same
        link.** ``link`` (the caller's argument) may be a snapshot read
        *before* the real, possibly slow device I/O in ``ping_link``/
        ``sample_link_traffic`` completed -- and this method's own writes
        below (``consecutive_unhealthy_count + 1``, the traffic-counter
        delta) are read-then-increment against that snapshot's *previous*
        value. A manual "Check health now" racing the automated 60s sweep
        on the same link (two independent DB sessions, each with its own
        in-memory copy) is a genuine last-write-wins lost update without
        protection -- so this re-fetches the row via ``SELECT ... FOR
        UPDATE`` (``IspRepository.get_link_for_update``) first, and every
        read/write below uses that freshly-locked ``current`` row, never
        the possibly-stale ``link`` argument. The second concurrent caller
        to reach this point blocks until the first commits, then correctly
        computes its own delta against the first's *committed* result --
        real serialization, not a best-effort guess.

        **Self-congestion suppression.** If ``IspService.run_speed_test``
        has this same link's own real on-router download in flight right
        now (``constants.SPEED_TEST_ACTIVE_REDIS_KEY_TEMPLATE``), an
        ``UNHEALTHY`` reading landing in this exact window is at real risk
        of being purely a side effect of that speed test's own bandwidth
        saturation, not a genuine outage -- it is still recorded honestly
        (the real ``IspHealthCheck`` row/status are never suppressed or
        faked), but it does not advance ``consecutive_unhealthy_count``
        toward a real failover, so an admin troubleshooting a flaky link
        with "Run Speed Test" can never *cause* the very failover they're
        trying to diagnose around. A recovering (``HEALTHY``/``DEGRADED``)
        reading during that same window is never suppressed -- resetting
        the streak early is always safe."""
        current = await self.repository.get_link_for_update(link.id)
        if current is None:
            # The link was hard-removed out from under this call between
            # the caller's own read and this point -- a real (if rare)
            # race, not a reason to crash a routine health check. Fall
            # back to the caller's own snapshot so the rest of this method
            # still runs against a valid, if slightly stale, object.
            current = link

        now = datetime.now(UTC)
        status = classify_health_status(
            latency_ms=ping_result.avg_rtt_ms,
            packet_loss_percentage=ping_result.packet_loss_percentage,
        )

        speed_test_active = False
        if self._redis is not None and status == HealthStatus.UNHEALTHY:
            # `TTL` alone (no separate `GET`) is enough to test presence --
            # this key is always written with a real expiry (see
            # run_speed_test), so a positive remaining TTL means "still
            # in flight" and -2 (Redis's own "no such key" sentinel) means
            # "not running" -- matches this module's own narrow
            # `_RedisProtocol` (set/ttl/delete only, no `get` needed).
            active_key = SPEED_TEST_ACTIVE_REDIS_KEY_TEMPLATE.format(link_id=current.id)
            remaining_ttl = await self._redis.ttl(active_key)
            speed_test_active = remaining_ttl is not None and remaining_ttl > 0

        if status == HealthStatus.UNHEALTHY:
            if speed_test_active:
                logger.warning(
                    "isp_health_check_unhealthy_during_speed_test_suppressed",
                    extra={"isp_link_id": str(current.id)},
                )
                new_consecutive_unhealthy = current.consecutive_unhealthy_count
            else:
                new_consecutive_unhealthy = current.consecutive_unhealthy_count + 1
        else:
            new_consecutive_unhealthy = 0

        # Traffic-load rate: a real delta between this tick's counters and
        # the *previous* reading, over the real elapsed wall-clock time
        # between them -- never computed from a single snapshot (that's
        # not a rate, it's just a number), and never negative (an
        # interface reset mid-window means "no valid rate this tick", not
        # a garbage value) -- see sample_link_traffic's own docstring.
        download_mbps: float | None = None
        upload_mbps: float | None = None
        if (
            traffic is not None
            and current.last_rx_bytes is not None
            and current.last_tx_bytes is not None
            and current.last_checked_at is not None
        ):
            elapsed_seconds = (now - current.last_checked_at).total_seconds()
            if elapsed_seconds > 0:
                rx_delta = traffic.rx_bytes - current.last_rx_bytes
                tx_delta = traffic.tx_bytes - current.last_tx_bytes
                if rx_delta >= 0:
                    download_mbps = round(
                        (rx_delta * 8) / elapsed_seconds / 1_000_000, 3
                    )
                if tx_delta >= 0:
                    upload_mbps = round(
                        (tx_delta * 8) / elapsed_seconds / 1_000_000, 3
                    )

        await self.repository.create_health_check(
            isp_link_id=current.id,
            checked_at=now,
            status=status.value,
            source=HealthStatusSource.AUTOMATED.value,
            latency_ms=ping_result.avg_rtt_ms,
            packet_loss_percentage=ping_result.packet_loss_percentage,
            error_message=None,
            download_mbps=download_mbps,
            upload_mbps=upload_mbps,
        )
        update_fields: dict[str, object] = {
            "health_status": status.value,
            # A real ping always reclaims the link back to AUTOMATED,
            # overwriting any earlier manual override -- see
            # constants.HealthStatusSource's own docstring.
            "health_status_source": HealthStatusSource.AUTOMATED.value,
            "latency_ms": ping_result.avg_rtt_ms,
            "packet_loss_percentage": ping_result.packet_loss_percentage,
            "last_checked_at": now,
            "consecutive_unhealthy_count": new_consecutive_unhealthy,
        }
        if traffic is not None:
            # Always store this tick's own raw counters for the *next*
            # tick's delta, regardless of whether a rate was computable
            # this time (e.g. the link's very first sample ever) --
            # current_download_mbps/upload_mbps are left untouched (not
            # nulled) when a rate genuinely couldn't be computed, so a
            # single transient sampling gap doesn't blank out the last
            # known-real reading.
            update_fields["last_rx_bytes"] = traffic.rx_bytes
            update_fields["last_tx_bytes"] = traffic.tx_bytes
            if download_mbps is not None:
                update_fields["current_download_mbps"] = download_mbps
            if upload_mbps is not None:
                update_fields["current_upload_mbps"] = upload_mbps
        updated = await self.repository.update_link(current, update_fields)
        event = IspHealthCheckRecorded(
            link_id=updated.id,
            status=status.value,
            latency_ms=ping_result.avg_rtt_ms,
            packet_loss_percentage=ping_result.packet_loss_percentage,
        )
        logger.info("isp_health_check_recorded", extra=_event_extra(event))
        return await self._maybe_transition_uplink(updated)

    async def set_manual_health_status(
        self,
        link_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        health_status: HealthStatus,
        reason: str | None = None,
    ) -> IspLink:
        """An admin's own manual override of a link's *current* status --
        the "Internet Connection" dashboard view's one real write. Never
        opens a device connection or triggers a failover/failback itself
        (this view is read/observe-only against the router; see
        ``models.py``'s own "Manual status override" write-up) -- it only
        records what an admin has told this domain is true right now,
        exactly like a real reading would, so the existing
        ``health_status``/``health_status_source`` columns and the
        ``IspHealthCheck`` history/"Status Timeline" stay a single source
        of truth rather than growing a second, frontend-only notion of
        status. The very next real ping (sweep or manual check) reclaims
        the link back to ``HealthStatusSource.AUTOMATED`` regardless of
        this override -- see ``record_health_check_result``.

        Restricted to ``HEALTHY``/``UNHEALTHY`` at the schema layer
        (``IspLinkManualStatusRequest``) -- an admin's override is a
        binary "it's up" / "it's down" call, never a nuanced
        ``DEGRADED``/``UNKNOWN`` classification only a real measurement
        can produce.
        """
        link = await self.get_link(
            link_id, requesting_organization_id=requesting_organization_id
        )
        now = datetime.now(UTC)
        await self.repository.create_health_check(
            isp_link_id=link.id,
            checked_at=now,
            status=health_status.value,
            source=HealthStatusSource.MANUAL.value,
            latency_ms=None,
            packet_loss_percentage=None,
            error_message=reason,
        )
        updated = await self.repository.update_link(
            link,
            {
                "health_status": health_status.value,
                "health_status_source": HealthStatusSource.MANUAL.value,
                "last_checked_at": now,
                "updated_by": actor_user_id,
            },
        )
        event = IspLinkManualStatusSet(
            link_id=updated.id, health_status=health_status.value, reason=reason
        )
        logger.info("isp_link_manual_status_set", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.ISP_LINK_MANUAL_STATUS_SET,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=(
                f"ISP link '{updated.provider_name}' manually marked "
                f"{health_status.value}"
                + (f" ({reason})" if reason else "")
            ),
        )
        return updated

    async def _maybe_transition_uplink(self, link: IspLink) -> IspLink:
        """After recording a health check, evaluates whether this reading
        just crossed a real failover/failback boundary -- called from both
        the manual check endpoint and the scheduled sweep so there is
        exactly one place this decision is made."""
        if (
            link.role == IspLinkRole.PRIMARY.value
            and link.is_active_uplink
            and is_failover_threshold_reached(
                consecutive_unhealthy_count=link.consecutive_unhealthy_count,
                threshold=DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER,
            )
        ):
            try:
                return await self.trigger_failover(
                    link.router_id,
                    actor_user_id=None,
                    reason="consecutive_health_check_failures",
                )
            except IspNoBackupLinkAvailableError:
                # A real, honest outcome: the primary is down and there is
                # nothing safe to fail over to. Logged, never raised back
                # at the caller of a routine health check.
                logger.warning(
                    "isp_failover_unavailable", extra={"router_id": str(link.router_id)}
                )
                return link
        if (
            link.role == IspLinkRole.PRIMARY.value
            and not link.is_active_uplink
            and link.auto_failback
            and link.health_status == HealthStatus.HEALTHY.value
        ):
            return await self.trigger_failback(link.router_id, actor_user_id=None)
        return link

    # ========================================================================
    # Failover / failback
    # ========================================================================

    async def trigger_failover(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        reason: str,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> IspLink:
        """Fails traffic over from the router's current active uplink to
        its best available ``BACKUP`` -- "best" meaning the
        lowest-``priority``, enabled backup whose own ``health_status`` is
        not currently ``UNHEALTHY`` (a link this domain already knows is
        down is never a safe failover target). Raises
        ``IspNoBackupLinkAvailableError`` if none qualifies -- the
        primary's own outage is real, but there is nothing safe to switch
        to."""
        current_active = await self.repository.get_active_uplink_for_router(router_id)
        backups = await self.repository.list_backup_links_for_router(router_id)
        candidate = next(
            (
                backup
                for backup in backups
                if backup.is_enabled
                and backup.health_status != HealthStatus.UNHEALTHY.value
                and not (current_active and backup.id == current_active.id)
            ),
            None,
        )
        if candidate is None:
            raise IspNoBackupLinkAvailableError(router_id)

        if current_active is not None:
            await self.repository.update_link(
                current_active, {"is_active_uplink": False}
            )
        promoted = await self.repository.update_link(
            candidate, {"is_active_uplink": True}
        )
        event = IspFailoverTriggered(
            router_id=router_id,
            from_link_id=current_active.id if current_active else promoted.id,
            to_link_id=promoted.id,
            reason=reason,
        )
        logger.info("isp_failover_triggered", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.ISP_FAILOVER_TRIGGERED,
            entity_id=promoted.id,
            organization_id=promoted.organization_id,
            description=(
                f"ISP failover on router {router_id}: traffic moved to "
                f"'{promoted.provider_name}' ({reason})"
            ),
        )
        return promoted

    async def trigger_failback(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> IspLink:
        """Reverses a failover, handing traffic back to the router's own
        ``PRIMARY`` link. Requires the primary to currently be
        ``HEALTHY`` -- failing back onto a still-degraded/unhealthy link
        would recreate the exact outage the failover just fixed."""
        primary = await self.repository.get_primary_link_for_router(router_id)
        if primary is None or primary.health_status != HealthStatus.HEALTHY.value:
            raise IspNoBackupLinkAvailableError(router_id)
        if primary.is_active_uplink:
            return primary

        current_active = await self.repository.get_active_uplink_for_router(router_id)
        promoted = await self.repository.update_link(
            primary, {"is_active_uplink": True}
        )
        if current_active is not None:
            await self.repository.update_link(
                current_active, {"is_active_uplink": False}
            )
        event = IspFailbackTriggered(
            router_id=router_id,
            from_link_id=current_active.id if current_active else promoted.id,
            to_link_id=promoted.id,
        )
        logger.info("isp_failback_triggered", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.ISP_FAILBACK_TRIGGERED,
            entity_id=promoted.id,
            organization_id=promoted.organization_id,
            description=(
                f"ISP failback on router {router_id}: traffic restored to "
                f"primary '{promoted.provider_name}'"
            ),
        )
        return promoted

    # ========================================================================
    # Availability (computed read-model, never persisted)
    # ========================================================================

    def compute_availability_percentage(
        self, health_checks: list[IspHealthCheck]
    ) -> float | None:
        """The fraction of ``health_checks`` that came back HEALTHY or
        DEGRADED (i.e. *not* UNHEALTHY) -- a pure function of history,
        deliberately never persisted as its own column (mirrors
        ``app.domains.wireguard.constants.HealthStatus``'s own "computed
        at read time, not stored" reasoning: it would only ever risk
        drifting stale against the very history it summarizes). Returns
        ``None`` when there is no history at all yet to compute a
        percentage from -- not ``100.0`` (a link nobody has ever checked
        is not "fully available", it is simply unmeasured)."""
        if not health_checks:
            return None
        up_count = sum(
            1 for check in health_checks if check.status != HealthStatus.UNHEALTHY.value
        )
        return round(100.0 * up_count / len(health_checks), 2)

    async def compute_unhealthy_since(self, link: IspLink) -> datetime | None:
        """"Down since when" -- a computed read-model derived entirely
        from real, already-persisted ``IspHealthCheck`` history, never a
        new stored column (identical "computed at read time" posture as
        ``compute_availability_percentage`` above). ``None`` unless the
        link's own *current* ``health_status`` is ``UNHEALTHY`` right
        now.

        Walks history newest-to-oldest and returns the ``checked_at`` of
        the earliest row in the unbroken ``UNHEALTHY`` run ending at the
        most recent reading -- this works uniformly whether that run is
        entirely real ping failures, entirely a manual "Mark Down"
        override, or a mix of both, precisely because both write into the
        same ``IspHealthCheck`` table tagged only by ``source`` (see
        ``models.py``'s own "Manual status override" write-up) rather
        than two separate histories that would each need their own scan.
        Capped at ``UNHEALTHY_SINCE_LOOKBACK_LIMIT`` rows -- if the entire
        capped window is UNHEALTHY, returns that window's own oldest
        ``checked_at`` as a real, honest lower bound rather than an exact
        instant."""
        if link.health_status != HealthStatus.UNHEALTHY.value:
            return None
        checks = await self.repository.list_recent_health_checks_for_link(
            link.id, limit=UNHEALTHY_SINCE_LOOKBACK_LIMIT
        )
        since: datetime | None = None
        for check in checks:
            if check.status != HealthStatus.UNHEALTHY.value:
                break
            since = check.checked_at
        return since

    # ========================================================================
    # Internal helpers
    # ========================================================================

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="isp_link",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


async def run_health_check_sweep(
    repository: IspRepositoryProtocol,
    router_lookup: RouterLookupProtocol,
    *,
    audit_writer: AuditLogWriter | None = None,
    device_adapter_resolver=get_isp_health_adapter,
    redis: _RedisProtocol | None = None,
) -> HealthCheckSweepSummary:
    """The platform-wide health-check sweep ``tasks.run_isp_health_check_sweep``
    (Celery Beat) drives -- pulled out to module scope for the identical
    "Celery task + test suite share one real implementation, no live
    Postgres needed for the latter" reason
    ``app.domains.guest.service.enforce_session_timeouts``/
    ``run_fup_time_accrual`` were. Health-checks every enabled
    ``IspLink`` platform-wide, one at a time, with **per-link failure
    isolation**: a router that is unreachable/misconfigured (missing
    credentials, connection refused) is logged and skipped, never aborting
    the sweep for every other router's own links -- mirrors
    ``app.domains.billing.renewal_service.RenewalService
    .run_renewal_sweep``'s identical per-item isolation contract."""
    service = IspService(
        repository,
        router_lookup,
        audit_writer=audit_writer,
        device_adapter_resolver=device_adapter_resolver,
        redis=redis,
    )
    links = await repository.list_enabled_links_for_sweep()
    checked = 0
    failovers = 0
    failbacks = 0
    skipped = 0
    errors = 0
    for link in links:
        # Only a STATIC-mode link with no manually-entered gateway has
        # nothing to check at all -- skipped before even trying, exactly
        # as before this connection-mode split existed. DHCP links
        # legitimately have no gateway_ip_address (resolved live every
        # check -- see IspService.ping_link) and PPPOE links never had
        # one in the first place, so neither is ever skipped here; any
        # real resolution failure for either (e.g. DHCP hasn't leased
        # yet) surfaces through the same per-link try/except isolation
        # below as IspHealthCheckTargetUnavailableError, not a silent
        # pre-emptive skip that looks identical to "nothing to do here."
        if (
            link.connection_mode == IspConnectionMode.STATIC.value
            and not link.gateway_ip_address
        ):
            skipped += 1
            continue
        try:
            try:
                ping_result = await service.ping_link(link)
            except (
                IspDeviceConnectionError,
                IspDeviceOperationError,
                IspHealthCheckTargetUnavailableError,
            ) as exc:
                # A router that has gone genuinely unreachable (the exact
                # case this sweep exists to catch -- confirmed live: a WAN
                # uplink pulled on the one real test router left this
                # link's `last_checked_at`/`health_status` frozen at its
                # last successful check *forever*, since this branch used
                # to just log-and-skip like the missing-credentials/
                # unsupported-vendor config-error case below, never
                # reaching `record_health_check_result` at all -- a link
                # whose router is completely gone looked identical to one
                # checked seconds ago and genuinely healthy) is real
                # information about this link's own health, not a reason
                # to skip recording anything. Synthesize the worst-case
                # `PingResult` `classify_health_status` already treats as
                # `UNHEALTHY` (see its own docstring: a missing reading is
                # never silently "fine") and let it flow through the exact
                # same recording/consecutive-count/failover pipeline a
                # real failed ping would.
                logger.warning(
                    "isp_health_check_link_unreachable",
                    extra={"isp_link_id": str(link.id), "error": str(exc)},
                )
                ping_result = PingResult(
                    sent=1, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
                )
            traffic = await service.safe_sample_link_traffic(link)
            before_active = link.is_active_uplink
            before_role = link.role
            updated = await service.record_health_check_result(
                link, ping_result=ping_result, traffic=traffic
            )
            checked += 1
            if (
                before_role == IspLinkRole.PRIMARY.value
                and before_active
                and not updated.is_active_uplink
            ):
                failovers += 1
            elif (
                before_role == IspLinkRole.PRIMARY.value
                and not before_active
                and updated.is_active_uplink
            ):
                failbacks += 1
        except Exception as exc:  # noqa: BLE001 -- genuine config errors (missing
            # credentials, unsupported vendor) stay skip-only: there is no
            # live device state to record a health *reading* against, and
            # retrying every sweep tick would just repeat the same log line
            # until an admin fixes the configuration -- see per-link
            # isolation docstring above.
            errors += 1
            logger.warning(
                "isp_health_check_sweep_link_failed",
                extra={"isp_link_id": str(link.id), "error": str(exc)},
            )
    return HealthCheckSweepSummary(
        checked=checked,
        failovers=failovers,
        failbacks=failbacks,
        skipped=skipped,
        errors=errors,
    )


__all__ = [
    "RouterLookupProtocol",
    "AuditLogWriter",
    "HealthCheckSweepSummary",
    "TrafficCounters",
    "SpeedTestOutcome",
    "IspService",
    "run_health_check_sweep",
]
