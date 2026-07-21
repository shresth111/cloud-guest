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
from datetime import UTC, datetime
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import (
    DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER,
    ISP_PING_COUNT,
    ISP_PING_TIMEOUT_SECONDS,
    HealthStatus,
    IspLinkRole,
)
from .device_adapters import IspCredentials, PingResult, get_isp_health_adapter
from .events import (
    IspFailbackTriggered,
    IspFailoverTriggered,
    IspHealthCheckRecorded,
    IspLinkCreated,
    IspLinkDeleted,
    IspLinkUpdated,
)
from .exceptions import (
    CrossOrganizationIspLinkAccessError,
    IspLinkDisabledError,
    IspLinkNotFoundError,
    IspMissingCredentialsError,
    IspNoBackupLinkAvailableError,
    IspPrimaryLinkAlreadyExistsError,
)
from .models import IspHealthCheck, IspLink
from .repository import IspRepositoryProtocol
from .validators import classify_health_status, is_failover_threshold_reached

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
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        self._get_device_adapter = device_adapter_resolver

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
    ) -> tuple[list[IspHealthCheck], object]:
        """Verifies tenant ownership of the link first (via ``get_link``),
        then returns its paginated health-check history."""
        await self.get_link(
            link_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_health_checks_for_link(
            link_id, page=page, page_size=page_size
        )

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
        return await self.record_health_check_result(link, ping_result=ping_result)

    async def ping_link(self, link: IspLink) -> PingResult:
        router = await self.router_lookup.get_router(link.router_id)
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise IspMissingCredentialsError(router.id)
        credentials = IspCredentials(
            host=host, username=router.api_username, password=secret
        )
        target_ip = link.gateway_ip_address or host
        adapter = self._get_device_adapter(router.vendor)
        return await adapter.ping(
            credentials,
            target_ip=target_ip,
            count=ISP_PING_COUNT,
            timeout_seconds=ISP_PING_TIMEOUT_SECONDS,
        )

    async def record_health_check_result(
        self, link: IspLink, *, ping_result: PingResult
    ) -> IspLink:
        now = datetime.now(UTC)
        status = classify_health_status(
            latency_ms=ping_result.avg_rtt_ms,
            packet_loss_percentage=ping_result.packet_loss_percentage,
        )
        new_consecutive_unhealthy = (
            link.consecutive_unhealthy_count + 1
            if status == HealthStatus.UNHEALTHY
            else 0
        )
        await self.repository.create_health_check(
            isp_link_id=link.id,
            checked_at=now,
            status=status.value,
            latency_ms=ping_result.avg_rtt_ms,
            packet_loss_percentage=ping_result.packet_loss_percentage,
            error_message=None,
        )
        updated = await self.repository.update_link(
            link,
            {
                "health_status": status.value,
                "latency_ms": ping_result.avg_rtt_ms,
                "packet_loss_percentage": ping_result.packet_loss_percentage,
                "last_checked_at": now,
                "consecutive_unhealthy_count": new_consecutive_unhealthy,
            },
        )
        event = IspHealthCheckRecorded(
            link_id=updated.id,
            status=status.value,
            latency_ms=ping_result.avg_rtt_ms,
            packet_loss_percentage=ping_result.packet_loss_percentage,
        )
        logger.info("isp_health_check_recorded", extra=_event_extra(event))
        return await self._maybe_transition_uplink(updated)

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
    )
    links = await repository.list_enabled_links_for_sweep()
    checked = 0
    failovers = 0
    failbacks = 0
    skipped = 0
    errors = 0
    for link in links:
        if not link.gateway_ip_address:
            skipped += 1
            continue
        try:
            ping_result = await service.ping_link(link)
            before_active = link.is_active_uplink
            before_role = link.role
            updated = await service.record_health_check_result(
                link, ping_result=ping_result
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
        except Exception as exc:  # noqa: BLE001 -- per-link isolation, see docstring
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
    "IspService",
    "run_health_check_sweep",
]
