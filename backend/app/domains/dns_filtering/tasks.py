"""Celery tasks for DNS filtering: keep the DoH-by-IP / DoH-by-hostname
bypass layers fresh.

## Shape

Coordinator + per-router fan-out, the same as
``app.domains.dhcp.tasks.run_rogue_dhcp_detection_sweep``:

* **Coordinator** (Beat, every
  ``constants.DNS_BYPASS_REFRESH_INTERVAL_SECONDS``): takes a Redis overlap
  lock, fetches the public DoH lists **once for the whole platform**,
  validates them (``bypass_lists``: literals only, global unicast only,
  exclusions, a hard cap, and a refusal to shrink by more than half -- the
  last good copy stays in force), stores them, then dispatches one leaf per
  router that has a list-backed layer on. Its I/O is outbound HTTPS to
  GitHub plus the database; no router is dialled here, so it stays on the
  default queue.
* **Leaf** (``DEVICE_IO_QUEUE_NAME``): one RouterOS round trip on 8728,
  which re-converges that router's layers only if the combined list
  version moved since its last push. Controller-managed routers are
  refused before anything, like every other device write.

Nothing here touches a router that has not opted in, and a router whose
push fails keeps the rules it already has -- the error is recorded on its
row, never raised out of the task.
"""

from __future__ import annotations

import uuid

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.redis import create_redis_client
from app.database.session import SessionLocal
from app.domains.location.repository import (
    LocationCodeCounterRepository,
    LocationRepository,
)
from app.domains.location.service import LocationService
from app.domains.organization.repository import OrganizationRepository
from app.domains.organization.service import OrganizationService
from app.domains.rbac.repository import RBACRepository
from app.domains.router.repository import RouterRepository
from app.domains.router.service import RouterService

from .bypass_lists import HttpxListFetcher, RefreshSettings, refresh_blocklists
from .constants import (
    DNS_BYPASS_REFRESH_LOCK_REDIS_KEY,
    DNS_BYPASS_REFRESH_LOCK_TTL_SECONDS,
    LIST_BACKED_LAYERS,
    TASK_PUSH_DNS_BYPASS_LISTS_FOR_ROUTER,
    TASK_REFRESH_DNS_BYPASS_BLOCKLISTS,
)
from .repository import DnsFilteringRepository
from .service import DnsFilteringService

logger = get_logger(__name__)


def _refresh_settings() -> RefreshSettings:
    settings = get_settings()
    return RefreshSettings(
        ipv4_url=settings.dns_bypass_doh_ipv4_url,
        ipv6_url=settings.dns_bypass_doh_ipv6_url,
        domains_url=settings.dns_bypass_doh_domains_url,
        max_entries=settings.dns_bypass_list_max_entries,
        min_keep_ratio=settings.dns_bypass_list_min_keep_ratio,
        ip_exclusions=tuple(settings.dns_bypass_ip_exclusions),
        hostname_exclusions=tuple(settings.dns_bypass_hostname_exclusions),
    )


def _build_service(session) -> DnsFilteringService:  # noqa: ANN001
    """The real service graph, minus Cloudflare: a list push never touches
    Gateway (only the VPN toggle does, and that is a request, not this
    task). ``audit_writer`` stays ``None`` -- a scheduled refresh is not an
    operator action."""
    settings = get_settings()
    audit_repository = RBACRepository(session)
    organization_service = OrganizationService(
        OrganizationRepository(session), audit_writer=audit_repository
    )
    location_service = LocationService(
        LocationRepository(session),
        organization_service,
        location_code_counter=LocationCodeCounterRepository(session),
        audit_writer=audit_repository,
    )
    router_service = RouterService(
        RouterRepository(session),
        location_service,
        organization_service,
        audit_writer=audit_repository,
    )
    return DnsFilteringService(
        DnsFilteringRepository(session),
        router_service,
        location_service,
        gateway=None,
        probe_hostname=settings.dns_filtering_probe_hostname,
        ip_exclusions=tuple(settings.dns_bypass_ip_exclusions),
        hostname_exclusions=tuple(settings.dns_bypass_hostname_exclusions),
        list_max_entries=settings.dns_bypass_list_max_entries,
    )


async def _refresh_and_dispatch_async() -> dict[str, object]:
    redis = create_redis_client()
    try:
        acquired = await redis.set(
            DNS_BYPASS_REFRESH_LOCK_REDIS_KEY,
            "1",
            nx=True,
            ex=DNS_BYPASS_REFRESH_LOCK_TTL_SECONDS,
        )
        if not acquired:
            return {"dispatched": 0, "skipped_locked": True}
        try:
            settings = get_settings()
            async with SessionLocal() as session:
                repository = DnsFilteringRepository(session)
                outcome = await refresh_blocklists(
                    repository,
                    HttpxListFetcher(
                        timeout_seconds=settings.dns_bypass_list_timeout_seconds
                    ),
                    _refresh_settings(),
                )
                rows = await repository.list_bypass_hardened()
                router_ids = [
                    str(row.router_id)
                    for row in rows
                    if set(row.bypass_layers or []) & LIST_BACKED_LAYERS
                ]
            for router_id in router_ids:
                push_dns_bypass_lists_for_router.delay(router_id)
            return {
                "dispatched": len(router_ids),
                "skipped_locked": False,
                "lists": outcome.statuses,
                "errors": outcome.errors,
            }
        finally:
            await redis.delete(DNS_BYPASS_REFRESH_LOCK_REDIS_KEY)
    finally:
        await redis.aclose()


@celery_app.task(name=TASK_REFRESH_DNS_BYPASS_BLOCKLISTS)
def refresh_dns_bypass_blocklists() -> dict[str, object]:
    """Beat-scheduled coordinator. See the module docstring."""
    result = run_celery_task(_refresh_and_dispatch_async())
    logger.info("dns_bypass_blocklists_refreshed", extra=result)
    return result


async def _push_for_router_async(router_id: uuid.UUID) -> str:
    async with SessionLocal() as session:
        try:
            outcome = await _build_service(session).push_bypass_lists_to_router(
                router_id
            )
            await session.commit()
            return outcome
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_PUSH_DNS_BYPASS_LISTS_FOR_ROUTER)
def push_dns_bypass_lists_for_router(router_id: str) -> str:
    """Per-router leaf on the device-I/O queue."""
    outcome = run_celery_task(_push_for_router_async(uuid.UUID(router_id)))
    logger.info(
        "dns_bypass_lists_pushed", extra={"router_id": router_id, "outcome": outcome}
    )
    return outcome


__all__ = ["push_dns_bypass_lists_for_router", "refresh_dns_bypass_blocklists"]
