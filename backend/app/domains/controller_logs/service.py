"""Controller Logs business logic: a read-only aggregator over six real
log sources, one method per category. No writes, no new table -- see
``__init__.py``'s own module docstring for the full source mapping.

## Composition, not duplication, with five other domains

Every method here composes a narrow, duck-typed Protocol satisfied
structurally by a real, already-existing service/repository -- the
identical composition-over-duplication pattern every domain in this
codebase establishes. Nothing in this module ever queries another
domain's own table directly.

## Provision Logs: merging per-job logs, a real, documented bound

``ProvisionLog`` rows are stored per ``ProvisionJob``, not per router --
listing "provision logs for a router" means fetching this router's own
``MAX_PROVISION_JOBS_FOR_LOG_MERGE`` most recent jobs first (via the
real, org-validating ``ProvisioningJobLookupProtocol.get_history``), then
merging each job's own real logs (via ``ProvisionLogLookupProtocol
.list_logs_for_job``), sorted newest-first, paginated in Python. This is
a real, documented bound (never a silent, unbounded fetch across every
job a router has ever had) -- see this module's own ``constants.py``.

## Authentication Logs: two real sources, two real scopes

Admin/user login attempts (``LoginAttemptLookupProtocol``) are genuinely
platform-wide -- ``LoginAttempt`` has no ``organization_id`` column at
all. Guest login history (``GuestLoginHistoryLookupProtocol``) is
tenant-scoped. These are exposed as two distinct methods/endpoints, never
merged into one list -- forcing them together would either fabricate an
organization scope the admin-login side doesn't have, or silently drop
the guest side's own real tenant filter.

## System Logs: platform component health, not per-router

``HealthCheckLookupProtocol.get_health_history`` requires a
``component`` (database/redis/celery/...) -- there is no "all
components" mode on the real source this composes, and no per-router
system log exists anywhere in this codebase (confirmed during design).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from app.database.utils.pagination import PageParams, PaginationMeta

from .constants import MAX_PROVISION_JOBS_FOR_LOG_MERGE


class ProvisioningJobLookupProtocol(Protocol):
    async def get_history(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]: ...


class ProvisionLogLookupProtocol(Protocol):
    async def list_logs_for_job(self, job_id: uuid.UUID) -> list: ...


class ConfigVersionLookupProtocol(Protocol):
    async def list_versions(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]: ...


class RouterEventLookupProtocol(Protocol):
    async def list_events(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]: ...


class LoginAttemptLookupProtocol(Protocol):
    async def list_login_attempts(
        self,
        *,
        email: str | None = None,
        success: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]: ...


class GuestLoginHistoryLookupProtocol(Protocol):
    async def list_login_history(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        guest_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list, object]: ...


class HealthCheckLookupProtocol(Protocol):
    async def get_health_history(
        self, *, component: object, page: int, page_size: int
    ) -> tuple[list, object]: ...


class ControllerLogsService:
    """Core Controller Logs business logic -- see module docstring."""

    def __init__(
        self,
        provisioning_job_lookup: ProvisioningJobLookupProtocol,
        provision_log_lookup: ProvisionLogLookupProtocol,
        config_version_lookup: ConfigVersionLookupProtocol,
        router_event_lookup: RouterEventLookupProtocol,
        login_attempt_lookup: LoginAttemptLookupProtocol,
        guest_login_history_lookup: GuestLoginHistoryLookupProtocol,
        health_check_lookup: HealthCheckLookupProtocol,
    ) -> None:
        self.provisioning_job_lookup = provisioning_job_lookup
        self.provision_log_lookup = provision_log_lookup
        self.config_version_lookup = config_version_lookup
        self.router_event_lookup = router_event_lookup
        self.login_attempt_lookup = login_attempt_lookup
        self.guest_login_history_lookup = guest_login_history_lookup
        self.health_check_lookup = health_check_lookup

    async def list_provision_logs(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, PaginationMeta]:
        jobs, _ = await self.provisioning_job_lookup.get_history(
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
            page=1,
            page_size=MAX_PROVISION_JOBS_FOR_LOG_MERGE,
        )
        merged = []
        for job in jobs:
            merged.extend(await self.provision_log_lookup.list_logs_for_job(job.id))
        merged.sort(key=lambda entry: entry.logged_at, reverse=True)
        return _paginate_in_memory(merged, page=page, page_size=page_size)

    async def list_configuration_logs(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]:
        return await self.config_version_lookup.list_versions(
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
            page=page,
            page_size=page_size,
        )

    async def list_router_logs(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]:
        return await self.router_event_lookup.list_events(
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
            page=page,
            page_size=page_size,
        )

    async def list_admin_authentication_logs(
        self,
        *,
        email: str | None = None,
        success: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]:
        return await self.login_attempt_lookup.list_login_attempts(
            email=email, success=success, page=page, page_size=page_size
        )

    async def list_guest_authentication_logs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        guest_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]:
        return await self.guest_login_history_lookup.list_login_history(
            organization_id=requesting_organization_id,
            location_id=location_id,
            guest_id=guest_id,
            page=page,
            page_size=page_size,
        )

    async def list_system_logs(
        self, *, component: object, page: int = 1, page_size: int = 25
    ) -> tuple[list, object]:
        return await self.health_check_lookup.get_health_history(
            component=component, page=page, page_size=page_size
        )


def _paginate_in_memory(
    items: list, *, page: int, page_size: int
) -> tuple[list, PaginationMeta]:
    """Pure helper for the one category (Provision Logs) whose own
    entries are merged across multiple real sources in Python rather
    than paginated at the query layer -- uses the same real
    ``PageParams``/``PaginationMeta`` utilities every repository's own
    ``paginate`` call uses under the hood, not a hand-rolled
    reimplementation."""
    params = PageParams(page=page, page_size=page_size)
    paged = items[params.offset : params.offset + params.page_size]
    return paged, PaginationMeta.from_total(params, len(items))


__all__ = [
    "ProvisioningJobLookupProtocol",
    "ProvisionLogLookupProtocol",
    "ConfigVersionLookupProtocol",
    "RouterEventLookupProtocol",
    "LoginAttemptLookupProtocol",
    "GuestLoginHistoryLookupProtocol",
    "HealthCheckLookupProtocol",
    "ControllerLogsService",
]
