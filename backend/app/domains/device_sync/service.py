"""Device Synchronization business logic: orchestrates every real
per-router sync mechanism this codebase has, records one immutable
:class:`~.models.DeviceSyncRun` row per invocation.

## Composition, not duplication, with three other domains

* ``app.domains.router`` -- ``RouterLookupProtocol`` resolves the target
  router (existence/tenant-scoping), identical to every other domain in
  this codebase.
* ``app.domains.connected_devices`` -- ``ConnectedDeviceSyncProtocol``
  (satisfied structurally by the real ``ConnectedDeviceService``) drives
  the real DHCP-lease/ARP/wireless sync.
* ``app.domains.queue_management`` -- ``QueueSyncProtocol`` (satisfied
  structurally by the real ``QueueManagementService``) drives the real
  per-assignment device re-push via ``reapply_assignments_for_router``
  (added to that domain specifically for this orchestrator).
* ``app.domains.provisioning_engine`` -- ``ProvisioningLookupProtocol``
  (satisfied structurally by the real ``ProvisioningEngineService``) is
  a read-only check of the latest real ``ProvisionJob`` for this router.

DHCP/VLAN/Port Forwarding are always reported ``NOT_PROVISIONED`` -- see
this domain's own ``__init__.py`` module docstring for why (no real
device push exists for those domains today; that work is deferred to the
not-yet-built Network Configuration Management domain, never duplicated
or preempted here).

## Per-component failure isolation

One component's own failure (e.g. the router is unreachable for a
Connected Devices sync, but Queue Management's own device push still
succeeds) never aborts the other components -- mirrors
``app.domains.isp.service.run_health_check_sweep``'s identical per-item
isolation contract, applied here to *components of one run* rather than
*routers of one sweep*. The overall run status
(``validators.compute_overall_status``) reflects the mix honestly:
``SUCCESS``/``PARTIAL``/``FAILED``.

## Sync History: one immutable row per invocation

Mirrors ``app.domains.provisioning_engine.models.ProvisionJob``'s own
"new row, not mutate" convention -- there is no ``update`` method on this
domain's own repository at all. "Sync History" is simply
``list_runs``, ordered by ``started_at`` descending, never a second
table.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import UTC, datetime
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import UNPROVISIONED_COMPONENTS, SyncComponent, SyncComponentStatus
from .events import DeviceSyncRunCompleted
from .exceptions import (
    CrossOrganizationDeviceSyncRunAccessError,
    DeviceSyncRunNotFoundError,
)
from .models import DeviceSyncRun
from .repository import DeviceSyncRepositoryProtocol
from .validators import compute_overall_status

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
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...


class ConnectedDeviceSyncProtocol(Protocol):
    """The one ``ConnectedDeviceService`` method this module needs --
    reused directly, never reimplemented."""

    async def sync_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> object: ...


class QueueSyncProtocol(Protocol):
    """The one ``QueueManagementService`` method this module needs --
    reused directly, never reimplemented."""

    async def reapply_assignments_for_router(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> object: ...


class ProvisioningLookupProtocol(Protocol):
    """The one ``ProvisioningEngineService`` method this module needs --
    reused directly, never reimplemented."""

    async def list_jobs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        status: object | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list, object]: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Service
# ============================================================================


class DeviceSyncService:
    """Core Device Synchronization business logic."""

    def __init__(
        self,
        repository: DeviceSyncRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        connected_device_sync: ConnectedDeviceSyncProtocol,
        queue_sync: QueueSyncProtocol,
        provisioning_lookup: ProvisioningLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.connected_device_sync = connected_device_sync
        self.queue_sync = queue_sync
        self.provisioning_lookup = provisioning_lookup
        self.audit_writer = audit_writer

    async def sync_router(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> DeviceSyncRun:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        started_at = datetime.now(UTC)
        component_results: dict[str, dict[str, object]] = {}

        try:
            summary = await self.connected_device_sync.sync_router(
                router.id, requesting_organization_id=requesting_organization_id
            )
            component_results[SyncComponent.CONNECTED_DEVICES.value] = {
                "status": SyncComponentStatus.SUCCESS.value,
                "summary": {
                    "discovered": summary.discovered,
                    "updated": summary.updated,
                    "disconnected": summary.disconnected,
                },
            }
        except Exception as exc:  # noqa: BLE001 -- per-component isolation, see docstring
            component_results[SyncComponent.CONNECTED_DEVICES.value] = {
                "status": SyncComponentStatus.FAILED.value,
                "summary": {"error": str(exc)},
            }

        try:
            queue_summary = await self.queue_sync.reapply_assignments_for_router(
                router.id,
                actor_user_id=actor_user_id,
                requesting_organization_id=requesting_organization_id,
            )
            component_results[SyncComponent.QUEUE_MANAGEMENT.value] = {
                "status": SyncComponentStatus.SUCCESS.value,
                "summary": {
                    "reapplied": queue_summary.reapplied,
                    "failed": queue_summary.failed,
                },
            }
        except Exception as exc:  # noqa: BLE001 -- per-component isolation, see docstring
            component_results[SyncComponent.QUEUE_MANAGEMENT.value] = {
                "status": SyncComponentStatus.FAILED.value,
                "summary": {"error": str(exc)},
            }

        try:
            jobs, _ = await self.provisioning_lookup.list_jobs(
                requesting_organization_id=requesting_organization_id,
                router_id=router.id,
                page=1,
                page_size=1,
            )
            if jobs:
                component_results[SyncComponent.PROVISIONING.value] = {
                    "status": SyncComponentStatus.SUCCESS.value,
                    "summary": {
                        "job_id": str(jobs[0].id),
                        "job_status": jobs[0].status,
                    },
                }
            else:
                component_results[SyncComponent.PROVISIONING.value] = {
                    "status": SyncComponentStatus.NO_JOBS.value,
                    "summary": None,
                }
        except Exception as exc:  # noqa: BLE001 -- per-component isolation, see docstring
            component_results[SyncComponent.PROVISIONING.value] = {
                "status": SyncComponentStatus.FAILED.value,
                "summary": {"error": str(exc)},
            }

        for component in UNPROVISIONED_COMPONENTS:
            component_results[component.value] = {
                "status": SyncComponentStatus.NOT_PROVISIONED.value,
                "summary": None,
            }

        completed_at = datetime.now(UTC)
        overall_status = compute_overall_status(component_results)

        run = await self.repository.create_run(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            status=overall_status.value,
            component_results=component_results,
            started_at=started_at,
            completed_at=completed_at,
            created_by=actor_user_id,
        )
        event = DeviceSyncRunCompleted(
            id=run.id, router_id=router.id, status=overall_status.value
        )
        logger.info("device_sync_run_completed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            entity_id=run.id,
            organization_id=run.organization_id,
            description=(
                f"Device sync for router {router.id} completed: {overall_status.value}"
            ),
        )
        return run

    async def get_run(
        self,
        run_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> DeviceSyncRun:
        run = await self.repository.get_run_by_id(run_id)
        if run is None:
            raise DeviceSyncRunNotFoundError(run_id)
        if (
            requesting_organization_id is not None
            and run.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationDeviceSyncRunAccessError()
        return run

    async def list_runs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[DeviceSyncRun], object]:
        return await self.repository.list_runs(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=page,
            page_size=page_size,
        )

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        *,
        entity_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=AuditAction.DEVICE_SYNC_RUN_COMPLETED.value,
            entity_type="device_sync_run",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = [
    "RouterLookupProtocol",
    "ConnectedDeviceSyncProtocol",
    "QueueSyncProtocol",
    "ProvisioningLookupProtocol",
    "AuditLogWriter",
    "DeviceSyncService",
]
