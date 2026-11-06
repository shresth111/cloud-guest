"""FastAPI routes for the Monitored Hardware domain: register/list/delete
a venue's own network hardware.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against the
new ``monitored_hardware.*`` permission keys (see
``app.domains.rbac.seed`` -- ``PermissionModule.MONITORED_HARDWARE``) and
resolves ``CurrentOrganization``, passed through to
``MonitoredHardwareService`` as ``requesting_organization_id``.

**Route ordering matters.** ``GET /monitored-hardware`` is registered
before ``GET /monitored-hardware/{device_id}`` so Starlette's
first-match-wins routing resolves the literal path first, mirroring
``app.domains.network_device.router``'s identical discipline.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import AuthUser
from app.domains.dhcp.dependencies import get_dhcp_service
from app.domains.dhcp.service import DhcpService
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .dependencies import get_monitored_hardware_service
from .models import MonitoredHardware
from .schemas import (
    MessageResponse,
    MonitoredHardwareAddressBinding,
    MonitoredHardwareHealth,
    MonitoredHardwareHealthEvent,
    MonitoredHardwareListResponse,
    MonitoredHardwareRegisterRequest,
    MonitoredHardwareResponse,
)
from .service import HardwareWithStatus, MonitoredHardwareService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/monitored-hardware", tags=["Monitored Hardware"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _pagination_fields(meta: PaginationMeta) -> dict[str, int | bool]:
    return {
        "page": meta.page,
        "page_size": meta.page_size,
        "total_items": meta.total_items,
        "total_pages": meta.total_pages,
        "has_next": meta.has_next,
        "has_previous": meta.has_previous,
    }


#: A health row whose last probe is older than this is not a current
#: reading: the sweep runs every 30s, so five minutes means it stalled or
#: the router stopped answering. Reported as such, never as the old state.
_HEALTH_STALE_AFTER = timedelta(minutes=5)


def _health_response(item: HardwareWithStatus) -> MonitoredHardwareHealth | None:
    health = item.health
    if health is None:
        return None
    state, reason = health.state, health.reason
    if datetime.now(UTC) - health.last_probe_at > _HEALTH_STALE_AFTER:
        state, reason = "unknown", "not_checked_recently"
    flaps = sum(e.count or 0 for e in item.events if e.kind == "link_down")
    return MonitoredHardwareHealth(
        state=state,
        reason=reason,
        since=health.since,
        checked_at=health.last_probe_at,
        consecutive_failures=health.consecutive_failures,
        last_ok_at=health.last_ok_at,
        last_rtt_ms=health.last_rtt_ms,
        probe_method=health.probe_method,
        port_name=health.port_name,
        port_running=health.port_running,
        port_last_link_down_at=health.port_last_link_down_at,
        port_last_link_up_at=health.port_last_link_up_at,
        link_flaps_24h=flaps,
        clients_behind=health.clients_behind,
        rx_bps=health.rx_bps,
        tx_bps=health.tx_bps,
        events_24h=[
            MonitoredHardwareHealthEvent(
                at=e.occurred_at,
                kind=e.kind,
                from_state=e.from_state,
                to_state=e.to_state,
                reason=e.reason,
                count=e.count,
                detail=e.detail,
            )
            for e in item.events
        ],
    )


def _device_response(item: HardwareWithStatus) -> MonitoredHardwareResponse:
    device = item.device
    return MonitoredHardwareResponse(
        id=str(device.id),
        organization_id=str(device.organization_id),
        location_id=str(device.location_id),
        router_id=str(device.router_id) if device.router_id else None,
        name=device.name,
        mac_address=device.mac_address,
        device_type=device.device_type,
        floor=device.floor,
        status=item.status.value,
        last_seen_at=item.last_seen_at,
        connected_at=item.connected_at,
        status_source=item.status_source.value,
        status_reason=item.status_reason.value,
        health=_health_response(item),
        duplicate_locations=list(item.duplicate_locations),
        registered_elsewhere=item.registered_elsewhere,
        created_at=device.created_at,
    )


async def _bind_address(
    device: MonitoredHardware,
    service: MonitoredHardwareService,
    dhcp_service: DhcpService,
    *,
    actor_user_id: uuid.UUID,
) -> MonitoredHardwareAddressBinding:
    """Registering hardware binds its IP: the lease it holds right now is
    made static on the router that serves it. Best-effort -- the device is
    already registered, so nothing here may fail the request; a device
    with no lease yet is bound by the next device sync instead (see
    ``connected_devices.tasks._pin_monitored_hardware_leases``)."""
    router_ids = await service.lease_router_ids(device)
    if not router_ids:
        return MonitoredHardwareAddressBinding(status="unsupported")
    last_problem: MonitoredHardwareAddressBinding | None = None
    for router_id in router_ids:
        try:
            router_row = await dhcp_service.router_lookup.get_router(
                router_id, requesting_organization_id=device.organization_id
            )
            outcomes = await dhcp_service.pin_device_leases(
                router_row, [device.mac_address], actor_user_id=actor_user_id
            )
        except Exception as exc:  # noqa: BLE001 -- best-effort, see docstring
            logger.warning(
                "monitored_hardware_bind_failed",
                extra={"router_id": str(router_id), "error": str(exc)},
            )
            last_problem = MonitoredHardwareAddressBinding(
                status="failed", router_id=str(router_id), detail=str(exc)
            )
            continue
        for outcome in outcomes:
            if outcome.status == "no_lease":
                continue
            binding = MonitoredHardwareAddressBinding(
                status=outcome.status,
                ip_address=outcome.ip_address,
                router_id=str(router_id),
                detail=outcome.detail,
            )
            if outcome.status in {"pinned", "already_static"}:
                return binding
            last_problem = binding
    return last_problem or MonitoredHardwareAddressBinding(status="no_lease")


@router.post(
    "",
    response_model=ApiResponse[MonitoredHardwareResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("monitored_hardware.create"))],
)
async def register_monitored_hardware(
    request: Request,
    payload: MonitoredHardwareRegisterRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MonitoredHardwareService = Depends(get_monitored_hardware_service),
    dhcp_service: DhcpService = Depends(get_dhcp_service),
):
    device = await service.register_device(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        location_id=uuid.UUID(payload.location_id),
        router_id=uuid.UUID(payload.router_id) if payload.router_id else None,
        name=payload.name,
        mac_address=payload.mac_address,
        device_type=payload.device_type,
        floor=payload.floor,
    )
    binding = await _bind_address(
        device, service, dhcp_service, actor_user_id=uuid.UUID(actor.id)
    )
    item = await service.with_status(device)
    response = _device_response(item)
    response.address_binding = binding
    return build_response(
        success=True,
        message="Monitored hardware registered",
        data=response.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[MonitoredHardwareListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitored_hardware.read"))],
)
async def list_monitored_hardware(
    request: Request,
    location_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MonitoredHardwareService = Depends(get_monitored_hardware_service),
):
    items, meta = await service.list_devices(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        page=page,
        page_size=page_size,
    )
    payload = MonitoredHardwareListResponse(
        items=[_device_response(item) for item in items],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Monitored hardware retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{device_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitored_hardware.delete"))],
)
async def delete_monitored_hardware(
    request: Request,
    device_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MonitoredHardwareService = Depends(get_monitored_hardware_service),
):
    await service.delete_device(
        device_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Monitored hardware deleted",
        data=MessageResponse(message="Monitored hardware deleted").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
