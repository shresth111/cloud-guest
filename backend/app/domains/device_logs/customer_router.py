"""Customer NetLogs HTTP surface: ``/device-logs`` (list), ``/summary``,
``/export.csv``. Read-only, one organization.

Every route carries the same guards, in this order:

1. ``RequireOrganization`` -- exactly one organization, the caller's, as the
   request context resolved it. A Global Super Admin whose context names no
   organization is refused (400 ``UnspecifiedOrganizationScopeError``), and so
   is an explicit "all organizations" request (400
   ``SingleOrganizationRequiredError``): ``None`` never means "every tenant"
   here.
2. ``RequirePermission("network_logs.read", scope=ScopeType.LOCATION)`` --
   pinned explicitly (never inferred from headers: the scope-inference
   trap). An organization grant satisfies it for that organization, a
   location grant for that location.

Then, in the handler, ``NetLogsConfinement`` narrows every query to the
locations the caller holds ``network_logs.read`` on, and the service
validates ``location_id``/``router_id`` against the organization
(``customer_service``). There is no ``organization_id`` parameter.

Why a new ``network_logs`` permission and not ``device_logs.read``:
``device_logs`` is the Master viewer's key, GLOBAL-only by design (its lines
span every tenant and include unattributed traffic, tunnel IPs and tags).
Widening it to organization scope would make the Master key assignable to
customer roles. Same split as ``traffic_flows`` (Master) / ``venue_traffic``
(customer).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import RequireOrganization, RequirePermission
from app.domains.rbac.enums import ScopeType

from .constants import MAX_PAGE_SIZE
from .customer_scope import NETWORK_LOGS_READ, LogsConfinement, NetLogsConfinement
from .customer_service import NetLogsCustomerService
from .dependencies import get_netlogs_customer_service
from .repository import CustomerFilters, CustomerLogsRepository
from .schemas import NetLogPage, NetLogSummary

__all__ = ["netlogs_customer_router"]

netlogs_customer_router = APIRouter(prefix="/device-logs", tags=["NetLogs (customer)"])

_READ = RequirePermission(NETWORK_LOGS_READ, scope=ScopeType.LOCATION)
_GUARDS: list[Any] = [Depends(RequireOrganization), Depends(_READ)]

_LIST_HELP = "Repeatable, or comma-separated."


def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID", "") or str(
        getattr(getattr(request, "state", None), "request_id", "")
    )


async def _filters(
    service: NetLogsCustomerService,
    *,
    organization_id: uuid.UUID,
    confinement: LogsConfinement,
    **params: Any,
) -> CustomerFilters:
    return await service.build_filters(
        organization_id=organization_id, confinement=confinement, **params
    )


@netlogs_customer_router.get(
    "", response_model=ApiResponse[NetLogPage], dependencies=_GUARDS
)
async def list_netlogs(
    request: Request,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    router_id: uuid.UUID | None = Query(default=None),
    severity: list[str] | None = Query(default=None, description=_LIST_HELP),
    max_severity: int | None = Query(default=None, ge=0, le=7),
    category: list[str] | None = Query(default=None, description=_LIST_HELP),
    protocol: list[str] | None = Query(default=None, description=_LIST_HELP),
    status: list[str] | None = Query(default=None, description=_LIST_HELP),
    q: str | None = Query(default=None, max_length=200),
    cursor: str | None = Query(default=None, max_length=200),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    confinement: LogsConfinement = Depends(NetLogsConfinement),
    service: NetLogsCustomerService = Depends(get_netlogs_customer_service),
) -> dict[str, Any]:
    """This organization's device log lines, newest first, keyset-paginated.
    Default window: the last 24 hours; at most 730 days."""
    filters = await _filters(
        service,
        organization_id=organization_id,
        confinement=confinement,
        since=since,
        until=until,
        location_id=location_id,
        router_id=router_id,
        severity=severity,
        max_severity=max_severity,
        category=category,
        protocol=protocol,
        status=status,
        q=q,
        cursor=cursor,
    )
    data = await service.list_events(filters, limit=limit)
    return build_response(
        success=True,
        message="Network logs",
        data=NetLogPage.model_validate(data).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@netlogs_customer_router.get(
    "/summary", response_model=ApiResponse[NetLogSummary], dependencies=_GUARDS
)
async def netlogs_summary(
    request: Request,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    router_id: uuid.UUID | None = Query(default=None),
    severity: list[str] | None = Query(default=None, description=_LIST_HELP),
    category: list[str] | None = Query(default=None, description=_LIST_HELP),
    protocol: list[str] | None = Query(default=None, description=_LIST_HELP),
    status: list[str] | None = Query(default=None, description=_LIST_HELP),
    q: str | None = Query(default=None, max_length=200),
    tz: str | None = Query(default=None, max_length=64),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    confinement: LogsConfinement = Depends(NetLogsConfinement),
    service: NetLogsCustomerService = Depends(get_netlogs_customer_service),
) -> dict[str, Any]:
    """Counts by local day (``tz``, default Asia/Kolkata), category and
    severity; error/warning totals; the ten busiest routers. Same filters
    and scoping as the list. Default window: the last 7 days."""
    filters = await _filters(
        service,
        organization_id=organization_id,
        confinement=confinement,
        since=since,
        until=until,
        location_id=location_id,
        router_id=router_id,
        severity=severity,
        category=category,
        protocol=protocol,
        status=status,
        q=q,
        default_window=timedelta(days=7),
    )
    data = await service.summary(filters, tz=tz)
    return build_response(
        success=True,
        message="Network logs summary",
        data=NetLogSummary.model_validate(data).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@asynccontextmanager
async def _own_repository() -> AsyncIterator[CustomerLogsRepository]:
    from app.database.session import SessionLocal

    async with SessionLocal() as session:
        yield CustomerLogsRepository(session)


@netlogs_customer_router.get("/export.csv", dependencies=_GUARDS)
async def export_netlogs_csv(
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    router_id: uuid.UUID | None = Query(default=None),
    severity: list[str] | None = Query(default=None, description=_LIST_HELP),
    max_severity: int | None = Query(default=None, ge=0, le=7),
    category: list[str] | None = Query(default=None, description=_LIST_HELP),
    protocol: list[str] | None = Query(default=None, description=_LIST_HELP),
    status: list[str] | None = Query(default=None, description=_LIST_HELP),
    q: str | None = Query(default=None, max_length=200),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    confinement: LogsConfinement = Depends(NetLogsConfinement),
    service: NetLogsCustomerService = Depends(get_netlogs_customer_service),
) -> StreamingResponse:
    """The list's rows as CSV (newest first, at most 100,000 rows; a final
    ``# truncated`` line says when the cap was hit). Same filters and
    scoping as the list. 409 while device logging is switched off."""
    service.require_enabled()
    filters = await _filters(
        service,
        organization_id=organization_id,
        confinement=confinement,
        since=since,
        until=until,
        location_id=location_id,
        router_id=router_id,
        severity=severity,
        max_severity=max_severity,
        category=category,
        protocol=protocol,
        status=status,
        q=q,
    )
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return StreamingResponse(
        service.export_csv(filters, _own_repository),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="netlogs-{stamp}.csv"',
            "Cache-Control": "no-store",
        },
    )
