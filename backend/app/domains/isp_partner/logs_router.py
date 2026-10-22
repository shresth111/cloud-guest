"""``/isp/logs/*`` (API_CONTRACT §4.9): NetLogs, IPDR and guest auth logs
across the ISP's customers.

Shared filters ``isp_customer_id`` / ``isp_location_id`` / ``isp_router_id``
go through ``IspScope`` (a location or router implies its customer); with no
customer named, queries run over ``IspContext.child_ids()`` -- the caller's
confinement already applied -- and an empty list returns empty results.
Windows default to the last 24 h and are clamped exactly as the source
domains clamp them, because the source domains' own ``build_filters`` do it.
"""

from __future__ import annotations

import csv
import io
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.session import get_db_session
from app.domains.controller_logs.schemas import GuestLoginHistoryLogResponse
from app.domains.controller_logs.service import ControllerLogsService
from app.domains.device_logs.constants import (
    CUSTOMER_EXPORT_CHUNK,
    CUSTOMER_EXPORT_MAX_ROWS,
)
from app.domains.device_logs.constants import (
    DEFAULT_PAGE_SIZE as NETLOG_DEFAULT_PAGE,
)
from app.domains.device_logs.constants import (
    MAX_PAGE_SIZE as NETLOG_MAX_PAGE,
)
from app.domains.device_logs.customer_scope import LogsConfinement
from app.domains.device_logs.customer_service import (
    CSV_COLUMNS,
    NetLogsCustomerService,
    _csv_safe,
    event_view,
)
from app.domains.device_logs.repository import CustomerFilters
from app.domains.device_logs.service import encode_cursor
from app.domains.guest.models import GuestLoginHistory
from app.domains.guest.repository import GuestRepository
from app.domains.ipdr.constants import (
    AUDIT_ACTION_IPDR_EXPORTED,
    AUDIT_ACTION_IPDR_LISTED,
    EXPORT_MAX_ROWS,
    IPDR_COLUMNS,
    PROVENANCE_COLUMNS,
)
from app.domains.ipdr.constants import (
    MAX_PAGE_SIZE as IPDR_MAX_PAGE,
)
from app.domains.ipdr.dependencies import get_ipdr_service, ipdr_service_for
from app.domains.ipdr.formatting import csv_cells
from app.domains.ipdr.router import write_audit
from app.domains.ipdr.service import IpdrService
from app.domains.organization.models import Organization
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepository, RBACRepositoryProtocol

from .constants import (
    DEFAULT_PAGE_SIZE,
    ISP_IPDR_EXPORT,
    ISP_IPDR_READ,
    ISP_LOGS_EXPORT,
    ISP_LOGS_READ,
    MAX_PAGE_SIZE,
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspCustomerRequiredError
from .http import ok
from .logs_repository import IspLogsRepository
from .scoping import IspScope

logger = get_logger(__name__)

logs_router = APIRouter(prefix="/logs", tags=["ISP Partner: logs"])

_LIST_HELP = "Repeatable, or comma-separated."
_UNCONFINED = LogsConfinement(allowed=None)


async def _scope(
    isp: IspContext,
    isp_customer_id: uuid.UUID | None,
    isp_location_id: uuid.UUID | None,
    isp_router_id: uuid.UUID | None,
) -> tuple[uuid.UUID | None, uuid.UUID | None, uuid.UUID | None, list[uuid.UUID]]:
    customer_id, location_id, router_id = await IspScope.optional_filters(
        isp,
        isp_customer_id=isp_customer_id,
        isp_location_id=isp_location_id,
        isp_router_id=isp_router_id,
    )
    org_ids = [customer_id] if customer_id is not None else await isp.child_ids()
    return customer_id, location_id, router_id, org_ids


# ============================================================================
# NetLogs
# ============================================================================


async def _netlog_filters(
    isp: IspContext,
    db: AsyncSession,
    *,
    isp_customer_id: uuid.UUID | None,
    isp_location_id: uuid.UUID | None,
    isp_router_id: uuid.UUID | None,
    **params: Any,
) -> tuple[NetLogsCustomerService, CustomerFilters, list[uuid.UUID]]:
    customer_id, location_id, router_id, org_ids = await _scope(
        isp, isp_customer_id, isp_location_id, isp_router_id
    )
    repository = IspLogsRepository(db, org_ids)
    service = NetLogsCustomerService(repository, get_settings())
    # The organization only seeds the filter object; the query predicate is
    # replaced by `organization_id = ANY(org_ids)` in IspLogsRepository.
    seed_org = customer_id or (org_ids[0] if org_ids else isp.isp_org_id)
    filters = await service.build_filters(
        organization_id=seed_org,
        confinement=_UNCONFINED,
        location_id=location_id,
        router_id=router_id,
        **params,
    )
    return service, filters, org_ids


def _netlog_item(row: dict[str, Any], names: dict[uuid.UUID, str]) -> dict:
    view = event_view(row)
    org_id = row["event"].organization_id
    view["isp_customer_id"] = str(org_id) if org_id else None
    view["customer_name"] = names.get(org_id)
    view["received_at"] = view["received_at"].isoformat()
    if view["device_time"] is not None:
        view["device_time"] = view["device_time"].isoformat()
    return view


@logs_router.get("/netlogs", dependencies=isp_guards(ISP_LOGS_READ))
async def list_netlogs(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp_location_id: uuid.UUID | None = Query(default=None),
    isp_router_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    severity: list[str] | None = Query(default=None, description=_LIST_HELP),
    max_severity: int | None = Query(default=None, ge=0, le=7),
    category: list[str] | None = Query(default=None, description=_LIST_HELP),
    protocol: list[str] | None = Query(default=None, description=_LIST_HELP),
    status: list[str] | None = Query(default=None, description=_LIST_HELP),
    q: str | None = Query(default=None, max_length=200),
    cursor: str | None = Query(default=None, max_length=200),
    limit: int | None = Query(default=None, ge=1, le=NETLOG_MAX_PAGE),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    service, filters, org_ids = await _netlog_filters(
        isp,
        db,
        isp_customer_id=isp_customer_id,
        isp_location_id=isp_location_id,
        isp_router_id=isp_router_id,
        since=since,
        until=until,
        severity=severity,
        max_severity=max_severity,
        category=category,
        protocol=protocol,
        status=status,
        q=q,
        cursor=cursor,
    )
    size = max(1, min(limit or NETLOG_DEFAULT_PAGE, NETLOG_MAX_PAGE))
    base = {"since": filters.since.isoformat(), "until": filters.until.isoformat()}
    if not service.enabled:
        return ok(
            request,
            {"feature_enabled": False, "items": [], "next_cursor": None, **base},
            "Network logs",
        )
    rows = await service.repository.list_events(filters, limit=size + 1)
    has_more = len(rows) > size
    rows = rows[:size]
    names = await isp.repository.names(Organization, org_ids)
    next_cursor = None
    if has_more and rows:
        last = rows[-1]["event"]
        next_cursor = encode_cursor(last.received_at, last.id)
    return ok(
        request,
        {
            "feature_enabled": True,
            "items": [_netlog_item(r, names) for r in rows],
            "next_cursor": next_cursor,
            **base,
        },
        "Network logs",
    )


@logs_router.get("/netlogs/summary", dependencies=isp_guards(ISP_LOGS_READ))
async def netlogs_summary(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp_location_id: uuid.UUID | None = Query(default=None),
    isp_router_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    severity: list[str] | None = Query(default=None, description=_LIST_HELP),
    category: list[str] | None = Query(default=None, description=_LIST_HELP),
    protocol: list[str] | None = Query(default=None, description=_LIST_HELP),
    status: list[str] | None = Query(default=None, description=_LIST_HELP),
    q: str | None = Query(default=None, max_length=200),
    tz: str | None = Query(default=None, max_length=64),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    service, filters, org_ids = await _netlog_filters(
        isp,
        db,
        isp_customer_id=isp_customer_id,
        isp_location_id=isp_location_id,
        isp_router_id=isp_router_id,
        since=since,
        until=until,
        severity=severity,
        category=category,
        protocol=protocol,
        status=status,
        q=q,
        default_window=timedelta(hours=24),
    )
    from app.domains.device_logs.schemas import NetLogSummary

    data = await service.summary(filters, tz=tz or isp.organization.timezone)
    payload = NetLogSummary.model_validate(data).model_dump(mode="json")
    names = await isp.repository.names(Organization, org_ids)
    by_customer = []
    if service.enabled:
        for org_id, total, errors, warnings in await service.repository.by_customer(
            filters
        ):
            by_customer.append(
                {
                    "isp_customer_id": str(org_id),
                    "customer_name": names.get(org_id),
                    "total": int(total),
                    "errors": int(errors),
                    "warnings": int(warnings),
                }
            )
    by_customer.sort(key=lambda r: (-r["total"], r["customer_name"] or ""))
    payload["by_customer"] = by_customer
    return ok(request, payload, "Network logs summary")


async def _stream_netlogs(
    filters: CustomerFilters,
    org_ids: list[uuid.UUID],
    names: dict[uuid.UUID, str],
    *,
    max_rows: int = CUSTOMER_EXPORT_MAX_ROWS,
    chunk: int = CUSTOMER_EXPORT_CHUNK,
) -> AsyncIterator[str]:
    from dataclasses import replace

    from app.database.session import SessionLocal

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    columns = ["customer", *CSV_COLUMNS]

    def line(values: list[Any]) -> str:
        buffer.seek(0)
        buffer.truncate()
        writer.writerow([_csv_safe(v) for v in values])
        return buffer.getvalue()

    yield line(columns)
    if not org_ids:
        return
    written = 0
    current = filters
    async with SessionLocal() as session:
        repository = IspLogsRepository(session, org_ids)
        while written < max_rows:
            size = min(chunk, max_rows - written)
            rows = await repository.list_events(current, limit=size)
            for row in rows:
                v = event_view(row)
                yield line(
                    [
                        names.get(row["event"].organization_id, ""),
                        v["received_at"].isoformat(),
                        v["device_time"].isoformat() if v["device_time"] else "",
                        v["location_name"],
                        v["router_name"],
                        v["hostname"],
                        v["category"],
                        v["protocol"],
                        v["src_ip"],
                        v["dst_ip"],
                        v["status"],
                        v["severity_name"],
                        v["device_mac"],
                        v["summary"],
                        v["message"],
                    ]
                )
            written += len(rows)
            if len(rows) < size:
                return
            last = rows[-1]["event"]
            current = replace(current, cursor=(last.received_at, last.id))
        if await repository.list_events(current, limit=1):
            yield line(
                [f"# truncated at {max_rows} rows; narrow the date range"]
                + [""] * (len(columns) - 1)
            )


@logs_router.get("/netlogs/export.csv", dependencies=isp_guards(ISP_LOGS_EXPORT))
async def export_netlogs(
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp_location_id: uuid.UUID | None = Query(default=None),
    isp_router_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    severity: list[str] | None = Query(default=None, description=_LIST_HELP),
    max_severity: int | None = Query(default=None, ge=0, le=7),
    category: list[str] | None = Query(default=None, description=_LIST_HELP),
    protocol: list[str] | None = Query(default=None, description=_LIST_HELP),
    status: list[str] | None = Query(default=None, description=_LIST_HELP),
    q: str | None = Query(default=None, max_length=200),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> StreamingResponse:
    service, filters, org_ids = await _netlog_filters(
        isp,
        db,
        isp_customer_id=isp_customer_id,
        isp_location_id=isp_location_id,
        isp_router_id=isp_router_id,
        since=since,
        until=until,
        severity=severity,
        max_severity=max_severity,
        category=category,
        protocol=protocol,
        status=status,
        q=q,
    )
    service.require_enabled()
    names = await isp.repository.names(Organization, org_ids)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return StreamingResponse(
        _stream_netlogs(filters, org_ids, names),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="isp-netlogs-{stamp}.csv"',
            "Cache-Control": "no-store",
        },
    )


# ============================================================================
# IPDR
# ============================================================================


def _ipdr_query(
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    phone: str | None = Query(default=None, max_length=32),
    user_id: str | None = Query(default=None, max_length=255),
    mac: str | None = Query(default=None, max_length=32),
    ip: str | None = Query(default=None, max_length=64),
    dst_ip: str | None = Query(default=None, max_length=64),
    guests_only: bool = Query(default=False),
) -> dict[str, Any]:
    return {
        "since": since,
        "until": until,
        "phone": phone,
        "user_id": user_id,
        "mac": mac,
        "ip": ip,
        "dst_ip": dst_ip,
        "guests_only": guests_only,
    }


@logs_router.get("/ipdr/connections", dependencies=isp_guards(ISP_IPDR_READ))
async def list_ipdr(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp_location_id: uuid.UUID | None = Query(default=None),
    isp_router_id: uuid.UUID | None = Query(default=None),
    query: dict[str, Any] = Depends(_ipdr_query),
    cursor: str | None = Query(default=None, max_length=400),
    limit: int | None = Query(default=None, ge=1, le=IPDR_MAX_PAGE),
    isp: IspContext = Depends(RequireIspPartner),
    service: IpdrService = Depends(get_ipdr_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    """IPDR is per legal subscriber entity: the list needs a customer."""
    if isp_customer_id is None:
        raise IspCustomerRequiredError()
    customer_id, location_id, router_id, _ = await _scope(
        isp, isp_customer_id, isp_location_id, isp_router_id
    )
    assert customer_id is not None
    filters = await service.build_filters(
        organization_id=customer_id,
        location_id=location_id,
        router_id=router_id,
        cursor=cursor,
        **query,
    )
    data = await service.list_page(filters, limit=limit)
    await write_audit(
        audit,
        action=AUDIT_ACTION_IPDR_LISTED,
        actor_user_id=isp.user_id,
        filters=filters,
        row_count=len(data["items"]),
        cursor=bool(cursor),
        console="isp",
        isp_organization_id=str(isp.isp_org_id),
    )
    data["since"] = data["since"].isoformat()
    data["until"] = data["until"].isoformat()
    return ok(request, data, "IPDR connections")


async def _stream_ipdr(
    targets: list[tuple[str, Any]],
    *,
    provenance: bool,
    max_rows: int = EXPORT_MAX_ROWS,
) -> AsyncIterator[str]:
    """One CSV, customers in name order, ``customer`` first. The row cap is
    for the whole file, as the existing export's is."""
    from app.database.session import SessionLocal

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    columns = ["customer", *IPDR_COLUMNS, *(PROVENANCE_COLUMNS if provenance else ())]

    def line(values: list[str]) -> str:
        buffer.seek(0)
        buffer.truncate()
        writer.writerow(values)
        return buffer.getvalue()

    yield line(columns)
    written = 0
    async with SessionLocal() as session:
        service = ipdr_service_for(session, get_settings())
        for name, filters in targets:
            async for record in service.iter_records(filters):
                if written >= max_rows:
                    yield line(
                        [f"# truncated at {max_rows} rows; narrow the date range"]
                        + [""] * (len(columns) - 1)
                    )
                    return
                yield line([name, *csv_cells(record, provenance=provenance)])
                written += 1


@logs_router.get("/ipdr/export.csv", dependencies=isp_guards(ISP_IPDR_EXPORT))
async def export_ipdr(
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp_location_id: uuid.UUID | None = Query(default=None),
    isp_router_id: uuid.UUID | None = Query(default=None),
    query: dict[str, Any] = Depends(_ipdr_query),
    include_provenance: bool = Query(default=False),
    isp: IspContext = Depends(RequireIspPartner),
    service: IpdrService = Depends(get_ipdr_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
    db: AsyncSession = Depends(get_db_session),
) -> StreamingResponse:
    """CERT-In columns with ``customer`` first. Without a customer, every
    child in name order in one stream; one audit row per customer, committed
    before the first byte (fail closed)."""
    customer_id, location_id, router_id, org_ids = await _scope(
        isp, isp_customer_id, isp_location_id, isp_router_id
    )
    names = await isp.repository.names(Organization, org_ids)
    ordered = sorted(org_ids, key=lambda i: (names.get(i) or "", str(i)))
    targets: list[tuple[str, Any]] = []
    requested_at = datetime.now(UTC).isoformat()
    for org_id in ordered:
        filters = await service.build_filters(
            organization_id=org_id,
            location_id=location_id if org_id == customer_id else None,
            router_id=router_id if org_id == customer_id else None,
            **query,
        )
        await write_audit(
            audit,
            action=AUDIT_ACTION_IPDR_EXPORTED,
            actor_user_id=isp.user_id,
            filters=filters,
            row_count=None,
            include_provenance=include_provenance,
            requested_at=requested_at,
            console="isp",
            isp_organization_id=str(isp.isp_org_id),
            all_customers=customer_id is None,
        )
        targets.append((names.get(org_id) or str(org_id), filters))
    await db.commit()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    scope = "all" if customer_id is None else str(customer_id)
    return StreamingResponse(
        _stream_ipdr(targets, provenance=include_provenance),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="isp-ipdr-{scope}-{stamp}.csv"'
            ),
            "Cache-Control": "no-store",
        },
    )


# ============================================================================
# Guest auth logs
# ============================================================================


def _login_item(entry: Any, names: dict[uuid.UUID, str]) -> dict:
    item = GuestLoginHistoryLogResponse(
        id=str(entry.id),
        guest_id=str(entry.guest_id) if entry.guest_id else None,
        organization_id=str(entry.organization_id) if entry.organization_id else None,
        location_id=str(entry.location_id) if entry.location_id else None,
        identifier=entry.identifier,
        auth_method=entry.auth_method,
        success=entry.success,
        failure_reason=entry.failure_reason,
        attempted_at=entry.attempted_at,
        ip_address=entry.ip_address,
    ).model_dump(mode="json")
    item["isp_customer_id"] = item["organization_id"]
    item["customer_name"] = names.get(entry.organization_id)
    return item


@logs_router.get("/auth", dependencies=isp_guards(ISP_LOGS_READ))
async def list_auth_logs(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp_location_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    customer_id, location_id, _, org_ids = await _scope(
        isp, isp_customer_id, isp_location_id, None
    )
    names = await isp.repository.names(Organization, org_ids)
    if customer_id is not None:
        guest_repository = GuestRepository(db)
        service = ControllerLogsService(
            None,
            None,
            None,
            None,
            None,
            guest_repository,
            None,  # type: ignore[arg-type]
        )
        entries, meta = await service.list_guest_authentication_logs(
            requesting_organization_id=customer_id,
            location_id=location_id,
            page=page,
            page_size=page_size,
        )
        total = meta.total_items
    elif not org_ids:
        entries, total = [], 0
    else:
        conditions = [
            GuestLoginHistory.organization_id.in_(org_ids),
            GuestLoginHistory.is_deleted.is_(False),
        ]
        total = int(
            (
                await db.execute(
                    select(func.count())
                    .select_from(GuestLoginHistory)
                    .where(*conditions)
                )
            ).scalar_one()
        )
        entries = list(
            (
                await db.execute(
                    select(GuestLoginHistory)
                    .where(*conditions)
                    .order_by(
                        GuestLoginHistory.attempted_at.desc(), GuestLoginHistory.id
                    )
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
    pages = (total + page_size - 1) // page_size if total else 0
    return ok(
        request,
        {
            "items": [_login_item(e, names) for e in entries],
            "page": page,
            "page_size": page_size,
            "total_items": total,
            "total_pages": pages,
            "has_next": page < pages,
            "has_previous": page > 1 and pages > 0,
        },
        "Guest authentication logs",
    )


__all__ = ["logs_router", "RBACRepository"]
