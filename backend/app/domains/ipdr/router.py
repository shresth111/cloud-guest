"""IPDR HTTP surface (customer dashboard, NetLogs "Connections (IPDR)" tab):

* ``GET /ipdr/connections`` -- masked rows, keyset-paginated. ``ipdr.read``.
* ``GET /ipdr/export.csv`` -- the 18 standard columns, unmasked, streamed.
  ``ipdr.export``.

Guards on every route, in this order:

1. ``RequireOrganization`` -- exactly one organization, the caller's. A
   Global caller naming none, or asking for all, is refused (400).
2. ``RequirePermission(<key>, scope=ScopeType.ORGANIZATION)`` -- pinned,
   never inferred from headers (the scope-inference trap). Held by the
   Organization Owner and Organization Admin only among customer roles.

There is no ``organization_id`` parameter. Every call writes an audit row
(phone/user id masked in it); the export's row is committed before the
first byte, and a second row records the real count when the stream ends.
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
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import build_response
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentUser,
    RequireOrganization,
    RequirePermission,
    get_rbac_repository,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.repository import RBACRepository, RBACRepositoryProtocol

from .constants import (
    AUDIT_ACTION_IPDR_EXPORT_COMPLETED,
    AUDIT_ACTION_IPDR_EXPORTED,
    AUDIT_ACTION_IPDR_LISTED,
    EXPORT_MAX_ROWS,
    IPDR_COLUMNS,
    IPDR_EXPORT,
    IPDR_READ,
    IST,
    MAX_PAGE_SIZE,
    PROVENANCE_COLUMNS,
)
from .dependencies import get_ipdr_service, ipdr_service_for
from .formatting import csv_cells
from .service import IpdrFilters, IpdrService

logger = get_logger(__name__)

__all__ = ["ipdr_router", "write_audit"]

ipdr_router = APIRouter(prefix="/ipdr", tags=["IPDR (customer)"])

_READ_GUARDS: list[Any] = [
    Depends(RequireOrganization),
    Depends(RequirePermission(IPDR_READ, scope=ScopeType.ORGANIZATION)),
]
_EXPORT_GUARDS: list[Any] = [
    Depends(RequireOrganization),
    Depends(RequirePermission(IPDR_EXPORT, scope=ScopeType.ORGANIZATION)),
]


def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID", "") or str(
        getattr(getattr(request, "state", None), "request_id", "")
    )


async def write_audit(
    audit: Any,
    *,
    action: str,
    actor_user_id: uuid.UUID,
    filters: IpdrFilters,
    row_count: int | None,
    **more: Any,
) -> None:
    await audit.create_audit_log_entry(
        actor_user_id=actor_user_id,
        action=action,
        entity_type="organization",
        entity_id=filters.organization_id,
        description=(
            f"IPDR {action.removeprefix('ipdr_').replace('_', ' ')}: "
            f"{'?' if row_count is None else row_count} row(s), "
            f"{filters.since.isoformat()} to {filters.until.isoformat()}"
        ),
        event_metadata={
            "console": "customer",
            "since": filters.since.isoformat(),
            "until": filters.until.isoformat(),
            "filters": filters.audit_view(),
            "row_count": row_count,
            **more,
        },
        organization_id=filters.organization_id,
        location_id=filters.location_id,
    )


def _query(
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    router_id: uuid.UUID | None = Query(default=None),
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
        "location_id": location_id,
        "router_id": router_id,
        "phone": phone,
        "user_id": user_id,
        "mac": mac,
        "ip": ip,
        "dst_ip": dst_ip,
        "guests_only": guests_only,
    }


@ipdr_router.get("/connections", dependencies=_READ_GUARDS)
async def list_connections(
    request: Request,
    query: dict[str, Any] = Depends(_query),
    cursor: str | None = Query(default=None, max_length=400),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    user: AuthUser = Depends(CurrentUser),
    service: IpdrService = Depends(get_ipdr_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict[str, Any]:
    """IPDR rows (phone and email masked), newest first. Default: the last
    24 hours; at most 730 days. A page opens at most 31 days; ``next_cursor``
    continues. ``coverage`` says per IST day what was archived, built live or
    is missing."""
    filters = await service.build_filters(
        organization_id=organization_id, cursor=cursor, **query
    )
    data = await service.list_page(filters, limit=limit)
    await write_audit(
        audit,
        action=AUDIT_ACTION_IPDR_LISTED,
        actor_user_id=uuid.UUID(str(user.id)),
        filters=filters,
        row_count=len(data["items"]),
        cursor=bool(cursor),
    )
    data["since"] = data["since"].isoformat()
    data["until"] = data["until"].isoformat()
    return build_response(
        success=True,
        message="IPDR connections",
        data=data,
        request_id=_request_id(request),
    )


def _filename(filters: IpdrFilters) -> str:
    first = filters.since.astimezone(IST).strftime("%Y%m%d")
    last = (filters.until - timedelta(microseconds=1)).astimezone(IST)
    return f"ipdr-{filters.organization_id}-{first}-{last.strftime('%Y%m%d')}.csv"


async def stream_csv(
    filters: IpdrFilters,
    *,
    actor_user_id: uuid.UUID,
    provenance: bool,
    max_rows: int = EXPORT_MAX_ROWS,
) -> AsyncIterator[str]:
    """CSV lines on a session of the stream's own (the request's is closed
    before a streamed body is sent)."""
    from app.database.session import SessionLocal

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    columns = list(IPDR_COLUMNS) + (list(PROVENANCE_COLUMNS) if provenance else [])

    def line(values: list[str]) -> str:
        buffer.seek(0)
        buffer.truncate()
        writer.writerow(values)
        return buffer.getvalue()

    yield line(columns)
    written = 0
    truncated = False
    async with SessionLocal() as session:
        service = ipdr_service_for(session, get_settings())
        async for record in service.iter_records(filters):
            if written >= max_rows:
                truncated = True
                break
            yield line(csv_cells(record, provenance=provenance))
            written += 1
        if truncated:
            yield line(
                [f"# truncated at {max_rows} rows; narrow the date range"]
                + [""] * (len(columns) - 1)
            )
        try:
            await write_audit(
                RBACRepository(session),
                action=AUDIT_ACTION_IPDR_EXPORT_COMPLETED,
                actor_user_id=actor_user_id,
                filters=filters,
                row_count=written,
                truncated=truncated,
            )
            await session.commit()
        except Exception:
            # The export itself was audited before the first byte.
            logger.exception("ipdr_export_completion_audit_failed")


@ipdr_router.get("/export.csv", dependencies=_EXPORT_GUARDS)
async def export_csv(
    query: dict[str, Any] = Depends(_query),
    include_provenance: bool = Query(default=False),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    user: AuthUser = Depends(CurrentUser),
    service: IpdrService = Depends(get_ipdr_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
    db: AsyncSession = Depends(get_db_session),
) -> StreamingResponse:
    """The IPDR in the standard 18 columns (CERT-In IPDR format minus
    Address), unmasked, newest first, at most 1,000,000 rows (a final
    ``# truncated`` line says when the cap was hit). ``include_provenance``
    appends "Translated Address Source", "User Match", "MAC Source", "IP
    Allocation Source" and "Device Class". ``guests_only`` keeps only rows
    matched to a guest session (default: every row). Audited before the
    first byte."""
    filters = await service.build_filters(organization_id=organization_id, **query)
    actor = uuid.UUID(str(user.id))
    await write_audit(
        audit,
        action=AUDIT_ACTION_IPDR_EXPORTED,
        actor_user_id=actor,
        filters=filters,
        row_count=None,
        include_provenance=include_provenance,
        requested_at=datetime.now(UTC).isoformat(),
    )
    # Fail closed: no committed audit row, no download.
    await db.commit()
    return StreamingResponse(
        stream_csv(filters, actor_user_id=actor, provenance=include_provenance),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{_filename(filters)}"',
            "Cache-Control": "no-store",
        },
    )
