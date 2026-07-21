"""FastAPI routes for the DNS Management domain: per-router static DNS
record CRUD.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against the
already-seeded ``dns.*`` permission key (``PermissionModule.DNS``) and
resolves ``CurrentOrganization``, passed through to ``DnsService`` as
``requesting_organization_id`` -- the same tenant-scoping posture every
other domain's router already enforces.

**Route ordering matters.** ``GET /dns-records`` is registered before
``GET /dns-records/{record_id}`` so Starlette's first-match-wins routing
resolves the literal path first, mirroring the same discipline
``app.domains.dhcp.router`` already follows.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .constants import DnsRecordType
from .dependencies import get_dns_service
from .models import DnsRecord
from .schemas import (
    DnsRecordCreateRequest,
    DnsRecordListResponse,
    DnsRecordResponse,
    DnsRecordUpdateRequest,
    MessageResponse,
)
from .service import DnsService

router = APIRouter(prefix="/dns-records", tags=["DNS Management"])


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


def _record_response(record: DnsRecord) -> DnsRecordResponse:
    return DnsRecordResponse(
        id=str(record.id),
        router_id=str(record.router_id),
        organization_id=str(record.organization_id),
        location_id=str(record.location_id),
        name=record.name,
        record_type=record.record_type,
        address=record.address,
        ttl_seconds=record.ttl_seconds,
        comment=record.comment,
        is_enabled=record.is_enabled,
        created_at=record.created_at,
    )


@router.post(
    "",
    response_model=ApiResponse[DnsRecordResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("dns.create"))],
)
async def create_dns_record(
    request: Request,
    payload: DnsRecordCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsService = Depends(get_dns_service),
):
    record = await service.create_record(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        router_id=uuid.UUID(payload.router_id),
        name=payload.name,
        address=payload.address,
        record_type=payload.record_type,
        ttl_seconds=payload.ttl_seconds,
        comment=payload.comment,
        is_enabled=payload.is_enabled,
    )
    return build_response(
        success=True,
        message="DNS record created",
        data=_record_response(record).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[DnsRecordListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dns.read"))],
)
async def list_dns_records(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsService = Depends(get_dns_service),
):
    records, meta = await service.list_records(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = DnsRecordListResponse(
        items=[_record_response(record) for record in records],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="DNS records retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{record_id}",
    response_model=ApiResponse[DnsRecordResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dns.read"))],
)
async def get_dns_record(
    request: Request,
    record_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsService = Depends(get_dns_service),
):
    record = await service.get_record(
        record_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="DNS record retrieved",
        data=_record_response(record).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/{record_id}",
    response_model=ApiResponse[DnsRecordResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dns.update"))],
)
async def update_dns_record(
    request: Request,
    record_id: uuid.UUID,
    payload: DnsRecordUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsService = Depends(get_dns_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "record_type" in fields:
        fields["record_type"] = DnsRecordType(fields["record_type"])
    record = await service.update_record(
        record_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="DNS record updated",
        data=_record_response(record).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{record_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("dns.delete"))],
)
async def delete_dns_record(
    request: Request,
    record_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsService = Depends(get_dns_service),
):
    await service.delete_record(
        record_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="DNS record deleted",
        data=MessageResponse(message="DNS record deleted").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
