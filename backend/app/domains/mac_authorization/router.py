"""FastAPI routes for the MAC Authorization domain: organization-scoped
MAC whitelist CRUD plus bulk import/export.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router -- except
``export_mac_authorization_entries``, which deliberately returns a raw
CSV ``Response`` (mirrors
``app.domains.voucher.router.export_voucher_batch``'s identical "a file
someone opens directly cannot usefully be JSON-wrapped" reasoning).
Every endpoint is gated by RBAC's existing ``RequirePermission``
dependency against a brand-new ``mac_authorization.*`` permission key
(see ``app.domains.rbac.seed`` -- ``PermissionModule.MAC_AUTHORIZATION``)
and resolves ``CurrentOrganization`` (``X-Organization-Id``), passed
through to ``MacAuthorizationService`` as ``requesting_organization_id``.

**Route ordering matters.** ``/entries/import``/``/entries/export`` are
registered *before* ``/entries/{entry_id}`` so Starlette's
first-match-wins routing resolves the literal paths first -- otherwise
``GET /entries/export`` would be swallowed by the ``{entry_id}`` path
parameter and fail UUID parsing. ``GET /entries`` (list) is likewise
registered before ``GET /entries/{entry_id}``, mirroring the same
discipline every other domain's router already follows.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .constants import MacAuthorizationType
from .dependencies import get_mac_authorization_service
from .models import MacAuthorizationEntry
from .schemas import (
    MacAuthorizationEntryCreateRequest,
    MacAuthorizationEntryListResponse,
    MacAuthorizationEntryResponse,
    MacAuthorizationEntryUpdateRequest,
    MacAuthorizationImportRequest,
    MacAuthorizationImportResponse,
    MessageResponse,
    RejectedImportRowResponse,
)
from .service import MacAuthorizationService

router = APIRouter(prefix="/mac-authorization", tags=["MAC Authorization"])


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


def _entry_response(entry: MacAuthorizationEntry) -> MacAuthorizationEntryResponse:
    return MacAuthorizationEntryResponse(
        id=str(entry.id),
        organization_id=str(entry.organization_id),
        location_id=str(entry.location_id) if entry.location_id else None,
        mac_address=entry.mac_address,
        authorization_type=entry.authorization_type,
        expires_at=entry.expires_at,
        comment=entry.comment,
        is_enabled=entry.is_enabled,
        created_at=entry.created_at,
    )


@router.post(
    "/entries",
    response_model=ApiResponse[MacAuthorizationEntryResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("mac_authorization.create"))],
)
async def create_mac_authorization_entry(
    request: Request,
    payload: MacAuthorizationEntryCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MacAuthorizationService = Depends(get_mac_authorization_service),
):
    entry = await service.create_entry(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        mac_address=payload.mac_address,
        authorization_type=MacAuthorizationType(payload.authorization_type),
        location_id=uuid.UUID(payload.location_id) if payload.location_id else None,
        expires_at=payload.expires_at,
        comment=payload.comment,
        is_enabled=payload.is_enabled,
    )
    return build_response(
        success=True,
        message="MAC authorization entry created",
        data=_entry_response(entry).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/entries",
    response_model=ApiResponse[MacAuthorizationEntryListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("mac_authorization.read"))],
)
async def list_mac_authorization_entries(
    request: Request,
    location_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MacAuthorizationService = Depends(get_mac_authorization_service),
):
    entries, meta = await service.list_entries(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        page=page,
        page_size=page_size,
    )
    payload = MacAuthorizationEntryListResponse(
        items=[_entry_response(entry) for entry in entries], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="MAC authorization entries retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/entries/import",
    response_model=ApiResponse[MacAuthorizationImportResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("mac_authorization.import"))],
)
async def import_mac_authorization_entries(
    request: Request,
    payload: MacAuthorizationImportRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MacAuthorizationService = Depends(get_mac_authorization_service),
):
    result = await service.import_entries(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        entries=[row.model_dump() for row in payload.entries],
    )
    response_payload = MacAuthorizationImportResponse(
        imported_count=result.imported_count,
        imported_ids=[str(entry_id) for entry_id in result.imported_ids],
        rejected=[
            RejectedImportRowResponse(mac_address=row.mac_address, reason=row.reason)
            for row in result.rejected
        ],
    )
    return build_response(
        success=True,
        message="MAC authorization entries imported",
        data=response_payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/entries/export",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("mac_authorization.export"))],
)
async def export_mac_authorization_entries(
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MacAuthorizationService = Depends(get_mac_authorization_service),
) -> Response:
    csv_text = await service.export_entries_csv(
        requesting_organization_id=requesting_organization_id
    )
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                'attachment; filename="mac_authorization_entries.csv"'
            )
        },
    )


@router.get(
    "/entries/{entry_id}",
    response_model=ApiResponse[MacAuthorizationEntryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("mac_authorization.read"))],
)
async def get_mac_authorization_entry(
    request: Request,
    entry_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MacAuthorizationService = Depends(get_mac_authorization_service),
):
    entry = await service.get_entry(
        entry_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="MAC authorization entry retrieved",
        data=_entry_response(entry).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/entries/{entry_id}",
    response_model=ApiResponse[MacAuthorizationEntryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("mac_authorization.update"))],
)
async def update_mac_authorization_entry(
    request: Request,
    entry_id: uuid.UUID,
    payload: MacAuthorizationEntryUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MacAuthorizationService = Depends(get_mac_authorization_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "location_id" in fields:
        fields["location_id"] = uuid.UUID(fields["location_id"])
    entry = await service.update_entry(
        entry_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="MAC authorization entry updated",
        data=_entry_response(entry).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/entries/{entry_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("mac_authorization.delete"))],
)
async def delete_mac_authorization_entry(
    request: Request,
    entry_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: MacAuthorizationService = Depends(get_mac_authorization_service),
):
    await service.delete_entry(
        entry_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="MAC authorization entry deleted",
        data=MessageResponse(message="MAC authorization entry deleted").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
