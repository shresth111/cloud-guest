"""FastAPI routes for the API Keys domain: create (shown once), list,
revoke.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against
``api_keys.*`` (``PermissionModule.API_KEYS``, already seeded -- see
``app.domains.rbac.seed``) and resolves ``CurrentOrganization``, passed
through as ``requesting_organization_id`` -- the same tenant-scoping
posture every other domain's router already enforces. A created key acts
*as* the creating user (``CurrentUser``) -- see ``models.ApiKey``'s own
docstring.
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

from .dependencies import get_api_key_service
from .exceptions import OrganizationRequiredError
from .models import ApiKey
from .schemas import (
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyListResponse,
    ApiKeyResponse,
    MessageResponse,
)
from .service import ApiKeyService

router = APIRouter(prefix="/api-keys", tags=["API Keys"])


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


def _api_key_response(api_key: ApiKey) -> ApiKeyResponse:
    return ApiKeyResponse(
        id=str(api_key.id),
        organization_id=str(api_key.organization_id),
        name=api_key.name,
        display_prefix=api_key.display_prefix,
        expires_at=api_key.expires_at,
        revoked_at=api_key.revoked_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
    )


@router.post(
    "",
    response_model=ApiResponse[ApiKeyCreateResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("api_keys.create"))],
)
async def create_api_key(
    request: Request,
    payload: ApiKeyCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ApiKeyService = Depends(get_api_key_service),
):
    if requesting_organization_id is None:
        raise OrganizationRequiredError()

    api_key, plaintext_key = await service.create_api_key(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        name=payload.name,
        expires_at=payload.expires_at,
    )
    return build_response(
        success=True,
        message="API key created -- copy it now, it will not be shown again",
        data=ApiKeyCreateResponse(
            id=str(api_key.id),
            name=api_key.name,
            plaintext_key=plaintext_key,
            display_prefix=api_key.display_prefix,
            expires_at=api_key.expires_at,
            created_at=api_key.created_at,
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[ApiKeyListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("api_keys.read"))],
)
async def list_api_keys(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ApiKeyService = Depends(get_api_key_service),
):
    api_keys, meta = await service.list_api_keys(
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = ApiKeyListResponse(
        items=[_api_key_response(api_key) for api_key in api_keys],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="API keys retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{api_key_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("api_keys.delete"))],
)
async def revoke_api_key(
    request: Request,
    api_key_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ApiKeyService = Depends(get_api_key_service),
):
    await service.revoke_api_key(
        api_key_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="API key revoked",
        data=MessageResponse(message="API key revoked").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
