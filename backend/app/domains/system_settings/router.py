"""FastAPI routes for the System Settings domain.

Both endpoints are Master-console-only and RBAC-gated by
``RequirePermission`` against ``system_settings.*`` at ``ScopeType.GLOBAL``
(``app.domains.rbac.seed.MODULE_NARROWEST_SCOPE[PermissionModule
.SYSTEM_SETTINGS] == ScopeType.GLOBAL`` -- platform settings belong to no
organization). The scope is stated *explicitly* rather than inferred: these
routes carry no ``organization_id``/``location_id`` path parameter or
header, so ``RequirePermission``'s default inference would already resolve
``GLOBAL`` here, but naming it makes the platform-scope intent
unmistakable and immune to a future header sneaking in.

This is the read/write surface the reserved-but-unbuilt ``system_settings``
RBAC permission finally has a table behind (see ``service`` /
``models``).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import CurrentUser, RequirePermission
from app.domains.rbac.enums import ScopeType

from .dependencies import get_system_settings_service
from .schemas import PlatformSettingsResponse, PlatformSettingsUpdateRequest
from .service import SystemSettingsService

router = APIRouter(prefix="/system-settings", tags=["System Settings"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.get(
    "",
    response_model=ApiResponse[PlatformSettingsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("system_settings.read", scope=ScopeType.GLOBAL))
    ],
)
async def get_platform_settings(
    request: Request,
    service: SystemSettingsService = Depends(get_system_settings_service),
):
    payload = await service.get_platform_settings()
    return build_response(
        success=True,
        message="Platform settings retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "",
    response_model=ApiResponse[PlatformSettingsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("system_settings.update", scope=ScopeType.GLOBAL))
    ],
)
async def update_platform_settings(
    request: Request,
    body: PlatformSettingsUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    service: SystemSettingsService = Depends(get_system_settings_service),
):
    """Updates the platform-wide new-customer defaults. A field left unset is
    a no-op for that setting (partial update); ``new_customer_default_plan_id``
    sent as an empty string positively clears the default plan. A plan id is
    validated to exist before it is stored, and any real change is recorded
    to the audit log (see ``service.SystemSettingsService``)."""
    payload = await service.update_platform_settings(
        actor_user_id=uuid.UUID(user.id), body=body
    )
    return build_response(
        success=True,
        message="Platform settings updated",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )
