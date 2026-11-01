"""Master-only ISP partner endpoints (API_CONTRACT §3, TASKS FS-1).

Router ``isp_partner_platform_router``, prefix ``/platform/isp-partners``,
mounted by BE's E1 line in ``app/api/v1/router.py``.

## Why every route names ``scope=ScopeType.GLOBAL``

Only the Master console creates an ISP partner (founder rule 3). These routes
reuse the existing ``organizations.*`` keys, which an Organization Owner or an
MSP Owner holds at ORGANIZATION scope. ``RequirePermission`` with no
``scope=`` infers the scope from the caller's own headers, so such a grant
would satisfy it. With ``ScopeType.GLOBAL``, only a GLOBAL grant (a Master
role) passes: ``ScopeResolver`` refuses any grant narrower than the level being
checked. ``isp-*`` roles hold no ``organizations.*`` key at all.
``tests/unit/test_isp_partner_platform.py`` checks this at three altitudes:
the mounted route's closure, ``ScopeResolver`` and ``AccessValidator``.

There is no ``RequireOrganization``. These are platform routes, and the ISP is
named by the path id ``isp_partner_id`` (a ``NOT_SCOPE_BEARING_ID_PARAMS``
name, E5), never by a scope header.

``RequireIspFeatureEnabled`` is a router-level dependency, so it runs first:
with ``ISP_PARTNER_ENABLED`` off every route answers a plain 404 before auth.
"""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import ApiResponse, build_response
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.auth.repository import AuthRepositoryProtocol
from app.domains.billing.dependencies import get_plan_service
from app.domains.billing.service import PlanService
from app.domains.notification.dependencies import get_notification_service
from app.domains.notification.service import NotificationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.cache import PermissionCache
from app.domains.rbac.dependencies import (
    CurrentUser,
    RequirePermission,
    get_permission_cache,
    get_rbac_repository,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.tr069.credentials import CredentialStore
from app.domains.user.dependencies import get_identity_repository, get_user_service
from app.domains.user.service import UserService

from .config import RequireIspFeatureEnabled, get_isp_partner_settings
from .platform_repository import IspPlatformRepository
from .platform_schemas import (
    IspOwnerCredentialResponse,
    IspOwnerRequest,
    IspPartnerCreateRequest,
    IspPartnerCreateResponse,
    IspPartnerListResponse,
    IspPartnerResponse,
    IspPartnerSuspendRequest,
    IspPartnerUpdateRequest,
)
from .platform_service import IspPartnerPlatformService
from .repository import IspRepository

isp_partner_platform_router = APIRouter(
    prefix="/platform/isp-partners",
    tags=["ISP Partners (Master)"],
    dependencies=[Depends(RequireIspFeatureEnabled)],
)

#: Every permission this router checks, each pinned GLOBAL. Listed once so
#: the structural test can compare against the mounted routes.
PLATFORM_ROUTE_PERMISSIONS: dict[tuple[str, str], str] = {
    ("GET", ""): "organizations.read",
    ("POST", ""): "organizations.create",
    ("GET", "/{isp_partner_id}"): "organizations.read",
    ("PATCH", "/{isp_partner_id}"): "organizations.update",
    ("POST", "/{isp_partner_id}/suspend"): "organizations.manage",
    ("POST", "/{isp_partner_id}/activate"): "organizations.manage",
    ("POST", "/{isp_partner_id}/owners"): "organizations.manage",
    (
        "POST",
        "/{isp_partner_id}/users/{isp_user_id}/reset-password",
    ): "organizations.manage",
    # ADDENDUM_04 B6 (PARITY-2, isp_addons.py): mounted on this router from
    # isp_partner.router._include_lanes; listed here so the contract tests
    # cover them.
    ("GET", "/{isp_partner_id}/addon-allowances"): "organizations.read",
    ("PUT", "/{isp_partner_id}/addon-allowances"): "organizations.manage",
    # ADDENDUM_04 F1-F3 (PARITY-2, parity_settings.py).
    ("GET", "/{isp_partner_id}/parity-settings"): "organizations.read",
    ("PUT", "/{isp_partner_id}/parity-settings"): "organizations.manage",
    ("GET", "/{isp_partner_id}/wallet"): "organizations.read",
    ("POST", "/{isp_partner_id}/wallet/topups"): "organizations.manage",
}


def _gate(method: str, path: str) -> list:
    return [
        Depends(
            RequirePermission(
                PLATFORM_ROUTE_PERMISSIONS[(method, path)], scope=ScopeType.GLOBAL
            )
        )
    ]


def get_isp_partner_platform_service(
    db: AsyncSession = Depends(get_db_session),
    organization_service: OrganizationService = Depends(get_organization_service),
    user_service: UserService = Depends(get_user_service),
    identity_repository: AuthRepositoryProtocol = Depends(get_identity_repository),
    rbac_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    plan_service: PlanService = Depends(get_plan_service),
    notification_service: NotificationService = Depends(get_notification_service),
    permission_cache: PermissionCache = Depends(get_permission_cache),
) -> IspPartnerPlatformService:
    # Every provider above resolves the same request-scoped AsyncSession, so
    # the whole create is one transaction (get_db_session commits at the end
    # or rolls everything back on any exception).
    return IspPartnerPlatformService(
        IspPlatformRepository(db),
        organization_service,
        user_service,
        identity_repository,
        rbac_repository,
        plan_service,
        CredentialStore(db),
        IspRepository(db),
        notification_service,
        login_url=get_isp_partner_settings().login_url,
        permission_cache=permission_cache,
    )


def _rid(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _actor(user: AuthUser) -> uuid.UUID:
    return uuid.UUID(str(user.id))


@isp_partner_platform_router.get(
    "",
    response_model=ApiResponse[IspPartnerListResponse],
    dependencies=_gate("GET", ""),
)
async def list_isp_partners(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    partner_status: Literal["active", "suspended"] | None = Query(
        default=None, alias="status"
    ),
    search: str | None = Query(default=None, max_length=100),
    service: IspPartnerPlatformService = Depends(get_isp_partner_platform_service),
):
    data = await service.list_partners(
        page=page, page_size=page_size, status_filter=partner_status, search=search
    )
    return build_response(
        success=True,
        message="ISP partners retrieved",
        data=data.model_dump(mode="json"),
        request_id=_rid(request),
    )


@isp_partner_platform_router.post(
    "",
    response_model=ApiResponse[IspPartnerCreateResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=_gate("POST", ""),
)
async def create_isp_partner(
    request: Request,
    body: IspPartnerCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    service: IspPartnerPlatformService = Depends(get_isp_partner_platform_service),
):
    data = await service.create_partner(actor_user_id=_actor(user), data=body)
    return build_response(
        success=True,
        message="ISP partner created",
        data=data.model_dump(mode="json"),
        request_id=_rid(request),
    )


@isp_partner_platform_router.get(
    "/{isp_partner_id}",
    response_model=ApiResponse[IspPartnerResponse],
    dependencies=_gate("GET", "/{isp_partner_id}"),
)
async def get_isp_partner(
    request: Request,
    isp_partner_id: uuid.UUID,
    service: IspPartnerPlatformService = Depends(get_isp_partner_platform_service),
):
    data = await service.get_partner(isp_partner_id)
    return build_response(
        success=True,
        message="ISP partner retrieved",
        data=data.model_dump(mode="json"),
        request_id=_rid(request),
    )


@isp_partner_platform_router.patch(
    "/{isp_partner_id}",
    response_model=ApiResponse[IspPartnerResponse],
    dependencies=_gate("PATCH", "/{isp_partner_id}"),
)
async def update_isp_partner(
    request: Request,
    isp_partner_id: uuid.UUID,
    body: IspPartnerUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    service: IspPartnerPlatformService = Depends(get_isp_partner_platform_service),
):
    data = await service.update_partner(
        actor_user_id=_actor(user), isp_org_id=isp_partner_id, data=body
    )
    return build_response(
        success=True,
        message="ISP partner updated",
        data=data.model_dump(mode="json"),
        request_id=_rid(request),
    )


@isp_partner_platform_router.post(
    "/{isp_partner_id}/suspend",
    response_model=ApiResponse[IspPartnerResponse],
    dependencies=_gate("POST", "/{isp_partner_id}/suspend"),
)
async def suspend_isp_partner(
    request: Request,
    isp_partner_id: uuid.UUID,
    body: IspPartnerSuspendRequest,
    user: AuthUser = Depends(CurrentUser),
    service: IspPartnerPlatformService = Depends(get_isp_partner_platform_service),
):
    data = await service.suspend_partner(
        actor_user_id=_actor(user), isp_org_id=isp_partner_id, reason=body.reason
    )
    return build_response(
        success=True,
        message="ISP partner suspended",
        data=data.model_dump(mode="json"),
        request_id=_rid(request),
    )


@isp_partner_platform_router.post(
    "/{isp_partner_id}/activate",
    response_model=ApiResponse[IspPartnerResponse],
    dependencies=_gate("POST", "/{isp_partner_id}/activate"),
)
async def activate_isp_partner(
    request: Request,
    isp_partner_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    service: IspPartnerPlatformService = Depends(get_isp_partner_platform_service),
):
    data = await service.activate_partner(
        actor_user_id=_actor(user), isp_org_id=isp_partner_id
    )
    return build_response(
        success=True,
        message="ISP partner reactivated",
        data=data.model_dump(mode="json"),
        request_id=_rid(request),
    )


@isp_partner_platform_router.post(
    "/{isp_partner_id}/owners",
    response_model=ApiResponse[IspOwnerCredentialResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=_gate("POST", "/{isp_partner_id}/owners"),
)
async def add_isp_partner_owner(
    request: Request,
    isp_partner_id: uuid.UUID,
    body: IspOwnerRequest,
    user: AuthUser = Depends(CurrentUser),
    service: IspPartnerPlatformService = Depends(get_isp_partner_platform_service),
):
    data = await service.add_owner(
        actor_user_id=_actor(user), isp_org_id=isp_partner_id, data=body
    )
    return build_response(
        success=True,
        message="ISP owner added",
        data=data.model_dump(mode="json"),
        request_id=_rid(request),
    )


@isp_partner_platform_router.post(
    "/{isp_partner_id}/users/{isp_user_id}/reset-password",
    response_model=ApiResponse[IspOwnerCredentialResponse],
    dependencies=_gate("POST", "/{isp_partner_id}/users/{isp_user_id}/reset-password"),
)
async def reset_isp_user_password(
    request: Request,
    isp_partner_id: uuid.UUID,
    isp_user_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    service: IspPartnerPlatformService = Depends(get_isp_partner_platform_service),
):
    data = await service.reset_user_password(
        actor_user_id=_actor(user), isp_org_id=isp_partner_id, isp_user_id=isp_user_id
    )
    return build_response(
        success=True,
        message="ISP user password reset",
        data=data.model_dump(mode="json"),
        request_id=_rid(request),
    )


__all__ = [
    "PLATFORM_ROUTE_PERMISSIONS",
    "get_isp_partner_platform_service",
    "isp_partner_platform_router",
]


# ADDENDUM_04 B6 §2 (PARITY-2): Master's per-ISP add-on allowance
# (``isp_addons.py``), GLOBAL-pinned on organizations.* like the routes above.
from .isp_addons import addon_platform_router  # noqa: E402

isp_partner_platform_router.include_router(addon_platform_router)

# ADDENDUM_04 F1-F3 (PARITY-2, parity_settings.py): per-ISP unmask switch and
# the ISP's messaging credit wallet, GLOBAL-pinned on organizations.*.
from .parity_settings import parity_platform_router  # noqa: E402

isp_partner_platform_router.include_router(parity_platform_router)
