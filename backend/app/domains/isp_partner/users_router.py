"""``/isp/users`` and ``/isp/roles`` (API_CONTRACT §4.11). Every route is
``isp_partner.assign``. Bodies are ``extra="forbid"``: there is no field that
names an organization, so a user can only ever land in the ISP's own org."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.domains.rbac.dependencies import get_permission_cache, get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.user.dependencies import get_identity_repository, get_user_service
from app.domains.user.service import UserService

from .constants import DEFAULT_PAGE_SIZE, ISP_PARTNER_ASSIGN, MAX_PAGE_SIZE
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .schemas import IspUserCreateRequest, IspUserScopeRequest, IspUserUpdateRequest
from .users_service import IspUsersService

users_router = APIRouter(tags=["ISP Partner: users"])
_GUARDS = isp_guards(ISP_PARTNER_ASSIGN)


def get_isp_users_service(
    isp: IspContext = Depends(RequireIspPartner),
    user_service: UserService = Depends(get_user_service),
    identity_repository=Depends(get_identity_repository),
    rbac_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    permission_cache=Depends(get_permission_cache),
) -> IspUsersService:
    return IspUsersService(
        repository=isp.repository,
        user_service=user_service,
        identity_repository=identity_repository,
        rbac_repository=rbac_repository,
        permission_cache=permission_cache,
        audit=rbac_repository,
    )


@users_router.get("/users", dependencies=_GUARDS)
async def list_users(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    search: str | None = Query(default=None, max_length=200),
    role: str | None = Query(default=None, max_length=50),
    status_filter: str | None = Query(default=None, alias="status", pattern="^(active|disabled)$"),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspUsersService = Depends(get_isp_users_service),
) -> dict:
    data = await service.list_users(
        isp, search=search, role=role, status=status_filter, page_no=page, page_size=page_size
    )
    return ok(request, data, "ISP users")


@users_router.post("/users", status_code=status.HTTP_201_CREATED, dependencies=_GUARDS)
async def create_user(
    request: Request,
    payload: IspUserCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspUsersService = Depends(get_isp_users_service),
) -> dict:
    return ok(request, await service.create_user(isp, payload.model_dump()), "ISP user created")


@users_router.get("/users/{isp_user_id}", dependencies=_GUARDS)
async def get_user(
    request: Request,
    isp_user_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspUsersService = Depends(get_isp_users_service),
) -> dict:
    return ok(request, await service.get_user(isp, isp_user_id), "ISP user")


@users_router.patch("/users/{isp_user_id}", dependencies=_GUARDS)
async def update_user(
    request: Request,
    isp_user_id: uuid.UUID,
    payload: IspUserUpdateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspUsersService = Depends(get_isp_users_service),
) -> dict:
    data = await service.update_user(isp, isp_user_id, payload.model_dump(exclude_unset=True))
    return ok(request, data, "ISP user updated")


@users_router.put("/users/{isp_user_id}/customer-scope", dependencies=_GUARDS)
async def set_customer_scope(
    request: Request,
    isp_user_id: uuid.UUID,
    payload: IspUserScopeRequest,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspUsersService = Depends(get_isp_users_service),
) -> dict:
    data = await service.set_scope(isp, isp_user_id, payload.customer_ids)
    return ok(request, data, "Customer scope updated")


@users_router.post("/users/{isp_user_id}/disable", dependencies=_GUARDS)
async def disable_user(
    request: Request,
    isp_user_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspUsersService = Depends(get_isp_users_service),
) -> dict:
    return ok(request, await service.set_enabled(isp, isp_user_id, False), "ISP user disabled")


@users_router.post("/users/{isp_user_id}/enable", dependencies=_GUARDS)
async def enable_user(
    request: Request,
    isp_user_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspUsersService = Depends(get_isp_users_service),
) -> dict:
    return ok(request, await service.set_enabled(isp, isp_user_id, True), "ISP user enabled")


@users_router.post("/users/{isp_user_id}/reset-password", dependencies=_GUARDS)
async def reset_password(
    request: Request,
    isp_user_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspUsersService = Depends(get_isp_users_service),
) -> dict:
    return ok(request, await service.reset_password(isp, isp_user_id), "Password reset")


@users_router.post("/users/{isp_user_id}/force-logout", dependencies=_GUARDS)
async def force_logout(
    request: Request,
    isp_user_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: IspUsersService = Depends(get_isp_users_service),
) -> dict:
    return ok(request, await service.force_logout(isp, isp_user_id), "Signed out everywhere")


@users_router.get("/roles", dependencies=_GUARDS)
async def list_roles(request: Request) -> dict:
    return ok(request, {"items": IspUsersService.roles()}, "ISP roles")
