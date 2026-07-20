"""FastAPI routes for the Guest Access Control domain: admin-facing rule
CRUD for both guest (identifier-keyed) and device (MAC-keyed) rules, plus a
``POST /guest-access/check`` decision endpoint.

Every endpoint is gated by RBAC's existing ``RequirePermission`` dependency
against the ``guest_access.*`` permission keys
(``app.domains.rbac.seed.MODULE_ACTIONS[PermissionModule.GUEST_ACCESS]``)
and resolves ``CurrentOrganization`` (``X-Organization-Id``), passed through
to ``GuestAccessService`` as ``requesting_organization_id`` so tenant
scoping is enforced the same way every other domain's router enforces it --
mirrors ``app.domains.voucher.router``'s identical pattern.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .constants import AccessRuleType
from .dependencies import get_guest_access_service
from .models import DeviceAccessRule, GuestAccessRule
from .schemas import (
    AccessCheckRequest,
    AccessCheckResponse,
    DeviceAccessRuleCreate,
    DeviceAccessRuleListResponse,
    DeviceAccessRuleResponse,
    GuestAccessRuleCreate,
    GuestAccessRuleListResponse,
    GuestAccessRuleResponse,
)
from .service import GuestAccessService

router = APIRouter(prefix="/guest-access", tags=["Guest Access Control"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _guest_rule_response(rule: GuestAccessRule) -> GuestAccessRuleResponse:
    return GuestAccessRuleResponse.model_validate(rule)


def _device_rule_response(rule: DeviceAccessRule) -> DeviceAccessRuleResponse:
    return DeviceAccessRuleResponse.model_validate(rule)


# ============================================================================
# Guest (identifier-keyed) rules
# ============================================================================


@router.post(
    "/rules",
    response_model=ApiResponse[GuestAccessRuleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("guest_access.create"))],
)
async def create_guest_rule(
    request: Request,
    payload: GuestAccessRuleCreate,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestAccessService = Depends(get_guest_access_service),
):
    rule = await service.create_guest_rule(
        organization_id=payload.organization_id,
        requesting_organization_id=requesting_organization_id,
        location_id=payload.location_id,
        identifier=payload.identifier,
        rule_type=payload.rule_type,
        reason=payload.reason,
        expires_at=payload.expires_at,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Guest access rule created",
        data=_guest_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/rules",
    response_model=ApiResponse[GuestAccessRuleListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_access.read"))],
)
async def list_guest_rules(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    location_id: uuid.UUID | None = Query(default=None),
    identifier: str | None = Query(default=None),
    rule_type: AccessRuleType | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestAccessService = Depends(get_guest_access_service),
):
    result = await service.list_guest_rules(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        identifier=identifier,
        rule_type=rule_type,
        page=page,
        page_size=page_size,
    )
    payload = GuestAccessRuleListResponse(
        items=[_guest_rule_response(r) for r in result.items],
        page=result.meta.page,
        page_size=result.meta.page_size,
        total_items=result.meta.total_items,
        total_pages=result.meta.total_pages,
        has_next=result.meta.has_next,
        has_previous=result.meta.has_previous,
    )
    return build_response(
        success=True,
        message="Guest access rules retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/rules/{rule_id}",
    response_model=ApiResponse[GuestAccessRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_access.read"))],
)
async def get_guest_rule(
    request: Request,
    rule_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestAccessService = Depends(get_guest_access_service),
):
    rule = await service.get_guest_rule(
        rule_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Guest access rule retrieved",
        data=_guest_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/rules/{rule_id}/deactivate",
    response_model=ApiResponse[GuestAccessRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_access.update"))],
)
async def deactivate_guest_rule(
    request: Request,
    rule_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestAccessService = Depends(get_guest_access_service),
):
    rule = await service.deactivate_guest_rule(
        rule_id=rule_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Guest access rule deactivated",
        data=_guest_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/rules/{rule_id}",
    response_model=ApiResponse[None],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_access.delete"))],
)
async def delete_guest_rule(
    request: Request,
    rule_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestAccessService = Depends(get_guest_access_service),
):
    await service.delete_guest_rule(
        rule_id=rule_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Guest access rule deleted",
        data=None,
        request_id=_request_id(request),
    )


# ============================================================================
# Device (MAC-keyed) rules
# ============================================================================


@router.post(
    "/device-rules",
    response_model=ApiResponse[DeviceAccessRuleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("guest_access.create"))],
)
async def create_device_rule(
    request: Request,
    payload: DeviceAccessRuleCreate,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestAccessService = Depends(get_guest_access_service),
):
    rule = await service.create_device_rule(
        organization_id=payload.organization_id,
        requesting_organization_id=requesting_organization_id,
        location_id=payload.location_id,
        mac_address=payload.mac_address,
        rule_type=payload.rule_type,
        reason=payload.reason,
        expires_at=payload.expires_at,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Device access rule created",
        data=_device_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/device-rules",
    response_model=ApiResponse[DeviceAccessRuleListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_access.read"))],
)
async def list_device_rules(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    location_id: uuid.UUID | None = Query(default=None),
    mac_address: str | None = Query(default=None),
    rule_type: AccessRuleType | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestAccessService = Depends(get_guest_access_service),
):
    result = await service.list_device_rules(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        mac_address=mac_address,
        rule_type=rule_type,
        page=page,
        page_size=page_size,
    )
    payload = DeviceAccessRuleListResponse(
        items=[_device_rule_response(r) for r in result.items],
        page=result.meta.page,
        page_size=result.meta.page_size,
        total_items=result.meta.total_items,
        total_pages=result.meta.total_pages,
        has_next=result.meta.has_next,
        has_previous=result.meta.has_previous,
    )
    return build_response(
        success=True,
        message="Device access rules retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/device-rules/{rule_id}",
    response_model=ApiResponse[DeviceAccessRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_access.read"))],
)
async def get_device_rule(
    request: Request,
    rule_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestAccessService = Depends(get_guest_access_service),
):
    rule = await service.get_device_rule(
        rule_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Device access rule retrieved",
        data=_device_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/device-rules/{rule_id}/deactivate",
    response_model=ApiResponse[DeviceAccessRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_access.update"))],
)
async def deactivate_device_rule(
    request: Request,
    rule_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestAccessService = Depends(get_guest_access_service),
):
    rule = await service.deactivate_device_rule(
        rule_id=rule_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Device access rule deactivated",
        data=_device_rule_response(rule).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/device-rules/{rule_id}",
    response_model=ApiResponse[None],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_access.delete"))],
)
async def delete_device_rule(
    request: Request,
    rule_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestAccessService = Depends(get_guest_access_service),
):
    await service.delete_device_rule(
        rule_id=rule_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Device access rule deleted",
        data=None,
        request_id=_request_id(request),
    )


# ============================================================================
# Decision check
# ============================================================================


@router.post(
    "/check",
    response_model=ApiResponse[AccessCheckResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_access.read"))],
)
async def check_access(
    request: Request,
    payload: AccessCheckRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestAccessService = Depends(get_guest_access_service),
):
    """Admin-facing "would this identifier/MAC be allowed to connect right
    now" preview -- the same resolution ``GuestService``'s optional
    enforcement hook runs at real login time (see
    ``app.domains.guest.service`` module docstring), exposed here so an
    admin can verify a rule's effect without a guest actually attempting to
    log in."""
    decision = await service.check_access(
        organization_id=payload.organization_id,
        requesting_organization_id=requesting_organization_id,
        location_id=payload.location_id,
        identifier=payload.identifier,
        mac_address=payload.mac_address,
    )
    response = AccessCheckResponse(
        allowed=decision.allowed,
        rule_type=decision.rule_type.value if decision.rule_type else None,
        matched_rule_id=decision.matched_rule_id,
        reason=decision.reason,
    )
    return build_response(
        success=True,
        message="Access check completed",
        data=response.model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
