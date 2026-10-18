"""Login-messaging routes: the venue's own dashboard and the Master console.

Two routers over the same :class:`~.service.LoginMessagingService`:

* ``router`` (``/guest-messaging/providers``) -- the venue. The organization
  is ``RequireOrganization`` (the caller's scope); no route here takes an
  organization id from the path or body. The permission is
  ``marketing_providers.read`` / ``.manage`` pinned at ORGANIZATION: the
  existing grant for "who may see and change this venue's own messaging
  credentials" (Organization Owner holds it; no location role does), so no
  new permission has to be seeded before the card works.
* ``platform_router`` (``/platform/organizations/{organization_id}/
  guest-messaging/providers``) -- the Wyfy team, acting for a venue without
  logging in as it. The organization IS the path id; the permission is
  pinned GLOBAL (``organizations.read`` / ``organizations.update``), so an
  organization- or location-scoped grant can never satisfy it, whatever
  headers the caller sends. Every write is audited with the staff member
  and the target organization, and marks the row "set up by the Wyfy Guest
  team".
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, Response, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentUser,
    RequireOrganization,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .dependencies import get_login_messaging_service
from .schemas import (
    ChannelParam,
    LoginProviderPutRequest,
    VerifyConfirmRequest,
    VerifyStartRequest,
)
from .service import Actor, LoginMessagingService

router = APIRouter(prefix="/guest-messaging/providers", tags=["Login messaging"])
platform_router = APIRouter(
    prefix="/platform/organizations/{organization_id}/guest-messaging/providers",
    tags=["Login messaging (Master)"],
)

CUSTOMER_READ = "marketing_providers.read"
CUSTOMER_MANAGE = "marketing_providers.manage"
PLATFORM_READ = "organizations.read"
PLATFORM_MANAGE = "organizations.update"


def _customer(permission: str) -> list[Any]:
    return [
        Depends(RequireOrganization),
        Depends(RequirePermission(permission, scope=ScopeType.ORGANIZATION)),
    ]


def _platform(permission: str) -> list[Any]:
    return [Depends(RequirePermission(permission, scope=ScopeType.GLOBAL))]


def _ok(request: Request, message: str, data: Any) -> dict[str, Any]:
    return build_response(
        success=True,
        message=message,
        data=data,
        request_id=str(getattr(request.state, "request_id", "")),
    )


def _customer_actor(user: AuthUser) -> Actor:
    return Actor(user_id=uuid.UUID(user.id), via_platform=False)


def _platform_actor(user: AuthUser) -> Actor:
    return Actor(user_id=uuid.UUID(user.id), via_platform=True)


# ============================================================================
# Venue
# ============================================================================


@router.get("", response_model=ApiResponse[dict], dependencies=_customer(CUSTOMER_READ))
async def list_login_providers(
    request: Request,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: LoginMessagingService = Depends(get_login_messaging_service),
):
    return _ok(
        request,
        "Login messaging",
        await service.overview(organization_id, for_platform=False),
    )


@router.put(
    "/{channel}",
    response_model=ApiResponse[dict],
    dependencies=_customer(CUSTOMER_MANAGE),
)
async def put_login_provider(
    request: Request,
    response: Response,
    channel: ChannelParam,
    body: LoginProviderPutRequest,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    user: AuthUser = Depends(CurrentUser),
    service: LoginMessagingService = Depends(get_login_messaging_service),
):
    view, created = await service.put_provider(
        organization_id,
        channel,
        _customer_actor(user),
        provider_type=body.provider_type,
        config=body.config,
        enabled=body.enabled,
    )
    if created:
        response.status_code = status.HTTP_201_CREATED
    return _ok(request, "Provider saved", view)


@router.delete(
    "/{channel}",
    response_model=ApiResponse[dict],
    dependencies=_customer(CUSTOMER_MANAGE),
)
async def delete_login_provider(
    request: Request,
    channel: ChannelParam,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    user: AuthUser = Depends(CurrentUser),
    service: LoginMessagingService = Depends(get_login_messaging_service),
):
    return _ok(
        request,
        "Provider removed",
        await service.delete_provider(organization_id, channel, _customer_actor(user)),
    )


@router.post(
    "/{channel}/verify",
    response_model=ApiResponse[dict],
    dependencies=_customer(CUSTOMER_MANAGE),
)
async def start_login_provider_verification(
    request: Request,
    channel: ChannelParam,
    body: VerifyStartRequest,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    user: AuthUser = Depends(CurrentUser),
    service: LoginMessagingService = Depends(get_login_messaging_service),
):
    return _ok(
        request,
        "Verification code sent",
        await service.start_verification(
            organization_id, channel, _customer_actor(user), to=body.to
        ),
    )


@router.post(
    "/{channel}/verify/confirm",
    response_model=ApiResponse[dict],
    dependencies=_customer(CUSTOMER_MANAGE),
)
async def confirm_login_provider_verification(
    request: Request,
    channel: ChannelParam,
    body: VerifyConfirmRequest,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    user: AuthUser = Depends(CurrentUser),
    service: LoginMessagingService = Depends(get_login_messaging_service),
):
    return _ok(
        request,
        "Provider verified",
        await service.confirm_verification(
            organization_id, channel, _customer_actor(user), code=body.code
        ),
    )


# ============================================================================
# Master (Wyfy team, acting for the organization in the path)
# ============================================================================


@platform_router.get(
    "", response_model=ApiResponse[dict], dependencies=_platform(PLATFORM_READ)
)
async def platform_list_login_providers(
    request: Request,
    organization_id: uuid.UUID,
    service: LoginMessagingService = Depends(get_login_messaging_service),
):
    return _ok(
        request,
        "Login messaging",
        await service.overview(organization_id, for_platform=True),
    )


@platform_router.put(
    "/{channel}",
    response_model=ApiResponse[dict],
    dependencies=_platform(PLATFORM_MANAGE),
)
async def platform_put_login_provider(
    request: Request,
    response: Response,
    organization_id: uuid.UUID,
    channel: ChannelParam,
    body: LoginProviderPutRequest,
    user: AuthUser = Depends(CurrentUser),
    service: LoginMessagingService = Depends(get_login_messaging_service),
):
    view, created = await service.put_provider(
        organization_id,
        channel,
        _platform_actor(user),
        provider_type=body.provider_type,
        config=body.config,
        enabled=body.enabled,
    )
    if created:
        response.status_code = status.HTTP_201_CREATED
    return _ok(request, "Provider saved", view)


@platform_router.delete(
    "/{channel}",
    response_model=ApiResponse[dict],
    dependencies=_platform(PLATFORM_MANAGE),
)
async def platform_delete_login_provider(
    request: Request,
    organization_id: uuid.UUID,
    channel: ChannelParam,
    user: AuthUser = Depends(CurrentUser),
    service: LoginMessagingService = Depends(get_login_messaging_service),
):
    return _ok(
        request,
        "Provider removed",
        await service.delete_provider(organization_id, channel, _platform_actor(user)),
    )


@platform_router.post(
    "/{channel}/verify",
    response_model=ApiResponse[dict],
    dependencies=_platform(PLATFORM_MANAGE),
)
async def platform_start_login_provider_verification(
    request: Request,
    organization_id: uuid.UUID,
    channel: ChannelParam,
    body: VerifyStartRequest,
    user: AuthUser = Depends(CurrentUser),
    service: LoginMessagingService = Depends(get_login_messaging_service),
):
    return _ok(
        request,
        "Verification code sent",
        await service.start_verification(
            organization_id, channel, _platform_actor(user), to=body.to
        ),
    )


@platform_router.post(
    "/{channel}/verify/confirm",
    response_model=ApiResponse[dict],
    dependencies=_platform(PLATFORM_MANAGE),
)
async def platform_confirm_login_provider_verification(
    request: Request,
    organization_id: uuid.UUID,
    channel: ChannelParam,
    body: VerifyConfirmRequest,
    user: AuthUser = Depends(CurrentUser),
    service: LoginMessagingService = Depends(get_login_messaging_service),
):
    return _ok(
        request,
        "Provider verified",
        await service.confirm_verification(
            organization_id, channel, _platform_actor(user), code=body.code
        ),
    )


__all__ = ["platform_router", "router"]
