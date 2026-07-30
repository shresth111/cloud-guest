"""FastAPI routes for the Captive Portal domain: admin-facing config
CRUD/activate/deactivate/delete, plus a guest-facing resolve endpoint.

Every admin-facing endpoint is gated by RBAC's existing
``RequirePermission`` dependency against the already-seeded
``captive_portal.*`` permission keys (``app.domains.rbac.seed
.MODULE_ACTIONS[PermissionModule.CAPTIVE_PORTAL]`` = create/read/update/
delete/manage -- there is no dedicated ``approve``/``execute`` action for
this module) and resolves ``CurrentOrganization`` (``X-Organization-Id``),
passed through to ``CaptivePortalService`` as ``requesting_organization_id``
so tenant scoping is enforced the same way every other domain's router
enforces it.

**``activate``/``deactivate`` map to ``captive_portal.update``**, not
``.manage``/``.delete`` -- toggling whether a config is currently usable is
a lifecycle status change, not a destructive or platform-admin-only
action, mirroring ``app.domains.voucher.router``'s identical "revoke ->
voucher.update" precedent.

**``GET /captive-portal/resolve`` carries no ``RequirePermission``/
``CurrentUser`` dependency at all** -- mirrors ``app.domains.otp.router``/
``app.domains.voucher.router``'s identical justification: the caller is a
guest's device/captive-portal frontend, with no platform-user identity
RBAC could ever grant a permission to, resolving *before* the guest has
authenticated by any of OTP/voucher/future methods. It still uses the
standard ``ApiResponse`` envelope (consistent with OTP's/Voucher's own
guest-facing-but-still-enveloped precedent), since its real caller is the
captive-portal frontend, a real client that benefits from the same
structured contract every other user-facing endpoint returns.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import ApiResponse, build_response
from app.core.config import get_settings
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.auth.schemas import MessageResponse
from app.domains.branding.repository import BrandingRepository
from app.domains.branding.service import (
    PUBLIC_BACKGROUND_IMAGE_PATH_TEMPLATE,
    PUBLIC_LOGO_PATH_TEMPLATE,
)
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .dependencies import get_captive_portal_service
from .models import CaptivePortalConfig
from .schemas import (
    CaptivePortalConfigCreateRequest,
    CaptivePortalConfigListResponse,
    CaptivePortalConfigResponse,
    CaptivePortalConfigUpdateRequest,
    ResolvedCaptivePortalConfigResponse,
)
from .service import CaptivePortalService
from .validators import is_open_now

router = APIRouter(tags=["Captive Portal"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _config_response(config: CaptivePortalConfig) -> CaptivePortalConfigResponse:
    return CaptivePortalConfigResponse(
        id=str(config.id),
        organization_id=str(config.organization_id),
        location_id=str(config.location_id) if config.location_id else None,
        name=config.name,
        is_active=config.is_active,
        is_default=config.is_default,
        theme=config.theme,
        logo_url=config.logo_url,
        background_image_url=config.background_image_url,
        primary_color=config.primary_color,
        secondary_color=config.secondary_color,
        default_language=config.default_language,
        supported_languages=list(config.supported_languages),
        advertisement_banner_url=config.advertisement_banner_url,
        advertisement_banner_link=config.advertisement_banner_link,
        terms_and_conditions_text=config.terms_and_conditions_text,
        terms_and_conditions_url=config.terms_and_conditions_url,
        privacy_policy_text=config.privacy_policy_text,
        privacy_policy_url=config.privacy_policy_url,
        splash_headline=config.splash_headline,
        splash_welcome_message=config.splash_welcome_message,
        redirect_url=config.redirect_url,
        otp_sms_enabled=config.otp_sms_enabled,
        otp_email_enabled=config.otp_email_enabled,
        voucher_enabled=config.voucher_enabled,
        username_password_enabled=config.username_password_enabled,
        social_login_enabled=config.social_login_enabled,
        social_login_providers=list(config.social_login_providers),
        created_at=config.created_at,
        updated_at=config.updated_at,
    )


# ============================================================================
# Admin-facing CRUD + lifecycle
# ============================================================================


@router.post(
    "/captive-portal-configs",
    response_model=ApiResponse[CaptivePortalConfigResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("captive_portal.create"))],
)
async def create_captive_portal_config(
    request: Request,
    payload: CaptivePortalConfigCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CaptivePortalService = Depends(get_captive_portal_service),
):
    config = await service.create_config(
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        organization_id=payload.organization_id,
        location_id=payload.location_id,
        name=payload.name,
        is_active=payload.is_active,
        is_default=payload.is_default,
        theme=payload.theme,
        logo_url=payload.logo_url,
        background_image_url=payload.background_image_url,
        primary_color=payload.primary_color,
        secondary_color=payload.secondary_color,
        default_language=payload.default_language,
        supported_languages=payload.supported_languages,
        advertisement_banner_url=payload.advertisement_banner_url,
        advertisement_banner_link=payload.advertisement_banner_link,
        terms_and_conditions_text=payload.terms_and_conditions_text,
        terms_and_conditions_url=payload.terms_and_conditions_url,
        privacy_policy_text=payload.privacy_policy_text,
        privacy_policy_url=payload.privacy_policy_url,
        splash_headline=payload.splash_headline,
        splash_welcome_message=payload.splash_welcome_message,
        redirect_url=payload.redirect_url,
        otp_sms_enabled=payload.otp_sms_enabled,
        otp_email_enabled=payload.otp_email_enabled,
        voucher_enabled=payload.voucher_enabled,
        username_password_enabled=payload.username_password_enabled,
        social_login_enabled=payload.social_login_enabled,
        social_login_providers=payload.social_login_providers,
    )
    return build_response(
        success=True,
        message="Captive portal config created",
        data=_config_response(config).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/captive-portal-configs",
    response_model=ApiResponse[CaptivePortalConfigListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("captive_portal.read"))],
)
async def list_captive_portal_configs(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    location_id: uuid.UUID | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CaptivePortalService = Depends(get_captive_portal_service),
):
    configs, meta = await service.list_configs(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        page=page,
        page_size=page_size,
    )
    payload = CaptivePortalConfigListResponse(
        items=[_config_response(config) for config in configs],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Captive portal configs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/captive-portal-configs/{config_id}",
    response_model=ApiResponse[CaptivePortalConfigResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("captive_portal.read"))],
)
async def get_captive_portal_config(
    request: Request,
    config_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CaptivePortalService = Depends(get_captive_portal_service),
):
    config = await service.get_config(
        config_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Captive portal config retrieved",
        data=_config_response(config).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/captive-portal-configs/{config_id}",
    response_model=ApiResponse[CaptivePortalConfigResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("captive_portal.update"))],
)
async def update_captive_portal_config(
    request: Request,
    config_id: uuid.UUID,
    payload: CaptivePortalConfigUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CaptivePortalService = Depends(get_captive_portal_service),
):
    data = payload.model_dump(exclude_unset=True)
    config = await service.update_config(
        actor_user_id=uuid.UUID(user.id),
        config_id=config_id,
        requesting_organization_id=requesting_organization_id,
        data=data,
    )
    return build_response(
        success=True,
        message="Captive portal config updated",
        data=_config_response(config).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/captive-portal-configs/{config_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("captive_portal.delete"))],
)
async def delete_captive_portal_config(
    request: Request,
    config_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CaptivePortalService = Depends(get_captive_portal_service),
):
    await service.delete_config(
        actor_user_id=uuid.UUID(user.id),
        config_id=config_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Captive portal config deleted",
        data=MessageResponse(message="Captive portal config deleted").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/captive-portal-configs/{config_id}/activate",
    response_model=ApiResponse[CaptivePortalConfigResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("captive_portal.update"))],
)
async def activate_captive_portal_config(
    request: Request,
    config_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CaptivePortalService = Depends(get_captive_portal_service),
):
    config = await service.activate_config(
        actor_user_id=uuid.UUID(user.id),
        config_id=config_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Captive portal config activated",
        data=_config_response(config).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/captive-portal-configs/{config_id}/deactivate",
    response_model=ApiResponse[CaptivePortalConfigResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("captive_portal.update"))],
)
async def deactivate_captive_portal_config(
    request: Request,
    config_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CaptivePortalService = Depends(get_captive_portal_service),
):
    config = await service.deactivate_config(
        actor_user_id=uuid.UUID(user.id),
        config_id=config_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Captive portal config deactivated",
        data=_config_response(config).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Guest-facing resolution -- no RBAC, see module docstring
# ============================================================================


@router.get(
    "/captive-portal/resolve",
    response_model=ApiResponse[ResolvedCaptivePortalConfigResponse],
    status_code=status.HTTP_200_OK,
)
async def resolve_captive_portal_config(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    service: CaptivePortalService = Depends(get_captive_portal_service),
    db: AsyncSession = Depends(get_db_session),
):
    resolved = await service.resolve_portal_config(
        organization_id=organization_id, location_id=location_id
    )
    config_payload = _config_response(resolved.config).model_dump()

    # Fall back to the organization's own branding (app.domains.branding)
    # for whichever of logo_url/background_image_url this specific
    # captive_portal_configs row left unset -- a config controls login-
    # method toggles/legal text/theme colors, but plenty of real
    # organizations only ever uploaded a logo/background image through
    # the separate Branding admin page, never typed a URL into this
    # config's own fields. Guest-facing resolve only: every admin CRUD
    # endpoint above (list/get/create/update) returns the config exactly
    # as stored, unmerged, so an operator editing it sees real data, not
    # a synthesized value. Points at the *public* (unauthenticated)
    # branding proxy paths (see app.domains.branding.router's
    # get_logo_public/get_background_image_public) -- the real, private
    # /branding/logo/raw path this same organization's admins use
    # requires a JWT this anonymous guest's device will never have.
    #
    # Built as a full absolute URL (scheme+host from this very request,
    # not a bare path) -- unlike every *other* branding call in this
    # codebase, which goes through the authenticated `api` axios client
    # (whose own configured base URL supplies the host), the guest-facing
    # frontend renders this value directly as an <img src>/CSS
    # background-image, on its own separate origin (a different port in
    # this platform's actual deployment) -- a bare "/branding/..." path
    # would resolve against the *frontend's* origin, not the API's, and
    # 404. `request.base_url` is this same request's own scheme+host
    # (confirmed live against production: this API is reached directly,
    # not behind a Host-header-rewriting reverse proxy).
    needs_logo = config_payload["logo_url"] is None
    needs_background = config_payload["background_image_url"] is None
    if needs_logo or needs_background:
        branding = await BrandingRepository(db).get_by_organization(
            resolved.config.organization_id
        )
        if branding is not None:
            org_id = str(resolved.config.organization_id)
            api_base = str(request.base_url).rstrip("/") + get_settings().api_v1_prefix
            if config_payload["logo_url"] is None:
                if branding.logo_key:
                    # An uploaded logo needs the public proxy -- the
                    # object storage key isn't a URL a browser can load.
                    logo_path = PUBLIC_LOGO_PATH_TEMPLATE.format(organization_id=org_id)
                    config_payload["logo_url"] = api_base + logo_path
                elif branding.logo_url:
                    # A plain, already-hosted URL an admin typed in
                    # instead of uploading a file -- directly
                    # hotlinkable as-is, no proxy needed.
                    config_payload["logo_url"] = branding.logo_url
            if needs_background and branding.background_image_key:
                bg_path = PUBLIC_BACKGROUND_IMAGE_PATH_TEMPLATE.format(
                    organization_id=org_id
                )
                config_payload["background_image_url"] = api_base + bg_path

    response_payload = ResolvedCaptivePortalConfigResponse(
        **config_payload,
        resolved_via_location_override=resolved.resolved_via_location_override,
        is_open_now=is_open_now(
            enabled=resolved.config.business_hours_enabled,
            timezone=resolved.config.business_hours_timezone,
            schedule=resolved.config.business_hours_schedule,
        ),
    )
    return build_response(
        success=True,
        message="Captive portal config resolved",
        data=response_payload.model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
