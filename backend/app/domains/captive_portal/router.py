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

import hashlib
import uuid

from fastapi import (
    APIRouter,
    Depends,
    File,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)

from app.common.responses import ApiResponse, build_response
from app.core.config import get_settings
from app.core.storage import ObjectStorageError, get_object_storage
from app.domains.auth.models import AuthUser
from app.domains.auth.schemas import MessageResponse
from app.domains.billing.dependencies import get_entitlement_checker
from app.domains.billing.service import EntitlementChecker
from app.domains.branding.service import (
    _EXTENSION_TO_CONTENT_TYPE,
    BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES,
    BACKGROUND_IMAGE_MAX_BYTES,
    PUBLIC_BACKGROUND_IMAGE_PATH_TEMPLATE,
    PUBLIC_LOGO_PATH_TEMPLATE,
)
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .dependencies import get_captive_portal_service
from .exceptions import InvalidContentImageError
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

# The unauthenticated proxy path the uploaded pre-login content image is
# served from -- the guest portal renders `content_image_url` straight as
# an <img src> on its own separate origin (same absolute-URL reasoning as
# the branding fallback block in resolve), so this is a full path off the
# API base built per request, never a bare relative one.
PUBLIC_CONTENT_IMAGE_PATH_TEMPLATE = (
    "/captive-portal-configs/{config_id}/content-image/public"
)


def get_entitlement_aware_captive_portal_service(
    service: CaptivePortalService = Depends(get_captive_portal_service),
    entitlement_checker: EntitlementChecker = Depends(get_entitlement_checker),
) -> CaptivePortalService:
    """The admin write endpoints' service, with v7 Part 3 (P4)'s
    white-label entitlement check wired in.

    **Why this lives here and not in ``dependencies.py``.**
    ``app.domains.billing.dependencies`` reaches back into
    ``app.domains.captive_portal.dependencies`` through
    ``analytics.dependencies`` -> ``guest.dependencies``, so importing
    billing *from* that module is a genuine cycle -- it was tried, and it
    fails at import time from every entry point. ``router.py`` is a leaf
    nothing else imports, and ``captive_portal.dependencies`` itself has
    no billing edge, so the chain closes cleanly from here whichever
    module is loaded first.

    **Why only the write endpoints get it.** The gate must never touch
    ``GET /captive-portal/resolve``: that endpoint is unauthenticated and
    a 402 there would break the portal outright for every non-entitled
    tenant. Scoping the checker to this factory makes that structural
    rather than a comment -- the resolve endpoint is handed a service that
    has no checker to consult. ``guest``'s own login flow, which shares
    the plain ``get_captive_portal_service``, is unaffected for the same
    reason.

    Attaching rather than re-constructing keeps the whole service graph in
    ``dependencies.py``; this factory adds exactly one collaborator to the
    instance FastAPI has already built for this request.
    """
    service.entitlement_checker = entitlement_checker
    return service


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
        # Always emitted alongside redirect_url, in this one function, for
        # every endpoint at once -- admin CRUD and the guest-facing
        # /captive-portal/resolve both build their payload here. The two
        # fields are not alternatives (see the column's own comment in
        # models.py): the frontend needs both to decide what the
        # post-sign-in screen looks like, so neither may ever ship without
        # the other.
        post_login_html=config.post_login_html,
        content_mode=config.content_mode,
        content_heading=config.content_heading,
        content_body=config.content_body,
        content_image_url=config.content_image_url,
        content_survey=config.content_survey,
        # The post-connect ask flags travel with every other field, through
        # this one function, so the unauthenticated guest-facing
        # /captive-portal/resolve and the admin CRUD can never disagree
        # about what a venue turned on.
        collect_guest_name=config.collect_guest_name,
        collect_guest_email=config.collect_guest_email,
        review_card_enabled=config.review_card_enabled,
        review_url=config.review_url,
        guest_feedback_enabled=config.guest_feedback_enabled,
        feedback_dwell_minutes=config.feedback_dwell_minutes,
        otp_sms_enabled=config.otp_sms_enabled,
        otp_email_enabled=config.otp_email_enabled,
        otp_whatsapp_enabled=config.otp_whatsapp_enabled,
        voucher_enabled=config.voucher_enabled,
        username_password_enabled=config.username_password_enabled,
        pin_login_enabled=config.pin_login_enabled,
        social_login_enabled=config.social_login_enabled,
        social_login_providers=list(config.social_login_providers),
        business_hours_enabled=config.business_hours_enabled,
        business_hours_timezone=config.business_hours_timezone,
        business_hours_schedule=dict(config.business_hours_schedule),
        business_hours_closed_message=config.business_hours_closed_message,
        whitelist_only_enabled=config.whitelist_only_enabled,
        whitelist_only_denied_message=config.whitelist_only_denied_message,
        guest_font_choice=config.guest_font_choice,
        background_overlay_strength=config.background_overlay_strength,
        background_focal_x=config.background_focal_x,
        background_focal_y=config.background_focal_y,
        powered_by_enabled=config.powered_by_enabled,
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
    service: CaptivePortalService = Depends(
        get_entitlement_aware_captive_portal_service
    ),
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
        powered_by_enabled=payload.powered_by_enabled,
        redirect_url=payload.redirect_url,
        post_login_html=payload.post_login_html,
        content_mode=payload.content_mode,
        content_heading=payload.content_heading,
        content_body=payload.content_body,
        content_image_url=payload.content_image_url,
        content_survey=payload.content_survey,
        collect_guest_name=payload.collect_guest_name,
        collect_guest_email=payload.collect_guest_email,
        review_card_enabled=payload.review_card_enabled,
        review_url=payload.review_url,
        guest_feedback_enabled=payload.guest_feedback_enabled,
        feedback_dwell_minutes=payload.feedback_dwell_minutes,
        otp_sms_enabled=payload.otp_sms_enabled,
        otp_email_enabled=payload.otp_email_enabled,
        otp_whatsapp_enabled=payload.otp_whatsapp_enabled,
        voucher_enabled=payload.voucher_enabled,
        username_password_enabled=payload.username_password_enabled,
        pin_login_enabled=payload.pin_login_enabled,
        social_login_enabled=payload.social_login_enabled,
        social_login_providers=payload.social_login_providers,
        whitelist_only_enabled=payload.whitelist_only_enabled,
        whitelist_only_denied_message=payload.whitelist_only_denied_message,
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
    service: CaptivePortalService = Depends(
        get_entitlement_aware_captive_portal_service
    ),
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
# Per-venue content image ("Before sign-in: show a picture") upload
# ============================================================================
#
# The picture itself is venue content for one portal, so unlike the
# org-level logo/background (app.domains.branding, one row per org) it is
# keyed by the config row and stored under this domain's own namespace in
# the shared object storage. Admin upload/delete carry
# ``captive_portal.update`` (same write permission as every other config
# edit); the public GET streams the bytes with no auth at all -- a real
# captive-portal guest has no platform-user identity, exactly the
# branding public-proxy exception (see that router's get_logo_public).


def _content_image_asset_response(
    request: Request,
    *,
    content: bytes,
    content_type: str,
) -> Response:
    """Serves uploaded content-image bytes with the same strong-ETag
    browser caching the branding public proxies use (branding/router.py's
    ``_asset_response``) -- content-addressed hash, ``max-age`` from the
    branding asset TTL setting. The image URL never changes (it is the
    config's public path), so without the ETag every guest page load
    re-downloads the same bytes."""
    etag = hashlib.sha256(content).hexdigest()
    quoted_etag = f'"{etag}"'
    ttl = get_settings().branding_asset_cache_ttl_seconds
    headers = {
        "Cache-Control": f"public, max-age={ttl}, must-revalidate",
        "ETag": quoted_etag,
    }
    if_none_match = request.headers.get("if-none-match")
    if if_none_match is not None and quoted_etag in {
        tag.strip() for tag in if_none_match.split(",")
    }:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    return Response(content=content, media_type=content_type, headers=headers)


@router.post(
    "/captive-portal-configs/{config_id}/content-image",
    response_model=ApiResponse[CaptivePortalConfigResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("captive_portal.update"))],
)
async def upload_captive_portal_content_image(
    request: Request,
    config_id: uuid.UUID,
    file: UploadFile = File(...),
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CaptivePortalService = Depends(get_captive_portal_service),
):
    """Uploads (replacing any existing) the per-venue "Before sign-in:
    show a picture" content image for one portal config. Same constraints
    as the branding uploads (png/jpeg/webp/gif, <= 5 MiB); the bytes go
    to object storage and the config row records the durable key plus the
    absolute public URL the guest portal renders as an <img src>."""
    config = await service.get_config(
        config_id, requesting_organization_id=requesting_organization_id
    )
    content = await file.read()
    content_type = file.content_type or "application/octet-stream"
    extension = BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES.get(content_type)
    if extension is None:
        raise InvalidContentImageError(
            "Unsupported image type. Upload a PNG, JPEG, WebP or GIF."
        )
    if len(content) > BACKGROUND_IMAGE_MAX_BYTES:
        max_mb = BACKGROUND_IMAGE_MAX_BYTES // (1024 * 1024)
        raise InvalidContentImageError(f"Image is too large. The limit is {max_mb} MB.")

    api_base = str(request.base_url).rstrip("/") + get_settings().api_v1_prefix
    public_path = PUBLIC_CONTENT_IMAGE_PATH_TEMPLATE.format(config_id=config_id)
    content_image_url = api_base + public_path
    content_image_key = (
        f"captive_portal/{config.organization_id}/content/{config_id}/"
        f"{uuid.uuid4()}.{extension}"
    )
    try:
        await get_object_storage().upload(
            key=content_image_key,
            content=content,
            content_type=content_type,
        )
    except ObjectStorageError as exc:
        raise InvalidContentImageError(
            "Could not store the image right now. Please try again."
        ) from exc

    updated = await service.set_content_image(
        config_id,
        content_image_key=content_image_key,
        content_image_url=content_image_url,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Content image uploaded",
        data=_config_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/captive-portal-configs/{config_id}/content-image",
    response_model=ApiResponse[CaptivePortalConfigResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("captive_portal.update"))],
)
async def delete_captive_portal_content_image(
    request: Request,
    config_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: CaptivePortalService = Depends(get_captive_portal_service),
):
    """Removes the uploaded pre-login content image from a config row.
    The object bytes are left in storage (orphaned) exactly as branding's
    own delete does -- the row no longer references them, which is the
    observable contract."""
    updated = await service.clear_content_image(
        config_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Content image removed",
        data=_config_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/captive-portal-configs/{config_id}/content-image/public",
    status_code=status.HTTP_200_OK,
)
async def get_captive_portal_content_image_public(
    request: Request,
    config_id: uuid.UUID,
    service: CaptivePortalService = Depends(get_captive_portal_service),
):
    """Streams a config's uploaded pre-login content image with **no auth**
    -- the guest portal renders ``content_image_url`` straight as an
    ``<img src>`` before the guest has any identity. ``config_id`` in the
    path is the (unguessable) capability, mirroring the branding public
    proxies; a config with no uploaded image 404s."""
    key = await service.get_content_image_key(config_id)
    if not key:
        return Response(status_code=status.HTTP_404_NOT_FOUND)
    try:
        content = await get_object_storage().download(key=key)
    except ObjectStorageError:
        return Response(status_code=status.HTTP_404_NOT_FOUND)
    extension = key.rsplit(".", 1)[-1].lower() if "." in key else ""
    content_type = _EXTENSION_TO_CONTENT_TYPE.get(extension, "application/octet-stream")
    return _content_image_asset_response(
        request, content=content, content_type=content_type
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
):
    resolved = await service.resolve_portal_config(
        organization_id=organization_id, location_id=location_id
    )
    config_payload = _config_response(resolved.config).model_dump()

    # Whitelist-only mode is an operator setting, not something a guest is
    # told before they are refused -- see
    # `ResolvedCaptivePortalConfigResponse.whitelist_only_enabled` for the
    # full reasoning and for why this pop and that field's own
    # `exclude=True` are both here rather than either one alone.
    # `whitelist_only_denied_message` deliberately stays in the payload:
    # the portal runtime needs the venue's own refusal copy, the identical
    # path `business_hours_closed_message` already takes.
    config_payload.pop("whitelist_only_enabled", None)

    # `CaptivePortalConfig.name` is an internal admin label for telling
    # multiple configs apart (e.g. an org-level default vs. a
    # location-specific override) -- nothing in the customer-facing
    # Portal Configuration page ever lets an admin set it, and it isn't
    # meant to be a guest-facing venue name at all. Every guest-facing
    # surface (BrandPanel's "courtesy of {name}", the browser tab title,
    # the "{name} is currently closed" message) was rendering it as if
    # it were exactly that -- confirmed live: a real config's own
    # internal label happened to read "Guest WiFi Login" (copied from
    # its headline at creation time), so the BrandPanel's own generated
    # sentence read "Fast, secure WiFi, courtesy of Guest WiFi Login,"
    # directly overlapping/duplicating the sign-in card's own headline.
    # The real location's own name is what a guest actually recognizes
    # ("courtesy of Sunset Cafe", not an internal config label) --
    # substituted here whenever a real location is resolvable, falling
    # back to the config's own name only when there isn't one (an
    # org-level default with no location context at all).
    if location_id is not None and resolved.location_name is not None:
        # Sourced off the same location lookup `resolve_portal_config`
        # already made internally (piggybacked onto `location_country`) --
        # no second `LocationRepository` query needed, and it stays correct
        # on a cache hit too (baked into the cached payload itself).
        config_payload["name"] = resolved.location_name

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
    # 404. `request.base_url` is this same request's own scheme+host --
    # correctly `https` in production behind the real nginx reverse
    # proxy this deployment actually runs *only* because uvicorn's own
    # ProxyHeadersMiddleware is told to trust that proxy's peer IP (see
    # scripts/run_api.sh's own FORWARDED_ALLOW_IPS comment for the real
    # incident this fixed: guest phones on the real captive portal
    # silently never showed the org's logo, because this was quietly
    # "http" instead and the browser dropped the mixed-content image).
    #
    # The same branding row also carries the three v7 image
    # measurements (background_luminance / _top_luminance / _entropy,
    # design spec §1.4 C3/C5). They are read off the same row, and only
    # on the branch that actually adopts the branding image -- a config
    # with its own typed-in background_image_url points at a file
    # nothing measured, and reporting the org photo's numbers for a
    # *different* image would be worse than reporting None.
    #
    # Design spec §5 S7: that row is no longer fetched here. It is
    # resolved (and cached) by `CaptivePortalService.resolve_portal_config`
    # itself, under the same key as everything else, so a cache hit costs
    # no `SELECT brandings`, no connection checkout, and no COMMIT --
    # `app.database.session.get_db_session` commits unconditionally, so
    # this endpoint was paying a write-path round trip on a read-only
    # guest request. `resolved.branding` is None both when the row does
    # not exist and when this config supplied both its own URLs (in which
    # case the service correctly never looked); the loop below is a no-op
    # either way, which is exactly the old behaviour.
    #
    # What deliberately stays here rather than moving into the payload is
    # URL *construction*. `request.base_url` is per-request, and the
    # absolute-URL requirement is real (see the incident note below), so
    # baking a host into a shared cache entry would make one origin's
    # first guest pin the URL every other origin then serves.
    background_luminance: int | None = None
    background_top_luminance: int | None = None
    background_entropy: int | None = None

    branding = resolved.branding
    needs_background = config_payload["background_image_url"] is None
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
            background_luminance = branding.background_luminance
            background_top_luminance = branding.background_top_luminance
            background_entropy = branding.background_entropy

    response_payload = ResolvedCaptivePortalConfigResponse(
        **config_payload,
        resolved_via_location_override=resolved.resolved_via_location_override,
        is_open_now=is_open_now(
            enabled=resolved.config.business_hours_enabled,
            timezone=resolved.config.business_hours_timezone,
            schedule=resolved.config.business_hours_schedule,
        ),
        location_country=resolved.location_country,
        background_luminance=background_luminance,
        background_top_luminance=background_top_luminance,
        background_entropy=background_entropy,
    )
    return build_response(
        success=True,
        message="Captive portal config resolved",
        data=response_payload.model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
