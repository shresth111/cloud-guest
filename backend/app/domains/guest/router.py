"""FastAPI routes for the Guest domain (BE-010 Part 4): guest-facing login/
consent, admin-facing guest/session management, RADIUS-facing ``rlm_rest``
endpoints, and read-only guest analytics.

Four separate ``APIRouter`` instances are exported (rather than one),
because this module's endpoints genuinely span four different top-level
path groups with four different authentication postures:

* ``guest_router`` (``/guest/...``) -- guest-facing login/consent. No
  ``RequirePermission``/``CurrentUser`` at all, mirroring
  ``app.domains.otp.router``/``app.domains.voucher.router``'s identical
  justification: the caller is a guest at a captive portal with no
  platform-user identity RBAC could ever grant a permission to. Abuse
  protection is inherited entirely from ``OtpService``'s/
  ``VoucherService``'s own rate limiting (composed, not reimplemented).
* ``admin_router`` (``/guests``, ``/guest-sessions``) -- gated by RBAC's
  existing ``guest_wifi.*``/``guest_users.*``/``guest_sessions.*``
  permission keys.
* ``radius_router`` (``/radius/...``) -- gated by ``dependencies.CurrentNas``
  (NAS shared-secret authentication), not RBAC -- see ``service.py``'s
  module docstring. ``POST /radius/nas`` is the one RADIUS-prefixed
  endpoint that *is* RBAC-gated (an admin registering a NAS, not FreeRADIUS
  calling in).
* ``analytics_router`` (``/guest-analytics/...``) -- gated by RBAC's
  ``analytics.*`` permission keys.

All except the RADIUS-facing endpoints use the standard
``ApiResponse``/``build_response`` envelope. The RADIUS-facing endpoints
return their own minimal, documented JSON contract (see ``schemas.py``) --
consistent with ``app.domains.router_agent``'s device-facing endpoints,
which deliberately do not use ``ApiResponse`` either (the caller is
FreeRADIUS's ``rlm_rest`` module, not a rich client parsing a structured
envelope).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.core.config import get_settings
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequireOrganization,
    RequirePermission,
)
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.service import WireGuardService

from .constants import (
    MAX_BULK_DEVICE_LOOKUP_IDS,
    RADIUS_ACCT_STATUS_ACCOUNTING_OFF,
    RADIUS_ACCT_STATUS_ACCOUNTING_ON,
    RADIUS_ACCT_STATUS_INTERIM_UPDATE,
    RADIUS_ACCT_STATUS_START,
    RADIUS_ACCT_STATUS_STOP,
    GuestSessionStatus,
    NasStatus,
)
from .dependencies import (
    CurrentNas,
    get_guest_analytics_service,
    get_guest_service,
    get_radius_service,
)
from .exceptions import (
    RadiusAccountingUnsupportedStatusTypeError,
    RadiusNasBridgeDeregistrationError,
    RadiusNasNotFoundError,
)
from .models import Guest, GuestDevice, GuestLoginHistory, GuestSession, RadiusNasClient
from .schemas import (
    GuestAnalyticsSummaryResponse,
    GuestBlockRequest,
    GuestConsentRequest,
    GuestConsentResponse,
    GuestDetailResponse,
    GuestDeviceListResponse,
    GuestDeviceResponse,
    GuestDisconnectRequest,
    GuestListResponse,
    GuestLoginHistoryListResponse,
    GuestLoginHistoryResponse,
    GuestLoginResponse,
    GuestOtpLoginRequest,
    GuestPasswordLoginRequest,
    GuestPinLoginRequest,
    GuestResponse,
    GuestSessionListResponse,
    GuestSessionResponse,
    GuestSetPasswordRequest,
    GuestSetPasswordResponse,
    GuestSetPinRequest,
    GuestSetPinResponse,
    GuestUpdateProfileRequest,
    GuestUpdateProfileResponse,
    GuestVoucherLoginRequest,
    OtpSuccessRateResponse,
    RadiusAccountingRequest,
    RadiusAccountingResponse,
    RadiusAuthorizeRequest,
    RadiusNasCreatedResponse,
    RadiusNasDisableRequest,
    RadiusNasListResponse,
    RadiusNasRegisterRequest,
    RadiusNasResponse,
    RadiusNasUpdateRequest,
    SessionDisconnectRequest,
    SessionExtendRequest,
    SessionPauseRequest,
    SessionReconnectRequest,
    SessionTerminateRequest,
    TopDeviceItem,
    TopDevicesResponse,
    TopLocationItem,
    TopLocationsResponse,
    VoucherUsageResponse,
)
from .service import (
    GuestAnalyticsService,
    GuestLoginResult,
    GuestService,
    RadiusService,
)

guest_router = APIRouter(prefix="/guest", tags=["Guest"])
admin_router = APIRouter(tags=["Guest Admin"])
radius_router = APIRouter(prefix="/radius", tags=["RADIUS"])
nas_router = APIRouter(prefix="/radius/nas", tags=["RADIUS NAS Admin"])
nas_cross_reference_router = APIRouter(tags=["RADIUS NAS Admin"])
analytics_router = APIRouter(prefix="/guest-analytics", tags=["Guest Analytics"])

# The single-tenant FreeRADIUS bridge (ops/hub-agents/radius_agent.py,
# port 9092). These WERE module constants hardcoded to the old hub's public
# IP with the shared secret in cleartext in this file; both are now
# Settings fields (CLOUDGUEST_HUB_RADIUS_AGENT_URL / _SECRET) read per
# call. See app.domains.wireguard.router's identical note for why.

logger = logging.getLogger(__name__)


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


async def _deregister_nas_from_radius_bridge(nas_identifier: str) -> int:
    """Remove ``nas_identifier``'s live entry from the real FreeRADIUS
    server's ``clients.conf`` via the hub agent, returning how many
    ``client{}`` stanzas the hub reports it removed.

    Raises ``RadiusNasBridgeDeregistrationError`` on any failure. This
    function used to catch ``httpx.HTTPError``, log a WARNING and return
    normally, and that swallowing was the actual bug, not the transport
    error underneath it: the agent (``ops/hub-agents/radius_agent.py``)
    had no ``DELETE`` handler at all, so every single call in production
    got back ``501 Unsupported method ('DELETE')`` and every single delete
    was still reported to the operator as complete. The live hub ended up
    with 21 ``client{}`` stanzas against 0 active NAS rows -- five of them
    belonging to NAS clients an operator had deleted through the console
    minutes earlier, each still holding a valid shared secret the RADIUS
    server would still accept.

    The stanza count is returned rather than discarded because ``0``
    ("this NAS was not on the RADIUS server") is a genuinely different
    outcome from ``2`` ("two live credentials just got revoked"), and the
    delete endpoint says which one happened. ``0`` is still a success: it
    is the honest report of an already-consistent state, and it is what a
    retry after a partial failure must be able to return.

    Keyed on ``nas_identifier`` -- the one identifier a NAS keeps for its
    whole lifetime, unlike ``tunnel_ip``, which a WireGuard reallocation
    changes (and has changed, repeatedly, on the live fleet).
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            _settings = get_settings()
            resp = await client.request(
                "DELETE",
                _settings.hub_radius_agent_url,
                headers={
                    "X-Agent-Secret": _settings.hub_radius_agent_secret,
                    "Content-Type": "application/json",
                },
                json={"nas_identifier": nas_identifier},
            )
            resp.raise_for_status()
            body = resp.json()
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "radius_nas_bridge_deregister_failed",
            extra={
                "nas_identifier": nas_identifier,
                "status_code": exc.response.status_code,
            },
        )
        raise RadiusNasBridgeDeregistrationError(
            nas_identifier, f"the RADIUS agent returned HTTP {exc.response.status_code}"
        ) from exc
    except httpx.HTTPError as exc:
        logger.warning(
            "radius_nas_bridge_deregister_failed",
            extra={"nas_identifier": nas_identifier},
        )
        raise RadiusNasBridgeDeregistrationError(
            nas_identifier, "the RADIUS agent could not be reached"
        ) from exc
    except ValueError as exc:
        # A 200 whose body is not JSON is not a confirmed removal. The
        # agent that answered this call for months returned a plain-text
        # 501 error page; anything that is not the agent's real JSON
        # contract must fail, not be optimistically read as success.
        logger.warning(
            "radius_nas_bridge_deregister_unparseable_response",
            extra={"nas_identifier": nas_identifier},
        )
        raise RadiusNasBridgeDeregistrationError(
            nas_identifier, "the RADIUS agent returned an unreadable response"
        ) from exc

    removed = body.get("removed") if isinstance(body, dict) else None
    if not isinstance(removed, int) or removed < 0:
        # No `removed` count means this is not the deregistration handler
        # answering -- an older agent build, or some other service on the
        # port. Treating an unrecognised 200 as a completed revocation is
        # exactly the assumption that produced this bug in the first
        # place.
        logger.warning(
            "radius_nas_bridge_deregister_uncorroborated",
            extra={"nas_identifier": nas_identifier},
        )
        raise RadiusNasBridgeDeregistrationError(
            nas_identifier,
            "the RADIUS agent did not confirm how many client stanzas it removed",
        )
    return removed


async def deregister_radius_nas_client(
    service: RadiusService,
    *,
    nas_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None,
    actor_user_id: uuid.UUID | None,
) -> tuple[RadiusNasClient, int]:
    """Removes ``nas_id``'s live entry from the real FreeRADIUS server
    (bridge) *and then* soft-deletes it (DB) -- the one place both halves
    of a NAS's deletion happen together, so every caller (the explicit
    admin endpoint below, and ``app.domains.router.router
    .decommission_router``'s composition of this same function) gets the
    same guarantee, not just one of them.

    Returns the deleted row and the number of hub stanzas removed.

    **Bridge first, database second, and no exception swallowed between
    them.** The previous order (soft-delete, then best-effort bridge call)
    is what let the two sides drift: the DB row disappeared, the bridge
    call 501'd, the warning went to a log nobody reads, and the console
    said "deleted". Doing the revocation first means the only two states
    reachable are "neither happened, and the caller was told why" and
    "both happened". A NAS that is still in the database is still
    visible, still listed, and still deletable on a retry; a NAS that has
    silently kept a live RADIUS credential is none of those things.
    """
    nas_client = await service.get_nas_client(
        nas_id, requesting_organization_id=requesting_organization_id
    )
    removed = await _deregister_nas_from_radius_bridge(nas_client.nas_identifier)
    nas_client = await service.delete_nas(
        nas_id=nas_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=actor_user_id,
    )
    return nas_client, removed


def _device_response(device: GuestDevice) -> dict[str, object]:
    return {
        "id": str(device.id),
        "guest_id": str(device.guest_id),
        "mac_address": device.mac_address,
        "device_name": device.device_name,
        "first_seen_at": device.first_seen_at,
        "last_seen_at": device.last_seen_at,
    }


def _session_response(session: GuestSession) -> GuestSessionResponse:
    return GuestSessionResponse(
        id=str(session.id),
        guest_id=str(session.guest_id),
        device_id=str(session.device_id) if session.device_id else None,
        router_id=str(session.router_id),
        location_id=str(session.location_id),
        organization_id=str(session.organization_id),
        auth_method=session.auth_method,
        voucher_id=str(session.voucher_id) if session.voucher_id else None,
        status=session.status,
        started_at=session.started_at,
        ended_at=session.ended_at,
        last_activity_at=session.last_activity_at,
        ip_address=session.ip_address,
        bytes_uploaded=session.bytes_uploaded,
        bytes_downloaded=session.bytes_downloaded,
        data_limit_mb=session.data_limit_mb,
        session_timeout_minutes=session.session_timeout_minutes,
        disconnect_reason=session.disconnect_reason,
        user_agent=session.user_agent,
        created_at=session.created_at,
    )


def _nas_response(nas_client: RadiusNasClient) -> RadiusNasResponse:
    return RadiusNasResponse(
        id=str(nas_client.id),
        nas_code=nas_client.nas_code,
        router_id=str(nas_client.router_id),
        organization_id=str(nas_client.organization_id),
        location_id=str(nas_client.location_id),
        nas_identifier=nas_client.nas_identifier,
        status=nas_client.status,
        is_active=nas_client.is_active,
        name=nas_client.name,
        description=nas_client.description,
        ip_address=nas_client.ip_address,
        vendor=nas_client.vendor,
        created_at=nas_client.created_at,
        updated_at=nas_client.updated_at,
    )


def _guest_response(guest: Guest) -> GuestResponse:
    return GuestResponse(
        id=str(guest.id),
        organization_id=str(guest.organization_id),
        location_id=str(guest.location_id) if guest.location_id else None,
        identifier=guest.identifier,
        display_name=guest.display_name,
        first_seen_at=guest.first_seen_at,
        last_seen_at=guest.last_seen_at,
        total_visit_count=guest.total_visit_count,
        is_blocked=guest.is_blocked,
        blocked_reason=guest.blocked_reason,
        created_at=guest.created_at,
        updated_at=guest.updated_at,
    )


def _guest_device_response(device: GuestDevice) -> GuestDeviceResponse:
    """Same field set as ``_device_response`` above, wrapped as the real
    ``GuestDeviceResponse`` schema (rather than a bare dict) for ``GET
    /guest-devices``'s own top-level list response."""
    return GuestDeviceResponse(**_device_response(device))


def _login_history_response(entry: GuestLoginHistory) -> GuestLoginHistoryResponse:
    return GuestLoginHistoryResponse(
        id=str(entry.id),
        guest_id=str(entry.guest_id) if entry.guest_id else None,
        organization_id=str(entry.organization_id) if entry.organization_id else None,
        location_id=str(entry.location_id) if entry.location_id else None,
        identifier=entry.identifier,
        auth_method=entry.auth_method,
        success=entry.success,
        failure_reason=entry.failure_reason,
        attempted_at=entry.attempted_at,
        ip_address=entry.ip_address,
        created_at=entry.created_at,
    )


def _login_response(result: GuestLoginResult) -> GuestLoginResponse:
    return GuestLoginResponse(
        guest_id=str(result.guest.id),
        identifier=result.guest.identifier,
        is_new_guest=result.is_new_guest,
        has_password=bool(result.guest.hashed_password),
        has_pin=bool(result.guest.hashed_pin),
        session=_session_response(result.session),
        device=_device_response(result.device) if result.device else None,
    )


# ============================================================================
# Guest-facing endpoints -- no RBAC, see module docstring
# ============================================================================


@guest_router.post(
    "/login/otp",
    response_model=ApiResponse[GuestLoginResponse],
    status_code=status.HTTP_200_OK,
)
async def guest_login_via_otp(
    request: Request,
    payload: GuestOtpLoginRequest,
    service: GuestService = Depends(get_guest_service),
):
    ip_address = payload.ip_address or (request.client.host if request.client else None)
    # BE-012 Part 2: capture the raw User-Agent header at login time -- see
    # app.domains.guest.models.GuestSession.user_agent's docstring for the
    # full "narrow, additive hook" write-up and app.domains.analytics's own
    # honest read-side classification of this value.
    user_agent = request.headers.get("user-agent")
    # BE-012 Part 3: the exact same judgment call, applied to Accept-Language
    # -- see app.domains.guest.models.GuestSession.accept_language's docstring.
    accept_language = request.headers.get("accept-language")
    result = await service.login_via_otp(
        identifier=payload.identifier,
        code=payload.code,
        auth_method=payload.auth_method,
        organization_id=payload.organization_id,
        location_id=payload.location_id,
        router_id=payload.router_id,
        device_mac=payload.device_mac,
        device_name=payload.device_name,
        ip_address=ip_address,
        user_agent=user_agent,
        accept_language=accept_language,
    )
    return build_response(
        success=True,
        message="Guest logged in",
        data=_login_response(result).model_dump(),
        request_id=_request_id(request),
    )


@guest_router.post(
    "/login/voucher",
    response_model=ApiResponse[GuestLoginResponse],
    status_code=status.HTTP_200_OK,
)
async def guest_login_via_voucher(
    request: Request,
    payload: GuestVoucherLoginRequest,
    service: GuestService = Depends(get_guest_service),
):
    ip_address = payload.ip_address or (request.client.host if request.client else None)
    user_agent = request.headers.get("user-agent")
    accept_language = request.headers.get("accept-language")
    result = await service.login_via_voucher(
        code=payload.code,
        identifier=payload.identifier,
        organization_id=payload.organization_id,
        location_id=payload.location_id,
        router_id=payload.router_id,
        device_mac=payload.device_mac,
        device_name=payload.device_name,
        ip_address=ip_address,
        user_agent=user_agent,
        accept_language=accept_language,
    )
    return build_response(
        success=True,
        message="Guest logged in",
        data=_login_response(result).model_dump(),
        request_id=_request_id(request),
    )


@guest_router.post(
    "/login/password",
    response_model=ApiResponse[GuestLoginResponse],
    status_code=status.HTTP_200_OK,
)
async def guest_login_via_password(
    request: Request,
    payload: GuestPasswordLoginRequest,
    service: GuestService = Depends(get_guest_service),
):
    ip_address = payload.ip_address or (request.client.host if request.client else None)
    user_agent = request.headers.get("user-agent")
    accept_language = request.headers.get("accept-language")
    result = await service.login_via_password(
        identifier=payload.identifier,
        password=payload.password,
        organization_id=payload.organization_id,
        location_id=payload.location_id,
        router_id=payload.router_id,
        device_mac=payload.device_mac,
        device_name=payload.device_name,
        ip_address=ip_address,
        user_agent=user_agent,
        accept_language=accept_language,
    )
    return build_response(
        success=True,
        message="Guest logged in",
        data=_login_response(result).model_dump(),
        request_id=_request_id(request),
    )


@guest_router.post(
    "/login/pin",
    response_model=ApiResponse[GuestLoginResponse],
    status_code=status.HTTP_200_OK,
)
async def guest_login_via_pin(
    request: Request,
    payload: GuestPinLoginRequest,
    service: GuestService = Depends(get_guest_service),
):
    ip_address = payload.ip_address or (request.client.host if request.client else None)
    user_agent = request.headers.get("user-agent")
    accept_language = request.headers.get("accept-language")
    result = await service.login_via_pin(
        identifier=payload.identifier,
        pin=payload.pin,
        device_mac=payload.device_mac,
        organization_id=payload.organization_id,
        location_id=payload.location_id,
        router_id=payload.router_id,
        device_name=payload.device_name,
        ip_address=ip_address,
        user_agent=user_agent,
        accept_language=accept_language,
    )
    return build_response(
        success=True,
        message="Guest logged in",
        data=_login_response(result).model_dump(),
        request_id=_request_id(request),
    )


@guest_router.get(
    "/session/active",
    response_model=ApiResponse[GuestLoginResponse],
    status_code=status.HTTP_200_OK,
)
async def guest_active_session(
    request: Request,
    router_id: uuid.UUID = Query(...),
    device_mac: str = Query(...),
    service: GuestService = Depends(get_guest_service),
):
    """Guest-facing, unauthenticated (no RBAC/JWT -- same posture as
    ``/login/*``): lets the captive portal check, on load, whether this
    device already has a live session on this router before ever showing
    a sign-in form. ``data`` is ``null`` (not an error) when there is
    none -- a normal first-time visit."""
    result = await service.get_active_session_for_device(
        router_id=router_id, device_mac=device_mac
    )
    return build_response(
        success=True,
        message="Active session found" if result else "No active session",
        data=_login_response(result).model_dump() if result else None,
        request_id=_request_id(request),
    )


@guest_router.post(
    "/set-password",
    response_model=ApiResponse[GuestSetPasswordResponse],
    status_code=status.HTTP_200_OK,
)
async def guest_set_password(
    request: Request,
    payload: GuestSetPasswordRequest,
    service: GuestService = Depends(get_guest_service),
):
    guest = await service.set_guest_password(
        guest_id=payload.guest_id,
        session_id=payload.session_id,
        password=payload.password,
    )
    return build_response(
        success=True,
        message="Password set",
        data=GuestSetPasswordResponse(
            guest_id=str(guest.id), password_set=True
        ).model_dump(),
        request_id=_request_id(request),
    )


@guest_router.post(
    "/set-pin",
    response_model=ApiResponse[GuestSetPinResponse],
    status_code=status.HTTP_200_OK,
)
async def guest_set_pin(
    request: Request,
    payload: GuestSetPinRequest,
    service: GuestService = Depends(get_guest_service),
):
    guest = await service.set_guest_pin(
        guest_id=payload.guest_id,
        session_id=payload.session_id,
        pin=payload.pin,
    )
    return build_response(
        success=True,
        message="PIN set",
        data=GuestSetPinResponse(guest_id=str(guest.id), pin_set=True).model_dump(),
        request_id=_request_id(request),
    )


@guest_router.post(
    "/profile",
    response_model=ApiResponse[GuestUpdateProfileResponse],
    status_code=status.HTTP_200_OK,
)
async def guest_update_profile(
    request: Request,
    payload: GuestUpdateProfileRequest,
    service: GuestService = Depends(get_guest_service),
):
    guest = await service.update_guest_profile(
        guest_id=payload.guest_id,
        session_id=payload.session_id,
        display_name=payload.display_name,
        email=payload.email,
    )
    return build_response(
        success=True,
        message="Profile updated",
        data=GuestUpdateProfileResponse(
            guest_id=str(guest.id),
            display_name=guest.display_name,
            email=guest.email,
        ).model_dump(),
        request_id=_request_id(request),
    )


@guest_router.post(
    "/session/disconnect",
    response_model=ApiResponse[GuestSessionResponse],
    status_code=status.HTTP_200_OK,
)
async def guest_disconnect_own_session(
    request: Request,
    payload: GuestDisconnectRequest,
    service: GuestService = Depends(get_guest_service),
):
    session = await service.disconnect_own_session(
        guest_id=payload.guest_id,
        session_id=payload.session_id,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Disconnected",
        data=_session_response(session).model_dump(),
        request_id=_request_id(request),
    )


@guest_router.post(
    "/consent",
    response_model=ApiResponse[GuestConsentResponse],
    status_code=status.HTTP_201_CREATED,
)
async def guest_record_consent(
    request: Request,
    payload: GuestConsentRequest,
    service: GuestService = Depends(get_guest_service),
):
    ip_address = payload.ip_address or (request.client.host if request.client else None)
    consent = await service.record_consent(
        guest_id=payload.guest_id,
        captive_portal_config_id=payload.captive_portal_config_id,
        terms_version=payload.terms_version,
        ip_address=ip_address,
    )
    return build_response(
        success=True,
        message="Consent recorded",
        data=GuestConsentResponse(
            id=str(consent.id),
            guest_id=str(consent.guest_id),
            captive_portal_config_id=(
                str(consent.captive_portal_config_id)
                if consent.captive_portal_config_id
                else None
            ),
            consented_at=consent.consented_at,
            terms_version=consent.terms_version,
        ).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Admin-facing endpoints
# ============================================================================


@admin_router.get(
    "/guests",
    response_model=ApiResponse[GuestListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_users.read"))],
)
async def list_guests(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    location_id: uuid.UUID | None = Query(default=None),
    is_blocked: bool | None = Query(default=None),
    search: str | None = Query(default=None, max_length=255),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    guests, meta = await service.list_guests(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        is_blocked=is_blocked,
        search=search,
        page=page,
        page_size=page_size,
    )
    payload = GuestListResponse(
        items=[_guest_response(g) for g in guests],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Guests retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@admin_router.get(
    "/guests/{guest_id}",
    response_model=ApiResponse[GuestDetailResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_users.read"))],
)
async def get_guest(
    request: Request,
    guest_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    guest = await service.get_guest(
        guest_id, requesting_organization_id=requesting_organization_id
    )
    sessions = await service.get_guest_sessions(
        guest_id, requesting_organization_id=requesting_organization_id
    )
    payload = GuestDetailResponse(
        **_guest_response(guest).model_dump(),
        sessions=[_session_response(s) for s in sessions],
    )
    return build_response(
        success=True,
        message="Guest retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@admin_router.post(
    "/guests/{guest_id}/block",
    response_model=ApiResponse[GuestResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_users.update"))],
)
async def block_guest(
    request: Request,
    guest_id: uuid.UUID,
    payload: GuestBlockRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    guest = await service.block_guest(
        actor_user_id=uuid.UUID(user.id),
        guest_id=guest_id,
        requesting_organization_id=requesting_organization_id,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Guest blocked",
        data=_guest_response(guest).model_dump(),
        request_id=_request_id(request),
    )


@admin_router.post(
    "/guests/{guest_id}/unblock",
    response_model=ApiResponse[GuestResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_users.update"))],
)
async def unblock_guest(
    request: Request,
    guest_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    guest = await service.unblock_guest(
        actor_user_id=uuid.UUID(user.id),
        guest_id=guest_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Guest unblocked",
        data=_guest_response(guest).model_dump(),
        request_id=_request_id(request),
    )


@admin_router.get(
    "/guest-sessions",
    response_model=ApiResponse[GuestSessionListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_sessions.read"))],
)
async def list_guest_sessions(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    location_id: uuid.UUID | None = Query(default=None),
    router_id: uuid.UUID | None = Query(default=None),
    guest_id: uuid.UUID | None = Query(default=None),
    status_filter: GuestSessionStatus | None = Query(default=None, alias="status"),
    start_date: datetime | None = Query(
        default=None,
        description=(
            "Real server-side [start_date, end_date) filter on started_at, "
            "for a caller needing a real date-bounded listing (e.g. "
            "cloudguest-foundation's Bandwidth & Cost / Bandwidth by "
            "Location reports) instead of over-fetching the most recent N "
            "sessions and filtering client-side. Requires an organization "
            "context (start_date/end_date are ignored for a platform-level "
            "caller with no organization_id) and, when given, takes the "
            "router_id/guest_id/status filters out of scope -- pass only "
            "location_id alongside it."
        ),
    ),
    end_date: datetime | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    has_real_range = start_date is not None and end_date is not None
    if has_real_range and requesting_organization_id is not None:
        sessions, meta = await service.list_sessions_in_range(
            organization_id=requesting_organization_id,
            location_id=location_id,
            start=start_date,
            end=end_date,
            page=page,
            page_size=page_size,
        )
    else:
        sessions, meta = await service.list_sessions(
            requesting_organization_id=requesting_organization_id,
            location_id=location_id,
            router_id=router_id,
            guest_id=guest_id,
            status=status_filter,
            page=page,
            page_size=page_size,
        )
    payload = GuestSessionListResponse(
        items=[_session_response(s) for s in sessions],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Guest sessions retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@admin_router.get(
    "/guest-devices",
    response_model=ApiResponse[GuestDeviceListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_sessions.read"))],
)
async def list_guest_devices(
    request: Request,
    device_ids: list[uuid.UUID] = Query(
        ...,
        description=(
            "Bulk-resolve up to "
            f"{MAX_BULK_DEVICE_LOOKUP_IDS} device IDs (e.g. a page of "
            "GuestSession.device_id values from a Guest Session Log report) "
            "to their MAC addresses in one call -- avoids the N+1 that "
            "would otherwise result from resolving each session's device "
            "one at a time. An id with no matching device, or one outside "
            "the caller's own organization, is simply absent from the "
            "response rather than an error."
        ),
    ),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    devices = await service.list_devices_by_ids(
        device_ids=device_ids,
        requesting_organization_id=requesting_organization_id,
    )
    payload = GuestDeviceListResponse(
        items=[_guest_device_response(d) for d in devices]
    )
    return build_response(
        success=True,
        message="Guest devices retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@admin_router.get(
    "/guest-login-history",
    response_model=ApiResponse[GuestLoginHistoryListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_sessions.read"))],
)
async def list_guest_login_history(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    location_id: uuid.UUID | None = Query(default=None),
    guest_id: uuid.UUID | None = Query(default=None),
    start_date: datetime | None = Query(
        default=None,
        description=(
            "Real server-side [start_date, end_date) filter on "
            "attempted_at -- the exact same contract as GET "
            "/guest-sessions's own start_date/end_date, for the Login/"
            "Access Attempt Log report. Requires an organization context "
            "(ignored for a platform-level caller with no "
            "organization_id) and, when given, takes the guest_id filter "
            "out of scope -- pass only location_id alongside it."
        ),
    ),
    end_date: datetime | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    has_real_range = start_date is not None and end_date is not None
    if has_real_range and requesting_organization_id is not None:
        entries, meta = await service.list_login_history_in_range(
            organization_id=requesting_organization_id,
            location_id=location_id,
            start=start_date,
            end=end_date,
            page=page,
            page_size=page_size,
        )
    else:
        entries, meta = await service.list_login_history(
            requesting_organization_id=requesting_organization_id,
            location_id=location_id,
            guest_id=guest_id,
            page=page,
            page_size=page_size,
        )
    payload = GuestLoginHistoryListResponse(
        items=[_login_history_response(e) for e in entries],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Guest login history retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@admin_router.get(
    "/guest-sessions/{session_id}",
    response_model=ApiResponse[GuestSessionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_sessions.read"))],
)
async def get_guest_session(
    request: Request,
    session_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    session = await service.get_session(
        session_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Guest session retrieved",
        data=_session_response(session).model_dump(),
        request_id=_request_id(request),
    )


@admin_router.post(
    "/guest-sessions/{session_id}/disconnect",
    response_model=ApiResponse[GuestSessionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_sessions.execute"))],
)
async def disconnect_guest_session(
    request: Request,
    session_id: uuid.UUID,
    payload: SessionDisconnectRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    session = await service.disconnect_session(
        session_id=session_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Guest session disconnected",
        data=_session_response(session).model_dump(),
        request_id=_request_id(request),
    )


@admin_router.post(
    "/guest-sessions/{session_id}/terminate",
    response_model=ApiResponse[GuestSessionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_sessions.execute"))],
)
async def terminate_guest_session(
    request: Request,
    session_id: uuid.UUID,
    payload: SessionTerminateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    session = await service.terminate_session(
        session_id=session_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Guest session terminated",
        data=_session_response(session).model_dump(),
        request_id=_request_id(request),
    )


@admin_router.post(
    "/guest-sessions/{session_id}/pause",
    response_model=ApiResponse[GuestSessionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_sessions.execute"))],
)
async def pause_guest_session(
    request: Request,
    session_id: uuid.UUID,
    payload: SessionPauseRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    session = await service.pause_session(
        session_id=session_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Guest session paused",
        data=_session_response(session).model_dump(),
        request_id=_request_id(request),
    )


@admin_router.post(
    "/guest-sessions/{session_id}/resume",
    response_model=ApiResponse[GuestSessionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_sessions.execute"))],
)
async def resume_guest_session(
    request: Request,
    session_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    session = await service.resume_session(
        session_id=session_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Guest session resumed",
        data=_session_response(session).model_dump(),
        request_id=_request_id(request),
    )


@admin_router.post(
    "/guest-sessions/{session_id}/extend",
    response_model=ApiResponse[GuestSessionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_sessions.execute"))],
)
async def extend_guest_session(
    request: Request,
    session_id: uuid.UUID,
    payload: SessionExtendRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    session = await service.extend_session(
        session_id=session_id,
        additional_minutes=payload.additional_minutes,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Guest session extended",
        data=_session_response(session).model_dump(),
        request_id=_request_id(request),
    )


@admin_router.post(
    "/guests/{guest_id}/reconnect",
    response_model=ApiResponse[GuestSessionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("guest_sessions.execute"))],
)
async def reconnect_guest_session(
    request: Request,
    guest_id: uuid.UUID,
    payload: SessionReconnectRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
    session = await service.reconnect(
        guest_id=guest_id,
        requesting_organization_id=requesting_organization_id,
        router_id=payload.router_id,
        location_id=payload.location_id,
        device_mac=payload.device_mac,
        ip_address=payload.ip_address,
    )
    return build_response(
        success=True,
        message="Guest session reconnected",
        data=_session_response(session).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# NAS admin management endpoints -- ordinary RBAC-gated admin CRUD, see
# schemas.py's own "NAS admin-management schemas" section docstring for why
# these (unlike Authorize/Accounting below) use the standard ApiResponse
# envelope. Mounted under /radius/nas (nas_router) plus two cross-reference
# lookups mounted at their own natural prefixes (nas_cross_reference_router).
# ============================================================================


@nas_router.post(
    "",
    response_model=ApiResponse[RadiusNasCreatedResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("radius.create"))],
)
async def register_radius_nas(
    request: Request,
    payload: RadiusNasRegisterRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RadiusService = Depends(get_radius_service),
):
    result = await service.register_nas(
        actor_user_id=uuid.UUID(user.id),
        router_id=payload.router_id,
        nas_identifier=payload.nas_identifier,
        shared_secret=payload.shared_secret,
        name=payload.name,
        description=payload.description,
        ip_address=payload.ip_address,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="RADIUS NAS client registered",
        data=RadiusNasCreatedResponse(
            **_nas_response(result.nas_client).model_dump(),
            shared_secret=result.shared_secret,
        ).model_dump(),
        request_id=_request_id(request),
    )


@nas_router.post(
    "/register-external/{router_id}",
    response_model=ApiResponse[RadiusNasCreatedResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("radius.create"))],
)
async def register_external_radius_nas(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RadiusService = Depends(get_radius_service),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
):
    """Server-side equivalent of the Master console's Setup Script panel
    previously calling the FreeRADIUS agent bridge directly from the
    browser -- that bridge is a bare ``http.server.BaseHTTPRequestHandler``
    with no CORS/OPTIONS support, so a browser ``fetch()`` to it always
    failed once a custom auth header was involved (confirmed live, same
    root cause as the WireGuard bridge). Creates (or, if one already
    exists for this router, rotates) this router's NAS client, then pushes
    it to the real FreeRADIUS server from here instead -- using the
    router's already-allocated WireGuard tunnel IP as its NAS address,
    which is why this requires a WireGuard peer to exist first."""
    peer = await wireguard_service.get_peer(
        router_id=router_id, requesting_organization_id=requesting_organization_id
    )

    existing, _meta = await service.list_nas_clients(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=1,
        page_size=1,
    )
    if existing:
        result = await service.regenerate_secret(
            nas_id=existing[0].id,
            requesting_organization_id=requesting_organization_id,
            actor_user_id=uuid.UUID(user.id),
        )
    else:
        result = await service.register_nas(
            actor_user_id=uuid.UUID(user.id),
            router_id=router_id,
            nas_identifier=f"cg-{str(router_id)[:8]}",
            requesting_organization_id=requesting_organization_id,
        )

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            _settings = get_settings()
            resp = await client.post(
                _settings.hub_radius_agent_url,
                headers={
                    "X-Agent-Secret": _settings.hub_radius_agent_secret,
                    "Content-Type": "application/json",
                },
                json={
                    "tunnel_ip": peer.tunnel_ip_address,
                    "nas_identifier": result.nas_client.nas_identifier,
                    "secret": result.shared_secret,
                },
            )
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502, detail="Could not reach the RADIUS server bridge"
        ) from exc

    return build_response(
        success=True,
        message="RADIUS NAS client registered",
        data=RadiusNasCreatedResponse(
            **_nas_response(result.nas_client).model_dump(),
            shared_secret=result.shared_secret,
        ).model_dump(),
        request_id=_request_id(request),
    )


@nas_router.get(
    "",
    response_model=ApiResponse[RadiusNasListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("radius.read"))],
)
async def list_radius_nas(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    location_id: uuid.UUID | None = Query(default=None),
    router_id: uuid.UUID | None = Query(default=None),
    status_filter: NasStatus | None = Query(default=None, alias="status"),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RadiusService = Depends(get_radius_service),
):
    nas_clients, meta = await service.list_nas_clients(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        router_id=router_id,
        status=status_filter,
        page=page,
        page_size=page_size,
    )
    payload = RadiusNasListResponse(
        items=[_nas_response(n) for n in nas_clients],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="RADIUS NAS clients retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@nas_router.get(
    "/{nas_id}",
    response_model=ApiResponse[RadiusNasResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("radius.read"))],
)
async def get_radius_nas(
    request: Request,
    nas_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RadiusService = Depends(get_radius_service),
):
    nas_client = await service.get_nas_client(
        nas_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="RADIUS NAS client retrieved",
        data=_nas_response(nas_client).model_dump(),
        request_id=_request_id(request),
    )


@nas_router.put(
    "/{nas_id}",
    response_model=ApiResponse[RadiusNasResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("radius.update"))],
)
async def update_radius_nas(
    request: Request,
    nas_id: uuid.UUID,
    payload: RadiusNasUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RadiusService = Depends(get_radius_service),
):
    nas_client = await service.update_nas_client(
        nas_id=nas_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
        name=payload.name,
        description=payload.description,
        ip_address=payload.ip_address,
    )
    return build_response(
        success=True,
        message="RADIUS NAS client updated",
        data=_nas_response(nas_client).model_dump(),
        request_id=_request_id(request),
    )


@nas_router.delete(
    "/{nas_id}",
    response_model=ApiResponse[RadiusNasResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("radius.delete"))],
)
async def delete_radius_nas(
    request: Request,
    nas_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RadiusService = Depends(get_radius_service),
):
    nas_client, removed = await deregister_radius_nas_client(
        service,
        nas_id=nas_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    # The message states what happened on the RADIUS server, not just in
    # this database. "Deleted" on its own is what an operator saw while
    # the hub silently kept the credential (see
    # ``_deregister_nas_from_radius_bridge``); a bridge failure now never
    # reaches this line at all, and a zero-stanza removal says so rather
    # than reading as a revocation that occurred.
    if removed:
        message = (
            f"RADIUS NAS client deleted and removed from the RADIUS server "
            f"({removed} client stanza{'s' if removed != 1 else ''})"
        )
    else:
        message = (
            "RADIUS NAS client deleted; it had no client stanza on the "
            "RADIUS server to remove"
        )
    return build_response(
        success=True,
        message=message,
        data=_nas_response(nas_client).model_dump(),
        request_id=_request_id(request),
    )


@nas_router.post(
    "/{nas_id}/activate",
    response_model=ApiResponse[RadiusNasResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("radius.execute"))],
)
async def activate_radius_nas(
    request: Request,
    nas_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RadiusService = Depends(get_radius_service),
):
    nas_client = await service.activate_nas(
        nas_id=nas_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="RADIUS NAS client activated",
        data=_nas_response(nas_client).model_dump(),
        request_id=_request_id(request),
    )


@nas_router.post(
    "/{nas_id}/disable",
    response_model=ApiResponse[RadiusNasResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("radius.execute"))],
)
async def disable_radius_nas(
    request: Request,
    nas_id: uuid.UUID,
    payload: RadiusNasDisableRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RadiusService = Depends(get_radius_service),
):
    nas_client = await service.disable_nas(
        nas_id=nas_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="RADIUS NAS client disabled",
        data=_nas_response(nas_client).model_dump(),
        request_id=_request_id(request),
    )


@nas_router.post(
    "/{nas_id}/regenerate-secret",
    response_model=ApiResponse[RadiusNasCreatedResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("radius.execute"))],
)
async def regenerate_radius_nas_secret(
    request: Request,
    nas_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RadiusService = Depends(get_radius_service),
):
    result = await service.regenerate_secret(
        nas_id=nas_id,
        requesting_organization_id=requesting_organization_id,
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="RADIUS NAS client shared secret regenerated",
        data=RadiusNasCreatedResponse(
            **_nas_response(result.nas_client).model_dump(),
            shared_secret=result.shared_secret,
        ).model_dump(),
        request_id=_request_id(request),
    )


@nas_cross_reference_router.get(
    "/locations/{location_id}/nas",
    response_model=ApiResponse[RadiusNasListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("radius.read"))],
)
async def list_radius_nas_for_location(
    request: Request,
    location_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RadiusService = Depends(get_radius_service),
):
    nas_clients, meta = await service.list_nas_clients(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        page=page,
        page_size=page_size,
    )
    payload = RadiusNasListResponse(
        items=[_nas_response(n) for n in nas_clients],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="RADIUS NAS clients retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@nas_cross_reference_router.get(
    "/routers/{router_id}/nas",
    response_model=ApiResponse[RadiusNasResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("radius.read"))],
)
async def get_radius_nas_for_router(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: RadiusService = Depends(get_radius_service),
):
    """A router has at most one NAS (one-to-one, see
    ``models.RadiusNasClient``'s own docstring) -- this returns that single
    object, not a list, even though the module brief's own route shape
    named it ``/routers/{router_id}/nas``."""
    nas_clients, _meta = await service.list_nas_clients(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=1,
        page_size=1,
    )
    if not nas_clients:
        raise RadiusNasNotFoundError(router_id)
    return build_response(
        success=True,
        message="RADIUS NAS client retrieved",
        data=_nas_response(nas_clients[0]).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# RADIUS-facing endpoints -- NAS shared-secret authenticated, see module
# docstring
# ============================================================================


@radius_router.post(
    "/authorize",
    status_code=status.HTTP_200_OK,
)
async def radius_authorize(
    payload: RadiusAuthorizeRequest,
    nas_client=Depends(CurrentNas),
    service: RadiusService = Depends(get_radius_service),
) -> dict:
    """The real MAC-whitelist auto-connect bypass lives here, not a
    separate public endpoint -- see ``RadiusService.authorize``'s
    docstring. ``payload.calling_station_id`` (the NAS-asserted MAC, RFC
    2865 Section 5.31) only ever reaches this call alongside a shared-
    secret-authenticated ``nas_client``, so -- unlike the former
    ``POST /guest/login/mac`` -- a MAC address can never grant access
    here on the strength of an unauthenticated client's own claim.

    This endpoint's only real consumer is FreeRADIUS's own ``rlm_rest``
    module (``mods-enabled/rest``'s ``authorize {}`` block). Confirmed
    live via ``freeradius -X``: rlm_rest's JSON response decoder treats
    every top-level key as a literal RADIUS attribute name
    (``[list:]Attribute-Name``) -- this endpoint's previous plain
    ``{"authorized": true, ...}`` shape has no key rlm_rest recognizes,
    so every field was silently discarded ("Invalid vendor name in
    attribute name 'authorized', skipping..."). With nothing ever
    setting ``control:Auth-Type``, and no local password for FreeRADIUS's
    own ``pap``/``files`` modules to check (this architecture is
    session-lookup, not password verification, by design), FreeRADIUS
    fell through to its own hardcoded default -- "No Auth-Type found:
    rejecting the user" -- an Access-Reject on *every* login, regardless
    of this endpoint's own (correct) accept/reject decision, invisible
    behind an HTTP 200. The wire response below uses rlm_rest's real
    attribute-name convention instead."""
    result = await service.authorize(
        nas_client=nas_client,
        username=payload.username,
        calling_station_id=payload.calling_station_id,
    )
    reply: dict = {
        "control:Auth-Type": "Accept" if result.authorized else "Reject",
    }
    if result.authorized:
        if result.session_timeout_seconds is not None:
            reply["Session-Timeout"] = result.session_timeout_seconds
        if result.rate_limit is not None:
            reply["Mikrotik-Rate-Limit"] = result.rate_limit
        # Without this, RouterOS's hotspot profile (radius-interim-update
        # ="received" -- confirmed live, this platform's own setup script
        # never sets a fixed interval) never sends a single
        # Accounting-Interim-Update for the session's whole lifetime: it
        # only starts that periodic reporting once it's TOLD an interval
        # via this exact reply attribute (RFC 2869 §2.1). Confirmed live:
        # every real GuestSession's bytes_uploaded/bytes_downloaded stayed
        # 0 for the session's entire active lifetime as a direct result --
        # only a final Accounting-Stop (session end) ever carried real
        # totals, so "Reports" showed no usage for any still-active or
        # recently-active guest. 300s balances real-time-enough usage data
        # against accounting request volume at scale.
        reply["Acct-Interim-Interval"] = 300
    return reply


@radius_router.post(
    "/accounting",
    response_model=RadiusAccountingResponse,
    status_code=status.HTTP_200_OK,
)
async def radius_accounting(
    payload: RadiusAccountingRequest,
    nas_client=Depends(CurrentNas),
    service: RadiusService = Depends(get_radius_service),
) -> RadiusAccountingResponse:
    # Accounting-On/Accounting-Off (RFC 2866 §5.13) are NAS-level events --
    # no single session to report on, handled entirely separately from the
    # three session-scoped status types below. See
    # RadiusService.accounting_on/accounting_off's own docstrings.
    if payload.status_type == RADIUS_ACCT_STATUS_ACCOUNTING_ON:
        closed = await service.accounting_on(nas_client=nas_client)
        return RadiusAccountingResponse(
            session_id=None,
            status=payload.status_type,
            closed_session_count=len(closed),
        )
    if payload.status_type == RADIUS_ACCT_STATUS_ACCOUNTING_OFF:
        closed = await service.accounting_off(nas_client=nas_client)
        return RadiusAccountingResponse(
            session_id=None,
            status=payload.status_type,
            closed_session_count=len(closed),
        )

    # payload's own model_validator already guarantees username is set
    # for every status_type reachable below.
    if payload.status_type == RADIUS_ACCT_STATUS_START:
        session = await service.accounting_start(
            nas_client=nas_client, username=payload.username
        )
    elif payload.status_type == RADIUS_ACCT_STATUS_INTERIM_UPDATE:
        session = await service.accounting_interim_update(
            nas_client=nas_client,
            username=payload.username,
            bytes_uploaded_delta=payload.bytes_uploaded_delta,
            bytes_downloaded_delta=payload.bytes_downloaded_delta,
            # A real NAS sends running totals, never deltas -- see
            # ``RadiusService.accounting_interim_update``. The delta
            # fields stay wired up for the non-RADIUS callers that
            # already use them; totals win when both are present.
            bytes_uploaded_total=payload.bytes_uploaded_total,
            bytes_downloaded_total=payload.bytes_downloaded_total,
        )
    elif payload.status_type == RADIUS_ACCT_STATUS_STOP:
        session = await service.accounting_stop(
            nas_client=nas_client,
            username=payload.username,
            bytes_uploaded_total=payload.bytes_uploaded_total,
            bytes_downloaded_total=payload.bytes_downloaded_total,
            disconnect_reason=payload.disconnect_reason,
        )
    else:
        # Previously: silently treated as "stop". Any status_type this
        # module doesn't recognize (RFC 2866 defines several more, e.g.
        # modem-start/modem-stop) must never be handled as if it were a
        # real Accounting-Stop.
        raise RadiusAccountingUnsupportedStatusTypeError(payload.status_type)
    return RadiusAccountingResponse(session_id=str(session.id), status=session.status)


# ============================================================================
# Analytics endpoints
# ============================================================================


@analytics_router.get(
    "/summary",
    response_model=ApiResponse[GuestAnalyticsSummaryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_guest_analytics_summary(
    request: Request,
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    location_id: uuid.UUID | None = Query(default=None),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: GuestAnalyticsService = Depends(get_guest_analytics_service),
):
    summary = await service.get_summary(
        organization_id=organization_id,
        location_id=location_id,
        start=start_date,
        end=end_date,
    )
    return build_response(
        success=True,
        message="Guest analytics summary retrieved",
        data=GuestAnalyticsSummaryResponse(
            visitors=summary.visitors,
            unique_guests=summary.unique_guests,
            returning_guests=summary.returning_guests,
            average_session_duration_seconds=summary.average_session_duration_seconds,
            total_bandwidth_bytes=summary.total_bandwidth_bytes,
        ).model_dump(),
        request_id=_request_id(request),
    )


@analytics_router.get(
    "/top-locations",
    response_model=ApiResponse[TopLocationsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_top_locations(
    request: Request,
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    limit: int = Query(default=10, ge=1, le=100),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: GuestAnalyticsService = Depends(get_guest_analytics_service),
):
    items = await service.get_top_locations(
        organization_id=organization_id, start=start_date, end=end_date, limit=limit
    )
    payload = TopLocationsResponse(
        items=[
            TopLocationItem(
                location_id=str(item.location_id),
                location_name=item.location_name,
                session_count=item.session_count,
            )
            for item in items
        ]
    )
    return build_response(
        success=True,
        message="Top locations retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@analytics_router.get(
    "/top-devices",
    response_model=ApiResponse[TopDevicesResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_top_devices(
    request: Request,
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    limit: int = Query(default=10, ge=1, le=100),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: GuestAnalyticsService = Depends(get_guest_analytics_service),
):
    items = await service.get_top_devices(
        organization_id=organization_id, start=start_date, end=end_date, limit=limit
    )
    payload = TopDevicesResponse(
        items=[
            TopDeviceItem(
                device_id=str(item.device_id),
                mac_address=item.mac_address,
                session_count=item.session_count,
                unique_guest_count=item.unique_guest_count,
            )
            for item in items
        ]
    )
    return build_response(
        success=True,
        message="Top devices retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@analytics_router.get(
    "/otp-success-rate",
    response_model=ApiResponse[OtpSuccessRateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_otp_success_rate(
    request: Request,
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    location_id: uuid.UUID | None = Query(default=None),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: GuestAnalyticsService = Depends(get_guest_analytics_service),
):
    result = await service.get_otp_success_rate(
        organization_id=organization_id,
        location_id=location_id,
        start=start_date,
        end=end_date,
    )
    return build_response(
        success=True,
        message="OTP success rate retrieved",
        data=OtpSuccessRateResponse(
            total_attempts=result.total_attempts,
            successful_attempts=result.successful_attempts,
            success_rate=result.success_rate,
        ).model_dump(),
        request_id=_request_id(request),
    )


@analytics_router.get(
    "/voucher-usage",
    response_model=ApiResponse[VoucherUsageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_voucher_usage(
    request: Request,
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    location_id: uuid.UUID | None = Query(default=None),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: GuestAnalyticsService = Depends(get_guest_analytics_service),
):
    result = await service.get_voucher_usage(
        organization_id=organization_id,
        location_id=location_id,
        start=start_date,
        end=end_date,
    )
    return build_response(
        success=True,
        message="Voucher usage retrieved",
        data=VoucherUsageResponse(
            sessions=result.sessions,
            unique_guests=result.unique_guests,
            total_bandwidth_bytes=result.total_bandwidth_bytes,
        ).model_dump(),
        request_id=_request_id(request),
    )


__all__ = [
    "guest_router",
    "admin_router",
    "radius_router",
    "nas_router",
    "nas_cross_reference_router",
    "analytics_router",
    "deregister_radius_nas_client",
]
