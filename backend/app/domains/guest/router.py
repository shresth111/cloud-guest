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

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequireOrganization,
    RequirePermission,
)

from .constants import GuestSessionStatus
from .dependencies import (
    CurrentNas,
    get_guest_analytics_service,
    get_guest_service,
    get_radius_service,
)
from .models import Guest, GuestDevice, GuestSession
from .schemas import (
    GuestAnalyticsSummaryResponse,
    GuestBlockRequest,
    GuestConsentRequest,
    GuestConsentResponse,
    GuestDetailResponse,
    GuestListResponse,
    GuestLoginResponse,
    GuestOtpLoginRequest,
    GuestResponse,
    GuestSessionListResponse,
    GuestSessionResponse,
    GuestVoucherLoginRequest,
    OtpSuccessRateResponse,
    RadiusAccountingRequest,
    RadiusAccountingResponse,
    RadiusAuthorizeRequest,
    RadiusAuthorizeResponse,
    RadiusNasRegisterRequest,
    RadiusNasResponse,
    SessionDisconnectRequest,
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
analytics_router = APIRouter(prefix="/guest-analytics", tags=["Guest Analytics"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


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
        created_at=session.created_at,
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


def _login_response(result: GuestLoginResult) -> GuestLoginResponse:
    return GuestLoginResponse(
        guest_id=str(result.guest.id),
        identifier=result.guest.identifier,
        is_new_guest=result.is_new_guest,
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
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: GuestService = Depends(get_guest_service),
):
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
# RADIUS-facing endpoints -- NAS shared-secret authenticated, see module
# docstring
# ============================================================================


@radius_router.post(
    "/nas",
    response_model=ApiResponse[RadiusNasResponse],
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
    nas_client = await service.register_nas(
        actor_user_id=uuid.UUID(user.id),
        router_id=payload.router_id,
        nas_identifier=payload.nas_identifier,
        shared_secret=payload.shared_secret,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="RADIUS NAS client registered",
        data=RadiusNasResponse(
            id=str(nas_client.id),
            router_id=str(nas_client.router_id),
            nas_identifier=nas_client.nas_identifier,
            is_active=nas_client.is_active,
            created_at=nas_client.created_at,
        ).model_dump(),
        request_id=_request_id(request),
    )


@radius_router.post(
    "/authorize",
    response_model=RadiusAuthorizeResponse,
    status_code=status.HTTP_200_OK,
)
async def radius_authorize(
    payload: RadiusAuthorizeRequest,
    nas_client=Depends(CurrentNas),
    service: RadiusService = Depends(get_radius_service),
) -> RadiusAuthorizeResponse:
    result = await service.authorize(nas_client=nas_client, username=payload.username)
    return RadiusAuthorizeResponse(
        authorized=result.authorized,
        session_timeout_seconds=result.session_timeout_seconds,
        data_limit_mb=result.data_limit_mb,
        reply_message="accept" if result.authorized else "reject",
    )


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
    if payload.status_type == "start":
        session = await service.accounting_start(
            nas_client=nas_client, session_id=payload.session_id
        )
    elif payload.status_type == "interim-update":
        session = await service.accounting_interim_update(
            nas_client=nas_client,
            session_id=payload.session_id,
            bytes_uploaded_delta=payload.bytes_uploaded_delta,
            bytes_downloaded_delta=payload.bytes_downloaded_delta,
        )
    else:
        session = await service.accounting_stop(
            nas_client=nas_client,
            session_id=payload.session_id,
            bytes_uploaded_total=payload.bytes_uploaded_total,
            bytes_downloaded_total=payload.bytes_downloaded_total,
            disconnect_reason=payload.disconnect_reason,
        )
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


__all__ = ["guest_router", "admin_router", "radius_router", "analytics_router"]
