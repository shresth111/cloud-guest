"""FastAPI routes for the OTP domain: guest-facing code request/verification,
plus an admin-facing read-only listing endpoint.

**``POST /otp/request``/``POST /otp/verify`` carry no ``RequirePermission``/
``CurrentUser`` dependency at all.** This mirrors
``app.domains.router.router.provisioning_check_in``'s exact justification
(see that module's docstring, §5 of ``docs/router/ROUTER_ARCHITECTURE.md``):
the caller is a guest at a captive portal, who by definition has no
platform-user identity or JWT to present -- there is no RBAC permission a
guest could ever be granted, since RBAC's whole model is platform-user
roles/permissions. Abuse protection here comes entirely from this module's
own rate limiting (``OtpRateLimiter``, per-identifier request throttling)
and per-code attempt lockout (``OtpRequest.max_attempts``), not from an
authorization check that has no meaningful subject to authorize.

**Response envelope: the standard ``ApiResponse``, unlike device-facing
endpoints elsewhere in this codebase.** See ``service.py``'s module
docstring for why: the caller here is the captive-portal *frontend* (a real
web/app client that benefits from a consistent, structured contract),
unlike ``app.domains.router_agent``/``app.domains.wireguard``'s embedded-
device callers.

**``GET /otp/requests`` is an additive, admin-facing endpoint** (the module
brief left it to this module's judgment). It is gated by RBAC's existing
``RequirePermission("otp.read")`` against the already-seeded ``otp.read``
permission key (``app.domains.rbac.seed.MODULE_ACTIONS[PermissionModule.OTP]``
already includes ``READ``) -- genuinely valuable for platform support/audit
visibility into a captive portal's OTP traffic (e.g. "is this location
being spammed", "did this guest's code ever get verified") without granting
any ability to read a code's plaintext or hash, which never leaves
``service.py``.

**``POST /otp/request`` composes ``app.domains.guest``'s admission check.**
Per-property whitelist-only mode (``captive_portal_configs
.whitelist_only_enabled``) has to be enforced before a code is sent, not
only at ``POST /guest/login/otp``: this endpoint spends the venue's own SMS
credit on every hit, and gating only the later call would let anyone on the
street burn it by typing numbers into a page that is open by design. The
check is ``GuestService.check_portal_admission``, reached through the
already-wired ``get_guest_service`` rather than reimplemented here -- the
refusal, its Trusted-Devices reconciliation, and its
``guest_login_history`` record must be the *same* logic the login gate
uses, or the two drift and a venue's refusal list stops meaning one thing.

The same composition, and the same argument, covers the two venue gates
the login path enforces through ``GuestService._require_method_enabled``:
the requested channel's own ``CaptivePortalConfig`` enabled flag
(``otp_sms_enabled``/``otp_email_enabled``/``otp_whatsapp_enabled``) and
Open Hours. Login is *after* this endpoint has already paid for a real
SMS/email/WhatsApp, so a request for a disabled channel -- or one made
while the venue is closed -- would otherwise send a code the login step is
guaranteed to refuse. ``request_otp`` therefore calls
``GuestService.check_otp_request_allowed`` (a public seam over that exact
``_require_method_enabled`` logic, so the two call sites cannot drift)
between the whitelist check and the send: an unconfigured location gets the
same clean 404 the login path gives it, a disabled channel gets
``GuestAuthMethodNotEnabledError`` (403), and a closed venue gets
``VenueClosedError`` (403) -- all with the guest-friendly messages the
portal renders. Callers naming no organization and no location (an
account-level code carries no venue) are unaffected -- no venue, no venue
flags to read.

Direction of the import: ``otp.router`` -> ``guest.dependencies``. The
existing dependency runs ``guest.dependencies`` -> ``otp.dependencies``
(``GuestService`` composes ``OtpService``), and ``otp.dependencies``
imports nothing from ``guest``, so no cycle is closed. This module is a
router; nothing imports it but ``app.main``.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.database.constants import SortOrder
from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.dependencies import get_guest_service
from app.domains.guest.service import GuestService
from app.domains.rbac.dependencies import CurrentOrganization, RequirePermission

from .constants import OtpChannel, OtpPurpose
from .dependencies import get_otp_service
from .models import OtpRequest
from .schemas import (
    OtpRequestAdminResponse,
    OtpRequestCreate,
    OtpRequestListResponse,
    OtpRequestResponse,
    OtpVerifyRequest,
    OtpVerifyResponse,
)
from .service import OtpService

router = APIRouter(prefix="/otp", tags=["OTP"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _request_response(otp_request: OtpRequest) -> OtpRequestResponse:
    return OtpRequestResponse(
        id=str(otp_request.id),
        identifier=otp_request.identifier,
        channel=otp_request.channel,
        purpose=otp_request.purpose,
        expires_at=otp_request.expires_at,
        created_at=otp_request.created_at,
    )


def _verify_response(otp_request: OtpRequest) -> OtpVerifyResponse:
    assert otp_request.verified_at is not None  # guaranteed by verify_otp on success
    return OtpVerifyResponse(
        id=str(otp_request.id),
        identifier=otp_request.identifier,
        purpose=otp_request.purpose,
        verified_at=otp_request.verified_at,
    )


#: ``OtpChannel`` -> the ``GuestAuthMethod`` a login through that channel
#: would eventually be recorded as.
#:
#: Needed because a refusal at ``POST /otp/request`` is written to
#: ``guest_login_history`` through the same failure path a refusal at
#: ``POST /guest/login/otp`` uses, and that table records an auth method.
#: Mapping here rather than defaulting everything to ``OTP_SMS`` keeps a
#: venue's refusal list honest about *how* each person tried to sign in --
#: an operator whose email-OTP guests are all being turned away has a
#: different problem from one whose SMS guests are.
_CHANNEL_TO_AUTH_METHOD: dict[OtpChannel, GuestAuthMethod] = {
    OtpChannel.SMS: GuestAuthMethod.OTP_SMS,
    OtpChannel.EMAIL: GuestAuthMethod.OTP_EMAIL,
    OtpChannel.WHATSAPP: GuestAuthMethod.OTP_WHATSAPP,
}


def _admin_response(otp_request: OtpRequest) -> OtpRequestAdminResponse:
    return OtpRequestAdminResponse(
        id=str(otp_request.id),
        identifier=otp_request.identifier,
        channel=otp_request.channel,
        purpose=otp_request.purpose,
        expires_at=otp_request.expires_at,
        verified_at=otp_request.verified_at,
        attempt_count=otp_request.attempt_count,
        max_attempts=otp_request.max_attempts,
        is_consumed=otp_request.is_consumed,
        organization_id=str(otp_request.organization_id)
        if otp_request.organization_id
        else None,
        location_id=str(otp_request.location_id) if otp_request.location_id else None,
        created_at=otp_request.created_at,
        updated_at=otp_request.updated_at,
    )


# ============================================================================
# Guest-facing endpoints -- no RBAC, see module docstring
# ============================================================================


@router.post(
    "/request",
    response_model=ApiResponse[OtpRequestResponse],
    status_code=status.HTTP_201_CREATED,
)
async def request_otp(
    request: Request,
    payload: OtpRequestCreate,
    service: OtpService = Depends(get_otp_service),
    guest_service: GuestService = Depends(get_guest_service),
):
    # Whitelist-only mode is enforced *here*, before a code is generated
    # and before a provider is paid, not only at `POST /guest/login/otp`.
    #
    # This endpoint is the first thing a captive portal calls and it spends
    # real money on every hit. A property that admits only listed guests but
    # gates only the login call would send a real SMS to anyone on the
    # street who types a number in, and refuse them afterwards -- the
    # owner's bill, and a way to drain their SMS credit at will. It is also
    # kinder: someone who is not on the list learns it now rather than while
    # waiting for a code that cannot help them.
    #
    # `check_portal_admission` is a no-op at every property that has not
    # switched the feature on, and at every caller that names no property at
    # all (an account-level code carries no venue). See its own docstring.
    await guest_service.check_portal_admission(
        identifier=payload.identifier,
        auth_method=_CHANNEL_TO_AUTH_METHOD[payload.channel],
        organization_id=payload.organization_id,
        location_id=payload.location_id,
    )
    # The venue gates the login path enforces are *also* enforced here,
    # before a code is generated and a provider is paid -- the same way
    # whitelist-only mode is, and for the same reason (see the block
    # above). The login step's `GuestService._require_method_enabled`/
    # `_require_venue_open` gates fire only *after* this endpoint has spent
    # the venue's money: a request for a channel the venue disabled in its
    # `CaptivePortalConfig`, or made while the venue is closed, would
    # deliver a real SMS/email/WhatsApp that the login step is guaranteed to
    # refuse. Refusing here instead means the venue never pays for a send
    # that cannot succeed, and the guest is told now rather than while
    # waiting for a code that cannot help them.
    #
    # `check_otp_request_allowed` reuses the exact `_require_method_enabled`
    # logic the login paths call (config resolution, per-channel enabled
    # flag, Open Hours -- 404/403 with the same guest-friendly messages), so
    # the request-time and login-time gates cannot drift. It is a no-op for
    # callers that name no organization and no location (an account-level
    # code carries no venue), and unconfigured locations get the same clean
    # 404 login gives them, not a 500.
    await guest_service.check_otp_request_allowed(
        auth_method=_CHANNEL_TO_AUTH_METHOD[payload.channel],
        organization_id=payload.organization_id,
        location_id=payload.location_id,
    )
    otp_request = await service.request_otp(
        identifier=payload.identifier,
        channel=payload.channel,
        purpose=payload.purpose,
        organization_id=payload.organization_id,
        location_id=payload.location_id,
    )
    return build_response(
        success=True,
        message=f"Verification code sent via {payload.channel.value}",
        data=_request_response(otp_request).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/verify",
    response_model=ApiResponse[OtpVerifyResponse],
    status_code=status.HTTP_200_OK,
)
async def verify_otp(
    request: Request,
    payload: OtpVerifyRequest,
    service: OtpService = Depends(get_otp_service),
):
    otp_request = await service.verify_otp(
        identifier=payload.identifier,
        code=payload.code,
        purpose=payload.purpose,
    )
    return build_response(
        success=True,
        message="Verification code accepted",
        data=_verify_response(otp_request).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Admin-facing endpoint
# ============================================================================


@router.get(
    "/requests",
    response_model=ApiResponse[OtpRequestListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("otp.read"))],
)
async def list_otp_requests(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    identifier: str | None = Query(default=None, max_length=255),
    purpose: OtpPurpose | None = Query(default=None),
    organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_id: uuid.UUID | None = Query(default=None),
    service: OtpService = Depends(get_otp_service),
):
    # Tenant scoping: the effective organization is resolved from the caller's
    # auth scope (``CurrentOrganization``), never a client-supplied query param.
    # Previously ``organization_id`` came from the query string while the RBAC
    # permission check derived scope from the ``X-Organization-Id`` header -- so
    # an org-scoped admin who sent the header (passing the org-scoped
    # ``otp.read`` check) but omitted ``?organization_id=`` had the org filter
    # silently dropped and read every organization's OTP requests (guest
    # identifiers -- PII -- across tenants). Resolving it from the same header
    # the permission check uses closes that gap; a non-GLOBAL caller can only
    # ever resolve to an org they are an active member of, and a caller reaching
    # this handler with ``organization_id is None`` passed the GLOBAL-scope
    # permission gate and may legitimately read across organizations.
    filters: dict[str, object] = {
        "identifier": identifier,
        "purpose": purpose.value if purpose else None,
        "organization_id": organization_id,
        "location_id": location_id,
    }
    otp_requests, meta = await service.repository.list_requests(
        page=page,
        page_size=page_size,
        filters={k: v for k, v in filters.items() if v is not None} or None,
        sort_order=SortOrder.DESC,
    )
    payload = OtpRequestListResponse(
        items=[_admin_response(item) for item in otp_requests],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="OTP requests retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
