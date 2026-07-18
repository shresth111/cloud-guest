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
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.database.constants import SortOrder
from app.domains.rbac.dependencies import RequirePermission

from .constants import OtpPurpose
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
):
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
    organization_id: uuid.UUID | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    service: OtpService = Depends(get_otp_service),
):
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
