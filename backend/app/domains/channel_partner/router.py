"""FastAPI routes for the Channel Partner domain.

Every endpoint is Master-console-only and RBAC-gated by
``RequirePermission`` against ``channel_partners.*``
(``app.domains.rbac.seed.MODULE_ACTIONS[PermissionModule.CHANNEL_PARTNERS]``,
seeded at ``ScopeType.GLOBAL`` -- a channel partner belongs to no
organization, see ``models.py``'s own module docstring) -- mirrors
``app.domains.quotation.router``'s identical RBAC-gated, Master-console-
only, no-public-endpoint pattern.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import CurrentUser, RequirePermission

from .dependencies import get_channel_partner_service
from .models import ChannelPartner
from .schemas import (
    ChannelPartnerCreateRequest,
    ChannelPartnerListResponse,
    ChannelPartnerResponse,
)
from .service import ChannelPartnerService

router = APIRouter(prefix="/channel-partners", tags=["Channel Partners"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _build_partner_response(partner: ChannelPartner) -> ChannelPartnerResponse:
    return ChannelPartnerResponse.model_validate(partner)


def _onboard_message(partner: ChannelPartner) -> str:
    """Conditional phrasing mirroring
    ``app.domains.quotation.router.create_and_send_quotation``'s own
    "always 201s, message reflects the real per-channel outcome" pattern
    -- see the API contract's own documented copy in the feature spec."""
    sms_ok = partner.welcome_sms_error is None
    email_provided = partner.email is not None
    email_ok = email_provided and partner.welcome_email_error is None

    if sms_ok:
        message = f"{partner.name} onboarded — welcome SMS sent to {partner.phone}"
        if email_provided:
            message += (
                f" and email sent to {partner.email}"
                if email_ok
                else ", but the welcome email could not be sent"
            )
        return message

    message = f"{partner.name} onboarded, but the welcome SMS could not be sent"
    if email_provided:
        message += (
            f"; email sent to {partner.email}"
            if email_ok
            else " and the welcome email could not be sent either"
        )
    return message


@router.post(
    "",
    response_model=ApiResponse[ChannelPartnerResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("channel_partners.create"))],
)
async def onboard_channel_partner(
    request: Request,
    payload: ChannelPartnerCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    service: ChannelPartnerService = Depends(get_channel_partner_service),
):
    """Onboards a channel partner and sends its welcome message (SMS
    always, email when provided) in one step. Always returns ``201`` with
    the created partner -- a failed or unconfigured send never fails this
    request, it is reflected in the returned ``welcome_sms_error``/
    ``welcome_email_error`` fields instead (see
    ``service.ChannelPartnerService``'s own docstring)."""
    partner = await service.onboard_partner(
        actor_user_id=uuid.UUID(user.id), data=payload
    )
    response_payload = _build_partner_response(partner)
    return build_response(
        success=True,
        message=_onboard_message(partner),
        data=response_payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[ChannelPartnerListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("channel_partners.read"))],
)
async def list_channel_partners(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    partner_status: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None),
    service: ChannelPartnerService = Depends(get_channel_partner_service),
):
    result = await service.list_partners(
        page=page, page_size=page_size, status=partner_status, search=search
    )
    payload = ChannelPartnerListResponse(
        items=[_build_partner_response(partner) for partner in result.items],
        page=result.meta.page,
        page_size=result.meta.page_size,
        total_items=result.meta.total_items,
        total_pages=result.meta.total_pages,
        has_next=result.meta.has_next,
        has_previous=result.meta.has_previous,
    )
    return build_response(
        success=True,
        message="Channel partners retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/{channel_partner_id}",
    response_model=ApiResponse[ChannelPartnerResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("channel_partners.read"))],
)
async def get_channel_partner(
    request: Request,
    channel_partner_id: uuid.UUID,
    service: ChannelPartnerService = Depends(get_channel_partner_service),
):
    partner = await service.get_partner(channel_partner_id)
    response_payload = _build_partner_response(partner)
    return build_response(
        success=True,
        message="Channel partner retrieved",
        data=response_payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/{channel_partner_id}/revoke",
    response_model=ApiResponse[ChannelPartnerResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("channel_partners.manage"))],
)
async def revoke_channel_partner(
    request: Request,
    channel_partner_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    service: ChannelPartnerService = Depends(get_channel_partner_service),
):
    """Deactivates a channel partner -- ``POST .../revoke`` matches this
    codebase's own established status-transition shape
    (``app.domains.organization.router``'s ``.../suspend``/``.../activate``,
    ``app.domains.voucher.router``'s ``.../revoke``), gated behind
    ``channel_partners.manage`` (a mutation, not the ``.read`` permission
    listing/viewing a partner only requires). Idempotent -- see
    ``ChannelPartnerService.revoke_partner``'s own docstring -- so revoking
    an already-inactive partner is a ``200`` no-op, never an error."""
    partner = await service.revoke_partner(
        channel_partner_id, actor_user_id=uuid.UUID(user.id)
    )
    response_payload = _build_partner_response(partner)
    return build_response(
        success=True,
        message=f"Channel partner '{partner.name}' revoked",
        data=response_payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["router"]
