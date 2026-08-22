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
    ChannelPartnerChannelDeliveryResult,
    ChannelPartnerCreateRequest,
    ChannelPartnerListResponse,
    ChannelPartnerResendWelcomeRequest,
    ChannelPartnerResendWelcomeResponse,
    ChannelPartnerResponse,
)
from .service import (
    ChannelPartnerResendResult,
    ChannelPartnerService,
    WelcomeChannelOutcome,
)

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


def _resend_message(result: ChannelPartnerResendResult) -> str:
    """Same "the message reflects the real per-channel outcome" contract
    ``_onboard_message`` above and ``app.domains.billing.router
    ._send_invoice_email_and_build_response`` both hold to.

    The word "resent" appears only for a channel whose send was positively
    verified (``WelcomeChannelOutcome.sent``, not merely "didn't raise" --
    see ``ChannelPartnerService._channel_outcome``). An attempted channel
    that cannot be verified reports the failure, with the recorded reason
    when there is one, so an operator reading only this line is never told
    something went out when it didn't."""
    partner = result.partner
    parts: list[str] = []
    if result.sms.attempted:
        parts.append(
            f"welcome SMS resent to {partner.phone}"
            if result.sms.sent
            else (
                "the welcome SMS could not be sent"
                + (f" ({result.sms.error})" if result.sms.error else "")
            )
        )
    if result.email.attempted:
        parts.append(
            f"welcome email resent to {partner.email}"
            if result.email.sent
            else (
                "the welcome email could not be sent"
                + (f" ({result.email.error})" if result.email.error else "")
            )
        )
    return f"{partner.name}: " + ", ".join(parts)


def _build_channel_result(
    outcome: WelcomeChannelOutcome,
) -> ChannelPartnerChannelDeliveryResult:
    return ChannelPartnerChannelDeliveryResult(
        attempted=outcome.attempted,
        sent=outcome.sent,
        error=outcome.error,
        sent_at=outcome.sent_at,
    )


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
    "/{channel_partner_id}/resend-welcome-message",
    response_model=ApiResponse[ChannelPartnerResendWelcomeResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("channel_partners.manage"))],
)
async def resend_channel_partner_welcome_message(
    request: Request,
    channel_partner_id: uuid.UUID,
    payload: ChannelPartnerResendWelcomeRequest,
    user: AuthUser = Depends(CurrentUser),
    service: ChannelPartnerService = Depends(get_channel_partner_service),
):
    """Re-sends the welcome message for an existing partner, on the
    channels named in the body -- the console's "Send welcome message
    again" action, and the only thing that fixes a partner whose first
    send failed (re-running onboarding would create a duplicate row, and
    against a real GSTIN just ``409``s).

    ``POST .../resend-welcome-message`` matches this codebase's one
    existing resend action, ``app.domains.location.router
    .resend_welcome_email`` (``POST /locations/{id}/resend-welcome-email``,
    gated on ``locations.manage``, re-entering the provisioning service's
    own private ``_send_welcome_email``) -- only pluralised across the two
    channels this domain has. Gated on ``channel_partners.manage``, the
    same permission ``revoke_channel_partner`` below uses and for the same
    reason: this is a mutation with a real-world, un-recallable side effect
    on a third party, not a read. ``.manage`` is also already seeded as the
    module's catch-all for exactly this kind of action (see
    ``app.domains.rbac.seed.MODULE_ACTIONS``'s own comment on
    ``CHANNEL_PARTNERS``); no new permission is introduced.

    Always ``200`` when the partner exists and is active -- a failed or
    unconfigured send is not a failed request, it is reported in the
    per-channel ``sms``/``email`` results (and re-recorded on the row).
    ``sent`` is true only for a verified send; the envelope's ``success``
    never stands in for delivery. ``409`` when the partner is not active,
    or when ``send_email`` is asked for a partner with no email on record;
    ``422`` when neither channel is selected."""
    result = await service.resend_welcome_message(
        channel_partner_id,
        actor_user_id=uuid.UUID(user.id),
        send_sms=payload.send_sms,
        send_email=payload.send_email,
    )
    response_payload = ChannelPartnerResendWelcomeResponse(
        partner=_build_partner_response(result.partner),
        sms=_build_channel_result(result.sms),
        email=_build_channel_result(result.email),
    )
    return build_response(
        success=True,
        message=_resend_message(result),
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
