"""Batch B6: Marketing / Guest Messaging twins (ADDENDUM_04 §3 Engagement).

The customer's own Marketing page is mounted unchanged in the partner
console; its ``/marketing/*`` calls reach these twins through the shim's
prefix rewrite. Every row re-declares the original's gates:
``RequireFeature(GUEST_MARKETING)`` (plus ``GUEST_MARKETING_BYO`` on the
provider routes) and ``_PAID_WRITES`` -- evaluated against the CUSTOMER, so
nothing works until the add-on is on for that customer, which the ISP can do
only inside Master's allowance (``isp_addons``).

WHAT DIFFERS FROM A PLAIN TWIN
------------------------------
* The originals take ``scope: CallerScope`` (org + location + actor). The
  twin supplies it from the resolved ``X-Isp-Location-Id`` via
  ``isp_marketing_scope`` (a ``deps`` provider), never from the request body.
* **F1 wallet.** ``schedule`` and ``test-send`` get the marketing service
  through ``funded_marketing_service``, which first moves the shortfall from
  the ISP's one credit wallet to the customer's (``parity_settings.
  fund_customer``) -- 402 ``ISP_WALLET_EMPTY`` before anything is reserved.
* **F3 sender.** Provider WRITES at a venue are allowed only for a customer
  the ISP switched to its own sender (``isp_customer_messaging``); otherwise
  the ISP-level sender is used and these return 403 ``ISP_SENDER_IS_ISP_LEVEL``
  (manage it under ``/isp/messaging/providers``).
* ``/marketing/credits`` answers with the customer's wallet PLUS the ISP pool
  (``venue_marketing_credits``), because that is what a send can draw on.
"""

from __future__ import annotations

import hashlib
import inspect
import uuid
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.billing import credits_router as credit_routes
from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.credits_dependencies import get_credits_service
from app.domains.marketing import router as mk
from app.domains.marketing import schemas as ms
from app.domains.marketing.constants import Channel, TemplateCategory
from app.domains.marketing.dependencies import (
    get_marketing_service,
    get_provider_service,
)
from app.domains.marketing.service import CallerScope
from app.domains.rbac.dependencies import CurrentUser

from .constants import (
    ISP_ENGAGE_CREATE,
    ISP_ENGAGE_DELETE,
    ISP_ENGAGE_MANAGE,
    ISP_ENGAGE_READ,
    ISP_ENGAGE_UPDATE,
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspBadRequestError, IspError
from .http import ok
from .scoping import IspScope
from .twin_body import BodyId
from .twin_gates import enforce_customer_gates, get_twin_entitlement_checker
from .twin_headers import HEADER_LOCATION
from .twins import Param, TwinSpec

__all__ = [
    "MARKETING_TWINS",
    "funded_marketing_service",
    "isp_marketing_scope",
    "venue_marketing_router",
]


class IspSenderIsIspLevelError(IspError):
    code = "ISP_SENDER_IS_ISP_LEVEL"
    status_code_default = status.HTTP_403_FORBIDDEN
    default_message = (
        "This customer uses your ISP-level sender. Change it under Messaging "
        "settings, or switch this customer to its own sender first."
    )


async def _header_location(request: Request, isp: IspContext) -> Any:
    raw = request.headers.get(HEADER_LOCATION)
    if not raw:
        raise IspBadRequestError(f"{HEADER_LOCATION} is required")
    try:
        location_id = uuid.UUID(raw)
    except ValueError:
        raise IspBadRequestError(f"{HEADER_LOCATION} is not a valid id") from None
    return await IspScope.assert_location(isp, location_id)


async def isp_marketing_scope(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    user: AuthUser = Depends(CurrentUser),
) -> CallerScope:
    """The original's ``CallerScope``: the pinned venue's customer + venue."""
    location = await _header_location(request, isp)
    return CallerScope(
        organization_id=location.organization_id,
        location_id=location.id,
        actor_user_id=uuid.UUID(str(user.id)),
    )


async def isp_marketing_scope_own_sender(
    request: Request,
    scope: CallerScope = Depends(isp_marketing_scope),
    db: AsyncSession = Depends(get_db_session),
) -> CallerScope:
    """Provider writes at a venue: only for a customer on its own sender."""
    from .parity_settings import own_sender

    if not await own_sender(db, scope.organization_id):
        raise IspSenderIsIspLevelError()
    return scope


async def funded_marketing_service(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    scope: CallerScope = Depends(isp_marketing_scope),
    service: Any = Depends(get_marketing_service),
    db: AsyncSession = Depends(get_db_session),
) -> Any:
    """F1: before schedule / test-send, move what this send may cost (minus
    what the customer already holds) from the ISP wallet to the customer's."""
    from .parity_settings import fund_customer

    campaign_id = uuid.UUID(str(request.path_params["campaign_id"]))
    estimate = await service.estimate(scope, campaign_id)
    body: dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - schedule with no body is the handler's 422
        body = {}
    if request.url.path.endswith("/test-send"):
        recipients = len(body.get("to") or []) if isinstance(body, dict) else 0
        needed = (
            int(estimate.get("unit_price_minor") or 0)
            * int(estimate.get("units_per_recipient_max") or 0)
            * recipients
        )
        key_src = f"test:{campaign_id}:{request.headers.get('X-Request-ID', '')}:{body}"
    else:
        needed = int(estimate.get("estimated_max_minor") or 0)
        key_src = f"schedule:{campaign_id}:{body.get('idempotency_key', '')}"
    await fund_customer(
        db,
        isp_org_id=isp.isp_org_id,
        customer_org_id=scope.organization_id,
        needed_minor=needed,
        idempotency_key="isp-fund:" + hashlib.sha256(key_src.encode()).hexdigest()[:32],
        actor_user_id=scope.actor_user_id,
    )
    return service


def _response(response: Response) -> Response:
    return response


# -- rows -----------------------------------------------------------------------

_MK = (PlanFeatureKey.GUEST_MARKETING,)
_BYO = (PlanFeatureKey.GUEST_MARKETING, PlanFeatureKey.GUEST_MARKETING_BYO)
_Page = Param("page", "query", int, 1)
_TemplateId = Param("template_id", "path", uuid.UUID)
_CampaignId = Param("campaign_id", "path", uuid.UUID)
_ChannelP = Param("channel", "path", Channel)
_Q = "query"


def _body(model: Any, default: Any = inspect.Parameter.empty) -> Param:
    return Param("body", "body", model, default)


def _row(
    method: str,
    path: str,
    key: str,
    handler: Any,
    *,
    params: tuple[Param, ...] = (),
    features: tuple[Any, ...] = _MK,
    body_ids: tuple[BodyId, ...] = (),
    service: Any = get_marketing_service,
    scope: Any = isp_marketing_scope,
    inject: dict[str, tuple[str, ...]] | None = None,
    extra_deps: dict[str, Any] | None = None,
    status_code: int | None = None,
) -> TwinSpec:
    return TwinSpec(
        method=method,
        path=f"/venue/marketing{path}",
        permission_key=key,
        handler=handler,
        target="header_location",
        params=params,
        requires_features=features,
        body_ids=body_ids,
        deps={"scope": scope, "service": service, **(extra_deps or {})},
        inject=inject or {},
        status_code=status_code,
    )


_LOC = {"location_id": ("location",)}

MARKETING_TWINS: tuple[TwinSpec, ...] = (
    _row("GET", "/status", ISP_ENGAGE_READ, mk.marketing_status),
    _row(
        "PUT",
        "/portal-consent",
        ISP_ENGAGE_UPDATE,
        mk.update_portal_consent,
        params=(_body(ms.PortalConsentUpdate),),
        body_ids=(BodyId("location_id", "force_location", param="body"),),
    ),
    _row(
        "GET",
        "/contacts",
        ISP_ENGAGE_READ,
        mk.list_contacts,
        params=(
            Param("channel", _Q, Channel),
            Param("consent_status", _Q, str, "opted_in"),
            Param("search", _Q, str | None, None),
            _Page,
            Param("page_size", _Q, int, 25),
        ),
        inject=_LOC,
    ),
    _row(
        "POST",
        "/contacts/{guest_id}/opt-out",
        ISP_ENGAGE_UPDATE,
        mk.staff_opt_out,
        params=(Param("guest_id", "path", uuid.UUID), _body(ms.StaffOptOutRequest)),
    ),
    _row(
        "POST",
        "/audience/preview",
        ISP_ENGAGE_READ,
        mk.audience_preview,
        params=(_body(ms.AudienceFilter),),
        # Locations are filtered inside the customer org by the service; a
        # foreign location id matches no guest of this customer.
        body_ids=(BodyId("location_ids", "opaque", param="body"),),
    ),
    _row(
        "GET",
        "/templates",
        ISP_ENGAGE_READ,
        mk.list_templates,
        params=(
            Param("channel", _Q, Channel | None, None),
            Param("category", _Q, TemplateCategory | None, None),
            Param("include_system", _Q, bool, True),
            _Page,
            Param("page_size", _Q, int, 50),
        ),
    ),
    _row(
        "POST",
        "/templates/preview",
        ISP_ENGAGE_READ,
        mk.preview_template,
        params=(_body(ms.TemplatePreviewRequest),),
        body_ids=(
            BodyId("template_id", "opaque", param="body"),
            BodyId("location_id", "force_location", param="body"),
        ),
    ),
    _row(
        "GET",
        "/templates/{template_id}",
        ISP_ENGAGE_READ,
        mk.get_template,
        params=(_TemplateId,),
    ),
    _row(
        "POST",
        "/templates",
        ISP_ENGAGE_CREATE,
        mk.create_template,
        params=(_body(ms.TemplateCreate),),
        status_code=201,
    ),
    _row(
        "PATCH",
        "/templates/{template_id}",
        ISP_ENGAGE_UPDATE,
        mk.update_template,
        params=(_TemplateId, _body(ms.TemplateUpdate)),
    ),
    _row(
        "DELETE",
        "/templates/{template_id}",
        ISP_ENGAGE_DELETE,
        mk.delete_template,
        params=(_TemplateId,),
    ),
    _row(
        "POST",
        "/templates/{template_id}/duplicate",
        ISP_ENGAGE_CREATE,
        mk.duplicate_template,
        params=(_TemplateId, _body(ms.TemplateDuplicate)),
        status_code=201,
    ),
    _row(
        "GET",
        "/campaigns",
        ISP_ENGAGE_READ,
        mk.list_campaigns,
        params=(
            Param("status_filter", _Q, str | None, None),
            Param("channel", _Q, Channel | None, None),
            Param("search", _Q, str | None, None),
            _Page,
            Param("page_size", _Q, int, 25),
        ),
        inject=_LOC,
    ),
    _row(
        "POST",
        "/campaigns",
        ISP_ENGAGE_CREATE,
        mk.create_campaign,
        params=(_body(ms.CampaignCreate),),
        body_ids=(
            BodyId("template_id", "opaque", param="body"),
            BodyId("location_id", "force_location", param="body"),
        ),
        status_code=201,
    ),
    _row(
        "GET",
        "/campaigns/{campaign_id}",
        ISP_ENGAGE_READ,
        mk.get_campaign,
        params=(_CampaignId,),
    ),
    _row(
        "GET",
        "/campaigns/{campaign_id}/estimate",
        ISP_ENGAGE_READ,
        mk.estimate_campaign,
        params=(_CampaignId,),
    ),
    _row(
        "PATCH",
        "/campaigns/{campaign_id}",
        ISP_ENGAGE_UPDATE,
        mk.update_campaign,
        params=(_CampaignId, _body(ms.CampaignUpdate)),
        body_ids=(
            BodyId("template_id", "opaque", param="body"),
            BodyId("location_id", "force_location", param="body"),
        ),
    ),
    _row(
        "DELETE",
        "/campaigns/{campaign_id}",
        ISP_ENGAGE_DELETE,
        mk.delete_campaign,
        params=(_CampaignId,),
    ),
    _row(
        "POST",
        "/campaigns/{campaign_id}/test-send",
        ISP_ENGAGE_MANAGE,
        mk.test_send,
        params=(_CampaignId, _body(ms.TestSendRequest)),
        service=funded_marketing_service,
    ),
    _row(
        "POST",
        "/campaigns/{campaign_id}/schedule",
        ISP_ENGAGE_MANAGE,
        mk.schedule_campaign,
        params=(_CampaignId, _body(ms.ScheduleRequest)),
        service=funded_marketing_service,
    ),
    _row(
        "POST",
        "/campaigns/{campaign_id}/unschedule",
        ISP_ENGAGE_MANAGE,
        mk.unschedule_campaign,
        params=(_CampaignId,),
    ),
    _row(
        "POST",
        "/campaigns/{campaign_id}/cancel",
        ISP_ENGAGE_MANAGE,
        mk.cancel_campaign,
        params=(_CampaignId, _body(ms.EmptyRequest | None, None)),
    ),
    _row(
        "GET",
        "/campaigns/{campaign_id}/recipients",
        ISP_ENGAGE_READ,
        mk.list_recipients,
        params=(
            _CampaignId,
            Param("status_filter", _Q, str | None, None),
            _Page,
            Param("page_size", _Q, int, 25),
        ),
    ),
    _row(
        "GET",
        "/deliveries",
        ISP_ENGAGE_READ,
        mk.list_deliveries,
        params=(
            Param("channel", _Q, Channel | None, None),
            Param("status_filter", _Q, str | None, None),
            Param("campaign_id", _Q, uuid.UUID | None, None),
            Param("date_from", _Q, date | None, None),
            Param("date_to", _Q, date | None, None),
            _Page,
            Param("page_size", _Q, int, 25),
        ),
        inject=_LOC,
    ),
    # -- own-sender providers at a venue (F3 override customers only for writes)
    _row(
        "GET",
        "/providers",
        ISP_ENGAGE_READ,
        mk.list_providers,
        features=_BYO,
        service=get_provider_service,
    ),
    _row(
        "POST",
        "/providers/whatsapp/sync-templates",
        ISP_ENGAGE_MANAGE,
        mk.sync_whatsapp_templates,
        params=(_body(ms.EmptyRequest | None, None),),
        features=_BYO,
        service=get_provider_service,
    ),
    _row(
        "GET",
        "/providers/{channel}",
        ISP_ENGAGE_READ,
        mk.get_provider,
        params=(_ChannelP,),
        features=_BYO,
        service=get_provider_service,
    ),
    _row(
        "PUT",
        "/providers/{channel}",
        ISP_ENGAGE_MANAGE,
        mk.put_provider,
        params=(_ChannelP, _body(ms.ProviderPutRequest)),
        features=_BYO,
        service=get_provider_service,
        scope=isp_marketing_scope_own_sender,
        extra_deps={"response": _response},
    ),
    _row(
        "DELETE",
        "/providers/{channel}",
        ISP_ENGAGE_MANAGE,
        mk.delete_provider,
        params=(_ChannelP,),
        features=_BYO,
        service=get_provider_service,
        scope=isp_marketing_scope_own_sender,
    ),
    _row(
        "POST",
        "/providers/{channel}/verify",
        ISP_ENGAGE_MANAGE,
        mk.verify_provider,
        params=(_ChannelP, _body(ms.ProviderVerifyRequest)),
        body_ids=(BodyId("template_id", "opaque", param="body"),),
        features=_BYO,
        service=get_provider_service,
        scope=isp_marketing_scope_own_sender,
    ),
    # -- credits ledger (the customer's own wallet; the pool view is below)
    TwinSpec(
        method="GET",
        path="/venue/marketing/credits/ledger",
        permission_key=ISP_ENGAGE_READ,
        handler=credit_routes.list_marketing_credit_ledger,
        target="header_location",
        requires_features=_MK,
        params=(
            Param("entry_type", _Q, str | None, None),
            Param("campaign_id", _Q, uuid.UUID | None, None),
            Param("date_from", _Q, date | None, None),
            Param("date_to", _Q, date | None, None),
            Param("detail", _Q, str | None, None),
            _Page,
            Param("page_size", _Q, int, 25),
        ),
        deps={"service": get_credits_service},
        inject={"organization_id": ("org",)},
    ),
)


# The customer pages ask "what is my organization entitled to?" to decide
# which add-on screens to unlock (Marketing, Traffic Lens records). The venue
# answer is the pinned CUSTOMER's entitlements -- the same read the original
# gives a customer user, never the ISP's own.
from app.domains.feature_entitlement import router as fe_routes  # noqa: E402
from app.domains.feature_entitlement.dependencies import (  # noqa: E402
    get_feature_entitlement_service,
)

from .constants import ISP_PARTNER_READ  # noqa: E402

ENTITLEMENT_TWINS: tuple[TwinSpec, ...] = (
    TwinSpec(
        method="GET",
        path="/venue/me/entitlements",
        permission_key=ISP_PARTNER_READ,
        handler=fe_routes.get_my_entitlements,
        target="header_location",
        deps={"service": get_feature_entitlement_service},
        inject={"organization_id": ("org",), "user": ("user",)},
    ),
)

MARKETING_TWINS = MARKETING_TWINS + ENTITLEMENT_TWINS

# -- the credits view: customer wallet + the ISP pool -------------------------

venue_marketing_router = APIRouter(tags=["ISP Partner: venue marketing"])


@venue_marketing_router.get(
    "/venue/marketing/credits", dependencies=isp_guards(ISP_ENGAGE_READ)
)
async def venue_marketing_credits(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    service: Any = Depends(get_credits_service),
    db: AsyncSession = Depends(get_db_session),
    checker: Any = Depends(get_twin_entitlement_checker),
):
    """The original ``/marketing/credits`` body for the customer, with
    ``available_minor`` = what the customer holds + the ISP pool (what a send
    can draw on), and both parts reported separately."""
    from app.domains.billing.credits_constants import CreditBucket
    from app.domains.billing.credits_repository import CreditRepository
    from app.domains.billing.credits_service import wallet_summary

    location = await _header_location(request, isp)
    await enforce_customer_gates(
        checker, location.organization_id, method="GET", paid_write=False, features=_MK
    )
    body = await service.customer_balance(location.organization_id)
    pool = wallet_summary(
        await CreditRepository(db).get_wallet(
            isp.isp_org_id, CreditBucket.MARKETING.value
        )
    )
    held = body.get("available_minor", 0)
    body = {
        **body,
        "available_minor": held + pool["available_minor"],
        "customer_held_minor": held,
        "isp_pool_available_minor": pool["available_minor"],
        "funded_by": "isp_wallet",
    }
    return ok(request, body, "Marketing credits")


# -- F3: the ISP-level sender ---------------------------------------------------
#
# The original provider handlers, called with the ISP ORGANIZATION as the scope
# (so the ISP's own ``org_marketing_providers`` rows hold the sender), then
# ``sync_sender_to_all`` copies the stored ciphertext to every customer that is
# not on its own sender. SMS DLT registration stays the ISP's responsibility.

isp_messaging_router = APIRouter(tags=["ISP Partner: messaging sender"])


async def isp_level_scope(
    isp: IspContext = Depends(RequireIspPartner),
    user: AuthUser = Depends(CurrentUser),
) -> CallerScope:
    return CallerScope(
        organization_id=isp.isp_org_id,
        location_id=None,
        actor_user_id=uuid.UUID(str(user.id)),
    )


async def _resync(db: AsyncSession, isp: IspContext, scope: CallerScope) -> dict:
    from .parity_settings import sync_sender_to_all

    synced = await sync_sender_to_all(db, isp, scope.actor_user_id)
    await db.commit()
    return synced


@isp_messaging_router.get(
    "/messaging/providers", dependencies=isp_guards(ISP_ENGAGE_READ)
)
async def list_isp_providers(
    request: Request,
    scope: CallerScope = Depends(isp_level_scope),
    service: Any = Depends(get_provider_service),
):
    return await mk.list_providers(request, scope=scope, service=service)


@isp_messaging_router.get(
    "/messaging/providers/{channel}", dependencies=isp_guards(ISP_ENGAGE_READ)
)
async def get_isp_provider(
    request: Request,
    channel: Channel,
    scope: CallerScope = Depends(isp_level_scope),
    service: Any = Depends(get_provider_service),
):
    return await mk.get_provider(request, channel=channel, scope=scope, service=service)


@isp_messaging_router.put(
    "/messaging/providers/{channel}", dependencies=isp_guards(ISP_ENGAGE_MANAGE)
)
async def put_isp_provider(
    request: Request,
    response: Response,
    channel: Channel,
    body: ms.ProviderPutRequest,
    isp: IspContext = Depends(RequireIspPartner),
    scope: CallerScope = Depends(isp_level_scope),
    service: Any = Depends(get_provider_service),
    db: AsyncSession = Depends(get_db_session),
):
    out = await mk.put_provider(
        request,
        response=response,
        channel=channel,
        body=body,
        scope=scope,
        service=service,
    )
    await _resync(db, isp, scope)
    return out


@isp_messaging_router.delete(
    "/messaging/providers/{channel}", dependencies=isp_guards(ISP_ENGAGE_MANAGE)
)
async def delete_isp_provider(
    request: Request,
    channel: Channel,
    isp: IspContext = Depends(RequireIspPartner),
    scope: CallerScope = Depends(isp_level_scope),
    service: Any = Depends(get_provider_service),
    db: AsyncSession = Depends(get_db_session),
):
    out = await mk.delete_provider(
        request, channel=channel, scope=scope, service=service
    )
    await _resync(db, isp, scope)
    return out


@isp_messaging_router.post(
    "/messaging/providers/{channel}/verify", dependencies=isp_guards(ISP_ENGAGE_MANAGE)
)
async def verify_isp_provider(
    request: Request,
    channel: Channel,
    body: ms.ProviderVerifyRequest,
    isp: IspContext = Depends(RequireIspPartner),
    scope: CallerScope = Depends(isp_level_scope),
    service: Any = Depends(get_provider_service),
    db: AsyncSession = Depends(get_db_session),
):
    if body.template_id is not None:
        # A template id names a row in the ISP org's own template table only.
        body = body.model_copy(update={"template_id": None})
    out = await mk.verify_provider(
        request, channel=channel, body=body, scope=scope, service=service
    )
    await _resync(db, isp, scope)
    return out


@isp_messaging_router.post(
    "/messaging/providers/sync", dependencies=isp_guards(ISP_ENGAGE_MANAGE)
)
async def resync_isp_provider(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    scope: CallerScope = Depends(isp_level_scope),
    db: AsyncSession = Depends(get_db_session),
):
    """Copy the ISP-level sender to every customer not on its own sender (for
    customers added since the last change)."""
    return ok(request, {"synced": await _resync(db, isp, scope)})
