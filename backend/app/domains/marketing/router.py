"""FastAPI routes for Guest Marketing -- contract §5.

Three routers:

* ``router`` (``/marketing/*``) -- customer routes. Every route carries, in
  this order: ``RequireOrganization`` (400 ``organization_required``),
  ``RequireFeature(GUEST_MARKETING)`` (402 ``feature_not_entitled`` /
  ``license_not_active`` -- before any permission or data work), then
  ``RequirePermission("marketing.<action>", scope=ScopeType.LOCATION)``.
  The scope is pinned rather than inferred from headers so a caller cannot
  choose the level their own grant is checked at; LOCATION is the module's
  narrowest scope, which an organization grant satisfies for its own org and
  a location grant satisfies only for the location in ``X-Location-Id``.
  Mounted with ``_PAID_WRITES``.
* ``public_router`` (``/public/marketing/*``) -- the unsubscribe page.
  Unauthenticated, not licence- or entitlement-gated: honouring an opt-out is
  a legal duty whatever the billing state. Rate-limited per IP.
* ``guest_router`` (``/guest/marketing-consent``) -- the portal opt-in.
  Unauthenticated; the proof is the guest's own ACTIVE session.
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response, status
from redis.asyncio import Redis

from app.common.responses import ApiResponse, build_response
from app.database.redis import get_redis_client
from app.database.utils.pagination import PaginationMeta
from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.dependencies import RequireFeature
from app.domains.rbac.dependencies import RequireOrganization, RequirePermission
from app.domains.rbac.enums import ScopeType

from .constants import (
    PUBLIC_RATE_LIMIT_KEY_TEMPLATE,
    PUBLIC_RATE_LIMIT_PER_MINUTE,
    Channel,
    TemplateCategory,
)
from .dependencies import (
    get_caller_scope,
    get_marketing_service,
    get_platform_provider_service,
    get_provider_service,
    get_public_marketing_service,
)
from .exceptions import PublicRateLimitedError
from .provider_service import ProviderService
from .schemas import (
    AudienceFilter,
    CampaignCreate,
    CampaignUpdate,
    EmptyRequest,
    GuestConsentRequest,
    PortalConsentUpdate,
    ProviderPutRequest,
    ProviderVerifyRequest,
    ScheduleRequest,
    StaffOptOutRequest,
    TemplateCreate,
    TemplateDuplicate,
    TemplatePreviewRequest,
    TemplateUpdate,
    TestSendRequest,
)
from .service import CallerScope, MarketingService

router = APIRouter(prefix="/marketing", tags=["Marketing"])
# Bring-your-own providers (spec §12.4). Its own router so the guard set can
# differ: both add-ons, and a permission pinned at ORGANIZATION (never
# grantable at a location -- a location-confined caller is refused).
providers_router = APIRouter(
    prefix="/marketing/providers", tags=["Marketing providers"]
)
# Master read-only view, pinned GLOBAL.
platform_providers_router = APIRouter(
    prefix="/platform/organizations", tags=["Platform Add-ons"]
)
public_router = APIRouter(prefix="/public/marketing", tags=["Marketing (public)"])
guest_router = APIRouter(prefix="/guest", tags=["Marketing (guest)"])


def _guards(permission: str) -> list[Any]:
    return [
        Depends(RequireOrganization),
        Depends(RequireFeature(PlanFeatureKey.GUEST_MARKETING)),
        Depends(RequirePermission(permission, scope=ScopeType.LOCATION)),
    ]


def _provider_guards(permission: str) -> list[Any]:
    return [
        Depends(RequireOrganization),
        Depends(RequireFeature(PlanFeatureKey.GUEST_MARKETING)),
        Depends(RequireFeature(PlanFeatureKey.GUEST_MARKETING_BYO)),
        Depends(RequirePermission(permission, scope=ScopeType.ORGANIZATION)),
    ]


def _rid(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _ok(request: Request, message: str, data: Any) -> dict[str, Any]:
    return build_response(
        success=True, message=message, data=data, request_id=_rid(request)
    )


def _page(items: list[Any], meta: PaginationMeta) -> dict[str, Any]:
    return {
        "items": items,
        "page": meta.page,
        "page_size": meta.page_size,
        "total_items": meta.total_items,
        "total_pages": meta.total_pages,
        "has_next": meta.has_next,
        "has_previous": meta.has_previous,
    }


def _csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [part.strip() for part in value.split(",") if part.strip()] or None


# ============================================================================
# §5.1 Status and settings
# ============================================================================


@router.get(
    "/status",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.read"),
)
async def marketing_status(
    request: Request,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(request, "Marketing status", await service.status(scope))


@router.put(
    "/portal-consent",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.manage"),
)
async def update_portal_consent(
    request: Request,
    body: PortalConsentUpdate,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request,
        "Portal opt-in updated",
        await service.update_portal_consent(scope, body),
    )


# ============================================================================
# §5.2 Contacts
# ============================================================================


@router.get(
    "/contacts",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.read"),
)
async def list_contacts(
    request: Request,
    channel: Channel = Query(...),
    consent_status: str = Query(default="opted_in"),
    location_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    items, meta = await service.list_contacts(
        scope,
        channel=channel,
        consent_status=consent_status,
        location_id=location_id,
        search=search,
        page=page,
        page_size=page_size,
    )
    return _ok(request, "Contacts retrieved", _page(items, meta))


@router.post(
    "/contacts/{guest_id}/opt-out",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.update"),
)
async def staff_opt_out(
    request: Request,
    guest_id: uuid.UUID,
    body: StaffOptOutRequest,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request,
        "Opt-out recorded",
        await service.staff_opt_out(scope, guest_id, body.channels, body.note),
    )


# ============================================================================
# §5.3 Audience preview
# ============================================================================


@router.post(
    "/audience/preview",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.read"),
)
async def audience_preview(
    request: Request,
    body: AudienceFilter,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(request, "Audience preview", await service.audience_preview(scope, body))


# ============================================================================
# §5.4 Templates
# ============================================================================


@router.get(
    "/templates",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.read"),
)
async def list_templates(
    request: Request,
    channel: Channel | None = Query(default=None),
    category: TemplateCategory | None = Query(default=None),
    include_system: bool = Query(default=True),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    items, meta = await service.list_templates(
        scope,
        channel=channel,
        category=category,
        include_system=include_system,
        page=page,
        page_size=page_size,
    )
    return _ok(request, "Templates retrieved", _page(items, meta))


@router.post(
    "/templates/preview",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.read"),
)
async def preview_template(
    request: Request,
    body: TemplatePreviewRequest,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(request, "Template preview", await service.preview_template(scope, body))


@router.get(
    "/templates/{template_id}",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.read"),
)
async def get_template(
    request: Request,
    template_id: uuid.UUID,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request, "Template retrieved", await service.get_template(scope, template_id)
    )


@router.post(
    "/templates",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_201_CREATED,
    dependencies=_guards("marketing.create"),
)
async def create_template(
    request: Request,
    body: TemplateCreate,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(request, "Template created", await service.create_template(scope, body))


@router.patch(
    "/templates/{template_id}",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.update"),
)
async def update_template(
    request: Request,
    template_id: uuid.UUID,
    body: TemplateUpdate,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request,
        "Template updated",
        await service.update_template(scope, template_id, body),
    )


@router.delete(
    "/templates/{template_id}",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.delete"),
)
async def delete_template(
    request: Request,
    template_id: uuid.UUID,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request, "Template deleted", await service.delete_template(scope, template_id)
    )


@router.post(
    "/templates/{template_id}/duplicate",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_201_CREATED,
    dependencies=_guards("marketing.create"),
)
async def duplicate_template(
    request: Request,
    template_id: uuid.UUID,
    body: TemplateDuplicate,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request,
        "Template duplicated",
        await service.duplicate_template(scope, template_id, body.name),
    )


# ============================================================================
# §5.5 Campaigns
# ============================================================================


@router.get(
    "/campaigns",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.read"),
)
async def list_campaigns(
    request: Request,
    status_filter: str | None = Query(default=None, alias="status"),
    channel: Channel | None = Query(default=None),
    search: str | None = Query(default=None, max_length=120),
    location_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    items, meta = await service.list_campaigns(
        scope,
        statuses=_csv(status_filter),
        channel=channel,
        search=search,
        page=page,
        page_size=page_size,
        location_id=location_id,
    )
    return _ok(request, "Campaigns retrieved", _page(items, meta))


@router.post(
    "/campaigns",
    response_model=ApiResponse[dict],
    status_code=status.HTTP_201_CREATED,
    dependencies=_guards("marketing.create"),
)
async def create_campaign(
    request: Request,
    body: CampaignCreate,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(request, "Campaign created", await service.create_campaign(scope, body))


@router.get(
    "/campaigns/{campaign_id}",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.read"),
)
async def get_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request, "Campaign retrieved", await service.get_campaign(scope, campaign_id)
    )


@router.get(
    "/campaigns/{campaign_id}/estimate",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.read"),
)
async def estimate_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    """Credits estimate (spec §13.7): what schedule would reserve now."""
    return _ok(request, "Campaign estimate", await service.estimate(scope, campaign_id))


@router.patch(
    "/campaigns/{campaign_id}",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.update"),
)
async def update_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    body: CampaignUpdate,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request,
        "Campaign updated",
        await service.update_campaign(scope, campaign_id, body),
    )


@router.delete(
    "/campaigns/{campaign_id}",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.delete"),
)
async def delete_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request, "Campaign deleted", await service.delete_campaign(scope, campaign_id)
    )


@router.post(
    "/campaigns/{campaign_id}/test-send",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.execute"),
)
async def test_send(
    request: Request,
    campaign_id: uuid.UUID,
    body: TestSendRequest,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request,
        "Test send finished",
        await service.test_send(scope, campaign_id, body.to, body.sample_guest_name),
    )


@router.post(
    "/campaigns/{campaign_id}/schedule",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.execute"),
)
async def schedule_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    body: ScheduleRequest,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request,
        "Campaign scheduled",
        await service.schedule(
            scope,
            campaign_id,
            scheduled_at=body.scheduled_at,
            idempotency_key=body.idempotency_key,
            acknowledge_wyfy_fallback=body.acknowledge_wyfy_fallback,
        ),
    )


@router.post(
    "/campaigns/{campaign_id}/unschedule",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.execute"),
)
async def unschedule_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(
        request, "Campaign unscheduled", await service.unschedule(scope, campaign_id)
    )


@router.post(
    "/campaigns/{campaign_id}/cancel",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.execute"),
)
async def cancel_campaign(
    request: Request,
    campaign_id: uuid.UUID,
    body: EmptyRequest | None = None,
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    return _ok(request, "Campaign cancelled", await service.cancel(scope, campaign_id))


# ============================================================================
# §5.6 Delivery logs
# ============================================================================


@router.get(
    "/campaigns/{campaign_id}/recipients",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.read"),
)
async def list_recipients(
    request: Request,
    campaign_id: uuid.UUID,
    status_filter: str | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    items, meta = await service.list_recipients(
        scope, campaign_id, statuses=_csv(status_filter), page=page, page_size=page_size
    )
    return _ok(request, "Recipients retrieved", _page(items, meta))


@router.get(
    "/deliveries",
    response_model=ApiResponse[dict],
    dependencies=_guards("marketing.read"),
)
async def list_deliveries(
    request: Request,
    channel: Channel | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    campaign_id: uuid.UUID | None = Query(default=None),
    date_from: date | None = Query(default=None, alias="from"),
    date_to: date | None = Query(default=None, alias="to"),
    location_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    scope: CallerScope = Depends(get_caller_scope),
    service: MarketingService = Depends(get_marketing_service),
):
    items, meta = await service.list_deliveries(
        scope,
        channel=channel,
        statuses=_csv(status_filter),
        campaign_id=campaign_id,
        date_from=date_from,
        date_to=date_to,
        page=page,
        page_size=page_size,
        location_id=location_id,
    )
    return _ok(request, "Deliveries retrieved", _page(items, meta))


# ============================================================================
# §5.7 Public unsubscribe
# ============================================================================


async def _public_rate_limit(
    request: Request, redis: Redis = Depends(get_redis_client)
) -> None:
    ip = request.client.host if request.client else "unknown"
    key = PUBLIC_RATE_LIMIT_KEY_TEMPLATE.format(ip=ip)
    try:
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, 60)
    except Exception:  # noqa: BLE001 - never block an opt-out on Redis
        return
    if count > PUBLIC_RATE_LIMIT_PER_MINUTE:
        raise PublicRateLimitedError("Too many requests; try again in a minute")


@public_router.get(
    "/unsubscribe/{token}",
    response_model=ApiResponse[dict],
    dependencies=[Depends(_public_rate_limit)],
)
async def unsubscribe_info(
    request: Request,
    token: str,
    service: MarketingService = Depends(get_public_marketing_service),
):
    return _ok(request, "Subscription", await service.unsubscribe_info(token))


@public_router.post(
    "/unsubscribe/{token}",
    response_model=ApiResponse[dict],
    dependencies=[Depends(_public_rate_limit)],
)
async def unsubscribe(
    request: Request,
    token: str,
    service: MarketingService = Depends(get_public_marketing_service),
):
    # Accepts JSON ``{}`` and the RFC 8058 one-click form body
    # (``List-Unsubscribe=One-Click``, form-encoded). The body carries no
    # information either way -- the token is the whole request.
    ip = request.client.host if request.client else None
    return _ok(request, "Unsubscribed", await service.unsubscribe(token, ip_address=ip))


# ============================================================================
# §5.8 Guest consent capture
# ============================================================================


@guest_router.post("/marketing-consent", response_model=ApiResponse[dict])
async def guest_marketing_consent(
    request: Request,
    body: GuestConsentRequest,
    service: MarketingService = Depends(get_public_marketing_service),
):
    ip = request.client.host if request.client else None
    return _ok(
        request,
        "Consent recorded" if body.opt_in else "No consent recorded",
        await service.record_guest_consent(
            guest_id=body.guest_id,
            session_id=body.session_id,
            opt_in=body.opt_in,
            consent_text_version=body.consent_text_version,
            ip_address=ip,
        ),
    )


# ============================================================================
# §12.4 Own providers
# ============================================================================


@providers_router.get(
    "",
    response_model=ApiResponse[dict],
    dependencies=_provider_guards("marketing_providers.read"),
)
async def list_providers(
    request: Request,
    scope: CallerScope = Depends(get_caller_scope),
    service: ProviderService = Depends(get_provider_service),
):
    return _ok(request, "Providers", await service.list_providers(scope))


@providers_router.post(
    "/whatsapp/sync-templates",
    response_model=ApiResponse[dict],
    dependencies=_provider_guards("marketing_providers.manage"),
)
async def sync_whatsapp_templates(
    request: Request,
    body: EmptyRequest | None = None,
    scope: CallerScope = Depends(get_caller_scope),
    service: ProviderService = Depends(get_provider_service),
):
    return _ok(
        request, "Templates synced", await service.sync_whatsapp_templates(scope)
    )


@providers_router.get(
    "/{channel}",
    response_model=ApiResponse[dict],
    dependencies=_provider_guards("marketing_providers.read"),
)
async def get_provider(
    request: Request,
    channel: Channel,
    scope: CallerScope = Depends(get_caller_scope),
    service: ProviderService = Depends(get_provider_service),
):
    return _ok(request, "Provider", await service.get_provider(scope, channel))


@providers_router.put(
    "/{channel}",
    response_model=ApiResponse[dict],
    dependencies=_provider_guards("marketing_providers.manage"),
)
async def put_provider(
    request: Request,
    response: Response,
    channel: Channel,
    body: ProviderPutRequest,
    scope: CallerScope = Depends(get_caller_scope),
    service: ProviderService = Depends(get_provider_service),
):
    view, created = await service.put_provider(
        scope,
        channel,
        provider_type=body.provider_type,
        config=dict(body.config),
        enabled=body.enabled,
    )
    if created:
        response.status_code = status.HTTP_201_CREATED
    return _ok(request, "Provider saved", view)


@providers_router.delete(
    "/{channel}",
    response_model=ApiResponse[dict],
    dependencies=_provider_guards("marketing_providers.manage"),
)
async def delete_provider(
    request: Request,
    channel: Channel,
    scope: CallerScope = Depends(get_caller_scope),
    service: ProviderService = Depends(get_provider_service),
):
    return _ok(
        request, "Provider removed", await service.delete_provider(scope, channel)
    )


@providers_router.post(
    "/{channel}/verify",
    response_model=ApiResponse[dict],
    dependencies=_provider_guards("marketing_providers.manage"),
)
async def verify_provider(
    request: Request,
    channel: Channel,
    body: ProviderVerifyRequest,
    scope: CallerScope = Depends(get_caller_scope),
    service: ProviderService = Depends(get_provider_service),
):
    return _ok(
        request,
        "Verification finished",
        await service.verify(
            scope, channel, test_to=body.test_to, template_id=body.template_id
        ),
    )


@platform_providers_router.get(
    "/{organization_id}/marketing-providers",
    response_model=ApiResponse[dict],
    dependencies=[
        Depends(RequirePermission("organizations.read", scope=ScopeType.GLOBAL))
    ],
)
async def platform_marketing_providers(
    request: Request,
    organization_id: uuid.UUID,
    service: ProviderService = Depends(get_platform_provider_service),
):
    return _ok(
        request, "Marketing providers", await service.platform_view(organization_id)
    )
