"""FastAPI routes for Cloudflare Gateway DNS (category) filtering.

Every route names its scope in the path (``organization_id``,
``location_id`` or ``router_id``) and **pins** ``RequirePermission``'s scope
explicitly. Without ``scope=``, the check level is inferred from whichever
scope identifiers the caller supplied -- which lets the caller choose how
narrow the check is. Pinned, a location-scoped account cannot set an
organization's default, and a router is always checked as a router (its
location and organization derived from the row, not from headers).

Permissions reuse the ``content_filtering`` module's keys -- this is the
provider-backed half of the same customer feature -- so no RBAC seed change
is needed: ``read`` to look, ``update`` to choose categories (a policy edit,
applied at Cloudflare), ``execute`` for anything that changes a live router
(switching its resolver, restoring it, bypass hardening).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .cloudflare_client import GatewayCategory
from .constants import SECURITY_THREATS_CATEGORY_ID, RouterFilteringState
from .dependencies import get_dns_filtering_service
from .models import DnsFilteringRouterLocation
from .schemas import (
    BypassCountersResponse,
    BypassHardeningRequest,
    BypassLayerCounters,
    CategoryListResponse,
    CategoryResponse,
    LocationPolicyResponse,
    OrganizationPolicyResponse,
    PolicyUpdateRequest,
    RouterFilteringStatusResponse,
)
from .service import DnsFilteringService, EffectivePolicy

router = APIRouter(prefix="/dns-filtering", tags=["DNS Filtering"])

LIMITATIONS = [
    "Enforced by Cloudflare Gateway at the DNS layer, not by the router.",
    "Devices using their own DNS, DNS-over-HTTPS or DNS-over-TLS are not "
    "covered unless DNS bypass hardening is on -- and even then DoH to an "
    "unlisted server looks like ordinary HTTPS and still gets through.",
    "Nothing at the router stops a VPN or DNS-over-HTTPS server that runs on "
    "port 443 with no recognisable name (or with Encrypted Client Hello), a "
    "resolver the guest runs themselves, or a phone on mobile data. Bypass "
    "protection stops default settings and casual workarounds, not a "
    "determined user.",
    "Blocks whole domains only: no URL paths, no in-app content.",
    "If Cloudflare Gateway is unreachable, guests at this venue cannot "
    "resolve names until filtering is disabled.",
]


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _category(c: GatewayCategory, *, security: bool = False) -> CategoryResponse:
    is_security = security or c.id == SECURITY_THREATS_CATEGORY_ID
    return CategoryResponse(
        id=c.id,
        name=c.name,
        description=c.description,
        category_class=c.category_class,
        beta=c.beta,
        is_security=is_security,
        subcategories=[_category(s, security=is_security) for s in c.subcategories],
    )


def _location_policy(
    location: object, effective: EffectivePolicy
) -> LocationPolicyResponse:
    return LocationPolicyResponse(
        location_id=str(location.id),  # type: ignore[attr-defined]
        organization_id=str(location.organization_id),  # type: ignore[attr-defined]
        effective_category_ids=effective.category_ids,
        source=effective.source,
        location_category_ids=(
            list(effective.location_policy.category_ids)
            if effective.location_policy is not None
            else None
        ),
        organization_category_ids=(
            list(effective.organization_policy.category_ids)
            if effective.organization_policy is not None
            else None
        ),
    )


def _status(
    router_id: uuid.UUID,
    row: DnsFilteringRouterLocation | None,
    effective: EffectivePolicy,
) -> RouterFilteringStatusResponse:
    return RouterFilteringStatusResponse(
        router_id=str(router_id),
        enabled=row is not None and row.state == RouterFilteringState.ACTIVE.value,
        state=row.state if row is not None else RouterFilteringState.DISABLED.value,
        device_push_status=row.device_push_status if row is not None else None,
        device_push_error=row.device_push_error if row is not None else None,
        device_pushed_at=row.device_pushed_at if row is not None else None,
        effective_category_ids=effective.category_ids,
        policy_source=effective.source,
        bypass_hardening_enabled=bool(row and row.bypass_hardening_enabled),
        bypass_hardening_status=row.bypass_hardening_status
        if row is not None
        else "off",
        bypass_hardening_error=row.bypass_hardening_error if row is not None else None,
        bypass_layers=list(row.bypass_layers or []) if row is not None else [],
        bypass_lists_pushed_at=row.bypass_lists_pushed_at if row is not None else None,
        routeros_version=row.routeros_version if row is not None else None,
        limitations=LIMITATIONS,
    )


# -- categories ---------------------------------------------------------------


@router.get(
    "/categories",
    response_model=ApiResponse[CategoryListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("content_filtering.read", scope=ScopeType.LOCATION))
    ],
)
async def list_categories(
    request: Request,
    location_id: uuid.UUID = Query(...),
    service: DnsFilteringService = Depends(get_dns_filtering_service),
):
    """Cloudflare's category catalogue (cached in-process for an hour).
    ``location_id`` is required so the permission check has a venue to pin
    to; the catalogue itself is the same for everyone."""
    categories = await service.list_categories()
    payload = CategoryListResponse(items=[_category(c) for c in categories])
    return build_response(
        success=True,
        message="DNS filtering categories retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


# -- policies -----------------------------------------------------------------


@router.get(
    "/organizations/{organization_id}/policy",
    response_model=ApiResponse[OrganizationPolicyResponse],
    dependencies=[
        Depends(
            RequirePermission("content_filtering.read", scope=ScopeType.ORGANIZATION)
        )
    ],
)
async def get_organization_policy(
    request: Request,
    organization_id: uuid.UUID,
    service: DnsFilteringService = Depends(get_dns_filtering_service),
):
    policy = await service.get_organization_policy(organization_id)
    payload = OrganizationPolicyResponse(
        organization_id=str(organization_id),
        category_ids=list(policy.category_ids) if policy is not None else [],
        updated_at=policy.updated_at if policy is not None else None,
    )
    return build_response(
        success=True,
        message="Organization DNS filtering policy retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/organizations/{organization_id}/policy",
    response_model=ApiResponse[OrganizationPolicyResponse],
    dependencies=[
        Depends(
            RequirePermission("content_filtering.update", scope=ScopeType.ORGANIZATION)
        )
    ],
)
async def set_organization_policy(
    request: Request,
    organization_id: uuid.UUID,
    payload: PolicyUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    service: DnsFilteringService = Depends(get_dns_filtering_service),
):
    policy = await service.set_organization_policy(
        organization_id,
        category_ids=payload.category_ids,
        actor_user_id=uuid.UUID(actor.id),
    )
    body = OrganizationPolicyResponse(
        organization_id=str(organization_id),
        category_ids=list(policy.category_ids),
        updated_at=policy.updated_at,
    )
    return build_response(
        success=True,
        message="Organization DNS filtering policy updated",
        data=body.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/locations/{location_id}/policy",
    response_model=ApiResponse[LocationPolicyResponse],
    dependencies=[
        Depends(RequirePermission("content_filtering.read", scope=ScopeType.LOCATION))
    ],
)
async def get_location_policy(
    request: Request,
    location_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsFilteringService = Depends(get_dns_filtering_service),
):
    location, effective = await service.get_location_policy(
        location_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Venue DNS filtering policy retrieved",
        data=_location_policy(location, effective).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/locations/{location_id}/policy",
    response_model=ApiResponse[LocationPolicyResponse],
    dependencies=[
        Depends(RequirePermission("content_filtering.update", scope=ScopeType.LOCATION))
    ],
)
async def set_location_policy(
    request: Request,
    location_id: uuid.UUID,
    payload: PolicyUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsFilteringService = Depends(get_dns_filtering_service),
):
    location, effective = await service.set_location_policy(
        location_id,
        category_ids=payload.category_ids,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Venue DNS filtering policy updated",
        data=_location_policy(location, effective).model_dump(mode="json"),
        request_id=_request_id(request),
    )


# -- routers ------------------------------------------------------------------


@router.get(
    "/routers/{router_id}",
    response_model=ApiResponse[RouterFilteringStatusResponse],
    dependencies=[
        Depends(RequirePermission("content_filtering.read", scope=ScopeType.ROUTER))
    ],
)
async def get_router_status(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsFilteringService = Depends(get_dns_filtering_service),
):
    found, row, effective = await service.get_router_status(
        router_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Router DNS filtering status retrieved",
        data=_status(found.id, row, effective).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/enable",
    response_model=ApiResponse[RouterFilteringStatusResponse],
    dependencies=[
        Depends(RequirePermission("content_filtering.execute", scope=ScopeType.ROUTER))
    ],
)
async def enable_router(
    request: Request,
    router_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsFilteringService = Depends(get_dns_filtering_service),
):
    """Switch the router's resolver to its Cloudflare Gateway DoH endpoint.

    No try/except here: a failed switch raises a typed error carrying its own
    status (409 refused before any write, 502 after a rolled-back write), and
    the row's failure record is committed before the raise.
    """
    await service.enable_router(
        router_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    found, row, effective = await service.get_router_status(
        router_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Category filtering enabled",
        data=_status(found.id, row, effective).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/disable",
    response_model=ApiResponse[RouterFilteringStatusResponse],
    dependencies=[
        Depends(RequirePermission("content_filtering.execute", scope=ScopeType.ROUTER))
    ],
)
async def disable_router(
    request: Request,
    router_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsFilteringService = Depends(get_dns_filtering_service),
):
    await service.disable_router(
        router_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    found, row, effective = await service.get_router_status(
        router_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message=(
            "Category filtering disabled; the router's own DNS settings "
            "were restored"
        ),
        data=_status(found.id, row, effective).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/routers/{router_id}/bypass-hardening",
    response_model=ApiResponse[RouterFilteringStatusResponse],
    dependencies=[
        Depends(RequirePermission("content_filtering.execute", scope=ScopeType.ROUTER))
    ],
)
async def set_bypass_hardening(
    request: Request,
    router_id: uuid.UUID,
    payload: BypassHardeningRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsFilteringService = Depends(get_dns_filtering_service),
):
    """Opt-in, off by default: converge the router's DNS-bypass layers on
    ``layers`` (omitted = every layer except VPN blocking), or remove them
    all with ``enabled=false``."""
    await service.set_bypass_hardening(
        router_id,
        enabled=payload.enabled,
        layers=payload.layers,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    found, row, effective = await service.get_router_status(
        router_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="DNS bypass hardening updated",
        data=_status(found.id, row, effective).model_dump(mode="json"),
        request_id=_request_id(request),
    )


COUNTER_SEMANTICS = (
    "Packets dropped by this platform's bypass rules on the router, "
    "cumulative since each rule was added or the router last restarted "
    "(RouterOS resets counters on reboot). One blocked connection is usually "
    "several packets, so this is not a count of attempts or of people. "
    "Lookups answered 'does not exist' by the canary and DoH-hostname "
    "entries are not counted by RouterOS at all."
)


@router.get(
    "/routers/{router_id}/bypass-hardening/counters",
    response_model=ApiResponse[BypassCountersResponse],
    dependencies=[
        Depends(RequirePermission("content_filtering.read", scope=ScopeType.ROUTER))
    ],
)
async def get_bypass_counters(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: DnsFilteringService = Depends(get_dns_filtering_service),
):
    """Evidence, not a claim: per-layer drop counters read live off the
    router's own marked rules over 8728. ``available=false`` with a reason
    whenever a number cannot be read -- never a zero standing in for one."""
    view = await service.get_bypass_counters(
        router_id, requesting_organization_id=requesting_organization_id
    )
    payload = BypassCountersResponse(
        router_id=str(router_id),
        available=view.available,
        reason=view.reason,
        router_uptime=view.router_uptime,
        layers=[
            BypassLayerCounters(
                layer=v.layer,
                enabled=v.enabled,
                available=v.available,
                packets=v.packets,
                bytes=v.bytes,
                reason=v.reason,
            )
            for v in view.layers
        ],
        semantics=COUNTER_SEMANTICS,
    )
    return build_response(
        success=True,
        message="DNS bypass counters retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["COUNTER_SEMANTICS", "LIMITATIONS", "router"]
