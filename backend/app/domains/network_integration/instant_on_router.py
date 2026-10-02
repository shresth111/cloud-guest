"""HTTP surface for the Aruba Instant On read-only integration.

Two routers, two scopes, never mixed:

``instant_on_customer_router`` -- ``/network-integrations/locations/
{location_id}/instant-on/{access-points|clients|ssids|alerts}``.
``locations.read`` at ``ScopeType.ORGANIZATION`` (the permission a venue
owner already holds to read the location, as ``controller-devices`` uses).
The caller names a location and nothing else; the site is resolved by a
query carrying the caller's organization **and** that location, then the
caller's location confinement is applied to the row. Another tenant's
location, a location with no Instant On site, and one not yet switched on
for customers all return the same ``unavailable / not_configured`` body.
There is no request body on these routes, so there is no body id either.

``instant_on_platform_router`` -- ``/platform/instant-on/...``, Master
console only, every route **pinned** to ``ScopeType.GLOBAL`` (never left to
scope inference: ``network_integrations.*`` is held at organization scope
by venue owners). Keyed on a fleet ``router_id``. The one write,
``PUT /routers/{router_id}/site``, writes only to this platform's database:
it maps the router to its Instant On site and sets the per-venue flags. Its
body carries no organization or location -- both are copied from the router.

Nothing here writes to Instant On.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, Request

from app.common.responses import ApiResponse, build_response
from app.core.config import get_settings
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .dependencies import get_instant_on_read_service
from .instant_on_schemas import (
    InstantOnAccessPointItem,
    InstantOnAccountSitesResponse,
    InstantOnAlertItem,
    InstantOnClientItem,
    InstantOnClientUsageItem,
    InstantOnCustomerView,
    InstantOnHealthItem,
    InstantOnPlatformView,
    InstantOnSiteConfigRequest,
    InstantOnSitesResponse,
    InstantOnSiteStatus,
    InstantOnSsidItem,
)
from .instant_on_service import InstantOnKind, InstantOnReadService, InstantOnView

__all__ = ["instant_on_customer_router", "instant_on_platform_router"]

instant_on_customer_router = APIRouter(
    prefix="/network-integrations", tags=["Instant On (customer)"]
)
instant_on_platform_router = APIRouter(
    prefix="/platform/instant-on", tags=["Instant On (platform)"]
)

_CUSTOMER_PERMISSION = RequirePermission("locations.read", scope=ScopeType.ORGANIZATION)
_PLATFORM_READ = RequirePermission("network_integrations.read", scope=ScopeType.GLOBAL)
_PLATFORM_UPDATE = RequirePermission(
    "network_integrations.update", scope=ScopeType.GLOBAL
)

_ITEM_MODELS: dict[InstantOnKind, type] = {
    InstantOnKind.ACCESS_POINTS: InstantOnAccessPointItem,
    InstantOnKind.CLIENTS: InstantOnClientItem,
    InstantOnKind.SSIDS: InstantOnSsidItem,
    InstantOnKind.ALERTS: InstantOnAlertItem,
    InstantOnKind.HEALTH: InstantOnHealthItem,
    InstantOnKind.CLIENT_USAGE: InstantOnClientUsageItem,
}

_PATH_SEGMENT: dict[InstantOnKind, str] = {
    InstantOnKind.ACCESS_POINTS: "access-points",
    InstantOnKind.CLIENTS: "clients",
    InstantOnKind.SSIDS: "ssids",
    InstantOnKind.ALERTS: "alerts",
    InstantOnKind.HEALTH: "health",
    InstantOnKind.CLIENT_USAGE: "client-usage",
}


def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID", "") or str(
        getattr(getattr(request, "state", None), "request_id", "")
    )


def _view_payload(view: InstantOnView, *, platform: bool) -> dict[str, Any]:
    item_model = _ITEM_MODELS[InstantOnKind(view.kind)]
    model = (InstantOnPlatformView if platform else InstantOnCustomerView)[item_model]  # type: ignore[index]
    data: dict[str, Any] = {
        "source": view.source,
        "kind": view.kind,
        "status": view.status,
        "unavailable_reason": view.unavailable_reason,
        "as_of": view.as_of,
        "last_success_at": view.last_success_at,
        "stale_after_seconds": view.stale_after_seconds,
        "items": view.items,
    }
    if platform:
        data["error_code"] = view.error_code
        data["api_state"] = view.api_state
    return model.model_validate(data).model_dump(mode="json")


# ============================================================================
# Customer (organization-scoped, location-keyed)
# ============================================================================


def _customer_endpoint(kind: InstantOnKind) -> Callable[..., Any]:
    async def endpoint(
        location_id: uuid.UUID,
        request: Request,
        requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
        service: InstantOnReadService = Depends(get_instant_on_read_service),
    ) -> dict[str, Any]:
        view = await service.customer_view(
            location_id=location_id,
            organization_id=requesting_organization_id,
            kind=kind,
        )
        return build_response(
            success=True,
            message=f"Instant On {kind.value.replace('_', ' ')}",
            data=_view_payload(view, platform=False),
            request_id=_request_id(request),
        )

    endpoint.__name__ = f"get_location_instant_on_{kind.value}"
    endpoint.__qualname__ = endpoint.__name__
    endpoint.__doc__ = (
        f"Instant On {kind.value.replace('_', ' ')} for one of the caller's "
        "locations. `status: unavailable` (with `items: null`) whenever the "
        "data cannot be vouched for -- never stale data, never zeros."
    )
    return endpoint


for _kind in (
    InstantOnKind.ACCESS_POINTS,
    InstantOnKind.CLIENTS,
    InstantOnKind.SSIDS,
    InstantOnKind.ALERTS,
):
    instant_on_customer_router.add_api_route(
        f"/locations/{{location_id}}/instant-on/{_PATH_SEGMENT[_kind]}",
        _customer_endpoint(_kind),
        methods=["GET"],
        response_model=ApiResponse[InstantOnCustomerView[_ITEM_MODELS[_kind]]],  # type: ignore[index]
        dependencies=[Depends(_CUSTOMER_PERMISSION)],
    )


# ============================================================================
# Master console (GLOBAL, pinned)
# ============================================================================


def _platform_endpoint(kind: InstantOnKind) -> Callable[..., Any]:
    async def endpoint(
        router_id: uuid.UUID,
        request: Request,
        service: InstantOnReadService = Depends(get_instant_on_read_service),
    ) -> dict[str, Any]:
        view = await service.platform_view(router_id=router_id, kind=kind)
        return build_response(
            success=True,
            message=f"Instant On {kind.value.replace('_', ' ')}",
            data=_view_payload(view, platform=True),
            request_id=_request_id(request),
        )

    endpoint.__name__ = f"get_platform_instant_on_{kind.value}"
    endpoint.__qualname__ = endpoint.__name__
    endpoint.__doc__ = (
        f"Master: Instant On {kind.value.replace('_', ' ')} for a NAS-only "
        "fleet device, with the poll's error code and API state."
    )
    return endpoint


for _kind in InstantOnKind:
    instant_on_platform_router.add_api_route(
        f"/routers/{{router_id}}/{_PATH_SEGMENT[_kind]}",
        _platform_endpoint(_kind),
        methods=["GET"],
        response_model=ApiResponse[InstantOnPlatformView[_ITEM_MODELS[_kind]]],  # type: ignore[index]
        dependencies=[Depends(_PLATFORM_READ)],
    )


def _site_status(site: Any) -> dict[str, Any]:
    return InstantOnSiteStatus.model_validate(site, from_attributes=True).model_dump(
        mode="json"
    )


@instant_on_platform_router.get(
    "/sites",
    response_model=ApiResponse[InstantOnSitesResponse],
    dependencies=[Depends(_PLATFORM_READ)],
)
async def list_instant_on_sites(
    request: Request,
    service: InstantOnReadService = Depends(get_instant_on_read_service),
) -> dict[str, Any]:
    """Master: every mapped Instant On site with its poll state
    (``ok | auth_failed | incompatible | rate_limited | not_invited |
    upstream_error | not_configured | never_polled``)."""
    settings = get_settings()
    sites = await service.platform_list_sites()
    payload = InstantOnSitesResponse(
        poller_enabled=settings.instant_on_poller_enabled,
        service_account_configured=bool(settings.instant_on_service_account_secret_arn),
        api_version=settings.instant_on_api_version,
        sites=[
            InstantOnSiteStatus.model_validate(s, from_attributes=True) for s in sites
        ],
    )
    return build_response(
        success=True,
        message="Instant On sites",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@instant_on_platform_router.put(
    "/routers/{router_id}/site",
    response_model=ApiResponse[InstantOnSiteStatus],
    dependencies=[Depends(_PLATFORM_UPDATE)],
)
async def configure_instant_on_site(
    router_id: uuid.UUID,
    payload: InstantOnSiteConfigRequest,
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: InstantOnReadService = Depends(get_instant_on_read_service),
    router_service: RouterService = Depends(get_router_service),
) -> dict[str, Any]:
    """Master: map a NAS-only (Instant On) fleet device to its Instant On
    site and set the per-venue ``poll_enabled`` / ``customer_visible``
    flags. Writes only to this platform's database."""
    site = await service.configure_site(
        router_id=router_id,
        site_id=payload.site_id,
        site_name=payload.site_name,
        poll_enabled=payload.poll_enabled,
        customer_visible=payload.customer_visible,
        router_lookup=router_service,
        actor_user_id=uuid.UUID(str(user.id)),
    )
    return build_response(
        success=True,
        message="Instant On site saved",
        data=_site_status(site),
        request_id=_request_id(request),
    )


@instant_on_platform_router.get(
    "/account/sites",
    response_model=ApiResponse[InstantOnAccountSitesResponse],
    dependencies=[Depends(_PLATFORM_READ)],
)
async def list_instant_on_account_sites(request: Request) -> dict[str, Any]:
    """Master: the Instant On sites the Wyfy service account can currently
    see (a LIVE read of ``GET /api/sites``). A venue whose site is missing
    here has not invited the service account yet."""
    import httpx

    from .instant_on_tasks import build_live_provider
    from .providers.aruba_instant_on_client import InstantOnError

    settings = get_settings()
    async with httpx.AsyncClient(
        timeout=settings.instant_on_http_timeout_seconds
    ) as http:
        provider = build_live_provider(http, settings)
        try:
            sites = await provider.list_sites()
        except InstantOnError as error:
            body = InstantOnAccountSitesResponse(
                status="unavailable",
                unavailable_reason=error.code,
                message=str(error),
            )
        else:
            body = InstantOnAccountSitesResponse(
                status="ok",
                sites=[{"site_id": s.site_id, "name": s.name} for s in sites],  # type: ignore[misc]
            )
    return build_response(
        success=True,
        message="Instant On account sites",
        data=body.model_dump(mode="json"),
        request_id=_request_id(request),
    )
