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

Nothing here writes to Instant On, except ``PUT /routers/{router_id}/
guest-rate-limit`` -- Master only, GLOBAL, behind
``Settings.instant_on_cloud_control_enabled`` + the router allowlist, and a
preview (``dry_run``, the default) unless explicitly asked to apply.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import ApiResponse, build_response
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.session import get_db_session
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
    InstantOnGuestNetworksResponse,
    InstantOnGuestRateLimitRequest,
    InstantOnGuestRateLimitResponse,
    InstantOnGuestRateLimitState,
    InstantOnHealthItem,
    InstantOnPlatformView,
    InstantOnSiteConfigRequest,
    InstantOnSitesResponse,
    InstantOnSiteStatus,
    InstantOnSsidItem,
)
from .instant_on_service import InstantOnKind, InstantOnReadService, InstantOnView

__all__ = ["instant_on_customer_router", "instant_on_platform_router"]

logger = get_logger(__name__)

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


@instant_on_platform_router.put(
    "/routers/{router_id}/guest-rate-limit",
    response_model=ApiResponse[InstantOnGuestRateLimitResponse],
    dependencies=[Depends(_PLATFORM_UPDATE)],
)
async def set_instant_on_guest_rate_limit(
    router_id: uuid.UUID,
    payload: InstantOnGuestRateLimitRequest,
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Master: preview or apply the guest SSID's per-client speed cap on
    Instant On. This is the only speed control Instant On has -- one cap for
    every guest on the SSID (no per-guest rate exists on any path we can
    reach; see INSTANT_ON_CLOUD_CONTROL.md). Applying writes to Instant On
    and is read back; a cap Instant On did not keep is ``failed``."""
    import httpx

    from .instant_on_control import build_live_control_client, resolve_control_target
    from .instant_on_repository import InstantOnRepository
    from .providers.aruba_instant_on_client import InstantOnError

    settings = get_settings()
    site = await InstantOnRepository(db).get_site_for_router(router_id)
    target = (
        await resolve_control_target(
            db,
            organization_id=site.organization_id,
            router_id=router_id,
            settings=settings,
        )
        if site is not None
        else None
    )
    requested = InstantOnGuestRateLimitState(
        network_id=payload.network_id,
        enabled=payload.download_mbps is not None or payload.upload_mbps is not None,
        download_mbps=payload.download_mbps,
        upload_mbps=payload.upload_mbps,
    )

    def _state(limit: Any) -> InstantOnGuestRateLimitState:
        return InstantOnGuestRateLimitState(
            network_id=limit.network_id,
            network_name=limit.network_name,
            enabled=limit.enabled,
            download_mbps=limit.download_mbps,
            upload_mbps=limit.upload_mbps,
        )

    if target is None:
        body = InstantOnGuestRateLimitResponse(
            status="unavailable",
            reason="cloud_control_not_enabled",
            message=(
                "Instant On cloud control is not switched on for this device "
                "(global flag, router allowlist, write account, site mapping)."
            ),
            requested=requested,
        )
    else:
        async with httpx.AsyncClient(
            timeout=settings.instant_on_http_timeout_seconds
        ) as http:
            client = build_live_control_client(
                http, settings, secret_arn=target.secret_arn
            )
            try:
                before = await client.get_guest_network_rate_limit(
                    target.site_id, payload.network_id
                )
                if payload.dry_run:
                    body = InstantOnGuestRateLimitResponse(
                        status="preview", before=_state(before), requested=requested
                    )
                else:
                    after = await client.set_guest_network_rate_limit(
                        target.site_id,
                        payload.network_id,
                        download_mbps=payload.download_mbps,
                        upload_mbps=payload.upload_mbps,
                    )
                    logger.info(
                        "instant_on_guest_rate_limit_applied",
                        extra={
                            "router_id": str(router_id),
                            "actor_user_id": str(user.id),
                        },
                    )
                    body = InstantOnGuestRateLimitResponse(
                        status="applied",
                        before=_state(before),
                        requested=requested,
                        after=_state(after),
                    )
            except InstantOnError as error:
                body = InstantOnGuestRateLimitResponse(
                    status="failed",
                    reason=error.code,
                    message=str(error),
                    requested=requested,
                )
    return build_response(
        success=True,
        message="Instant On guest speed limit",
        data=body.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@instant_on_platform_router.get(
    "/routers/{router_id}/guest-networks",
    response_model=ApiResponse[InstantOnGuestNetworksResponse],
    dependencies=[Depends(_PLATFORM_READ)],
)
async def list_instant_on_guest_networks(
    router_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Master: the venue's guest SSIDs with their current per-client caps,
    read live through the write account (cloud control must be enabled for
    this router). Read-only; feeds the speed-tiers-by-SSID screen."""
    import httpx

    from .instant_on_control import build_live_control_client, resolve_control_target
    from .instant_on_repository import InstantOnRepository
    from .providers.aruba_instant_on_client import InstantOnError

    settings = get_settings()
    site = await InstantOnRepository(db).get_site_for_router(router_id)
    target = (
        await resolve_control_target(
            db,
            organization_id=site.organization_id,
            router_id=router_id,
            settings=settings,
        )
        if site is not None
        else None
    )
    if target is None:
        body = InstantOnGuestNetworksResponse(
            status="unavailable", reason="cloud_control_not_enabled"
        )
    else:
        async with httpx.AsyncClient(
            timeout=settings.instant_on_http_timeout_seconds
        ) as http:
            client = build_live_control_client(
                http, settings, secret_arn=target.secret_arn
            )
            try:
                limits = await client.list_guest_network_rate_limits(target.site_id)
            except InstantOnError as error:
                body = InstantOnGuestNetworksResponse(
                    status="failed", reason=error.code, message=str(error)
                )
            else:
                body = InstantOnGuestNetworksResponse(
                    status="ok",
                    networks=[
                        InstantOnGuestRateLimitState(
                            network_id=n.network_id,
                            network_name=n.network_name,
                            enabled=n.enabled,
                            download_mbps=n.download_mbps,
                            upload_mbps=n.upload_mbps,
                            is_guest=n.is_guest,
                        )
                        for n in limits
                    ],
                )
    return build_response(
        success=True,
        message="Instant On guest networks",
        data=body.model_dump(mode="json"),
        request_id=_request_id(request),
    )
