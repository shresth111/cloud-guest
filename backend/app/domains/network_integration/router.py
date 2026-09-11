"""FastAPI routes for the Network Integration domain.

Responses use the project's standard envelope
(``ApiResponse``/``build_response``), matching every other domain's
router. Every customer and platform endpoint is gated by RBAC's existing
``RequirePermission`` dependency against the ``network_integrations.*``
permission keys (see ``app.domains.rbac.seed`` --
``PermissionModule.NETWORK_INTEGRATIONS``).

## Two routers, mounted at the same prefix, and why

``router`` carries the customer and platform surfaces. ``portal_router``
carries exactly one route, ``POST /network-integrations/portal/authorize``.

They are separate objects so that the *licence gate* can be applied to one
and not the other. ``app.api.v1.router`` includes the first with
``RequireActiveLicenseForWrites`` and the second with nothing -- because
cutting a venue's guest WiFi over a billing state would punish the guests
standing in its lobby for the owner's lapsed card, and turn a revenue
problem into an outage. That is the single most important line in that
module's own gating write-up, and ``voucher_router`` is already an
exception there for precisely this reason. Keeping the guest-facing route
on its own object makes the distinction structural rather than a comment
somebody has to remember.

## Route ordering matters

Starlette matches first-registered-wins. ``/platform/...``,
``/test-connection`` and ``/portal/authorize`` are all registered before
``/{integration_id}``, so a literal path can never be swallowed by the
parameterised one. The same discipline
``app.domains.queue_management.router`` and ``app.domains.isp.router``
already document for themselves.

## Why the platform routes name their scope explicitly

``RequirePermission("network_integrations.read", scope=ScopeType.GLOBAL)``
rather than the bare key. An Organization Owner holds
``network_integrations.read`` at ORGANIZATION scope, and
``_infer_scope_type`` would resolve ORGANIZATION from their
``X-Organization-Id`` header -- so the bare key would let a customer read
every tenant's integrations from the platform endpoints. The explicit
GLOBAL is the entire access control on the cross-tenant reads; see
``service.list_platform_integrations``, and
``tests/unit/test_cross_tenant_path_id_reads.py`` for the precedent where
omitting it leaked another tenant's data in this codebase.

## ``CurrentOrganization`` is declared on every by-id route

Not because the handler always uses the value directly, but because
``tests/unit/test_cross_tenant_path_id_reads.py`` checks structurally that
a route reading a resource by path id resolves the caller's organization.
Declaring it is what makes the service-layer comparison possible at all --
a route that omits it hands ``None`` to the service, and ``None`` means
"platform caller, no filter".
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .dependencies import get_network_integration_service
from .models import NetworkIntegration
from .schemas import (
    NetworkIntegrationClientListResponse,
    NetworkIntegrationClientResponse,
    NetworkIntegrationCreateRequest,
    NetworkIntegrationCredentialRotateRequest,
    NetworkIntegrationDeviceListResponse,
    NetworkIntegrationDeviceResponse,
    NetworkIntegrationDisconnectGuestRequest,
    NetworkIntegrationDisconnectGuestResponse,
    NetworkIntegrationEventListResponse,
    NetworkIntegrationEventResponse,
    NetworkIntegrationListResponse,
    NetworkIntegrationResponse,
    NetworkIntegrationSiteListResponse,
    NetworkIntegrationSiteResponse,
    NetworkIntegrationSsidListResponse,
    NetworkIntegrationSsidResponse,
    NetworkIntegrationStatusResponse,
    NetworkIntegrationSyncResponse,
    NetworkIntegrationUpdateRequest,
    PlatformNetworkIntegrationListResponse,
    PlatformNetworkIntegrationSummaryResponse,
    PlatformOnboardRequest,
    PlatformOnboardResponse,
    PortalAuthorizeRequest,
    PortalAuthorizeResponse,
    TestConnectionRequest,
    TestConnectionResponse,
)
from .service import NetworkIntegrationService
from .validators import build_external_portal_url, portal_readiness_gaps

router = APIRouter(prefix="/network-integrations", tags=["Network Integrations"])
portal_router = APIRouter(
    prefix="/network-integrations", tags=["Network Integrations (Portal)"]
)


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _pagination_fields(meta: PaginationMeta) -> dict[str, int | bool]:
    return {
        "page": meta.page,
        "page_size": meta.page_size,
        "total_items": meta.total_items,
        "total_pages": meta.total_pages,
        "has_next": meta.has_next,
        "has_previous": meta.has_previous,
    }


def _actor_id(actor: AuthUser | None) -> uuid.UUID | None:
    return uuid.UUID(actor.id) if actor is not None else None


# ============================================================================
# Response builders
# ============================================================================


def _integration_response(
    integration: NetworkIntegration,
    *,
    counts: dict[str, int] | None = None,
    organization_name: str | None = None,
    location_name: str | None = None,
) -> NetworkIntegrationResponse:
    """Assemble the wire shape.

    ``has_credentials`` is derived from whether the ciphertext column is
    populated -- the only thing any endpoint ever says about a stored
    credential. There is deliberately no branch here that could ever put
    the value itself in a response.
    """
    numbers = counts or {}
    portal_url = build_external_portal_url(
        organization_id=integration.organization_id,
        location_id=integration.location_id,
        router_id=integration.router_id,
        provider=integration.provider,
    )
    return NetworkIntegrationResponse(
        id=str(integration.id),
        organization_id=str(integration.organization_id),
        location_id=(
            str(integration.location_id) if integration.location_id else None
        ),
        organization_name=organization_name,
        location_name=location_name,
        provider=integration.provider,
        name=integration.name,
        status=integration.status,
        is_enabled=integration.is_enabled,
        base_url=integration.base_url,
        auth_mode=integration.auth_mode,
        tls_mode=integration.tls_mode,
        tls_pinned_sha256=integration.tls_pinned_sha256,
        tls_trust_decided_at=integration.tls_trust_decided_at,
        controller_id=integration.controller_id,
        controller_version=integration.controller_version,
        external_site_id=integration.external_site_id,
        external_site_name=integration.external_site_name,
        guest_ssid_id=integration.guest_ssid_id,
        guest_ssid_name=integration.guest_ssid_name,
        session_duration_seconds=integration.session_duration_seconds,
        sync_interval_seconds=integration.sync_interval_seconds,
        last_sync_at=integration.last_sync_at,
        last_sync_status=integration.last_sync_status,
        last_error_code=integration.last_error_code,
        last_error_message=integration.last_error_message,
        last_error_at=integration.last_error_at,
        device_count=numbers.get("device_count", 0),
        client_count=numbers.get("client_count", 0),
        active_authorization_count=numbers.get("active_authorization_count", 0),
        has_credentials=integration.credentials_encrypted is not None,
        # Both computed on read, never stored. Every input is already a
        # column on this row, so a persisted copy would be a second set of
        # the same facts able to disagree with them the moment a mapping is
        # edited -- the reasoning `validators.portal_readiness_gaps` already
        # spells out for itself.
        portal_url_scheme=portal_url.scheme if portal_url else None,
        portal_url_host_and_query=portal_url.host_and_query if portal_url else None,
        portal_readiness_gaps=[gap.value for gap in portal_readiness_gaps(integration)],
        created_at=integration.created_at,
        updated_at=integration.updated_at,
    )


def _tls_fields(observation) -> dict[str, object]:  # noqa: ANN001
    """The certificate half of a ``TestConnectionResponse``.

    One helper for all three probe routes so the platform probe and the two
    customer probes cannot drift into reporting different subsets of the
    same observation. ``None`` in means every field absent, which is how
    "we could not look at the certificate" is expressed -- distinct from
    any verdict about it.
    """
    if observation is None:
        return {}
    return {
        "tls_fingerprint_sha256": observation.fingerprint_sha256,
        "tls_chain_trusted": observation.chain_trusted,
        "tls_matches_pin": observation.matches_pin,
        "tls_certificate_subject": observation.subject,
        "tls_certificate_issuer": observation.issuer,
        "tls_certificate_expires_at": observation.not_valid_after,
    }


def _event_response(event) -> NetworkIntegrationEventResponse:  # noqa: ANN001
    return NetworkIntegrationEventResponse(
        id=str(event.id),
        event_type=event.event_type,
        status=event.status,
        error_code=event.error_code,
        message=event.message,
        context=event.context or {},
        created_at=event.created_at,
    )


# ============================================================================
# Platform (Master console) -- registered FIRST so the literal
# `/platform/...` segments are never matched by `/{integration_id}`.
# ============================================================================


@router.get(
    "/platform/summary",
    response_model=ApiResponse[PlatformNetworkIntegrationSummaryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            RequirePermission("network_integrations.read", scope=ScopeType.GLOBAL)
        )
    ],
)
async def get_platform_summary(
    request: Request,
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    """Platform-wide counts. Unscoped by definition -- it counts tenants.

    GLOBAL scope is the whole access control here; see this module's
    docstring and ``repository.platform_summary``.
    """
    summary = await service.get_platform_summary()
    payload = PlatformNetworkIntegrationSummaryResponse(
        tenant_count=summary.tenant_count,
        integration_count=summary.integration_count,
        connected_count=summary.connected_count,
        error_count=summary.error_count,
        disabled_count=summary.disabled_count,
        device_count=summary.device_count,
        client_count=summary.client_count,
        active_authorization_count=summary.active_authorization_count,
        last_sync_at=summary.last_sync_at,
    )
    return build_response(
        success=True,
        message="Network integration summary retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/platform/integrations",
    response_model=ApiResponse[PlatformNetworkIntegrationListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            RequirePermission("network_integrations.read", scope=ScopeType.GLOBAL)
        )
    ],
)
async def list_platform_integrations(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    provider: str | None = Query(default=None),
    integration_status: str | None = Query(default=None, alias="status"),
    q: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    """Cross-tenant list for the Master console.

    ``organization_id`` here is a *filter a platform operator chose*, not
    a tenant boundary derived from their identity -- omitting it returns
    every tenant's integrations, which is the requirement. The GLOBAL
    scope on the permission is what makes that safe.
    """
    integrations, meta, names = await service.list_platform_integrations(
        organization_id=organization_id,
        provider=provider,
        status=integration_status,
        query=q,
        page=page,
        page_size=page_size,
    )
    items = []
    for integration in integrations:
        organization_name, location_name = names.get(integration.id, (None, None))
        items.append(
            _integration_response(
                integration,
                counts=await service.counts_for(integration),
                organization_name=organization_name,
                location_name=location_name,
            )
        )
    payload = PlatformNetworkIntegrationListResponse(
        items=items, **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Network integrations retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/platform/integrations/{integration_id}",
    response_model=ApiResponse[NetworkIntegrationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            RequirePermission("network_integrations.read", scope=ScopeType.GLOBAL)
        )
    ],
)
async def get_platform_integration(
    request: Request,
    integration_id: uuid.UUID,
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    integration, (organization_name, location_name) = (
        await service.get_platform_integration(integration_id)
    )
    return build_response(
        success=True,
        message="Network integration retrieved",
        data=_integration_response(
            integration,
            counts=await service.counts_for(integration),
            organization_name=organization_name,
            location_name=location_name,
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/platform/integrations/{integration_id}/events",
    response_model=ApiResponse[NetworkIntegrationEventListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            RequirePermission("network_integrations.read", scope=ScopeType.GLOBAL)
        )
    ],
)
async def list_platform_integration_events(
    request: Request,
    integration_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    events, meta = await service.list_events(
        integration_id,
        requesting_organization_id=None,
        page=page,
        page_size=page_size,
    )
    payload = NetworkIntegrationEventListResponse(
        items=[_event_response(event) for event in events],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Network integration events retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/platform/integrations/{integration_id}/enable",
    response_model=ApiResponse[NetworkIntegrationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            RequirePermission("network_integrations.update", scope=ScopeType.GLOBAL)
        )
    ],
)
async def enable_platform_integration(
    request: Request,
    integration_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    integration = await service.set_platform_enabled(
        integration_id, actor_user_id=_actor_id(actor), is_enabled=True
    )
    return build_response(
        success=True,
        message="Network integration enabled",
        data=_integration_response(
            integration, counts=await service.counts_for(integration)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/platform/integrations/{integration_id}/disable",
    response_model=ApiResponse[NetworkIntegrationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            RequirePermission("network_integrations.update", scope=ScopeType.GLOBAL)
        )
    ],
)
async def disable_platform_integration(
    request: Request,
    integration_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    """Stop this platform polling a customer's controller.

    A deliberate cross-tenant write -- the only one in this domain. It
    exists so a platform operator can halt traffic against a customer's
    hardware during an incident without waiting for that customer to log
    in. Audited on every call with the target organization recorded; see
    ``service.set_platform_enabled``.
    """
    integration = await service.set_platform_enabled(
        integration_id, actor_user_id=_actor_id(actor), is_enabled=False
    )
    return build_response(
        success=True,
        message="Network integration disabled",
        data=_integration_response(
            integration, counts=await service.counts_for(integration)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/platform/integrations/{integration_id}/test-connection",
    response_model=ApiResponse[TestConnectionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            RequirePermission("network_integrations.update", scope=ScopeType.GLOBAL)
        )
    ],
)
async def test_platform_integration_connection(
    request: Request,
    integration_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    info, error, observation = await service.test_platform_connection(
        integration_id, actor_user_id=_actor_id(actor)
    )
    payload = TestConnectionResponse(
        ok=error is None,
        provider="omada",
        controller_id=info.controller_id if info else None,
        controller_version=info.controller_version if info else None,
        model=info.model if info else None,
        supports_openapi=bool(info.supports_openapi) if info else False,
        error_code=error.code.value if error else None,
        message=error.message if error else None,
        **_tls_fields(observation),
    )
    return build_response(
        success=error is None,
        message="Connection test completed",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/platform/onboard",
    response_model=ApiResponse[PlatformOnboardResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            RequirePermission("network_integrations.create", scope=ScopeType.GLOBAL)
        )
    ],
)
async def onboard_platform_integration(
    request: Request,
    payload: PlatformOnboardRequest,
    actor: AuthUser = Depends(CurrentUser),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    """Register a customer's controller *and* its fleet device row.

    The Master-driven onboarding path (contract §11.6). Creating both rows
    is the point: ``guest_sessions.router_id`` is NOT NULL, so a venue whose
    only equipment is a controller cannot issue a guest session -- and
    therefore cannot get anyone online -- until something in the fleet
    represents it.

    GLOBAL-scoped, and the tenant is named in the body rather than taken
    from a header: a platform operator has no organization of their own.
    The pairing is re-verified where it can actually be checked -- the
    router domain resolves the location *with* that organization id and
    refuses one belonging to another tenant.

    Customer self-service (``POST /network-integrations``) is unchanged and
    still creates no fleet row.
    """
    integration, fleet_device = await service.create_integration_with_fleet_device(
        actor_user_id=_actor_id(actor),
        organization_id=payload.organization_id,
        location_id=payload.location_id,
        provider=payload.provider,
        name=payload.name,
        base_url=payload.base_url,
        auth_mode=payload.auth_mode,
        controller_id=payload.controller_id,
        controller_model=payload.controller_model,
        serial_number=payload.serial_number,
        mac_address=payload.mac_address,
        external_site_id=payload.external_site_id,
        external_site_name=payload.external_site_name,
        guest_ssid_id=payload.guest_ssid_id,
        guest_ssid_name=payload.guest_ssid_name,
        session_duration_seconds=payload.session_duration_seconds,
        sync_interval_seconds=payload.sync_interval_seconds,
        is_enabled=payload.is_enabled,
        tls_mode=payload.tls_mode,
        tls_pinned_sha256=payload.tls_pinned_sha256,
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        username=payload.username,
        password=payload.password,
    )
    response = PlatformOnboardResponse(
        integration=_integration_response(
            integration, counts=await service.counts_for(integration)
        ),
        router_id=fleet_device.id,
        router_serial_number=fleet_device.serial_number,
        router_vendor=fleet_device.vendor,
        synthetic_identity=bool(
            (fleet_device.settings or {}).get("synthetic_identity", False)
        ),
    )
    return build_response(
        success=True,
        message="Controller onboarded",
        data=response.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Customer: pre-save probe (literal path, registered before `/{id}`)
# ============================================================================


@router.post(
    "/test-connection",
    response_model=ApiResponse[TestConnectionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.create"))],
)
async def test_connection(
    request: Request,
    payload: TestConnectionRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    """Probe a controller before any row exists. Persists nothing.

    Gated on ``.create`` rather than ``.read``: it makes this platform
    open an authenticated outbound connection to an address the caller
    chose, which is a write-shaped action even though no row is written.
    An audit entry is recorded either way -- see
    ``service.test_connection_unsaved``.

    Returns 200 with ``ok: false`` on a controller failure rather than a
    502, so the wizard can render the specific reason inline next to the
    form instead of the browser swallowing it.
    """
    info, error, observation = await service.test_connection_unsaved(
        actor_user_id=_actor_id(actor),
        requesting_organization_id=requesting_organization_id,
        provider=payload.provider,
        base_url=payload.base_url,
        auth_mode=payload.auth_mode,
        controller_id=payload.controller_id,
        tls_mode=payload.tls_mode,
        tls_pinned_sha256=payload.tls_pinned_sha256,
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        username=payload.username,
        password=payload.password,
    )
    response = TestConnectionResponse(
        ok=error is None,
        provider=payload.provider,
        controller_id=info.controller_id if info else None,
        controller_version=info.controller_version if info else None,
        model=info.model if info else None,
        supports_openapi=bool(info.supports_openapi) if info else False,
        error_code=error.code.value if error else None,
        message=error.message if error else None,
        **_tls_fields(observation),
    )
    return build_response(
        success=error is None,
        message="Connection test completed",
        data=response.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Customer: integration CRUD
# ============================================================================


@router.get(
    "",
    response_model=ApiResponse[NetworkIntegrationListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.read"))],
)
async def list_integrations(
    request: Request,
    location_id: uuid.UUID | None = Query(default=None),
    provider: str | None = Query(default=None),
    integration_status: str | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    integrations, meta = await service.list_integrations(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        provider=provider,
        status=integration_status,
        page=page,
        page_size=page_size,
    )
    items = [
        _integration_response(
            integration, counts=await service.counts_for(integration)
        )
        for integration in integrations
    ]
    payload = NetworkIntegrationListResponse(items=items, **_pagination_fields(meta))
    return build_response(
        success=True,
        message="Network integrations retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "",
    response_model=ApiResponse[NetworkIntegrationResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("network_integrations.create"))],
)
async def create_integration(
    request: Request,
    payload: NetworkIntegrationCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    integration = await service.create_integration(
        actor_user_id=_actor_id(actor),
        requesting_organization_id=requesting_organization_id,
        provider=payload.provider,
        name=payload.name,
        base_url=payload.base_url,
        auth_mode=payload.auth_mode,
        controller_id=payload.controller_id,
        location_id=(
            uuid.UUID(payload.location_id) if payload.location_id else None
        ),
        external_site_id=payload.external_site_id,
        external_site_name=payload.external_site_name,
        guest_ssid_id=payload.guest_ssid_id,
        guest_ssid_name=payload.guest_ssid_name,
        session_duration_seconds=payload.session_duration_seconds,
        sync_interval_seconds=payload.sync_interval_seconds,
        is_enabled=payload.is_enabled,
        tls_mode=payload.tls_mode,
        tls_pinned_sha256=payload.tls_pinned_sha256,
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        username=payload.username,
        password=payload.password,
    )
    return build_response(
        success=True,
        message="Network integration created",
        data=_integration_response(
            integration, counts=await service.counts_for(integration)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{integration_id}",
    response_model=ApiResponse[NetworkIntegrationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.read"))],
)
async def get_integration(
    request: Request,
    integration_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    integration = await service.get_integration(
        integration_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Network integration retrieved",
        data=_integration_response(
            integration, counts=await service.counts_for(integration)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.patch(
    "/{integration_id}",
    response_model=ApiResponse[NetworkIntegrationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.update"))],
)
async def update_integration(
    request: Request,
    integration_id: uuid.UUID,
    payload: NetworkIntegrationUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    """Partial update.

    ``exclude_unset`` rather than dropping ``None`` values: this domain
    has fields a caller must be able to *clear* (``location_id``,
    ``external_site_id``), and a filter that discards ``None`` makes
    "unset this" indistinguishable from "don't touch this".
    """
    fields = payload.model_dump(exclude_unset=True)
    if "location_id" in fields and fields["location_id"] is not None:
        fields["location_id"] = uuid.UUID(str(fields["location_id"]))
    integration = await service.update_integration(
        integration_id,
        actor_user_id=_actor_id(actor),
        requesting_organization_id=requesting_organization_id,
        fields=fields,
    )
    return build_response(
        success=True,
        message="Network integration updated",
        data=_integration_response(
            integration, counts=await service.counts_for(integration)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{integration_id}",
    response_model=ApiResponse[NetworkIntegrationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.delete"))],
)
async def delete_integration(
    request: Request,
    integration_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    integration = await service.delete_integration(
        integration_id,
        actor_user_id=_actor_id(actor),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Network integration deleted",
        data=_integration_response(integration).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{integration_id}/test-connection",
    response_model=ApiResponse[TestConnectionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.update"))],
)
async def test_integration_connection(
    request: Request,
    integration_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    info, error, observation = await service.test_integration_connection(
        integration_id,
        actor_user_id=_actor_id(actor),
        requesting_organization_id=requesting_organization_id,
    )
    payload = TestConnectionResponse(
        ok=error is None,
        provider="omada",
        controller_id=info.controller_id if info else None,
        controller_version=info.controller_version if info else None,
        model=info.model if info else None,
        supports_openapi=bool(info.supports_openapi) if info else False,
        error_code=error.code.value if error else None,
        message=error.message if error else None,
        **_tls_fields(observation),
    )
    return build_response(
        success=error is None,
        message="Connection test completed",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{integration_id}/credentials",
    response_model=ApiResponse[NetworkIntegrationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.update"))],
)
async def rotate_credentials(
    request: Request,
    integration_id: uuid.UUID,
    payload: NetworkIntegrationCredentialRotateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    """Replace the stored controller credentials. Write-only.

    The old value is never decrypted, never compared and never returned --
    see ``service.rotate_credentials``. The response is the ordinary
    integration shape, whose only statement about credentials is
    ``has_credentials: true``.
    """
    integration = await service.rotate_credentials(
        integration_id,
        actor_user_id=_actor_id(actor),
        requesting_organization_id=requesting_organization_id,
        auth_mode=payload.auth_mode,
        tls_mode=payload.tls_mode,
        tls_pinned_sha256=payload.tls_pinned_sha256,
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        username=payload.username,
        password=payload.password,
    )
    return build_response(
        success=True,
        message="Controller credentials updated",
        data=_integration_response(
            integration, counts=await service.counts_for(integration)
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{integration_id}/sync",
    response_model=ApiResponse[NetworkIntegrationSyncResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.update"))],
)
async def sync_integration(
    request: Request,
    integration_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    outcome = await service.sync_integration(
        integration_id,
        actor_user_id=_actor_id(actor),
        requesting_organization_id=requesting_organization_id,
    )
    payload = NetworkIntegrationSyncResponse(
        id=str(outcome.integration_id),
        status=outcome.status,
        synced=outcome.synced,
        device_count=outcome.device_count,
        client_count=outcome.client_count,
        site_count=outcome.site_count,
        error_code=outcome.error_code,
        message=outcome.message,
    )
    return build_response(
        success=outcome.synced,
        message="Sync completed" if outcome.synced else "Sync failed",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{integration_id}/status",
    response_model=ApiResponse[NetworkIntegrationStatusResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.read"))],
)
async def get_integration_status(
    request: Request,
    integration_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    """Cached status. Deliberately not a live controller round trip -- a
    dashboard polls this, and making it live would mean every open browser
    tab generating traffic against a venue's hardware."""
    payload = await service.get_status(
        integration_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Network integration status retrieved",
        data=NetworkIntegrationStatusResponse(**payload).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Customer: live controller reads
#
# Every one of these four refuses a `legacy`-mode integration with
# OMADA_API_UNSUPPORTED rather than returning an empty list (contract
# change CR-002) -- an operator credential cannot read controller
# inventory, and `[]` would read to a venue owner as "you have no access
# points", which is a false statement about their hardware. See
# `exceptions.NetworkIntegrationInventoryRequiresOpenApiError`.
# ============================================================================


@router.get(
    "/{integration_id}/sites",
    response_model=ApiResponse[NetworkIntegrationSiteListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.read"))],
)
async def list_sites(
    request: Request,
    integration_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    sites = await service.list_sites(
        integration_id, requesting_organization_id=requesting_organization_id
    )
    payload = NetworkIntegrationSiteListResponse(
        sites=[
            NetworkIntegrationSiteResponse(
                site_id=site.site_id,
                name=site.name,
                device_count=site.device_count,
                client_count=site.client_count,
            )
            for site in sites
        ]
    )
    return build_response(
        success=True,
        message="Controller sites retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{integration_id}/ssids",
    response_model=ApiResponse[NetworkIntegrationSsidListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.read"))],
)
async def list_ssids(
    request: Request,
    integration_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    ssids = await service.list_ssids(
        integration_id, requesting_organization_id=requesting_organization_id
    )
    payload = NetworkIntegrationSsidListResponse(
        ssids=[
            NetworkIntegrationSsidResponse(
                ssid_id=ssid.ssid_id,
                name=ssid.name,
                portal_enabled=ssid.portal_enabled,
            )
            for ssid in ssids
        ]
    )
    return build_response(
        success=True,
        message="Controller SSIDs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{integration_id}/devices",
    response_model=ApiResponse[NetworkIntegrationDeviceListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.read"))],
)
async def list_devices(
    request: Request,
    integration_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    devices = await service.list_devices(
        integration_id, requesting_organization_id=requesting_organization_id
    )
    payload = NetworkIntegrationDeviceListResponse(
        devices=[
            NetworkIntegrationDeviceResponse(
                mac=device.mac,
                name=device.name,
                device_type=device.device_type,
                model=device.model,
                status=device.status,
                ip_address=device.ip_address,
                firmware_version=device.firmware_version,
                uptime_seconds=device.uptime_seconds,
                client_count=device.client_count,
            )
            for device in devices
        ]
    )
    return build_response(
        success=True,
        message="Controller devices retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{integration_id}/clients",
    response_model=ApiResponse[NetworkIntegrationClientListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.read"))],
)
async def list_clients(
    request: Request,
    integration_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    clients = await service.list_clients(
        integration_id, requesting_organization_id=requesting_organization_id
    )
    payload = NetworkIntegrationClientListResponse(
        clients=[
            NetworkIntegrationClientResponse(
                mac=client.mac,
                name=client.name,
                ip_address=client.ip_address,
                ssid=client.ssid,
                ap_mac=client.ap_mac,
                radio_id=client.radio_id,
                vlan_id=client.vlan_id,
                is_guest=client.is_guest,
                is_authorized=client.is_authorized,
                connected_since=client.connected_since,
                duration_seconds=client.duration_seconds,
                traffic_down_bytes=client.traffic_down_bytes,
                traffic_up_bytes=client.traffic_up_bytes,
                signal_dbm=client.signal_dbm,
            )
            for client in clients
        ]
    )
    return build_response(
        success=True,
        message="Controller clients retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/{integration_id}/clients/disconnect",
    response_model=ApiResponse[NetworkIntegrationDisconnectGuestResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.update"))],
)
async def disconnect_guest(
    request: Request,
    integration_id: uuid.UUID,
    payload: NetworkIntegrationDisconnectGuestRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    """End one guest's network access now.

    A sibling of ``GET /{integration_id}/clients`` and deliberately placed
    under it: the integration id the caller already needs to *see* the
    clients is the one that scopes the disconnect, so the control can live
    on that table with nothing extra to fetch.

    ``network_integrations.update`` rather than a new ``.execute``: the
    module seeds create/read/update/delete/manage and nothing else, and
    inventing an action here would leave every existing role without it
    until the seed and its tests were changed too. ``update`` is the
    right blast radius in the meantime -- a caller who can rewrite this
    integration's credentials can certainly end one guest's session.

    A 501 means the integration has no hotspot operator credentials, which
    is the one configuration where the controller cannot be asked. It is
    not the old "Omada cannot do this"; see
    ``exceptions.NetworkIntegrationDeauthorizationUnsupportedError``.
    """
    outcome = await service.disconnect_guest(
        integration_id,
        client_mac=payload.client_mac,
        reason=payload.reason,
        actor_user_id=_actor_id(actor),
        requesting_organization_id=requesting_organization_id,
    )
    body = NetworkIntegrationDisconnectGuestResponse(
        disconnected=outcome.disconnected,
        provider=outcome.provider,
        client_mac=outcome.client_mac,
        had_active_authorization=outcome.had_active_authorization,
        deauthorized_at=outcome.deauthorized_at,
        guest_session_id=(
            str(outcome.guest_session_id) if outcome.guest_session_id else None
        ),
        guest_session_ended=outcome.guest_session_ended,
    )
    return build_response(
        success=True,
        message="Guest access ended",
        data=body.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{integration_id}/events",
    response_model=ApiResponse[NetworkIntegrationEventListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_integrations.read"))],
)
async def list_integration_events(
    request: Request,
    integration_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    events, meta = await service.list_events(
        integration_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = NetworkIntegrationEventListResponse(
        items=[_event_response(event) for event in events],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Network integration events retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Portal (public, no RBAC, rate-limited)
# ============================================================================


@portal_router.post(
    "/portal/authorize",
    response_model=ApiResponse[PortalAuthorizeResponse],
    status_code=status.HTTP_200_OK,
)
async def authorize_portal_client(
    request: Request,
    payload: PortalAuthorizeRequest,
    service: NetworkIntegrationService = Depends(get_network_integration_service),
):
    """Authorize a guest's device on the venue's controller.

    **Public and unauthenticated, on purpose.** A guest joining WiFi has
    no platform login and no RBAC grants, so there is no permission to
    check -- the same category of exception as ``GET
    /captive-portal/resolve`` and ``POST /vouchers/redeem``, both of which
    are already allowlisted in
    ``tests/unit/test_route_permission_coverage.py`` for this reason.

    **It authenticates nobody.** OTP, voucher, consent and analytics stay
    entirely in ``app.domains.guest``; by the time this is called, that
    domain has already decided the guest may go online and has issued a
    ``GuestSession``. This is the network-enforcement step that follows --
    the Omada equivalent of the existing MikroTik ``link-login-only``
    POST.

    What stands in for authentication is proof of a genuine session:
    ``service.authorize_portal_client`` requires an ``ACTIVE``
    ``GuestSession`` whose own ``organization_id`` *and* ``location_id``
    match the body, and resolves the integration from the **session's**
    venue rather than the body's -- so a body that lied consistently still
    cannot reach a foreign controller. A ``TERMINATED`` session is refused,
    which matters: that is the punitive kill an admin used to throw an
    abusive guest off, and honouring it here would hand them a fresh
    authorization.

    Two rate-limit layers, neither sufficient alone: per client IP in
    ``app.middleware.rate_limit`` (bounds one source rotating session
    ids), and per guest session in this domain's service (bounds one
    session replayed from many sources).

    The guest's browser never sees controller credentials and never talks
    to the controller.
    """
    outcome = await service.authorize_portal_client(
        session_id=uuid.UUID(payload.session_id),
        organization_id=uuid.UUID(payload.organization_id),
        location_id=uuid.UUID(payload.location_id),
        provider=payload.provider,
        client_mac=payload.client_mac,
        site=payload.site,
        ap_mac=payload.ap_mac,
        ssid_name=payload.ssid_name,
        radio_id=payload.radio_id,
        gateway_mac=payload.gateway_mac,
        vid=payload.vid,
        t=payload.t,
        redirect_url=payload.redirect_url,
    )
    response = PortalAuthorizeResponse(
        authorized=outcome.authorized,
        provider=outcome.provider,
        expires_at=outcome.expires_at,
        redirect_url=outcome.redirect_url,
    )
    return build_response(
        success=outcome.authorized,
        message=(
            "Guest authorized on the network controller"
            if outcome.authorized
            else "The network controller declined the authorization"
        ),
        data=response.model_dump(),
        request_id=_request_id(request),
    )
