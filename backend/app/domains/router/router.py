"""FastAPI routes for the Router domain: device CRUD, lifecycle management,
and zero-touch provisioning.

Responses use the project's standard envelope (``ApiResponse`` /
``build_response``), matching every other domain's router -- except the
device-presented check-in endpoint, which deliberately does not (see
``docs/router/ROUTER_ARCHITECTURE.md`` §5). Every mutating (and cross-
tenant-sensitive read) user-facing endpoint is gated by RBAC's existing
``RequirePermission`` dependency against the already-seeded ``routers.*``/
``router_provisioning.*`` permission keys -- this domain defines no
permission keys of its own.

``location_id`` appears in the path for the two collection endpoints (list/
create, nested under ``/locations/{location_id}/routers``) since a router is
always registered at a specific location; the remaining endpoints address a
router directly by its own id. Every user-facing endpoint additionally
resolves ``CurrentOrganization`` (``X-Organization-Id``) and passes it to
``RouterService`` as ``requesting_organization_id`` so tenant scoping is
enforced the same way ``OrganizationService``/``LocationService`` enforce it
-- not just left to the permission check, which only verifies *what* the
caller can do, not *which tenant's data* they are doing it to.

**Provisioning-token generation is approval-gated**: ``router_provisioning``
is the only permission module seeded with an ``approve`` action alongside
``create`` (``routers`` itself has no ``approve`` action) -- a strong signal
this action exists specifically to gate issuing a bearer credential that lets
a physical device join the network. ``POST /routers/{id}/provisioning-token``
therefore requires *both* ``router_provisioning.create`` and
``router_provisioning.approve``.

**The device check-in endpoint is not a normal authenticated-user
endpoint.** ``POST /routers/provisioning/check-in`` carries no
``RequirePermission``/``CurrentUser`` dependency at all -- the physical
device has no platform user identity or JWT; its only credential is the
provisioning token itself, presented in the request body and validated by
``RouterService.check_in`` (hash-compare against ``token_hash``, expiry,
single-use). See ``docs/router/ROUTER_ARCHITECTURE.md`` §5 for the full
reasoning, including why this was chosen over a bespoke bearer-header auth
scheme.

**Additive dependency on Module 009 Part 2
(``app.domains.router_agent``).** ``provisioning_check_in`` composes with
``RouterAgentService.issue_credential_for_router`` to additionally issue
that module's persistent, device-facing bearer credential in the same
response -- see ``ProvisioningCheckInResponse``'s own docstring and
``app.domains.router_agent.service``'s module docstring for why this was
chosen over a separate, later "activate" endpoint. Nothing else in this
file changed for that module's sake.

**Additive dependency on Module 009 Part 3
(``app.domains.wireguard``).** ``provisioning_check_in`` also, optionally,
composes with ``WireGuardService.create_tunnel`` (its additive
``external_public_key`` parameter) when the device-presented request
carries ``wireguard_public_key`` -- the zero-touch bootstrap-script path
described in ``app.domains.network_config.renderers.render_bootstrap_script``'s
own docstring. This reuses ``WireGuardService``'s real tunnel-IP allocator
rather than a second, parallel one; see that method's own docstring for
why the device's public key is accepted as-is instead of a platform-
generated one.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import uuid

import httpx
from fastapi import APIRouter, Depends, Query, Request, Response, status
from redis.asyncio import Redis

from app.common.responses import ApiResponse, build_response
from app.database.redis import get_redis_client
from app.domains.auth.models import AuthUser
from app.domains.guest.dependencies import get_radius_service
from app.domains.guest.router import deregister_radius_nas_client
from app.domains.guest.service import RadiusService
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType
from app.domains.router_agent.dependencies import get_router_agent_service
from app.domains.router_agent.service import RouterAgentService
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.exceptions import WireGuardPeerNotFoundError
from app.domains.wireguard.service import WireGuardService

from .dependencies import get_router_service
from .device_adapters import (
    DeviceInterfaceQueryError,
    list_available_device_interfaces,
    reboot_device,
)
from .enums import RouterStatus
from .models import Router
from .schemas import (
    DeviceConnectionResponse,
    DeviceInterfaceResponse,
    DeviceInterfacesResponse,
    HeartbeatRequest,
    MessageResponse,
    ProvisioningCheckInRequest,
    ProvisioningCheckInResponse,
    ProvisioningTokenResponse,
    RouterCreateRequest,
    RouterListResponse,
    RouterResponse,
    RouterUpdateRequest,
    WebfigSessionResponse,
)
from .service import RouterService

router = APIRouter(tags=["Routers"])

logger = logging.getLogger(__name__)


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _router_response(router_device: Router) -> RouterResponse:
    return RouterResponse(
        id=str(router_device.id),
        location_id=str(router_device.location_id),
        organization_id=str(router_device.organization_id),
        name=router_device.name,
        serial_number=router_device.serial_number,
        mac_address=router_device.mac_address,
        model=router_device.model,
        vendor=router_device.vendor,
        routeros_version=router_device.routeros_version,
        management_ip_address=router_device.management_ip_address,
        public_ip_address=router_device.public_ip_address,
        status=RouterStatus(router_device.status),
        last_seen_at=router_device.last_seen_at,
        last_health_check_at=router_device.last_health_check_at,
        health_status=router_device.health_status,
        has_api_credentials=router_device.api_credentials_encrypted is not None,
        settings=router_device.settings,
        created_at=router_device.created_at,
        updated_at=router_device.updated_at,
    )


# ============================================================================
# Collection endpoints (nested under a location)
# ============================================================================


@router.get(
    "/locations/{location_id}/routers",
    response_model=ApiResponse[RouterListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.read"))],
)
async def list_routers(
    request: Request,
    location_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    search: str | None = Query(default=None, max_length=200),
    router_status: RouterStatus | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    routers, meta = await router_service.list_routers(
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
        search=search,
        status=router_status,
    )
    payload = RouterListResponse(
        items=[_router_response(item) for item in routers],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Routers retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/locations/{location_id}/routers",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("routers.create"))],
)
async def create_router(
    request: Request,
    location_id: uuid.UUID,
    payload: RouterCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    created = await router_service.create_router(
        actor_user_id=uuid.UUID(user.id),
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
        name=payload.name,
        serial_number=payload.serial_number,
        mac_address=payload.mac_address,
        model=payload.model,
        vendor=payload.vendor,
        management_ip_address=payload.management_ip_address,
        public_ip_address=payload.public_ip_address,
        api_username=payload.api_username,
        api_secret=payload.api_secret,
        settings=payload.settings,
    )
    return build_response(
        success=True,
        message="Router registered",
        data=_router_response(created).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Direct router endpoints
# ============================================================================


@router.get(
    "/routers/{router_id}",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.read"))],
)
async def get_router(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    router_device = await router_service.get_router(
        router_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Router retrieved",
        data=_router_response(router_device).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/routers/{router_id}",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.update"))],
)
async def update_router(
    request: Request,
    router_id: uuid.UUID,
    payload: RouterUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    data = payload.model_dump(exclude_unset=True)
    updated = await router_service.update_router(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        data=data,
    )
    return build_response(
        success=True,
        message="Router updated",
        data=_router_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/routers/{router_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    # Decommissioning a router is infra-level and hard to reverse (this is
    # exactly the action that, when reachable by an org-scoped role, let a
    # QA pass on a customer token delete a live physical router's platform
    # record in production). Explicit GLOBAL scope means only a
    # master-console role assignment can call this, regardless of which
    # X-Organization-Id header the caller sends -- an "Organization Owner"
    # role holding routers.delete at *organization* scope (legitimate for
    # normal router CRUD) no longer qualifies.
    dependencies=[Depends(RequirePermission("routers.delete", scope=ScopeType.GLOBAL))],
)
async def decommission_router(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
    radius_service: RadiusService = Depends(get_radius_service),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
):
    # Confirmed gap, same shape as the RadiusNasClient one below: a
    # decommissioned router's WireGuardPeer row was never revoked here --
    # ``WireGuardService.revoke_tunnel`` exists (releases the tunnel IP
    # back to the pool and marks the peer REVOKED) but nothing ever called
    # it from this endpoint. Run *before* ``decommission_router`` below,
    # not after: that call soft-deletes the Router row, and
    # ``revoke_tunnel``'s own router lookup excludes soft-deleted routers
    # by default, so revocation would 404 on its own target if attempted
    # afterward. Best-effort and non-fatal for the same reason the RADIUS
    # cleanup below is: most routers may not have completed WireGuard
    # enrollment at all, and a WireGuard-side failure here must not block
    # the decommission itself.
    try:
        await wireguard_service.revoke_tunnel(
            actor_user_id=uuid.UUID(user.id),
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
        )
    except WireGuardPeerNotFoundError:
        pass
    except Exception:
        logger.warning(
            "router_decommission_wireguard_revoke_failed",
            extra={"router_id": str(router_id)},
        )

    await router_service.decommission_router(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    # Confirmed gap: this router's RadiusNasClient row (if it ever
    # registered one) previously outlived decommissioning untouched --
    # ``ondelete="CASCADE"`` on that table's router_id FK never fires,
    # since decommissioning only soft-deletes the Router row rather than
    # actually deleting it, and even a real DB-level delete would still
    # never have told the live FreeRADIUS server to drop its
    # clients.conf entry. Left uncleaned, that stale entry can collide
    # with a future router re-provisioned onto the same physical public
    # IP (same site, ISP just handed the connection to a new device
    # registration) -- see ``deregister_radius_nas_client``'s own
    # docstring for the full write-up. Best-effort and non-fatal: most
    # routers never register a NAS at all, and a RADIUS-side failure here
    # must not block the decommission itself, which has already
    # succeeded by this point.
    try:
        existing, _meta = await radius_service.list_nas_clients(
            requesting_organization_id=None,
            router_id=router_id,
            page=1,
            page_size=1,
        )
        if existing:
            await deregister_radius_nas_client(
                radius_service,
                nas_id=existing[0].id,
                requesting_organization_id=None,
                actor_user_id=uuid.UUID(user.id),
            )
    except Exception:
        logger.warning(
            "router_decommission_radius_nas_cleanup_failed",
            extra={"router_id": str(router_id)},
        )
    return build_response(
        success=True,
        message="Router decommissioned",
        data=MessageResponse(message="Router decommissioned").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/suspend",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.manage"))],
)
async def suspend_router(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    updated = await router_service.suspend_router(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Router suspended",
        data=_router_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/reinstate",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.manage"))],
)
async def reinstate_router(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    updated = await router_service.reinstate_router(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Router reinstated",
        data=_router_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/routers/{router_id}/device-connection",
    response_model=ApiResponse[DeviceConnectionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.manage"))],
)
async def get_device_connection(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    """The one place this domain hands back a *decrypted* credential, not
    just its encrypted-at-rest form -- gated by the same ``routers.manage``
    permission as heartbeat/suspend/reinstate (real, high-trust device
    operations), never a lower-tier read permission. Two callers today:
    the dashboard's own SSH-capable config-push bridge (a small agent the
    browser calls directly, to apply a rendered network config to the real
    device without routing the push itself through this backend), and
    Master Console's "Remote Access" panel (a human clicking "reveal" to
    get WinBox connection details). Routes through
    ``RouterService.reveal_credentials`` rather than calling
    ``get_router``/``get_decrypted_api_secret`` directly so both callers
    leave an audit trail (``AuditAction.ROUTER_CREDENTIALS_REVEALED``) --
    unlike most of this domain's audited actions, this one changes no
    state, it exposes a secret, so "who saw this and when" is the record
    worth keeping."""
    router_row = await router_service.reveal_credentials(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    password = router_service.get_decrypted_api_secret(router_row)
    return build_response(
        success=True,
        message="Device connection resolved",
        data=DeviceConnectionResponse(
            host=router_row.management_ip_address or router_row.public_ip_address,
            username=router_row.api_username,
            password=password,
        ).model_dump(),
        request_id=_request_id(request),
    )


WEBFIG_SESSION_KEY_TEMPLATE = "webfig_session:{token}"
WEBFIG_SESSION_TTL_SECONDS = 600


@router.post(
    "/routers/{router_id}/webfig-session",
    response_model=ApiResponse[WebfigSessionResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("routers.manage"))],
)
async def create_webfig_session(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
    redis: Redis = Depends(get_redis_client),
):
    """Mints a short-lived, single-router-scoped opaque token so Master
    Console's "Open web console" iframe can reach ``GET .../webfig/...``
    below *without* a ``Bearer`` header -- a browser navigating an
    ``<iframe src>`` has no way to attach one, so that endpoint can't sit
    behind the normal ``CurrentUser``/``RequirePermission`` dependency
    chain the rest of this domain uses. This endpoint is the actual
    authorization check (real ``routers.manage`` permission, real tenant
    scoping via ``reveal_credentials``); the token it returns is a
    capability, not a credential -- it grants proxy access to exactly this
    one router's WebFig for ``WEBFIG_SESSION_TTL_SECONDS``, nothing else,
    and is never the caller's own session/JWT."""
    await router_service.reveal_credentials(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    token = secrets.token_urlsafe(32)
    await redis.set(
        WEBFIG_SESSION_KEY_TEMPLATE.format(token=token),
        str(router_id),
        ex=WEBFIG_SESSION_TTL_SECONDS,
    )
    return build_response(
        success=True,
        message="WebFig session created",
        data=WebfigSessionResponse(
            session_token=token, expires_in=WEBFIG_SESSION_TTL_SECONDS
        ).model_dump(),
        request_id=_request_id(request),
    )


WEBFIG_PROXY_PREFIX_TEMPLATE = "/api/v1/routers/{router_id}/webfig"


def _rewrite_webfig_absolute_paths(body: bytes, content_type: str, router_id: uuid.UUID) -> bytes:
    """RouterOS's own WebFig assets hardcode a handful of *absolute*
    (root-relative) paths -- confirmed live in its login script.js:
    ``window.location.replace(`/webfig/${window.location.hash}`)``. A
    relative path (``script.js``, what most of WebFig actually uses)
    naturally resolves against wherever this proxy is mounted and needs no
    help; an absolute one always resolves against *this app's own*
    origin root, bypassing the proxy prefix entirely and landing on a
    path our own SPA doesn't have -- which is exactly the "opens WebFig,
    logs in, then 404s" bug this rewrite exists to fix. Only applied to
    text-ish responses (html/javascript/css) -- images and other binary
    content are returned untouched, both because rewriting them makes no
    sense and because blindly decoding arbitrary bytes as text would
    corrupt them."""
    if not any(t in content_type for t in ("text/html", "javascript", "text/css")):
        return body
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body
    prefix = WEBFIG_PROXY_PREFIX_TEMPLATE.format(router_id=router_id)
    # Order matters: the longer, slash-terminated form first so it isn't
    # left partially rewritten by the shorter form's replacement.
    text = text.replace("/webfig/", f"{prefix}/")
    text = text.replace('"/webfig"', f'"{prefix}"').replace("'/webfig'", f"'{prefix}'")
    return text.encode("utf-8")


@router.api_route(
    "/routers/{router_id}/webfig/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def proxy_webfig(
    request: Request,
    router_id: uuid.UUID,
    path: str,
    session: str | None = Query(default=None),
    router_service: RouterService = Depends(get_router_service),
    redis: Redis = Depends(get_redis_client),
):
    """Reverse-proxies to this router's own RouterOS WebFig (its official
    browser-based management GUI -- the same real tool a WinBox user would
    otherwise need the separate native desktop app for) over the same
    WireGuard tunnel every other real device operation in this domain
    already uses -- a browser on an operator's own machine has no route to
    a router's private tunnel IP directly (see ``RouterService.
    reveal_credentials``'s own docstring on this exact reachability gap),
    so this backend, which *is* a WireGuard peer, is the one thing that
    can actually reach it.

    Deliberately NOT behind ``CurrentUser``/``RequirePermission`` -- an
    ``<iframe src>`` navigation can't carry a ``Bearer`` header, so this
    validates the short-lived, router-scoped ``session`` token
    ``create_webfig_session`` above minted instead (real authorization
    already happened there).

    ## Cookie fallback -- why the query param alone isn't enough

    The *first* request (the iframe's own ``src``) carries ``?session=...``
    explicitly, but WebFig's own HTML then requests its JS/CSS/image
    assets and makes its own AJAX calls using *relative* URLs (e.g.
    ``script.js``) -- which never inherit the original URL's query string.
    Every one of those follow-up requests would arrive with no ``session``
    param and 401 for a reason invisible to anyone watching the iframe
    just render blank. So: on first successful validation via the query
    param, this sets a ``wf_session_{router_id}`` cookie scoped to this
    exact proxy path -- the browser then attaches it automatically to
    every same-path sub-resource request, session-param or not, which is
    exactly the "stay authenticated across relative-URL asset loads"
    behavior a query param alone can't provide.

    Injects HTTP Basic Auth using this router's own stored RouterOS
    credentials so the operator isn't asked to log into WebFig a second
    time; if WebFig renders its own login screen anyway (its Basic-Auth
    support varies by RouterOS version), the same credentials from the
    Remote Access panel's "Reveal" button work there too."""
    cookie_name = f"wf_session_{router_id}"
    token = session or request.cookies.get(cookie_name)
    if token is None:
        return Response(status_code=status.HTTP_401_UNAUTHORIZED, content="Missing WebFig session")

    session_key = WEBFIG_SESSION_KEY_TEMPLATE.format(token=token)
    scoped_router_id = await redis.get(session_key)
    if scoped_router_id is None or scoped_router_id != str(router_id):
        return Response(status_code=status.HTTP_401_UNAUTHORIZED, content="Invalid or expired WebFig session")

    router_row = await router_service.get_router(router_id)
    host = router_row.management_ip_address or router_row.public_ip_address
    if not host:
        return Response(status_code=status.HTTP_502_BAD_GATEWAY, content="This router has no reachable management address")
    password = router_service.get_decrypted_api_secret(router_row)

    upstream_url = f"http://{host}/{path}"
    body = await request.body()
    excluded_headers = {"host", "authorization", "content-length"}
    forward_headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded_headers}
    # WebFig establishes its own router-side session via a Set-Cookie on a
    # successful request; that cookie must round-trip (browser -> proxy ->
    # router, and router -> proxy -> browser) for the router to recognize
    # the browser as logged in on subsequent requests. Strip only our own
    # session cookie before forwarding upstream -- the router doesn't need
    # it and it's an internal proxy-auth detail, not something to leak.
    cookie_header = request.headers.get("cookie", "")
    if cookie_header:
        kept = [
            part.strip()
            for part in cookie_header.split(";")
            if part.strip() and not part.strip().startswith(f"{cookie_name}=")
        ]
        if kept:
            forward_headers["cookie"] = "; ".join(kept)

    async with httpx.AsyncClient(
        auth=httpx.BasicAuth(router_row.api_username or "", password or ""),
        timeout=15.0,
        follow_redirects=False,
    ) as client:
        try:
            upstream_params = {k: v for k, v in request.query_params.items() if k != "session"}
            upstream = await client.request(
                request.method,
                upstream_url,
                params=upstream_params,
                headers=forward_headers,
                content=body,
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "router_webfig_proxy_failed",
                extra={"router_id": str(router_id), "error": str(exc)},
            )
            return Response(status_code=status.HTTP_502_BAD_GATEWAY, content=f"Could not reach the router: {exc}")

    response_headers = {
        k: v
        for k, v in upstream.headers.items()
        if k.lower() not in {"content-encoding", "content-length", "transfer-encoding", "connection", "set-cookie"}
    }
    content_type = upstream.headers.get("content-type", "")
    response_body = _rewrite_webfig_absolute_paths(upstream.content, content_type, router_id)
    proxy_response = Response(
        content=response_body,
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=content_type or None,
    )
    # RouterOS's own WebFig sets a session cookie on the login response and
    # relies on the browser sending it back to recognize the browser as
    # authenticated -- without this, WebFig always looks unauthenticated and
    # bounces back to its login screen no matter what credentials were
    # submitted. httpx collapses repeated response headers, so read the raw
    # Set-Cookie values explicitly (there can be more than one).
    for router_cookie in upstream.headers.get_list("set-cookie"):
        proxy_response.headers.append("set-cookie", router_cookie)
    if session:
        proxy_response.set_cookie(
            cookie_name,
            token,
            max_age=WEBFIG_SESSION_TTL_SECONDS,
            path=f"/api/v1/routers/{router_id}/webfig",
            httponly=True,
            samesite="lax",
        )
    return proxy_response


@router.get(
    "/routers/{router_id}/device-interfaces",
    response_model=ApiResponse[DeviceInterfacesResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.manage"))],
)
async def get_device_interfaces(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    """Real, currently-available interfaces read live off the physical
    device -- backs the dashboard's Interface picker (DHCP Pool / VLAN
    forms) so an admin selects from what the router actually has instead
    of typing a name that might not exist, or might already be in use.
    See ``device_adapters.list_available_device_interfaces`` for what
    "available" excludes. Read-only (never applies anything), so unlike
    the config-push path this stays a backend-owned live query, same
    posture as ``get_device_connection`` above."""
    router_row = await router_service.get_router(
        router_id, requesting_organization_id=requesting_organization_id
    )
    host = router_row.management_ip_address or router_row.public_ip_address
    password = router_service.get_decrypted_api_secret(router_row)
    if not host or not router_row.api_username or not password:
        return build_response(
            success=True,
            message="Device has no API credentials configured",
            data=DeviceInterfacesResponse(interfaces=[]).model_dump(),
            request_id=_request_id(request),
        )
    try:
        interfaces = await list_available_device_interfaces(
            host=host, username=router_row.api_username, password=password
        )
    except DeviceInterfaceQueryError as exc:
        return build_response(
            success=False,
            message=f"Could not reach device: {exc.detail}",
            data=DeviceInterfacesResponse(interfaces=[]).model_dump(),
            request_id=_request_id(request),
        )
    return build_response(
        success=True,
        message="Device interfaces retrieved",
        data=DeviceInterfacesResponse(
            interfaces=[
                DeviceInterfaceResponse(
                    name=i.name,
                    type=i.type,
                    running=i.running,
                    disabled=i.disabled,
                    bridge=i.bridge,
                    has_ip_address=i.has_ip_address,
                )
                for i in interfaces
            ]
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/reboot",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.manage"))],
)
async def reboot_router(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    """Real, immediate ``/system reboot`` on the physical device -- a
    genuinely disruptive, hard-to-undo action (every guest currently
    connected drops, and the device is unreachable for its normal ~1-2
    minute boot cycle), gated by the same ``routers.manage`` permission as
    every other high-trust device operation in this domain. See
    ``device_adapters.reboot_device``'s own docstring for why a dropped
    connection here is the expected success signal, not a failure."""
    router_row = await router_service.get_router(
        router_id, requesting_organization_id=requesting_organization_id
    )
    host = router_row.management_ip_address or router_row.public_ip_address
    password = router_service.get_decrypted_api_secret(router_row)
    if not host or not router_row.api_username or not password:
        return build_response(
            success=False,
            message="Device has no API credentials configured",
            data=MessageResponse(message="Cannot reboot: no device credentials").model_dump(),
            request_id=_request_id(request),
        )
    try:
        await reboot_device(host=host, username=router_row.api_username, password=password)
    except DeviceInterfaceQueryError as exc:
        return build_response(
            success=False,
            message=f"Could not reach device: {exc.detail}",
            data=MessageResponse(message="Reboot not sent").model_dump(),
            request_id=_request_id(request),
        )
    return build_response(
        success=True,
        message="Reboot command sent",
        data=MessageResponse(message="Router is rebooting").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/heartbeat",
    response_model=ApiResponse[RouterResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("routers.manage"))],
)
async def router_heartbeat(
    request: Request,
    router_id: uuid.UUID,
    payload: HeartbeatRequest,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    updated = await router_service.heartbeat(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        routeros_version=payload.routeros_version,
        management_ip_address=payload.management_ip_address,
    )
    return build_response(
        success=True,
        message="Heartbeat recorded",
        data=_router_response(updated).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/provisioning-token",
    response_model=ApiResponse[ProvisioningTokenResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(RequirePermission("router_provisioning.create")),
        Depends(RequirePermission("router_provisioning.approve")),
    ],
)
async def generate_provisioning_token(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    router_service: RouterService = Depends(get_router_service),
):
    token, plaintext = await router_service.generate_provisioning_token(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    payload = ProvisioningTokenResponse(
        router_id=str(token.router_id), token=plaintext, expires_at=token.expires_at
    )
    return build_response(
        success=True,
        message=(
            "Provisioning token generated -- store it now, it will not be "
            "shown again"
        ),
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Device-facing zero-touch provisioning endpoint
# ============================================================================


@router.post(
    "/routers/provisioning/check-in",
    status_code=status.HTTP_200_OK,
)
async def provisioning_check_in(
    payload: ProvisioningCheckInRequest,
    router_service: RouterService = Depends(get_router_service),
    agent_service: RouterAgentService = Depends(get_router_agent_service),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
) -> ProvisioningCheckInResponse:
    """Presented by the physical device, not an authenticated platform user
    -- see module docstring and ``docs/router/ROUTER_ARCHITECTURE.md`` §5.

    Additively issues the device's persistent ``app.domains.router_agent``
    credential in the same response (see
    ``ProvisioningCheckInResponse``'s own docstring and
    ``app.domains.router_agent.service``'s module docstring for why here,
    not a separate later endpoint): this call is the device's last chance to
    authenticate itself with a credential (the one-time provisioning token)
    this platform already trusts before that token is consumed.

    **Module 009 Part 3 (zero-touch enrollment) additive extension:** when
    ``payload.wireguard_public_key`` is present, this call also composes
    with ``WireGuardService.create_tunnel`` (via its additive
    ``external_public_key`` parameter -- see that method's own docstring)
    to allocate this router's tunnel IP and create its ``WireGuardPeer``
    row right here, using the *same* allocation logic every other tunnel
    on this platform goes through -- not a second, parallel allocator. This
    is deliberately optional: a device presenting only ``token`` (no public
    key yet, or a non-WireGuard enrollment path) gets exactly today's
    behavior, unchanged. When absent, no ``WireGuardPeer`` is created and
    the four WireGuard-shaped response fields stay ``None`` -- a device can
    always create its tunnel later through the ordinary, authenticated
    ``app.domains.wireguard`` admin surface instead."""
    updated = await router_service.check_in(plaintext_token=payload.token)
    credential, agent_credential = await agent_service.issue_credential_for_router(
        updated
    )

    tunnel_ip_address: str | None = None
    wireguard_server_public_key: str | None = None
    wireguard_endpoint_host: str | None = None
    wireguard_endpoint_port: int | None = None
    wireguard_hub_tunnel_address: str | None = None
    if payload.wireguard_public_key:
        delivery = await wireguard_service.create_tunnel(
            actor_user_id=None,
            router_id=updated.id,
            requesting_organization_id=None,
            external_public_key=payload.wireguard_public_key,
        )
        tunnel_ip_address = delivery.peer.tunnel_ip_address
        wireguard_server_public_key = delivery.server.public_key
        wireguard_endpoint_host = delivery.server.endpoint_host
        wireguard_endpoint_port = delivery.server.endpoint_port
        # The hub's own conventional tunnel address (first usable host of
        # its tunnel_network_cidr) -- mirrors
        # app.domains.network_config.renderers._hub_tunnel_address's
        # identical derivation exactly, computed here rather than imported
        # since that helper is that module's own private implementation
        # detail, not a shared cross-domain surface. See
        # ProvisioningCheckInResponse.wireguard_hub_tunnel_address's own
        # docstring for why the device needs this real value, not a
        # fabricated one, for its own allowed-address=.
        hub_network = ipaddress.ip_network(
            delivery.server.tunnel_network_cidr, strict=False
        )
        wireguard_hub_tunnel_address = str(next(hub_network.hosts()))

    return ProvisioningCheckInResponse(
        router_id=str(updated.id),
        status=RouterStatus(updated.status),
        agent_credential=agent_credential,
        agent_credential_expires_at=credential.expires_at,
        tunnel_ip_address=tunnel_ip_address,
        wireguard_server_public_key=wireguard_server_public_key,
        wireguard_endpoint_host=wireguard_endpoint_host,
        wireguard_endpoint_port=wireguard_endpoint_port,
        wireguard_hub_tunnel_address=wireguard_hub_tunnel_address,
    )


__all__ = ["router"]
