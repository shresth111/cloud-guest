"""FastAPI dependencies for the WireGuard domain.

Authorization for the admin-facing peer endpoints is provided entirely by
RBAC's existing ``RequirePermission`` dependency
(``app.domains.rbac.dependencies``) against the already-seeded
``wireguard.*`` permission keys -- nothing here re-implements authorization.
This module only wires the repository/service layer, composing with
``app.domains.router`` (BE-008's ``RouterService``, for tenant-scoped router
lookups) and RBAC (for audit logging) rather than duplicating either.

The device-facing endpoints (``GET /agent/wireguard-config``,
``POST /agent/wireguard-config/handshake``) are authenticated entirely by
``app.domains.router_agent``'s own ``CurrentAgent`` dependency, imported and
reused as-is in ``router.py`` -- there is no separate device-credential
dependency defined here. See ``router.py``'s module docstring for the full
cross-domain composition.
"""

from __future__ import annotations

import httpx
from fastapi import Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.exceptions import CloudGuestError
from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .constants import HubRemovalOutcome
from .repository import WireGuardRepository, WireGuardRepositoryProtocol
from .service import HubCapabilities, WireGuardService


class HubBridgeUnavailableError(CloudGuestError):
    """The hub's peer bridge could not be reached or refused the removal.

    Deliberately its own error rather than a swallowed warning. A revoke
    that never reached the hub has not revoked anything -- the address is
    freed in the database while the hub still hands it out, which is the
    state that left 68 orphaned peers on the tunnel box.

    TWO TRAPS LIVE HERE, both of them about the fact that this subclasses
    ``CloudGuestError`` and NOT ``exceptions.WireGuardError``.

    1. ``except WireGuardError`` does not catch it. Nothing about the name
       says so, and the one place that tried --
       ``hub_reconciliation.tasks`` -- named this class in its own comment
       while catching a type that excludes it, so the most likely failure in
       that task escaped the handler written for it. Fixed 2026-09-01; if a
       new caller wants "any hub failure", it must name both.

    2. ``status_code`` had to move into ``__init__``. It was written as a
       CLASS attribute (``status_code = 502``), which
       ``CloudGuestError.__init__`` then overwrote on every instance with
       its own default of 500 -- so this was raised as a 502 in intent and
       served as a 500 "Internal server error" in fact, for its whole life.
       A hub bridge that is down is not an internal server error; it is an
       upstream dependency that is down, and a client cannot tell the
       difference between "retry, the hub is unreachable" and "this
       platform is broken" from a 500. ``error_code`` below is left as a
       class attribute because ``CloudGuestError`` never sets one, so
       nothing shadows it -- though nothing reads it either today, the
       shared handler in ``app.common.exceptions`` serialises ``message``
       and ``data`` only.
    """

    error_code = "hub_bridge_unavailable"

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_502_BAD_GATEWAY)


def bridge_error_detail(resp: httpx.Response) -> str:
    """The hub agent's own explanation of a >=400.

    Lived in ``router.py`` until the allocation call moved down into the
    service layer; it is here now because both the HTTP endpoint and the
    injected allocator below need it, and because the identically-named
    helper in ``app.domains.guest.router`` documents the reason it has to
    exist at all -- both hub agents answer with the ``{"error":
    "<str(exception)>"}`` shape and their ``log_message`` is a deliberate
    no-op, so this body is the only description of the failure that exists
    anywhere.
    """
    try:
        body = resp.json()
    except ValueError:
        return (resp.text or "<empty response body>")[:600]
    if isinstance(body, dict) and "error" in body:
        return str(body["error"])[:600]
    return str(body)[:600]


def make_hub_peer_allocator(settings: Settings):
    """Builds the callable ``WireGuardService.allocate_tunnel_via_hub`` uses
    to have the hub mint a peer -- ``POST /wg/peer`` on
    ``ops/hub-agents/wg_agent.py``, the same URL/secret the deregistrar and
    the lister already use. One bridge, three verbs.

    THIS IS THE ONLY PATH THAT PRODUCES A KEY BOTH SIDES KNOW. The agent
    generates the keypair itself and returns both halves; there is no verb
    that accepts a public key the caller already has, which is exactly what
    ``exceptions.HubCannotLearnPlatformKeyError`` guards against on the
    ``create_tunnel``/``rotate_tunnel`` side.

    Injected on the service rather than called inline from a route for the
    same reason as ``make_hub_peer_deregistrar``: the orchestration around
    it (reuse, adopt, refuse-over-a-live-device) is business logic that more
    than one caller needs -- the Master console's WireGuard tab *and*
    ``LocationProvisioningService.provision_location`` -- and the in-memory
    test suite has to be able to drive all of it without HTTP.

    Raises ``HubBridgeUnavailableError`` (a 502, and NOT a
    ``WireGuardError`` -- see that class's own docstring, trap 1) on both
    an unreachable bridge and a bridge that answered with a >=400.
    """

    async def _allocate() -> dict:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    settings.hub_wg_agent_url,
                    headers={"X-Agent-Secret": settings.hub_wg_agent_secret},
                )
        except httpx.HTTPError as exc:
            raise HubBridgeUnavailableError(
                f"Could not reach the WireGuard hub bridge: {exc!s}"
            ) from exc
        if resp.status_code >= 400:
            raise HubBridgeUnavailableError(
                "The WireGuard hub bridge refused this allocation "
                f"(HTTP {resp.status_code}): {bridge_error_detail(resp)}"
            )
        return resp.json()

    return _allocate


def make_hub_peer_deregistrar(settings: Settings):
    """Builds the callable `WireGuardService` uses to remove a peer from the
    hub, from the same settings the ALLOCATION path already uses.

    Same URL and same shared secret as `allocate_external_wireguard_peer`'s
    POST -- one bridge, two verbs. It is built here rather than imported
    inside the service so the service stays drivable from the in-memory test
    suite without HTTP.

    A 404 from the bridge is SUCCESS, not failure: it means the hub does not
    have this peer, which is the state we were trying to reach. Anything
    else -- unreachable, 401, 500 -- raises, because those are all "we do
    not know whether the hub still has it", and guessing is what produced
    the drift.

    A **501** is the one status that is neither. It is not a failure to
    retry and it is not success: it is the deployed agent saying it has no
    such verb, which is a permanent fact about that host until someone
    installs a new one. It is returned as ``HubRemovalOutcome.UNSUPPORTED``
    so the caller can record an orphan instead of raising, once per
    superseded peer, an exception whose stack trace says nothing an
    operator can act on. ``ops/hub-agents/wg_agent.py`` as deployed
    implements only ``do_POST``/``do_GET``, so ``http.server`` answers the
    ``DELETE`` itself with ``501 Unsupported method``; the ``do_DELETE``
    handler in that file is written and waiting on shell access to the hub.
    """

    async def _deregister(public_key: str) -> HubRemovalOutcome:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.request(
                    "DELETE",
                    settings.hub_wg_agent_url,
                    headers={"X-Agent-Secret": settings.hub_wg_agent_secret},
                    json={"public_key": public_key},
                )
        except httpx.HTTPError as exc:
            raise HubBridgeUnavailableError(
                "Could not reach the WireGuard hub bridge to remove this peer"
            ) from exc
        if resp.status_code == 404:
            return HubRemovalOutcome.NOT_PRESENT
        if resp.status_code == status.HTTP_501_NOT_IMPLEMENTED:
            return HubRemovalOutcome.UNSUPPORTED
        if resp.status_code >= 400:
            raise HubBridgeUnavailableError(
                f"The WireGuard hub bridge refused the removal ({resp.status_code})"
            )
        # The deployed agent's own contract (`remove_peer`) distinguishes
        # "removed 1" from "removed 0, it was not here" -- carry that
        # through rather than flattening both into REMOVED, for the same
        # reason `radius_agent.remove_client` bothers to return the count.
        try:
            removed = resp.json().get("removed")
        except ValueError:
            removed = None
        if removed == 0:
            return HubRemovalOutcome.NOT_PRESENT
        return HubRemovalOutcome.REMOVED

    return _deregister


def make_hub_peer_lister(settings: Settings):
    """Builds the callable `WireGuardService.get_fleet_status` uses to read
    the hub's own live peer list (`GET /wg/peers`, see
    `ops/hub-agents/wg_agent.py`'s module docstring) -- the same
    private-VNet URL/secret pattern as `make_hub_peer_deregistrar`, just a
    GET instead of a DELETE. Built here, not imported into the service,
    for the identical reason: the in-memory test suite drives the service
    with a fake lister, never real HTTP.

    Raises on anything but a clean 200 -- a fleet-status view built on a
    guess about the hub's state (rather than a clear "the hub could not be
    reached" error) is worse than no view at all, the same reasoning
    `HubBridgeUnavailableError`'s own docstring gives for the deregistrar.
    """

    async def _list_peers() -> list[dict]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    settings.hub_wg_agent_peers_url,
                    headers={"X-Agent-Secret": settings.hub_wg_agent_secret},
                )
        except httpx.HTTPError as exc:
            raise HubBridgeUnavailableError(
                "Could not reach the WireGuard hub bridge to list live peers"
            ) from exc
        if resp.status_code >= 400:
            raise HubBridgeUnavailableError(
                f"The WireGuard hub bridge refused the peer list ({resp.status_code})"
            )
        return resp.json()["peers"]

    return _list_peers


def get_wireguard_repository(
    db: AsyncSession = Depends(get_db_session),
) -> WireGuardRepositoryProtocol:
    return WireGuardRepository(db)


def hub_capabilities_from_settings(settings: Settings) -> HubCapabilities:
    """What the hub agent this deployment points at can actually be asked
    to do -- see ``service.HubCapabilities`` for why both default to
    ``False`` in production and ``True`` everywhere else.

    Settings-driven, not hard-coded, because these are the two flags that
    flip the day a new agent is installed on the hub. Landing
    ``do_DELETE`` is then an env change
    (``CLOUDGUEST_HUB_WG_AGENT_SUPPORTS_PEER_REMOVAL=true``) and a restart,
    with no code path that has to be found and edited under pressure --
    which is the whole point of separating "what the code can do" from
    "what this hub can do"."""
    return HubCapabilities(
        can_register_public_key=settings.hub_wg_agent_supports_key_registration,
        can_remove_peer=settings.hub_wg_agent_supports_peer_removal,
    )


def get_wireguard_service(
    repository: WireGuardRepositoryProtocol = Depends(get_wireguard_repository),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> WireGuardService:
    return WireGuardService(
        repository,
        router_service,
        audit_writer=audit_repository,
        handshake_stale_after_minutes=settings.wireguard_handshake_stale_after_minutes,
        hub_peer_deregistrar=make_hub_peer_deregistrar(settings),
        hub_peer_lister=make_hub_peer_lister(settings),
        hub_peer_allocator=make_hub_peer_allocator(settings),
        hub_capabilities=hub_capabilities_from_settings(settings),
        # No `peer_address_listener` here on purpose: wiring it would mean
        # importing `app.domains.guest`, which already imports this module.
        # `app.domains.hub_reconciliation` builds the fully-wired service.
    )


__all__ = [
    "get_wireguard_repository",
    "get_wireguard_service",
    "hub_capabilities_from_settings",
    "bridge_error_detail",
    "make_hub_peer_allocator",
    "make_hub_peer_deregistrar",
    "make_hub_peer_lister",
    "HubBridgeUnavailableError",
]
