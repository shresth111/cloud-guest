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
    """

    status_code = 502
    error_code = "hub_bridge_unavailable"


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
        hub_capabilities=hub_capabilities_from_settings(settings),
        # No `peer_address_listener` here on purpose: wiring it would mean
        # importing `app.domains.guest`, which already imports this module.
        # `app.domains.hub_reconciliation` builds the fully-wired service.
    )


__all__ = [
    "get_wireguard_repository",
    "get_wireguard_service",
    "hub_capabilities_from_settings",
    "make_hub_peer_deregistrar",
    "make_hub_peer_lister",
    "HubBridgeUnavailableError",
]
