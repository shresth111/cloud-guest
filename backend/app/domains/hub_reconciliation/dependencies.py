"""Wiring for the reconciliation pass -- and the one place a
``WireGuardService`` is built WITH its ``peer_address_listener`` attached.

``app.domains.wireguard.dependencies.get_wireguard_service`` deliberately
leaves that hook ``None``: attaching it there would mean importing
``app.domains.guest``, which already imports the WireGuard domain, closing
an import cycle. This module is the layer above both, so it can do it.
"""

from __future__ import annotations

import uuid

from fastapi import Depends

from app.core.config import Settings, get_settings
from app.domains.guest.dependencies import get_radius_service
from app.domains.guest.service import RadiusService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService
from app.domains.wireguard.dependencies import (
    get_wireguard_repository,
    hub_capabilities_from_settings,
    make_hub_peer_deregistrar,
    make_hub_peer_lister,
)
from app.domains.wireguard.repository import WireGuardRepositoryProtocol
from app.domains.wireguard.service import WireGuardService

from .service import HubReconciliationService


def get_hub_reconciliation_service(
    wireguard_repository: WireGuardRepositoryProtocol = Depends(
        get_wireguard_repository
    ),
    router_service: RouterService = Depends(get_router_service),
    radius_service: RadiusService = Depends(get_radius_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> HubReconciliationService:
    """Builds both services and ties the knot between them.

    The listener is installed AFTER construction because it needs the
    reconciliation service, which needs the WireGuard service. That
    circularity is real -- an adoption triggers a RADIUS re-push, which is
    owned one layer up -- and a late assignment is the honest way to
    express it. The alternative, threading a factory through
    ``WireGuardService.__init__``, would hide the same cycle behind more
    machinery without removing it.
    """
    wireguard_service = WireGuardService(
        wireguard_repository,
        router_service,
        audit_writer=audit_repository,
        handshake_stale_after_minutes=settings.wireguard_handshake_stale_after_minutes,
        hub_peer_deregistrar=make_hub_peer_deregistrar(settings),
        hub_peer_lister=make_hub_peer_lister(settings),
        hub_capabilities=hub_capabilities_from_settings(settings),
    )
    reconciliation = HubReconciliationService(wireguard_service, radius_service)

    async def _on_peer_address_changed(
        *,
        router_id: uuid.UUID,
        previous_tunnel_ip_address: str,
        tunnel_ip_address: str,
    ) -> None:
        await reconciliation.rebind_nas_for_router(
            router_id=router_id, tunnel_ip_address=tunnel_ip_address
        )

    wireguard_service.peer_address_listener = _on_peer_address_changed
    return reconciliation


__all__ = ["get_hub_reconciliation_service"]
