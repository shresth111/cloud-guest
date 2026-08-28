"""Data access layer for the WireGuard domain.

Mirrors ``app.domains.router_agent.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``WireGuardRepositoryProtocol``), and a concrete, ``GenericRepository``
-backed implementation (``WireGuardRepository``) for this module's three
tables. Hand-written queries are used only where ``GenericRepository``'s
equality filters can't express the need (resolving "the" active hub,
listing a hub's currently-occupied tunnel IPs).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.domains.router.models import Router

from .constants import HubPeerLifecycle, PeerStatus
from .models import WireGuardPeer, WireGuardPeerIssuance, WireGuardServer


class WireGuardRepositoryProtocol(Protocol):
    # -- servers (hubs) -------------------------------------------------------
    async def get_server_by_id(
        self, server_id: uuid.UUID, *, include_deleted: bool = False
    ) -> WireGuardServer | None: ...

    async def get_active_server(self) -> WireGuardServer | None: ...

    async def list_servers(self) -> list[WireGuardServer]: ...

    async def create_server(self, **fields: object) -> WireGuardServer: ...

    async def update_server(
        self, server: WireGuardServer, data: dict[str, object]
    ) -> WireGuardServer: ...

    # -- peers ------------------------------------------------------------------
    async def get_peer_by_id(
        self, peer_id: uuid.UUID, *, include_deleted: bool = False
    ) -> WireGuardPeer | None: ...

    async def get_peer_by_router_id(
        self, router_id: uuid.UUID
    ) -> WireGuardPeer | None: ...

    async def list_occupied_tunnel_ips(
        self, server_id: uuid.UUID, *, exclude_peer_id: uuid.UUID | None = None
    ) -> set[str]: ...

    async def list_all_peers_with_router_names(
        self,
    ) -> list[tuple[WireGuardPeer, str | None]]: ...

    async def create_peer(self, **fields: object) -> WireGuardPeer: ...

    async def update_peer(
        self, peer: WireGuardPeer, data: dict[str, object]
    ) -> WireGuardPeer: ...

    # -- issuance ledger --------------------------------------------------------
    async def create_issuance(self, **fields: object) -> WireGuardPeerIssuance: ...

    async def update_issuance(
        self, issuance: WireGuardPeerIssuance, data: dict[str, object]
    ) -> WireGuardPeerIssuance: ...

    async def list_issuances_for_router(
        self, router_id: uuid.UUID
    ) -> list[WireGuardPeerIssuance]: ...

    async def get_issuance_by_public_key(
        self, public_key: str
    ) -> WireGuardPeerIssuance | None: ...

    async def list_all_issuances(self) -> list[WireGuardPeerIssuance]: ...

    async def list_hub_held_tunnel_ips(self, server_id: uuid.UUID) -> set[str]: ...


class WireGuardRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``WireGuardRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.servers = GenericRepository(WireGuardServer, session)
        self.peers = GenericRepository(WireGuardPeer, session)
        self.issuances = GenericRepository(WireGuardPeerIssuance, session)

    # -- servers (hubs) -----------------------------------------------------------

    async def get_server_by_id(
        self, server_id: uuid.UUID, *, include_deleted: bool = False
    ) -> WireGuardServer | None:
        return await self.servers.get_by_id(server_id, include_deleted=include_deleted)

    async def get_active_server(self) -> WireGuardServer | None:
        """Resolves "the" hub this platform currently uses -- see
        ``models.WireGuardServer``'s module docstring for why this is a
        query (not a schema-level singleton constraint): today it always
        returns the single seeded active hub, but nothing prevents a future
        implementation from choosing among several active rows."""
        results = await self.servers.get_all(filters={"is_active": True}, limit=1)
        return results[0] if results else None

    async def list_servers(self) -> list[WireGuardServer]:
        return await self.servers.get_all()

    async def create_server(self, **fields: object) -> WireGuardServer:
        return await self.servers.create(fields)

    async def update_server(
        self, server: WireGuardServer, data: dict[str, object]
    ) -> WireGuardServer:
        return await self.servers.update(server, data)

    # -- peers --------------------------------------------------------------------

    async def get_peer_by_id(
        self, peer_id: uuid.UUID, *, include_deleted: bool = False
    ) -> WireGuardPeer | None:
        return await self.peers.get_by_id(peer_id, include_deleted=include_deleted)

    async def get_peer_by_router_id(self, router_id: uuid.UUID) -> WireGuardPeer | None:
        results = await self.peers.get_all(filters={"router_id": router_id}, limit=1)
        return results[0] if results else None

    async def list_occupied_tunnel_ips(
        self, server_id: uuid.UUID, *, exclude_peer_id: uuid.UUID | None = None
    ) -> set[str]:
        """Every tunnel IP currently considered "taken" for ``server_id`` --
        every non-``revoked`` peer's address (see ``models.WireGuardPeer``'s
        module docstring: a revoked peer's IP is deliberately excluded, "freed
        for reuse"). ``exclude_peer_id`` lets a rotation/re-create flow
        ignore the very row being mutated when it recomputes availability."""
        statement = select(WireGuardPeer.id, WireGuardPeer.tunnel_ip_address).where(
            WireGuardPeer.server_id == server_id,
            WireGuardPeer.status != PeerStatus.REVOKED.value,
        )
        result = await self.session.execute(statement)
        return {
            tunnel_ip
            for peer_id, tunnel_ip in result.all()
            if peer_id != exclude_peer_id
        }

    async def list_all_peers_with_router_names(
        self,
    ) -> list[tuple[WireGuardPeer, str | None]]:
        """Platform-wide, not tenant-scoped -- backs
        ``WireGuardService.get_fleet_status``, which is itself only ever
        reachable via a platform-level (GLOBAL scope) permission, the same
        posture ``master.operators.tsx``'s own directory endpoint documents
        for why an unscoped read is fine there. Hand-written (not
        ``GenericRepository``) because the point is the router's ``name``
        for display -- a plain peer list would leave the fleet-status view
        with nothing to show a human besides a bare UUID."""
        statement = (
            select(WireGuardPeer, Router.name)
            .outerjoin(Router, Router.id == WireGuardPeer.router_id)
            .where(WireGuardPeer.is_deleted.is_(False))
        )
        result = await self.session.execute(statement)
        return [(peer, name) for peer, name in result.all()]

    async def create_peer(self, **fields: object) -> WireGuardPeer:
        return await self.peers.create(fields)

    async def update_peer(
        self, peer: WireGuardPeer, data: dict[str, object]
    ) -> WireGuardPeer:
        return await self.peers.update(peer, data)

    # -- issuance ledger ------------------------------------------------------------

    async def create_issuance(self, **fields: object) -> WireGuardPeerIssuance:
        return await self.issuances.create(fields)

    async def update_issuance(
        self, issuance: WireGuardPeerIssuance, data: dict[str, object]
    ) -> WireGuardPeerIssuance:
        return await self.issuances.update(issuance, data)

    async def list_issuances_for_router(
        self, router_id: uuid.UUID
    ) -> list[WireGuardPeerIssuance]:
        return await self.issuances.get_all(filters={"router_id": router_id})

    async def get_issuance_by_public_key(
        self, public_key: str
    ) -> WireGuardPeerIssuance | None:
        """The most recent issuance recorded for ``public_key``.

        ``get_all`` sorts by ``created_at`` descending by default
        (``GenericRepository.DEFAULT_SORT_FIELD``/``SortOrder.DESC``), and
        "most recent" is the right answer here: a key can appear twice for
        one router (issued, then adopted once the device proved it was
        using it), and the adoption is the fact a caller asking "who owns
        this key" wants."""
        results = await self.issuances.get_all(
            filters={"public_key": public_key}, limit=1
        )
        return results[0] if results else None

    async def list_all_issuances(self) -> list[WireGuardPeerIssuance]:
        """Platform-wide, same unscoped posture (and same GLOBAL-permission-
        only reachability) as ``list_all_peers_with_router_names`` -- backs
        the fleet-status attribution join, which is a question about the
        whole hub, not about one tenant."""
        return await self.issuances.get_all()

    async def list_hub_held_tunnel_ips(self, server_id: uuid.UUID) -> set[str]:
        """Every address on ``server_id`` the platform believes the hub is
        still routing, whether or not any live peer row claims it.

        This is the quarantine set, and it exists because
        ``list_occupied_tunnel_ips`` cannot answer the question: it reads
        ``wireguard_peers``, which holds exactly one row per router and
        therefore forgets a superseded address the instant it is
        overwritten. Handing such an address to the next router is not a
        theoretical hazard -- the hub routes by ``allowed-ips``, so two
        peers claiming one address means the newer one's traffic is
        delivered to whichever the kernel picked, and the symptom is "the
        tunnel is flaky" on a router whose configuration is perfect."""
        statement = select(WireGuardPeerIssuance.tunnel_ip_address).where(
            WireGuardPeerIssuance.server_id == server_id,
            WireGuardPeerIssuance.is_deleted.is_(False),
            WireGuardPeerIssuance.hub_lifecycle.in_(
                (HubPeerLifecycle.LIVE.value, HubPeerLifecycle.ORPHANED.value)
            ),
        )
        result = await self.session.execute(statement)
        return {row[0] for row in result.all()}


__all__ = ["WireGuardRepositoryProtocol", "WireGuardRepository"]
