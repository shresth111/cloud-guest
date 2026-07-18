"""Data access layer for the WireGuard domain.

Mirrors ``app.domains.router_agent.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``WireGuardRepositoryProtocol``), and a concrete, ``GenericRepository``
-backed implementation (``WireGuardRepository``) for this module's two
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

from .constants import PeerStatus
from .models import WireGuardPeer, WireGuardServer


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

    async def create_peer(self, **fields: object) -> WireGuardPeer: ...

    async def update_peer(
        self, peer: WireGuardPeer, data: dict[str, object]
    ) -> WireGuardPeer: ...


class WireGuardRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``WireGuardRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.servers = GenericRepository(WireGuardServer, session)
        self.peers = GenericRepository(WireGuardPeer, session)

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

    async def create_peer(self, **fields: object) -> WireGuardPeer:
        return await self.peers.create(fields)

    async def update_peer(
        self, peer: WireGuardPeer, data: dict[str, object]
    ) -> WireGuardPeer:
        return await self.peers.update(peer, data)


__all__ = ["WireGuardRepositoryProtocol", "WireGuardRepository"]
