"""WireGuard business logic: hub (server) management, automatic tunnel
creation for a router, tunnel-IP allocation, device-facing config/handshake
delivery, and key/tunnel rotation.

Design notes worth calling out up front (see ``docs/wireguard/FLOW.md`` for
the full write-up):

## Composition, not duplication, with BE-008

This service never queries the ``routers`` table directly -- it composes
with the real ``RouterService`` through a narrow, duck-typed
``RouterLookupProtocol`` (the exact cross-domain-composition pattern
``RouterProvisioningService``/``RouterAgentService`` already establish for
the same reason). Tenant isolation for every admin-facing operation is
therefore inherited for free: ``RouterLookupProtocol.get_router`` already
raises ``CrossOrganizationRouterAccessError`` for a caller acting outside
its own organization (or an MSP's child organizations) -- this module adds
no second tenant-scoping check.

## Why the peer's own private key is Fernet-encrypted via BE-008's
``app.domains.router.crypto``, not a new mechanism

Every existing *hashed* secret in this codebase (``RouterProvisioningToken
.token_hash``, ``RouterAgentCredential.credential_hash``) is one-way by
design -- the platform only ever needs to compare, never recover, a
device-presented bearer credential. A WireGuard peer's private key is a
fundamentally different kind of secret: in this platform's cloud-managed
model the *platform* generates it (see module docstring in ``models.py``),
which means the platform must be able to decrypt it back to plaintext in
order to ever hand it to the device. That is exactly the problem
``app.domains.router.crypto.encrypt_secret``/``decrypt_secret`` (Fernet,
AES-128-CBC + HMAC-SHA256) was already built to solve for
``Router.api_credentials_encrypted`` -- reusing it here (and for the hub's
own private key, which never leaves the platform but is still encrypted at
rest for defense-in-depth) means this module adds zero new cryptographic
surface area to audit.

## Why WireGuard keys are generated with ``cryptography``'s X25519 classes

WireGuard uses Curve25519 (X25519) keypairs: a 32-byte private scalar, a
32-byte public point, both conventionally presented base64-encoded (exactly
what ``wg genkey``/``wg pubkey`` produce). The ``cryptography`` package
this codebase already depends on for Fernet exposes
``hazmat.primitives.asymmetric.x25519.X25519PrivateKey``/``X25519PublicKey``,
including ``.generate()`` and the raw-bytes accessors
(``private_bytes_raw()``/``public_bytes_raw()``, both confirmed present in
the pinned ``cryptography==44.0.0``) needed to produce exactly this key
shape -- so no new dependency was added for key generation, only stdlib
``base64`` to match WireGuard's own encoding convention.

## Tunnel rotation and key rotation are the same operation

The module brief invited treating "tunnel rotation" (possibly including a
new tunnel IP) as distinct from "key rotation" (just the keypair). This
service collapses them into one ``rotate_tunnel`` method: rotating a peer's
keypair already forces the device to re-pull its configuration and
re-establish its handshake from scratch (see
``constants.PEER_STATUS_TRANSITIONS``'s ``ACTIVE -> PENDING`` edge) --
there is no meaningfully distinct "tunnel-level" state a second operation
could rotate independently of that key material. A full IP reallocation is
already available through the existing revoke-then-``create_tunnel`` path
(``WireGuardPeerAlreadyExistsError``'s own docstring), so a second endpoint
whose only difference would be "also picks a new IP" would either duplicate
that path or need its own bespoke IP-reuse rule; neither was judged to earn
its keep as a separate operation. ``rotate_tunnel`` therefore always keeps
the peer's existing ``tunnel_ip_address`` -- a deliberate choice consistent
with real-world operational practice, too: firewall rules, DNS, or
monitoring configured against a router's known tunnel IP should not need to
change just because its keys were rotated.

## One row per router, mutated in place across its lifecycle

``WireGuardPeer.router_id`` is unique (see ``models.py``'s module
docstring) -- ``create_tunnel`` called against a router whose only existing
peer is ``revoked`` reuses that same row (new keys, new IP, status reset to
``pending``, ``rotation_count`` incremented) rather than inserting a second
row, and ``rotate_tunnel`` always mutates the existing row. This mirrors
``RouterAgentService.issue_credential_for_router``'s identical "reissue in
place, never a second row" design for the identical reason: the FK is
unique, so anything else would require relaxing that constraint for no
distinct query need.
"""

from __future__ import annotations

import base64
import dataclasses
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.database.exceptions import DuplicateRecordError
from app.domains.rbac.enums import AuditAction
from app.domains.router.crypto import decrypt_secret, encrypt_secret
from app.domains.router.models import Router

from .constants import HealthStatus, PeerStatus
from .events import TunnelCreated, TunnelHandshakeRecorded, TunnelRevoked, TunnelRotated
from .exceptions import (
    NoActiveWireGuardServerError,
    TunnelIPAllocationConflictError,
    WireGuardPeerAlreadyExistsError,
    WireGuardPeerNotFoundError,
    WireGuardPeerRevokedError,
    WireGuardServerNotFoundError,
)
from .models import WireGuardPeer, WireGuardServer
from .repository import WireGuardRepositoryProtocol
from .validators import (
    allocate_tunnel_ip,
    validate_peer_transition,
    validate_router_eligible_for_wireguard,
)

logger = logging.getLogger(__name__)

# How many times ``create_tunnel``/``rotate_tunnel`` will retry IP
# allocation after losing a race to a concurrent request (see
# ``validators.allocate_tunnel_ip``'s module docstring for the full
# concurrency-safety reasoning: the database's unique constraint is the
# real safety net, this is just enough retry budget to smooth over a
# same-instant collision in this sandbox's synchronous test usage before
# giving up and surfacing a clear, retryable error to the caller).
_MAX_ALLOCATION_ATTEMPTS = 3


def generate_wireguard_keypair() -> tuple[str, str]:
    """Generates a fresh, platform-side WireGuard (X25519/Curve25519)
    keypair, returning ``(private_key_b64, public_key_b64)`` -- both
    base64-encoded 32-byte values, exactly the format ``wg genkey``/
    ``wg pubkey`` produce. See module docstring for why ``cryptography``'s
    X25519 classes are reused rather than adding a new dependency."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_b64 = base64.b64encode(private_key.private_bytes_raw()).decode("ascii")
    public_b64 = base64.b64encode(public_key.public_bytes_raw()).decode("ascii")
    return private_b64, public_b64


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class RouterLookupProtocol(Protocol):
    """The subset of BE-008's real ``RouterService`` surface this module
    needs: resolving a router by id with tenant scoping already enforced."""

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table -- the same narrow, duck-typed protocol
    shape every other domain's service (``RouterService``,
    ``RouterProvisioningService``, ...) already defines for itself."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Value objects returned to callers (router.py builds response schemas from
# these -- kept here, not in schemas.py, since they carry real key material
# and are not themselves Pydantic response models)
# ============================================================================


class TunnelDeliveryInfo:
    """Everything a device needs to configure its local WireGuard
    interface: its own (freshly decrypted) private key, plus the hub's
    public connection details. Returned by ``create_tunnel``,
    ``rotate_tunnel``, and ``get_config_for_agent`` alike so ``router.py``
    can build both the admin-facing and device-facing response schemas from
    one common shape."""

    __slots__ = ("peer", "peer_private_key", "server")

    def __init__(
        self, *, peer: WireGuardPeer, peer_private_key: str, server: WireGuardServer
    ) -> None:
        self.peer = peer
        self.peer_private_key = peer_private_key
        self.server = server


class WireGuardService:
    """Core WireGuard business logic."""

    def __init__(
        self,
        repository: WireGuardRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        handshake_stale_after_minutes: int = 5,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        self.handshake_stale_after = timedelta(minutes=handshake_stale_after_minutes)

    # ========================================================================
    # Hub (WireGuardServer) management -- service-layer only in this
    # iteration (see docs/wireguard/README.md: no HTTP CRUD surface for hubs
    # yet, single-hub bootstrap is an operational/seed concern, not a
    # per-tenant one -- consistent with section 10's exact, deliberately
    # narrow endpoint list).
    # ========================================================================

    async def create_server(
        self,
        *,
        name: str,
        endpoint_host: str,
        endpoint_port: int,
        tunnel_network_cidr: str,
        public_key: str | None = None,
        private_key: str | None = None,
        is_active: bool = True,
    ) -> WireGuardServer:
        """Creates a new hub, generating its keypair unless one is supplied
        (tests/bootstrap tooling may want a deterministic keypair)."""
        if public_key is None or private_key is None:
            private_key, public_key = generate_wireguard_keypair()
        return await self.repository.create_server(
            name=name,
            endpoint_host=endpoint_host,
            endpoint_port=endpoint_port,
            public_key=public_key,
            private_key_encrypted=encrypt_secret(private_key),
            tunnel_network_cidr=tunnel_network_cidr,
            is_active=is_active,
        )

    async def get_server(self, server_id: uuid.UUID) -> WireGuardServer:
        server = await self.repository.get_server_by_id(server_id)
        if server is None:
            raise WireGuardServerNotFoundError(server_id)
        return server

    async def list_servers(self) -> list[WireGuardServer]:
        return await self.repository.list_servers()

    async def get_active_server(self) -> WireGuardServer:
        server = await self.repository.get_active_server()
        if server is None:
            raise NoActiveWireGuardServerError()
        return server

    async def deactivate_server(self, server_id: uuid.UUID) -> WireGuardServer:
        server = await self.get_server(server_id)
        return await self.repository.update_server(server, {"is_active": False})

    # ========================================================================
    # Peer reads
    # ========================================================================

    async def get_peer(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> WireGuardPeer:
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        peer = await self.repository.get_peer_by_router_id(router_id)
        if peer is None:
            raise WireGuardPeerNotFoundError(router_id)
        return peer

    def compute_health_status(
        self, peer: WireGuardPeer, *, now: datetime | None = None
    ) -> HealthStatus:
        """Derives a read-time connectivity signal from
        ``last_handshake_at`` -- never persisted, always computed fresh. See
        ``constants.HealthStatus``'s module docstring for the full
        reasoning, including why this is honestly a DB-tracked,
        device-*reported* signal rather than a live ``wg show``
        integration."""
        if peer.status == PeerStatus.REVOKED.value:
            return HealthStatus.REVOKED
        if peer.last_handshake_at is None:
            return HealthStatus.UNKNOWN
        moment = now or datetime.now(UTC)
        if moment - peer.last_handshake_at <= self.handshake_stale_after:
            return HealthStatus.HEALTHY
        return HealthStatus.STALE

    # ========================================================================
    # Tunnel creation / re-creation
    # ========================================================================

    async def create_tunnel(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> TunnelDeliveryInfo:
        """Generates a fresh keypair, allocates a tunnel IP, and creates (or
        re-creates, if the router's only existing peer is ``revoked``) its
        ``WireGuardPeer`` row. Rejects the call outright if the router
        already has a non-revoked peer -- see ``WireGuardPeerAlreadyExistsError``'s
        own docstring for why this module chose reject-and-require-an-
        explicit-revoke over silent revoke-then-recreate.

        ``include_deleted=True`` on the router lookup mirrors
        ``app.domains.router_agent.dependencies.CurrentAgent``'s identical
        reasoning: ``RouterService.decommission_router`` both sets
        ``status=decommissioned`` *and* soft-deletes the row, so without
        ``include_deleted=True`` a decommissioned router would surface a
        misleading ``RouterNotFoundError`` instead of the more informative
        ``WireGuardRouterNotEligibleError`` that
        ``validate_router_eligible_for_wireguard`` below is meant to raise."""
        router = await self.router_lookup.get_router(
            router_id,
            requesting_organization_id=requesting_organization_id,
            include_deleted=True,
        )
        validate_router_eligible_for_wireguard(router)

        server = await self.get_active_server()
        existing = await self.repository.get_peer_by_router_id(router.id)
        if existing is not None and not existing.is_revoked():
            raise WireGuardPeerAlreadyExistsError(router.id)

        peer, private_key = await self._allocate_and_persist(
            server=server, existing=existing, router_id=router.id
        )

        await self._record_event_and_audit(
            actor_user_id,
            AuditAction.WIREGUARD_TUNNEL_CREATED,
            router=router,
            peer=peer,
            description=f"WireGuard tunnel created for router '{router.name}'",
        )
        event = TunnelCreated(
            router_id=router.id,
            peer_id=peer.id,
            tunnel_ip_address=peer.tunnel_ip_address,
        )
        logger.info("wireguard_tunnel_created", extra=_event_extra(event))
        return TunnelDeliveryInfo(
            peer=peer, peer_private_key=private_key, server=server
        )

    async def _allocate_and_persist(
        self,
        *,
        server: WireGuardServer,
        existing: WireGuardPeer | None,
        router_id: uuid.UUID,
    ) -> tuple[WireGuardPeer, str]:
        exclude_id = existing.id if existing is not None else None
        for attempt in range(_MAX_ALLOCATION_ATTEMPTS):
            occupied = await self.repository.list_occupied_tunnel_ips(
                server.id, exclude_peer_id=exclude_id
            )
            tunnel_ip = allocate_tunnel_ip(server.tunnel_network_cidr, occupied)
            private_key, public_key = generate_wireguard_keypair()
            try:
                if existing is not None:
                    peer = await self.repository.update_peer(
                        existing,
                        {
                            "server_id": server.id,
                            "tunnel_ip_address": tunnel_ip,
                            "public_key": public_key,
                            "private_key_encrypted": encrypt_secret(private_key),
                            "status": PeerStatus.PENDING.value,
                            "rotation_count": existing.rotation_count + 1,
                            "last_handshake_at": None,
                            "revoked_at": None,
                        },
                    )
                else:
                    peer = await self.repository.create_peer(
                        router_id=router_id,
                        server_id=server.id,
                        tunnel_ip_address=tunnel_ip,
                        public_key=public_key,
                        private_key_encrypted=encrypt_secret(private_key),
                        status=PeerStatus.PENDING.value,
                        rotation_count=0,
                        last_handshake_at=None,
                        revoked_at=None,
                    )
                return peer, private_key
            except DuplicateRecordError:
                # Lost a race for this tunnel_ip (or, vanishingly unlikely,
                # a public_key collision) -- retry with a fresh occupancy
                # read. See validators.allocate_tunnel_ip's module docstring.
                logger.warning(
                    "wireguard_tunnel_ip_allocation_conflict",
                    extra={"attempt": attempt + 1, "tunnel_ip": tunnel_ip},
                )
                continue
        raise TunnelIPAllocationConflictError()

    # ========================================================================
    # Revocation
    # ========================================================================

    async def revoke_tunnel(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> WireGuardPeer:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        peer = await self.repository.get_peer_by_router_id(router.id)
        if peer is None:
            raise WireGuardPeerNotFoundError(router.id)
        validate_peer_transition(peer.status, PeerStatus.REVOKED)

        now = datetime.now(UTC)
        updated = await self.repository.update_peer(
            peer, {"status": PeerStatus.REVOKED.value, "revoked_at": now}
        )
        await self._record_event_and_audit(
            actor_user_id,
            AuditAction.WIREGUARD_TUNNEL_REVOKED,
            router=router,
            peer=updated,
            description=f"WireGuard tunnel revoked for router '{router.name}'",
        )
        event = TunnelRevoked(router_id=router.id, peer_id=updated.id)
        logger.info("wireguard_tunnel_revoked", extra=_event_extra(event))
        return updated

    # ========================================================================
    # Rotation (key rotation == tunnel rotation -- see module docstring)
    # ========================================================================

    async def rotate_tunnel(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> TunnelDeliveryInfo:
        # include_deleted=True: same reasoning as create_tunnel's own
        # router lookup -- see that method's docstring.
        router = await self.router_lookup.get_router(
            router_id,
            requesting_organization_id=requesting_organization_id,
            include_deleted=True,
        )
        validate_router_eligible_for_wireguard(router)

        peer = await self.repository.get_peer_by_router_id(router.id)
        if peer is None:
            raise WireGuardPeerNotFoundError(router.id)
        # Rotation is not a transition on ``PEER_STATUS_TRANSITIONS`` in the
        # ordinary sense -- it is legal from *either* non-revoked state
        # (``pending`` -- e.g. a freshly-created peer the device hasn't
        # pulled yet -- or ``active``), always landing back on ``pending``.
        # ``validate_peer_transition`` is deliberately not consulted here:
        # its "no same-status no-op" discipline is correct for
        # ``revoke_tunnel`` (an ordinary state transition) but would wrongly
        # reject rotating an already-``pending`` peer, which has real,
        # non-no-op side effects (a brand new keypair) despite the status
        # value not changing. ``is_revoked()`` is the only illegal state.
        if peer.is_revoked():
            raise WireGuardPeerRevokedError(router.id)

        server = await self.get_server(peer.server_id)
        private_key, public_key = generate_wireguard_keypair()
        updated = await self.repository.update_peer(
            peer,
            {
                "public_key": public_key,
                "private_key_encrypted": encrypt_secret(private_key),
                "status": PeerStatus.PENDING.value,
                "rotation_count": peer.rotation_count + 1,
                "last_handshake_at": None,
            },
        )
        await self._record_event_and_audit(
            actor_user_id,
            AuditAction.WIREGUARD_TUNNEL_ROTATED,
            router=router,
            peer=updated,
            description=f"WireGuard tunnel keys rotated for router '{router.name}'",
        )
        event = TunnelRotated(
            router_id=router.id,
            peer_id=updated.id,
            rotation_count=updated.rotation_count,
        )
        logger.info("wireguard_tunnel_rotated", extra=_event_extra(event))
        return TunnelDeliveryInfo(
            peer=updated, peer_private_key=private_key, server=server
        )

    # ========================================================================
    # Device-facing: config pull + handshake reporting
    # ========================================================================

    async def get_config_for_agent(self, *, router: Router) -> TunnelDeliveryInfo:
        """Composes with ``app.domains.router_agent``'s ``CurrentAgent``
        dependency (see ``router.py``'s module docstring for the exact
        cross-domain wiring): ``router`` here is already the identity
        ``CurrentAgent`` resolved and validated from the device's persistent
        agent credential, so no further tenant-scoping check is needed --
        there is nothing left for the caller to spoof.

        On a peer's very first successful pull, transitions it
        ``pending -> active`` (see ``constants.PeerStatus``'s module
        docstring: this is the "delivered" signal, distinct from the
        time-based handshake/health signal)."""
        peer = await self.repository.get_peer_by_router_id(router.id)
        if peer is None or peer.is_revoked():
            raise WireGuardPeerNotFoundError(router.id)

        server = await self.get_server(peer.server_id)
        if peer.status == PeerStatus.PENDING.value:
            peer = await self.repository.update_peer(
                peer, {"status": PeerStatus.ACTIVE.value}
            )

        private_key = decrypt_secret(peer.private_key_encrypted)
        return TunnelDeliveryInfo(
            peer=peer, peer_private_key=private_key, server=server
        )

    async def record_handshake(self, *, router: Router) -> WireGuardPeer:
        """Device-facing handshake report -- the honest, DB-tracked proxy
        for a real ``wg show`` "latest handshake" reading this sandbox has
        no live WireGuard daemon to observe directly (see
        ``constants.HealthStatus``'s module docstring)."""
        peer = await self.repository.get_peer_by_router_id(router.id)
        if peer is None or peer.is_revoked():
            raise WireGuardPeerNotFoundError(router.id)

        now = datetime.now(UTC)
        data: dict[str, object] = {"last_handshake_at": now}
        if peer.status == PeerStatus.PENDING.value:
            data["status"] = PeerStatus.ACTIVE.value
        updated = await self.repository.update_peer(peer, data)

        event = TunnelHandshakeRecorded(router_id=router.id, peer_id=updated.id)
        logger.info("wireguard_handshake_recorded", extra=_event_extra(event))
        return updated

    # ========================================================================
    # Internal helpers
    # ========================================================================

    async def _record_event_and_audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        router: Router,
        peer: WireGuardPeer,
        description: str,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="wireguard_peer",
                entity_id=peer.id,
                description=description,
                event_metadata={"router_id": str(router.id)},
                organization_id=router.organization_id,
                location_id=router.location_id,
            )
        logger.info(
            "wireguard_audit_event",
            extra={"action": action.value, "entity_id": str(peer.id)},
        )


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick to ``app.domains.router_agent.service._event_extra``
    (``vars()`` doesn't work on slotted dataclasses)."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


__all__ = [
    "WireGuardService",
    "RouterLookupProtocol",
    "AuditLogWriter",
    "TunnelDeliveryInfo",
    "generate_wireguard_keypair",
]
