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

from .constants import FleetPeerStatus, HealthStatus, PeerStatus
from .events import TunnelCreated, TunnelHandshakeRecorded, TunnelRevoked, TunnelRotated
from .exceptions import (
    HubPeerListerNotConfiguredError,
    NoActiveWireGuardServerError,
    TunnelIPAllocationConflictError,
    WireGuardPeerAlreadyExistsError,
    WireGuardPeerNotFoundError,
    WireGuardPeerRevokedError,
    WireGuardPrivateKeyUnavailableError,
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

# Stored in ``WireGuardPeer.private_key_encrypted`` (``NOT NULL``, models.py)
# for a peer created with an externally (device-)supplied public key --
# see ``create_tunnel``'s ``external_public_key`` parameter, added for
# Module 009 Part 3 zero-touch enrollment. This module never possesses a
# real private key for such a peer (that is the entire point -- see
# ``app.domains.router.schemas.ProvisioningCheckInRequest
# .wireguard_public_key``'s own docstring), so the column cannot hold one;
# an unmistakable, never-a-real-base64-X25519-key marker is stored instead
# of e.g. an empty string, so any future reader (including
# ``render_wireguard_peer``) can tell at a glance "this row's private key
# is not recoverable, do not attempt to deliver or re-render it" rather
# than silently mis-decrypting/mis-delivering a nonsense value as if it
# were real key material.
#
# KNOWN GAP (documented, not fixed here -- would need a schema change
# outside this addition's footprint): nothing on ``WireGuardPeer`` itself
# records *that* a row is externally-managed versus platform-generated
# other than this sentinel's exact value. ``render_wireguard_peer`` checks
# for it (see that function's own docstring) so a full-config re-fetch
# does not push this sentinel to a device as a literal ``private-key=``,
# but a dedicated column (e.g. ``key_source``) would be the more durable
# fix if this pattern grows a second use.
EXTERNALLY_MANAGED_KEY_SENTINEL = "external:device-managed-key"


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


class HubPeerDeregistrar(Protocol):
    """Removes a peer from the hub itself.

    The hub is a second, independent record of the fleet: `wg0` plus
    `wg0.conf` on the tunnel box. Marking a peer REVOKED in the database
    frees its address for reuse HERE, while the hub keeps handing the old
    peer that same address -- so the next router provisioned gets an address
    another peer still claims, and WireGuard routes by allowed-ips.

    Measured 2026-08-23: 72 peers on the hub against 1 in the database, 68 of
    which had never completed a handshake.
    """

    async def __call__(self, public_key: str) -> None: ...


class HubPeerLister(Protocol):
    """Reads the hub's own live peer list -- ``GET /wg/peers`` on
    ``ops/hub-agents/wg_agent.py``, straight from ``wg show wg0 dump``.

    This is the other half of the same drift ``HubPeerDeregistrar``'s own
    docstring measures (72 peers on the hub against 1 in the database,
    2026-08-23): that number could only ever be produced by comparing the
    hub's real state against this table, which nothing did automatically
    until ``WireGuardService.get_fleet_status`` below. Each dict matches
    ``ops/hub-agents/wg_agent.py``'s ``list_peers()`` return shape exactly:
    ``public_key``, ``endpoint``, ``allowed_ips``,
    ``latest_handshake_epoch``, ``transfer_rx_bytes``,
    ``transfer_tx_bytes``.
    """

    async def __call__(self) -> list[dict]: ...


@dataclasses.dataclass(frozen=True, slots=True)
class FleetPeerEntry:
    """One row of ``WireGuardService.get_fleet_status``'s per-peer detail
    list -- a merge of whatever this table knows (if anything) and what the
    hub itself reports (if anything) for one WireGuard public key."""

    status: FleetPeerStatus
    public_key: str
    router_id: uuid.UUID | None
    router_name: str | None
    tunnel_ip_address: str | None
    last_handshake_at: datetime | None


@dataclasses.dataclass(frozen=True, slots=True)
class FleetStatus:
    """Return shape of ``WireGuardService.get_fleet_status`` -- a summary
    count per ``FleetPeerStatus`` plus the full per-peer detail list,
    exactly what ``router.py``'s ``GET /wireguard/fleet-status`` needs to
    answer "how many of the fleet are actually connected right now,
    according to the hub itself" and to surface any drift as data a human
    can act on rather than a number buried in a log line."""

    summary: dict[FleetPeerStatus, int]
    peers: list[FleetPeerEntry]


class WireGuardService:
    """Core WireGuard business logic."""

    def __init__(
        self,
        repository: WireGuardRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        handshake_stale_after_minutes: int = 5,
        hub_peer_deregistrar: HubPeerDeregistrar | None = None,
        hub_peer_lister: HubPeerLister | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        self.handshake_stale_after = timedelta(minutes=handshake_stale_after_minutes)
        # INJECTED, and it lives on the SERVICE rather than at the two call
        # sites on purpose. `revoke_tunnel` is reached from two places -- the
        # WireGuard DELETE endpoint and router decommission -- and "remember
        # to also tell the hub at every caller" is precisely the shape that
        # produced this bug: one side updated, the other not, nothing
        # reporting the difference. Injected rather than imported so the
        # in-memory test suite can drive it without HTTP.
        self.hub_peer_deregistrar = hub_peer_deregistrar
        # Same injection reasoning as `hub_peer_deregistrar` -- see
        # `get_fleet_status`, the only caller.
        self.hub_peer_lister = hub_peer_lister

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

    async def get_fleet_status(self, *, now: datetime | None = None) -> FleetStatus:
        """Merges this table's own record of the fleet against the hub's
        live ``wg show`` state (via ``hub_peer_lister``), classifying every
        peer found in EITHER source into exactly one of four
        ``FleetPeerStatus`` values. Platform-wide, not tenant-scoped -- see
        ``repository.list_all_peers_with_router_names``'s own docstring.

        Correlated by ``public_key`` -- the one identifier both sides
        genuinely share (this table's own unique constraint on it, and the
        hub's ``wg show`` dump keys every line by it too). A peer present
        on the hub but entirely absent from this table (``router_id`` is
        therefore unknown) is exactly the ``UNTRACKED_CONNECTED`` case this
        method exists to surface -- it is reported with ``router_id``/
        ``router_name`` both ``None`` rather than dropped, since a silent
        drop would recreate the exact blind spot ``HubPeerDeregistrar``'s
        own docstring measured (72 peers on the hub, 1 in the database).

        Raises ``HubPeerListerNotConfiguredError`` if no lister was
        injected, and propagates ``HubBridgeUnavailableError`` (from
        ``dependencies.make_hub_peer_lister``) if the hub is unreachable --
        neither is swallowed into a DB-only fallback, for the reason each
        exception's own docstring gives.
        """
        if self.hub_peer_lister is None:
            raise HubPeerListerNotConfiguredError()

        moment = now or datetime.now(UTC)
        hub_peers = {p["public_key"]: p for p in await self.hub_peer_lister()}
        db_rows = await self.repository.list_all_peers_with_router_names()
        db_by_key = {peer.public_key: (peer, name) for peer, name in db_rows}

        entries: list[FleetPeerEntry] = []

        for public_key, hub_peer in hub_peers.items():
            db_match = db_by_key.get(public_key)
            handshake_epoch = hub_peer["latest_handshake_epoch"]
            hub_last_handshake = (
                datetime.fromtimestamp(handshake_epoch, tz=UTC)
                if handshake_epoch > 0
                else None
            )
            is_recent = (
                hub_last_handshake is not None
                and moment - hub_last_handshake <= self.handshake_stale_after
            )
            if db_match is None:
                entries.append(
                    FleetPeerEntry(
                        status=FleetPeerStatus.UNTRACKED_CONNECTED,
                        public_key=public_key,
                        router_id=None,
                        router_name=None,
                        tunnel_ip_address=hub_peer.get("allowed_ips"),
                        last_handshake_at=hub_last_handshake,
                    )
                )
                continue
            peer, router_name = db_match
            entries.append(
                FleetPeerEntry(
                    status=(
                        FleetPeerStatus.TRACKED_CONNECTED
                        if is_recent
                        else FleetPeerStatus.TRACKED_STALE
                    ),
                    public_key=public_key,
                    router_id=peer.router_id,
                    router_name=router_name,
                    tunnel_ip_address=peer.tunnel_ip_address,
                    last_handshake_at=hub_last_handshake,
                )
            )

        # DB rows the hub has no record of at all -- a peer this platform
        # believes it provisioned that the hub has completely forgotten
        # (e.g. a `wg0.conf` rebuilt from an older backup). Not the drift
        # this feature was built to catch, but a real 4th state worth
        # surfacing rather than silently omitting.
        for public_key, (peer, router_name) in db_by_key.items():
            if public_key in hub_peers:
                continue
            entries.append(
                FleetPeerEntry(
                    status=FleetPeerStatus.TRACKED_MISSING_FROM_HUB,
                    public_key=public_key,
                    router_id=peer.router_id,
                    router_name=router_name,
                    tunnel_ip_address=peer.tunnel_ip_address,
                    last_handshake_at=peer.last_handshake_at,
                )
            )

        summary = {status: 0 for status in FleetPeerStatus}
        for entry in entries:
            summary[entry.status] += 1

        return FleetStatus(summary=summary, peers=entries)

    # ========================================================================
    # Tunnel creation / re-creation
    # ========================================================================

    async def create_tunnel(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        external_public_key: str | None = None,
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
        ``validate_router_eligible_for_wireguard`` below is meant to raise.

        ``external_public_key`` is an additive, optional parameter (Module
        009 Part 3, zero-touch enrollment): when supplied, allocation still
        runs through the exact same IP-allocation path below, but the
        peer's public key is *this* value, generated on-device, rather than
        a freshly platform-generated one -- see
        ``app.domains.router.schemas.ProvisioningCheckInRequest
        .wireguard_public_key``'s own docstring for why the platform must
        never generate (and therefore never hold a real private key for) a
        peer enrolled this way, and ``EXTERNALLY_MANAGED_KEY_SENTINEL``'s
        own comment for what is stored in ``private_key_encrypted`` instead."""
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
            server=server,
            existing=existing,
            router_id=router.id,
            external_public_key=external_public_key,
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

    async def ensure_tunnel_for_check_in(
        self,
        *,
        router_id: uuid.UUID,
        external_public_key: str | None = None,
    ) -> TunnelDeliveryInfo:
        """Device-enrollment (provisioning check-in) tunnel provisioning --
        the idempotent, re-run-safe entry point ``provisioning_check_in``
        composes with, so a technician re-pasting the bootstrap script is a
        supported recovery path, not a 409.

        First check-in behaves exactly like ``create_tunnel``. A repeat
        check-in (each re-paste carries a freshly-minted one-time token --
        ``RouterService.preview_bootstrap_script`` rewinds and re-mints)
        finds the router's existing live peer and **rotates** it in place
        via ``rotate_tunnel`` (fresh platform keypair, same tunnel IP,
        ``rotation_count`` bumped) instead of raising
        ``WireGuardPeerAlreadyExistsError``. That reject-over-recreate
        stance is deliberately preserved on the *admin* surface, where an
        explicit revoke must stay the one place a teardown is decided; a
        device re-enrolling with a valid one-time provisioning token has
        already proven exactly the authority a first enrollment proves, and
        the bootstrap script it is running is about to recreate its local
        interface against whatever this method returns.

        The rotate path deliberately does not consult
        ``external_public_key``: a device re-running the legacy
        device-generated-keypair script never reaches check-in with a live
        peer (its own ``/interface wireguard add`` line fails on the
        duplicate interface name first), so a live peer plus a supplied
        public key falls through to ``create_tunnel``'s existing, documented
        ``WireGuardPeerAlreadyExistsError`` rather than silently rebinding
        an admin-created tunnel to an unknown key."""
        if external_public_key is None:
            existing = await self.repository.get_peer_by_router_id(router_id)
            if existing is not None and not existing.is_revoked():
                return await self.rotate_tunnel(
                    actor_user_id=None,
                    router_id=router_id,
                    requesting_organization_id=None,
                )
        return await self.create_tunnel(
            actor_user_id=None,
            router_id=router_id,
            requesting_organization_id=None,
            external_public_key=external_public_key,
        )

    async def register_agent_allocated_peer(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        tunnel_ip_address: str,
        public_key: str,
    ) -> WireGuardPeer:
        """Records a peer the Master console's Setup Script panel already
        had a *different*, out-of-band bridge (a small agent process on
        the hub itself, not this domain) allocate and configure directly
        against the real hub -- see that panel's own comment for why:
        this domain's own ``create_tunnel`` has never had a way to
        actually reach a live hub (a genuine, honestly-documented gap,
        not a bug in this method), so the panel used the one thing that
        could, and this platform's own ``WireGuardPeer`` table never
        found out a tunnel existed at all. Confirmed live this session:
        the real, working production tunnel had no DB row whatsoever.

        Unlike ``create_tunnel``/``_allocate_and_persist``, this does
        **not** allocate a fresh IP or generate a keypair -- both are
        already decided (by the external bridge, before this call), so
        recording anything else here would just be wrong. It only
        validates the given IP isn't already claimed by a *different*
        peer on this hub (``TunnelIPAllocationConflictError`` if so) and
        writes/updates a real row with the exact values already live on
        the device. The private key is never known to this domain (the
        bridge is what generated and pushed it to the hub) -- stored as
        ``EXTERNALLY_MANAGED_KEY_SENTINEL``, the same convention
        ``create_tunnel``'s own ``external_public_key`` path already
        establishes for "a real key exists, but not one this domain ever
        held or can hand back."
        """
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        server = await self.get_active_server()
        existing = await self.repository.get_peer_by_router_id(router.id)

        occupied = await self.repository.list_occupied_tunnel_ips(
            server.id, exclude_peer_id=existing.id if existing is not None else None
        )
        if tunnel_ip_address in occupied:
            raise TunnelIPAllocationConflictError()

        fields = {
            "server_id": server.id,
            "tunnel_ip_address": tunnel_ip_address,
            "public_key": public_key,
            "private_key_encrypted": encrypt_secret(EXTERNALLY_MANAGED_KEY_SENTINEL),
            "status": PeerStatus.PENDING.value,
            "revoked_at": None,
        }
        if existing is not None:
            fields["rotation_count"] = existing.rotation_count + 1
            fields["last_handshake_at"] = None
            peer = await self.repository.update_peer(existing, fields)
        else:
            peer = await self.repository.create_peer(
                router_id=router.id, created_by=actor_user_id, **fields
            )

        await self._record_event_and_audit(
            actor_user_id,
            AuditAction.WIREGUARD_TUNNEL_CREATED,
            router=router,
            peer=peer,
            description=(
                f"WireGuard tunnel for router '{router.name}' registered "
                "from agent-allocated values"
            ),
        )
        logger.info(
            "wireguard_agent_peer_registered",
            extra={"router_id": str(router.id), "tunnel_ip_address": tunnel_ip_address},
        )
        return peer

    async def _allocate_and_persist(
        self,
        *,
        server: WireGuardServer,
        existing: WireGuardPeer | None,
        router_id: uuid.UUID,
        external_public_key: str | None = None,
    ) -> tuple[WireGuardPeer, str]:
        exclude_id = existing.id if existing is not None else None
        for attempt in range(_MAX_ALLOCATION_ATTEMPTS):
            occupied = await self.repository.list_occupied_tunnel_ips(
                server.id, exclude_peer_id=exclude_id
            )
            tunnel_ip = allocate_tunnel_ip(server.tunnel_network_cidr, occupied)
            if external_public_key is not None:
                # Device-generated keypair (see create_tunnel's own
                # docstring) -- the platform only ever learns the public
                # half, so private_key here is the documented sentinel, not
                # a real secret, and must never be delivered to any caller
                # as though it were one.
                public_key = external_public_key
                private_key = EXTERNALLY_MANAGED_KEY_SENTINEL
            else:
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
                #
                # CAVEAT (not exercised by this loop's own unit tests, which
                # use an in-memory fake repository): against the real
                # ``GenericRepository``, ``_flush_or_raise`` converts the
                # underlying ``IntegrityError`` into this exception via a
                # full ``session.rollback()`` -- for a caller sharing one
                # session/transaction across many already-flushed steps
                # (``LocationProvisioningService.provision_location``), that
                # can expire ORM state from earlier in the same request and
                # make a *second* collision here surface as a confusing
                # ``sqlalchemy.exc.MissingGreenlet`` instead of a clean
                # domain error, rather than cleanly retrying. In practice
                # this loop's realistic trigger (a revoked peer's tunnel IP
                # never actually being freed at the DB level) is fixed at
                # the source in ``revoke_tunnel`` below, which is expected
                # to make hitting this branch at all rare going forward. See
                # request_id ef092a85-0ff0-49b8-801f-327b733288f5 for a live
                # repro of the pre-fix crash.
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
        # Release the tunnel IP back to the pool -- ``(server_id,
        # tunnel_ip_address)`` carries an unconditional DB unique
        # constraint (models.py), so leaving a revoked peer's real address
        # in place would permanently block any *other* router from ever
        # being allocated that same address again: ``_allocate_and_persist``
        # already treats a revoked peer's IP as free (``list_occupied_tunnel_ips``
        # excludes non-active statuses), but that promise was never actually
        # honored at the database level -- the stale row's address would
        # deterministically collide on every future allocation attempt that
        # reached it (``allocate_tunnel_ip`` walks candidates in address
        # order, so a low, once-used address is retried indefinitely). A
        # deterministic, per-peer-unique placeholder both satisfies the
        # ``nullable=False`` column and can never again collide with a real
        # allocated address.
        released_tunnel_ip = peer.tunnel_ip_address
        revoked_public_key = peer.public_key

        # THE HUB FIRST, AND ITS FAILURE IS FATAL.
        #
        # Order matters. Freeing the address in the database while the hub
        # still holds it is the exact state that produced 68 orphaned peers:
        # the allocator then hands that address to the next router while the
        # old peer still claims it, and WireGuard routes by allowed-ips, so
        # both break in a way that reads as "the tunnel is flaky".
        #
        # RAISES rather than logging a warning and carrying on. The
        # RadiusNasClient deregistration made exactly that choice and the
        # result was a database with zero NAS clients and a hub with 21
        # stanzas, reported to the operator as success. A revoke that could
        # not reach the hub has not revoked anything; saying otherwise is
        # worse than failing.
        if self.hub_peer_deregistrar is not None:
            await self.hub_peer_deregistrar(revoked_public_key)

        updated = await self.repository.update_peer(
            peer,
            {
                "status": PeerStatus.REVOKED.value,
                "revoked_at": now,
                "tunnel_ip_address": f"revoked:{peer.id}",
            },
        )
        await self._record_event_and_audit(
            actor_user_id,
            AuditAction.WIREGUARD_TUNNEL_REVOKED,
            router=router,
            peer=updated,
            description=(
                f"WireGuard tunnel revoked for router '{router.name}' "
                f"(released {released_tunnel_ip})"
            ),
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

        private_key = decrypt_secret(peer.private_key_encrypted)
        if private_key == EXTERNALLY_MANAGED_KEY_SENTINEL:
            # The bootstrap script would otherwise install this literal
            # sentinel string as its private-key= -- see the exception's
            # own docstring. Checked before the pending -> active flip so a
            # peer whose key was never deliverable is not marked delivered.
            raise WireGuardPrivateKeyUnavailableError(router.id)

        server = await self.get_server(peer.server_id)
        if peer.status == PeerStatus.PENDING.value:
            peer = await self.repository.update_peer(
                peer, {"status": PeerStatus.ACTIVE.value}
            )

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
