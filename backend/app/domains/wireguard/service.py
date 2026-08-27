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
import contextlib
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

from .constants import (
    FleetPeerStatus,
    HealthStatus,
    HubPeerLifecycle,
    HubRemovalOutcome,
    PeerIdentitySource,
    PeerStatus,
)
from .events import TunnelCreated, TunnelHandshakeRecorded, TunnelRevoked, TunnelRotated
from .exceptions import (
    HubCannotLearnPlatformKeyError,
    HubPeerClaimedByAnotherRouterError,
    HubPeerListerNotConfiguredError,
    HubPeerNotOnHubError,
    NoActiveWireGuardServerError,
    TunnelIPAllocationConflictError,
    WireGuardPeerAlreadyExistsError,
    WireGuardPeerNotFoundError,
    WireGuardPeerRevokedError,
    WireGuardPrivateKeyUnavailableError,
    WireGuardServerNotFoundError,
)
from .models import WireGuardPeer, WireGuardPeerIssuance, WireGuardServer
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


@dataclasses.dataclass(frozen=True, slots=True)
class HubCapabilities:
    """What the *deployed* hub agent can actually be asked to do.

    This is the seam that keeps "what the backend should do today" and
    "what becomes possible once a new agent is installed" from being
    confused with each other. Both behaviours live in the code; which one
    runs is one boolean, set from settings, and nothing else changes.

    Today, against ``ops/hub-agents/wg_agent.py`` as running on
    ``172.31.40.230``, both are ``False``:

    * ``can_register_public_key`` -- there is no verb that accepts a public
      key the hub did not generate. ``POST /wg/peer`` takes an empty body
      and mints its own keypair. So every platform-generated keypair
      (``create_tunnel``'s default path, ``rotate_tunnel``) describes a
      tunnel that cannot establish, because the hub is still expecting the
      previous key. Guarded by ``HubCannotLearnPlatformKeyError`` rather
      than written and hoped over.
    * ``can_remove_peer`` -- ``DELETE /wg/peer`` returns ``501 Unsupported
      method``. A ``do_DELETE`` handler exists in the repo and is correct;
      it is undeployable because that host has no shell (no key, no EC2
      Instance Connect on its Debian AMI, no SSM agent, no instance
      profile). Until it lands, superseded peers are permanent, and the
      platform's job is to *account* for them (see
      ``constants.HubPeerLifecycle.ORPHANED`` and the quarantine in
      ``_allocate_and_persist``) rather than to keep pretending a removal
      might work.

    Defaults are ``True`` -- i.e. "a fully-featured hub" -- so that the
    in-memory test suite and any future agent get the unrestricted
    behaviour without opting in, and only the real, degraded production
    wiring (``dependencies.get_wireguard_service``) has to say so
    explicitly. A default of ``False`` would encode today's accident as
    the domain's idea of normal.
    """

    can_register_public_key: bool = True
    can_remove_peer: bool = True


class HubPeerDeregistrar(Protocol):
    """Removes a peer from the hub itself.

    The hub is a second, independent record of the fleet: `wg0` plus
    `wg0.conf` on the tunnel box. Marking a peer REVOKED in the database
    frees its address for reuse HERE, while the hub keeps handing the old
    peer that same address -- so the next router provisioned gets an address
    another peer still claims, and WireGuard routes by allowed-ips.

    Measured 2026-08-23: 72 peers on the hub against 1 in the database, 68 of
    which had never completed a handshake.

    Returns a ``HubRemovalOutcome`` rather than ``None``. The three values
    are three genuinely different states of the world -- gone, never there,
    and "this agent cannot do that" -- and the caller has a different
    correct response to each. Returning ``None`` for all three is what let
    a permanent ``501`` be handled as though it were a hiccup, once per
    orphaned peer, for weeks. A transport failure remains an exception, not
    a fourth value: see ``constants.HubRemovalOutcome``.
    """

    async def __call__(self, public_key: str) -> HubRemovalOutcome: ...


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


class PeerAddressListener(Protocol):
    """Notified after a peer's tunnel ADDRESS changes -- adoption, or any
    other correction that moves a router from one address to another.

    Exists because the WireGuard address and the FreeRADIUS ``client{}``
    stanza keyed on it are two halves of one fact, and nothing owned the
    pair. ``register_external_radius_nas`` derives the NAS address from
    ``peer.tunnel_ip_address`` once, at registration, and never again; on
    2026-08-27 the hub therefore held a stanza for ``10.20.0.8`` while the
    router was on ``10.20.0.6``, and every guest's Access-Request was
    dropped as coming from an unknown client -- silently, because an
    unknown client gets no reply at all.

    Deliberately a notification, not a transaction participant. If the
    re-push fails, the WireGuard adoption still stands: the platform's
    record of the router's identity is now *correct*, which is strictly
    better than leaving it wrong, and the mismatch it leaves behind
    (``RadiusNasClient.hub_client_synced_ip != peer.tunnel_ip_address``) is
    exactly what the next reconciliation pass looks for. The system
    converges instead of rolling back."""

    async def __call__(
        self,
        *,
        router_id: uuid.UUID,
        previous_tunnel_ip_address: str,
        tunnel_ip_address: str,
    ) -> None: ...


@dataclasses.dataclass(frozen=True, slots=True)
class FleetPeerEntry:
    """One row of ``WireGuardService.get_fleet_status``'s per-peer detail
    list -- a merge of whatever this table knows (if anything), what the
    issuance ledger can attribute (if anything), and what the hub itself
    reports (if anything) for one WireGuard public key."""

    status: FleetPeerStatus
    public_key: str
    router_id: uuid.UUID | None
    router_name: str | None
    tunnel_ip_address: str | None
    last_handshake_at: datetime | None
    # The address the HUB has in ``allowed-ips`` for this key, when the hub
    # knows the key at all. Reported alongside ``tunnel_ip_address`` (this
    # table's belief) rather than instead of it, because the two
    # disagreeing IS the finding -- collapsing them into one field is what
    # made a `.6`/`.8` split look like a healthy row.
    hub_tunnel_ip_address: str | None = None
    # Plain-English reason this row is classified the way it is. Written for
    # the operator staring at seven peers on a hub trying to work out which
    # ones matter; an orphan that says why it is an orphan is not drift.
    explanation: str | None = None


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
    # Public keys this pass actually adopted (``adopt=True`` only). Empty on
    # a plain read. Returned rather than only logged so the caller --
    # `hub_reconciliation`, which owns the RADIUS half -- can tell whether
    # anything changed without diffing two fleet reads.
    adopted_public_keys: list[str] = dataclasses.field(default_factory=list)


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
        hub_capabilities: HubCapabilities | None = None,
        peer_address_listener: PeerAddressListener | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        self.handshake_stale_after = timedelta(minutes=handshake_stale_after_minutes)
        # What the deployed hub agent can actually be asked to do -- see
        # `HubCapabilities`. Defaults to a fully-featured hub so the only
        # place that has to state today's degraded reality is the real
        # production wiring.
        self.hub_capabilities = hub_capabilities or HubCapabilities()
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
        # Notified whenever a peer's tunnel ADDRESS changes, which is the
        # event the RADIUS `client{}` stanza has to follow and never did.
        # Injected (and left `None` here) rather than imported so this
        # domain keeps its one-way dependency on `app.domains.router`/`rbac`
        # and nothing else -- `app.domains.guest` already imports THIS
        # module, so importing it back would close a cycle. The concrete
        # listener is built in `app.domains.hub_reconciliation`, which is
        # allowed to know about both.
        self.peer_address_listener = peer_address_listener

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
    # Issuance ledger -- the record of what this platform has handed out.
    # See ``models.WireGuardPeerIssuance``'s module docstring for why a hub
    # with no delete verb makes a superseded identity worth keeping.
    # ========================================================================

    async def _record_issuance(
        self,
        *,
        router_id: uuid.UUID,
        server_id: uuid.UUID,
        public_key: str,
        tunnel_ip_address: str,
        source: PeerIdentitySource,
        hub_lifecycle: HubPeerLifecycle,
        actor_user_id: uuid.UUID | None = None,
        note: str | None = None,
    ) -> WireGuardPeerIssuance:
        """Writes one ledger row and marks any previous live one for this
        router superseded. Called from every path that changes what the
        platform believes a router's WireGuard identity is -- there is no
        other way to change it, which is what makes the ledger complete
        going forward (it is, unavoidably, empty for anything issued before
        this shipped; see ``adopt_hub_peer`` for how those are handled)."""
        await self._supersede_current_issuance(
            router_id, replaced_by_public_key=public_key
        )
        return await self.repository.create_issuance(
            router_id=router_id,
            server_id=server_id,
            public_key=public_key,
            tunnel_ip_address=tunnel_ip_address,
            source=source.value,
            hub_lifecycle=hub_lifecycle.value,
            superseded_at=None,
            note=note,
            created_by=actor_user_id,
        )

    async def _supersede_current_issuance(
        self, router_id: uuid.UUID, *, replaced_by_public_key: str
    ) -> None:
        """Closes out whatever ledger row was current for ``router_id``.

        ``hub_lifecycle`` is NOT touched here on purpose. Whether the hub
        still holds the superseded peer is a fact about the hub, decided by
        whoever actually tried to remove it (``_deregister_from_hub``) --
        not something this bookkeeping step gets to assume. A row left at
        ``LIVE`` after being superseded and never successfully removed is
        promoted to ``ORPHANED`` by that call, and stays quarantined either
        way, so a missed promotion can only ever be conservative."""
        now = datetime.now(UTC)
        for issuance in await self.repository.list_issuances_for_router(router_id):
            if issuance.superseded_at is not None:
                continue
            if issuance.public_key == replaced_by_public_key:
                continue
            await self.repository.update_issuance(issuance, {"superseded_at": now})

    async def _deregister_from_hub(
        self, public_key: str, *, router_id: uuid.UUID
    ) -> HubRemovalOutcome:
        """Asks the hub to drop ``public_key`` and reports honestly what
        happened, updating the ledger to match.

        Never raises for the ``501`` case -- that is not a failure to
        handle, it is the deployed hub's permanent shape, and treating it
        as an exception once per superseded peer is what buried it in
        stack traces. It IS recorded, as ``HubPeerLifecycle.ORPHANED`` on
        the ledger row, which is a durable fact an operator can query
        rather than a WARNING that scrolls past.

        A genuinely unreachable hub still raises (via the deregistrar) --
        callers decide whether that is fatal. "We could not ask" and "we
        asked and it cannot" are different, and the difference is the whole
        point of this function."""
        if self.hub_peer_deregistrar is None:
            # No bridge is configured at all, so this deployment never
            # pushed anything to a hub through this service and there is
            # nothing there to orphan. Deliberately NOT the same answer as
            # "a bridge exists and cannot remove": marking these ORPHANED
            # would quarantine tunnel addresses forever in a deployment
            # that has no hub, which is the in-memory test suite and any
            # future hub-less configuration.
            outcome = HubRemovalOutcome.NOT_PRESENT
        elif not self.hub_capabilities.can_remove_peer:
            # A bridge exists and this hub genuinely holds the peer -- we
            # simply have no verb to ask. Skipping the call rather than
            # making it is not an optimisation: `501` is a known, permanent
            # answer, and re-asking every time produced one stack trace per
            # superseded peer for weeks while changing nothing.
            outcome = HubRemovalOutcome.UNSUPPORTED
        else:
            outcome = await self.hub_peer_deregistrar(public_key)

        lifecycle = {
            HubRemovalOutcome.REMOVED: HubPeerLifecycle.REMOVED,
            HubRemovalOutcome.NOT_PRESENT: HubPeerLifecycle.NEVER_REGISTERED,
            HubRemovalOutcome.UNSUPPORTED: HubPeerLifecycle.ORPHANED,
        }[outcome]
        issuance = await self.repository.get_issuance_by_public_key(public_key)
        if issuance is not None:
            await self.repository.update_issuance(
                issuance, {"hub_lifecycle": lifecycle.value}
            )
        if outcome is HubRemovalOutcome.UNSUPPORTED:
            logger.info(
                "wireguard_peer_orphaned_on_hub",
                extra={
                    "router_id": str(router_id),
                    "public_key": public_key,
                    "detail": (
                        "recorded as a known orphan -- the deployed hub agent "
                        "has no peer-removal verb, so this peer and its tunnel "
                        "address stay quarantined until one is installed"
                    ),
                },
            )
        return outcome

    async def _hub_peers_by_key(self) -> dict[str, dict] | None:
        """``GET /wg/peers`` keyed by public key, or ``None`` when the hub
        cannot be consulted at all (not configured, or unreachable).

        ``None`` is deliberately distinct from ``{}``: an empty hub is a
        real answer that means "the hub has forgotten everything", while an
        unreachable hub means "we do not know", and the two must never lead
        to the same decision. Conflating them is how a transient bridge
        blip could otherwise cost a router a permanent, unreclaimable peer
        allocation."""
        if self.hub_peer_lister is None:
            return None
        try:
            return {p["public_key"]: p for p in await self.hub_peer_lister()}
        except Exception:  # noqa: BLE001 -- see docstring; "unknown", not "empty"
            logger.warning(
                "wireguard_hub_peer_list_unavailable",
                extra={
                    "detail": (
                        "treating the hub's state as UNKNOWN rather than empty "
                        "-- every caller's safe fallback is to change nothing"
                    )
                },
                exc_info=True,
            )
            return None

    @staticmethod
    def _hub_address(hub_peer: dict) -> str | None:
        """The bare host address out of a hub peer's ``allowed-ips``.

        ``wg show dump`` renders this as a CIDR (``10.20.0.6/32``) and may
        list several, comma-separated. This platform allocates exactly one
        ``/32`` per peer (``wg_agent.allocate_peer``), so the first entry is
        the address -- but the ``/32`` has to come off before it can be
        compared with ``WireGuardPeer.tunnel_ip_address``, which stores a
        bare host address. Comparing the two forms directly is a mismatch
        that always reports true, which would make the address check
        useless in exactly the incident it was written for."""
        allowed = hub_peer.get("allowed_ips") or ""
        first = allowed.split(",")[0].strip()
        return first.split("/")[0] or None if first else None

    async def get_fleet_status(
        self, *, now: datetime | None = None, adopt: bool = False
    ) -> FleetStatus:
        """Merges this table's own record of the fleet, the issuance ledger,
        and the hub's live ``wg show`` state into one classified view --
        and, when ``adopt`` is set, repairs the disagreements it is certain
        about. Platform-wide, not tenant-scoped: see
        ``repository.list_all_peers_with_router_names``'s own docstring.

        Correlated by ``public_key`` -- the one identifier all three sources
        genuinely share.

        ## What changed, and why a read now writes

        The original version classified anything the hub had and this table
        did not as ``UNTRACKED_CONNECTED`` -- "no idea what this is". On
        2026-08-27 that was a lie about six of the seven peers on the
        production hub: the platform had allocated every one of them, for a
        single router, over twelve minutes, and then overwritten its own
        only record of having done so. ``wireguard_peer_issuances`` is that
        record kept; this method is what reads it back. An untracked hub
        peer the ledger can attribute is not drift, it is history, and it
        now says so.

        ## Adoption, and why it is BOTH automatic and operator-confirmed

        The device holds a private key nobody else has -- not the hub
        (``allocate_peer`` generates and forgets it), and never this
        platform (``EXTERNALLY_MANAGED_KEY_SENTINEL``). No server-side
        action can change what key that device is using. So when the hub
        shows a device handshaking on a key this table does not have, the
        table is what is wrong, and the only correct repair is to write
        down what the device demonstrably is.

        Automatic, but only where the evidence is a proof rather than an
        inference. All three must hold:

        1. the ledger attributes the key to a specific router (the platform
           issued it, so this is not a guess about whose device it is);
        2. the hub reports a handshake within the staleness window (the
           device is using it *now*, not once, months ago); and
        3. the router's currently-recorded peer has never handshaked on its
           own key -- so the record being overwritten is an unproven
           assertion, never a competing observation.

        Where (3) fails -- two keys for one router both live -- adoption
        stops and the row is reported ``ADOPTABLE_MISMATCH`` for a human.
        That is a genuinely ambiguous state (a half-migrated device, or two
        routers sharing a WAN), and picking one automatically would be the
        same class of confident-and-wrong the ledger exists to end. Where
        (1) fails, the key is unattributable and only
        ``adopt_hub_peer``'s explicit operator call can bind it -- which is
        exactly the path the seven pre-ledger orphans need.

        ``adopt`` defaults to ``False`` so ``GET /wireguard/fleet-status``
        stays a view. The reconciliation pass, which owns the RADIUS half
        of the repair, is the only caller that passes ``True``.

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
        db_by_router = {peer.router_id: (peer, name) for peer, name in db_rows}
        issuance_by_key: dict[str, WireGuardPeerIssuance] = {}
        for issuance in await self.repository.list_all_issuances():
            # `list_all_issuances` is created_at DESC, so the first row seen
            # for a key is its most recent -- an adoption beats the original
            # issuance of the same key, which is what a caller asking "whose
            # key is this" wants.
            issuance_by_key.setdefault(issuance.public_key, issuance)

        entries: list[FleetPeerEntry] = []
        adopted: list[str] = []

        def _is_recent(handshake: datetime | None) -> bool:
            return (
                handshake is not None
                and moment - handshake <= self.handshake_stale_after
            )

        for public_key, hub_peer in hub_peers.items():
            hub_address = self._hub_address(hub_peer)
            handshake_epoch = hub_peer["latest_handshake_epoch"]
            hub_last_handshake = (
                datetime.fromtimestamp(handshake_epoch, tz=UTC)
                if handshake_epoch > 0
                else None
            )
            is_recent = _is_recent(hub_last_handshake)
            db_match = db_by_key.get(public_key)

            if db_match is None:
                issuance = issuance_by_key.get(public_key)
                if issuance is None:
                    entries.append(
                        FleetPeerEntry(
                            status=FleetPeerStatus.UNTRACKED_CONNECTED,
                            public_key=public_key,
                            router_id=None,
                            router_name=None,
                            tunnel_ip_address=None,
                            hub_tunnel_ip_address=hub_address,
                            last_handshake_at=hub_last_handshake,
                            explanation=(
                                "The hub holds this peer and nothing in this "
                                "platform can attribute it -- no peer row and "
                                "no issuance record. Either it predates the "
                                "issuance ledger (everything allocated before "
                                "2026-08-27 does) or it was added directly on "
                                "the hub. Bind it with POST /wireguard/hub-"
                                "peers/{public_key}/adopt once you know which "
                                "router it belongs to."
                            ),
                        )
                    )
                    continue

                # SELF-CORRECT THE LEDGER FROM OBSERVATION.
                #
                # The hub demonstrably holds this key. If our record says it
                # was never registered there, our record is wrong, and
                # leaving it wrong un-quarantines an address the hub is
                # actively routing -- the allocator would then be free to
                # hand it to a different router. Promoting on a hub read
                # rather than trusting the write path is the same principle
                # adoption runs on: an observation beats an assertion.
                if issuance.hub_lifecycle == HubPeerLifecycle.NEVER_REGISTERED.value:
                    issuance = await self.repository.update_issuance(
                        issuance,
                        {"hub_lifecycle": HubPeerLifecycle.ORPHANED.value},
                    )

                current = db_by_router.get(issuance.router_id)
                current_peer = current[0] if current is not None else None
                router_name = current[1] if current is not None else None
                can_adopt = (
                    is_recent
                    and current_peer is not None
                    and not current_peer.is_revoked()
                    and current_peer.public_key != public_key
                    and current_peer.last_handshake_at is None
                )
                if can_adopt and adopt:
                    assert current_peer is not None  # noqa: S101 -- guarded above
                    await self._apply_adoption(
                        actor_user_id=None,
                        peer=current_peer,
                        public_key=public_key,
                        tunnel_ip_address=hub_address
                        or current_peer.tunnel_ip_address,
                        last_handshake_at=hub_last_handshake,
                        source=PeerIdentitySource.ADOPTED,
                        hub_peers=hub_peers,
                        note=(
                            "adopted automatically: the hub reports this key "
                            "handshaking, the issuance ledger attributes it to "
                            "this router, and the recorded peer had never "
                            "handshaked"
                        ),
                    )
                    adopted.append(public_key)
                    entries.append(
                        FleetPeerEntry(
                            status=FleetPeerStatus.TRACKED_CONNECTED,
                            public_key=public_key,
                            router_id=issuance.router_id,
                            router_name=router_name,
                            tunnel_ip_address=hub_address,
                            hub_tunnel_ip_address=hub_address,
                            last_handshake_at=hub_last_handshake,
                            explanation=(
                                "Adopted on this pass -- this table now records "
                                "the identity the device is demonstrably using."
                            ),
                        )
                    )
                    continue

                entries.append(
                    FleetPeerEntry(
                        status=(
                            FleetPeerStatus.ADOPTABLE_MISMATCH
                            if is_recent
                            else FleetPeerStatus.KNOWN_ORPHAN
                        ),
                        public_key=public_key,
                        router_id=issuance.router_id,
                        router_name=router_name,
                        tunnel_ip_address=(
                            current_peer.tunnel_ip_address
                            if current_peer is not None
                            else None
                        ),
                        hub_tunnel_ip_address=hub_address,
                        last_handshake_at=hub_last_handshake,
                        explanation=(
                            issuance.note
                            or self._explain_unadopted(
                                is_recent=is_recent,
                                current_peer=current_peer,
                                hub_lifecycle=issuance.hub_lifecycle,
                            )
                        ),
                    )
                )
                continue

            peer, router_name = db_match
            # RECONCILE THE HANDSHAKE WE JUST LEARNED ABOUT.
            #
            # `last_handshake_at` previously had exactly one writer --
            # `record_handshake`, which only the ROUTER'S OWN AGENT can
            # call. That is a circular dependency the moment anything is
            # wrong: an agent whose credential has been rotated, or whose
            # tunnel is the thing being diagnosed, cannot report the very
            # handshake that would prove the tunnel is fine.
            #
            # Confirmed live 2026-08-27 on router 01c9171e: the hub showed a
            # current handshake on 10.20.0.3 while this row held
            # `status='pending'` and `last_handshake_at IS NULL`, so
            # `compute_health_status` returned UNKNOWN and the WireGuard tab
            # showed a tunnel that had "never connected" -- about a tunnel
            # that was up at that moment.
            #
            # The hub is the authority on whether a handshake happened; we
            # have just read it. Writing it here is not papering over the
            # drift, it is closing the only gap that made the drift
            # unobservable. Strictly monotonic -- we never move the
            # timestamp backwards, so a fresher agent-reported value is
            # never clobbered by a stale hub read.
            if hub_last_handshake is not None and (
                peer.last_handshake_at is None
                or peer.last_handshake_at < hub_last_handshake
            ):
                reconciled: dict[str, object] = {
                    "last_handshake_at": hub_last_handshake
                }
                # A peer the hub has genuinely handshaked with is ACTIVE by
                # definition. PENDING means "recorded, never seen"; leaving
                # it PENDING after observing a handshake is the same lie in
                # a different column. REVOKED is deliberately untouched: a
                # revoked peer still handshaking is a real security finding
                # that must keep reporting as revoked, not be quietly
                # resurrected by a background read.
                if peer.status == PeerStatus.PENDING.value:
                    reconciled["status"] = PeerStatus.ACTIVE.value
                peer = await self.repository.update_peer(peer, reconciled)

            # THE ADDRESS DISAGREEMENT, REPORTED SEPARATELY.
            #
            # Same key on both sides, different tunnel address. Its own
            # status because the FreeRADIUS `client{}` stanza is keyed on
            # that address (`radius_agent.add_client` writes
            # `ipaddr = <tunnel_ip>/32`), so this specific mismatch means
            # every guest Access-Request from this router is dropped as an
            # unknown client -- with no reply and nothing logged, which is
            # what made it cost a day to find. A row that merely reads
            # "connected" would hide it completely.
            address_mismatch = (
                hub_address is not None
                and not peer.is_revoked()
                and hub_address != peer.tunnel_ip_address
            )
            if address_mismatch:
                status_value = FleetPeerStatus.TRACKED_KEY_MISMATCH
                explanation = (
                    f"The hub routes this key to {hub_address} but this "
                    f"platform records {peer.tunnel_ip_address}. The RADIUS "
                    "client stanza is keyed on the address, so guest logins "
                    "on this router are being dropped as an unknown client "
                    "until the two agree."
                )
            else:
                status_value = (
                    FleetPeerStatus.TRACKED_CONNECTED
                    if is_recent
                    else FleetPeerStatus.TRACKED_STALE
                )
                explanation = None

            entries.append(
                FleetPeerEntry(
                    status=status_value,
                    public_key=public_key,
                    router_id=peer.router_id,
                    router_name=router_name,
                    tunnel_ip_address=peer.tunnel_ip_address,
                    hub_tunnel_ip_address=hub_address,
                    last_handshake_at=hub_last_handshake,
                    explanation=explanation,
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
                    hub_tunnel_ip_address=None,
                    last_handshake_at=peer.last_handshake_at,
                    explanation=(
                        "This platform records a peer the hub has never heard "
                        "of. A platform-generated keypair is the usual cause: "
                        "the hub agent has no verb to be told a public key it "
                        "did not generate, so a rotation writes a key that "
                        "exists only here. This tunnel cannot establish."
                    ),
                )
            )

        summary = {status: 0 for status in FleetPeerStatus}
        for entry in entries:
            summary[entry.status] += 1

        return FleetStatus(
            summary=summary, peers=entries, adopted_public_keys=adopted
        )

    @staticmethod
    def _explain_unadopted(
        *,
        is_recent: bool,
        current_peer: WireGuardPeer | None,
        hub_lifecycle: str,
    ) -> str:
        """Why an attributable hub peer was reported rather than adopted.

        Split out because there are four distinct reasons and an operator
        reading a fleet-status page needs to know which one applies before
        deciding whether to act -- "not adopted" alone is the same
        unhelpful non-answer ``UNTRACKED_CONNECTED`` used to give."""
        if current_peer is None:
            return (
                "Issued to a router that no longer has a peer row (revoked, "
                "or the router was deleted). The hub still holds it because "
                "the deployed agent has no removal verb."
            )
        if not is_recent:
            return (
                "A superseded identity this platform issued to this router. "
                "It is not handshaking, so nothing is using it -- it stays on "
                "the hub, holding its address, because the deployed agent has "
                "no removal verb "
                f"(recorded lifecycle: {hub_lifecycle})."
            )
        if current_peer.last_handshake_at is not None:
            return (
                "TWO live identities for one router: this key is handshaking "
                "AND the recorded peer has handshaked on a different key. Not "
                "adopted automatically -- resolve by hand, because picking one "
                "wrongly moves the router's RADIUS binding to a dead address."
            )
        return "Attributable and handshaking, but adoption was not requested."

    async def _apply_adoption(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        peer: WireGuardPeer,
        public_key: str,
        tunnel_ip_address: str,
        last_handshake_at: datetime | None,
        source: PeerIdentitySource,
        hub_peers: dict[str, dict],
        note: str,
    ) -> WireGuardPeer:
        """Rewrites ``peer`` to the identity the device is actually using.

        Shared by automatic adoption (``get_fleet_status(adopt=True)``) and
        the operator-confirmed endpoint, so the two can never diverge in
        what "adopted" means.

        Three choices worth stating:

        * ``private_key_encrypted`` becomes ``EXTERNALLY_MANAGED_KEY_SENTINEL``
          because that is the truth: the hub generated this key and did not
          keep it, and this platform never saw it. Writing anything else
          would eventually be rendered into a device's ``private-key=``.
        * ``rotation_count`` is NOT incremented. Adoption mints no key
          material; it corrects a record. Bumping the counter would make the
          platform's own audit trail claim a rotation that never happened,
          which is how ``rotation_count=6`` came to describe a router whose
          device had changed identity twice.
        * ``status`` becomes ACTIVE and ``last_handshake_at`` is set from
          the hub, because a handshake is exactly the evidence that
          justified the adoption in the first place.
        """
        previous_public_key = peer.public_key
        previous_tunnel_ip = peer.tunnel_ip_address
        server_id = peer.server_id

        updated = await self.repository.update_peer(
            peer,
            {
                "public_key": public_key,
                "tunnel_ip_address": tunnel_ip_address,
                "private_key_encrypted": encrypt_secret(
                    EXTERNALLY_MANAGED_KEY_SENTINEL
                ),
                "status": PeerStatus.ACTIVE.value,
                "last_handshake_at": last_handshake_at,
                "revoked_at": None,
            },
        )
        await self._record_issuance(
            router_id=updated.router_id,
            server_id=server_id,
            public_key=public_key,
            tunnel_ip_address=tunnel_ip_address,
            source=source,
            hub_lifecycle=HubPeerLifecycle.LIVE,
            actor_user_id=actor_user_id,
            note=note,
        )
        # The identity we just stopped believing in. If the hub still holds
        # it, it is now an orphan and must be recorded as one so its address
        # stays quarantined; if the hub never had it (the usual case for a
        # platform-generated rotation key), say that instead of inventing an
        # orphan that does not exist.
        if previous_public_key and previous_public_key != public_key:
            if previous_public_key in hub_peers:
                await self._deregister_from_hub(
                    previous_public_key, router_id=updated.router_id
                )
            else:
                stale = await self.repository.get_issuance_by_public_key(
                    previous_public_key
                )
                if stale is not None:
                    await self.repository.update_issuance(
                        stale,
                        {"hub_lifecycle": HubPeerLifecycle.NEVER_REGISTERED.value},
                    )

        logger.info(
            "wireguard_peer_identity_adopted",
            extra={
                "router_id": str(updated.router_id),
                "public_key": public_key,
                "previous_public_key": previous_public_key,
                "tunnel_ip_address": tunnel_ip_address,
                "previous_tunnel_ip_address": previous_tunnel_ip,
                "source": source.value,
            },
        )
        if previous_tunnel_ip != tunnel_ip_address:
            await self._notify_address_changed(
                router_id=updated.router_id,
                previous_tunnel_ip_address=previous_tunnel_ip,
                tunnel_ip_address=tunnel_ip_address,
            )
        return updated

    async def _notify_address_changed(
        self,
        *,
        router_id: uuid.UUID,
        previous_tunnel_ip_address: str,
        tunnel_ip_address: str,
    ) -> None:
        """Best-effort notification that a router's tunnel address moved.

        Never propagates -- see ``PeerAddressListener``'s own docstring for
        why the WireGuard correction must stand even when the RADIUS
        re-push behind it fails. The failure is logged AND left detectable
        in the data (the NAS row's synced address still differs), so the
        next reconciliation retries rather than the operator having to
        notice a log line."""
        if self.peer_address_listener is None:
            return
        try:
            await self.peer_address_listener(
                router_id=router_id,
                previous_tunnel_ip_address=previous_tunnel_ip_address,
                tunnel_ip_address=tunnel_ip_address,
            )
        except Exception:  # noqa: BLE001 -- see docstring: converge, do not roll back
            logger.warning(
                "wireguard_peer_address_listener_failed",
                extra={
                    "router_id": str(router_id),
                    "tunnel_ip_address": tunnel_ip_address,
                    "detail": (
                        "the WireGuard identity is corrected; the RADIUS "
                        "binding still points at the old address and will be "
                        "retried by the next reconciliation pass"
                    ),
                },
                exc_info=True,
            )

    async def resolve_live_identity_for_router(
        self,
        *,
        router_id: uuid.UUID,
        now: datetime | None = None,
    ) -> dict | None:
        """The hub peer this router is DEMONSTRABLY using right now, or
        ``None`` if there is no evidence of one.

        "Demonstrably" means the hub reports a handshake inside the
        staleness window on a key attributable to this router -- either the
        key this table records, or any key the issuance ledger says was
        issued to it and that the hub has not been able to shed.

        The second half is what makes this useful. On 2026-08-27 the
        recorded key was ``5/q7n2Of...`` on ``10.20.0.8``, which had never
        handshaked; the device was on ``7hu3t0FJ...`` at ``10.20.0.6``,
        which this table had overwritten twelve minutes earlier. Asking
        only "is the recorded key live?" answers no and concludes the
        router needs a fresh allocation -- which is precisely the action
        that made things worse, four times.

        Returns the hub's own entry (the ``wg show dump`` dict) rather than
        a key, because the caller needs its ``allowed_ips`` too: the hub's
        routing table is what decides where this peer's packets actually
        go, so it is the authority on the address, not this table.

        ``None`` on an unreachable hub -- "cannot confirm" is not
        "confirmed absent", and every caller's safe response to the former
        is to change nothing.
        """
        hub_peers = await self._hub_peers_by_key()
        if not hub_peers:
            return None

        candidates: set[str] = set()
        peer = await self.repository.get_peer_by_router_id(router_id)
        if peer is not None and not peer.is_revoked():
            candidates.add(peer.public_key)
        for issuance in await self.repository.list_issuances_for_router(router_id):
            # Every key ever issued to this router, WITHOUT filtering on
            # `hub_lifecycle`. That column is this platform's belief about
            # the hub, and filtering by a belief before consulting the thing
            # the belief is about is the exact mistake pattern this whole
            # change exists to end. The hub read below is the filter: a key
            # it does not hold simply is not a candidate, and a key it does
            # hold is one no matter what we thought.
            candidates.add(issuance.public_key)

        moment = now or datetime.now(UTC)
        best: dict | None = None
        best_handshake: datetime | None = None
        for key in candidates:
            hub_peer = hub_peers.get(key)
            if hub_peer is None:
                continue
            epoch = hub_peer["latest_handshake_epoch"]
            if epoch <= 0:
                continue
            handshake = datetime.fromtimestamp(epoch, tz=UTC)
            if moment - handshake > self.handshake_stale_after:
                continue
            if best_handshake is None or handshake > best_handshake:
                best, best_handshake = hub_peer, handshake
        return best

    async def adopt_hub_peer(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        public_key: str,
        note: str | None = None,
    ) -> WireGuardPeer:
        """Operator-confirmed adoption: bind ``router_id`` to the identity
        the hub is already holding under ``public_key``.

        This is the path for everything automatic adoption deliberately
        will not touch -- a key with no issuance record (every peer
        allocated before the ledger existed, including the seven live on
        the production hub today), and the ambiguous two-live-identities
        case. The operator supplies the attribution the platform cannot
        prove; everything else is still verified rather than trusted:

        * the hub must actually hold the key (``HubPeerNotOnHubError``) --
          adopting a key ``GET /wg/peers`` has never seen would just be a
          differently-wrong row;
        * no other router may already record it
          (``HubPeerClaimedByAnotherRouterError``) -- two routers on one
          WireGuard identity means the hub silently delivers one's traffic
          to the other;
        * the address written is the one the HUB has in ``allowed-ips``,
          not one the caller chose, because the hub's routing table is what
          decides where packets for this peer actually go.

        Requires the hub to be reachable. There is no offline variant on
        purpose: adoption's entire justification is that it records
        something observed, and an unreachable hub means nothing was.
        """
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        hub_peers = await self._hub_peers_by_key()
        if hub_peers is None:
            raise HubPeerListerNotConfiguredError()
        hub_peer = hub_peers.get(public_key)
        if hub_peer is None:
            raise HubPeerNotOnHubError(public_key)

        peer = await self.repository.get_peer_by_router_id(router.id)
        if peer is None:
            raise WireGuardPeerNotFoundError(router.id)

        for other, _name in await self.repository.list_all_peers_with_router_names():
            if other.public_key == public_key and other.router_id != router.id:
                raise HubPeerClaimedByAnotherRouterError(public_key, other.router_id)

        handshake_epoch = hub_peer["latest_handshake_epoch"]
        updated = await self._apply_adoption(
            actor_user_id=actor_user_id,
            peer=peer,
            public_key=public_key,
            tunnel_ip_address=self._hub_address(hub_peer)
            or peer.tunnel_ip_address,
            last_handshake_at=(
                datetime.fromtimestamp(handshake_epoch, tz=UTC)
                if handshake_epoch > 0
                else None
            ),
            source=PeerIdentitySource.ADOPTED,
            hub_peers=hub_peers,
            note=note or "adopted by operator",
        )
        await self._record_event_and_audit(
            actor_user_id,
            AuditAction.WIREGUARD_TUNNEL_CREATED,
            router=router,
            peer=updated,
            description=(
                f"WireGuard peer identity adopted for router '{router.name}' "
                f"({updated.tunnel_ip_address}) -- recorded what the device is "
                "demonstrably using"
            ),
        )
        return updated


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
        check-in used to **rotate unconditionally** -- fresh platform
        keypair, ``status`` back to ``pending``, ``last_handshake_at``
        cleared, ``rotation_count`` bumped -- justified by the claim, in
        this method's own previous docstring, that "the bootstrap script it
        is running is about to recreate its local interface against
        whatever this method returns".

        ## Why that justification does not hold, and what replaces it

        Check-in is not only reached by a device. Confirmed live on
        2026-08-27 for router 21e13913: the Master console's "Generate"
        flow mints a provisioning token and burns it itself, ~50ms later,
        to obtain the agent credential it needs to bake into the ``.rsc``
        it is about to hand a technician. Three Generates produced three
        check-ins (17:35, 17:46, 17:47), each rotating the peer to a fresh
        platform keypair -- ``XdLGb1sx...``, ``rP4Bjge...``,
        ``Tytu4dAc...`` -- while the device at the venue was untouched,
        holding the key from the ``.rsc`` it had actually imported. No
        device ever read those responses, because no device made those
        calls.

        And the rotation was not merely useless. Every one of those keys
        was written to the hub by nobody: ``POST /wg/peer`` generates its
        own keypair and there is no verb to register one. So for the
        seconds until the next allocation superseded it, this platform's
        record of that router's identity was a public key that existed in
        no WireGuard implementation anywhere.

        So this method no longer rotates on the strength of "a check-in
        happened". It asks what is actually true, in this order:

        1. **The device told us who it is.** ``external_public_key`` is an
           observation, not an assertion, and it outranks anything this
           table believes. If it differs from the recorded peer, the peer
           is adopted onto it. This is the branch the previous
           implementation ignored entirely on the repeat path.
        2. **The hub says the recorded identity is live.** If ``GET
           /wg/peers`` still holds the recorded public key, the device can
           be on it, and the peer is returned unchanged. This is the common
           case -- a device that is fine and merely checked in again -- and
           it is now a no-op rather than a silent re-key.
        3. **The hub cannot be reached.** "Cannot confirm" is not "gone":
           the peer is returned unchanged, the same posture
           ``get_peer_if_usable`` already takes, because the cost of
           guessing wrong here is a router that stops working.
        4. Only when the hub is reachable AND has genuinely forgotten the
           recorded key does rotation happen -- and even then only if the
           hub could learn the new one, which today it cannot, so the
           caller gets ``HubCannotLearnPlatformKeyError`` naming the real
           action (allocate through the hub bridge) instead of a row that
           quietly cannot work.

        The acceptance test this is written against: a device that imports
        a ``.rsc``, checks in, and checks in again is still the peer this
        platform believes in. Steps 1-3 are what make that true.
        """
        existing = await self.repository.get_peer_by_router_id(router_id)
        if existing is None or existing.is_revoked():
            return await self.create_tunnel(
                actor_user_id=None,
                router_id=router_id,
                requesting_organization_id=None,
                external_public_key=external_public_key,
            )

        server = await self.get_server(existing.server_id)
        hub_peers = await self._hub_peers_by_key()

        # (1) The device named itself. Record it.
        if external_public_key is not None:
            if external_public_key != existing.public_key:
                if hub_peers is None:
                    # Adoption records something OBSERVED. With no hub read
                    # there is nothing observed -- the device's claim alone
                    # is a claim, and writing it would swap one unverified
                    # identity for another. Leave the row alone; the next
                    # check-in or reconciliation pass has the hub back.
                    logger.warning(
                        "wireguard_device_key_unverifiable",
                        extra={
                            "router_id": str(router_id),
                            "detail": (
                                "device reported a public key differing from "
                                "the recorded peer, but the hub could not be "
                                "read to confirm it -- leaving the peer "
                                "unchanged"
                            ),
                        },
                    )
                else:
                    hub_peer = hub_peers.get(external_public_key)
                    if hub_peer is None:
                        raise HubPeerNotOnHubError(external_public_key)
                    handshake_epoch = hub_peer["latest_handshake_epoch"]
                    existing = await self._apply_adoption(
                        actor_user_id=None,
                        peer=existing,
                        public_key=external_public_key,
                        tunnel_ip_address=self._hub_address(hub_peer)
                        or existing.tunnel_ip_address,
                        last_handshake_at=(
                            datetime.fromtimestamp(handshake_epoch, tz=UTC)
                            if handshake_epoch > 0
                            else None
                        ),
                        source=PeerIdentitySource.DEVICE_REPORTED,
                        hub_peers=hub_peers,
                        note=(
                            "adopted at check-in: the device reported this "
                            "public key and the hub holds it"
                        ),
                    )
            return self._delivery_for(existing, server)

        # (2)/(3) The hub decides whether the recorded identity is still
        # real. Unknown means change nothing.
        if hub_peers is None or existing.public_key in hub_peers:
            return self._delivery_for(existing, server)

        # (4) The hub has genuinely forgotten this peer.
        logger.info(
            "wireguard_check_in_recorded_peer_missing_from_hub",
            extra={
                "router_id": str(router_id),
                "public_key": existing.public_key,
            },
        )
        return await self.rotate_tunnel(
            actor_user_id=None,
            router_id=router_id,
            requesting_organization_id=None,
        )

    def _delivery_for(
        self, peer: WireGuardPeer, server: WireGuardServer
    ) -> TunnelDeliveryInfo:
        """A ``TunnelDeliveryInfo`` for a peer that was NOT just created or
        rotated -- i.e. one whose private key this platform may not hold.

        The sentinel is passed through verbatim rather than substituted or
        blanked. ``get_config_for_agent`` already refuses to serve it
        (``WireGuardPrivateKeyUnavailableError``), and the bootstrap script
        already fails loudly on an empty ``peer_private_key``; both of
        those are correct and neither works if this layer quietly invents
        something that looks like a key. Check-in's own response schema
        carries no private key at all, so on the path this matters for
        (a repeat check-in) nothing is disclosed either way."""
        return TunnelDeliveryInfo(
            peer=peer,
            peer_private_key=decrypt_secret(peer.private_key_encrypted),
            server=server,
        )


    async def get_peer_if_usable(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> WireGuardPeer | None:
        """This router's existing peer, IF reusing it is actually safe --
        otherwise ``None``, meaning "allocate a fresh one".

        Exists because ``ops/hub-agents/wg_agent.py`` has no delete and no
        update verb: `POST /wg/peer` always allocates, `GET /wg/peers`
        lists, and nothing else. Every allocation is therefore permanent
        and unreclaimable, so the caller must not make one it does not
        need. See ``allocate_external_wireguard_peer``'s own note.

        Three conditions, and the third is the one that matters:

        1. A peer row exists for this router.
        2. It is not REVOKED -- a revoked row keeps its id but its
           ``tunnel_ip_address`` has been overwritten with a
           ``revoked:<id>`` sentinel and its address freed for reuse, so
           there is nothing left to reuse.
        3. **The hub still has it.** Checked against ``GET /wg/peers``,
           the only server-side truth this platform can read. A row whose
           public key the hub has forgotten (a ``wg0.conf`` rebuilt from an
           older backup, or a hub replaced during a migration) describes a
           tunnel that cannot come up, and handing it back would leave the
           operator re-pasting a script that can never work. That case
           genuinely does need a fresh allocation.

        A hub that cannot be reached at all is deliberately NOT treated as
        "the peer is gone": that would turn a transient bridge blip into a
        permanent, unreclaimable peer allocation, which is the exact cost
        this method exists to avoid. Unreachable means "cannot confirm", and
        the safe response to "cannot confirm" is to reuse what we have and
        let the script's own on-device verification report the truth.
        """
        peer = await self.repository.get_peer_by_router_id(router_id)
        if peer is None or peer.status == PeerStatus.REVOKED.value:
            return None
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        if self.hub_peer_lister is None:
            return peer
        try:
            hub_keys = {p["public_key"] for p in await self.hub_peer_lister()}
        except Exception:  # noqa: BLE001 -- see the docstring's last paragraph
            logger.warning(
                "wireguard_reuse_check_could_not_reach_hub",
                extra={
                    "router_id": str(router_id),
                    "detail": (
                        "reusing the recorded peer without confirming it against "
                        "the hub -- allocating instead would permanently consume "
                        "another tunnel IP that no API can reclaim"
                    ),
                },
                exc_info=True,
            )
            return peer
        if peer.public_key not in hub_keys:
            logger.info(
                "wireguard_recorded_peer_missing_from_hub",
                extra={
                    "router_id": str(router_id),
                    "public_key": peer.public_key,
                    "detail": (
                        "allocating a fresh peer -- the hub has no record of this one"
                    ),
                },
            )
            return None
        return peer

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
            # REMOVE THE PEER WE ARE SUPERSEDING FROM THE HUB.
            #
            # !! CURRENTLY INERT IN PRODUCTION, ON PURPOSE. !!
            # `make_hub_peer_deregistrar` issues `DELETE /wg/peer`, and
            # `ops/hub-agents/wg_agent.py` as deployed implements only
            # `do_POST` and `do_GET` -- a DELETE returns `501 Unsupported
            # method`. So this call always fails today and always takes the
            # best-effort branch below. It is kept, and kept first, because
            # (a) it is the correct behaviour the moment the hub gains the
            # verb -- a `do_DELETE` handler is written and waiting in
            # `ops/hub-agents/wg_agent.py`, undeployable only because there
            # is no shell access to that host -- and (b) the warning it logs
            # is the only running record that peers are being orphaned.
            # The fix that actually stops the bleeding today is upstream:
            # `allocate_external_wireguard_peer` no longer calls the hub at
            # all when a usable peer already exists.
            #
            # Without this, every Generate left the previous peer in place on
            # the hub forever: the bridge allocates a fresh keypair and the
            # next free tunnel IP on each call, this row is overwritten to
            # point at the new one, and nothing ever told the hub to forget
            # the old. Confirmed live 2026-08-27 on router 01c9171e --
            # `GET /wg/peers` returned 10.20.0.2, 10.20.0.3 and 10.20.0.4 for
            # a single router, with a handshake on .3 (the address the device
            # was actually still using) while this table tracked .4.
            #
            # Three separate harms, all of which this closes:
            #  1. A leaked peer still has `allowed_ips` on the hub, so the
            #     hub will happily route to a tunnel IP no live device owns.
            #  2. `next_free_ip()` scans live kernel state, so leaked peers
            #     permanently consume addresses out of a /24 -- at the three
            #     rotations this router accumulated, the fleet ceiling is
            #     about 84 routers rather than 254.
            #  3. `get_fleet_status` reports each orphan as
            #     UNTRACKED_CONNECTED, which is exactly the drift that view
            #     exists to surface -- self-inflicted, on every Generate.
            #
            # Deliberately best-effort, unlike `revoke_tunnel`'s hard-failing
            # deregistration. The ordering is forced: the bridge has ALREADY
            # created the new peer on the hub by the time this runs, so
            # raising here would abort before the row is written and leave a
            # hub peer with no DB row at all -- strictly worse drift than the
            # stale peer we are trying to remove. A failure is logged and the
            # registration continues.
            #
            # WHAT CHANGED (2026-08-27, second pass). This used to log a
            # WARNING with a stack trace on every single call, because the
            # hub answers `501` and always will until a new agent is
            # installed. That warning was, in its own words, "the only
            # running record that peers are being orphaned" -- and being the
            # only record is exactly the problem: it scrolled past, it was
            # not queryable, and it left `get_fleet_status` calling the
            # resulting peers UNTRACKED_CONNECTED, i.e. unattributable, when
            # the platform had just been told precisely which router they
            # belonged to.
            #
            # `_deregister_from_hub` now writes that fact where it survives:
            # the superseded issuance row moves to
            # `HubPeerLifecycle.ORPHANED`, which quarantines its address
            # against reallocation and makes fleet-status report it as a
            # KNOWN_ORPHAN with the router's name on it. A `501` is no
            # longer an exception at all, because it is not a failure of
            # this call -- it is a permanent property of the deployed hub.
            if existing.public_key and existing.public_key != public_key:
                try:
                    await self._deregister_from_hub(
                        existing.public_key, router_id=router.id
                    )
                except Exception:  # noqa: BLE001 -- unreachable hub, see above
                    logger.warning(
                        "wireguard_superseded_peer_not_removed",
                        extra={
                            "router_id": str(router.id),
                            "superseded_public_key": existing.public_key,
                            "detail": (
                                "could not reach the hub bridge to remove the "
                                "superseded peer -- the replacement is live and "
                                "recorded, and the next reconciliation pass "
                                "will classify whatever the hub still holds"
                            ),
                        },
                        exc_info=True,
                    )

            fields["rotation_count"] = existing.rotation_count + 1
            fields["last_handshake_at"] = None
            peer = await self.repository.update_peer(existing, fields)
        else:
            peer = await self.repository.create_peer(
                router_id=router.id, created_by=actor_user_id, **fields
            )

        # The bridge has already created this peer on the hub -- unlike
        # `_allocate_and_persist`'s platform-generated keys, this one is
        # genuinely LIVE there, and recording that is what lets the
        # allocator quarantine its address for as long as it stays there.
        await self._record_issuance(
            router_id=router.id,
            server_id=server.id,
            public_key=public_key,
            tunnel_ip_address=tunnel_ip_address,
            source=PeerIdentitySource.HUB_ALLOCATED,
            hub_lifecycle=HubPeerLifecycle.LIVE,
            actor_user_id=actor_user_id,
        )
        if existing is not None and existing.tunnel_ip_address != tunnel_ip_address:
            # The RADIUS `client{}` stanza is keyed on this address. Before
            # this call existed, a re-allocation moved the router and left
            # the stanza behind, which is the entire "OTP verifies but no
            # internet" failure mode: FreeRADIUS drops an Access-Request
            # from an address it has no client for, silently, with no reply.
            await self._notify_address_changed(
                router_id=router.id,
                previous_tunnel_ip_address=existing.tunnel_ip_address,
                tunnel_ip_address=tunnel_ip_address,
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
        if external_public_key is None and not (
            self.hub_capabilities.can_register_public_key
        ):
            # A keypair generated here can never reach the hub -- see
            # `HubCannotLearnPlatformKeyError`. Refused rather than written,
            # because the row it would write describes a tunnel that cannot
            # establish and nothing downstream would notice: the device
            # pulls a private key that works, the hub keeps expecting the
            # previous public key, and the only symptom is a tunnel that
            # never handshakes.
            raise HubCannotLearnPlatformKeyError("Creating this tunnel")

        exclude_id = existing.id if existing is not None else None
        for attempt in range(_MAX_ALLOCATION_ATTEMPTS):
            occupied = await self.repository.list_occupied_tunnel_ips(
                server.id, exclude_peer_id=exclude_id
            )
            # QUARANTINE. `list_occupied_tunnel_ips` reads `wireguard_peers`,
            # which holds one row per router and therefore forgets every
            # superseded address the moment it is overwritten -- while the
            # hub goes on routing to it, because it has no removal verb. The
            # ledger is the only record that those addresses are spoken for.
            # Without this union the allocator will eventually hand a live
            # orphan's address to a different router, and WireGuard routes by
            # allowed-ips, so both routers break in a way that reads as "the
            # tunnel is flaky".
            occupied = occupied | await self.repository.list_hub_held_tunnel_ips(
                server.id
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
                await self._record_issuance(
                    router_id=router_id,
                    server_id=server.id,
                    public_key=public_key,
                    tunnel_ip_address=tunnel_ip,
                    source=(
                        PeerIdentitySource.DEVICE_REPORTED
                        if external_public_key is not None
                        else PeerIdentitySource.PLATFORM_GENERATED
                    ),
                    # A platform-generated key is not on the hub and never
                    # will be (no registration verb); a device-reported one
                    # is on the hub only if the device's own enrollment put
                    # it there. Neither is something this method observed,
                    # so neither is recorded as LIVE -- the reconciliation
                    # pass promotes it once `GET /wg/peers` proves it.
                    hub_lifecycle=HubPeerLifecycle.NEVER_REGISTERED,
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

        # THE HUB FIRST, AND ITS UNREACHABILITY IS STILL FATAL.
        #
        # Order matters. Freeing the address in the database while the hub
        # still holds it is the exact state that produced 68 orphaned peers:
        # the allocator then hands that address to the next router while the
        # old peer still claims it, and WireGuard routes by allowed-ips, so
        # both break in a way that reads as "the tunnel is flaky".
        #
        # An UNREACHABLE hub still raises, and must. The RadiusNasClient
        # deregistration made the opposite choice -- log a warning, report
        # success -- and the result was a database with zero NAS clients and
        # a hub with 21 stanzas, each still holding a live shared secret. A
        # revoke that could not reach the hub has not revoked anything.
        #
        # WHAT CHANGED: a hub that ANSWERS, saying it has no removal verb,
        # is no longer treated the same way. It used to raise identically,
        # which meant revoke was not merely degraded but impossible --
        # every call, forever, against the deployed agent. That is worse
        # than the hazard it was protecting against, because it left an
        # operator with no way at all to stop serving a router.
        #
        # The hazard itself is now closed by different means: the
        # superseded identity is recorded as `ORPHANED` in the issuance
        # ledger, and `_allocate_and_persist` unions those addresses into
        # its occupancy set. So the address is never handed to another
        # router while the hub still routes it -- which was the only reason
        # the removal had to succeed. The revoke proceeds, honestly
        # reported, with the orphan on the record instead of in a log line.
        removal = await self._deregister_from_hub(
            revoked_public_key, router_id=router.id
        )

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
                f"(released {released_tunnel_ip}; hub removal: {removal.value})"
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

        if not self.hub_capabilities.can_register_public_key:
            # Rotation mints a keypair here and has no way to tell the hub
            # about it -- `POST /wg/peer` generates its own and there is no
            # registration verb. The row would say the router's identity is
            # a key the hub has never seen, and the tunnel would simply stop
            # handshaking with nothing anywhere naming the cause. That is
            # not a rotation, it is a quiet disconnection, and it happened
            # three times on 21e13913 in twelve minutes.
            raise HubCannotLearnPlatformKeyError("Rotating this tunnel")

        server = await self.get_server(peer.server_id)
        private_key, public_key = generate_wireguard_keypair()
        previous_public_key = peer.public_key
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
        await self._record_issuance(
            router_id=router.id,
            server_id=server.id,
            public_key=public_key,
            tunnel_ip_address=updated.tunnel_ip_address,
            source=PeerIdentitySource.PLATFORM_GENERATED,
            hub_lifecycle=HubPeerLifecycle.NEVER_REGISTERED,
            actor_user_id=actor_user_id,
        )
        # Rotation keeps the address, so the peer this replaces claimed the
        # SAME address on the hub. Recording its disposition matters anyway:
        # if it is still live there, the hub is now routing that address to
        # a key no device holds, and the ledger is what says so.
        if previous_public_key and previous_public_key != public_key:
            with contextlib.suppress(Exception):
                await self._deregister_from_hub(
                    previous_public_key, router_id=router.id
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
    "HubCapabilities",
    "HubPeerDeregistrar",
    "HubPeerLister",
    "PeerAddressListener",
    "FleetPeerEntry",
    "FleetStatus",
    "EXTERNALLY_MANAGED_KEY_SENTINEL",
    "generate_wireguard_keypair",
]
