"""Unit tests for the WireGuard domain (BE-009 Part 3): hub CRUD, tunnel-IP
allocation (including collision-skipping and pool exhaustion), automatic
tunnel creation (keypair generation, encrypted storage, decrypt round-trip),
peer revoke + re-create (row reuse, IP freed for reuse), key/tunnel
rotation (same IP, new keys, status reset to ``pending``), device-facing
config pull composed through ``app.domains.router_agent``'s real
``CurrentAgent`` dependency (with and without a valid agent credential),
handshake reporting + health-status staleness threshold logic, and tenant
isolation.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_router_agent.py``); ``asyncio_mode = "auto"`` runs async
tests directly. Exercises ``WireGuardService`` against a real
``RouterService`` instance (itself wired against small in-memory fakes,
mirroring ``test_router_agent.py``'s own ``make_services`` setup) rather
than a hand-rolled fake for it -- this both avoids duplicating
``RouterService``'s tenant-scoping/status-transition logic in a second fake
and directly exercises the real cross-domain composition
(``WireGuardService`` -> ``RouterService``) this module relies on for
tenant isolation and router-eligibility checks.
"""

from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.exceptions import DuplicateRecordError
from app.domains.location.exceptions import (
    CrossOrganizationLocationAccessError,
    LocationNotFoundError,
)
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationType
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization
from app.domains.rbac.enums import ScopeType
from app.domains.router.crypto import decrypt_secret
from app.domains.router.enums import RouterStatus
from app.domains.router.exceptions import CrossOrganizationRouterAccessError
from app.domains.router.models import Router, RouterProvisioningToken
from app.domains.router.service import RouterService
from app.domains.router_agent.constants import (
    AGENT_CREDENTIAL_HEADER,
    AgentLicenseStatus,
)
from app.domains.router_agent.dependencies import CurrentAgent
from app.domains.router_agent.exceptions import (
    AgentCredentialInvalidError,
    AgentCredentialMissingError,
)
from app.domains.router_agent.models import RouterAgentCredential
from app.domains.router_agent.service import RouterAgentService, hash_credential
from app.domains.wireguard.constants import (
    FleetPeerStatus,
    HealthStatus,
    HubPeerLifecycle,
    HubRemovalOutcome,
    PeerIdentitySource,
    PeerStatus,
)
from app.domains.wireguard.exceptions import (
    HubCannotLearnPlatformKeyError,
    HubPeerClaimedByAnotherRouterError,
    HubPeerListerNotConfiguredError,
    HubPeerNotOnHubError,
    InvalidPeerStatusTransitionError,
    NoActiveWireGuardServerError,
    TunnelIPAllocationConflictError,
    TunnelIPPoolExhaustedError,
    WireGuardPeerAlreadyExistsError,
    WireGuardPeerNotFoundError,
    WireGuardPeerRevokedError,
    WireGuardPrivateKeyUnavailableError,
    WireGuardRouterNotEligibleError,
)
from app.domains.wireguard.models import (
    WireGuardPeer,
    WireGuardPeerIssuance,
    WireGuardServer,
)
from app.domains.wireguard.router import router as wireguard_router
from app.domains.wireguard.service import (
    HubCapabilities,
    WireGuardService,
    generate_wireguard_keypair,
)
from app.domains.wireguard.validators import allocate_tunnel_ip, validate_cidr


def _permission_keys(route: object) -> list[str]:
    """The permission strings a route's ``RequirePermission`` dependencies
    actually enforce -- mirrors ``test_user.py``'s own helper of the same
    name/shape (``RequirePermission`` is a closure factory, so the key
    lives in ``_dependency``'s nonlocals)."""
    return [
        inspect.getclosurevars(dependency.dependency).nonlocals["permission_key"]
        for dependency in route.dependencies  # type: ignore[attr-defined]
    ]


# ============================================================================
# Test doubles: BE-008 (Router domain) side -- mirrors test_router_agent.py
# exactly (duplicated, not imported -- established per-test-file convention)
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeOrganizationLookup:
    organizations: dict[uuid.UUID, Organization] = field(default_factory=dict)

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization:
        organization = self.organizations.get(organization_id)
        if organization is None or (organization.is_deleted and not include_deleted):
            raise OrganizationNotFoundError(organization_id)
        return organization

    def add(self) -> Organization:
        organization = Organization(
            **_base_fields(
                name="Org",
                slug=f"org-{uuid.uuid4()}",
                legal_name=None,
                org_type=OrganizationType.STANDARD.value,
                status="active",
                parent_organization_id=None,
                contact_email="admin@example.com",
                contact_phone=None,
                timezone="UTC",
                default_locale="en",
                settings={},
                subscription_tier=None,
            )
        )
        self.organizations[organization.id] = organization
        return organization


@dataclass
class FakeLocationLookup:
    organization_lookup: FakeOrganizationLookup
    locations: dict[uuid.UUID, Location] = field(default_factory=dict)

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location:
        location = self.locations.get(location_id)
        if location is None or (location.is_deleted and not include_deleted):
            raise LocationNotFoundError(location_id)
        await self._enforce_scope(location, requesting_organization_id)
        return location

    async def _enforce_scope(
        self, location: Location, requesting_organization_id: uuid.UUID | None
    ) -> None:
        if requesting_organization_id is None:
            return
        if location.organization_id == requesting_organization_id:
            return
        organization = await self.organization_lookup.get_organization(
            location.organization_id, include_deleted=True
        )
        if organization.parent_organization_id == requesting_organization_id:
            return
        raise CrossOrganizationLocationAccessError()

    def add(self, *, organization_id: uuid.UUID) -> Location:
        location = Location(
            **_base_fields(
                organization_id=organization_id,
                name="HQ",
                slug=f"hq-{uuid.uuid4()}",
                status="active",
                address_line1="1 Main St",
                address_line2=None,
                city="Austin",
                state_province="TX",
                postal_code="78701",
                country="US",
                timezone="UTC",
                latitude=None,
                longitude=None,
                contact_name=None,
                contact_phone=None,
                contact_email=None,
                settings={},
            )
        )
        self.locations[location.id] = location
        return location


@dataclass
class FakeRouterRepository:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)
    tokens: dict[uuid.UUID, RouterProvisioningToken] = field(default_factory=dict)

    async def get_by_id(
        self, router_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Router | None:
        router = self.routers.get(router_id)
        if router is None:
            return None
        if router.is_deleted and not include_deleted:
            return None
        return router

    async def get_by_serial_number(self, serial_number: str) -> Router | None:
        return next(
            (r for r in self.routers.values() if r.serial_number == serial_number),
            None,
        )

    async def get_by_mac_address(self, mac_address: str) -> Router | None:
        return next(
            (r for r in self.routers.values() if r.mac_address == mac_address), None
        )

    async def create_router(self, **fields: object) -> Router:
        defaults = {
            "routeros_version": None,
            "management_ip_address": None,
            "public_ip_address": None,
            "last_seen_at": None,
            "last_health_check_at": None,
            "health_status": None,
            "api_username": None,
            "api_credentials_encrypted": None,
            "settings": {},
        }
        router = Router(**_base_fields(**{**defaults, **fields}))
        self.routers[router.id] = router
        return router

    async def update_router(self, router: Router, data: dict[str, object]) -> Router:
        for key, value in data.items():
            if hasattr(router, key):
                setattr(router, key, value)
        router.version += 1
        return router

    async def soft_delete_router(self, router: Router) -> Router:
        router.is_deleted = True
        router.deleted_at = _now()
        return router

    async def list_routers(self, **_kwargs: object):  # pragma: no cover - unused here
        raise NotImplementedError

    async def create_provisioning_token(
        self, **fields: object
    ) -> RouterProvisioningToken:
        token = RouterProvisioningToken(**_base_fields(**fields))
        self.tokens[token.id] = token
        return token

    async def get_provisioning_token_by_hash(self, token_hash: str):
        return next(
            (t for t in self.tokens.values() if t.token_hash == token_hash), None
        )

    async def mark_provisioning_token_used(self, token, *, used_at: object):
        token.used_at = used_at
        return token


# ============================================================================
# Test double: this module's own repository (WireGuardRepositoryProtocol)
# ============================================================================


@dataclass
class FakeWireGuardRepository:
    servers: dict[uuid.UUID, WireGuardServer] = field(default_factory=dict)
    peers: dict[uuid.UUID, WireGuardPeer] = field(default_factory=dict)
    # Router names, keyed by router_id -- tests populate this directly
    # (there's no fake Router object here, only the display label
    # `list_all_peers_with_router_names` needs) rather than wiring in a
    # second fake repository just to look up a name.
    router_names: dict[uuid.UUID, str] = field(default_factory=dict)
    # Append-only, mirroring the real table. See the ledger methods below
    # for why order matters here.
    issuances: list[WireGuardPeerIssuance] = field(default_factory=list)

    async def get_server_by_id(self, server_id, *, include_deleted: bool = False):
        server = self.servers.get(server_id)
        if server is None or (server.is_deleted and not include_deleted):
            return None
        return server

    async def get_active_server(self) -> WireGuardServer | None:
        return next(
            (s for s in self.servers.values() if s.is_active and not s.is_deleted),
            None,
        )

    async def list_servers(self) -> list[WireGuardServer]:
        return [s for s in self.servers.values() if not s.is_deleted]

    async def create_server(self, **fields: object) -> WireGuardServer:
        server = WireGuardServer(**_base_fields(**fields))
        self.servers[server.id] = server
        return server

    async def update_server(self, server, data: dict[str, object]) -> WireGuardServer:
        for key, value in data.items():
            if hasattr(server, key):
                setattr(server, key, value)
        server.version += 1
        return server

    async def get_peer_by_id(self, peer_id, *, include_deleted: bool = False):
        peer = self.peers.get(peer_id)
        if peer is None or (peer.is_deleted and not include_deleted):
            return None
        return peer

    async def get_peer_by_router_id(self, router_id) -> WireGuardPeer | None:
        return next((p for p in self.peers.values() if p.router_id == router_id), None)

    async def list_occupied_tunnel_ips(
        self, server_id, *, exclude_peer_id: uuid.UUID | None = None
    ) -> set[str]:
        return {
            p.tunnel_ip_address
            for p in self.peers.values()
            if p.server_id == server_id
            and p.status != PeerStatus.REVOKED.value
            and p.id != exclude_peer_id
        }

    def _check_unique(
        self,
        *,
        server_id: uuid.UUID,
        tunnel_ip_address: str,
        public_key: str,
        exclude_id: uuid.UUID | None,
    ) -> None:
        """Mirrors the real ``wireguard_peers`` table's unique constraints
        (``(server_id, tunnel_ip_address)``, ``public_key``) -- lets tests
        exercise ``WireGuardService``'s allocation-conflict retry loop the
        same way the real ``GenericRepository``/Postgres would (raising
        ``DuplicateRecordError`` on a collision), without needing a real
        database."""
        for existing in self.peers.values():
            if existing.id == exclude_id:
                continue
            if (
                existing.server_id == server_id
                and existing.tunnel_ip_address == tunnel_ip_address
                and existing.status != PeerStatus.REVOKED.value
            ):
                raise DuplicateRecordError("WireGuardPeer", "tunnel_ip_address")
            if existing.public_key == public_key:
                raise DuplicateRecordError("WireGuardPeer", "public_key")

    async def create_peer(self, **fields: object) -> WireGuardPeer:
        # Mirror the column-level defaults the real table applies. Without
        # these, a caller that legitimately omits an optional field (e.g.
        # `register_agent_allocated_peer`, which leaves `rotation_count` to
        # the column default on a first registration) gets None here and
        # fails on arithmetic that works fine against Postgres -- a fake
        # that is stricter than the schema, which is the wrong direction
        # for a test double to be wrong in.
        fields.setdefault("status", PeerStatus.PENDING.value)
        fields.setdefault("rotation_count", 0)
        fields.setdefault("last_handshake_at", None)
        fields.setdefault("revoked_at", None)
        self._check_unique(
            server_id=fields["server_id"],
            tunnel_ip_address=fields["tunnel_ip_address"],
            public_key=fields["public_key"],
            exclude_id=None,
        )
        peer = WireGuardPeer(**_base_fields(**fields))
        self.peers[peer.id] = peer
        return peer

    async def update_peer(self, peer, data: dict[str, object]) -> WireGuardPeer:
        self._check_unique(
            server_id=data.get("server_id", peer.server_id),
            tunnel_ip_address=data.get("tunnel_ip_address", peer.tunnel_ip_address),
            public_key=data.get("public_key", peer.public_key),
            exclude_id=peer.id,
        )
        for key, value in data.items():
            if hasattr(peer, key):
                setattr(peer, key, value)
        peer.version += 1
        return peer

    async def list_all_peers_with_router_names(
        self,
    ) -> list[tuple[WireGuardPeer, str | None]]:
        return [
            (peer, self.router_names.get(peer.router_id))
            for peer in self.peers.values()
            if not peer.is_deleted
        ]

    # -- issuance ledger ------------------------------------------------
    # Insertion-ordered, and every read that cares about recency reverses
    # it -- the real ``GenericRepository.get_all`` sorts ``created_at``
    # DESC, and several ledger reads ("the most recent issuance of this
    # key") are only correct under that ordering. A fake that returned
    # ascending order would let a wrong implementation pass here and fail
    # against Postgres.

    async def create_issuance(self, **fields: object) -> WireGuardPeerIssuance:
        issuance = WireGuardPeerIssuance(**_base_fields(**fields))
        self.issuances.append(issuance)
        return issuance

    async def update_issuance(
        self, issuance, data: dict[str, object]
    ) -> WireGuardPeerIssuance:
        for key, value in data.items():
            if hasattr(issuance, key):
                setattr(issuance, key, value)
        issuance.version += 1
        return issuance

    async def list_issuances_for_router(
        self, router_id
    ) -> list[WireGuardPeerIssuance]:
        return [i for i in reversed(self.issuances) if i.router_id == router_id]

    async def get_issuance_by_public_key(
        self, public_key: str
    ) -> WireGuardPeerIssuance | None:
        return next(
            (i for i in reversed(self.issuances) if i.public_key == public_key),
            None,
        )

    async def list_all_issuances(self) -> list[WireGuardPeerIssuance]:
        return list(reversed(self.issuances))

    async def list_hub_held_tunnel_ips(self, server_id) -> set[str]:
        return {
            i.tunnel_ip_address
            for i in self.issuances
            if i.server_id == server_id
            and not i.is_deleted
            and i.hub_lifecycle
            in (HubPeerLifecycle.LIVE.value, HubPeerLifecycle.ORPHANED.value)
        }


@dataclass
class RacyWireGuardRepository(FakeWireGuardRepository):
    """A ``FakeWireGuardRepository`` whose ``list_occupied_tunnel_ips``
    returns a stale (empty) result the first ``stale_reads_remaining``
    times it is called, simulating a concurrent request that already
    committed an address this read missed -- exercises
    ``WireGuardService``'s allocation-conflict retry loop
    (``_allocate_and_persist``) exactly the way the real database's unique
    constraint would (see ``validators.allocate_tunnel_ip``'s module
    docstring)."""

    stale_reads_remaining: int = 0

    async def list_occupied_tunnel_ips(
        self, server_id, *, exclude_peer_id: uuid.UUID | None = None
    ) -> set[str]:
        if self.stale_reads_remaining > 0:
            self.stale_reads_remaining -= 1
            return set()
        return await super().list_occupied_tunnel_ips(
            server_id, exclude_peer_id=exclude_peer_id
        )


@dataclass
class FakeRouterAgentRepository:
    """Minimal stand-in for ``app.domains.router_agent.repository
    .RouterAgentRepository`` -- only what ``CurrentAgent`` itself needs
    (``get_by_credential_hash``, ``update_credential``), mirroring
    ``test_router_agent.py``'s own fake."""

    credentials: dict[uuid.UUID, RouterAgentCredential] = field(default_factory=dict)

    async def get_by_router_id(self, router_id) -> RouterAgentCredential | None:
        return next(
            (c for c in self.credentials.values() if c.router_id == router_id), None
        )

    async def get_by_credential_hash(
        self, credential_hash: str
    ) -> RouterAgentCredential | None:
        return next(
            (
                c
                for c in self.credentials.values()
                if c.credential_hash == credential_hash
            ),
            None,
        )

    async def create_credential(self, **fields: object) -> RouterAgentCredential:
        credential = RouterAgentCredential(**_base_fields(**fields))
        self.credentials[credential.id] = credential
        return credential

    async def update_credential(self, credential, data):
        for key, value in data.items():
            if hasattr(credential, key):
                setattr(credential, key, value)
        credential.version += 1
        return credential


@dataclass
class FakeRequest:
    """A minimal stand-in for ``fastapi.Request`` -- ``CurrentAgent`` only
    ever reads ``request.headers.get(...)``."""

    headers: dict[str, str] = field(default_factory=dict)


# ============================================================================
# Fixture assembly
# ============================================================================


@dataclass
class Fixture:
    wireguard_service: WireGuardService
    wireguard_repo: FakeWireGuardRepository
    router_service: RouterService
    router_repo: FakeRouterRepository
    agent_repo: FakeRouterAgentRepository
    location_lookup: FakeLocationLookup
    org_lookup: FakeOrganizationLookup
    audit: FakeAuditLogWriter


def make_services(
    *,
    handshake_stale_after_minutes: int = 5,
    wireguard_repo: FakeWireGuardRepository | None = None,
    hub_peer_deregistrar=None,
    hub_peer_lister=None,
    hub_peer_allocator=None,
    hub_capabilities: HubCapabilities | None = None,
    peer_address_listener=None,
) -> Fixture:
    org_lookup = FakeOrganizationLookup()
    location_lookup = FakeLocationLookup(organization_lookup=org_lookup)
    router_repo = FakeRouterRepository()
    shared_audit = FakeAuditLogWriter()

    router_service = RouterService(
        router_repo,
        location_lookup,
        org_lookup,
        audit_writer=shared_audit,
        provisioning_token_ttl_hours=24,
    )

    wireguard_repo = (
        wireguard_repo if wireguard_repo is not None else FakeWireGuardRepository()
    )
    wireguard_service = WireGuardService(
        wireguard_repo,
        router_service,
        audit_writer=shared_audit,
        handshake_stale_after_minutes=handshake_stale_after_minutes,
        hub_peer_deregistrar=hub_peer_deregistrar,
        hub_peer_lister=hub_peer_lister,
        hub_peer_allocator=hub_peer_allocator,
        # Defaults to a fully-featured hub (HubCapabilities()'s own
        # defaults) so every pre-existing test keeps exercising the
        # unrestricted paths; the tests that care about today's degraded
        # production hub opt in explicitly.
        hub_capabilities=hub_capabilities,
        peer_address_listener=peer_address_listener,
    )

    return Fixture(
        wireguard_service=wireguard_service,
        wireguard_repo=wireguard_repo,
        router_service=router_service,
        router_repo=router_repo,
        agent_repo=FakeRouterAgentRepository(),
        location_lookup=location_lookup,
        org_lookup=org_lookup,
        audit=shared_audit,
    )


def _unique_mac() -> str:
    hex_digits = uuid.uuid4().hex[:12]
    return ":".join(hex_digits[i : i + 2] for i in range(0, 12, 2)).upper()


async def make_router(
    fx: Fixture,
    organization: Organization,
    *,
    status: RouterStatus = RouterStatus.ONLINE,
) -> Router:
    location = fx.location_lookup.add(organization_id=organization.id)
    router_device = await fx.router_service.create_router(
        actor_user_id=uuid.uuid4(),
        location_id=location.id,
        requesting_organization_id=None,
        name="Front Desk AP",
        serial_number=f"SN-{uuid.uuid4()}",
        mac_address=_unique_mac(),
        model="hAP ac2",
    )
    if status == RouterStatus.PENDING_PROVISIONING:
        return router_device

    _token, plaintext = await fx.router_service.generate_provisioning_token(
        actor_user_id=uuid.uuid4(),
        router_id=router_device.id,
        requesting_organization_id=None,
    )
    router_device = await fx.router_service.check_in(plaintext_token=plaintext)
    if status == RouterStatus.PROVISIONING:
        return router_device

    router_device = await fx.router_service.heartbeat(router_id=router_device.id)
    if status in (RouterStatus.ONLINE, RouterStatus.OFFLINE):
        return router_device

    if status == RouterStatus.SUSPENDED:
        return await fx.router_service.suspend_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
    if status == RouterStatus.DECOMMISSIONED:
        return await fx.router_service.decommission_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
    raise AssertionError(f"unsupported status for make_router: {status}")


async def make_hub(
    fx: Fixture, *, cidr: str = "10.100.0.0/16", is_active: bool = True
) -> WireGuardServer:
    return await fx.wireguard_service.create_server(
        name="Primary Hub",
        endpoint_host="hub.cloudguest.example",
        endpoint_port=51820,
        tunnel_network_cidr=cidr,
        is_active=is_active,
    )


async def issue_agent_credential(fx: Fixture, router_device: Router) -> str:
    """Issues a real, hashed ``RouterAgentCredential`` row directly against
    ``fx.agent_repo`` and returns the plaintext -- enough to drive the real
    ``CurrentAgent`` dependency without depending on the full
    ``RouterAgentService`` (out of scope for this module's own tests, and
    already covered by ``test_router_agent.py``)."""
    plaintext = f"agent-credential-{uuid.uuid4()}"
    now = _now()
    await fx.agent_repo.create_credential(
        router_id=router_device.id,
        credential_hash=hash_credential(plaintext),
        issued_at=now,
        expires_at=now + timedelta(days=365),
        last_used_at=None,
        revoked_at=None,
        rotation_count=0,
        agent_software_version=None,
        capabilities={},
        license_key=None,
        license_status=AgentLicenseStatus.UNKNOWN.value,
        last_status_report_at=None,
    )
    return plaintext


# ============================================================================
# Hub (WireGuardServer) CRUD
# ============================================================================


class TestHubCrud:
    async def test_create_server_generates_keypair_and_encrypts_private_key(
        self,
    ) -> None:
        fx = make_services()
        server = await make_hub(fx)

        assert server.public_key
        assert server.private_key_encrypted != server.public_key
        # Round-trips through the exact same Fernet helper BE-008 already
        # established -- see service.py's module docstring.
        decrypted = decrypt_secret(server.private_key_encrypted)
        assert decrypted
        assert decrypted != server.private_key_encrypted

    async def test_get_active_server_returns_the_active_hub(self) -> None:
        fx = make_services()
        active = await make_hub(fx)
        await make_hub(fx, cidr="10.200.0.0/16", is_active=False)

        resolved = await fx.wireguard_service.get_active_server()
        assert resolved.id == active.id

    async def test_get_active_server_raises_when_none_active(self) -> None:
        fx = make_services()
        await make_hub(fx, is_active=False)

        with pytest.raises(NoActiveWireGuardServerError):
            await fx.wireguard_service.get_active_server()

    async def test_list_servers_returns_every_hub(self) -> None:
        fx = make_services()
        await make_hub(fx, cidr="10.100.0.0/16")
        await make_hub(fx, cidr="10.200.0.0/16", is_active=False)

        servers = await fx.wireguard_service.list_servers()
        assert len(servers) == 2

    async def test_deactivate_server(self) -> None:
        fx = make_services()
        server = await make_hub(fx)

        deactivated = await fx.wireguard_service.deactivate_server(server.id)
        assert deactivated.is_active is False
        with pytest.raises(NoActiveWireGuardServerError):
            await fx.wireguard_service.get_active_server()


# ============================================================================
# Tunnel IP allocation
# ============================================================================


class TestTunnelIpAllocation:
    def test_allocate_skips_reserved_hub_address(self) -> None:
        ip = allocate_tunnel_ip("10.100.0.0/29", occupied=set())
        # .0 is network, .1 is reserved for the hub -- first peer gets .2.
        assert ip == "10.100.0.2"

    def test_allocate_skips_occupied_addresses(self) -> None:
        occupied = {"10.100.0.2", "10.100.0.3"}
        ip = allocate_tunnel_ip("10.100.0.0/29", occupied=occupied)
        assert ip == "10.100.0.4"

    def test_allocate_raises_when_pool_exhausted(self) -> None:
        # /29 = 8 addresses total; .0 network, .7 broadcast (excluded by
        # .hosts()), .1 reserved for the hub -- leaves .2-.6 (5 addresses).
        occupied = {f"10.100.0.{i}" for i in range(2, 7)}
        with pytest.raises(TunnelIPPoolExhaustedError):
            allocate_tunnel_ip("10.100.0.0/29", occupied=occupied)

    def test_validate_cidr_rejects_host_bits_set(self) -> None:
        from app.domains.wireguard.exceptions import InvalidWireGuardCidrError

        with pytest.raises(InvalidWireGuardCidrError):
            validate_cidr("10.100.0.5/16")

    def test_validate_cidr_accepts_clean_network(self) -> None:
        network = validate_cidr("10.100.0.0/16")
        assert str(network) == "10.100.0.0/16"


# ============================================================================
# Keypair generation
# ============================================================================


class TestKeypairGeneration:
    def test_generate_wireguard_keypair_produces_distinct_base64_32_byte_keys(
        self,
    ) -> None:
        import base64

        private_b64, public_b64 = generate_wireguard_keypair()
        assert private_b64 != public_b64
        assert len(base64.b64decode(private_b64)) == 32
        assert len(base64.b64decode(public_b64)) == 32

    def test_generate_wireguard_keypair_is_random(self) -> None:
        first_private, first_public = generate_wireguard_keypair()
        second_private, second_public = generate_wireguard_keypair()
        assert first_private != second_private
        assert first_public != second_public


# ============================================================================
# Automatic tunnel creation
# ============================================================================


class TestCreateTunnel:
    async def test_create_tunnel_allocates_ip_and_encrypts_private_key(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        info = await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        assert info.peer.router_id == router_device.id
        assert info.peer.status == PeerStatus.PENDING.value
        assert info.peer.tunnel_ip_address == "10.100.0.2"
        assert info.peer.rotation_count == 0
        # Encrypted at rest, decrypts back to exactly what was handed back.
        assert info.peer.private_key_encrypted != info.peer_private_key
        assert decrypt_secret(info.peer.private_key_encrypted) == info.peer_private_key

    async def test_create_tunnel_records_audit_entry(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        assert any(e["action"] == "wireguard_tunnel_created" for e in fx.audit.entries)

    async def test_create_tunnel_without_active_hub_raises(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        with pytest.raises(NoActiveWireGuardServerError):
            await fx.wireguard_service.create_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )

    async def test_create_tunnel_rejects_second_active_peer(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        with pytest.raises(WireGuardPeerAlreadyExistsError):
            await fx.wireguard_service.create_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )

    @pytest.mark.parametrize(
        "status", [RouterStatus.DECOMMISSIONED, RouterStatus.SUSPENDED]
    )
    async def test_create_tunnel_rejects_ineligible_router(self, status) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization, status=status)

        with pytest.raises(WireGuardRouterNotEligibleError):
            await fx.wireguard_service.create_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )

    async def test_two_routers_get_distinct_tunnel_ips(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        first_router = await make_router(fx, organization)
        second_router = await make_router(fx, organization)

        first_info = await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=first_router.id,
            requesting_organization_id=None,
        )
        second_info = await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=second_router.id,
            requesting_organization_id=None,
        )
        assert first_info.peer.tunnel_ip_address != second_info.peer.tunnel_ip_address


class TestCreateTunnelExternalPublicKey:
    """Module 009 Part 3 (zero-touch enrollment): ``create_tunnel``'s
    additive ``external_public_key`` parameter -- see that method's own
    docstring."""

    async def test_uses_device_supplied_public_key_not_a_generated_one(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        device_public_key = "ZGV2aWNlLWdlbmVyYXRlZC1wdWJsaWMta2V5LTMyYnl0ZXM="

        info = await fx.wireguard_service.create_tunnel(
            actor_user_id=None,
            router_id=router_device.id,
            requesting_organization_id=None,
            external_public_key=device_public_key,
        )

        assert info.peer.public_key == device_public_key
        assert info.peer.tunnel_ip_address == "10.100.0.2"

    async def test_private_key_encrypted_holds_sentinel_not_a_real_key(self) -> None:
        from app.domains.wireguard.service import EXTERNALLY_MANAGED_KEY_SENTINEL

        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        info = await fx.wireguard_service.create_tunnel(
            actor_user_id=None,
            router_id=router_device.id,
            requesting_organization_id=None,
            external_public_key="ZGV2aWNlLXB1YmxpYy1rZXk=",
        )

        # The platform never possesses this peer's real private key -- the
        # "private key" this call returns is the documented sentinel, and
        # it round-trips through encryption exactly like any other stored
        # value (proving the NOT NULL column constraint is satisfied),
        # never a fabricated/random secret.
        assert info.peer_private_key == EXTERNALLY_MANAGED_KEY_SENTINEL
        assert decrypt_secret(info.peer.private_key_encrypted) == (
            EXTERNALLY_MANAGED_KEY_SENTINEL
        )

    async def test_omitting_external_public_key_still_generates_one(self) -> None:
        """Unchanged, pre-existing behavior: no ``external_public_key``
        means the platform still generates both keys itself, exactly as
        before this addition."""
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        info = await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        assert info.peer_private_key != "EXTERNALLY_MANAGED_KEY_SENTINEL"
        assert decrypt_secret(info.peer.private_key_encrypted) == info.peer_private_key


class TestProvisioningCheckInWireGuardComposition:
    """Exercises the exact composition
    ``app.domains.router.router.provisioning_check_in`` performs when the
    device-presented request carries ``wireguard_public_key`` -- mirrors
    ``test_router_agent.py``'s own
    ``test_check_in_then_issue_credential_full_flow``'s "re-implement the
    endpoint's own composition inline against real services" convention,
    extended one step further (check-in -> issue agent credential ->
    create tunnel with the device's public key)."""

    async def test_check_in_with_public_key_allocates_tunnel(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        location = fx.location_lookup.add(organization_id=organization.id)
        router_device = await fx.router_service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            name="Bootstrap AP",
            serial_number=f"SN-{uuid.uuid4()}",
            mac_address=_unique_mac(),
            model="hAP ac2",
        )
        _token, plaintext_token = await fx.router_service.generate_provisioning_token(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        # -- the same composition provisioning_check_in performs --
        checked_in = await fx.router_service.check_in(plaintext_token=plaintext_token)
        assert checked_in.status == RouterStatus.PROVISIONING.value

        agent_service = RouterAgentService(
            fx.agent_repo,
            fx.router_service,
            None,  # config_version_lookup: unused by issue_credential_for_router
            None,  # job_queue_lookup: unused by issue_credential_for_router
            None,  # job_lifecycle: unused by issue_credential_for_router
        )
        credential, agent_plaintext = await agent_service.issue_credential_for_router(
            checked_in
        )
        assert agent_plaintext

        device_public_key = "ZGV2aWNlLWdlbmVyYXRlZC1wdWJsaWMta2V5LTMyYnl0ZXM="
        delivery = await fx.wireguard_service.create_tunnel(
            actor_user_id=None,
            router_id=checked_in.id,
            requesting_organization_id=None,
            external_public_key=device_public_key,
        )

        # Everything app.domains.router.router.provisioning_check_in's
        # response would carry, all real, non-None values.
        assert delivery.peer.public_key == device_public_key
        assert delivery.peer.tunnel_ip_address == "10.100.0.2"
        assert delivery.server.public_key
        assert delivery.server.endpoint_host == "hub.cloudguest.example"
        assert delivery.server.endpoint_port == 51820
        assert credential.expires_at is not None

    async def test_check_in_without_public_key_platform_generates_tunnel(
        self,
    ) -> None:
        """A device presenting only ``token`` -- the current bootstrap
        script -- gets a platform-generated tunnel at check-in
        (``provisioning_check_in`` now composes with
        ``ensure_tunnel_for_check_in`` unconditionally): a real,
        deliverable private key, never the externally-managed sentinel, so
        the script's immediate ``GET /agent/wireguard-config`` can hand the
        key straight to ``/interface wireguard add``."""
        from app.domains.wireguard.service import EXTERNALLY_MANAGED_KEY_SENTINEL

        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        location = fx.location_lookup.add(organization_id=organization.id)
        router_device = await fx.router_service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            name="No-WG AP",
            serial_number=f"SN-{uuid.uuid4()}",
            mac_address=_unique_mac(),
            model="hAP ac2",
        )
        _token, plaintext_token = await fx.router_service.generate_provisioning_token(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        checked_in = await fx.router_service.check_in(plaintext_token=plaintext_token)

        delivery = await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=checked_in.id,
        )

        peer = await fx.wireguard_repo.get_peer_by_router_id(checked_in.id)
        assert peer is not None
        assert delivery.peer_private_key != EXTERNALLY_MANAGED_KEY_SENTINEL
        assert decrypt_secret(peer.private_key_encrypted) == delivery.peer_private_key
        # Everything the (now-required) check-in response fields carry.
        assert delivery.peer.tunnel_ip_address
        assert delivery.server.public_key
        assert delivery.server.endpoint_host
        assert delivery.server.endpoint_port


class TestEnsureTunnelForCheckIn:
    """``ensure_tunnel_for_check_in`` is what makes re-pasting the bootstrap
    script a supported recovery path: the second check-in (with its fresh
    one-time token) must rotate the existing peer in place, never 409."""

    async def _enrolled_router(self, fx):  # noqa: ANN001, ANN202 -- test helper
        await make_hub(fx)
        organization = fx.org_lookup.add()
        return await make_router(fx, organization)

    async def test_first_check_in_creates_a_platform_keyed_peer(self) -> None:
        fx = make_services()
        router_device = await self._enrolled_router(fx)

        delivery = await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=router_device.id,
        )

        assert delivery.peer.rotation_count == 0
        assert delivery.peer.status == PeerStatus.PENDING.value
        assert decrypt_secret(delivery.peer.private_key_encrypted) == (
            delivery.peer_private_key
        )

    async def test_second_check_in_keeps_the_identity_the_hub_confirms(
        self,
    ) -> None:
        """THE ACCEPTANCE TEST for the 2026-08-27 fault.

        A device that enrolled and then checks in again must still be the
        peer the platform believes in. This previously rotated to a fresh
        platform keypair on every repeat check-in, which the Master
        console's own Generate flow triggers (it mints a provisioning token
        and burns it itself, ~50ms later, to get the agent credential it
        bakes into the .rsc). Three Generates on router 21e13913 produced
        three rotations to keys no WireGuard implementation anywhere held.
        """
        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        fx = make_services(hub_peer_lister=_lister)
        router_device = await self._enrolled_router(fx)
        first = await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=router_device.id,
        )
        # Snapshot before the re-run: the in-memory fake updates the same
        # peer object in place, so post-hoc comparisons through first.peer
        # would compare the row with itself.
        first_peer_id = first.peer.id
        first_tunnel_ip = first.peer.tunnel_ip_address
        first_public_key = first.peer.public_key
        first_private_key = first.peer_private_key
        first_rotation_count = first.peer.rotation_count
        # The hub now holds exactly this identity -- i.e. the device is
        # configured and the platform's record is correct.
        hub.append(
            {
                "public_key": first_public_key,
                "endpoint": "203.0.113.9:51820",
                "allowed_ips": f"{first_tunnel_ip}/32",
                "latest_handshake_epoch": int(_now().timestamp()),
                "transfer_rx_bytes": 3772,
                "transfer_tx_bytes": 1092,
            }
        )

        second = await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=router_device.id,
        )

        # Never WireGuardPeerAlreadyExistsError, and never a re-key.
        assert second.peer.id == first_peer_id
        assert second.peer.tunnel_ip_address == first_tunnel_ip
        assert second.peer.public_key == first_public_key
        assert second.peer_private_key == first_private_key
        assert second.peer.rotation_count == first_rotation_count

    async def test_second_check_in_with_unreachable_hub_changes_nothing(
        self,
    ) -> None:
        """"Cannot confirm" is not "gone". With no way to read the hub, the
        safe answer is to leave the router exactly as it is -- rotating on
        a guess is what breaks a venue that was working."""
        fx = make_services()
        router_device = await self._enrolled_router(fx)
        first = await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=router_device.id,
        )
        first_public_key = first.peer.public_key
        first_rotation_count = first.peer.rotation_count

        second = await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=router_device.id,
        )

        assert second.peer.public_key == first_public_key
        assert second.peer.rotation_count == first_rotation_count

    async def test_check_in_rotation_is_refused_when_the_hub_cannot_learn_the_key(
        self,
    ) -> None:
        """The hub has forgotten this peer, so rotation IS the right shape
        of repair -- but ``POST /wg/peer`` generates its own keypair and
        there is no verb to register one, so a platform-generated rotation
        writes a key the hub will never expect. Refused, naming the action
        that does work, instead of silently writing a dead tunnel."""

        async def _lister() -> list[dict]:
            return []  # a hub that has genuinely forgotten everything

        fx = make_services(
            hub_peer_lister=_lister,
            hub_capabilities=HubCapabilities(
                can_register_public_key=False, can_remove_peer=False
            ),
        )
        router_device = await self._enrolled_router(fx)
        # The first check-in has to be allowed through, so build the peer
        # with a device-supplied key -- the only path a key-registration-
        # less hub supports.
        await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=router_device.id,
            external_public_key="ZGV2aWNlLXB1YmxpYy1rZXktb25l",
        )

        with pytest.raises(HubCannotLearnPlatformKeyError):
            await fx.wireguard_service.ensure_tunnel_for_check_in(
                router_id=router_device.id,
            )

    async def test_revoked_peer_is_recreated_not_rotated(self) -> None:
        fx = make_services()
        router_device = await self._enrolled_router(fx)
        await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=router_device.id,
        )
        await fx.wireguard_service.revoke_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        delivery = await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=router_device.id,
        )

        assert delivery.peer.status == PeerStatus.PENDING.value
        assert not delivery.peer.is_revoked()

    async def test_live_peer_plus_device_reported_key_is_adopted(self) -> None:
        """A live peer plus a device-supplied public key used to raise
        ``WireGuardPeerAlreadyExistsError`` -- treating the device telling
        us who it is as a conflict.

        It is not a conflict, it is the best information available. The
        device holds a private key nobody else has; no server-side action
        can change which key it is using, so the only correct response is
        to record it. Verified against the hub first: a key the hub does
        not hold is not an observation, and adopting it would swap one
        wrong row for another."""
        device_key = "ZGV2aWNlLXB1YmxpYy1rZXktYWRvcHRlZA=="

        async def _lister() -> list[dict]:
            return [
                {
                    "public_key": device_key,
                    "endpoint": "203.0.113.9:51820",
                    "allowed_ips": "10.100.0.9/32",
                    "latest_handshake_epoch": int(_now().timestamp()),
                    "transfer_rx_bytes": 3772,
                    "transfer_tx_bytes": 1092,
                }
            ]

        fx = make_services(hub_peer_lister=_lister)
        router_device = await self._enrolled_router(fx)
        first = await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=router_device.id,
        )
        peer_id = first.peer.id

        second = await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=router_device.id,
            external_public_key=device_key,
        )

        assert second.peer.id == peer_id
        assert second.peer.public_key == device_key
        # The ADDRESS follows the key, because the hub's allowed-ips is
        # what decides where packets for this peer actually go.
        assert second.peer.tunnel_ip_address == "10.100.0.9"
        assert second.peer.status == PeerStatus.ACTIVE.value
        # Adoption mints no key material, so it must not claim a rotation.
        assert second.peer.rotation_count == first.peer.rotation_count

    async def test_device_reported_key_the_hub_does_not_hold_is_refused(
        self,
    ) -> None:
        async def _lister() -> list[dict]:
            return []

        fx = make_services(hub_peer_lister=_lister)
        router_device = await self._enrolled_router(fx)
        await fx.wireguard_service.ensure_tunnel_for_check_in(
            router_id=router_device.id,
        )

        with pytest.raises(HubPeerNotOnHubError):
            await fx.wireguard_service.ensure_tunnel_for_check_in(
                router_id=router_device.id,
                external_public_key="dW5rbm93bi1rZXktbm90LW9uLXRoZS1odWI=",
            )


class TestAllocationConflictRetry:
    """Exercises ``WireGuardService``'s allocation-conflict retry loop
    directly, using ``RacyWireGuardRepository`` to simulate a concurrent
    request that already committed an address a stale read missed -- see
    ``validators.allocate_tunnel_ip``'s module docstring for why the
    database's unique constraint (mirrored here by
    ``FakeWireGuardRepository._check_unique``) is the real safety net, and
    this retry loop is only the smoothing-over layer on top of it."""

    async def test_retries_and_succeeds_after_one_stale_read(self) -> None:
        racy_repo = RacyWireGuardRepository(stale_reads_remaining=1)
        fx = make_services(wireguard_repo=racy_repo)
        await make_hub(fx, cidr="10.100.0.0/29")
        organization = fx.org_lookup.add()

        # A peer already occupies .2 (the first allocatable address) --
        # simulating a concurrent request that already committed.
        occupying_router = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=occupying_router.id,
            requesting_organization_id=None,
        )
        racy_repo.stale_reads_remaining = 1

        new_router = await make_router(fx, organization)
        info = await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=new_router.id,
            requesting_organization_id=None,
        )
        # The stale first read claimed .2 was free (it collided and was
        # rejected); the retry's fresh read correctly picked .3.
        assert info.peer.tunnel_ip_address == "10.100.0.3"

    async def test_raises_conflict_error_after_exhausting_retries(self) -> None:
        racy_repo = RacyWireGuardRepository(stale_reads_remaining=0)
        fx = make_services(wireguard_repo=racy_repo)
        await make_hub(fx, cidr="10.100.0.0/29")
        organization = fx.org_lookup.add()

        occupying_router = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=occupying_router.id,
            requesting_organization_id=None,
        )
        # Every subsequent occupancy read is stale for the rest of this
        # test -- every allocation attempt collides, exhausting the retry
        # budget.
        racy_repo.stale_reads_remaining = 10

        new_router = await make_router(fx, organization)
        with pytest.raises(TunnelIPAllocationConflictError):
            await fx.wireguard_service.create_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=new_router.id,
                requesting_organization_id=None,
            )


# ============================================================================
# Revoke + re-create
# ============================================================================


class TestRevokeAndRecreate:
    async def test_revoke_marks_peer_revoked(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        revoked = await fx.wireguard_service.revoke_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        assert revoked.status == PeerStatus.REVOKED.value
        assert revoked.revoked_at is not None

    async def test_revoke_already_revoked_peer_raises(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        await fx.wireguard_service.revoke_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        with pytest.raises(InvalidPeerStatusTransitionError):
            await fx.wireguard_service.revoke_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )

    async def test_revoke_frees_ip_for_reuse_by_another_router(self) -> None:
        # /29 = 8 addresses; .0 network, .7 broadcast (excluded by .hosts()),
        # .1 reserved for the hub -- leaves exactly 5 peer-assignable
        # addresses: .2, .3, .4, .5, .6.
        fx = make_services()
        await make_hub(fx, cidr="10.100.0.0/29")
        organization = fx.org_lookup.add()
        first_router = await make_router(fx, organization)

        first_info = await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=first_router.id,
            requesting_organization_id=None,
        )
        freed_ip = first_info.peer.tunnel_ip_address
        assert freed_ip == "10.100.0.2"

        # Fill up every *other* address (.3-.6) while first_router still
        # holds .2, so the pool is fully saturated except for .2 itself.
        for _ in range(4):
            filler = await make_router(fx, organization)
            await fx.wireguard_service.create_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=filler.id,
                requesting_organization_id=None,
            )

        # Now revoke first_router -- .2 becomes the *only* free address.
        await fx.wireguard_service.revoke_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=first_router.id,
            requesting_organization_id=None,
        )

        second_router = await make_router(fx, organization)
        second_info = await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=second_router.id,
            requesting_organization_id=None,
        )
        assert second_info.peer.tunnel_ip_address == freed_ip

    async def test_recreate_tunnel_for_revoked_router_reuses_same_row(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        first_info = await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        first_peer_id = first_info.peer.id
        await fx.wireguard_service.revoke_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        second_info = await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        assert second_info.peer.id == first_peer_id
        assert second_info.peer.status == PeerStatus.PENDING.value
        assert second_info.peer.rotation_count == 1
        assert second_info.peer_private_key != first_info.peer_private_key
        # Exactly one row exists for this router -- reuse, never a second row.
        assert len(fx.wireguard_repo.peers) == 1

    async def test_revoke_nonexistent_peer_raises(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        with pytest.raises(WireGuardPeerNotFoundError):
            await fx.wireguard_service.revoke_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )


# ============================================================================
# Key / tunnel rotation
# ============================================================================


class TestRotateTunnel:
    async def test_rotate_keeps_same_ip_changes_keys(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        created = await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        # The fake (like the real GenericRepository) mutates and returns the
        # *same* instance on update -- capture every value that rotation
        # will change *before* rotating, mirroring
        # test_router_agent.py's identical "capture by value first" note.
        created_peer_id = created.peer.id
        created_tunnel_ip = created.peer.tunnel_ip_address
        created_public_key = created.peer.public_key
        created_private_key = created.peer_private_key
        created_rotation_count = created.peer.rotation_count

        rotated = await fx.wireguard_service.rotate_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        assert rotated.peer.tunnel_ip_address == created_tunnel_ip
        assert rotated.peer.public_key != created_public_key
        assert rotated.peer_private_key != created_private_key
        assert rotated.peer.rotation_count == created_rotation_count + 1
        assert rotated.peer.id == created_peer_id

    async def test_rotate_resets_status_to_pending_and_clears_handshake(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        await fx.wireguard_service.record_handshake(router=router_device)

        rotated = await fx.wireguard_service.rotate_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        assert rotated.peer.status == PeerStatus.PENDING.value
        assert rotated.peer.last_handshake_at is None

    async def test_rotate_records_audit_entry(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        await fx.wireguard_service.rotate_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        assert any(e["action"] == "wireguard_tunnel_rotated" for e in fx.audit.entries)

    async def test_rotate_revoked_peer_raises(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        await fx.wireguard_service.revoke_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        with pytest.raises(WireGuardPeerRevokedError):
            await fx.wireguard_service.rotate_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )

    async def test_rotate_nonexistent_peer_raises(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        with pytest.raises(WireGuardPeerNotFoundError):
            await fx.wireguard_service.rotate_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )


# ============================================================================
# Device-facing config pull, composed through router_agent's CurrentAgent
# ============================================================================


class TestDeviceFacingConfigPull:
    async def test_pull_config_with_valid_credential_activates_peer(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        plaintext_credential = await issue_agent_credential(fx, router_device)

        identity = await CurrentAgent(
            FakeRequest(headers={AGENT_CREDENTIAL_HEADER: plaintext_credential}),
            agent_repository=fx.agent_repo,
            router_repository=fx.router_repo,
        )
        assert identity.router.id == router_device.id

        info = await fx.wireguard_service.get_config_for_agent(router=identity.router)
        assert info.peer.status == PeerStatus.ACTIVE.value
        assert info.peer_private_key
        assert info.server.public_key

    async def test_pull_config_without_credential_header_raises(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await issue_agent_credential(fx, router_device)

        with pytest.raises(AgentCredentialMissingError):
            await CurrentAgent(
                FakeRequest(headers={}),
                agent_repository=fx.agent_repo,
                router_repository=fx.router_repo,
            )

    async def test_pull_config_with_invalid_credential_raises(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await issue_agent_credential(fx, router_device)

        with pytest.raises(AgentCredentialInvalidError):
            await CurrentAgent(
                FakeRequest(headers={AGENT_CREDENTIAL_HEADER: "not-a-real-credential"}),
                agent_repository=fx.agent_repo,
                router_repository=fx.router_repo,
            )

    async def test_pull_config_with_no_peer_raises(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        plaintext_credential = await issue_agent_credential(fx, router_device)

        identity = await CurrentAgent(
            FakeRequest(headers={AGENT_CREDENTIAL_HEADER: plaintext_credential}),
            agent_repository=fx.agent_repo,
            router_repository=fx.router_repo,
        )
        with pytest.raises(WireGuardPeerNotFoundError):
            await fx.wireguard_service.get_config_for_agent(router=identity.router)

    async def test_pull_config_for_device_managed_peer_refuses_sentinel(
        self,
    ) -> None:
        """A legacy device-generated-keypair peer stores only the sentinel
        -- serving it as ``peer_private_key`` would have the bootstrap
        script install a literal placeholder string as the interface's
        private key. The pull must refuse loudly instead, and must not
        flip the peer to ``active`` (nothing was delivered)."""
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            external_public_key="ZGV2aWNlLXB1YmxpYy1rZXk=",
        )

        with pytest.raises(WireGuardPrivateKeyUnavailableError):
            await fx.wireguard_service.get_config_for_agent(router=router_device)

        peer = await fx.wireguard_repo.get_peer_by_router_id(router_device.id)
        assert peer is not None
        assert peer.status == PeerStatus.PENDING.value

    async def test_pull_config_never_leaks_hub_private_key(self) -> None:
        """The device only ever receives its own private key plus the hub's
        *public* key/endpoint -- never the hub's private key."""
        fx = make_services()
        server = await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        info = await fx.wireguard_service.get_config_for_agent(router=router_device)
        assert info.server.private_key_encrypted == server.private_key_encrypted
        assert info.peer_private_key != decrypt_secret(server.private_key_encrypted)


# ============================================================================
# Handshake reporting + health-status staleness threshold
# ============================================================================


class TestHandshakeAndHealth:
    async def test_record_handshake_sets_timestamp_and_activates_pending_peer(
        self,
    ) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        updated = await fx.wireguard_service.record_handshake(router=router_device)
        assert updated.last_handshake_at is not None
        assert updated.status == PeerStatus.ACTIVE.value

    async def test_record_handshake_on_revoked_peer_raises(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        await fx.wireguard_service.revoke_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        with pytest.raises(WireGuardPeerNotFoundError):
            await fx.wireguard_service.record_handshake(router=router_device)

    async def test_health_status_unknown_before_any_handshake(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        info = await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        status_value = fx.wireguard_service.compute_health_status(info.peer)
        assert status_value == HealthStatus.UNKNOWN

    async def test_health_status_healthy_within_threshold(self) -> None:
        fx = make_services(handshake_stale_after_minutes=5)
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        peer = await fx.wireguard_service.record_handshake(router=router_device)

        now = peer.last_handshake_at + timedelta(minutes=2)
        status_value = fx.wireguard_service.compute_health_status(peer, now=now)
        assert status_value == HealthStatus.HEALTHY

    async def test_health_status_stale_past_threshold(self) -> None:
        fx = make_services(handshake_stale_after_minutes=5)
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        peer = await fx.wireguard_service.record_handshake(router=router_device)

        now = peer.last_handshake_at + timedelta(minutes=10)
        status_value = fx.wireguard_service.compute_health_status(peer, now=now)
        assert status_value == HealthStatus.STALE

    async def test_health_status_revoked_overrides_handshake_recency(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        peer = await fx.wireguard_service.record_handshake(router=router_device)
        revoked = await fx.wireguard_service.revoke_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        status_value = fx.wireguard_service.compute_health_status(revoked)
        assert status_value == HealthStatus.REVOKED
        assert peer.id == revoked.id


# ============================================================================
# Tenant isolation
# ============================================================================


class TestTenantIsolation:
    async def test_create_tunnel_rejects_cross_organization_caller(self) -> None:
        fx = make_services()
        await make_hub(fx)
        owning_org = fx.org_lookup.add()
        other_org = fx.org_lookup.add()
        router_device = await make_router(fx, owning_org)

        with pytest.raises(CrossOrganizationRouterAccessError):
            await fx.wireguard_service.create_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=other_org.id,
            )

    async def test_get_peer_rejects_cross_organization_caller(self) -> None:
        fx = make_services()
        await make_hub(fx)
        owning_org = fx.org_lookup.add()
        other_org = fx.org_lookup.add()
        router_device = await make_router(fx, owning_org)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        with pytest.raises(CrossOrganizationRouterAccessError):
            await fx.wireguard_service.get_peer(
                router_id=router_device.id,
                requesting_organization_id=other_org.id,
            )

    async def test_get_peer_allows_same_organization_caller(self) -> None:
        fx = make_services()
        await make_hub(fx)
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        await fx.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        peer = await fx.wireguard_service.get_peer(
            router_id=router_device.id,
            requesting_organization_id=organization.id,
        )
        assert peer.router_id == router_device.id


class TestRevokeTellsTheHub:
    """The database and the hub are two separate records of the same fleet.

    Freeing an address here while the hub still hands it out is what left 68
    orphaned peers on the tunnel box against 1 row in the database -- and it
    means the next router provisioned is given an address another peer still
    claims.
    """

    async def _peer(self, f):
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
        )
        return router

    async def test_revoke_removes_the_peer_from_the_hub(self) -> None:
        called: list[str] = []

        async def _dereg(public_key: str) -> HubRemovalOutcome:
            called.append(public_key)
            return HubRemovalOutcome.REMOVED

        f = make_services(hub_peer_deregistrar=_dereg)
        router = await self._peer(f)
        peer = await f.wireguard_repo.get_peer_by_router_id(router.id)
        key = peer.public_key

        await f.wireguard_service.revoke_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
        )

        assert called == [key]

    async def test_a_hub_that_cannot_be_reached_fails_the_revoke(self) -> None:
        """NOT a warning. The RadiusNasClient deregistration logged and
        carried on, and the result was a database with zero NAS clients, a
        hub with 21 stanzas, and an operator told it had worked."""

        async def _boom(public_key: str) -> None:
            raise RuntimeError("hub bridge unreachable")

        f = make_services(hub_peer_deregistrar=_boom)
        router = await self._peer(f)

        with pytest.raises(RuntimeError):
            await f.wireguard_service.revoke_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                requesting_organization_id=None,
            )

    async def test_a_failed_hub_call_leaves_the_address_still_taken(self) -> None:
        """The ordering guarantee. If the hub still holds the peer, the
        database must still consider that address occupied -- otherwise the
        allocator hands it to the next router while the old peer keeps
        claiming it, which is the whole failure."""

        async def _boom(public_key: str) -> None:
            raise RuntimeError("hub bridge unreachable")

        f = make_services(hub_peer_deregistrar=_boom)
        router = await self._peer(f)
        peer = await f.wireguard_repo.get_peer_by_router_id(router.id)
        held = peer.tunnel_ip_address

        with pytest.raises(RuntimeError):
            await f.wireguard_service.revoke_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                requesting_organization_id=None,
            )

        after = await f.wireguard_repo.get_peer_by_router_id(router.id)
        assert after.status != PeerStatus.REVOKED.value
        assert after.tunnel_ip_address == held
        occupied = await f.wireguard_repo.list_occupied_tunnel_ips(peer.server_id)
        assert held in occupied


# ============================================================================
# Fleet status: this table vs. the hub's own live `wg show` state
# ============================================================================


def _hub_peer(
    public_key: str,
    *,
    handshake_epoch: int,
    allowed_ips: str = "10.20.0.99/32",
    tunnel_ip: str | None = None,
) -> dict:
    """``tunnel_ip`` is the shorthand every "the two sides agree" test
    wants: the hub reports allowed-ips as a CIDR, and a hub address that
    disagrees with the peer row is now its own finding
    (``TRACKED_KEY_MISMATCH``) rather than a detail the classifier ignores.
    Tests that are not about that disagreement must not accidentally
    produce it."""
    """One entry in the shape ``ops/hub-agents/wg_agent.py``'s
    ``list_peers()`` / ``HubPeerLister`` return -- see
    ``service.HubPeerLister``'s own docstring for the exact field set."""
    return {
        "public_key": public_key,
        "endpoint": "203.0.113.5:51820",
        "allowed_ips": f"{tunnel_ip}/32" if tunnel_ip else allowed_ips,
        "latest_handshake_epoch": handshake_epoch,
        "transfer_rx_bytes": 1024,
        "transfer_tx_bytes": 2048,
    }


class TestFleetStatus:
    """``get_fleet_status`` is the live-``wg show``-vs-database comparison
    that ``HubPeerLister``'s own docstring exists to make possible -- see
    that class and ``TestRevokeTellsTheHub`` above for the same
    "two independent records of the fleet" framing. Every state below is
    exercised with a hub-reported peer list built by hand
    (``_hub_peer``), never real HTTP."""

    async def test_no_lister_configured_raises(self) -> None:
        f = make_services(hub_peer_lister=None)

        with pytest.raises(HubPeerListerNotConfiguredError):
            await f.wireguard_service.get_fleet_status()

    async def test_tracked_and_recently_connected(self) -> None:
        async def _lister() -> list[dict]:
            return [
                _hub_peer(
                    peer_public_key,
                    handshake_epoch=int(now.timestamp()),
                    tunnel_ip=peer_tunnel_ip,
                )
            ]

        f = make_services(hub_peer_lister=_lister)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        f.wireguard_repo.router_names[router.id] = router.name
        now = datetime.now(UTC)
        await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
        )
        peer = await f.wireguard_repo.get_peer_by_router_id(router.id)
        peer_public_key = peer.public_key
        peer_tunnel_ip = peer.tunnel_ip_address

        result = await f.wireguard_service.get_fleet_status(now=now)

        assert result.summary[FleetPeerStatus.TRACKED_CONNECTED] == 1
        assert result.summary[FleetPeerStatus.TRACKED_STALE] == 0
        assert result.summary[FleetPeerStatus.UNTRACKED_CONNECTED] == 0
        assert result.summary[FleetPeerStatus.TRACKED_MISSING_FROM_HUB] == 0
        (entry,) = result.peers
        assert entry.status == FleetPeerStatus.TRACKED_CONNECTED
        assert entry.router_id == router.id
        assert entry.router_name == router.name
        assert entry.public_key == peer_public_key

    async def test_tracked_but_stale_handshake(self) -> None:
        now = datetime.now(UTC)
        stale_epoch = int((now - timedelta(hours=2)).timestamp())

        async def _lister() -> list[dict]:
            return [
                _hub_peer(
                    peer_public_key,
                    handshake_epoch=stale_epoch,
                    tunnel_ip=peer_tunnel_ip,
                )
            ]

        f = make_services(hub_peer_lister=_lister, handshake_stale_after_minutes=5)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
        )
        _stale_peer = await f.wireguard_repo.get_peer_by_router_id(router.id)
        peer_public_key = _stale_peer.public_key
        peer_tunnel_ip = _stale_peer.tunnel_ip_address

        result = await f.wireguard_service.get_fleet_status(now=now)

        assert result.summary[FleetPeerStatus.TRACKED_STALE] == 1
        assert result.peers[0].status == FleetPeerStatus.TRACKED_STALE

    async def test_untracked_connected_is_the_ghost_peer_case(self) -> None:
        """The exact drift this feature was built to surface: the hub has a
        real, live peer this table has never heard of."""
        ghost_key = "ghost-public-key-not-in-db"

        async def _lister() -> list[dict]:
            handshake = int(datetime.now(UTC).timestamp())
            return [_hub_peer(ghost_key, handshake_epoch=handshake)]

        f = make_services(hub_peer_lister=_lister)

        result = await f.wireguard_service.get_fleet_status()

        assert result.summary[FleetPeerStatus.UNTRACKED_CONNECTED] == 1
        (entry,) = result.peers
        assert entry.status == FleetPeerStatus.UNTRACKED_CONNECTED
        assert entry.public_key == ghost_key
        assert entry.router_id is None
        assert entry.router_name is None

    async def test_tracked_missing_from_hub(self) -> None:
        """A DB row the hub has completely forgotten -- the inverse drift,
        surfaced rather than silently dropped."""

        async def _lister() -> list[dict]:
            return []

        f = make_services(hub_peer_lister=_lister)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
        )

        result = await f.wireguard_service.get_fleet_status()

        assert result.summary[FleetPeerStatus.TRACKED_MISSING_FROM_HUB] == 1
        assert result.peers[0].status == FleetPeerStatus.TRACKED_MISSING_FROM_HUB
        assert result.peers[0].router_id == router.id

    async def test_all_four_states_at_once(self) -> None:
        """A realistic mixed fleet -- one of each state in a single call,
        verifying classification doesn't leak between peers."""
        now = datetime.now(UTC)
        ghost_key = "ghost-public-key"

        f = make_services(handshake_stale_after_minutes=5)
        await make_hub(f)
        org = f.org_lookup.add()

        connected_router = await make_router(f, org)
        await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=connected_router.id,
            requesting_organization_id=None,
        )
        _connected_peer = await f.wireguard_repo.get_peer_by_router_id(
            connected_router.id
        )
        connected_key = _connected_peer.public_key
        connected_ip = _connected_peer.tunnel_ip_address

        stale_router = await make_router(f, org)
        await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=stale_router.id,
            requesting_organization_id=None,
        )
        _stale_peer = await f.wireguard_repo.get_peer_by_router_id(stale_router.id)
        stale_key = _stale_peer.public_key
        stale_ip = _stale_peer.tunnel_ip_address

        missing_router = await make_router(f, org)
        await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=missing_router.id,
            requesting_organization_id=None,
        )

        async def _lister() -> list[dict]:
            return [
                _hub_peer(
                    connected_key,
                    handshake_epoch=int(now.timestamp()),
                    tunnel_ip=connected_ip,
                ),
                _hub_peer(
                    stale_key,
                    handshake_epoch=int((now - timedelta(hours=1)).timestamp()),
                    tunnel_ip=stale_ip,
                ),
                _hub_peer(ghost_key, handshake_epoch=int(now.timestamp())),
            ]

        f.wireguard_service.hub_peer_lister = _lister
        result = await f.wireguard_service.get_fleet_status(now=now)

        assert result.summary == {
            FleetPeerStatus.TRACKED_CONNECTED: 1,
            FleetPeerStatus.TRACKED_STALE: 1,
            FleetPeerStatus.UNTRACKED_CONNECTED: 1,
            FleetPeerStatus.TRACKED_MISSING_FROM_HUB: 1,
            # The three states added for the 2026-08-27 fault. Asserted as
            # zero rather than dropped from the comparison: this test's
            # value is that it pins the WHOLE classification, so a peer
            # silently landing in a new bucket fails here.
            FleetPeerStatus.ADOPTABLE_MISMATCH: 0,
            FleetPeerStatus.KNOWN_ORPHAN: 0,
            FleetPeerStatus.TRACKED_KEY_MISMATCH: 0,
        }
        assert len(result.peers) == 4
        by_status = {entry.status: entry for entry in result.peers}
        assert by_status[FleetPeerStatus.TRACKED_CONNECTED].public_key == connected_key
        assert by_status[FleetPeerStatus.TRACKED_STALE].public_key == stale_key
        assert by_status[FleetPeerStatus.UNTRACKED_CONNECTED].public_key == ghost_key


class TestFleetStatusRouteRequiresPermission:
    """A genuine, executable check for the ``wireguard.read``-gated,
    GLOBAL-scope fleet-status route -- same convention
    ``TestImpersonateRouteRequiresPermission`` (test_user.py) establishes
    for asserting a route's ``RequirePermission`` key/scope directly off
    its FastAPI dependency, rather than only through a live 403."""

    def _route(self):
        return next(
            route
            for route in wireguard_router.routes
            if route.path == "/wireguard/fleet-status"
        )

    def test_route_is_gated_by_wireguard_read(self) -> None:
        route = self._route()
        assert route.methods == {"GET"}
        assert _permission_keys(route) == ["wireguard.read"]

    def test_route_checks_global_scope_explicitly(self) -> None:
        route = self._route()
        (dependency,) = route.dependencies
        nonlocals = inspect.getclosurevars(dependency.dependency).nonlocals
        assert nonlocals["scope"] == ScopeType.GLOBAL


class TestSupersededPeerIsRemovedFromHub:
    """Every Generate in the Master console's Setup Script panel calls the
    hub bridge for a FRESH keypair and the NEXT FREE tunnel IP, then
    overwrites this router's row to point at it. Nothing ever told the hub
    to forget the peer it replaced.

    Confirmed live 2026-08-27 on router 01c9171e: ``GET /wg/peers``
    returned 10.20.0.2, 10.20.0.3 AND 10.20.0.4 for one router, with the
    handshake on .3 -- the address the device was actually still using --
    while this table tracked .4. Three harms: the hub routes to tunnel IPs
    no live device owns; ``next_free_ip()`` scans live kernel state so
    orphans permanently consume a /24 (three rotations each caps the fleet
    near 84 routers, not 254); and ``get_fleet_status`` reports every
    orphan as UNTRACKED_CONNECTED -- self-inflicted drift, on every click.
    """

    async def _router_with_peer(self, f):
        """Seeds via ``create_tunnel``, the same helper every other class in
        this file uses, and hands back the peer's real generated key --
        which is what the re-registration below must supersede."""
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
        )
        peer = await f.wireguard_repo.get_peer_by_router_id(router.id)
        return router, peer.public_key

    async def test_re_registration_deregisters_the_key_it_replaces(self) -> None:
        removed: list[str] = []

        async def _dereg(public_key: str) -> HubRemovalOutcome:
            removed.append(public_key)
            return HubRemovalOutcome.REMOVED

        f = make_services(hub_peer_deregistrar=_dereg)
        router, old_key = await self._router_with_peer(f)

        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.44",
            public_key="NEWKEY",
        )

        assert removed == [old_key], (
            "the superseded peer was left on the hub -- this is exactly how one router "
            "accumulated 10.20.0.2/.3/.4"
        )

    async def test_re_registering_the_same_key_removes_nothing(self) -> None:
        """An idempotent re-registration must not deregister the very key
        it is re-asserting -- that would take a working tunnel down."""
        removed: list[str] = []

        async def _dereg(public_key: str) -> HubRemovalOutcome:
            removed.append(public_key)
            return HubRemovalOutcome.REMOVED

        f = make_services(hub_peer_deregistrar=_dereg)
        router, same_key = await self._router_with_peer(f)
        peer = await f.wireguard_repo.get_peer_by_router_id(router.id)

        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address=peer.tunnel_ip_address,
            public_key=same_key,
        )

        assert removed == []

    async def test_a_hub_that_refuses_the_removal_still_records_the_new_peer(
        self,
    ) -> None:
        """Deliberately best-effort here, unlike ``revoke_tunnel`` which
        fails hard. The ordering is forced: the bridge has ALREADY created
        the replacement peer on the hub by the time this runs, so raising
        would abort before the row is written and leave a hub peer with no
        DB row at all -- strictly worse drift than the stale peer we were
        trying to remove."""

        async def _boom(public_key: str) -> None:
            raise RuntimeError("hub bridge unreachable")

        f = make_services(hub_peer_deregistrar=_boom)
        router, _old_key = await self._router_with_peer(f)

        peer = await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.44",
            public_key="NEWKEY",
        )

        assert peer.public_key == "NEWKEY"
        assert peer.tunnel_ip_address == "10.20.0.44"


# ============================================================================
# The 2026-08-27 "huda city center" fault: reconciliation, adoption, and
# honest accounting for peers a hub with no DELETE verb can never shed.
#
# Every scenario below is the shape of a state measured on the production
# hub that day, not an invented one -- the venue's device was handshaking
# on 10.20.0.6 with a key the platform had overwritten, while the platform
# recorded 10.20.0.8 and had pushed the RADIUS client stanza to match its
# own wrong record.
# ============================================================================


class TestIssuanceLedger:
    """``wireguard_peer_issuances`` is the record that makes adoption a
    proof rather than a guess. Without it, six of the seven peers on the
    production hub were unattributable -- despite the platform having
    allocated every one of them, for one router, in twelve minutes."""

    async def test_every_identity_handed_out_is_recorded(self) -> None:
        f = make_services()
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)

        await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
        )
        peer = await f.wireguard_repo.get_peer_by_router_id(router.id)

        ledger = await f.wireguard_repo.list_issuances_for_router(router.id)
        assert len(ledger) == 1
        assert ledger[0].public_key == peer.public_key
        assert ledger[0].tunnel_ip_address == peer.tunnel_ip_address
        assert ledger[0].source == PeerIdentitySource.PLATFORM_GENERATED.value
        assert ledger[0].superseded_at is None

    async def test_a_replaced_identity_is_superseded_not_forgotten(self) -> None:
        f = make_services()
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        first = await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.6",
            public_key="KEY-SIX",
        )
        assert first.tunnel_ip_address == "10.20.0.6"

        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.8",
            public_key="KEY-EIGHT",
        )

        ledger = await f.wireguard_repo.list_issuances_for_router(router.id)
        assert len(ledger) == 2
        current = [i for i in ledger if i.superseded_at is None]
        assert [i.public_key for i in current] == ["KEY-EIGHT"]
        superseded = next(i for i in ledger if i.public_key == "KEY-SIX")
        # No deregistrar wired here, so nothing was ever pushed to a hub by
        # this service and there is nothing to orphan -- see
        # `_deregister_from_hub`'s own comment on why that is NOT the same
        # answer as "a hub exists and cannot remove".
        assert superseded.hub_lifecycle == HubPeerLifecycle.NEVER_REGISTERED.value


class TestOrphanAccountingWhenTheHubCannotDelete:
    """Production's actual configuration: a hub bridge that answers, and
    answers 501. The peer is not removed and never will be, so the platform
    has to account for it rather than keep asking."""

    def _degraded(self, **kwargs):  # noqa: ANN001, ANN202 -- test helper
        async def _dereg(public_key: str) -> HubRemovalOutcome:
            return HubRemovalOutcome.UNSUPPORTED

        return make_services(
            hub_peer_deregistrar=_dereg,
            hub_capabilities=HubCapabilities(
                can_register_public_key=False, can_remove_peer=False
            ),
            **kwargs,
        )

    async def test_a_superseded_peer_becomes_a_recorded_orphan(self) -> None:
        f = self._degraded()
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.6",
            public_key="KEY-SIX",
        )

        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.8",
            public_key="KEY-EIGHT",
        )

        orphan = await f.wireguard_repo.get_issuance_by_public_key("KEY-SIX")
        assert orphan.hub_lifecycle == HubPeerLifecycle.ORPHANED.value

    async def test_an_orphans_address_is_quarantined_from_reallocation(
        self,
    ) -> None:
        """The hazard the old hard-failing revoke existed to prevent, closed
        by different means. An address the hub still routes must never be
        handed to another router: WireGuard routes by allowed-ips, so both
        break in a way that reads as "the tunnel is flaky"."""
        f = self._degraded()
        await make_hub(f, cidr="10.20.0.0/29")
        org = f.org_lookup.add()
        first_router = await make_router(f, org)
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=first_router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.2",
            public_key="KEY-TWO",
        )
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=first_router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.3",
            public_key="KEY-THREE",
        )
        # .2 is now superseded in `wireguard_peers` -- the table has one row
        # per router and it points at .3 -- but the hub still holds it.
        assert (
            await f.wireguard_repo.get_peer_by_router_id(first_router.id)
        ).tunnel_ip_address == "10.20.0.3"

        second_router = await make_router(f, org)
        info = await f.wireguard_service.create_tunnel(
            actor_user_id=None,
            router_id=second_router.id,
            requesting_organization_id=None,
            external_public_key="c2Vjb25kLXJvdXRlcnMtb3duLWtleQ==",
        )

        assert info.peer.tunnel_ip_address != "10.20.0.2"

    async def test_revoke_proceeds_and_records_the_orphan(self) -> None:
        """Revoke used to raise on a 501, which made it not merely degraded
        but impossible -- every call, forever, against the deployed agent.
        That left an operator with no way at all to stop serving a router,
        which is worse than the hazard it was guarding against."""
        f = self._degraded()
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.6",
            public_key="KEY-SIX",
        )

        revoked = await f.wireguard_service.revoke_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
        )

        assert revoked.is_revoked()
        orphan = await f.wireguard_repo.get_issuance_by_public_key("KEY-SIX")
        assert orphan.hub_lifecycle == HubPeerLifecycle.ORPHANED.value

    async def test_an_unreachable_hub_still_fails_the_revoke(self) -> None:
        """Unchanged, and it must stay unchanged. "We could not ask" is not
        "we asked and it cannot" -- the first is transient and guessing is
        what left 21 live client stanzas against 0 NAS rows."""

        async def _boom(public_key: str) -> HubRemovalOutcome:
            raise RuntimeError("hub bridge unreachable")

        f = make_services(hub_peer_deregistrar=_boom)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
        )

        with pytest.raises(RuntimeError):
            await f.wireguard_service.revoke_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                requesting_organization_id=None,
            )


class TestHubCannotLearnAPlatformGeneratedKey:
    """``POST /wg/peer`` generates its own keypair and there is no verb to
    register one, so a platform-generated key exists in exactly one place:
    this database. Writing it produces a tunnel that cannot establish, with
    no symptom but a handshake that never happens."""

    def _no_registration(self):  # noqa: ANN202 -- test helper
        return make_services(
            hub_capabilities=HubCapabilities(
                can_register_public_key=False, can_remove_peer=False
            )
        )

    async def test_create_tunnel_refuses_to_generate_a_keypair(self) -> None:
        f = self._no_registration()
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)

        with pytest.raises(HubCannotLearnPlatformKeyError):
            await f.wireguard_service.create_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                requesting_organization_id=None,
            )

    async def test_a_device_supplied_key_is_still_allowed(self) -> None:
        """The restriction is on keys the platform invents, not on the
        enrollment path that works -- a device-generated key reaches the hub
        by the device's own enrollment, not by this service pushing it."""
        f = self._no_registration()
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)

        info = await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
            external_public_key="ZGV2aWNlLWdlbmVyYXRlZC1wdWJsaWMta2V5",
        )

        assert info.peer.public_key == "ZGV2aWNlLWdlbmVyYXRlZC1wdWJsaWMta2V5"

    async def test_rotate_refuses(self) -> None:
        f = self._no_registration()
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.create_tunnel(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
            external_public_key="ZGV2aWNlLWdlbmVyYXRlZC1wdWJsaWMta2V5",
        )

        with pytest.raises(HubCannotLearnPlatformKeyError):
            await f.wireguard_service.rotate_tunnel(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                requesting_organization_id=None,
            )


class TestAutomaticAdoption:
    """The exact production state: the hub shows the device handshaking on
    a key the platform issued to that router and then overwrote."""

    async def _diverged(self, f, *, hub):  # noqa: ANN001, ANN202 -- test helper
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        f.wireguard_repo.router_names[router.id] = router.name
        # Issued .6, which the device imported and is using.
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.6",
            public_key="KEY-SIX",
        )
        # Then a second Generate allocated .8, which no device ever saw.
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.8",
            public_key="KEY-EIGHT",
        )
        hub.extend(
            [
                _hub_peer(
                    "KEY-SIX",
                    handshake_epoch=int(datetime.now(UTC).timestamp()),
                    tunnel_ip="10.20.0.6",
                ),
                _hub_peer("KEY-EIGHT", handshake_epoch=0, tunnel_ip="10.20.0.8"),
            ]
        )
        return router

    async def test_a_plain_read_reports_the_mismatch_and_changes_nothing(
        self,
    ) -> None:
        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_lister=_lister)
        router = await self._diverged(f, hub=hub)

        result = await f.wireguard_service.get_fleet_status()

        assert result.adopted_public_keys == []
        entry = next(e for e in result.peers if e.public_key == "KEY-SIX")
        assert entry.status == FleetPeerStatus.ADOPTABLE_MISMATCH
        # Attributed, not "untracked" -- this is the whole point of the
        # ledger. The old classifier called this UNTRACKED_CONNECTED.
        assert entry.router_id == router.id
        assert entry.router_name == router.name
        assert entry.explanation
        peer = await f.wireguard_repo.get_peer_by_router_id(router.id)
        assert peer.public_key == "KEY-EIGHT"

    async def test_adopt_records_what_the_device_demonstrably_is(self) -> None:
        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_lister=_lister)
        router = await self._diverged(f, hub=hub)

        result = await f.wireguard_service.get_fleet_status(adopt=True)

        assert result.adopted_public_keys == ["KEY-SIX"]
        peer = await f.wireguard_repo.get_peer_by_router_id(router.id)
        assert peer.public_key == "KEY-SIX"
        assert peer.tunnel_ip_address == "10.20.0.6"
        assert peer.status == PeerStatus.ACTIVE.value
        assert peer.last_handshake_at is not None
        # The platform never held this key -- the hub generated it and did
        # not keep it. Anything else here eventually gets rendered into a
        # device's `private-key=`.
        assert decrypt_secret(peer.private_key_encrypted) == (
            "external:device-managed-key"
        )

    async def test_adoption_notifies_the_radius_binding(self) -> None:
        """The WireGuard address and the FreeRADIUS client stanza keyed on
        it are two halves of one fact. An adoption that moved the address
        and left the stanza behind would fix the symptom the operator can
        see and leave the one that actually blocks guests."""
        hub: list[dict] = []
        moves: list[tuple[str, str]] = []

        async def _lister() -> list[dict]:
            return list(hub)

        async def _listener(
            *, router_id, previous_tunnel_ip_address, tunnel_ip_address
        ) -> None:
            moves.append((previous_tunnel_ip_address, tunnel_ip_address))

        f = make_services(hub_peer_lister=_lister, peer_address_listener=_listener)
        await self._diverged(f, hub=hub)

        await f.wireguard_service.get_fleet_status(adopt=True)

        assert moves == [("10.20.0.8", "10.20.0.6")]

    async def test_a_failing_radius_rebind_does_not_undo_the_adoption(
        self,
    ) -> None:
        """Converge, never roll back. The WireGuard record being correct is
        strictly better than it being wrong, and the leftover mismatch is
        exactly what the next reconciliation pass looks for."""
        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        async def _listener(**kwargs: object) -> None:
            raise RuntimeError("the RADIUS bridge is down")

        f = make_services(hub_peer_lister=_lister, peer_address_listener=_listener)
        router = await self._diverged(f, hub=hub)

        await f.wireguard_service.get_fleet_status(adopt=True)

        peer = await f.wireguard_repo.get_peer_by_router_id(router.id)
        assert peer.public_key == "KEY-SIX"

    async def test_two_live_identities_are_never_adopted_automatically(
        self,
    ) -> None:
        """A router whose recorded peer has ALSO handshaked is genuinely
        ambiguous -- a half-migrated device, or two routers behind one WAN.
        Picking one automatically moves the RADIUS binding, so getting it
        wrong takes a working venue down."""
        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_lister=_lister)
        router = await self._diverged(f, hub=hub)
        current = await f.wireguard_repo.get_peer_by_router_id(router.id)
        await f.wireguard_repo.update_peer(
            current, {"last_handshake_at": datetime.now(UTC)}
        )
        hub[1]["latest_handshake_epoch"] = int(datetime.now(UTC).timestamp())

        result = await f.wireguard_service.get_fleet_status(adopt=True)

        assert result.adopted_public_keys == []
        entry = next(e for e in result.peers if e.public_key == "KEY-SIX")
        assert entry.status == FleetPeerStatus.ADOPTABLE_MISMATCH
        assert "TWO live identities" in entry.explanation

    async def test_an_unattributable_key_stays_untracked(self) -> None:
        """No issuance record means no proof of whose device this is. This
        is the state of all seven peers on the production hub today, every
        one of them allocated before the ledger existed -- they need an
        operator's explicit adoption, not a background heuristic."""

        async def _lister() -> list[dict]:
            return [
                _hub_peer(
                    "KEY-FROM-BEFORE-THE-LEDGER",
                    handshake_epoch=int(datetime.now(UTC).timestamp()),
                    tunnel_ip="10.20.0.3",
                )
            ]

        f = make_services(hub_peer_lister=_lister)
        await make_hub(f)

        result = await f.wireguard_service.get_fleet_status(adopt=True)

        assert result.adopted_public_keys == []
        (entry,) = result.peers
        assert entry.status == FleetPeerStatus.UNTRACKED_CONNECTED
        assert entry.router_id is None
        assert "adopt" in entry.explanation


class TestOperatorConfirmedAdoption:
    """``adopt_hub_peer`` is the repair path for everything automatic
    adoption deliberately will not touch."""

    async def _router_and_hub(self, f, hub):  # noqa: ANN001, ANN202 -- helper
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.8",
            public_key="KEY-EIGHT",
        )
        hub.append(
            _hub_peer(
                "PRE-LEDGER-KEY",
                handshake_epoch=int(datetime.now(UTC).timestamp()),
                tunnel_ip="10.20.0.6",
            )
        )
        return router

    async def test_binds_the_router_to_what_the_hub_holds(self) -> None:
        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_lister=_lister)
        router = await self._router_and_hub(f, hub)

        peer = await f.wireguard_service.adopt_hub_peer(
            actor_user_id=uuid.uuid4(),
            router_id=router.id,
            requesting_organization_id=None,
            public_key="PRE-LEDGER-KEY",
            note="matched to the .rsc the technician actually imported",
        )

        assert peer.public_key == "PRE-LEDGER-KEY"
        # The ADDRESS comes from the hub's allowed-ips, never from the
        # caller: the hub's routing table is what decides where packets for
        # this peer actually go.
        assert peer.tunnel_ip_address == "10.20.0.6"
        ledger = await f.wireguard_repo.get_issuance_by_public_key("PRE-LEDGER-KEY")
        assert ledger.source == PeerIdentitySource.ADOPTED.value
        assert ledger.note == "matched to the .rsc the technician actually imported"

    async def test_refuses_a_key_the_hub_does_not_hold(self) -> None:
        """Adoption's justification is that it writes down something
        observed. A key `GET /wg/peers` has never seen is not an
        observation, and adopting it would be a differently-wrong row."""
        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_lister=_lister)
        router = await self._router_and_hub(f, hub)

        with pytest.raises(HubPeerNotOnHubError):
            await f.wireguard_service.adopt_hub_peer(
                actor_user_id=uuid.uuid4(),
                router_id=router.id,
                requesting_organization_id=None,
                public_key="A-KEY-NOBODY-HAS",
            )

    async def test_refuses_a_key_another_router_already_records(self) -> None:
        """Two routers on one WireGuard identity means the hub silently
        delivers one's traffic to the other -- it routes by allowed-ips and
        has no idea two rows disagree."""
        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_lister=_lister)
        first = await self._router_and_hub(f, hub)
        org = f.org_lookup.add()
        second = await make_router(f, org)
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=second.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.9",
            public_key="SECOND-ROUTERS-KEY",
        )
        hub.append(
            _hub_peer(
                "SECOND-ROUTERS-KEY",
                handshake_epoch=int(datetime.now(UTC).timestamp()),
                tunnel_ip="10.20.0.9",
            )
        )

        with pytest.raises(HubPeerClaimedByAnotherRouterError):
            await f.wireguard_service.adopt_hub_peer(
                actor_user_id=uuid.uuid4(),
                router_id=first.id,
                requesting_organization_id=None,
                public_key="SECOND-ROUTERS-KEY",
            )


class TestAddressMismatchIsItsOwnFinding:
    """Same key on both sides, different tunnel address. Reported
    separately because the RADIUS client stanza is keyed on the address, so
    this specific disagreement drops every guest login on that router --
    silently, with no reply and nothing logged."""

    async def test_reported_as_key_mismatch_not_as_connected(self) -> None:
        async def _lister() -> list[dict]:
            return [
                _hub_peer(
                    "KEY-SIX",
                    handshake_epoch=int(datetime.now(UTC).timestamp()),
                    tunnel_ip="10.20.0.6",
                )
            ]

        f = make_services(hub_peer_lister=_lister)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.8",
            public_key="KEY-SIX",
        )

        result = await f.wireguard_service.get_fleet_status()

        (entry,) = result.peers
        assert entry.status == FleetPeerStatus.TRACKED_KEY_MISMATCH
        # Both addresses reported. The two disagreeing IS the finding, and
        # a view showing only one of them hides it completely.
        assert entry.tunnel_ip_address == "10.20.0.8"
        assert entry.hub_tunnel_ip_address == "10.20.0.6"


class TestLiveIdentityGuard:
    """``resolve_live_identity_for_router`` is what stops a Generate click
    from allocating over a device that is working.

    The peer-reuse fix shipped 2026-08-27 did not stop it, because it is
    gated on ``rotate`` and the Master console sends ``?rotate=true`` on
    every Generate -- measured: four allocate-external calls for router
    21e13913 in 24h, all four ``?rotate=true``, the last at 18:32 (AFTER
    the fix deployed) allocating 10.20.0.9 while the device sat handshaking
    on 10.20.0.6. The reuse branch was never entered once. A guard the
    caller can switch off is not a guard.
    """

    async def _diverged_router(self, f, hub):  # noqa: ANN001, ANN202 -- helper
        """The production shape: issued .6 (which the device imported and
        is using), then superseded it with .8 (which no device ever saw)."""
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.6",
            public_key="KEY-SIX",
        )
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.8",
            public_key="KEY-EIGHT",
        )
        hub.extend(
            [
                _hub_peer(
                    "KEY-SIX",
                    handshake_epoch=int(datetime.now(UTC).timestamp()),
                    tunnel_ip="10.20.0.6",
                ),
                _hub_peer("KEY-EIGHT", handshake_epoch=0, tunnel_ip="10.20.0.8"),
            ]
        )
        return router

    async def test_finds_the_device_through_the_ledger_not_the_peer_row(
        self,
    ) -> None:
        """Asking only "is the RECORDED key live?" answers no here -- .8 has
        never handshaked -- and concludes the router needs a fresh
        allocation, which is exactly the action that made things worse four
        times. The ledger is what turns that no into the right answer."""
        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_lister=_lister)
        router = await self._diverged_router(f, hub)

        live = await f.wireguard_service.resolve_live_identity_for_router(
            router_id=router.id
        )

        assert live is not None
        assert live["public_key"] == "KEY-SIX"
        assert live["allowed_ips"] == "10.20.0.6/32"

    async def test_a_router_that_has_never_connected_has_no_live_identity(
        self,
    ) -> None:
        """The genuine "the device lost its config" case still allocates --
        the guard only refuses what it can prove is working."""
        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_lister=_lister)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.20.0.8",
            public_key="KEY-EIGHT",
        )
        hub.append(_hub_peer("KEY-EIGHT", handshake_epoch=0, tunnel_ip="10.20.0.8"))

        assert (
            await f.wireguard_service.resolve_live_identity_for_router(
                router_id=router.id
            )
            is None
        )

    async def test_a_stale_handshake_is_not_a_live_identity(self) -> None:
        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_lister=_lister, handshake_stale_after_minutes=5)
        router = await self._diverged_router(f, hub)
        hub[0]["latest_handshake_epoch"] = int(
            (datetime.now(UTC) - timedelta(hours=3)).timestamp()
        )

        assert (
            await f.wireguard_service.resolve_live_identity_for_router(
                router_id=router.id
            )
            is None
        )

    async def test_an_unreachable_hub_reports_no_live_identity(self) -> None:
        """"Cannot confirm" must not read as "confirmed connected" either --
        this returns None, and the CALLER's fallback (the pre-existing
        reuse branch) is what keeps a bridge blip from costing a peer."""
        f = make_services(hub_peer_lister=None)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)

        assert (
            await f.wireguard_service.resolve_live_identity_for_router(
                router_id=router.id
            )
            is None
        )


class TestHubBridgeUnavailableIsA502:
    """A hub bridge that is down is an UPSTREAM failure, not this
    platform's own.

    ``HubBridgeUnavailableError`` declared ``status_code = 502`` as a class
    attribute -- which ``CloudGuestError.__init__`` then overwrote on every
    instance with its own default of 500. So for its entire life it was
    raised as a 502 in intent and served as a 500 "Internal server error" in
    fact. That distinction is the whole difference between "retry, the hub
    is unreachable" and "this platform is broken", and the console has no
    other way to tell them apart: the shared handler in
    ``app.common.exceptions`` serialises ``message`` and ``data`` only, so
    the status IS the classification.
    """

    def test_the_instance_carries_502_not_the_base_class_default(self) -> None:
        from app.domains.wireguard.dependencies import HubBridgeUnavailableError

        exc = HubBridgeUnavailableError("Could not reach the WireGuard hub bridge")

        assert exc.status_code == 502
        assert exc.message == "Could not reach the WireGuard hub bridge"

    def test_it_is_not_a_wireguard_error_and_that_is_load_bearing(self) -> None:
        """Pinned deliberately. ``except WireGuardError`` does NOT catch this
        -- ``hub_reconciliation.tasks`` claimed in a comment that it did and
        was wrong for as long as that comment existed. Anyone changing this
        hierarchy has to come through here and read that."""
        from app.common.exceptions import CloudGuestError
        from app.domains.wireguard.dependencies import HubBridgeUnavailableError
        from app.domains.wireguard.exceptions import WireGuardError

        assert issubclass(HubBridgeUnavailableError, CloudGuestError)
        assert not issubclass(HubBridgeUnavailableError, WireGuardError)


# ============================================================================
# The hub bridge is the only path to a usable tunnel
# ============================================================================


def _agent_allocation(
    *,
    public_key: str = "HUB-MINTED-KEY",
    tunnel_ip: str = "10.100.0.7",
    cidr: str = "10.100.0.0/16",
) -> dict:
    """The exact JSON ``ops/hub-agents/wg_agent.py``'s ``POST /wg/peer``
    returns -- it runs ``wg genkey`` itself and hands back BOTH halves,
    which is the whole reason this path produces a key the hub actually
    holds and ``create_tunnel``'s does not."""
    return {
        "router_public_key": public_key,
        "router_private_key": "HUB-MINTED-PRIVATE-KEY",
        "router_tunnel_ip": tunnel_ip,
        "server_public_key": "HUB-SERVER-KEY",
        "server_endpoint_host": "hub.cloudguest.example",
        "server_endpoint_port": 51820,
        "tunnel_subnet": cidr,
    }


class TestAllocateTunnelViaHub:
    """``allocate_tunnel_via_hub`` is the orchestration that used to live
    inline in ``router.allocate_external_wireguard_peer``.

    It moved onto the service on 2026-09-01 because it was never
    endpoint-specific: ``LocationProvisioningService.provision_location``
    needs the identical sequence, and while it lived in a route handler the
    only thing provisioning could reach was ``create_tunnel`` -- whose
    platform-generated public key the hub has no verb to learn, so every
    attempt to add a customer died on ``HubCannotLearnPlatformKeyError``.
    """

    async def test_allocates_through_the_bridge_and_records_the_hub_key(
        self,
    ) -> None:
        calls: list[int] = []

        async def _allocator() -> dict:
            calls.append(1)
            return _agent_allocation()

        f = make_services(hub_peer_allocator=_allocator)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)

        allocation = await f.wireguard_service.allocate_tunnel_via_hub(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
        )

        assert calls == [1]
        assert allocation.reused is False
        assert allocation.adopted is False
        # The recorded identity is the HUB's, not one generated here.
        assert allocation.peer.public_key == "HUB-MINTED-KEY"
        assert allocation.peer.tunnel_ip_address == "10.100.0.7"
        assert allocation.peer_private_key == "HUB-MINTED-PRIVATE-KEY"
        assert allocation.hub_public_key == "HUB-SERVER-KEY"
        assert allocation.hub_tunnel_ip_address == "10.100.0.1"

    async def test_never_generates_a_keypair_the_hub_cannot_learn(self) -> None:
        """The contrast that is the whole bug. On the same fixture, with a
        hub that has no key-registration verb (production's real
        capability set), ``create_tunnel`` refuses -- and
        ``allocate_tunnel_via_hub`` succeeds."""

        async def _allocator() -> dict:
            return _agent_allocation()

        f = make_services(
            hub_peer_allocator=_allocator,
            hub_capabilities=HubCapabilities(can_register_public_key=False),
        )
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)

        with pytest.raises(HubCannotLearnPlatformKeyError):
            await f.wireguard_service.create_tunnel(
                actor_user_id=None,
                router_id=router.id,
                requesting_organization_id=None,
            )

        allocation = await f.wireguard_service.allocate_tunnel_via_hub(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
        )
        assert allocation.peer.public_key == "HUB-MINTED-KEY"

    async def test_reuses_an_existing_peer_instead_of_leaking_another(self) -> None:
        """Every allocation is permanent -- the deployed agent has no
        ``do_DELETE`` -- so a second call for a router that already has a
        usable peer must not reach the bridge at all."""
        calls: list[int] = []

        async def _allocator() -> dict:
            calls.append(1)
            return _agent_allocation()

        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_allocator=_allocator, hub_peer_lister=_lister)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)

        first = await f.wireguard_service.allocate_tunnel_via_hub(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
        )
        hub.append(
            _hub_peer("HUB-MINTED-KEY", handshake_epoch=0, tunnel_ip="10.100.0.7")
        )

        second = await f.wireguard_service.allocate_tunnel_via_hub(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
        )

        assert calls == [1]
        assert second.reused is True
        # The platform never held this key's private half -- it was
        # generated on the hub -- so it is not invented on the reuse path.
        assert second.peer_private_key is None
        assert second.peer.public_key == first.peer.public_key

    async def test_a_live_device_is_never_allocated_over_even_with_rotate(
        self,
    ) -> None:
        """``rotate=true`` is what the Master console sent on every
        Generate, four times in 24h, while the device sat handshaking. The
        guard cannot live behind a flag the caller controls."""
        calls: list[int] = []

        async def _allocator() -> dict:
            calls.append(1)
            return _agent_allocation()

        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_allocator=_allocator, hub_peer_lister=_lister)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.100.0.6",
            public_key="KEY-SIX",
        )
        hub.append(
            _hub_peer(
                "KEY-SIX",
                handshake_epoch=int(datetime.now(UTC).timestamp()),
                tunnel_ip="10.100.0.6",
            )
        )

        allocation = await f.wireguard_service.allocate_tunnel_via_hub(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            rotate=True,
        )

        assert calls == []
        assert allocation.reused is True
        assert allocation.peer.tunnel_ip_address == "10.100.0.6"

    async def test_a_diverged_router_is_adopted_not_reallocated(self) -> None:
        """The production shape: issued .6 (which the device imported and
        is using), then superseded it with .8 (which no device ever saw).
        Clicking Generate must repair the divergence, not deepen it."""
        calls: list[int] = []

        async def _allocator() -> dict:
            calls.append(1)
            return _agent_allocation()

        hub: list[dict] = []

        async def _lister() -> list[dict]:
            return list(hub)

        f = make_services(hub_peer_allocator=_allocator, hub_peer_lister=_lister)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.100.0.6",
            public_key="KEY-SIX",
        )
        await f.wireguard_service.register_agent_allocated_peer(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            tunnel_ip_address="10.100.0.8",
            public_key="KEY-EIGHT",
        )
        hub.extend(
            [
                _hub_peer(
                    "KEY-SIX",
                    handshake_epoch=int(datetime.now(UTC).timestamp()),
                    tunnel_ip="10.100.0.6",
                ),
                _hub_peer("KEY-EIGHT", handshake_epoch=0, tunnel_ip="10.100.0.8"),
            ]
        )

        allocation = await f.wireguard_service.allocate_tunnel_via_hub(
            actor_user_id=None,
            router_id=router.id,
            requesting_organization_id=None,
            rotate=True,
        )

        assert calls == []
        assert allocation.adopted is True
        assert allocation.peer.public_key == "KEY-SIX"
        assert allocation.peer.tunnel_ip_address == "10.100.0.6"

    async def test_an_ineligible_router_is_refused_before_the_hub_is_touched(
        self,
    ) -> None:
        """Validation runs BEFORE the irreversible call. A decommissioned
        router that got as far as the bridge would leak a peer that no
        router will ever use and no verb can remove."""
        calls: list[int] = []

        async def _allocator() -> dict:
            calls.append(1)
            return _agent_allocation()

        f = make_services(hub_peer_allocator=_allocator)
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org, status=RouterStatus.DECOMMISSIONED)

        with pytest.raises(WireGuardRouterNotEligibleError):
            await f.wireguard_service.allocate_tunnel_via_hub(
                actor_user_id=None,
                router_id=router.id,
                requesting_organization_id=None,
            )

        assert calls == []

    async def test_no_allocator_configured_fails_loudly(self) -> None:
        """It must NOT degrade to ``create_tunnel``: the only local
        fallback available is the platform-generated keypair that cannot
        work."""
        from app.domains.wireguard.exceptions import (
            HubPeerAllocatorNotConfiguredError,
        )

        f = make_services()
        await make_hub(f)
        org = f.org_lookup.add()
        router = await make_router(f, org)

        with pytest.raises(HubPeerAllocatorNotConfiguredError) as excinfo:
            await f.wireguard_service.allocate_tunnel_via_hub(
                actor_user_id=None,
                router_id=router.id,
                requesting_organization_id=None,
            )
        assert excinfo.value.status_code == 503

    async def test_tenant_scope_is_enforced_on_the_router_lookup(self) -> None:
        """RBAC/tenant scoping is unchanged by the move: the router lookup
        still carries ``requesting_organization_id``, so a caller scoped to
        another organization cannot allocate against this router."""
        from app.domains.router.exceptions import (
            CrossOrganizationRouterAccessError,
        )

        calls: list[int] = []

        async def _allocator() -> dict:
            calls.append(1)
            return _agent_allocation()

        f = make_services(hub_peer_allocator=_allocator)
        await make_hub(f)
        org = f.org_lookup.add()
        other_org = f.org_lookup.add()
        router = await make_router(f, org)

        with pytest.raises(CrossOrganizationRouterAccessError):
            await f.wireguard_service.allocate_tunnel_via_hub(
                actor_user_id=None,
                router_id=router.id,
                requesting_organization_id=other_org.id,
            )

        assert calls == []
