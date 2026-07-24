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
from app.domains.wireguard.constants import HealthStatus, PeerStatus
from app.domains.wireguard.exceptions import (
    InvalidPeerStatusTransitionError,
    NoActiveWireGuardServerError,
    TunnelIPAllocationConflictError,
    TunnelIPPoolExhaustedError,
    WireGuardPeerAlreadyExistsError,
    WireGuardPeerNotFoundError,
    WireGuardPeerRevokedError,
    WireGuardRouterNotEligibleError,
)
from app.domains.wireguard.models import WireGuardPeer, WireGuardServer
from app.domains.wireguard.service import WireGuardService, generate_wireguard_keypair
from app.domains.wireguard.validators import allocate_tunnel_ip, validate_cidr

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

    async def test_check_in_without_public_key_creates_no_peer(self) -> None:
        """A device presenting only ``token`` (no ``wireguard_public_key``)
        gets exactly today's pre-existing behavior -- no ``WireGuardPeer``
        is created at check-in."""
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

        # No create_tunnel call at all -- mirrors provisioning_check_in's
        # own ``if payload.wireguard_public_key:`` gate.
        peer = await fx.wireguard_repo.get_peer_by_router_id(checked_in.id)
        assert peer is None


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
