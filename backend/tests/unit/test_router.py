"""Unit tests for the Router domain: device CRUD, serial/MAC uniqueness,
location-must-exist-and-not-be-archived validation, status-transition graph
(legal and illegal transitions), zero-touch provisioning (token generation,
single-use consumption, expiry), credential encryption round-trip, tenant
scoping (platform vs. org-scoped vs. MSP-child access), and the RBAC
``router_id`` FK follow-up (confirmed via the RBAC test suite itself still
passing, plus a direct check here that the FK/column wiring is sane).

Follows this project's plain-``assert`` / native-``async def`` style (see
``tests/unit/test_location.py``); ``asyncio_mode = "auto"`` runs async tests
directly. Exercises ``RouterService`` against small in-memory fake
repository/location-lookup/organization-lookup/audit-writer, mirroring
``FakeLocationRepository``/``FakeOrganizationLookup``, since there is no
live Postgres/Redis in this environment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.location.exceptions import (
    CrossOrganizationLocationAccessError,
    LocationArchivedError,
    LocationNotFoundError,
)
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationType
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization
from app.domains.router.crypto import decrypt_secret, encrypt_secret
from app.domains.router.enums import RouterStatus
from app.domains.router.exceptions import (
    CrossOrganizationRouterAccessError,
    DuplicateMacAddressError,
    DuplicateSerialNumberError,
    InvalidRouterStatusTransitionError,
    ProvisioningTokenAlreadyUsedError,
    ProvisioningTokenExpiredError,
    ProvisioningTokenGenerationNotAllowedError,
    ProvisioningTokenNotFoundError,
    ProvisioningTokenRouterStateError,
    RouterDecommissionedError,
    RouterNotFoundError,
)
from app.domains.router.models import Router, RouterProvisioningToken
from app.domains.router.service import RouterService

# ============================================================================
# Test doubles
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
    """In-memory stand-in for ``RouterService``'s ``OrganizationLookupProtocol``."""

    organizations: dict[uuid.UUID, Organization] = field(default_factory=dict)

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization:
        organization = self.organizations.get(organization_id)
        if organization is None or (organization.is_deleted and not include_deleted):
            raise OrganizationNotFoundError(organization_id)
        return organization

    def add(
        self,
        *,
        org_type: str = OrganizationType.STANDARD.value,
        parent_organization_id: uuid.UUID | None = None,
    ) -> Organization:
        organization = Organization(
            **_base_fields(
                name="Org",
                slug=f"org-{uuid.uuid4()}",
                legal_name=None,
                org_type=org_type,
                status="active",
                parent_organization_id=parent_organization_id,
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
    """In-memory stand-in for ``RouterService``'s ``LocationLookupProtocol``,
    deliberately independent of the real ``LocationService`` (mirrors
    ``test_location.py``'s own ``FakeOrganizationLookup`` posture) while
    reproducing the same "self org, or MSP-child org" access rule so
    tenant-scoping tests exercise the real contract."""

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

    def add(self, *, organization_id: uuid.UUID, status: str = "active") -> Location:
        location = Location(
            **_base_fields(
                organization_id=organization_id,
                name="HQ",
                slug=f"hq-{uuid.uuid4()}",
                status=status,
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
    """In-memory stand-in for :class:`RouterRepositoryProtocol`."""

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
            (
                r
                for r in self.routers.values()
                if r.serial_number == serial_number and not r.is_deleted
            ),
            None,
        )

    async def get_by_mac_address(self, mac_address: str) -> Router | None:
        return next(
            (
                r
                for r in self.routers.values()
                if r.mac_address == mac_address and not r.is_deleted
            ),
            None,
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

    async def list_routers(
        self,
        *,
        location_id: uuid.UUID,
        page: int,
        page_size: int,
        search: str | None = None,
        status: str | None = None,
    ) -> tuple[list[Router], PaginationMeta]:
        values = [
            r
            for r in self.routers.values()
            if r.location_id == location_id and not r.is_deleted
        ]
        if status is not None:
            values = [r for r in values if r.status == status]
        if search:
            lowered = search.lower()
            values = [
                r
                for r in values
                if lowered in r.name.lower() or lowered in r.serial_number.lower()
            ]
        values.sort(key=lambda r: r.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def create_provisioning_token(
        self, **fields: object
    ) -> RouterProvisioningToken:
        token = RouterProvisioningToken(**_base_fields(**fields))
        self.tokens[token.id] = token
        return token

    async def get_provisioning_token_by_hash(
        self, token_hash: str
    ) -> RouterProvisioningToken | None:
        return next(
            (t for t in self.tokens.values() if t.token_hash == token_hash), None
        )

    async def mark_provisioning_token_used(
        self, token: RouterProvisioningToken, *, used_at: object
    ) -> RouterProvisioningToken:
        token.used_at = used_at
        return token

    async def list_expired_unused_provisioning_tokens(
        self, *, now: object
    ) -> list[RouterProvisioningToken]:
        return [
            t
            for t in self.tokens.values()
            if not t.is_deleted and t.used_at is None and t.expires_at < now
        ]

    async def soft_delete_provisioning_token(
        self, token: RouterProvisioningToken
    ) -> RouterProvisioningToken:
        token.is_deleted = True
        token.deleted_at = _now()
        return token


def make_service(
    repo: FakeRouterRepository | None = None,
    location_lookup: FakeLocationLookup | None = None,
    org_lookup: FakeOrganizationLookup | None = None,
) -> tuple[
    RouterService,
    FakeRouterRepository,
    FakeLocationLookup,
    FakeOrganizationLookup,
    FakeAuditLogWriter,
]:
    repository = repo or FakeRouterRepository()
    organization_lookup = org_lookup or FakeOrganizationLookup()
    location_lookup = location_lookup or FakeLocationLookup(
        organization_lookup=organization_lookup
    )
    audit_writer = FakeAuditLogWriter()
    service = RouterService(
        repository,
        location_lookup,
        organization_lookup,
        audit_writer=audit_writer,
        provisioning_token_ttl_hours=24,
    )
    return service, repository, location_lookup, organization_lookup, audit_writer


def _create_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "name": "Front Desk AP",
        "serial_number": "HB31090ABCD",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "model": "hAP ac2",
    }
    base.update(overrides)
    return base


def _unique_mac() -> str:
    hex_digits = uuid.uuid4().hex[:12]
    return ":".join(hex_digits[i : i + 2] for i in range(0, 12, 2)).upper()


async def make_router(
    repo: FakeRouterRepository,
    *,
    location_id: uuid.UUID,
    organization_id: uuid.UUID,
    status: RouterStatus = RouterStatus.PENDING_PROVISIONING,
    serial_number: str | None = None,
    mac_address: str | None = None,
) -> Router:
    return await repo.create_router(
        location_id=location_id,
        organization_id=organization_id,
        name="Front Desk AP",
        serial_number=serial_number or f"SN-{uuid.uuid4()}",
        mac_address=mac_address or "AA:BB:CC:DD:EE:FF",
        model="hAP ac2",
        status=status.value,
    )


# ============================================================================
# Router CRUD
# ============================================================================


class TestRouterCRUD:
    async def test_create_router_success(self) -> None:
        service, _repo, location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)

        router_device = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )

        assert router_device.name == "Front Desk AP"
        assert router_device.status == RouterStatus.PENDING_PROVISIONING.value
        assert router_device.location_id == location.id
        assert router_device.organization_id == organization.id
        assert router_device.mac_address == "AA:BB:CC:DD:EE:FF"
        assert any(e["action"] == "router_created" for e in audit.entries)

    async def test_create_router_defaults_to_mikrotik_vendor(self) -> None:
        """Provisioning Engine extension -- see
        docs/router_provisioning/PROVISIONING_ENGINE.md."""
        service, _repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)

        router_device = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )
        assert router_device.vendor == "mikrotik"

    async def test_create_router_honors_explicit_vendor(self) -> None:
        service, _repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)

        router_device = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(vendor="opnsense"),
        )
        assert router_device.vendor == "opnsense"

    async def test_create_router_normalizes_mac_address(self) -> None:
        service, _repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)

        router_device = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(mac_address="aa:bb:cc:dd:ee:ff"),
        )

        assert router_device.mac_address == "AA:BB:CC:DD:EE:FF"

    async def test_create_router_rejects_duplicate_serial_number(self) -> None:
        service, _repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )

        with pytest.raises(DuplicateSerialNumberError):
            await service.create_router(
                actor_user_id=uuid.uuid4(),
                location_id=location.id,
                requesting_organization_id=None,
                **_create_kwargs(mac_address="11:22:33:44:55:66"),
            )

    async def test_create_router_rejects_duplicate_mac_address(self) -> None:
        service, _repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )

        with pytest.raises(DuplicateMacAddressError):
            await service.create_router(
                actor_user_id=uuid.uuid4(),
                location_id=location.id,
                requesting_organization_id=None,
                **_create_kwargs(serial_number="OTHER-SERIAL"),
            )

    async def test_create_router_under_nonexistent_location_raises(self) -> None:
        service, _repo, _location_lookup, _org_lookup, _audit = make_service()

        with pytest.raises(LocationNotFoundError):
            await service.create_router(
                actor_user_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                requesting_organization_id=None,
                **_create_kwargs(),
            )

    async def test_create_router_under_archived_location_raises(self) -> None:
        service, _repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(
            organization_id=organization.id, status="archived"
        )

        with pytest.raises(LocationArchivedError):
            await service.create_router(
                actor_user_id=uuid.uuid4(),
                location_id=location.id,
                requesting_organization_id=None,
                **_create_kwargs(),
            )

    async def test_get_router_not_found_raises(self) -> None:
        service, _repo, _location_lookup, _org_lookup, _audit = make_service()
        with pytest.raises(RouterNotFoundError):
            await service.get_router(uuid.uuid4())

    async def test_update_router_renames_and_audits(self) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo, location_id=uuid.uuid4(), organization_id=organization.id
        )

        updated = await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"name": "Renamed AP"},
        )

        assert updated.name == "Renamed AP"
        assert any(e["action"] == "router_updated" for e in audit.entries)

    async def test_update_router_ignores_location_and_organization_id(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        other_location_id = uuid.uuid4()
        router_device = await make_router(
            repo, location_id=uuid.uuid4(), organization_id=organization.id
        )
        original_location_id = router_device.location_id

        updated = await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"location_id": other_location_id, "name": "Still Same Location"},
        )

        assert updated.location_id == original_location_id
        assert updated.name == "Still Same Location"

    async def test_update_decommissioned_router_raises(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.DECOMMISSIONED,
        )

        with pytest.raises(RouterDecommissionedError):
            await service.update_router(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
                data={"name": "New Name"},
            )

    async def test_decommission_router_soft_deletes_and_sets_status(self) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.OFFLINE,
        )

        decommissioned = await service.decommission_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        assert decommissioned.status == RouterStatus.DECOMMISSIONED.value
        assert decommissioned.is_deleted is True
        assert any(e["action"] == "router_decommissioned" for e in audit.entries)

    async def test_list_routers_within_location(self) -> None:
        service, repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location_a = location_lookup.add(organization_id=organization.id)
        location_b = location_lookup.add(organization_id=organization.id)
        await make_router(
            repo, location_id=location_a.id, organization_id=organization.id
        )
        await make_router(
            repo, location_id=location_a.id, organization_id=organization.id
        )
        await make_router(
            repo, location_id=location_b.id, organization_id=organization.id
        )

        routers, meta = await service.list_routers(
            location_id=location_a.id, requesting_organization_id=None
        )

        assert meta.total_items == 2
        assert all(r.location_id == location_a.id for r in routers)


# ============================================================================
# Status transition graph (legal and illegal)
# ============================================================================


class TestRouterStatusTransitions:
    async def test_suspend_from_online_and_offline_succeeds(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        for start_status in (RouterStatus.ONLINE, RouterStatus.OFFLINE):
            router_device = await make_router(
                repo,
                location_id=uuid.uuid4(),
                organization_id=organization.id,
                status=start_status,
            )
            suspended = await service.suspend_router(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )
            assert suspended.status == RouterStatus.SUSPENDED.value

    async def test_suspend_from_pending_provisioning_raises(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.PENDING_PROVISIONING,
        )

        with pytest.raises(InvalidRouterStatusTransitionError):
            await service.suspend_router(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )

    async def test_reinstate_suspended_router_lands_on_offline(self) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.SUSPENDED,
        )

        reinstated = await service.reinstate_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        assert reinstated.status == RouterStatus.OFFLINE.value
        assert any(e["action"] == "router_reinstated" for e in audit.entries)

    async def test_decommission_from_pending_provisioning_succeeds(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.PENDING_PROVISIONING,
        )

        decommissioned = await service.decommission_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        assert decommissioned.status == RouterStatus.DECOMMISSIONED.value

    async def test_decommission_from_decommissioned_raises(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.DECOMMISSIONED,
        )

        with pytest.raises(InvalidRouterStatusTransitionError):
            await service.decommission_router(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )

    async def test_heartbeat_completes_provisioning(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.PROVISIONING,
        )

        updated = await service.heartbeat(router_id=router_device.id)

        assert updated.status == RouterStatus.ONLINE.value
        assert updated.last_seen_at is not None
        assert updated.health_status == "healthy"

    async def test_heartbeat_resumes_offline_router(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.OFFLINE,
        )

        updated = await service.heartbeat(router_id=router_device.id)

        assert updated.status == RouterStatus.ONLINE.value

    async def test_heartbeat_while_pending_provisioning_raises(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.PENDING_PROVISIONING,
        )

        with pytest.raises(InvalidRouterStatusTransitionError):
            await service.heartbeat(router_id=router_device.id)

    async def test_heartbeat_while_suspended_raises(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.SUSPENDED,
        )

        with pytest.raises(InvalidRouterStatusTransitionError):
            await service.heartbeat(router_id=router_device.id)


# ============================================================================
# Zero-touch provisioning
# ============================================================================


class TestRouterProvisioning:
    async def test_generate_token_and_check_in_transitions_to_provisioning(
        self,
    ) -> None:
        service, repo, location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        router_device = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )

        token, plaintext = await service.generate_provisioning_token(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        assert token.used_at is None
        assert len(plaintext) > 20
        assert any(
            e["action"] == "router_provisioning_token_generated" for e in audit.entries
        )

        checked_in = await service.check_in(plaintext_token=plaintext)

        assert checked_in.status == RouterStatus.PROVISIONING.value
        assert checked_in.last_seen_at is not None
        assert any(e["action"] == "router_provisioned" for e in audit.entries)

    async def test_check_in_token_is_single_use(self) -> None:
        service, repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        router_device = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )
        _token, plaintext = await service.generate_provisioning_token(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        await service.check_in(plaintext_token=plaintext)

        with pytest.raises(ProvisioningTokenAlreadyUsedError):
            await service.check_in(plaintext_token=plaintext)

    async def test_check_in_rejects_unknown_token(self) -> None:
        service, _repo, _location_lookup, _org_lookup, _audit = make_service()

        with pytest.raises(ProvisioningTokenNotFoundError):
            await service.check_in(plaintext_token="not-a-real-token")

    async def test_check_in_rejects_expired_token(self) -> None:
        service, repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        router_device = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )
        _token, plaintext = await service.generate_provisioning_token(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        # Force expiry directly on the fake-repository-stored token.
        stored = next(iter(repo.tokens.values()))
        stored.expires_at = _now() - timedelta(hours=1)

        with pytest.raises(ProvisioningTokenExpiredError):
            await service.check_in(plaintext_token=plaintext)

    async def test_check_in_rejects_router_not_pending(self) -> None:
        service, repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        router_device = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )
        _token, plaintext = await service.generate_provisioning_token(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        # Router moves on (e.g. admin decommissions) before the device ever
        # presents the token.
        await service.decommission_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )

        with pytest.raises(ProvisioningTokenRouterStateError):
            await service.check_in(plaintext_token=plaintext)

    async def test_generate_token_rejected_outside_pending_provisioning(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.ONLINE,
        )

        with pytest.raises(ProvisioningTokenGenerationNotAllowedError):
            await service.generate_provisioning_token(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )


# ============================================================================
# Enrollment token expiry cleanup sweep
# ============================================================================


class TestProvisioningTokenCleanupSweep:
    async def test_soft_deletes_only_expired_unused_tokens(self) -> None:
        service, repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)

        async def _new_token() -> RouterProvisioningToken:
            router_device = await service.create_router(
                actor_user_id=uuid.uuid4(),
                location_id=location.id,
                requesting_organization_id=None,
                **_create_kwargs(
                    serial_number=f"SN-{uuid.uuid4()}",
                    mac_address=_unique_mac(),
                ),
            )
            token, _plaintext = await service.generate_provisioning_token(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )
            return token

        expired_unused = await _new_token()
        expired_unused.expires_at = _now() - timedelta(hours=1)

        expired_but_used = await _new_token()
        expired_but_used.expires_at = _now() - timedelta(hours=1)
        expired_but_used.used_at = _now()

        still_valid = await _new_token()

        cleaned = await service.sweep_expired_provisioning_tokens()

        assert cleaned == 1
        assert repo.tokens[expired_unused.id].is_deleted is True
        assert repo.tokens[expired_but_used.id].is_deleted is False
        assert repo.tokens[still_valid.id].is_deleted is False

    async def test_returns_zero_when_nothing_expired(self) -> None:
        service, _repo, _location_lookup, _org_lookup, _audit = make_service()

        cleaned = await service.sweep_expired_provisioning_tokens()

        assert cleaned == 0

    async def test_one_token_failing_to_soft_delete_never_aborts_the_sweep(
        self,
    ) -> None:
        service, repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)

        async def _new_expired_token() -> RouterProvisioningToken:
            router_device = await service.create_router(
                actor_user_id=uuid.uuid4(),
                location_id=location.id,
                requesting_organization_id=None,
                **_create_kwargs(
                    serial_number=f"SN-{uuid.uuid4()}",
                    mac_address=_unique_mac(),
                ),
            )
            token, _plaintext = await service.generate_provisioning_token(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )
            token.expires_at = _now() - timedelta(hours=1)
            return token

        bad_token = await _new_expired_token()
        good_token = await _new_expired_token()

        original_soft_delete = repo.soft_delete_provisioning_token

        async def flaky_soft_delete(token: RouterProvisioningToken):
            if token.id == bad_token.id:
                raise RuntimeError("transient db error")
            return await original_soft_delete(token)

        repo.soft_delete_provisioning_token = flaky_soft_delete  # type: ignore[method-assign]

        cleaned = await service.sweep_expired_provisioning_tokens()

        assert cleaned == 1
        assert repo.tokens[good_token.id].is_deleted is True
        assert repo.tokens[bad_token.id].is_deleted is False


# ============================================================================
# Credential encryption
# ============================================================================


class TestRouterCredentialEncryption:
    def test_encrypt_then_decrypt_round_trips(self) -> None:
        plaintext = "S3cretRouterOSPassw0rd!"
        ciphertext = encrypt_secret(plaintext)

        assert ciphertext != plaintext
        assert decrypt_secret(ciphertext) == plaintext

    async def test_create_router_stores_only_ciphertext(self) -> None:
        service, repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)

        router_device = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            api_username="admin",
            api_secret="TopSecret123!",
            **_create_kwargs(),
        )

        assert router_device.api_credentials_encrypted != "TopSecret123!"
        assert service.get_decrypted_api_secret(router_device) == "TopSecret123!"

    async def test_get_decrypted_api_secret_none_when_unset(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo, location_id=uuid.uuid4(), organization_id=organization.id
        )

        assert service.get_decrypted_api_secret(router_device) is None


# ============================================================================
# Tenant scoping (list/read/write access)
# ============================================================================


class TestRouterTenantScoping:
    async def test_platform_scope_can_access_any_router(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        router_device = await make_router(
            repo, location_id=uuid.uuid4(), organization_id=organization.id
        )

        fetched = await service.get_router(
            router_device.id, requesting_organization_id=None
        )

        assert fetched.id == router_device.id

    async def test_org_scoped_caller_cannot_access_other_orgs_router(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        router_b = await make_router(
            repo, location_id=uuid.uuid4(), organization_id=org_b.id
        )

        with pytest.raises(CrossOrganizationRouterAccessError):
            await service.get_router(router_b.id, requesting_organization_id=org_a.id)

    async def test_msp_can_access_its_childs_router(self) -> None:
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        msp = org_lookup.add(org_type=OrganizationType.MSP.value)
        child = org_lookup.add(parent_organization_id=msp.id)
        router_device = await make_router(
            repo, location_id=uuid.uuid4(), organization_id=child.id
        )

        fetched = await service.get_router(
            router_device.id, requesting_organization_id=msp.id
        )

        assert fetched.id == router_device.id

    async def test_create_router_outside_scope_raises(self) -> None:
        service, _repo, location_lookup, org_lookup, _audit = make_service()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        location_b = location_lookup.add(organization_id=org_b.id)

        with pytest.raises(CrossOrganizationLocationAccessError):
            await service.create_router(
                actor_user_id=uuid.uuid4(),
                location_id=location_b.id,
                requesting_organization_id=org_a.id,
                **_create_kwargs(),
            )


# ============================================================================
# RBAC router_id FK follow-up (models-level sanity, not the FK itself since
# SQLite/no-DB unit tests can't exercise a real Postgres constraint -- the FK
# constraint itself is exercised by running the full RBAC suite, confirmed
# unaffected by this change).
# ============================================================================


class TestRbacRouterFkFollowUp:
    def test_rbac_models_declare_router_fk(self) -> None:
        from app.domains.rbac.models import PermissionOverride, UserRole

        for model in (UserRole, PermissionOverride):
            column = model.__table__.columns["router_id"]
            assert len(column.foreign_keys) == 1
            foreign_key = next(iter(column.foreign_keys))
            assert foreign_key.target_fullname == "routers.id"

    def test_audit_log_entry_has_no_router_id_column(self) -> None:
        from app.domains.rbac.models import AuditLogEntry

        assert "router_id" not in AuditLogEntry.__table__.columns

    def test_msp_id_columns_remain_fk_less(self) -> None:
        from app.domains.rbac.models import UserRole

        column = UserRole.__table__.columns["msp_id"]
        assert len(column.foreign_keys) == 0
