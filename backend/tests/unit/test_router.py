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

import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.location.exceptions import (
    CrossOrganizationLocationAccessError,
    LocationArchivedError,
    LocationNotFoundError,
)
from app.domains.location.models import Location
from app.domains.monitoring.constants import ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES
from app.domains.network_config.constants import BootstrapMode
from app.domains.organization.enums import OrganizationType
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction
from app.domains.router.audit_changes import (
    OPAQUE_ROUTER_FIELDS,
    REDACTED_ROUTER_FIELDS,
    describe_router_changes,
    router_field_changes,
)
from app.domains.router.constants import (
    ROUTER_REACHABILITY_HITS_TO_RESOLVE,
    ROUTER_REACHABILITY_MISSES_TO_ALERT,
    ROUTER_REACHABILITY_SILENCE_SECONDS,
    ROUTER_REACHABILITY_SWEEP_INTERVAL_SECONDS,
)
from app.domains.router.crypto import decrypt_secret, encrypt_secret
from app.domains.router.enums import (
    RouterHealthStatus,
    RouterReachabilityState,
    RouterStatus,
)
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
    RemoteBootstrapNeverEnrolledError,
    RouterDecommissionedError,
    RouterLiveCredentialRotationFailedError,
    RouterNotFoundError,
)
from app.domains.router.models import Router, RouterProvisioningToken
from app.domains.router.repository import stale_heartbeat_statement
from app.domains.router.schemas import (
    HeartbeatRequest,
    RouterCreateRequest,
    RouterManagementAccessRequest,
    RouterUpdateRequest,
)
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
    # router_id -> last moment an agent credential for it was used. Stands
    # in for the real join onto ``router_agent_credentials.last_used_at``;
    # a router missing from this dict has no usable credential and the real
    # query excludes it. See ``list_reachability_candidates`` below.
    agent_contact: dict[uuid.UUID, datetime] = field(default_factory=dict)
    # router_id -> the live NetworkIntegration referencing it, for
    # `controller_context`. A router missing from this dict has none, which
    # is `not_registered` and not an absence of data.
    integrations: dict[uuid.UUID, object] = field(default_factory=dict)

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

    # How many live `network_integrations` rows point at a router. The real
    # repository counts them in SQL; here a test sets the number it wants.
    # Only `change_router_vendor` reads it -- an integration's provider is
    # what chose the fleet row's vendor, so the value cannot be changed out
    # from under one.
    integration_counts: dict[uuid.UUID, int] = field(default_factory=dict)

    async def count_integrations_referencing_router(self, router_id: uuid.UUID) -> int:
        return self.integration_counts.get(router_id, 0)

    async def integrations_for_routers(
        self, router_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, object]:
        return {
            rid: self.integrations[rid]
            for rid in router_ids
            if rid in self.integrations
        }

    async def names_for_routers(
        self, router_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, str]:
        return {
            rid: self.routers[rid].name
            for rid in router_ids
            if rid in self.routers
        }

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
    ) -> bool:
        """Mirrors the real repository's compare-and-set semantics: a
        no-op (returning ``False``) if the token was already used."""
        if token.used_at is not None:
            return False
        token.used_at = used_at
        return True

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

    async def list_reachability_candidates(
        self, *, now: object
    ) -> list[tuple[Router, object]]:
        """Mirrors ``reachability_candidate_statement`` on the two axes
        that decide who gets judged: only ONLINE/OFFLINE routers, and only
        those with a usable (unrevoked, unexpired) agent credential to read
        a ``last_used_at`` from.

        ``agent_contact`` here stands in for the real join onto
        ``router_agent_credentials.last_used_at``; a router absent from the
        dict is one with no usable credential and is excluded exactly as
        the real query excludes it -- which is the behaviour
        ``test_a_router_with_no_usable_agent_credential_is_never_judged``
        below pins down.
        """
        return [
            (r, self.agent_contact[r.id])
            for r in self.routers.values()
            if not r.is_deleted
            and r.status in (RouterStatus.ONLINE.value, RouterStatus.OFFLINE.value)
            and r.id in self.agent_contact
        ]

    async def list_online_routers_with_stale_heartbeat(
        self, *, cutoff: object
    ) -> list[Router]:
        """Mirrors the real query exactly, INCLUDING the `last_seen_at IS
        NULL` arm. A fake that quietly narrows the real predicate is a test
        that passes for a query nobody ships."""
        return [
            r
            for r in self.routers.values()
            if not r.is_deleted
            and r.status == RouterStatus.ONLINE.value
            and (r.last_seen_at is None or r.last_seen_at < cutoff)
        ]


def make_service(
    repo: FakeRouterRepository | None = None,
    location_lookup: FakeLocationLookup | None = None,
    org_lookup: FakeOrganizationLookup | None = None,
    credential_rotator: object | None = None,
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
        credential_rotator=credential_rotator,
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

    async def test_preview_bootstrap_script_renders_step_zero_script(self) -> None:
        service, _repo, location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        location.location_code = "HQ-001"
        router_device = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )

        location_code, lines, expires_at = await service.preview_bootstrap_script(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            api_base_url="https://api.cloudguest.example",
        )

        script = "\n".join(lines)
        assert location_code == "HQ-001"
        # Raised 30 -> 36 on 2026-08-27 alongside the identical cap in
        # tests/unit/test_network_config.py, for the clock/NTP block the
        # bootstrap renderer now emits. See that file for the reasoning.
        # Raised 36 -> 38 on 2026-08-29, again in lockstep with that file,
        # for the captive-portal walled garden (2 lines, one per platform
        # host). These two caps are deliberately kept identical -- they
        # guard the same script, and letting them drift would mean one of
        # them silently stops guarding anything.
        #
        # Raised 38 -> 39 on 2026-08-29: the walled garden emits a third
        # line. `_render_vlan_hotspot` redirects to a per-VLAN
        # `{tag}.HOTSPOT_DNS_NAME`, and RouterOS `dst-host` does not treat a
        # bare name as covering its subdomains, so the wildcard form has to
        # be allowed too or the one hostname guests are actually sent to is
        # the one hostname walled off. Keeps the one line of slack this cap
        # has carried since the 30 -> 36 raise.
        #
        # Raised 39 -> 42 on 2026-09-07, again in lockstep, for the three
        # lines that make the HTTPS portal reachable pre-auth at all: a
        # fourth host-based row for `GUEST_PORTAL_HOST` (the host the guest
        # is actually sent to, which this section had never allowed), one
        # joined line of address-based `/ip hotspot walled-garden ip`
        # writes, and one verification line. See test_network_config.py for
        # why the address-based row is the only one that can pass TLS.
        assert len(lines) <= 42
        assert '/system identity set name="HQ-001"' in script
        assert "provisioning/check-in" in script
        # Step 1 ends at a verified tunnel + success line; the full config
        # import belongs to the later wizard steps, not this paste.
        assert "/agent/wireguard-config" in script
        assert "CloudGuest bootstrap successful" in script
        assert expires_at is not None
        assert any(
            e["action"] == "router_provisioning_token_generated" for e in audit.entries
        )

    async def test_preview_remote_mode_refuses_never_checked_in_router(
        self,
    ) -> None:
        service, _repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        location.location_code = "LOC-2026-000039"
        router_device = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )

        # Never checked in: last_seen_at is NULL -- there is no live tunnel
        # to protect and none to deliver the script through.
        with pytest.raises(RemoteBootstrapNeverEnrolledError):
            await service.preview_bootstrap_script(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
                api_base_url="https://api.cloudguest.example",
                mode=BootstrapMode.REMOTE,
            )

    async def test_preview_remote_mode_rewinds_live_router_and_stages(
        self,
    ) -> None:
        service, repo, location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        location.location_code = "LOC-2026-000039"
        router_device = await make_router(
            repo,
            location_id=location.id,
            organization_id=organization.id,
            status=RouterStatus.ONLINE,
        )
        await repo.update_router(router_device, {"last_seen_at": datetime.now(UTC)})

        location_code, lines, expires_at = await service.preview_bootstrap_script(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            api_base_url="https://api.cloudguest.example",
            mode=BootstrapMode.REMOTE,
        )

        script = "\n".join(lines)
        assert location_code == "LOC-2026-000039"
        # The remote rendering, not the on-site one: staged schedulers, no
        # in-session teardown.
        assert "/system scheduler add name=cloudguest-bootstrap-revert" in script
        assert "/system scheduler add name=cloudguest-bootstrap-cutover" in script
        assert not any(line.startswith("/interface wireguard remove") for line in lines)
        assert expires_at is not None
        # The live router was rewound through the transition graph's
        # re-provision edge (so the eventual device check-in is legal),
        # audited with the dedicated remote-reprovision action, and a
        # token was minted.
        refreshed = await repo.get_by_id(router_device.id)
        assert refreshed is not None
        assert refreshed.status == RouterStatus.PENDING_PROVISIONING.value
        assert any(
            e["action"] == "router_remote_reprovision_started" for e in audit.entries
        )
        assert any(
            e["action"] == "router_provisioning_token_generated" for e in audit.entries
        )

    async def test_preview_remote_mode_rejects_suspended_router(self) -> None:
        service, repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        location.location_code = "LOC-2026-000039"
        router_device = await make_router(
            repo,
            location_id=location.id,
            organization_id=organization.id,
            status=RouterStatus.SUSPENDED,
        )
        await repo.update_router(router_device, {"last_seen_at": datetime.now(UTC)})

        with pytest.raises(ProvisioningTokenGenerationNotAllowedError):
            await service.preview_bootstrap_script(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
                api_base_url="https://api.cloudguest.example",
                mode=BootstrapMode.REMOTE,
            )

    async def test_preview_onsite_mode_never_touches_router_status(self) -> None:
        # On-site remains exactly the pre-split behavior: a live router is
        # NOT silently rewound -- token minting refuses it, same as before
        # the mode split.
        service, repo, location_lookup, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        location.location_code = "LOC-2026-000039"
        router_device = await make_router(
            repo,
            location_id=location.id,
            organization_id=organization.id,
            status=RouterStatus.ONLINE,
        )

        with pytest.raises(ProvisioningTokenGenerationNotAllowedError):
            await service.preview_bootstrap_script(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
                api_base_url="https://api.cloudguest.example",
            )
        refreshed = await repo.get_by_id(router_device.id)
        assert refreshed is not None
        assert refreshed.status == RouterStatus.ONLINE.value

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

    async def test_check_in_treats_lost_compare_and_set_race_as_already_used(
        self,
    ) -> None:
        """Regression test for a TOCTOU race: two concurrent ``check_in``
        calls for the same token can both pass the earlier in-memory
        ``token.is_used()`` guard before either one's write lands. This
        simulates the *loser* of that race -- ``mark_provisioning_token_used``
        reports "0 rows affected" (``False``) even though the token this
        call already fetched still looks unused -- and asserts ``check_in``
        surfaces the same ``ProvisioningTokenAlreadyUsedError`` a normal
        already-used token would, and never transitions the router."""

        class LostRaceRepository(FakeRouterRepository):
            async def mark_provisioning_token_used(
                self, token: RouterProvisioningToken, *, used_at: object
            ) -> bool:
                # Simulate someone else's concurrent, already-committed
                # compare-and-set claiming this token first -- the atomic
                # UPDATE ... WHERE used_at IS NULL affected zero rows.
                return False

        repo = LostRaceRepository()
        service, repo, location_lookup, org_lookup, _audit = make_service(repo=repo)
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

        with pytest.raises(ProvisioningTokenAlreadyUsedError):
            await service.check_in(plaintext_token=plaintext)

        refreshed = await repo.get_by_id(router_device.id)
        assert refreshed is not None
        assert refreshed.status == RouterStatus.PENDING_PROVISIONING.value

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


class TestStaleHeartbeatStatement:
    """Reads the SHIPPED query, not the in-memory fake.

    Every other test in this file drives the service through
    `FakeRouterRepository`, whose `list_online_routers_with_stale_heartbeat`
    is a hand-written reimplementation of the real predicate. That is fine
    for the service's own logic and useless for the predicate itself:
    measured, widening the real query to also sweep PROVISIONING routers
    left the entire suite green. These read the compiled SQL instead."""

    def _where(self) -> str:
        """THE WHERE CLAUSE ONLY, not the whole statement.

        `select(Router)` puts every column in the SELECT list, so
        `"is_deleted" in sql` is satisfied by the projection and stays true
        after the filter is deleted -- measured: removing
        `Router.is_deleted.is_(False)` from the query left that assertion
        green. Reading the whole statement tests what is being SELECTED
        while claiming to test what is being FILTERED."""
        compiled = str(
            stale_heartbeat_statement(cutoff=_now()).compile(
                compile_kwargs={"literal_binds": True}
            )
        ).lower()
        # Whitespace-normalised first: SQLAlchemy puts WHERE on its own
        # line, so a naive `" where "` search finds nothing and every
        # assertion below would fail for a reason that has nothing to do
        # with the query.
        sql = " ".join(compiled.split())
        assert " where " in sql
        return sql.split(" where ", 1)[1]

    def test_only_online_routers_are_selected(self) -> None:
        where = self._where()
        assert "'online'" in where
        # The states a missed heartbeat has no business overriding. A router
        # mid-install has never sent one BY DEFINITION; the other three are
        # administrative facts, not reachability.
        for never in ("provisioning", "suspended", "decommissioned"):
            assert f"'{never}'" not in where

    def test_a_router_with_no_timestamp_is_still_selected(self) -> None:
        """Excluding NULL would create a permanently unsweepable state."""
        assert "last_seen_at is null" in self._where()

    def test_soft_deleted_routers_are_excluded(self) -> None:
        assert "is_deleted" in self._where()

    def test_the_comparison_is_a_cutoff_not_an_equality(self) -> None:
        assert "last_seen_at <" in self._where()


class TestSweepStaleHeartbeats:
    """The writer that did not exist. `heartbeat()` wrote ONLINE and nothing
    ever wrote it back, so a router that died weeks ago read as online to
    every consumer of `Router.status`."""

    async def _router(
        self,
        service,
        location_lookup,
        org_lookup,
        *,
        status: str,
        last_seen_at,
    ) -> Router:
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        router = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(
                serial_number=f"SN-{uuid.uuid4()}",
                mac_address=_unique_mac(),
            ),
        )
        router.status = status
        router.last_seen_at = last_seen_at
        return router

    async def test_a_router_that_stopped_answering_is_marked_offline(self) -> None:
        service, repo, loc, org, _audit = make_service()
        stale = await self._router(
            service,
            loc,
            org,
            status=RouterStatus.ONLINE.value,
            last_seen_at=_now() - timedelta(hours=3),
        )

        result = await service.sweep_stale_heartbeats()

        assert result["marked_offline"] == 1
        assert repo.routers[stale.id].status == RouterStatus.OFFLINE.value

    async def test_being_marked_offline_also_clears_the_health_verdict(self) -> None:
        """`status` and `health_status` must move together.

        This sweep used to write `status` alone, so a router swept offline
        kept whatever `health_status` its last successful heartbeat had
        written -- permanently "healthy". Confirmed live 2026-08-27 on
        router 01c9171e: `status='offline'` next to `health_status='healthy'`
        in the same row, i.e. the console answering "is this router up?" two
        different ways on two different screens from one record.

        UNHEALTHY rather than None/"unknown": this is a positive finding,
        not an absence of one. We know the router has not checked in past
        the stale cutoff, and `RouterHealthStatus` defines this field as
        "is this router currently reachable" -- which we have just
        determined it is not. `None` would claim no health check had ever
        run, a lie in the opposite direction.
        """
        service, repo, loc, org, _audit = make_service()
        stale = await self._router(
            service,
            loc,
            org,
            status=RouterStatus.ONLINE.value,
            last_seen_at=_now() - timedelta(hours=3),
        )
        repo.routers[stale.id].health_status = "healthy"

        await service.sweep_stale_heartbeats()

        swept = repo.routers[stale.id]
        assert swept.status == RouterStatus.OFFLINE.value
        assert (
            swept.health_status == "unhealthy"
        ), "a router the platform has just given up on cannot still be reported healthy"
        assert swept.last_health_check_at is not None

    async def test_a_router_heard_from_recently_is_left_alone(self) -> None:
        service, repo, loc, org, _audit = make_service()
        fresh = await self._router(
            service,
            loc,
            org,
            status=RouterStatus.ONLINE.value,
            last_seen_at=_now() - timedelta(minutes=1),
        )

        result = await service.sweep_stale_heartbeats()

        assert result["marked_offline"] == 0
        assert repo.routers[fresh.id].status == RouterStatus.ONLINE.value

    async def test_the_boundary_is_the_shared_threshold_not_a_new_one(self) -> None:
        """A second, slightly different definition of "offline" is how two
        screens start disagreeing about one router. One router sits just
        inside the shared threshold and one just outside it."""
        service, repo, loc, org, _audit = make_service()
        inside = await self._router(
            service,
            loc,
            org,
            status=RouterStatus.ONLINE.value,
            last_seen_at=_now()
            - timedelta(minutes=ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES - 1),
        )
        outside = await self._router(
            service,
            loc,
            org,
            status=RouterStatus.ONLINE.value,
            last_seen_at=_now()
            - timedelta(minutes=ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES + 1),
        )

        await service.sweep_stale_heartbeats()

        assert repo.routers[inside.id].status == RouterStatus.ONLINE.value
        assert repo.routers[outside.id].status == RouterStatus.OFFLINE.value

    async def test_a_router_being_installed_right_now_is_never_swept(self) -> None:
        """PROVISIONING routers have never sent a heartbeat BY DEFINITION --
        the only transition out of PROVISIONING is `heartbeat`. Sweeping them
        would mark every router currently being installed as offline, which
        is the loudest possible way to be wrong."""
        service, repo, loc, org, _audit = make_service()
        installing = await self._router(
            service,
            loc,
            org,
            status=RouterStatus.PROVISIONING.value,
            last_seen_at=_now() - timedelta(days=2),
        )

        result = await service.sweep_stale_heartbeats()

        assert result["marked_offline"] == 0
        assert repo.routers[installing.id].status == RouterStatus.PROVISIONING.value

    async def test_administrative_states_are_never_overridden(self) -> None:
        service, repo, loc, org, _audit = make_service()
        held = []
        for status in (
            RouterStatus.SUSPENDED.value,
            RouterStatus.DECOMMISSIONED.value,
            RouterStatus.PENDING_PROVISIONING.value,
        ):
            held.append(
                await self._router(
                    service,
                    loc,
                    org,
                    status=status,
                    last_seen_at=_now() - timedelta(days=30),
                )
            )

        result = await service.sweep_stale_heartbeats()

        assert result["marked_offline"] == 0
        for router in held:
            assert repo.routers[router.id].status != RouterStatus.OFFLINE.value

    async def test_online_with_no_timestamp_at_all_is_swept(self) -> None:
        """`heartbeat()` is the only path into ONLINE and it always stamps
        `last_seen_at`, so a NULL here means the row came from somewhere
        else. Excluding it would create a permanently unsweepable state --
        the same bug in a smaller box."""
        service, repo, loc, org, _audit = make_service()
        impossible = await self._router(
            service, loc, org, status=RouterStatus.ONLINE.value, last_seen_at=None
        )

        result = await service.sweep_stale_heartbeats()

        assert result["marked_offline"] == 1
        assert repo.routers[impossible.id].status == RouterStatus.OFFLINE.value

    async def test_one_router_failing_never_aborts_the_sweep(self) -> None:
        service, repo, loc, org, _audit = make_service()
        first = await self._router(
            service,
            loc,
            org,
            status=RouterStatus.ONLINE.value,
            last_seen_at=_now() - timedelta(hours=3),
        )
        second = await self._router(
            service,
            loc,
            org,
            status=RouterStatus.ONLINE.value,
            last_seen_at=_now() - timedelta(hours=3),
        )

        original_update = repo.update_router
        exploded: list[uuid.UUID] = []

        async def _boom(router: Router, data: dict[str, object]) -> Router:
            if router.id == first.id and not exploded:
                exploded.append(router.id)
                raise RuntimeError("transient database error")
            return await original_update(router, data)

        repo.update_router = _boom  # type: ignore[method-assign]

        result = await service.sweep_stale_heartbeats()

        assert result["failed"] == 1
        assert result["marked_offline"] == 1
        assert repo.routers[second.id].status == RouterStatus.OFFLINE.value

    async def test_the_sweep_preserves_the_evidence_it_acted_on(self) -> None:
        """The sweep must NOT clear `last_seen_at`. That timestamp is the
        only record of when the router was last heard from, and both the
        dashboard and Master console render it -- wiping it would turn
        "last check-in 3 hours ago", which tells an operator how long the
        venue has been down, into "never heard from this router", which is
        false and strictly less useful. Writing `status` and nothing else
        is the whole point."""
        service, repo, loc, org, _audit = make_service()
        heard_at = _now() - timedelta(hours=3)
        stale = await self._router(
            service,
            loc,
            org,
            status=RouterStatus.ONLINE.value,
            last_seen_at=heard_at,
        )

        await service.sweep_stale_heartbeats()

        assert repo.routers[stale.id].status == RouterStatus.OFFLINE.value
        assert repo.routers[stale.id].last_seen_at == heard_at

    async def test_the_transition_is_audited_with_no_human_actor(self) -> None:
        """An expired token aging out is routine housekeeping and is
        deliberately not audited. A router being declared offline is a
        statement about a venue's service that someone may later have to
        account for -- with a null actor, because no human performed it."""
        service, _repo, loc, org, audit = make_service()
        await self._router(
            service,
            loc,
            org,
            status=RouterStatus.ONLINE.value,
            last_seen_at=_now() - timedelta(hours=3),
        )

        await service.sweep_stale_heartbeats()

        entries = [
            e
            for e in audit.entries
            if e.get("action") == AuditAction.ROUTER_MARKED_OFFLINE.value
        ]
        assert len(entries) == 1
        assert entries[0]["actor_user_id"] is None
        assert entries[0]["entity_type"] == "router"

    async def test_a_quiet_run_is_distinguishable_from_a_failing_one(self) -> None:
        service, _repo, _loc, _org, _audit = make_service()

        result = await service.sweep_stale_heartbeats()

        assert result == {"considered": 0, "marked_offline": 0, "failed": 0}


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
# Live credential rotation -- see RouterLiveCredentialRotationFailedError's
# own docstring for the "Permission denied for user cloudguest-api"
# production incident this closes.
# ============================================================================


@dataclass
class FakeCredentialRotator:
    """In-memory stand-in for ``DeviceCredentialRotatorProtocol``. Records
    every call it receives; ``should_fail`` controls whether
    ``rotate_password`` raises ``DeviceCredentialRotationError``, mirroring
    a real device that's unreachable or rejects the old password."""

    should_fail: bool = False
    calls: list[dict[str, str]] = field(default_factory=list)

    async def rotate_password(
        self, *, host: str, username: str, old_password: str, new_password: str
    ) -> None:
        self.calls.append(
            {
                "host": host,
                "username": username,
                "old_password": old_password,
                "new_password": new_password,
            }
        )
        if self.should_fail:
            from app.domains.router.device_credential_rotator import (
                DeviceCredentialRotationError,
            )

            raise DeviceCredentialRotationError("device unreachable")


class TestCredentialRotatorWiring:
    """Production DI always wires the gateway-backed rotator singleton."""

    def test_get_router_service_builds_gateway_rotator(self) -> None:
        from app.domains.router.dependencies import _credential_rotator
        from app.domains.router.device_credential_rotator import (
            GatewayDeviceCredentialRotator,
        )

        assert isinstance(_credential_rotator, GatewayDeviceCredentialRotator)


class TestRouterLiveCredentialRotation:
    async def _make_provisioned_router(
        self, repo: FakeRouterRepository, org_lookup: FakeOrganizationLookup
    ) -> Router:
        organization = org_lookup.add()
        router_device = await make_router(
            repo,
            location_id=uuid.uuid4(),
            organization_id=organization.id,
            status=RouterStatus.ONLINE,
        )
        # Simulate a router that already went through Setup Script once --
        # a real host/username/secret already on file, exactly the state
        # that makes a second api_secret change a *rotation*, not
        # first-time issuance.
        return await repo.update_router(
            router_device,
            {
                "management_ip_address": "10.20.0.41",
                "api_username": "cloudguest-api",
                "api_credentials_encrypted": encrypt_secret("old-secret-123"),
            },
        )

    async def test_rotation_pushes_old_and_new_secret_to_device(self) -> None:
        rotator = FakeCredentialRotator()
        service, repo, _location_lookup, org_lookup, _audit = make_service(
            credential_rotator=rotator
        )
        router_device = await self._make_provisioned_router(repo, org_lookup)

        updated = await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"api_secret": "new-secret-456"},
        )

        assert len(rotator.calls) == 1
        assert rotator.calls[0] == {
            "host": "10.20.0.41",
            "username": "cloudguest-api",
            "old_password": "old-secret-123",
            "new_password": "new-secret-456",
        }
        assert service.get_decrypted_api_secret(updated) == "new-secret-456"

    async def test_failed_rotation_raises_and_leaves_stored_secret_unchanged(
        self,
    ) -> None:
        rotator = FakeCredentialRotator(should_fail=True)
        service, repo, _location_lookup, org_lookup, _audit = make_service(
            credential_rotator=rotator
        )
        router_device = await self._make_provisioned_router(repo, org_lookup)

        with pytest.raises(RouterLiveCredentialRotationFailedError):
            await service.update_router(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
                data={"api_secret": "new-secret-456"},
            )

        assert len(rotator.calls) == 1
        # The stored secret still matches the device -- the DB never
        # learned about the new one since the live push failed.
        reloaded = await repo.get_by_id(router_device.id)
        assert reloaded is not None
        assert service.get_decrypted_api_secret(reloaded) == "old-secret-123"

    async def test_first_time_issuance_skips_rotation(self) -> None:
        """A freshly-created router has no management_ip/api_username/
        api_credentials_encrypted yet -- its very first api_secret is
        issuance, not rotation, so the rotator must never be called (and
        would fail this test if it were, since ``should_fail=True``)."""
        rotator = FakeCredentialRotator(should_fail=True)
        service, repo, _location_lookup, org_lookup, _audit = make_service(
            credential_rotator=rotator
        )
        organization = org_lookup.add()
        router_device = await make_router(
            repo, location_id=uuid.uuid4(), organization_id=organization.id
        )

        updated = await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"api_username": "cloudguest-api", "api_secret": "first-secret"},
        )

        assert rotator.calls == []
        assert service.get_decrypted_api_secret(updated) == "first-secret"

    async def test_no_rotator_configured_falls_back_to_direct_persist(self) -> None:
        """Backward-compatible default -- ``make_service()`` with no
        rotator (every other test in this module) keeps today's
        behavior unchanged."""
        service, repo, _location_lookup, org_lookup, _audit = make_service()
        router_device = await self._make_provisioned_router(repo, org_lookup)

        updated = await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"api_secret": "new-secret-456"},
        )

        assert service.get_decrypted_api_secret(updated) == "new-secret-456"

    async def test_simultaneous_host_change_skips_rotation(self) -> None:
        """Changing management_ip_address in the same call is out of
        scope (too ambiguous which host the old secret was ever valid
        against) -- falls back to direct persist rather than pushing
        against a possibly-wrong host."""
        rotator = FakeCredentialRotator(should_fail=True)
        service, repo, _location_lookup, org_lookup, _audit = make_service(
            credential_rotator=rotator
        )
        router_device = await self._make_provisioned_router(repo, org_lookup)

        updated = await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={
                "management_ip_address": "10.20.0.99",
                "api_secret": "new-secret-456",
            },
        )

        assert rotator.calls == []
        assert service.get_decrypted_api_secret(updated) == "new-secret-456"


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


class TestBootstrapSingleLineCopy:
    """A multi-line paste of the bootstrap script cannot work: RouterOS
    executes each pasted line as its own command with its own scope, so
    the ``:local enroll`` set by the check-in line is already gone by the
    time the next line dereferences it. Confirmed on a real RouterOS
    7.23.3 device -- every field check reported "check-in response
    missing ..." while the platform had in fact returned every field.
    ``script_single_line`` is the form a human pastes."""

    def test_single_line_join_keeps_every_command(self) -> None:
        from app.domains.network_config.renderers import render_bootstrap_script

        lines = render_bootstrap_script(
            location_code="LOC-2026-000039",
            provisioning_token="TOKEN",
            api_base_url="https://api.example.com",
        )
        joined = "; ".join(lines)
        assert joined.count(";") >= len(lines) - 1
        assert "\n" not in joined

    def test_no_hash_comments_would_swallow_the_join(self) -> None:
        """A ``#`` comment anywhere would eat every command after it once
        the script is joined onto one line -- silently, with no error."""
        from app.domains.network_config.renderers import render_bootstrap_script

        lines = render_bootstrap_script(
            location_code="LOC-2026-000039",
            provisioning_token="TOKEN",
            api_base_url="https://api.example.com",
        )
        assert not any(line.lstrip().startswith("#") for line in lines)

    def test_local_vars_and_their_uses_share_one_joined_scope(self) -> None:
        from app.domains.network_config.renderers import render_bootstrap_script

        lines = render_bootstrap_script(
            location_code="LOC-2026-000039",
            provisioning_token="TOKEN",
            api_base_url="https://api.example.com",
        )
        joined = "; ".join(lines)
        for var in ("enroll", "wgcfg", "tunaddr"):
            assert f":local {var}" in joined
            assert f"${var}" in joined


# ============================================================================
# Customer-reachable router endpoints must not carry platform credentials
# ============================================================================
#
# The regression these exist for (2026-09-01): ``RouterResponse`` emitted
# ``snmp_enabled``/``has_snmp_community``/``snmp_version``/``snmp_port``, and
# ``RouterCreateRequest``/``RouterUpdateRequest`` accepted plaintext
# ``snmp_community`` and ``api_secret``. All four routes carrying those
# schemas are gated on ``routers.read``/``create``/``update`` at
# *organization* scope -- which ``organization-owner`` holds in full (see
# ``TestRouterPermissionsAreHeldByCustomerScopedRoles`` below), and which
# ``LocationProvisioningService`` assigns to every venue owner it
# provisions. The customer dashboard really does call
# ``GET /locations/{id}/routers`` for venue liveness, so that payload
# reached venue-owner browsers, and a venue owner could set the router's
# SNMP community string and the platform's own RouterOS API secret.


class TestRouterPermissionsAreHeldByCustomerScopedRoles:
    """The premise the split below exists for, asserted rather than assumed.

    If a future seed change genuinely takes ``routers.*`` away from every
    organization-scoped role, these fail and whoever is reading can decide
    the split is no longer load-bearing -- rather than the split quietly
    outliving its reason.
    """

    @staticmethod
    def _grants(slug: str):
        from app.domains.rbac.enums import PermissionModule
        from app.domains.rbac.seed import SYSTEM_ROLES

        role = next(r for r in SYSTEM_ROLES if r.slug == slug)
        return role, role.grants().get(PermissionModule.ROUTERS, ())

    def test_organization_owner_holds_routers_read_and_update(self) -> None:
        from app.domains.rbac.enums import PermissionAction, ScopeType

        role, actions = self._grants("organization-owner")
        assert role.scope_type == ScopeType.ORGANIZATION
        assert PermissionAction.READ in actions
        assert PermissionAction.UPDATE in actions
        assert PermissionAction.CREATE in actions

    def test_other_customer_scoped_roles_hold_them_too(self) -> None:
        from app.domains.rbac.enums import PermissionAction, ScopeType

        for slug in ("organization-admin", "msp-owner", "msp-admin"):
            role, actions = self._grants(slug)
            assert role.scope_type == ScopeType.ORGANIZATION, slug
            assert PermissionAction.UPDATE in actions, slug

    def test_an_organization_scoped_grant_can_never_satisfy_a_global_check(
        self,
    ) -> None:
        """The one property the whole fix rests on: pointing the sensitive
        fields at a ``ScopeType.GLOBAL`` route really does exclude an
        organization-scoped role, whatever ``X-Organization-Id`` it sends."""
        from app.domains.rbac.authorization import ScopeResolver
        from app.domains.rbac.context import GrantScope, ScopeContext
        from app.domains.rbac.enums import ScopeType

        org_id = uuid.uuid4()
        grant = GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=org_id)
        assert (
            ScopeResolver.satisfies(
                grant, ScopeType.GLOBAL, ScopeContext(organization_id=org_id)
            )
            is False
        )
        # ...while still satisfying the organization-scoped liveness read
        # the customer dashboard legitimately needs.
        assert (
            ScopeResolver.satisfies(
                grant, ScopeType.LOCATION, ScopeContext(organization_id=org_id)
            )
            is True
        )


class TestCustomerReachableRouterSchemasCarryNoCredentials:
    def test_router_response_has_no_credential_or_snmp_config_field(self) -> None:
        from app.domains.router.schemas import (
            CUSTOMER_FORBIDDEN_ROUTER_FIELDS,
            RouterResponse,
        )

        leaked = set(RouterResponse.model_fields) & CUSTOMER_FORBIDDEN_ROUTER_FIELDS
        assert leaked == set(), (
            f"RouterResponse is returned by organization-scoped routes that a "
            f"venue owner reaches; it must not carry {sorted(leaked)}. Put the "
            f"field on RouterPlatformResponse instead."
        )

    def test_create_and_update_requests_cannot_set_a_secret(self) -> None:
        from app.domains.router.schemas import (
            CUSTOMER_FORBIDDEN_ROUTER_FIELDS,
            RouterCreateRequest,
            RouterUpdateRequest,
        )

        for schema in (RouterCreateRequest, RouterUpdateRequest):
            leaked = set(schema.model_fields) & CUSTOMER_FORBIDDEN_ROUTER_FIELDS
            assert leaked == set(), (
                f"{schema.__name__} is accepted by an organization-scoped "
                f"route; it must not accept {sorted(leaked)}."
            )

    def test_a_customer_write_carrying_a_secret_never_reaches_the_service(
        self,
    ) -> None:
        """The end the service actually sees. ``update_router`` takes a plain
        dict, so what matters is that the route's ``model_dump`` of a hostile
        payload contains no credential key at all -- not merely that the
        field is undeclared."""
        from app.domains.router.schemas import (
            CUSTOMER_FORBIDDEN_ROUTER_FIELDS,
            RouterCreateRequest,
            RouterUpdateRequest,
        )

        hostile = {
            "api_username": "attacker",
            "api_secret": "pwned",
            "snmp_enabled": True,
            "snmp_community": "public",
            "snmp_version": "2c",
            "snmp_port": 1610,
        }
        update = RouterUpdateRequest.model_validate({"name": "Front Desk", **hostile})
        assert set(update.model_dump(exclude_unset=True)) == {"name"}

        create = RouterCreateRequest.model_validate(
            {
                "name": "Front Desk",
                "serial_number": "HB31090ABCD",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "model": "hAP ac2",
                **hostile,
            }
        )
        assert not set(create.model_dump()) & CUSTOMER_FORBIDDEN_ROUTER_FIELDS

    def test_the_platform_response_still_carries_them(self) -> None:
        """The Master console must not lose the fields -- only the audience
        changes."""
        from app.domains.router.schemas import RouterPlatformResponse

        assert {
            "snmp_enabled",
            "has_snmp_community",
            "snmp_version",
            "snmp_port",
        } <= set(RouterPlatformResponse.model_fields)

    def test_the_platform_write_schema_still_carries_them(self) -> None:
        from app.domains.router.schemas import RouterManagementAccessRequest

        assert {
            "api_username",
            "api_secret",
            "snmp_enabled",
            "snmp_community",
            "snmp_version",
            "snmp_port",
        } == set(RouterManagementAccessRequest.model_fields)

    def test_the_platform_response_never_echoes_a_plaintext_secret(self) -> None:
        from app.domains.router.schemas import RouterPlatformResponse

        assert not {
            "api_secret",
            "snmp_community",
            "api_credentials_encrypted",
            "snmp_community_encrypted",
        } & set(RouterPlatformResponse.model_fields)


class TestPlatformRouterRoutesAreGlobalScopeOnly:
    """Asserts the route dependencies directly, the same convention
    ``test_wireguard.py``'s ``TestFleetStatusRouteRequiresPermission`` and
    ``test_user.py``'s impersonate tests already establish."""

    @staticmethod
    def _route(path: str, method: str):
        from app.domains.router.router import router as router_module

        return next(
            route
            for route in router_module.routes
            if route.path == path and method in route.methods  # type: ignore[attr-defined]
        )

    @staticmethod
    def _dependency_nonlocals(route):
        import inspect

        return [
            inspect.getclosurevars(dependency.dependency).nonlocals
            for dependency in route.dependencies
        ]

    def test_platform_read_route_is_routers_read_at_global_scope(self) -> None:
        from app.domains.rbac.enums import ScopeType

        (nonlocals,) = self._dependency_nonlocals(
            self._route("/platform/routers/{router_id}", "GET")
        )
        assert nonlocals["permission_key"] == "routers.read"
        assert nonlocals["scope"] == ScopeType.GLOBAL

    def test_management_access_route_is_routers_update_at_global_scope(self) -> None:
        from app.domains.rbac.enums import ScopeType

        (nonlocals,) = self._dependency_nonlocals(
            self._route(
                "/platform/routers/{router_id}/management-access",
                "PUT",
            )
        )
        assert nonlocals["permission_key"] == "routers.update"
        assert nonlocals["scope"] == ScopeType.GLOBAL

    def test_the_organization_scoped_routes_serialize_the_customer_safe_shape(
        self,
    ) -> None:
        """The other half: the routes a venue owner reaches must be declared
        with ``RouterResponse``/``RouterListResponse``, never the platform
        one. A future edit that swaps the response_model back fails here."""
        from app.domains.router.schemas import (
            RouterListResponse,
            RouterPlatformResponse,
            RouterResponse,
        )

        for path, method, expected in (
            ("/locations/{location_id}/routers", "GET", RouterListResponse),
            ("/locations/{location_id}/routers", "POST", RouterResponse),
            ("/routers/{router_id}", "GET", RouterResponse),
            ("/routers/{router_id}", "PUT", RouterResponse),
        ):
            route = self._route(path, method)
            (inner,) = route.response_model.__pydantic_generic_metadata__["args"]
            assert inner is expected, (method, path)
            assert inner is not RouterPlatformResponse

    def test_the_organization_scoped_routes_are_not_global_scoped(self) -> None:
        """Guards the other direction: these four must stay reachable by the
        customer dashboard's liveness read and the venue's own network pages.
        Tightening them to GLOBAL would break both."""
        from app.domains.rbac.enums import ScopeType

        for path, method in (
            ("/locations/{location_id}/routers", "GET"),
            ("/locations/{location_id}/routers", "POST"),
            ("/routers/{router_id}", "GET"),
            ("/routers/{router_id}", "PUT"),
        ):
            for nonlocals in self._dependency_nonlocals(self._route(path, method)):
                assert nonlocals["scope"] != ScopeType.GLOBAL, (method, path)


class TestLivenessFieldsSurviveOnTheCustomerShape:
    """``src/lib/location-liveness.ts`` and ``customer.service.ts`` read
    exactly ``id``/``name``/``status``/``last_seen_at`` off
    ``GET /locations/{id}/routers``; ``src/services/router.service.ts``'s
    ``toRouter()`` (which the venue's own DHCP/DNS/VLAN/QoS/hotspot/ISP
    pages reach through ``listForLocation``) reads the rest. Removing any of
    them would break the customer dashboard, so they are pinned here."""

    def test_customer_consumed_fields_are_present(self) -> None:
        from app.domains.router.schemas import RouterResponse

        assert {
            "id",
            "location_id",
            "organization_id",
            "name",
            "serial_number",
            "mac_address",
            "model",
            "vendor",
            "routeros_version",
            "management_ip_address",
            "public_ip_address",
            "status",
            "last_seen_at",
            "last_health_check_at",
            "health_status",
            "has_api_credentials",
            "settings",
            "created_at",
            "updated_at",
        } <= set(RouterResponse.model_fields)


# api_secret/api_username: RouterOS script injection hardening
#
# GatewayDeviceCredentialRotator.rotate_password interpolates these values
# into a RouterOS console script (`/user set [find name="{username}"]
# password="{new_password}"`) executed over SSH. Two independent layers
# guard against a malicious value breaking out of that script:
#   1. A strict charset allowlist at the schema layer
#      (RouterManagementAccessRequest, the master-console route that
#      sets these) -- tested below.
#   2. Proper `"`/`\`/`$` escaping in device_credential_rotator itself,
#      regardless of what the schema layer permits -- tested further below.
# ============================================================================


class TestApiCredentialCharsetValidation:
    """The allowlist lives on ``RouterManagementAccessRequest``, the
    master-console route that actually sets these credentials.

    It was written against ``RouterCreateRequest``/``RouterUpdateRequest``,
    which carried ``api_secret`` at the time. #91 has since removed
    credentials and SNMP config from both of those customer-reachable
    schemas -- see ``TestCustomerReachableRouterSchemasCarryNoCredentials``
    above, which asserts exactly that. Re-pointing these here keeps the
    hardening on the one schema where the field still exists; asserting it
    on the customer schemas would only re-prove that the field is absent.
    """

    def test_rejects_double_quote_in_api_secret(self) -> None:
        with pytest.raises(ValidationError):
            RouterManagementAccessRequest(
                api_secret='p"; :put [/system identity print]; #',
            )

    def test_rejects_semicolon_in_api_secret(self) -> None:
        with pytest.raises(ValidationError):
            RouterManagementAccessRequest(api_secret="password;reboot")

    def test_rejects_bad_charset_in_api_username(self) -> None:
        with pytest.raises(ValidationError):
            RouterManagementAccessRequest(api_username='admin"]')

    def test_rejects_backslash_and_dollar(self) -> None:
        with pytest.raises(ValidationError):
            RouterManagementAccessRequest(api_secret="pa\\ssword")
        with pytest.raises(ValidationError):
            RouterManagementAccessRequest(api_secret="$RandomVar")

    def test_accepts_generated_url_safe_secret(self) -> None:
        # secrets.token_urlsafe()'s alphabet (A-Za-z0-9-_) is exactly the
        # shape RouterService actually generates -- must keep working.
        request = RouterManagementAccessRequest(
            api_secret="AbC123-_xyZ", api_username="cloudguest-api"
        )
        assert request.api_secret == "AbC123-_xyZ"

    def test_accepts_none(self) -> None:
        # Unset stays unset -- the validator must not choke on the common
        # "not touching this field" case.
        request = RouterManagementAccessRequest(api_secret=None)
        assert request.api_secret is None


class TestRouterOsScriptEscaping:
    """``GatewayDeviceCredentialRotator.rotate_password`` builds a RouterOS
    console script by interpolating ``username``/``new_password`` into
    double-quoted string literals. These tests prove a value containing
    ``"`` and ``;`` cannot break out of the intended single command, i.e.
    that the escaping layer holds even if it were ever reached with a
    value the schema-level charset allowlist should have already
    rejected (defense in depth)."""

    @staticmethod
    def _parse_quoted_routeros_string(script: str, *, after: str) -> tuple[str, str]:
        """Finds ``after`` (e.g. ``password="``) in ``script``, then walks
        forward RouterOS-escaping-aware (``\\\\`` and ``\\"`` are literal
        escapes) to find the *true* closing ``"``. Returns
        ``(recovered_value, remainder_after_closing_quote)`` -- a naive
        "find the next literal double-quote" parse would be fooled by an
        improperly-escaped value exactly the way this test guards
        against."""
        start = script.index(after) + len(after)
        i = start
        recovered: list[str] = []
        while i < len(script):
            ch = script[i]
            if ch == "\\" and i + 1 < len(script):
                recovered.append(script[i + 1])
                i += 2
                continue
            if ch == '"':
                return "".join(recovered), script[i + 1 :]
            recovered.append(ch)
            i += 1
        raise AssertionError("unterminated RouterOS string literal in script")

    async def test_double_quote_and_semicolon_cannot_break_out_of_command(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.domains.router import device_credential_rotator as rotator_module
        from app.domains.router.device_adapters import RawCommandResult

        malicious_password = 'x"; /user remove [find]; :put "pwned'
        captured: dict[str, object] = {}

        async def fake_execute_live_command(
            *, host: str, username: str, password: str, command: str
        ):
            captured["host"] = host
            captured["username"] = username
            captured["password"] = password
            captured["command"] = command
            return RawCommandResult(
                command=command, stdout="", stderr="", exit_status=0
            )

        monkeypatch.setattr(
            rotator_module, "execute_live_command", fake_execute_live_command
        )
        rotator = rotator_module.GatewayDeviceCredentialRotator()
        await rotator.rotate_password(
            host="10.0.0.1",
            username="cloudguest-api",
            old_password="old-secret",
            new_password=malicious_password,
        )

        script = captured["command"]
        assert isinstance(script, str)
        # Exactly one RouterOS statement -- a real semicolon-separated
        # second command would show up as more than one top-level `/`
        # command in the script.
        assert script.count("/user set") == 1

        recovered_password, remainder = self._parse_quoted_routeros_string(
            script, after='password="'
        )
        assert recovered_password == malicious_password
        # Nothing but the trailing newline may follow the closing quote --
        # if the malicious `"` had closed the literal early, `remainder`
        # would instead start with `; /user remove [find]; :put "pwned"`.
        assert remainder.strip() == ""

    async def test_double_quote_in_username_cannot_break_out_of_command(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.domains.router import device_credential_rotator as rotator_module
        from app.domains.router.device_adapters import RawCommandResult

        malicious_username = 'admin"] ; /user remove [find'
        captured: dict[str, object] = {}

        async def fake_execute_live_command(
            *, host: str, username: str, password: str, command: str
        ):
            captured["command"] = command
            return RawCommandResult(
                command=command, stdout="", stderr="", exit_status=0
            )

        monkeypatch.setattr(
            rotator_module, "execute_live_command", fake_execute_live_command
        )
        rotator = rotator_module.GatewayDeviceCredentialRotator()
        await rotator.rotate_password(
            host="10.0.0.1",
            username=malicious_username,
            old_password="old-secret",
            new_password="NewSecret123",
        )

        script = captured["command"]
        assert isinstance(script, str)
        assert script.count("/user set") == 1
        recovered_username, _ = self._parse_quoted_routeros_string(
            script, after='find name="'
        )
        assert recovered_username == malicious_username

    def test_escape_helper_handles_backslash_quote_and_dollar(self) -> None:
        from app.domains.router.device_credential_rotator import (
            _escape_routeros_string,
        )

        assert _escape_routeros_string('a"b') == 'a\\"b'
        assert _escape_routeros_string("a\\b") == "a\\\\b"
        assert _escape_routeros_string("$var") == "\\$var"
        assert _escape_routeros_string('mix\\ed"$val;ue') == 'mix\\\\ed\\"\\$val;ue'


# ============================================================================
# management_ip_address/public_ip_address: format validation
#
# These values are later used as a literal `host` in an outbound request
# (router.py's WebFig proxy: `f"http://{host}/{path}"`), so an unvalidated
# value is a request-forgery-shaped risk, not just a data-quality one.
# ============================================================================


class TestHostAddressValidation:
    def test_create_request_rejects_garbage_management_ip_address(self) -> None:
        with pytest.raises(ValidationError):
            RouterCreateRequest(
                **_create_kwargs(), management_ip_address="not an ip; rm -rf /"
            )

    def test_create_request_rejects_url_shaped_public_ip_address(self) -> None:
        with pytest.raises(ValidationError):
            RouterCreateRequest(
                **_create_kwargs(),
                public_ip_address="10.0.0.1:8080@evil.example.com",
            )

    def test_create_request_accepts_valid_ipv4(self) -> None:
        request = RouterCreateRequest(
            **_create_kwargs(), management_ip_address="10.0.0.1"
        )
        assert request.management_ip_address == "10.0.0.1"

    def test_create_request_accepts_valid_ipv6(self) -> None:
        request = RouterCreateRequest(
            **_create_kwargs(), public_ip_address="2001:db8::1"
        )
        assert request.public_ip_address == "2001:db8::1"

    def test_create_request_accepts_valid_hostname(self) -> None:
        request = RouterCreateRequest(
            **_create_kwargs(), management_ip_address="router-01.local"
        )
        assert request.management_ip_address == "router-01.local"

    def test_update_request_rejects_garbage_management_ip_address(self) -> None:
        with pytest.raises(ValidationError):
            RouterUpdateRequest(management_ip_address="../../etc/passwd")

    def test_update_request_accepts_none(self) -> None:
        request = RouterUpdateRequest(
            management_ip_address=None, public_ip_address=None
        )
        assert request.management_ip_address is None
        assert request.public_ip_address is None

    def test_heartbeat_request_rejects_garbage_management_ip_address(self) -> None:
        with pytest.raises(ValidationError):
            HeartbeatRequest(management_ip_address="not-valid!!")

    def test_heartbeat_request_accepts_valid_ipv4(self) -> None:
        request = HeartbeatRequest(management_ip_address="192.168.1.1")
        assert request.management_ip_address == "192.168.1.1"


class TestSweepRouterReachability:
    """The FAST outage path, and the guards that keep a two-minute
    threshold from crying wolf.

    Context these tests are written against, from production on
    2026-09-07: a real router at a real venue went down twice inside 35
    minutes (03:50-04:12 and again from 04:16). Five minutes into the first
    outage the dashboard still said ``online``, because ``Router.status``
    only moves at the shared 15-minute
    ``ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES``. Nobody was emailed at all.
    Meanwhile the ``/agent/authorized-macs`` poll -- every 60 seconds --
    had stopped within a minute of the site going away, both times. This
    sweep reads that signal.
    """

    async def _router(
        self,
        service,
        location_lookup,
        org_lookup,
        repo,
        *,
        agent_contact,
        status: str = RouterStatus.ONLINE.value,
        reachability_state: str | None = None,
        misses: int = 0,
        hits: int = 0,
    ) -> Router:
        organization = org_lookup.add()
        location = location_lookup.add(organization_id=organization.id)
        router = await service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            **_create_kwargs(
                serial_number=f"SN-{uuid.uuid4()}",
                mac_address=_unique_mac(),
            ),
        )
        router.status = status
        router.reachability_state = reachability_state
        router.reachability_consecutive_misses = misses
        router.reachability_consecutive_hits = hits
        if agent_contact is not None:
            repo.agent_contact[router.id] = agent_contact
        return router

    @staticmethod
    def _awake(now: datetime) -> datetime:
        """A ``previous_sweep_at`` that satisfies the awake-window guard --
        i.e. the platform was demonstrably running one interval ago."""
        return now - timedelta(seconds=ROUTER_REACHABILITY_SWEEP_INTERVAL_SECONDS)

    async def test_a_silent_router_is_declared_unreachable_within_two_minutes(
        self,
    ) -> None:
        """THE HEADLINE REQUIREMENT, expressed as a clock.

        Two consecutive misses at a 30-second cadence, against a 90-second
        silence window, puts the UNREACHABLE verdict on the board no later
        than ~120s after the site went quiet. The alert evaluation sweep
        (also 30s) then has it as an ``Alert`` and an email inside the
        founder's two minutes.
        """
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(
            service, loc, org, repo, agent_contact=now - timedelta(seconds=100)
        )

        first = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now)
        )
        assert first["marked_unreachable"] == 0, "one miss must not be enough"
        assert repo.routers[router.id].reachability_state is None

        later = now + timedelta(seconds=ROUTER_REACHABILITY_SWEEP_INTERVAL_SECONDS)
        second = await service.sweep_router_reachability(
            now=later, previous_sweep_at=self._awake(later)
        )

        assert second["marked_unreachable"] == 1
        assert (
            repo.routers[router.id].reachability_state
            == RouterReachabilityState.UNREACHABLE.value
        )

    async def test_a_single_missed_poll_never_alerts(self) -> None:
        """A dropped packet, a 502 during a release, a worker running a
        second late -- one miss is noise, and the debounce exists so noise
        does not reach a venue owner's inbox."""
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(
            service, loc, org, repo, agent_contact=now - timedelta(seconds=100)
        )

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now)
        )

        assert result["silent"] == 1
        assert result["marked_unreachable"] == 0
        assert repo.routers[router.id].reachability_consecutive_misses == 1

    async def test_a_router_still_polling_us_is_reachable(self) -> None:
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(
            service, loc, org, repo, agent_contact=now - timedelta(seconds=20)
        )

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now)
        )

        assert result["silent"] == 0
        assert (
            repo.routers[router.id].reachability_state
            == RouterReachabilityState.REACHABLE.value
        )

    async def test_our_own_downtime_does_not_declare_the_fleet_unreachable(
        self,
    ) -> None:
        """THE DEPLOY GUARD.

        On 2026-09-07 the api container restarted at 03:49:19. Any sweep
        that reasoned across that gap would have seen every router in the
        fleet as silent -- because nothing was listening -- and paged every
        venue we have. Absence may only be judged over a window we can
        prove we were awake for.
        """
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(
            service, loc, org, repo, agent_contact=now - timedelta(minutes=10)
        )

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=now - timedelta(minutes=9)
        )

        assert result["skipped_platform_gap"] == 1
        assert result["marked_unreachable"] == 0
        assert repo.routers[router.id].reachability_state is None
        assert (
            repo.routers[router.id].reachability_consecutive_misses == 0
        ), "a window we slept through must not even count as a miss"

    async def test_a_first_ever_run_judges_nobody(self) -> None:
        """No recorded previous sweep means a cold worker. Failing safe
        costs one 30-second cycle; failing open costs an email to every
        venue on the platform."""
        service, repo, loc, org, _audit = make_service()
        now = _now()
        await self._router(
            service, loc, org, repo, agent_contact=now - timedelta(minutes=10)
        )

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=None
        )

        assert result["skipped_platform_gap"] == 1
        assert result["marked_unreachable"] == 0

    async def test_most_of_the_fleet_going_quiet_at_once_is_read_as_our_fault(
        self,
    ) -> None:
        """Four venues do not lose power in the same 30-second window. Our
        broker, our hub, or our network does."""
        service, repo, loc, org, _audit = make_service()
        now = _now()
        for _ in range(4):
            await self._router(
                service, loc, org, repo, agent_contact=now - timedelta(seconds=200)
            )

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now)
        )

        assert result["silent"] == 4
        assert result["skipped_fleet_outage"] == 4
        assert result["marked_unreachable"] == 0

    async def test_the_fleet_guard_does_not_silence_a_small_deployment(self) -> None:
        """With two routers deployed, "half the fleet is silent" is just
        "one real venue is down" -- which is precisely the alert this
        feature exists to send. The guard must not swallow it."""
        service, repo, loc, org, _audit = make_service()
        now = _now()
        down = await self._router(
            service,
            loc,
            org,
            repo,
            agent_contact=now - timedelta(seconds=200),
            misses=1,
        )
        await self._router(
            service, loc, org, repo, agent_contact=now - timedelta(seconds=10)
        )

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now)
        )

        assert result["skipped_fleet_outage"] == 0
        assert result["marked_unreachable"] == 1
        assert (
            repo.routers[down.id].reachability_state
            == RouterReachabilityState.UNREACHABLE.value
        )

    async def test_a_live_tunnel_withholds_the_alert(self) -> None:
        """Silent to us but the tunnel is still handshaking = our agent
        script is broken, not their power. Alerting here would send a venue
        owner to check a plug that is already in the wall."""
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(
            service,
            loc,
            org,
            repo,
            agent_contact=now - timedelta(seconds=200),
            misses=1,
        )

        async def probe(routers):
            return {r.id: True for r in routers}

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now), tunnel_probe=probe
        )

        assert result["tunnel_alive_despite_silence"] == 1
        assert result["marked_unreachable"] == 0
        assert repo.routers[router.id].reachability_state != (
            RouterReachabilityState.UNREACHABLE.value
        )

    async def test_a_dead_tunnel_confirms_the_alert(self) -> None:
        """Both signals agree. This is the 2026-09-07 shape exactly: agent
        polls stopped, and port 8728 went from 24ms to an 8-second
        timeout."""
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(
            service,
            loc,
            org,
            repo,
            agent_contact=now - timedelta(seconds=200),
            misses=1,
        )

        async def probe(routers):
            return {r.id: False for r in routers}

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now), tunnel_probe=probe
        )

        assert result["marked_unreachable"] == 1
        assert (
            repo.routers[router.id].reachability_state
            == RouterReachabilityState.UNREACHABLE.value
        )

    async def test_a_probe_that_raises_never_blocks_the_alert(self) -> None:
        """The confirmation is allowed to withhold an alert, never to
        prevent one by failing. A hub bridge that is down must degrade to
        absence-alone, which is the no-probe behaviour."""
        service, repo, loc, org, _audit = make_service()
        now = _now()
        await self._router(
            service,
            loc,
            org,
            repo,
            agent_contact=now - timedelta(seconds=200),
            misses=1,
        )

        async def probe(routers):
            raise RuntimeError("hub bridge unreachable")

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now), tunnel_probe=probe
        )

        assert result["marked_unreachable"] == 1

    async def test_a_flapping_router_does_not_resolve_on_first_contact(self) -> None:
        """THE FLAP GUARD, against the real night.

        The router came back at 04:12 and went down again at 04:16.
        Resolving on the first successful poll would have emailed "it's
        back" at 04:13 and "it's down" again at 04:18 -- four emails for
        one bad night. The alert must stay open until the site has held on.
        """
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(
            service,
            loc,
            org,
            repo,
            agent_contact=now - timedelta(seconds=5),
            reachability_state=RouterReachabilityState.UNREACHABLE.value,
        )

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now)
        )

        assert result["marked_reachable"] == 0
        assert (
            repo.routers[router.id].reachability_state
            == RouterReachabilityState.UNREACHABLE.value
        ), "still unreachable, so the open alert stays open and sends nothing"
        assert repo.routers[router.id].reachability_consecutive_hits == 1

    async def test_a_router_that_stays_up_eventually_resolves(self) -> None:
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(
            service,
            loc,
            org,
            repo,
            agent_contact=now - timedelta(seconds=5),
            reachability_state=RouterReachabilityState.UNREACHABLE.value,
            hits=ROUTER_REACHABILITY_HITS_TO_RESOLVE - 1,
        )

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now)
        )

        assert result["marked_reachable"] == 1
        assert (
            repo.routers[router.id].reachability_state
            == RouterReachabilityState.REACHABLE.value
        )

    async def test_going_down_again_resets_the_recovery_counter(self) -> None:
        """The half of the flap guard that makes it a guard rather than a
        delay: partial recovery earns no credit toward being called back."""
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(
            service,
            loc,
            org,
            repo,
            agent_contact=now - timedelta(seconds=200),
            reachability_state=RouterReachabilityState.UNREACHABLE.value,
            hits=ROUTER_REACHABILITY_HITS_TO_RESOLVE - 1,
        )

        await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now)
        )

        assert repo.routers[router.id].reachability_consecutive_hits == 0
        assert (
            repo.routers[router.id].reachability_state
            == RouterReachabilityState.UNREACHABLE.value
        )

    async def test_a_router_with_no_usable_agent_credential_is_never_judged(
        self,
    ) -> None:
        """An expired or revoked credential makes ``CurrentAgent`` raise
        before it stamps anything, so such a router looks permanently
        silent. Alerting on it would blame a venue's power for our own
        credential lifecycle -- and it would never stop."""
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(service, loc, org, repo, agent_contact=None)

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now)
        )

        assert result["considered"] == 0
        assert repo.routers[router.id].reachability_state is None

    async def test_administrative_states_are_never_judged(self) -> None:
        """A venue we suspended or decommissioned on purpose must not email
        anybody at 3am about being off. Same reasoning
        ``stale_heartbeat_statement`` gives for leaving PROVISIONING
        alone."""
        service, repo, loc, org, _audit = make_service()
        now = _now()
        for status in (
            RouterStatus.SUSPENDED.value,
            RouterStatus.DECOMMISSIONED.value,
            RouterStatus.PENDING_PROVISIONING.value,
        ):
            await self._router(
                service,
                loc,
                org,
                repo,
                agent_contact=now - timedelta(hours=5),
                status=status,
            )

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now)
        )

        assert result["considered"] == 0

    async def test_one_router_failing_never_aborts_the_sweep(self) -> None:
        """The same per-router isolation contract
        ``sweep_stale_heartbeats`` documents, in the sweep that now sits on
        the critical path for every outage email."""
        service, repo, loc, org, _audit = make_service()
        now = _now()
        broken = await self._router(
            service,
            loc,
            org,
            repo,
            agent_contact=now - timedelta(seconds=200),
            misses=1,
        )
        healthy = await self._router(
            service,
            loc,
            org,
            repo,
            agent_contact=now - timedelta(seconds=200),
            misses=1,
        )

        original_update = repo.update_router

        async def exploding_update(router, data):
            if router.id == broken.id:
                raise RuntimeError("row is wedged")
            return await original_update(router, data)

        repo.update_router = exploding_update

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now)
        )

        assert result["failed"] == 1
        assert result["marked_unreachable"] == 1
        assert (
            repo.routers[healthy.id].reachability_state
            == RouterReachabilityState.UNREACHABLE.value
        )

    async def test_the_shared_offline_definition_is_left_completely_alone(
        self,
    ) -> None:
        """THE CONSTRAINT THAT SHAPED THIS WHOLE DESIGN.

        ``ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES`` is read by
        ``compute_lifecycle_stage``, ``compute_internet_availability`` and
        the frontend's ``location-liveness`` module, and
        ``sweep_stale_heartbeats``'s docstring says a second, slightly
        different definition of "offline" is how two screens start
        disagreeing about one router. So the fast path had to be a new
        column with a new name, not a faster threshold on the old one --
        and this test fails the moment somebody "simplifies" it back.
        """
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(
            service, loc, org, repo, agent_contact=now - timedelta(seconds=200)
        )
        router.last_seen_at = now - timedelta(seconds=200)
        router.health_status = RouterHealthStatus.HEALTHY.value

        for tick in range(ROUTER_REACHABILITY_MISSES_TO_ALERT):
            moment = now + timedelta(
                seconds=ROUTER_REACHABILITY_SWEEP_INTERVAL_SECONDS * tick
            )
            await service.sweep_router_reachability(
                now=moment, previous_sweep_at=self._awake(moment)
            )

        stored = repo.routers[router.id]
        assert (
            stored.reachability_state == RouterReachabilityState.UNREACHABLE.value
        ), "the fast verdict is in"
        assert (
            stored.status == RouterStatus.ONLINE.value
        ), "but Router.status is untouched -- it belongs to the 15-minute sweep"
        assert stored.health_status == RouterHealthStatus.HEALTHY.value
        assert stored.last_seen_at == now - timedelta(seconds=200)

    async def test_a_live_tunnel_also_never_resolves_an_open_outage(self) -> None:
        """The other direction of the same abstention.

        A router already declared UNREACHABLE, still not talking to us, but
        whose tunnel has come back must not accumulate recovery credit.
        Letting it would eventually mail "back online and has stayed up"
        about a site we have not heard a word from -- a sentence we would
        have no evidence for.
        """
        service, repo, loc, org, _audit = make_service()
        now = _now()
        router = await self._router(
            service,
            loc,
            org,
            repo,
            agent_contact=now - timedelta(seconds=200),
            reachability_state=RouterReachabilityState.UNREACHABLE.value,
            hits=ROUTER_REACHABILITY_HITS_TO_RESOLVE - 1,
        )

        async def probe(routers):
            return {r.id: True for r in routers}

        result = await service.sweep_router_reachability(
            now=now, previous_sweep_at=self._awake(now), tunnel_probe=probe
        )

        assert result["tunnel_alive_despite_silence"] == 1
        assert result["marked_reachable"] == 0
        stored = repo.routers[router.id]
        assert stored.reachability_state == RouterReachabilityState.UNREACHABLE.value
        assert stored.reachability_consecutive_hits == (
            ROUTER_REACHABILITY_HITS_TO_RESOLVE - 1
        ), "untouched -- we abstained, we did not vote"


class TestReachabilitySweepIsActuallyScheduled:
    """A sweep that is registered but absent from ``beat_schedule``, or
    scheduled under a task name nothing registered, never runs -- and it
    fails exactly as silently as a fleet that is entirely healthy.

    That is not hypothetical here. The whole reason this feature was needed
    is that ``AlertService.evaluate_alert_rules`` sat fully built and
    dormant for a long time, and that ``sweep_stale_heartbeats`` -- the only
    writer of ONLINE -> OFFLINE -- did not exist at all while every screen
    happily reported ``online``. Both halves are asserted, and that they
    name the same task.
    """

    def test_the_sweep_is_registered_and_scheduled_under_the_same_name(self) -> None:
        import app.domains.router.tasks  # noqa: F401 -- registers the task
        from app.core.celery_app import celery_app
        from app.domains.router.constants import (
            TASK_RUN_ROUTER_REACHABILITY_SWEEP,
        )

        entry = celery_app.conf.beat_schedule.get("router-reachability-sweep")
        assert entry is not None, "the fast outage path has no Beat entry"
        assert entry["task"] == TASK_RUN_ROUTER_REACHABILITY_SWEEP
        assert entry["schedule"] == ROUTER_REACHABILITY_SWEEP_INTERVAL_SECONDS
        assert (
            TASK_RUN_ROUTER_REACHABILITY_SWEEP in celery_app.tasks
        ), "scheduled under a task name nothing registered"

    def test_the_two_minute_budget_still_adds_up(self) -> None:
        """The founder's number, as arithmetic rather than as a comment.

        Detection is (misses required) x (sweep interval), plus up to one
        more interval of silence before the first miss is even observed;
        the alert evaluation sweep then adds its own interval before the
        email goes out. If somebody widens any of these three constants,
        this fails rather than quietly turning two minutes into six.
        """
        from app.domains.monitoring.constants import (
            ALERT_RULE_EVALUATION_SWEEP_INTERVAL_SECONDS,
        )

        worst_case_seconds = (
            ROUTER_REACHABILITY_SILENCE_SECONDS
            + ROUTER_REACHABILITY_MISSES_TO_ALERT
            * ROUTER_REACHABILITY_SWEEP_INTERVAL_SECONDS
            + ALERT_RULE_EVALUATION_SWEEP_INTERVAL_SECONDS
        )
        assert worst_case_seconds <= 180, (
            f"detection-to-email worst case is now {worst_case_seconds}s; the "
            "founder asked for two minutes and this budget no longer fits it"
        )

    def test_the_recovery_window_is_long_enough_to_absorb_a_flap(self) -> None:
        """The 2026-09-07 router was back for four minutes before it went
        down again. The recovery window has to be comfortably longer than
        that, or the flap guard is decorative."""
        recovery_seconds = (
            ROUTER_REACHABILITY_HITS_TO_RESOLVE
            * ROUTER_REACHABILITY_SWEEP_INTERVAL_SECONDS
        )
        assert recovery_seconds >= 300, (
            f"recovery needs only {recovery_seconds}s of uptime; the real "
            "outage came back for ~4 minutes before dropping again"
        )


# ============================================================================
# Router update audit detail -- what actually changed
# ============================================================================


def _router_updated_entries(audit: FakeAuditLogWriter) -> list[dict[str, object]]:
    return [e for e in audit.entries if e["action"] == "router_updated"]


def _only_router_updated_entry(audit: FakeAuditLogWriter) -> dict[str, object]:
    entries = _router_updated_entries(audit)
    assert len(entries) == 1, entries
    return entries[0]


def _changes_of(entry: dict[str, object]) -> dict[str, dict[str, object]]:
    """The change set as the audit reader sees it.

    ``FakeAuditLogWriter`` records the kwargs ``_audit`` passes through, so
    the metadata lives under ``event_metadata`` -- the column name, not the
    ``metadata=`` parameter name ``RouterService._audit`` takes.
    """
    metadata = entry["event_metadata"]
    assert isinstance(metadata, dict), metadata
    assert set(metadata) == {"changes"}, metadata
    changes = metadata["changes"]
    assert isinstance(changes, dict), changes
    return changes


def _redacted_keys(changes: dict[str, dict[str, object]], *stems: str) -> list[str]:
    """Keys recorded as redacted whose name contains one of ``stems``.

    The service renames ``api_secret`` to ``api_credentials_encrypted`` on
    its way to the column, so the audited key may be either spelling. What
    matters for this suite is that *some* key names the field and that its
    value carries no ``from``/``to``.
    """
    return [
        key
        for key, delta in changes.items()
        if delta == {"redacted": True} and any(stem in key for stem in stems)
    ]


async def _audited_router(
    repo: FakeRouterRepository,
    organization_id: uuid.UUID,
    **attributes: object,
) -> Router:
    """A router with ``attributes`` forced on directly.

    ``Router.vendor`` carries a SQLAlchemy column ``default``, which fires on
    INSERT and never on plain instantiation -- and these fakes never reach a
    database. A router built by ``make_router`` therefore has ``vendor is
    None``, which is not the state any of these tests are about.
    """
    router_device = await make_router(
        repo, location_id=uuid.uuid4(), organization_id=organization_id
    )
    for key, value in attributes.items():
        setattr(router_device, key, value)
    return router_device


class TestRouterUpdateAuditDetail:
    """``router_updated`` has to say what changed, not merely that something did.

    On 2026-09-10 seven routers were silently relabelled to ``tplink_omada``.
    The audit trail recorded the fact of each update and nothing else --
    ``Router 'X' updated``, with ``event_metadata`` an empty ``{}`` -- so
    there was no way to learn from the log which field had moved or what it
    had moved from. Recovering the old vendor values meant diffing the
    database by hand against a backup.

    So the update audit now carries a change set: every field that actually
    moved, with its before and after, and a human-readable summary in the
    description so the answer is visible without opening the metadata. The
    hard constraint is that gaining this detail must not turn the audit log
    into a place secrets are written down -- see the redaction tests below,
    which are the load-bearing half of this class.
    """

    async def test_a_vendor_change_records_the_old_and_the_new_vendor(self) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(repo, organization.id, vendor="mikrotik")

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"vendor": "tplink_omada"},
        )

        entry = _only_router_updated_entry(audit)
        assert _changes_of(entry)["vendor"] == {
            "from": "mikrotik",
            "to": "tplink_omada",
        }
        # The bit a human sees without opening the metadata column -- the
        # 2026-09-10 investigation never got that far.
        assert "vendor mikrotik -> tplink_omada" in entry["description"]

    async def test_the_description_names_the_router_and_lists_the_change(self) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(repo, organization.id, vendor="mikrotik")

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"vendor": "tplink_omada"},
        )

        entry = _only_router_updated_entry(audit)
        assert entry["description"] == (
            "Router 'Front Desk AP' updated: vendor mikrotik -> tplink_omada"
        )

    async def test_a_multi_field_update_records_every_field_that_moved(self) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(
            repo,
            organization.id,
            vendor="mikrotik",
            management_ip_address="10.0.0.1",
        )

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={
                "name": "Office Guest",
                "vendor": "tplink_omada",
                "management_ip_address": "10.0.9.9",
            },
        )

        entry = _only_router_updated_entry(audit)
        changes = _changes_of(entry)
        assert changes["name"] == {"from": "Front Desk AP", "to": "Office Guest"}
        assert changes["vendor"] == {"from": "mikrotik", "to": "tplink_omada"}
        assert changes["management_ip_address"] == {
            "from": "10.0.0.1",
            "to": "10.0.9.9",
        }

    async def test_the_description_names_every_field_of_a_multi_field_update(
        self,
    ) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(
            repo,
            organization.id,
            vendor="mikrotik",
            management_ip_address="10.0.0.1",
        )

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={
                "name": "Office Guest",
                "vendor": "tplink_omada",
                "management_ip_address": "10.0.9.9",
            },
        )

        description = _only_router_updated_entry(audit)["description"]
        # The new name, because the description describes the router as it
        # now stands and the change list says where it came from.
        assert description.startswith("Router 'Office Guest' updated: ")
        assert "name 'Front Desk AP' -> 'Office Guest'" in description
        assert "vendor mikrotik -> tplink_omada" in description
        assert "management_ip_address 10.0.0.1 -> 10.0.9.9" in description

    async def test_an_update_that_changes_nothing_records_an_empty_change_set(
        self,
    ) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(repo, organization.id, vendor="mikrotik")

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"name": router_device.name},
        )

        assert _changes_of(_only_router_updated_entry(audit)) == {}

    async def test_an_update_that_changes_nothing_says_so_without_a_field_list(
        self,
    ) -> None:
        """A trailing ``: `` with nothing after it reads as a truncated log."""
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(repo, organization.id, vendor="mikrotik")

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"name": router_device.name},
        )

        description = _only_router_updated_entry(audit)["description"]
        assert description == "Router 'Front Desk AP' updated"
        assert ":" not in description

    async def test_an_api_secret_never_reaches_any_audit_entry(self) -> None:
        """The load-bearing one: detail must not become disclosure."""
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(repo, organization.id, vendor="mikrotik")

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"api_secret": "sup3r-s3cret-value", "vendor": "tplink_omada"},
        )

        assert audit.entries
        for entry in audit.entries:
            serialized = json.dumps(entry, default=str)
            assert "sup3r-s3cret-value" not in serialized, entry

    async def test_an_api_secret_change_is_named_but_carries_no_value(self) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(repo, organization.id, vendor="mikrotik")

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"api_secret": "sup3r-s3cret-value", "vendor": "tplink_omada"},
        )

        changes = _changes_of(_only_router_updated_entry(audit))
        named = _redacted_keys(changes, "api_secret", "api_credentials")
        assert named, changes
        for key in named:
            assert changes[key] == {"redacted": True}
            assert "from" not in changes[key]
            assert "to" not in changes[key]

    async def test_a_non_secret_field_changed_alongside_a_secret_is_still_recorded(
        self,
    ) -> None:
        """Redaction is per field. One secret in the payload must not blank
        out the rest of the change set -- that would reproduce the 2026-09-10
        blindness for any update that happened to rotate a credential."""
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(repo, organization.id, vendor="mikrotik")

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"api_secret": "sup3r-s3cret-value", "vendor": "tplink_omada"},
        )

        entry = _only_router_updated_entry(audit)
        assert _changes_of(entry)["vendor"] == {
            "from": "mikrotik",
            "to": "tplink_omada",
        }
        assert "vendor mikrotik -> tplink_omada" in entry["description"]

    async def test_an_snmp_community_never_reaches_any_audit_entry(self) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(repo, organization.id, vendor="mikrotik")

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"snmp_community": "sup3r-s3cret-value", "vendor": "tplink_omada"},
        )

        assert audit.entries
        for entry in audit.entries:
            serialized = json.dumps(entry, default=str)
            assert "sup3r-s3cret-value" not in serialized, entry

    async def test_an_snmp_community_change_is_named_but_carries_no_value(self) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(repo, organization.id, vendor="mikrotik")

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"snmp_community": "sup3r-s3cret-value", "vendor": "tplink_omada"},
        )

        changes = _changes_of(_only_router_updated_entry(audit))
        named = _redacted_keys(changes, "snmp_community")
        assert named, changes
        for key in named:
            assert changes[key] == {"redacted": True}
        assert changes["vendor"] == {"from": "mikrotik", "to": "tplink_omada"}

    async def test_the_encrypted_columns_never_carry_a_from_or_a_to(self) -> None:
        """Fernet ciphertext is still the secret, just wearing a hat. The
        column the service actually writes is the encrypted one, so the
        redaction has to hold at that spelling and not only at the
        write-only ``api_secret``/``snmp_community`` request fields."""
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(repo, organization.id, vendor="mikrotik")

        await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={
                "api_secret": "sup3r-s3cret-value",
                "snmp_community": "public-ish-but-still-a-credential",
                "vendor": "tplink_omada",
            },
        )

        encrypted_columns = ("api_credentials_encrypted", "snmp_community_encrypted")
        for entry in _router_updated_entries(audit):
            changes = _changes_of(entry)
            for column in encrypted_columns:
                delta = changes.get(column)
                if delta is None:
                    continue
                assert "from" not in delta, (column, delta)
                assert "to" not in delta, (column, delta)
                assert delta == {"redacted": True}, (column, delta)

    async def test_the_stored_ciphertext_itself_never_appears_in_an_entry(self) -> None:
        service, repo, _location_lookup, org_lookup, audit = make_service()
        organization = org_lookup.add()
        router_device = await _audited_router(repo, organization.id, vendor="mikrotik")

        updated = await service.update_router(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
            data={"api_secret": "sup3r-s3cret-value"},
        )
        ciphertext = updated.api_credentials_encrypted
        assert ciphertext  # the service really did store something

        for entry in audit.entries:
            assert ciphertext not in json.dumps(entry, default=str), entry


class TestRouterFieldChangeHelpers:
    """``router_field_changes``/``describe_router_changes`` on their own.

    The service tests above prove the wiring; these pin the encoding, so a
    future refactor of the helpers cannot quietly change what the audit log
    means. Same 2026-09-10 incident -- see ``TestRouterUpdateAuditDetail``.
    """

    def test_an_unchanged_field_is_absent_rather_than_recorded_as_equal(self) -> None:
        changes = router_field_changes(
            {"name": "Lobby AP", "vendor": "mikrotik"},
            {"name": "Lobby AP", "vendor": "tplink_omada"},
        )
        assert "name" not in changes
        assert changes == {"vendor": {"from": "mikrotik", "to": "tplink_omada"}}

    def test_nothing_changed_is_an_empty_change_set(self) -> None:
        assert router_field_changes({"name": "Lobby AP"}, {"name": "Lobby AP"}) == {}

    def test_a_uuid_is_recorded_as_its_string_form(self) -> None:
        before_id = uuid.uuid4()
        after_id = uuid.uuid4()

        changes = router_field_changes({"tag": before_id}, {"tag": after_id})

        assert changes == {"tag": {"from": str(before_id), "to": str(after_id)}}
        json.dumps(changes)  # must survive the JSONB column as-is

    def test_a_datetime_is_recorded_as_its_string_form(self) -> None:
        before_at = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
        after_at = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)

        changes = router_field_changes(
            {"last_seen_at": before_at}, {"last_seen_at": after_at}
        )

        assert changes == {
            "last_seen_at": {"from": str(before_at), "to": str(after_at)}
        }
        json.dumps(changes)

    def test_a_field_arriving_from_none_records_none_not_a_missing_key(self) -> None:
        changes = router_field_changes(
            {"management_ip_address": None}, {"management_ip_address": "10.0.0.1"}
        )
        assert changes == {"management_ip_address": {"from": None, "to": "10.0.0.1"}}

    def test_a_field_cleared_to_none_is_still_a_recorded_change(self) -> None:
        changes = router_field_changes(
            {"management_ip_address": "10.0.0.1"}, {"management_ip_address": None}
        )
        assert changes == {"management_ip_address": {"from": "10.0.0.1", "to": None}}

    def test_none_renders_as_lowercase_none_in_the_description(self) -> None:
        changes = router_field_changes(
            {"management_ip_address": None}, {"management_ip_address": "10.0.0.1"}
        )
        assert (
            describe_router_changes(changes) == "management_ip_address none -> 10.0.0.1"
        )

    def test_only_a_value_containing_a_space_is_quoted(self) -> None:
        changes = router_field_changes(
            {"name": "Lobby AP", "vendor": "mikrotik"},
            {"name": "Office Guest", "vendor": "tplink_omada"},
        )
        assert describe_router_changes(changes) == (
            "name 'Lobby AP' -> 'Office Guest', vendor mikrotik -> tplink_omada"
        )

    def test_the_named_secret_fields_are_redacted_by_name_only(self) -> None:
        for field_name in (
            "api_secret",
            "api_credentials_encrypted",
            "snmp_community",
            "snmp_community_encrypted",
            "token_hash",
            "password",
            "secret",
            "token",
        ):
            assert field_name in REDACTED_ROUTER_FIELDS, field_name
            changes = router_field_changes({field_name: "old"}, {field_name: "new"})
            assert changes == {field_name: {"redacted": True}}, field_name
            assert "old" not in json.dumps(changes)
            assert "new" not in json.dumps(changes)

    def test_a_secret_looking_key_outside_the_explicit_set_is_still_redacted(
        self,
    ) -> None:
        """``radius_secret`` is not in the list and never will be until
        someone adds it. The stem match is what makes the redaction hold for
        the field nobody thought to enumerate."""
        assert "radius_secret" not in REDACTED_ROUTER_FIELDS

        changes = router_field_changes(
            {"radius_secret": "old-radius"}, {"radius_secret": "new-radius"}
        )

        assert changes == {"radius_secret": {"redacted": True}}
        assert "radius" not in json.dumps(changes).replace("radius_secret", "")

    def test_every_secret_stem_redacts_a_key_that_merely_contains_it(self) -> None:
        for stem in ("secret", "password", "token", "credentials", "community"):
            field_name = f"vendor_{stem}_field"
            changes = router_field_changes(
                {field_name: "leak-me"}, {field_name: "leak-me-too"}
            )
            assert changes == {field_name: {"redacted": True}}, field_name
            assert "leak-me" not in json.dumps(changes), field_name

    def test_a_redacted_field_says_the_value_is_not_recorded(self) -> None:
        changes = router_field_changes({"api_secret": "a"}, {"api_secret": "b"})
        assert (
            describe_router_changes(changes)
            == "api_secret changed (value not recorded)"
        )

    def test_settings_is_opaque_and_records_no_values(self) -> None:
        assert isinstance(OPAQUE_ROUTER_FIELDS, frozenset)
        assert set(OPAQUE_ROUTER_FIELDS) == {"settings"}

        changes = router_field_changes(
            {"settings": {"portal_theme": "dark"}},
            {"settings": {"portal_theme": "light", "quirks": ["omada"]}},
        )

        assert changes == {"settings": {"changed": True}}
        serialized = json.dumps(changes)
        assert "portal_theme" not in serialized
        assert "omada" not in serialized

    def test_unchanged_settings_are_absent_like_any_other_field(self) -> None:
        same = {"portal_theme": "dark"}
        assert router_field_changes({"settings": same}, {"settings": dict(same)}) == {}

    def test_settings_reads_as_changed_with_no_arrow(self) -> None:
        changes = router_field_changes({"settings": {}}, {"settings": {"a": 1}})
        assert describe_router_changes(changes) == "settings changed"

    def test_the_description_lists_fields_in_alphabetical_order(self) -> None:
        changes = router_field_changes(
            {
                "vendor": "mikrotik",
                "name": "Lobby AP",
                "api_secret": "old",
                "settings": {},
            },
            {
                "vendor": "tplink_omada",
                "name": "Office Guest",
                "api_secret": "new",
                "settings": {"a": 1},
            },
        )

        assert describe_router_changes(changes) == (
            "api_secret changed (value not recorded), "
            "name 'Lobby AP' -> 'Office Guest', "
            "settings changed, "
            "vendor mikrotik -> tplink_omada"
        )

    def test_the_ordering_does_not_follow_the_insertion_order_of_the_dicts(
        self,
    ) -> None:
        """Dicts preserve insertion order, so a description built by
        iterating one reads differently depending on which order the caller
        happened to pass the fields. Two orders, one string."""
        before = {"vendor": "mikrotik", "name": "Lobby AP"}
        after = {"vendor": "tplink_omada", "name": "Office Guest"}
        reversed_before = {"name": "Lobby AP", "vendor": "mikrotik"}
        reversed_after = {"name": "Office Guest", "vendor": "tplink_omada"}

        assert describe_router_changes(
            router_field_changes(before, after)
        ) == describe_router_changes(
            router_field_changes(reversed_before, reversed_after)
        )

    def test_an_empty_change_set_describes_as_the_empty_string(self) -> None:
        assert describe_router_changes({}) == ""


# ============================================================================
# FIX-PLAN D2 -- controller_state
# ============================================================================


@dataclass
class FakeIntegration:
    """Only what `controller_state_for` reads. Duck-typed on purpose: the
    derivation imports no ORM, which is what lets `readiness` and
    `monitoring` keep importing `vendor_capabilities`."""

    is_enabled: bool = True
    last_error_code: str | None = None
    external_site_id: str | None = "6aa3913c3ee1605f71ac35a1"
    router_id: uuid.UUID | None = field(default_factory=uuid.uuid4)
    last_sync_at: datetime | None = None


async def _controller_row(repo: FakeRouterRepository, **overrides: object) -> Router:
    """A genuine controller row: `tplink_omada` and NO agent evidence."""
    router_device = await make_router(
        repo,
        location_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        serial_number=f"SN-{uuid.uuid4()}",
        mac_address="AA:BB:CC:DD:EE:01",
    )
    router_device.vendor = "tplink_omada"
    for key, value in overrides.items():
        setattr(router_device, key, value)
    return router_device


class TestControllerStateIsNotASecondLivenessAnswer:
    """The constraint the whole field is built around.

    `Router.reachability_state` carries a comment forbidding its own
    exposure: "the moment a screen can render it, the platform has two
    answers to 'is this router up?' and they disagree for up to thirteen
    minutes." `controller_state` must not become that second answer, and the
    mechanism is that it has NO VALUE AT ALL on a row an agent manages.
    """

    async def test_an_agent_managed_row_has_no_controller_state(self) -> None:
        service, repo, _loc, _org, _audit = make_service()
        router_device = await make_router(
            repo, location_id=uuid.uuid4(), organization_id=uuid.uuid4()
        )
        (context,) = (await service.controller_context([router_device])).values()
        assert context.state is None
        assert context.reason is None
        assert context.last_contacted_at is None

    async def test_a_mislabelled_row_is_judged_on_its_evidence(self) -> None:
        """The 2026-09-10 mislabel, from this field's side. A row whose
        `vendor` says controller while it has heartbeated is agent-managed
        HERE TOO -- so `controller_state` can never contradict a heartbeat,
        and the two are never both populated on one row."""
        service, repo, _loc, _org, _audit = make_service()
        router_device = await _controller_row(
            repo, last_seen_at=datetime.now(UTC) - timedelta(days=2)
        )
        repo.integrations[router_device.id] = FakeIntegration()
        (context,) = (await service.controller_context([router_device])).values()
        assert context.state is None
        # ...and the contradiction is REPORTED rather than only routed
        # around, so the null above is explicable instead of looking like
        # "no integration".
        assert context.vendor_claim_is_contradicted is True

    async def test_a_genuine_controller_is_not_flagged_as_contradicted(self) -> None:
        service, repo, _loc, _org, _audit = make_service()
        router_device = await _controller_row(repo)
        repo.integrations[router_device.id] = FakeIntegration()
        (context,) = (await service.controller_context([router_device])).values()
        assert context.vendor_claim_is_contradicted is False
        assert context.state == "reachable"


class TestTheControllerStateLadder:
    @pytest.mark.parametrize(
        ("integration", "expected_state", "expected_reason"),
        [
            (None, "not_registered", "no_integration"),
            (FakeIntegration(is_enabled=False), "disabled", "integration_disabled"),
            (
                FakeIntegration(last_error_code="OMADA_AUTH_FAILED"),
                "credentials_rejected",
                "OMADA_AUTH_FAILED",
            ),
            (
                FakeIntegration(last_error_code="OMADA_TLS_UNTRUSTED"),
                "certificate_unverified",
                "OMADA_TLS_UNTRUSTED",
            ),
            # A certificate that CHANGED. Same state, different reason --
            # the operator's next action is identical (go and look at the
            # certificate) but the events are not, and failing loudly on a
            # changed one is the entire reason pinning was chosen.
            (
                FakeIntegration(last_error_code="OMADA_TLS_PIN_MISMATCH"),
                "certificate_unverified",
                "OMADA_TLS_PIN_MISMATCH",
            ),
            (
                FakeIntegration(last_error_code="OMADA_TIMEOUT"),
                "unreachable",
                "OMADA_TIMEOUT",
            ),
            (
                FakeIntegration(external_site_id=None),
                "not_mapped",
                "site_not_selected",
            ),
            (FakeIntegration(router_id=None), "not_mapped", "fleet_device_missing"),
            (FakeIntegration(), "reachable", "ok"),
        ],
    )
    async def test_the_first_matching_rung_wins(
        self,
        integration: object | None,
        expected_state: str,
        expected_reason: str,
    ) -> None:
        service, repo, _loc, _org, _audit = make_service()
        router_device = await _controller_row(repo)
        if integration is not None:
            repo.integrations[router_device.id] = integration
        (context,) = (await service.controller_context([router_device])).values()
        assert (context.state, context.reason) == (expected_state, expected_reason)

    async def test_a_disabled_integration_outranks_its_stale_error(self) -> None:
        """Precedence, not a lookup. Switched off is a deliberate answer to
        whatever the last error was, and an alert about something its owner
        turned off is one they learn to ignore."""
        service, repo, _loc, _org, _audit = make_service()
        router_device = await _controller_row(repo)
        repo.integrations[router_device.id] = FakeIntegration(
            is_enabled=False, last_error_code="OMADA_AUTH_FAILED"
        )
        (context,) = (await service.controller_context([router_device])).values()
        assert context.state == "disabled"

    async def test_a_capability_boundary_is_still_reachable(self) -> None:
        """A hotspot-operator login cannot read the controller's inventory,
        by design. A controller we are talking to and cannot list the
        devices of is still a controller we are talking to, and the captive
        portal it runs is unaffected -- so it is `reachable`, not a fault.
        The reason still carries the code."""
        service, repo, _loc, _org, _audit = make_service()
        router_device = await _controller_row(repo)
        repo.integrations[router_device.id] = FakeIntegration(
            last_error_code="OMADA_API_UNSUPPORTED"
        )
        (context,) = (await service.controller_context([router_device])).values()
        assert context.state == "reachable"
        assert context.reason == "OMADA_API_UNSUPPORTED"

    async def test_last_contacted_is_the_scheduled_sync_not_a_probe(self) -> None:
        """Both probe paths persist nothing, deliberately -- a manual probe
        is an operator action, and the scheduled sync is what "are we still
        reaching this controller" means. So `last_sync_at` is the only
        honest answer, and there is nothing more optimistic to prefer."""
        service, repo, _loc, _org, _audit = make_service()
        router_device = await _controller_row(repo)
        when = datetime.now(UTC) - timedelta(minutes=9)
        repo.integrations[router_device.id] = FakeIntegration(last_sync_at=when)
        (context,) = (await service.controller_context([router_device])).values()
        assert context.last_contacted_at == when


class TestControllerStateOnTheReadShape:
    @staticmethod
    def _shapes() -> tuple[type, type]:
        from app.domains.router.schemas import RouterPlatformResponse, RouterResponse

        return RouterResponse, RouterPlatformResponse

    def test_the_customer_shape_carries_it(self) -> None:
        """`GET /locations/{id}/routers` is the list the customer dashboard
        reads for venue liveness AND the list the Master fleet assembles
        itself from -- the one endpoint feeding the three surfaces that
        contradicted each other."""
        response_shape, _ = self._shapes()
        for name in (
            "controller_state",
            "controller_state_reason",
            "controller_last_contacted_at",
            "vendor_claim_is_contradicted",
        ):
            assert name in response_shape.model_fields

    def test_reachability_state_is_still_not_exposed(self) -> None:
        """The line this field must not cross. `Router.reachability_state`
        is an input to an alert, not a second status, and adding
        `controller_state` must not have made it feel safe to ship."""
        response_shape, platform_shape = self._shapes()
        assert "reachability_state" not in response_shape.model_fields
        assert "reachability_state" not in platform_shape.model_fields

    async def test_the_page_costs_one_query_not_one_per_row(self) -> None:
        service, repo, _loc, _org, _audit = make_service()
        rows = [await _controller_row(repo) for _ in range(5)]
        for row in rows:
            repo.integrations[row.id] = FakeIntegration()
        calls: list[int] = []
        original = repo.integrations_for_routers

        async def counting(router_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, object]:
            calls.append(len(router_ids))
            return await original(router_ids)

        repo.integrations_for_routers = counting  # type: ignore[assignment]
        contexts = await service.controller_context(rows)
        assert calls == [5]
        assert all(c.state == "reachable" for c in contexts.values())

    async def test_an_all_mikrotik_page_asks_the_integration_table_nothing(
        self,
    ) -> None:
        """`CONTROLLER_MANAGED_VENDORS` holds one vendor and most venues are
        MikroTik, so the common page must cost nothing extra at all."""
        service, repo, _loc, _org, _audit = make_service()
        rows = [
            await make_router(
                repo,
                location_id=uuid.uuid4(),
                organization_id=uuid.uuid4(),
                serial_number=f"SN-{uuid.uuid4()}",
                mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
            )
            for i in range(3)
        ]
        called = False

        async def explode(router_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, object]:
            nonlocal called
            called = True
            return {}

        repo.integrations_for_routers = explode  # type: ignore[assignment]
        contexts = await service.controller_context(rows)
        assert called is False
        assert all(c.state is None for c in contexts.values())


# ============================================================================
# Bulk router-name resolution -- backs GuestSessionResponse.router_name
# (the guest-session list's Router column). See
# tests/unit/test_guest_session_router_name.py for the serializer side.
# ============================================================================


class TestRouterNamesForIds:
    async def test_resolves_ids_to_names_in_one_query(self) -> None:
        service, repo, _loc, _org, _audit = make_service()
        a = await repo.create_router(
            location_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            name="QA Omada Venue -- Fleet",
            serial_number=f"SN-{uuid.uuid4()}",
            mac_address="AA:BB:CC:DD:EE:01",
            model="omada-controller",
        )
        b = await repo.create_router(
            location_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            name="Reception AP",
            serial_number=f"SN-{uuid.uuid4()}",
            mac_address="AA:BB:CC:DD:EE:02",
            model="hAP ac2",
        )
        names = await service.router_names_for_ids([a.id, b.id])
        assert names == {a.id: "QA Omada Venue -- Fleet", b.id: "Reception AP"}

    async def test_unknown_ids_are_simply_absent(self) -> None:
        service, _repo, _loc, _org, _audit = make_service()
        names = await service.router_names_for_ids([uuid.uuid4()])
        assert names == {}

    async def test_empty_input_makes_no_claim(self) -> None:
        service, _repo, _loc, _org, _audit = make_service()
        assert await service.router_names_for_ids([]) == {}
