"""Unit tests for the Router Agent domain: persistent agent-credential
issuance (and rotation on reissue), device-authenticated heartbeat (composing
with BE-008's ``RouterService.heartbeat``), current-config pull (with and
without an applied version), agent status push (updating
``RouterAgentCredential`` fields, conditionally refreshing BE-008's
``Router.routeros_version``, and recording a ``RouterEvent``), the
provisioning-action queue (poll claims queued jobs, complete calls back
through ``RouterProvisioningService.complete_provisioning_job``), and the
``CurrentAgent`` auth dependency's rejection paths (missing/invalid/expired/
revoked credential, decommissioned/suspended router).

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_router_provisioning.py``); ``asyncio_mode = "auto"`` runs
async tests directly. Exercises ``RouterAgentService``/``CurrentAgent``
against real ``RouterService``/``RouterProvisioningService`` instances
(themselves wired against small in-memory fakes, mirroring
``test_router_provisioning.py``'s own ``make_services`` setup) rather than a
hand-rolled fake for either -- this both avoids duplicating their business
logic in a second fake and directly exercises the real cross-domain
composition (``RouterAgentService`` -> ``RouterService``/
``RouterProvisioningService``/``RouterProvisioningRepository``) this module
relies on. Everything a test needs is bundled into one ``Fixture``
dataclass returned by ``make_services()`` (rather than a long positional
tuple) so every test shares exactly one, correctly-wired
``location_lookup``/``org_lookup`` pair with the ``router_service`` under
test.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.location.exceptions import (
    CrossOrganizationLocationAccessError,
    LocationNotFoundError,
)
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationType
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization
from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router, RouterProvisioningToken
from app.domains.router.service import RouterService
from app.domains.router_agent.constants import (
    AGENT_CREDENTIAL_HEADER,
    AgentLicenseStatus,
)
from app.domains.router_agent.dependencies import CurrentAgent
from app.domains.router_agent.exceptions import (
    AgentCredentialExpiredError,
    AgentCredentialInvalidError,
    AgentCredentialMissingError,
    AgentCredentialRevokedError,
    AgentRouterNotEligibleError,
    NoConfigAssignedError,
)
from app.domains.router_agent.models import RouterAgentCredential
from app.domains.router_agent.service import RouterAgentService, hash_credential
from app.domains.router_provisioning.constants import ProvisioningJobStatus
from app.domains.router_provisioning.exceptions import (
    ProvisioningJobRouterMismatchError,
)
from app.domains.router_provisioning.models import (
    ConfigProfile,
    ConfigTemplate,
    ConfigVariable,
    ConfigVersion,
    ProvisioningJob,
    RouterEnrollmentRequest,
    RouterEvent,
    RouterHealthSnapshot,
)
from app.domains.router_provisioning.service import RouterProvisioningService

# ============================================================================
# Test doubles: BE-008 (Router domain) side -- mirrors test_router.py /
# test_router_provisioning.py exactly
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
# Test doubles: Router Provisioning (Module 009 Part 1) side
# ============================================================================


@dataclass
class FakeQueueDispatcher:
    enqueued: list[uuid.UUID] = field(default_factory=list)

    async def enqueue(self, job_id: uuid.UUID) -> None:
        self.enqueued.append(job_id)


@dataclass
class FakeRouterProvisioningRepository:
    """Identical in shape to ``test_router_provisioning.py``'s own fake --
    duplicated (not imported), matching this project's established
    per-test-file convention of self-contained fakes."""

    templates: dict[uuid.UUID, ConfigTemplate] = field(default_factory=dict)
    variables: dict[uuid.UUID, ConfigVariable] = field(default_factory=dict)
    profiles: dict[uuid.UUID, ConfigProfile] = field(default_factory=dict)
    versions: dict[uuid.UUID, ConfigVersion] = field(default_factory=dict)
    enrollments: dict[uuid.UUID, RouterEnrollmentRequest] = field(default_factory=dict)
    jobs: dict[uuid.UUID, ProvisioningJob] = field(default_factory=dict)
    health_snapshots: dict[uuid.UUID, RouterHealthSnapshot] = field(
        default_factory=dict
    )
    events: dict[uuid.UUID, RouterEvent] = field(default_factory=dict)

    # -- templates -----------------------------------------------------------
    async def get_template(self, template_id, *, include_deleted: bool = False):
        template = self.templates.get(template_id)
        if template is None or (template.is_deleted and not include_deleted):
            return None
        return template

    async def create_template(self, **fields: object) -> ConfigTemplate:
        template = ConfigTemplate(**_base_fields(**fields))
        self.templates[template.id] = template
        return template

    async def update_template(self, template, data):
        for key, value in data.items():
            if hasattr(template, key):
                setattr(template, key, value)
        template.version += 1
        return template

    async def soft_delete_template(self, template):
        template.is_deleted = True
        template.deleted_at = _now()
        return template

    async def list_templates(self, *, requesting_organization_id, page, page_size):
        values = [t for t in self.templates.values() if not t.is_deleted]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    # -- variables -------------------------------------------------------------
    async def get_variable(self, variable_id):
        return self.variables.get(variable_id)

    async def find_variable(
        self, *, scope_type, organization_id, location_id, router_id, key
    ):
        for v in self.variables.values():
            if v.is_deleted:
                continue
            if (
                v.scope_type == scope_type
                and v.organization_id == organization_id
                and v.location_id == location_id
                and v.router_id == router_id
                and v.key == key
            ):
                return v
        return None

    async def create_variable(self, **fields: object) -> ConfigVariable:
        variable = ConfigVariable(**_base_fields(**fields))
        self.variables[variable.id] = variable
        return variable

    async def update_variable(self, variable, data):
        for key, value in data.items():
            if hasattr(variable, key):
                setattr(variable, key, value)
        variable.version += 1
        return variable

    async def soft_delete_variable(self, variable):
        variable.is_deleted = True
        variable.deleted_at = _now()
        return variable

    async def list_global_variables(self):
        return [
            v
            for v in self.variables.values()
            if not v.is_deleted
            and v.scope_type == "organization"
            and v.organization_id is None
        ]

    async def list_organization_variables(self, organization_id):
        return [
            v
            for v in self.variables.values()
            if not v.is_deleted
            and v.scope_type == "organization"
            and v.organization_id == organization_id
        ]

    async def list_location_variables(self, location_id):
        return [
            v
            for v in self.variables.values()
            if not v.is_deleted
            and v.scope_type == "location"
            and v.location_id == location_id
        ]

    async def list_router_variables(self, router_id):
        return [
            v
            for v in self.variables.values()
            if not v.is_deleted
            and v.scope_type == "router"
            and v.router_id == router_id
        ]

    async def list_variables(self, *, scope_type, page, page_size):
        values = [v for v in self.variables.values() if not v.is_deleted]
        if scope_type:
            values = [v for v in values if v.scope_type == scope_type]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    # -- profiles --------------------------------------------------------------
    async def get_profile(self, profile_id):
        return self.profiles.get(profile_id)

    async def get_profile_for_router(self, router_id):
        return next(
            (
                p
                for p in self.profiles.values()
                if p.router_id == router_id and not p.is_deleted
            ),
            None,
        )

    async def create_profile(self, **fields: object) -> ConfigProfile:
        profile = ConfigProfile(**_base_fields(**fields))
        self.profiles[profile.id] = profile
        return profile

    async def update_profile(self, profile, data):
        for key, value in data.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
        profile.version += 1
        return profile

    # -- versions --------------------------------------------------------------
    async def get_version(self, version_id):
        return self.versions.get(version_id)

    async def create_version(self, **fields: object) -> ConfigVersion:
        version = ConfigVersion(**_base_fields(**fields))
        self.versions[version.id] = version
        return version

    async def update_version(self, version, data):
        for key, value in data.items():
            if hasattr(version, key):
                setattr(version, key, value)
        version.version += 1
        return version

    async def get_next_version_number(self, router_id) -> int:
        existing = [
            v.version_number for v in self.versions.values() if v.router_id == router_id
        ]
        return (max(existing) if existing else 0) + 1

    async def get_latest_applied_version(self, router_id, *, exclude_version_id=None):
        candidates = [
            v
            for v in self.versions.values()
            if v.router_id == router_id
            and not v.is_deleted
            and not v.is_backup
            and v.status == "applied"
            and (exclude_version_id is None or v.id != exclude_version_id)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda v: v.version_number)

    async def get_latest_version_for_router(self, router_id):
        candidates = [
            v
            for v in self.versions.values()
            if v.router_id == router_id and not v.is_deleted
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda v: v.version_number)

    async def list_versions_for_router(self, router_id, *, page, page_size):
        values = [
            v
            for v in self.versions.values()
            if v.router_id == router_id and not v.is_deleted
        ]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    # -- enrollment --------------------------------------------------------------
    async def get_enrollment(self, enrollment_id):
        return self.enrollments.get(enrollment_id)

    async def create_enrollment(self, **fields: object) -> RouterEnrollmentRequest:
        enrollment = RouterEnrollmentRequest(**_base_fields(**fields))
        self.enrollments[enrollment.id] = enrollment
        return enrollment

    async def update_enrollment(self, enrollment, data):
        for key, value in data.items():
            if hasattr(enrollment, key):
                setattr(enrollment, key, value)
        enrollment.version += 1
        return enrollment

    async def find_pending_enrollment(self, *, serial_number, mac_address):
        for e in self.enrollments.values():
            if e.is_deleted or e.status != "pending":
                continue
            if e.serial_number == serial_number or e.mac_address == mac_address:
                return e
        return None

    async def list_pending_enrollments(self, *, page, page_size):
        values = [
            e
            for e in self.enrollments.values()
            if not e.is_deleted and e.status == "pending"
        ]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    # -- provisioning jobs -------------------------------------------------------
    async def get_job(self, job_id):
        return self.jobs.get(job_id)

    async def create_job(self, **fields: object) -> ProvisioningJob:
        job = ProvisioningJob(**_base_fields(**fields))
        self.jobs[job.id] = job
        return job

    async def update_job(self, job, data):
        for key, value in data.items():
            if hasattr(job, key):
                setattr(job, key, value)
        job.version += 1
        return job

    async def list_jobs_for_router(self, router_id, *, page, page_size):
        values = [
            j
            for j in self.jobs.values()
            if j.router_id == router_id and not j.is_deleted
        ]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_active_jobs_for_router(self, router_id):
        return [
            j
            for j in self.jobs.values()
            if j.router_id == router_id
            and not j.is_deleted
            and j.status in ("queued", "running")
        ]

    # -- health / events ---------------------------------------------------------
    async def create_health_snapshot(self, **fields: object) -> RouterHealthSnapshot:
        snapshot = RouterHealthSnapshot(**_base_fields(**fields))
        self.health_snapshots[snapshot.id] = snapshot
        return snapshot

    async def list_health_snapshots_for_router(self, router_id, *, page, page_size):
        values = [
            s
            for s in self.health_snapshots.values()
            if s.router_id == router_id and not s.is_deleted
        ]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def create_event(self, **fields: object) -> RouterEvent:
        event = RouterEvent(**_base_fields(**fields))
        self.events[event.id] = event
        return event

    async def list_events_for_router(self, router_id, *, page, page_size):
        values = [
            e
            for e in self.events.values()
            if e.router_id == router_id and not e.is_deleted
        ]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))


# ============================================================================
# Test doubles: this module's own credential table
# ============================================================================


@dataclass
class FakeRouterAgentRepository:
    credentials: dict[uuid.UUID, RouterAgentCredential] = field(default_factory=dict)

    async def get_by_router_id(self, router_id) -> RouterAgentCredential | None:
        return next(
            (
                c
                for c in self.credentials.values()
                if c.router_id == router_id and not c.is_deleted
            ),
            None,
        )

    async def get_by_credential_hash(
        self, credential_hash: str
    ) -> RouterAgentCredential | None:
        return next(
            (
                c
                for c in self.credentials.values()
                if c.credential_hash == credential_hash and not c.is_deleted
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


# ============================================================================
# Fixture assembly
# ============================================================================


@dataclass
class Fixture:
    agent_service: RouterAgentService
    agent_repo: FakeRouterAgentRepository
    router_service: RouterService
    router_repo: FakeRouterRepository
    provisioning_service: RouterProvisioningService
    provisioning_repo: FakeRouterProvisioningRepository
    location_lookup: FakeLocationLookup
    org_lookup: FakeOrganizationLookup
    audit: FakeAuditLogWriter


def make_services() -> Fixture:
    """Builds real ``RouterService``/``RouterProvisioningService`` instances
    (themselves wired against small in-memory fakes, mirroring
    ``test_router_provisioning.py``'s own ``make_services``) plus a
    ``RouterAgentService`` composed against both -- the same composition
    wiring ``app.domains.router_agent.dependencies`` uses in production. All
    of it (including ``location_lookup``/``org_lookup``) is returned on one
    ``Fixture`` so every test shares a single, correctly-wired set rather
    than accidentally constructing a second, disconnected pair."""
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

    provisioning_repo = FakeRouterProvisioningRepository()
    queue_dispatcher = FakeQueueDispatcher()
    provisioning_service = RouterProvisioningService(
        provisioning_repo,
        router_service,
        location_lookup,
        queue_dispatcher=queue_dispatcher,
        audit_writer=shared_audit,
    )

    agent_repo = FakeRouterAgentRepository()
    agent_service = RouterAgentService(
        agent_repo,
        router_service,
        provisioning_repo,
        provisioning_repo,
        provisioning_service,
        event_writer=provisioning_repo,
    )
    return Fixture(
        agent_service=agent_service,
        agent_repo=agent_repo,
        router_service=router_service,
        router_repo=router_repo,
        provisioning_service=provisioning_service,
        provisioning_repo=provisioning_repo,
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
    status: RouterStatus = RouterStatus.PENDING_PROVISIONING,
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
    if status != RouterStatus.PENDING_PROVISIONING:
        if status in (
            RouterStatus.PROVISIONING,
            RouterStatus.ONLINE,
            RouterStatus.OFFLINE,
        ):
            _token, plaintext = await fx.router_service.generate_provisioning_token(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )
            router_device = await fx.router_service.check_in(plaintext_token=plaintext)
            if status in (RouterStatus.ONLINE, RouterStatus.OFFLINE):
                router_device = await fx.router_service.heartbeat(
                    router_id=router_device.id
                )
        elif status == RouterStatus.SUSPENDED:
            # SUSPENDED is only reachable from ONLINE/OFFLINE (see
            # ``ROUTER_STATUS_TRANSITIONS``) -- drive through check-in +
            # heartbeat first, exactly like the ONLINE/OFFLINE branch above.
            _token, plaintext = await fx.router_service.generate_provisioning_token(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )
            router_device = await fx.router_service.check_in(plaintext_token=plaintext)
            router_device = await fx.router_service.heartbeat(
                router_id=router_device.id
            )
            router_device = await fx.router_service.suspend_router(
                actor_user_id=uuid.uuid4(),
                router_id=router_device.id,
                requesting_organization_id=None,
            )
        elif status == RouterStatus.DECOMMISSIONED:
            router_device = await fx.router_service.repository.update_router(
                router_device, {"status": RouterStatus.DECOMMISSIONED.value}
            )
    return router_device


@dataclass
class FakeRequest:
    """A minimal stand-in for ``fastapi.Request`` -- ``CurrentAgent`` only
    ever reads ``request.headers.get(...)``, so nothing richer is needed."""

    headers: dict[str, str] = field(default_factory=dict)


# ============================================================================
# Credential issuance
# ============================================================================


class TestCredentialIssuance:
    async def test_issue_credential_stores_only_hash(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        credential, plaintext = await fx.agent_service.issue_credential_for_router(
            router_device
        )

        assert credential.credential_hash != plaintext
        assert credential.credential_hash == hash_credential(plaintext)
        assert credential.router_id == router_device.id
        assert credential.rotation_count == 0
        assert credential.revoked_at is None
        stored = fx.agent_repo.credentials[credential.id]
        assert stored.credential_hash == credential.credential_hash

    async def test_issue_credential_records_event(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        await fx.agent_service.issue_credential_for_router(router_device)

        events = [
            e
            for e in fx.provisioning_repo.events.values()
            if e.router_id == router_device.id
        ]
        assert any(e.event_type == "agent_credential_issued" for e in events)

    async def test_reissue_rotates_existing_credential(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        (
            first_credential,
            first_plaintext,
        ) = await fx.agent_service.issue_credential_for_router(router_device)
        # The fake (like the real GenericRepository) mutates and returns the
        # *same* instance on update -- capture the hash by value now, before
        # the second issuance mutates that same object in place.
        first_credential_id = first_credential.id
        first_hash = first_credential.credential_hash

        (
            second_credential,
            second_plaintext,
        ) = await fx.agent_service.issue_credential_for_router(router_device)

        assert second_credential.id == first_credential_id
        assert second_credential.rotation_count == 1
        assert second_plaintext != first_plaintext
        assert second_credential.credential_hash != first_hash
        # Exactly one row exists for this router -- a reissue rotates, it
        # never creates a second credential row.
        assert len(fx.agent_repo.credentials) == 1

    async def test_check_in_then_issue_credential_full_flow(self) -> None:
        """Exercises the real seam this module composes with: BE-008's
        check-in transitions the router to PROVISIONING, and this module's
        credential issuance immediately follows -- the exact composition
        ``app.domains.router.router.provisioning_check_in`` performs."""
        fx = make_services()
        organization = fx.org_lookup.add()
        location = fx.location_lookup.add(organization_id=organization.id)
        router_device = await fx.router_service.create_router(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            name="AP",
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
        assert checked_in.status == RouterStatus.PROVISIONING.value

        credential, plaintext = await fx.agent_service.issue_credential_for_router(
            checked_in
        )
        assert credential.router_id == checked_in.id
        assert hash_credential(plaintext) == credential.credential_hash


# ============================================================================
# CurrentAgent auth dependency
# ============================================================================


class TestCurrentAgentDependency:
    async def _setup(self, *, router_status: RouterStatus = RouterStatus.ONLINE):
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization, status=router_status)
        _credential, plaintext = await fx.agent_service.issue_credential_for_router(
            router_device
        )
        return fx, router_device, plaintext

    async def test_missing_header_rejected(self) -> None:
        fx, _router, _plaintext = await self._setup()
        with pytest.raises(AgentCredentialMissingError):
            await CurrentAgent(
                FakeRequest(headers={}),
                agent_repository=fx.agent_repo,
                router_repository=fx.router_repo,
            )

    async def test_invalid_credential_rejected(self) -> None:
        fx, _router, _plaintext = await self._setup()
        with pytest.raises(AgentCredentialInvalidError):
            await CurrentAgent(
                FakeRequest(headers={AGENT_CREDENTIAL_HEADER: "not-a-real-credential"}),
                agent_repository=fx.agent_repo,
                router_repository=fx.router_repo,
            )

    async def test_valid_credential_resolves_router_and_updates_last_used(
        self,
    ) -> None:
        fx, router_device, plaintext = await self._setup()
        identity = await CurrentAgent(
            FakeRequest(headers={AGENT_CREDENTIAL_HEADER: plaintext}),
            agent_repository=fx.agent_repo,
            router_repository=fx.router_repo,
        )
        assert identity.router.id == router_device.id
        assert identity.credential.last_used_at is not None

    async def test_expired_credential_rejected(self) -> None:
        fx, _router, plaintext = await self._setup()
        credential = await fx.agent_repo.get_by_credential_hash(
            hash_credential(plaintext)
        )
        await fx.agent_repo.update_credential(
            credential, {"expires_at": _now() - timedelta(days=1)}
        )
        with pytest.raises(AgentCredentialExpiredError):
            await CurrentAgent(
                FakeRequest(headers={AGENT_CREDENTIAL_HEADER: plaintext}),
                agent_repository=fx.agent_repo,
                router_repository=fx.router_repo,
            )

    async def test_revoked_credential_rejected(self) -> None:
        fx, _router, plaintext = await self._setup()
        credential = await fx.agent_repo.get_by_credential_hash(
            hash_credential(plaintext)
        )
        await fx.agent_repo.update_credential(credential, {"revoked_at": _now()})
        with pytest.raises(AgentCredentialRevokedError):
            await CurrentAgent(
                FakeRequest(headers={AGENT_CREDENTIAL_HEADER: plaintext}),
                agent_repository=fx.agent_repo,
                router_repository=fx.router_repo,
            )

    async def test_decommissioned_router_rejected(self) -> None:
        fx, _router, plaintext = await self._setup(
            router_status=RouterStatus.DECOMMISSIONED
        )
        with pytest.raises(AgentRouterNotEligibleError):
            await CurrentAgent(
                FakeRequest(headers={AGENT_CREDENTIAL_HEADER: plaintext}),
                agent_repository=fx.agent_repo,
                router_repository=fx.router_repo,
            )

    async def test_suspended_router_rejected(self) -> None:
        fx, _router, plaintext = await self._setup(router_status=RouterStatus.SUSPENDED)
        with pytest.raises(AgentRouterNotEligibleError):
            await CurrentAgent(
                FakeRequest(headers={AGENT_CREDENTIAL_HEADER: plaintext}),
                agent_repository=fx.agent_repo,
                router_repository=fx.router_repo,
            )


# ============================================================================
# Heartbeat
# ============================================================================


class TestAgentHeartbeat:
    async def test_heartbeat_completes_provisioning_via_agent_auth(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(
            fx, organization, status=RouterStatus.PROVISIONING
        )
        _credential, plaintext = await fx.agent_service.issue_credential_for_router(
            router_device
        )
        identity = await CurrentAgent(
            FakeRequest(headers={AGENT_CREDENTIAL_HEADER: plaintext}),
            agent_repository=fx.agent_repo,
            router_repository=fx.router_repo,
        )

        updated = await fx.agent_service.heartbeat(router=identity.router)
        assert updated.status == RouterStatus.ONLINE.value
        assert updated.last_seen_at is not None

    async def test_heartbeat_refreshes_routeros_version(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization, status=RouterStatus.ONLINE)
        _credential, plaintext = await fx.agent_service.issue_credential_for_router(
            router_device
        )
        identity = await CurrentAgent(
            FakeRequest(headers={AGENT_CREDENTIAL_HEADER: plaintext}),
            agent_repository=fx.agent_repo,
            router_repository=fx.router_repo,
        )

        updated = await fx.agent_service.heartbeat(
            router=identity.router, routeros_version="7.15"
        )
        assert updated.routeros_version == "7.15"


# ============================================================================
# Config pull
# ============================================================================


class TestConfigPull:
    async def test_pull_config_without_applied_version_raises(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)

        with pytest.raises(NoConfigAssignedError):
            await fx.agent_service.get_current_config(router_id=router_device.id)

    async def test_pull_config_returns_latest_applied_version(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization, status=RouterStatus.ONLINE)
        template = await fx.provisioning_service.create_template(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            name="Basic",
            template_content="applied content",
        )
        _profile, version = await fx.provisioning_service.assign_profile(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            template_id=template.id,
            requesting_organization_id=None,
        )
        _updated, job = await fx.provisioning_service.apply_version(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            version_id=version.id,
            requesting_organization_id=None,
        )
        await fx.provisioning_service.start_provisioning_job(job.id)
        await fx.provisioning_service.complete_provisioning_job(job.id, success=True)

        pulled = await fx.agent_service.get_current_config(router_id=router_device.id)
        assert pulled.id == version.id
        assert pulled.rendered_content == "applied content"


# ============================================================================
# Status push
# ============================================================================


class TestStatusPush:
    async def test_status_push_updates_credential_and_records_event(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        credential, _plaintext = await fx.agent_service.issue_credential_for_router(
            router_device
        )

        updated_credential = await fx.agent_service.report_status(
            router=router_device,
            credential=credential,
            routeros_version=None,
            agent_software_version="cloudguest-agent 1.2.0",
            capabilities={"model": "hAP ac2", "interfaces": ["ether1", "wlan1"]},
            license_key="LICENSE-123",
            license_status=AgentLicenseStatus.VALID,
        )

        assert updated_credential.agent_software_version == "cloudguest-agent 1.2.0"
        assert updated_credential.license_status == AgentLicenseStatus.VALID.value
        assert updated_credential.capabilities["model"] == "hAP ac2"
        assert updated_credential.last_status_report_at is not None

        events = [
            e
            for e in fx.provisioning_repo.events.values()
            if e.router_id == router_device.id
        ]
        assert any(e.event_type == "agent_status_reported" for e in events)

    async def test_status_push_updates_routeros_version_only_when_changed(
        self,
    ) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization)
        credential, _plaintext = await fx.agent_service.issue_credential_for_router(
            router_device
        )

        await fx.agent_service.report_status(
            router=router_device,
            credential=credential,
            routeros_version="7.15",
            agent_software_version=None,
            capabilities={},
            license_key=None,
            license_status=AgentLicenseStatus.UNKNOWN,
        )
        assert fx.router_repo.routers[router_device.id].routeros_version == "7.15"
        audit_count_after_first = len(fx.audit.entries)

        # Reporting the identical version again must not re-trigger
        # RouterService.update_router (and its audit_log_entries write).
        refreshed_router = fx.router_repo.routers[router_device.id]
        await fx.agent_service.report_status(
            router=refreshed_router,
            credential=credential,
            routeros_version="7.15",
            agent_software_version=None,
            capabilities={},
            license_key=None,
            license_status=AgentLicenseStatus.UNKNOWN,
        )
        assert len(fx.audit.entries) == audit_count_after_first


# ============================================================================
# Action queue: poll + complete
# ============================================================================


class TestActionQueue:
    async def test_poll_actions_claims_queued_jobs(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization, status=RouterStatus.ONLINE)
        job = await fx.provisioning_service.factory_reset(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        assert job.status == ProvisioningJobStatus.QUEUED.value

        jobs = await fx.agent_service.poll_actions(router_id=router_device.id)
        assert len(jobs) == 1
        assert jobs[0].id == job.id
        assert jobs[0].status == ProvisioningJobStatus.RUNNING.value

    async def test_poll_actions_includes_already_running_jobs_without_reclaiming(
        self,
    ) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization, status=RouterStatus.ONLINE)
        job = await fx.provisioning_service.factory_reset(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        started = await fx.provisioning_service.start_provisioning_job(job.id)
        assert started.attempts == 1

        jobs = await fx.agent_service.poll_actions(router_id=router_device.id)
        assert len(jobs) == 1
        assert jobs[0].status == ProvisioningJobStatus.RUNNING.value
        # Already-running jobs are surfaced as-is, not re-transitioned (that
        # would bump ``attempts`` again).
        assert jobs[0].attempts == 1

    async def test_complete_action_calls_complete_provisioning_job(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization, status=RouterStatus.ONLINE)
        job = await fx.provisioning_service.factory_reset(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        await fx.agent_service.poll_actions(router_id=router_device.id)

        completed = await fx.agent_service.complete_action(
            router_id=router_device.id, job_id=job.id, success=True
        )
        assert completed.status == ProvisioningJobStatus.SUCCEEDED.value
        # Realized via BE-008's RouterService.reset_to_pending_provisioning,
        # composed by RouterProvisioningService -- confirms the seam this
        # module calls through actually took effect.
        assert (
            fx.router_repo.routers[router_device.id].status
            == RouterStatus.PENDING_PROVISIONING.value
        )

    async def test_complete_action_reports_failure(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_device = await make_router(fx, organization, status=RouterStatus.ONLINE)
        job = await fx.provisioning_service.factory_reset(
            actor_user_id=uuid.uuid4(),
            router_id=router_device.id,
            requesting_organization_id=None,
        )
        await fx.agent_service.poll_actions(router_id=router_device.id)

        completed = await fx.agent_service.complete_action(
            router_id=router_device.id,
            job_id=job.id,
            success=False,
            error_message="device offline mid-reset",
        )
        assert completed.status == ProvisioningJobStatus.FAILED.value
        assert completed.error_message == "device offline mid-reset"

    async def test_complete_action_rejects_job_for_different_router(self) -> None:
        fx = make_services()
        organization = fx.org_lookup.add()
        router_a = await make_router(fx, organization, status=RouterStatus.ONLINE)
        router_b = await make_router(fx, organization, status=RouterStatus.ONLINE)
        job = await fx.provisioning_service.factory_reset(
            actor_user_id=uuid.uuid4(),
            router_id=router_a.id,
            requesting_organization_id=None,
        )

        with pytest.raises(ProvisioningJobRouterMismatchError):
            await fx.agent_service.complete_action(
                router_id=router_b.id, job_id=job.id, success=True
            )
