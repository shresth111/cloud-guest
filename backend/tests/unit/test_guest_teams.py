"""Unit tests for the Guest Teams domain: team creation and join-code
generation (uniqueness, alphabet correctness), the join flow (happy path,
over-max-members rejection, expired/revoked team rejection, idempotent
re-join while active, re-join-after-removal behavior), member removal (and
its session-termination decision), team revocation (verifying
``GuestService.terminate_session`` is actually called per active member,
never reimplemented, with per-member failure isolation), the shared-quota
check (under and over quota), tenant isolation, and that the guest-facing
join endpoint requires no RBAC permission.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_voucher.py``/``tests/unit/test_guest.py``);
``asyncio_mode = "auto"`` runs async tests directly. ``GuestTeamService`` is
exercised against small, hand-rolled in-memory fakes for its own repository
and organization/location lookups, composed with a **real**
``app.domains.guest.service.GuestService`` (itself backed by an in-memory
fake ``GuestRepositoryProtocol``, mirroring ``test_guest.py``'s own
``FakeGuestRepository`` shape) -- so every assertion about
``terminate_session``/``get_guest_sessions``/``_get_or_create_guest`` being
"actually called, not reimplemented" is proven against the real method
bodies, not a mock that could silently drift from them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.guest.constants import BYTES_PER_MB, GuestSessionStatus
from app.domains.guest.exceptions import GuestSessionNotFoundError
from app.domains.guest.models import Guest, GuestDevice, GuestSession
from app.domains.guest.service import GuestService
from app.domains.guest_teams.constants import (
    TEAM_CODE_ALPHABET,
    TEAM_CODE_LENGTH,
    GuestTeamStatus,
)
from app.domains.guest_teams.exceptions import (
    CrossOrganizationGuestTeamAccessError,
    GuestTeamMemberCapExceededError,
    GuestTeamMemberNotFoundError,
    GuestTeamNotActiveError,
    GuestTeamNotFoundError,
    InvalidGuestTeamExpiryError,
    InvalidGuestTeamStatusTransitionError,
    InvalidMaxMembersError,
    InvalidSharedDataLimitError,
)
from app.domains.guest_teams.models import GuestTeam, GuestTeamMember
from app.domains.guest_teams.router import guest_router
from app.domains.guest_teams.service import GuestTeamService
from app.domains.location.exceptions import (
    CrossOrganizationLocationAccessError,
    LocationNotFoundError,
)
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationType
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization

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
        if (
            requesting_organization_id is not None
            and location.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationLocationAccessError()
        return location

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
class FakeGuestRepository:
    """In-memory stand-in for ``GuestRepositoryProtocol`` -- trimmed to
    exactly what ``GuestTeamService`` composes through the real
    ``GuestService`` (guest lookup/creation, device get-or-create, session
    creation/lookup/update/listing). Mirrors ``test_guest.py``'s own
    ``FakeGuestRepository`` shape."""

    guests: dict[uuid.UUID, Guest] = field(default_factory=dict)
    devices: dict[uuid.UUID, GuestDevice] = field(default_factory=dict)
    sessions: dict[uuid.UUID, GuestSession] = field(default_factory=dict)

    async def create_guest(self, **fields: object) -> Guest:
        guest = Guest(**_base_fields(**fields))
        self.guests[guest.id] = guest
        return guest

    async def get_guest_by_id(
        self, guest_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Guest | None:
        return self.guests.get(guest_id)

    async def get_guest_by_identifier(
        self, organization_id: uuid.UUID, identifier: str
    ) -> Guest | None:
        for guest in self.guests.values():
            if (
                guest.organization_id == organization_id
                and guest.identifier == identifier
            ):
                return guest
        return None

    async def update_guest(self, guest: Guest, data: dict[str, object]) -> Guest:
        for key, value in data.items():
            setattr(guest, key, value)
        guest.version += 1
        return guest

    async def create_device(self, **fields: object) -> GuestDevice:
        device = GuestDevice(**_base_fields(**fields))
        self.devices[device.id] = device
        return device

    async def get_device_by_id(self, device_id: uuid.UUID) -> GuestDevice | None:
        return self.devices.get(device_id)

    async def get_device_by_mac(self, mac_address: str) -> GuestDevice | None:
        for device in self.devices.values():
            if device.mac_address == mac_address:
                return device
        return None

    async def update_device(
        self, device: GuestDevice, data: dict[str, object]
    ) -> GuestDevice:
        for key, value in data.items():
            setattr(device, key, value)
        device.version += 1
        return device

    async def create_session(self, **fields: object) -> GuestSession:
        session = GuestSession(**_base_fields(**fields))
        self.sessions[session.id] = session
        return session

    async def get_session_by_id(
        self, session_id: uuid.UUID, *, include_deleted: bool = False
    ) -> GuestSession | None:
        return self.sessions.get(session_id)

    async def update_session(
        self, session: GuestSession, data: dict[str, object]
    ) -> GuestSession:
        for key, value in data.items():
            setattr(session, key, value)
        session.version += 1
        return session

    async def list_sessions_for_guest(
        self, guest_id: uuid.UUID, *, limit: int | None = None
    ) -> list[GuestSession]:
        items = [s for s in self.sessions.values() if s.guest_id == guest_id]
        items.sort(key=lambda s: s.started_at, reverse=True)
        return items[:limit] if limit else items

    def add_session(
        self,
        *,
        guest_id: uuid.UUID,
        organization_id: uuid.UUID,
        status: str = GuestSessionStatus.ACTIVE.value,
        bytes_uploaded: int = 0,
        bytes_downloaded: int = 0,
    ) -> GuestSession:
        now = _now()
        session = GuestSession(
            **_base_fields(
                guest_id=guest_id,
                device_id=None,
                router_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                organization_id=organization_id,
                auth_method="otp_sms",
                voucher_id=None,
                status=status,
                started_at=now,
                ended_at=None,
                last_activity_at=now,
                ip_address=None,
                user_agent=None,
                accept_language=None,
                bytes_uploaded=bytes_uploaded,
                bytes_downloaded=bytes_downloaded,
                data_limit_mb=None,
                session_timeout_minutes=None,
                disconnect_reason=None,
            )
        )
        self.sessions[session.id] = session
        return session


class _FailingSessionLookupGuestRepository(FakeGuestRepository):
    """A ``FakeGuestRepository`` whose ``list_sessions_for_guest`` raises for
    one designated guest id -- used to prove ``revoke_team``'s per-member
    failure isolation without touching ``GuestService``'s own real
    ``terminate_session``/``get_guest_sessions`` bodies."""

    def __init__(self, *, failing_guest_id: uuid.UUID) -> None:
        super().__init__()
        self.failing_guest_id = failing_guest_id

    async def list_sessions_for_guest(
        self, guest_id: uuid.UUID, *, limit: int | None = None
    ) -> list[GuestSession]:
        if guest_id == self.failing_guest_id:
            raise GuestSessionNotFoundError(guest_id)
        return await super().list_sessions_for_guest(guest_id, limit=limit)


@dataclass
class FakeGuestTeamRepository:
    teams: dict[uuid.UUID, GuestTeam] = field(default_factory=dict)
    members: dict[uuid.UUID, GuestTeamMember] = field(default_factory=dict)

    async def create_team(self, **fields: object) -> GuestTeam:
        team = GuestTeam(**_base_fields(**fields))
        self.teams[team.id] = team
        return team

    async def get_team_by_id(
        self, team_id: uuid.UUID, *, include_deleted: bool = False
    ) -> GuestTeam | None:
        return self.teams.get(team_id)

    async def get_team_by_code(self, team_code: str) -> GuestTeam | None:
        for team in self.teams.values():
            if team.team_code == team_code:
                return team
        return None

    async def update_team(self, team: GuestTeam, data: dict[str, object]) -> GuestTeam:
        for key, value in data.items():
            setattr(team, key, value)
        team.version += 1
        return team

    async def list_teams(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = "created_at",
        sort_order: object = None,
    ) -> tuple[list[GuestTeam], object]:
        items = list(self.teams.values())
        for key, value in (filters or {}).items():
            items = [i for i in items if getattr(i, key) == value]
        total = len(items)

        class _Meta:
            def __init__(self, total_items: int) -> None:
                self.page = page
                self.page_size = page_size
                self.total_items = total_items
                self.total_pages = 1
                self.has_next = False
                self.has_previous = False

        return items, _Meta(total)

    async def find_existing_codes(self, codes: list[str]) -> list[str]:
        existing = {t.team_code for t in self.teams.values()}
        return [c for c in codes if c in existing]

    async def create_member(self, **fields: object) -> GuestTeamMember:
        member = GuestTeamMember(**_base_fields(**fields))
        self.members[member.id] = member
        return member

    async def get_active_membership(
        self, team_id: uuid.UUID, guest_id: uuid.UUID
    ) -> GuestTeamMember | None:
        for member in self.members.values():
            if (
                member.team_id == team_id
                and member.guest_id == guest_id
                and member.is_active
            ):
                return member
        return None

    async def update_member(
        self, member: GuestTeamMember, data: dict[str, object]
    ) -> GuestTeamMember:
        for key, value in data.items():
            setattr(member, key, value)
        member.version += 1
        return member

    async def count_active_members(self, team_id: uuid.UUID) -> int:
        return len(
            [m for m in self.members.values() if m.team_id == team_id and m.is_active]
        )

    async def list_active_members(self, team_id: uuid.UUID) -> list[GuestTeamMember]:
        return [
            m for m in self.members.values() if m.team_id == team_id and m.is_active
        ]


# ============================================================================
# Fixtures / setup helpers
# ============================================================================


def _build_service(
    *,
    guest_repository: FakeGuestRepository | None = None,
) -> tuple[
    GuestTeamService, FakeGuestTeamRepository, FakeGuestRepository, GuestService
]:
    team_repository = FakeGuestTeamRepository()
    guest_repo = guest_repository or FakeGuestRepository()
    guest_service = GuestService(
        guest_repo,
        otp_service=None,
        voucher_service=None,
        captive_portal_service=None,
        router_lookup=None,
        audit_writer=FakeAuditLogWriter(),
    )
    org_lookup = FakeOrganizationLookup()
    location_lookup = FakeLocationLookup()
    service = GuestTeamService(
        team_repository,
        org_lookup,
        location_lookup,
        guest_service,
        audit_writer=FakeAuditLogWriter(),
    )
    return service, team_repository, guest_repo, guest_service


# ============================================================================
# Team creation + join-code generation
# ============================================================================


class TestTeamCreation:
    async def test_create_team_generates_active_status_and_code(self) -> None:
        service, _, _, _ = _build_service()
        organization = service.organization_lookup.add()

        team = await service.create_team(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            organization_id=organization.id,
            location_id=None,
            name="Wedding Party",
            max_members=10,
            shared_data_limit_mb=1024,
            expires_at=None,
        )
        assert team.status == GuestTeamStatus.ACTIVE.value
        assert len(team.team_code) == TEAM_CODE_LENGTH
        assert all(c in TEAM_CODE_ALPHABET for c in team.team_code)

    async def test_team_codes_are_unique_across_many_teams(self) -> None:
        service, _, _, _ = _build_service()
        organization = service.organization_lookup.add()

        codes = set()
        for _ in range(25):
            team = await service.create_team(
                actor_user_id=None,
                requesting_organization_id=None,
                organization_id=organization.id,
                location_id=None,
                name="Team",
                max_members=None,
                shared_data_limit_mb=None,
                expires_at=None,
            )
            codes.add(team.team_code)
        assert len(codes) == 25

    async def test_create_team_rejects_cross_organization_actor(self) -> None:
        service, _, _, _ = _build_service()
        organization = service.organization_lookup.add()
        other_org_id = uuid.uuid4()

        with pytest.raises(CrossOrganizationGuestTeamAccessError):
            await service.create_team(
                actor_user_id=None,
                requesting_organization_id=other_org_id,
                organization_id=organization.id,
                location_id=None,
                name="Team",
                max_members=None,
                shared_data_limit_mb=None,
                expires_at=None,
            )

    async def test_create_team_rejects_invalid_max_members(self) -> None:
        service, _, _, _ = _build_service()
        organization = service.organization_lookup.add()

        with pytest.raises(InvalidMaxMembersError):
            await service.create_team(
                actor_user_id=None,
                requesting_organization_id=None,
                organization_id=organization.id,
                location_id=None,
                name="Team",
                max_members=0,
                shared_data_limit_mb=None,
                expires_at=None,
            )

    async def test_create_team_rejects_invalid_shared_data_limit(self) -> None:
        service, _, _, _ = _build_service()
        organization = service.organization_lookup.add()

        with pytest.raises(InvalidSharedDataLimitError):
            await service.create_team(
                actor_user_id=None,
                requesting_organization_id=None,
                organization_id=organization.id,
                location_id=None,
                name="Team",
                max_members=None,
                shared_data_limit_mb=-5,
                expires_at=None,
            )

    async def test_create_team_rejects_past_expiry(self) -> None:
        service, _, _, _ = _build_service()
        organization = service.organization_lookup.add()

        with pytest.raises(InvalidGuestTeamExpiryError):
            await service.create_team(
                actor_user_id=None,
                requesting_organization_id=None,
                organization_id=organization.id,
                location_id=None,
                name="Team",
                max_members=None,
                shared_data_limit_mb=None,
                expires_at=_now() - timedelta(hours=1),
            )

    async def test_create_team_is_audited(self) -> None:
        service, _, _, _ = _build_service()
        organization = service.organization_lookup.add()

        await service.create_team(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            organization_id=organization.id,
            location_id=None,
            name="Team",
            max_members=None,
            shared_data_limit_mb=None,
            expires_at=None,
        )
        assert service.audit_writer.entries[-1]["action"] == "guest_team_created"


# ============================================================================
# Helpers to build an ACTIVE team quickly for join/removal/revoke tests
# ============================================================================


async def _create_active_team(
    service: GuestTeamService,
    *,
    max_members: int | None = None,
    shared_data_limit_mb: int | None = None,
    expires_at: datetime | None = None,
) -> tuple[GuestTeam, uuid.UUID]:
    organization = service.organization_lookup.add()
    team = await service.create_team(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=None,
        organization_id=organization.id,
        location_id=None,
        name="Team",
        max_members=max_members,
        shared_data_limit_mb=shared_data_limit_mb,
        expires_at=expires_at,
    )
    return team, organization.id


# ============================================================================
# Join flow
# ============================================================================


class TestJoinTeam:
    async def test_join_happy_path_creates_new_guest_and_membership(self) -> None:
        service, team_repo, guest_repo, _ = _build_service()
        team, _ = await _create_active_team(service)

        result = await service.join_team(
            team_code=team.team_code, identifier="+15551234567"
        )
        assert result.is_new_guest is True
        assert result.is_new_membership is True
        assert result.membership.is_active is True
        assert len(guest_repo.guests) == 1
        assert await team_repo.count_active_members(team.id) == 1

    async def test_join_is_idempotent_for_already_active_member(self) -> None:
        service, _, _, _ = _build_service()
        team, _ = await _create_active_team(service)

        first = await service.join_team(
            team_code=team.team_code, identifier="+15551234567"
        )
        second = await service.join_team(
            team_code=team.team_code, identifier="+15551234567"
        )
        assert second.is_new_membership is False
        assert second.membership.id == first.membership.id
        assert second.is_new_guest is False

    async def test_join_rejects_when_over_max_members(self) -> None:
        service, _, _, _ = _build_service()
        team, _ = await _create_active_team(service, max_members=1)

        await service.join_team(team_code=team.team_code, identifier="guest-1")
        with pytest.raises(GuestTeamMemberCapExceededError):
            await service.join_team(team_code=team.team_code, identifier="guest-2")

    async def test_join_rejects_expired_team(self) -> None:
        service, _, _, _ = _build_service()
        team, _ = await _create_active_team(
            service, expires_at=_now() + timedelta(seconds=1)
        )
        # Force expiry without waiting on a real clock.
        team.expires_at = _now() - timedelta(seconds=1)

        with pytest.raises(GuestTeamNotActiveError):
            await service.join_team(team_code=team.team_code, identifier="guest-1")
        assert team.status == GuestTeamStatus.EXPIRED.value

    async def test_join_rejects_revoked_team(self) -> None:
        service, _, _, _ = _build_service()
        team, org_id = await _create_active_team(service)
        await service.revoke_team(
            team_id=team.id,
            requesting_organization_id=org_id,
            actor_user_id=uuid.uuid4(),
            reason="event cancelled",
        )

        with pytest.raises(GuestTeamNotActiveError):
            await service.join_team(team_code=team.team_code, identifier="guest-1")

    async def test_join_rejects_unknown_team_code(self) -> None:
        service, _, _, _ = _build_service()
        with pytest.raises(GuestTeamNotFoundError):
            await service.join_team(team_code="NOPE0000", identifier="guest-1")

    async def test_rejoin_after_removal_creates_new_membership_row(self) -> None:
        service, team_repo, _, _ = _build_service()
        team, org_id = await _create_active_team(service)

        joined = await service.join_team(team_code=team.team_code, identifier="guest-1")
        await service.remove_team_member(
            team_id=team.id,
            guest_id=joined.guest_id,
            requesting_organization_id=org_id,
            actor_user_id=uuid.uuid4(),
            reason="left early",
        )
        rejoined = await service.join_team(
            team_code=team.team_code, identifier="guest-1"
        )

        assert rejoined.is_new_membership is True
        assert rejoined.membership.id != joined.membership.id
        # Two rows for the same (team, guest) pair now exist: one terminal
        # (the original, removed stint) and one active (the new stint) --
        # see models.py's "append-only-per-stint" docstring.
        rows_for_pair = [
            m
            for m in team_repo.members.values()
            if m.team_id == team.id and m.guest_id == joined.guest_id
        ]
        assert len(rows_for_pair) == 2
        assert sum(1 for m in rows_for_pair if m.is_active) == 1

    async def test_join_uses_or_create_device(self) -> None:
        service, _, guest_repo, _ = _build_service()
        team, _ = await _create_active_team(service)

        await service.join_team(
            team_code=team.team_code,
            identifier="guest-1",
            device_mac="aa:bb:cc:dd:ee:ff",
        )
        assert len(guest_repo.devices) == 1


# ============================================================================
# Member removal
# ============================================================================


class TestMemberRemoval:
    async def test_removal_marks_membership_inactive(self) -> None:
        service, _, _, _ = _build_service()
        team, org_id = await _create_active_team(service)
        joined = await service.join_team(team_code=team.team_code, identifier="guest-1")

        result = await service.remove_team_member(
            team_id=team.id,
            guest_id=joined.guest_id,
            requesting_organization_id=org_id,
            actor_user_id=uuid.uuid4(),
            reason="no longer attending",
        )
        assert result.membership.is_active is False
        assert result.membership.left_at is not None
        assert result.membership.removal_reason == "no longer attending"

    async def test_removal_terminates_active_session(self) -> None:
        service, _, guest_repo, _ = _build_service()
        team, org_id = await _create_active_team(service)
        joined = await service.join_team(team_code=team.team_code, identifier="guest-1")
        session = guest_repo.add_session(
            guest_id=joined.guest_id, organization_id=org_id
        )

        result = await service.remove_team_member(
            team_id=team.id,
            guest_id=joined.guest_id,
            requesting_organization_id=org_id,
            actor_user_id=uuid.uuid4(),
            reason=None,
        )
        assert session.id in result.terminated_session_ids
        assert guest_repo.sessions[session.id].status == "terminated"

    async def test_removal_leaves_non_active_sessions_untouched(self) -> None:
        service, _, guest_repo, _ = _build_service()
        team, org_id = await _create_active_team(service)
        joined = await service.join_team(team_code=team.team_code, identifier="guest-1")
        disconnected = guest_repo.add_session(
            guest_id=joined.guest_id,
            organization_id=org_id,
            status="disconnected",
        )

        result = await service.remove_team_member(
            team_id=team.id,
            guest_id=joined.guest_id,
            requesting_organization_id=org_id,
            actor_user_id=uuid.uuid4(),
            reason=None,
        )
        assert disconnected.id not in result.terminated_session_ids
        assert guest_repo.sessions[disconnected.id].status == "disconnected"

    async def test_removal_of_unknown_member_raises(self) -> None:
        service, _, _, _ = _build_service()
        team, org_id = await _create_active_team(service)

        with pytest.raises(GuestTeamMemberNotFoundError):
            await service.remove_team_member(
                team_id=team.id,
                guest_id=uuid.uuid4(),
                requesting_organization_id=org_id,
                actor_user_id=uuid.uuid4(),
                reason=None,
            )

    async def test_removal_is_audited(self) -> None:
        service, _, _, _ = _build_service()
        team, org_id = await _create_active_team(service)
        joined = await service.join_team(team_code=team.team_code, identifier="guest-1")

        await service.remove_team_member(
            team_id=team.id,
            guest_id=joined.guest_id,
            requesting_organization_id=org_id,
            actor_user_id=uuid.uuid4(),
            reason=None,
        )
        assert service.audit_writer.entries[-1]["action"] == "guest_team_member_removed"


# ============================================================================
# Team revocation
# ============================================================================


class TestTeamRevocation:
    async def test_revoke_transitions_status_and_terminates_active_sessions(
        self,
    ) -> None:
        service, _, guest_repo, guest_service = _build_service()
        team, org_id = await _create_active_team(service)

        member_a = await service.join_team(team_code=team.team_code, identifier="a")
        member_b = await service.join_team(team_code=team.team_code, identifier="b")
        session_a = guest_repo.add_session(
            guest_id=member_a.guest_id, organization_id=org_id
        )
        session_b = guest_repo.add_session(
            guest_id=member_b.guest_id, organization_id=org_id
        )

        result = await service.revoke_team(
            team_id=team.id,
            requesting_organization_id=org_id,
            actor_user_id=uuid.uuid4(),
            reason="event cancelled",
        )

        assert result.team.status == GuestTeamStatus.REVOKED.value
        assert result.team.revoked_reason == "event cancelled"
        assert set(result.terminated_session_ids) == {session_a.id, session_b.id}
        assert guest_repo.sessions[session_a.id].status == "terminated"
        assert guest_repo.sessions[session_b.id].status == "terminated"
        # Prove the REAL GuestService.terminate_session ran (not a
        # hand-rolled bulk update): it always sets ended_at and, since
        # audit_writer was wired on the real GuestService, writes its own
        # GUEST_SESSION_TERMINATED audit entry too.
        assert guest_repo.sessions[session_a.id].ended_at is not None
        guest_audit_actions = [e["action"] for e in guest_service.audit_writer.entries]
        assert guest_audit_actions.count("guest_session_terminated") == 2

    async def test_revoke_has_per_member_failure_isolation(self) -> None:
        team_repo = FakeGuestTeamRepository()
        org_lookup = FakeOrganizationLookup()
        organization = org_lookup.add()
        location_lookup = FakeLocationLookup()

        # First build against a normal repository just to allocate two real
        # guest ids via a throwaway join, then rebuild the real service
        # around a repository that fails session lookup for one of them.
        scratch_guest_repo = FakeGuestRepository()
        scratch_guest_service = GuestService(
            scratch_guest_repo,
            otp_service=None,
            voucher_service=None,
            captive_portal_service=None,
            router_lookup=None,
        )
        scratch_service = GuestTeamService(
            team_repo, org_lookup, location_lookup, scratch_guest_service
        )
        team = await scratch_service.create_team(
            actor_user_id=None,
            requesting_organization_id=None,
            organization_id=organization.id,
            location_id=None,
            name="Team",
            max_members=None,
            shared_data_limit_mb=None,
            expires_at=None,
        )
        member_good = await scratch_service.join_team(
            team_code=team.team_code, identifier="good"
        )
        member_bad = await scratch_service.join_team(
            team_code=team.team_code, identifier="bad"
        )

        failing_guest_repo = _FailingSessionLookupGuestRepository(
            failing_guest_id=member_bad.guest_id
        )
        failing_guest_repo.guests = scratch_guest_repo.guests
        good_session = failing_guest_repo.add_session(
            guest_id=member_good.guest_id, organization_id=organization.id
        )
        failing_guest_service = GuestService(
            failing_guest_repo,
            otp_service=None,
            voucher_service=None,
            captive_portal_service=None,
            router_lookup=None,
        )
        service = GuestTeamService(
            team_repo, org_lookup, location_lookup, failing_guest_service
        )

        result = await service.revoke_team(
            team_id=team.id,
            requesting_organization_id=organization.id,
            actor_user_id=uuid.uuid4(),
            reason=None,
        )

        # The team is revoked regardless of the per-member failure.
        assert result.team.status == GuestTeamStatus.REVOKED.value
        # The good member's session was still terminated...
        assert good_session.id in result.terminated_session_ids
        # ...and the bad member is reported as failed, not silently dropped,
        # while the whole call did not raise / abort.
        assert member_bad.guest_id in result.failed_member_ids
        assert member_good.guest_id not in result.failed_member_ids

    async def test_revoke_is_audited(self) -> None:
        service, _, _, _ = _build_service()
        team, org_id = await _create_active_team(service)

        await service.revoke_team(
            team_id=team.id,
            requesting_organization_id=org_id,
            actor_user_id=uuid.uuid4(),
            reason=None,
        )
        assert service.audit_writer.entries[-1]["action"] == "guest_team_revoked"

    async def test_revoke_already_revoked_team_raises(self) -> None:
        service, _, _, _ = _build_service()
        team, org_id = await _create_active_team(service)
        await service.revoke_team(
            team_id=team.id,
            requesting_organization_id=org_id,
            actor_user_id=None,
            reason=None,
        )
        with pytest.raises(InvalidGuestTeamStatusTransitionError):
            await service.revoke_team(
                team_id=team.id,
                requesting_organization_id=org_id,
                actor_user_id=None,
                reason=None,
            )


# ============================================================================
# Shared quota check
# ============================================================================


class TestSharedQuotaCheck:
    async def test_no_limit_never_exceeded(self) -> None:
        service, _, _, _ = _build_service()
        team, _ = await _create_active_team(service, shared_data_limit_mb=None)

        result = await service.check_shared_quota(team.id)
        assert result.exceeded is False
        assert result.shared_data_limit_mb is None

    async def test_under_quota(self) -> None:
        service, _, guest_repo, _ = _build_service()
        team, org_id = await _create_active_team(service, shared_data_limit_mb=10)
        member = await service.join_team(team_code=team.team_code, identifier="a")
        guest_repo.add_session(
            guest_id=member.guest_id,
            organization_id=org_id,
            bytes_uploaded=1 * BYTES_PER_MB,
            bytes_downloaded=1 * BYTES_PER_MB,
        )

        result = await service.check_shared_quota(team.id)
        assert result.exceeded is False
        assert result.current_usage_bytes == 2 * BYTES_PER_MB

    async def test_over_quota(self) -> None:
        service, _, guest_repo, _ = _build_service()
        team, org_id = await _create_active_team(service, shared_data_limit_mb=1)
        member_a = await service.join_team(team_code=team.team_code, identifier="a")
        member_b = await service.join_team(team_code=team.team_code, identifier="b")
        guest_repo.add_session(
            guest_id=member_a.guest_id,
            organization_id=org_id,
            bytes_uploaded=BYTES_PER_MB,
            bytes_downloaded=0,
        )
        guest_repo.add_session(
            guest_id=member_b.guest_id,
            organization_id=org_id,
            bytes_uploaded=BYTES_PER_MB,
            bytes_downloaded=0,
        )

        result = await service.check_shared_quota(team.id)
        assert result.exceeded is True
        assert result.current_usage_bytes == 2 * BYTES_PER_MB

    async def test_quota_check_ignores_non_active_sessions(self) -> None:
        service, _, guest_repo, _ = _build_service()
        team, org_id = await _create_active_team(service, shared_data_limit_mb=1)
        member = await service.join_team(team_code=team.team_code, identifier="a")
        guest_repo.add_session(
            guest_id=member.guest_id,
            organization_id=org_id,
            status="disconnected",
            bytes_uploaded=5 * BYTES_PER_MB,
            bytes_downloaded=5 * BYTES_PER_MB,
        )

        result = await service.check_shared_quota(team.id)
        assert result.current_usage_bytes == 0
        assert result.exceeded is False


# ============================================================================
# get_team_summary
# ============================================================================


class TestTeamSummary:
    async def test_summary_counts_members_sessions_and_bandwidth(self) -> None:
        service, _, guest_repo, _ = _build_service()
        team, org_id = await _create_active_team(service, shared_data_limit_mb=100)
        member = await service.join_team(team_code=team.team_code, identifier="a")
        guest_repo.add_session(
            guest_id=member.guest_id,
            organization_id=org_id,
            bytes_uploaded=10 * BYTES_PER_MB,
            bytes_downloaded=0,
        )

        summary = await service.get_team_summary(team.id)
        assert summary.member_count == 1
        assert summary.active_session_count == 1
        assert summary.total_bandwidth_bytes == 10 * BYTES_PER_MB
        assert summary.remaining_shared_quota_mb == 90.0
        assert summary.quota_exceeded is False


# ============================================================================
# Tenant isolation
# ============================================================================


class TestTenantIsolation:
    async def test_get_team_rejects_cross_organization_request(self) -> None:
        service, _, _, _ = _build_service()
        team, org_id = await _create_active_team(service)
        other_org_id = uuid.uuid4()
        assert other_org_id != org_id

        with pytest.raises(CrossOrganizationGuestTeamAccessError):
            await service.get_team(team.id, requesting_organization_id=other_org_id)

    async def test_list_teams_scopes_by_organization(self) -> None:
        service, _, _, _ = _build_service()
        team_one, org_one = await _create_active_team(service)
        team_two, org_two = await _create_active_team(service)
        assert org_one != org_two

        teams, _ = await service.list_teams(requesting_organization_id=org_one)
        ids = {t.id for t in teams}
        assert team_one.id in ids
        assert team_two.id not in ids

    async def test_revoke_rejects_cross_organization_request(self) -> None:
        service, _, _, _ = _build_service()
        team, org_id = await _create_active_team(service)
        other_org_id = uuid.uuid4()
        assert other_org_id != org_id

        with pytest.raises(CrossOrganizationGuestTeamAccessError):
            await service.revoke_team(
                team_id=team.id,
                requesting_organization_id=other_org_id,
                actor_user_id=None,
                reason=None,
            )


# ============================================================================
# Guest-facing endpoint requires no RBAC permission
# ============================================================================


class TestGuestFacingEndpointHasNoRbac:
    def test_join_route_has_no_permission_dependency(self) -> None:
        join_routes = [
            route for route in guest_router.routes if route.path.endswith("/join")
        ]
        assert len(join_routes) == 1
        assert join_routes[0].dependencies == []
