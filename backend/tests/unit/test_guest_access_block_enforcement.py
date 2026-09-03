"""Blocking a guest ends the session they are in -- and says so honestly
when it cannot.

The defect these tests pin down: ``GuestAccessService.create_guest_rule``
wrote a row, audited it, returned 201, and never contacted a router, while
the customer dashboard's Blocked Guests form promised *"Takes effect
immediately, ending any session these users currently have."*

Every test here asserts an observable state change -- a row gone from the
fake router's active table, a session row moved to a terminal status, a
commit that happened before a re-raise. A test that only asserted "the
adapter was called" would have passed against the bug, because the bug was
that nothing was called at all.

Follows this project's plain-``assert``/native-``async def`` style
(``tests/unit/test_guest.py``); ``asyncio_mode = "auto"`` runs async tests
directly. Everything is exercised against small hand-rolled in-memory
fakes -- there is no live Postgres and no router in this environment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.domains.guest_access.constants import AccessRuleType, BlockEnforcementStatus
from app.domains.guest_access.device_adapters import (
    GuestAccessCredentials,
    SessionControlSnapshot,
    SessionEndOutcome,
)
from app.domains.guest_access.enforcement import BlocklistEnforcer
from app.domains.guest_access.exceptions import (
    BlockEnforcementMissingCredentialsError,
    GuestAccessDeviceConnectionError,
    RouterHasNoHotspotError,
    SessionStillActiveOnDeviceError,
)
from app.domains.guest_access.models import DeviceAccessRule, GuestAccessRule
from app.domains.guest_access.service import GuestAccessService

# The value ``dependencies.get_block_enforcer`` injects in the running app.
# Hard-coded here rather than imported so a silent rename of the guest
# domain's own enum cannot make these tests agree with a broken wiring.
TERMINATED = "terminated"
ACTIVE = "active"


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
class FakeGuestAccessRepository:
    guest_rules: dict[uuid.UUID, GuestAccessRule] = field(default_factory=dict)
    device_rules: dict[uuid.UUID, DeviceAccessRule] = field(default_factory=dict)
    #: Counts the explicit commits the enforcement path issues. The commit
    #: is the point of several tests below: ``GenericRepository.update``
    #: only flushes, and ``get_db_session`` rolls back on any exception, so
    #: a failure record written just before a re-raise is discarded unless
    #: it is committed first.
    commits: int = 0

    async def create_guest_rule(self, **fields: object) -> GuestAccessRule:
        rule = GuestAccessRule(**_base_fields(**fields))
        self.guest_rules[rule.id] = rule
        return rule

    async def get_guest_rule_by_id(self, rule_id: uuid.UUID) -> GuestAccessRule | None:
        return self.guest_rules.get(rule_id)

    async def update_guest_rule(
        self, rule: GuestAccessRule, data: dict[str, object]
    ) -> GuestAccessRule:
        for key, value in data.items():
            setattr(rule, key, value)
        return rule

    async def commit(self) -> None:
        self.commits += 1


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeGuest:
    id: uuid.UUID


@dataclass
class FakeDevice:
    mac_address: str


@dataclass
class FakeSession:
    id: uuid.UUID
    router_id: uuid.UUID
    device_id: uuid.UUID | None
    status: str = ACTIVE
    ended_at: datetime | None = None
    disconnect_reason: str | None = None
    updated_by: uuid.UUID | None = None


@dataclass
class FakeSessionLookup:
    """Structurally satisfies ``LiveSessionLookupProtocol`` -- the same
    subset ``app.domains.guest.repository.GuestRepository`` provides."""

    guests: dict[tuple[uuid.UUID, str], FakeGuest] = field(default_factory=dict)
    sessions: dict[uuid.UUID, list[FakeSession]] = field(default_factory=dict)
    devices: dict[uuid.UUID, FakeDevice] = field(default_factory=dict)

    async def get_guest_by_identifier(
        self, organization_id: uuid.UUID, identifier: str
    ) -> FakeGuest | None:
        return self.guests.get((organization_id, identifier))

    async def list_active_sessions_for_guest(
        self, guest_id: uuid.UUID
    ) -> list[FakeSession]:
        return [s for s in self.sessions.get(guest_id, []) if s.status == ACTIVE]

    async def get_device_by_id(self, device_id: uuid.UUID) -> FakeDevice | None:
        return self.devices.get(device_id)

    async def update_session(
        self, session: FakeSession, data: dict[str, object]
    ) -> FakeSession:
        for key, value in data.items():
            setattr(session, key, value)
        return session


@dataclass
class FakeRouter:
    id: uuid.UUID
    vendor: str = "mikrotik"
    api_username: str | None = "admin"
    management_ip_address: str | None = "10.20.0.6"
    public_ip_address: str | None = None


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, FakeRouter] = field(default_factory=dict)
    secret: str | None = "hunter2"

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> FakeRouter:
        return self.routers[router_id]

    def get_decrypted_api_secret(self, router: FakeRouter) -> str | None:
        return self.secret


@dataclass
class FakeDeviceAdapter:
    """A router's active table, as far as this domain can see it."""

    vendor: str = "mikrotik"
    #: MACs/usernames currently logged in on this fake router.
    active_macs: set[str] = field(default_factory=set)
    active_users: set[str] = field(default_factory=set)
    hotspot_servers: int = 1
    coa_accept: bool = False
    coa_port: int | None = 3799
    #: When set, this router refuses to actually drop the rows -- the
    #: "remove returned quietly and the guest is still online" case.
    refuse_removal: bool = False
    #: When set, raised instead of connecting.
    raises: Exception | None = None
    calls: list[tuple[str | None, str | None]] = field(default_factory=list)

    async def read_session_control(
        self, credentials: GuestAccessCredentials
    ) -> SessionControlSnapshot:
        return SessionControlSnapshot(
            hotspot_servers=self.hotspot_servers,
            coa_accept=self.coa_accept,
            coa_port=self.coa_port,
        )

    async def end_sessions(
        self,
        credentials: GuestAccessCredentials,
        *,
        mac_address: str | None,
        username: str | None,
    ) -> SessionEndOutcome:
        if self.raises is not None:
            raise self.raises
        self.calls.append((mac_address, username))
        matched = 0
        if mac_address is not None and mac_address in self.active_macs:
            matched += 1
            if not self.refuse_removal:
                self.active_macs.discard(mac_address)
        if username is not None and username in self.active_users:
            matched += 1
            if not self.refuse_removal:
                self.active_users.discard(username)
        still = 0
        if mac_address is not None and mac_address in self.active_macs:
            still += 1
        if username is not None and username in self.active_users:
            still += 1
        return SessionEndOutcome(
            control=await self.read_session_control(credentials),
            matched=matched,
            removed=matched,
            still_active=still,
        )


# ============================================================================
# Fixture assembly
# ============================================================================


@dataclass
class Fixture:
    service: GuestAccessService
    repository: FakeGuestAccessRepository
    session_lookup: FakeSessionLookup
    router_lookup: FakeRouterLookup
    adapter: FakeDeviceAdapter
    audit: FakeAuditLogWriter
    organization_id: uuid.UUID
    router_id: uuid.UUID
    guest_id: uuid.UUID
    identifier: str


def _build(
    *,
    online: bool = True,
    with_device: bool = True,
    adapter: FakeDeviceAdapter | None = None,
    with_enforcer: bool = True,
    router: FakeRouter | None = None,
    secret: str | None = "hunter2",
) -> Fixture:
    organization_id = uuid.uuid4()
    router_id = uuid.uuid4()
    guest_id = uuid.uuid4()
    device_id = uuid.uuid4()
    identifier = "+919876543210"
    mac = "AA:BB:CC:DD:EE:01"

    adapter = adapter or FakeDeviceAdapter()
    if online:
        adapter.active_users.add(identifier)
        if with_device:
            adapter.active_macs.add(mac)

    session_lookup = FakeSessionLookup(
        guests={(organization_id, identifier): FakeGuest(id=guest_id)},
        sessions={
            guest_id: (
                [
                    FakeSession(
                        id=uuid.uuid4(),
                        router_id=router_id,
                        device_id=device_id if with_device else None,
                    )
                ]
                if online
                else []
            )
        },
        devices={device_id: FakeDevice(mac_address=mac)},
    )
    router_lookup = FakeRouterLookup(
        routers={router_id: router or FakeRouter(id=router_id)}, secret=secret
    )
    repository = FakeGuestAccessRepository()
    audit = FakeAuditLogWriter()
    enforcer = (
        BlocklistEnforcer(
            session_lookup=session_lookup,
            router_lookup=router_lookup,
            terminated_session_status=TERMINATED,
            adapter_factory=lambda vendor: adapter,
        )
        if with_enforcer
        else None
    )
    service = GuestAccessService(
        repository, block_enforcer=enforcer, audit_writer=audit
    )
    return Fixture(
        service=service,
        repository=repository,
        session_lookup=session_lookup,
        router_lookup=router_lookup,
        adapter=adapter,
        audit=audit,
        organization_id=organization_id,
        router_id=router_id,
        guest_id=guest_id,
        identifier=identifier,
    )


async def _block(fx: Fixture, **overrides: object) -> GuestAccessRule:
    kwargs: dict[str, object] = {
        "organization_id": fx.organization_id,
        "requesting_organization_id": fx.organization_id,
        "location_id": None,
        "identifier": fx.identifier,
        "rule_type": AccessRuleType.BLOCKLIST,
        "reason": "abuse",
        "expires_at": None,
        "actor_user_id": uuid.uuid4(),
    }
    kwargs.update(overrides)
    return await fx.service.create_guest_rule(**kwargs)  # type: ignore[arg-type]


# ============================================================================
# The session really ends
# ============================================================================


class TestBlockingEndsTheSession:
    async def test_blocking_removes_the_guest_from_the_routers_active_table(
        self,
    ) -> None:
        """The bug, directly. Before this, a blocked guest's row survived
        on the router and RouterOS kept forwarding for them."""
        fx = _build()

        await _block(fx)

        assert fx.adapter.active_users == set()
        assert fx.adapter.active_macs == set()

    async def test_blocking_terminates_the_platforms_own_session_record(self) -> None:
        """Required alongside the device work, not instead of it:
        ``RadiusService.authorize`` re-admits a guest who still holds an
        ``ACTIVE`` session, so a row left active is a standing
        re-admission ticket."""
        fx = _build()
        session = fx.session_lookup.sessions[fx.guest_id][0]

        await _block(fx)

        assert session.status == TERMINATED
        assert session.ended_at is not None
        assert session.disconnect_reason == "Blocked: abuse"

    async def test_the_device_is_told_both_identifiers_it_can_match_on(self) -> None:
        """A live session's ``user`` on the router and this platform's own
        stored identifier have been seen to disagree (2026-08-18). Sending
        both is what keeps that guest endable."""
        fx = _build()

        await _block(fx)

        assert fx.adapter.calls == [("AA:BB:CC:DD:EE:01", "+919876543210")]

    async def test_a_session_with_no_recorded_device_is_still_ended(self) -> None:
        """``GuestSession.device_id`` is nullable. A missing MAC is not a
        failure -- the portal username still identifies the guest."""
        fx = _build(with_device=False)

        await _block(fx)

        assert fx.adapter.calls == [(None, "+919876543210")]
        assert fx.adapter.active_users == set()

    async def test_the_rule_records_what_was_actually_confirmed(self) -> None:
        fx = _build()

        rule = await _block(fx)

        assert rule.enforcement_status == BlockEnforcementStatus.ENFORCED.value
        assert rule.enforcement_error is None
        assert rule.enforced_at is not None
        assert rule.sessions_ended == 1

    async def test_a_guest_who_is_offline_is_blocked_without_touching_a_router(
        self,
    ) -> None:
        """Zero sessions ended is a real, correct outcome -- not a
        failure, and not a reason to open a socket."""
        fx = _build(online=False)

        rule = await _block(fx)

        assert fx.adapter.calls == []
        assert rule.enforcement_status == BlockEnforcementStatus.ENFORCED.value
        assert rule.sessions_ended == 0

    async def test_a_guest_who_has_never_connected_is_blocked_successfully(
        self,
    ) -> None:
        """These tables are identifier-keyed precisely so a rule can exist
        before any ``Guest`` row does (see ``models.py``). No guest, no
        session, nothing to end."""
        fx = _build(online=False)
        fx.session_lookup.guests.clear()

        rule = await _block(fx)

        assert rule.enforcement_status == BlockEnforcementStatus.ENFORCED.value
        assert rule.sessions_ended == 0

    async def test_blocking_twice_is_idempotent(self) -> None:
        fx = _build()

        await _block(fx)
        second = await _block(fx)

        assert second.enforcement_status == BlockEnforcementStatus.ENFORCED.value
        assert second.sessions_ended == 0
        assert fx.adapter.active_users == set()


# ============================================================================
# A router that cannot be made to agree is reported, never skipped
# ============================================================================


class TestFailuresAreReported:
    async def test_a_session_still_on_the_device_is_an_error_not_a_green_toast(
        self,
    ) -> None:
        """The router accepted the removal and kept the session. The guest
        is barred from signing in again and is, right now, still online --
        which the caller must be told."""
        fx = _build(adapter=FakeDeviceAdapter(refuse_removal=True))

        with pytest.raises(SessionStillActiveOnDeviceError):
            await _block(fx)

    async def test_the_error_names_coa_availability_read_from_that_router(
        self,
    ) -> None:
        """CoA availability is the operator's next lever, and it is a fact
        about *this* router -- never inferred from what this platform
        believes it configured."""
        fx = _build(adapter=FakeDeviceAdapter(refuse_removal=True, coa_accept=False))

        with pytest.raises(SessionStillActiveOnDeviceError) as excinfo:
            await _block(fx)

        assert "does not accept RADIUS Disconnect-Requests" in str(excinfo.value)
        assert excinfo.value.status_code == 502

    async def test_a_coa_capable_router_is_described_differently(self) -> None:
        fx = _build(
            adapter=FakeDeviceAdapter(
                refuse_removal=True, coa_accept=True, coa_port=3799
            )
        )

        with pytest.raises(SessionStillActiveOnDeviceError) as excinfo:
            await _block(fx)

        assert "accepts RADIUS Disconnect-Requests on port 3799" in str(excinfo.value)

    async def test_a_router_with_no_captive_portal_is_refused_not_reported_clean(
        self,
    ) -> None:
        """With no ``/ip hotspot`` server there is no active table, so
        "removed nothing" and "was never online here" are the same
        observation. A platform that cannot tell them apart must not claim
        the stronger one."""
        fx = _build(adapter=FakeDeviceAdapter(hotspot_servers=0))

        with pytest.raises(RouterHasNoHotspotError):
            await _block(fx)

    async def test_an_unreachable_router_raises_rather_than_reporting_success(
        self,
    ) -> None:
        fx = _build(
            adapter=FakeDeviceAdapter(
                raises=GuestAccessDeviceConnectionError("10.20.0.6", "timed out")
            )
        )

        with pytest.raises(GuestAccessDeviceConnectionError):
            await _block(fx)

    async def test_missing_router_credentials_raise_rather_than_guess(self) -> None:
        fx = _build(secret=None)

        with pytest.raises(BlockEnforcementMissingCredentialsError):
            await _block(fx)

    async def test_a_failure_is_recorded_committed_and_re_raised(self) -> None:
        """The commit is the point. ``GenericRepository.update`` only
        ``flush()``es and ``get_db_session`` rolls back on any exception,
        so without an explicit commit the failure record is discarded and
        the row reads as though the block had reached the device."""
        fx = _build(adapter=FakeDeviceAdapter(refuse_removal=True))

        with pytest.raises(SessionStillActiveOnDeviceError):
            await _block(fx)

        rule = next(iter(fx.repository.guest_rules.values()))
        assert rule.enforcement_status == BlockEnforcementStatus.FAILED.value
        assert rule.enforcement_error
        assert rule.sessions_ended == 0
        # Two: the block itself, committed before any socket is opened, and
        # the failure record, committed before the re-raise.
        assert fx.repository.commits == 2

    async def test_the_block_itself_survives_a_device_failure(self) -> None:
        """Barring a future sign-in is the half this platform can always
        deliver. A customer who asked for someone to be blocked must not
        end up with neither the block nor the disconnection because a
        router was unreachable."""
        fx = _build(
            adapter=FakeDeviceAdapter(
                raises=GuestAccessDeviceConnectionError("10.20.0.6", "timed out")
            )
        )

        with pytest.raises(GuestAccessDeviceConnectionError):
            await _block(fx)

        rule = next(iter(fx.repository.guest_rules.values()))
        assert rule.is_active is True
        assert rule.rule_type == AccessRuleType.BLOCKLIST.value

    async def test_a_device_failure_leaves_the_session_record_untouched(self) -> None:
        """The safe direction to be wrong in. A record that still says
        ``ACTIVE`` under-claims; a record saying ``TERMINATED`` over a
        guest the device is still forwarding is the exact falsehood being
        fixed."""
        fx = _build(adapter=FakeDeviceAdapter(refuse_removal=True))
        session = fx.session_lookup.sessions[fx.guest_id][0]

        with pytest.raises(SessionStillActiveOnDeviceError):
            await _block(fx)

        assert session.status == ACTIVE
        assert session.ended_at is None


# ============================================================================
# Nothing is enforced silently
# ============================================================================


class TestEnforcementIsNeverSilent:
    async def test_a_non_blocklist_rule_contacts_no_router(self) -> None:
        fx = _build()

        rule = await _block(fx, rule_type=AccessRuleType.WHITELIST)

        assert fx.adapter.calls == []
        assert rule.enforcement_status == BlockEnforcementStatus.NOT_APPLICABLE.value
        assert fx.adapter.active_users == {fx.identifier}

    async def test_a_block_created_with_no_enforcer_records_that_it_was_not_enforced(
        self,
    ) -> None:
        """"Nothing needed doing" and "nobody was wired up to do it" are
        different facts. Collapsing them is how a block that ends no
        sessions goes unnoticed -- which is how the original defect
        survived."""
        fx = _build(with_enforcer=False)

        rule = await _block(fx)

        assert rule.enforcement_status == BlockEnforcementStatus.UNENFORCED.value
        assert rule.enforcement_status != BlockEnforcementStatus.NOT_APPLICABLE.value
        assert rule.enforcement_status != BlockEnforcementStatus.ENFORCED.value

    async def test_a_pending_row_never_claims_to_be_enforced_before_the_device_agrees(
        self,
    ) -> None:
        """The value committed before the first socket must not be
        ``ENFORCED`` -- a process killed mid-write has to leave a row
        saying "nobody confirmed this"."""
        recorded: list[str | None] = []
        fx = _build()
        original = fx.repository.create_guest_rule

        async def _spy(**fields: object) -> GuestAccessRule:
            recorded.append(fields.get("enforcement_status"))  # type: ignore[arg-type]
            return await original(**fields)

        fx.repository.create_guest_rule = _spy  # type: ignore[method-assign]
        await _block(fx)

        assert recorded == [BlockEnforcementStatus.PENDING.value]


# ============================================================================
# Retry and reversibility
# ============================================================================


class TestRetryAndUnblock:
    async def test_enforcement_can_be_retried_without_creating_a_second_rule(
        self,
    ) -> None:
        """The same separation ``VlanService.push_vlan_to_device`` makes:
        an operator whose block failed on an unreachable router retries the
        device half alone."""
        adapter = FakeDeviceAdapter(refuse_removal=True)
        fx = _build(adapter=adapter)

        with pytest.raises(SessionStillActiveOnDeviceError):
            await _block(fx)
        rule = next(iter(fx.repository.guest_rules.values()))
        assert rule.enforcement_status == BlockEnforcementStatus.FAILED.value

        adapter.refuse_removal = False
        retried = await fx.service.enforce_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )

        assert len(fx.repository.guest_rules) == 1
        assert retried.enforcement_status == BlockEnforcementStatus.ENFORCED.value
        assert adapter.active_users == set()
        assert fx.session_lookup.sessions[fx.guest_id][0].status == TERMINATED

    async def test_unblocking_needs_no_device_work_because_nothing_was_left_there(
        self,
    ) -> None:
        """Reversibility falls out of the mechanism: enforcement only ever
        *removes* rows from the router's active table. It writes no
        binding, no filter rule and no address-list entry, so there is no
        residue an unblock would have to clean up -- and no way for a
        stale artefact to keep blocking a guest whose rule is gone.

        This is exactly why an ``ip-binding type=blocked`` was not used for
        identifier-keyed rules: that *would* leave durable device state,
        keyed on a MAC phones rotate.
        """
        fx = _build()
        rule = await _block(fx)
        calls_after_block = len(fx.adapter.calls)

        await fx.service.deactivate_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )

        assert rule.is_active is False
        assert len(fx.adapter.calls) == calls_after_block

    async def test_an_unblocked_guest_is_allowed_again_by_the_decision_path(
        self,
    ) -> None:
        """The half that lets them back in. ``check_access`` is what every
        login path consults, so this is the real proof that a block is
        reversible rather than a one-way door."""
        fx = _build()
        rule = await _block(fx)

        matching: list[GuestAccessRule] = [rule]

        async def _list_matching(**_: object) -> list[GuestAccessRule]:
            return [r for r in matching if r.is_active]

        fx.repository.list_matching_guest_rules = _list_matching  # type: ignore[attr-defined]
        fx.repository.list_matching_device_rules = (  # type: ignore[attr-defined]
            lambda **_: _empty()
        )

        blocked = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,
            identifier=fx.identifier,
            mac_address=None,
        )
        assert blocked.allowed is False

        await fx.service.deactivate_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )

        allowed = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,
            identifier=fx.identifier,
            mac_address=None,
        )
        assert allowed.allowed is True


async def _empty() -> list[DeviceAccessRule]:
    return []
