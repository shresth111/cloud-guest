"""Access Tiers: a tier reaches its members, and only its members.

Three things were wrong, each of which made the Access Tiers screen describe
something the platform did not do:

* Mapping a tier to a location wrote the same untargeted assignment that
  makes a policy the location's default, so the tier applied to every guest
  there and the newest mapping won. Re-saving the location's own limits did
  not win it back.
* Publishing any policy re-applied every live queue for nobody in
  particular, which put each tier member back on the location's speed.
* Removing a member, unmapping a tier or deleting one told no one, so guests
  already online kept the tier until they next signed in.

A tier-to-location mapping is now a ``MEMBERS`` assignment: it records that
the tier is offered there and is never a resolution candidate. Who the tier
reaches is said only by the ``GUEST`` assignments beside it.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.domains.policy import router as policy_router
from app.domains.policy.constants import PolicyAssignmentTargetType, PolicyType
from app.domains.policy.exceptions import (
    PolicyAssignmentTargetIdNotAllowedError,
    PolicyRulesValidationError,
)
from app.domains.policy.models import Policy
from app.domains.policy.repository import PolicyRepository
from app.domains.policy.schemas import (
    PolicyAssignmentCreateRequest,
    PolicyResponse,
    PolicyVersionCreateRequest,
)
from app.domains.policy.service import PolicyService
from app.domains.queue_management import tasks as queue_tasks
from app.domains.queue_management.constants import QueueStatus, QueueTargetType
from app.domains.rbac.enums import ScopeType

from .test_policy import (
    FakeAuditLogWriter,
    FakeLocationLookup,
    FakeOrganizationLookup,
    FakePolicyRepository,
    _now,
)
from .test_queue_management import _make_router, make_harness

LOCATION = ScopeType.LOCATION.value
NONE = PolicyAssignmentTargetType.NONE.value
MEMBERS = PolicyAssignmentTargetType.MEMBERS.value
GUEST = PolicyAssignmentTargetType.GUEST.value


# ============================================================================
# A venue: one organization, one location, a default and a tier
# ============================================================================


class Venue:
    def __init__(self) -> None:
        self.repo = FakePolicyRepository()
        self.orgs = FakeOrganizationLookup()
        self.locations = FakeLocationLookup()
        self.service = PolicyService(
            self.repo, self.orgs, self.locations, audit_writer=FakeAuditLogWriter()
        )
        self.org = self.orgs.add()
        self.location = self.locations.add(organization_id=self.org.id)

    async def policy(
        self, policy_type: PolicyType, name: str, rules: dict[str, object]
    ) -> Policy:
        """Created through the same request schema the dashboard posts, so
        an unknown key is rejected here exactly as it would be over HTTP."""
        policy = await self.service.create_policy(
            actor_user_id=None,
            requesting_organization_id=self.org.id,
            organization_id=self.org.id,
            policy_type=policy_type,
            name=name,
            description=None,
        )
        await self.publish(policy, rules)
        return policy

    async def publish(self, policy: Policy, rules: dict[str, object]) -> None:
        payload = PolicyVersionCreateRequest(rules=rules)
        version = await self.service.create_version(
            policy_id=policy.id,
            requesting_organization_id=self.org.id,
            actor_user_id=None,
            rules=payload.rules,
        )
        await self.service.publish_version(
            policy_id=policy.id,
            version_id=version.id,
            requesting_organization_id=self.org.id,
            actor_user_id=None,
        )

    async def assign(
        self,
        policy: Policy,
        *,
        target_type: str,
        target_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
    ):
        payload = PolicyAssignmentCreateRequest(
            scope_type=LOCATION,
            scope_id=location_id or self.location.id,
            target_type=target_type,
            target_id=target_id,
        )
        return await self.service.create_assignment(
            policy_id=policy.id,
            requesting_organization_id=self.org.id,
            actor_user_id=None,
            scope_type=payload.scope_type,
            scope_id=payload.scope_id,
            priority=payload.priority,
            target_type=payload.target_type,
            target_id=payload.target_id,
        )

    async def unassign(self, policy: Policy, assignment_id: uuid.UUID):
        return await self.service.deactivate_assignment(
            policy_id=policy.id,
            assignment_id=assignment_id,
            requesting_organization_id=self.org.id,
            actor_user_id=None,
        )

    async def speed_for(self, guest_id: uuid.UUID | None) -> tuple[object, str]:
        resolved = await self.service.resolve_effective_policy(
            policy_type=PolicyType.BANDWIDTH,
            organization_id=self.org.id,
            location_id=self.location.id,
            guest_id=guest_id,
        )
        return resolved.rules.get("download_rate_kbps"), resolved.source

    async def rules_for(
        self, policy_type: PolicyType, guest_id: uuid.UUID | None
    ) -> dict[str, object]:
        resolved = await self.service.resolve_effective_policy(
            policy_type=policy_type,
            organization_id=self.org.id,
            location_id=self.location.id,
            guest_id=guest_id,
        )
        return resolved.rules


def _speed(kbps: int) -> dict[str, object]:
    return {"download_rate_kbps": kbps, "upload_rate_kbps": kbps}


async def _venue_with_default_and_tier() -> tuple[Venue, Policy, Policy]:
    """The location's own limits at 40 Mbps, then a 10 Mbps tier mapped to
    the same location afterwards -- the tier's mapping is the newer row."""
    venue = Venue()
    default = await venue.policy(PolicyType.BANDWIDTH, "HQ", _speed(40960))
    await venue.assign(default, target_type=NONE)
    tier = await venue.policy(PolicyType.BANDWIDTH, "Staff", _speed(10240))
    await venue.assign(tier, target_type=MEMBERS)
    return venue, default, tier


# ============================================================================
# Scope
# ============================================================================


class TestATierReachesOnlyItsMembers:
    async def test_a_guest_who_is_not_a_member_gets_the_location_speed(self) -> None:
        venue, _, _ = await _venue_with_default_and_tier()

        assert await venue.speed_for(uuid.uuid4()) == (
            40960,
            f"location:{venue.location.id}",
        )
        # And a login that names no guest at all.
        assert (await venue.speed_for(None))[0] == 40960

    async def test_a_member_gets_the_tier_speed(self) -> None:
        venue, _, tier = await _venue_with_default_and_tier()
        member = uuid.uuid4()
        await venue.assign(tier, target_type=GUEST, target_id=member)

        assert await venue.speed_for(member) == (10240, f"guest:{member}")
        assert (await venue.speed_for(uuid.uuid4()))[0] == 40960

    async def test_resaving_the_location_limits_leaves_both_correct(self) -> None:
        """The location's limits are re-saved (a new published version on
        the same policy, the same mapping reused). Non-members follow the
        new number; the member stays on the tier."""
        venue, default, tier = await _venue_with_default_and_tier()
        member = uuid.uuid4()
        await venue.assign(tier, target_type=GUEST, target_id=member)

        await venue.publish(default, _speed(20480))

        assert (await venue.speed_for(uuid.uuid4()))[0] == 20480
        assert (await venue.speed_for(member))[0] == 10240

    async def test_the_old_untargeted_mapping_did_apply_to_everyone(self) -> None:
        """What a tier mapping used to be, kept as a test so the difference
        stays visible: the same tier mapped with ``NONE`` is the location's
        newest default and reaches a guest who was never added to it."""
        venue = Venue()
        default = await venue.policy(PolicyType.BANDWIDTH, "HQ", _speed(40960))
        await venue.assign(default, target_type=NONE)
        tier = await venue.policy(PolicyType.BANDWIDTH, "Staff", _speed(10240))
        await venue.assign(tier, target_type=NONE)

        assert (await venue.speed_for(uuid.uuid4()))[0] == 10240

    async def test_a_tier_mapped_to_another_location_reaches_no_one_here(self) -> None:
        venue, _, tier = await _venue_with_default_and_tier()
        elsewhere = venue.locations.add(organization_id=venue.org.id)
        member = uuid.uuid4()
        await venue.assign(
            tier, target_type=GUEST, target_id=member, location_id=elsewhere.id
        )

        assert (await venue.speed_for(member))[0] == 40960

    async def test_a_members_mapping_takes_no_target_id(self) -> None:
        venue, _, tier = await _venue_with_default_and_tier()
        with pytest.raises(PolicyAssignmentTargetIdNotAllowedError):
            await venue.assign(tier, target_type=MEMBERS, target_id=uuid.uuid4())

    async def test_the_paired_policies_follow_the_same_rule(self) -> None:
        """A tier is several policies kept in step. Each one resolves for a
        member and for nobody else -- device count, session and idle
        timeouts, and the data and daily-time limits alike."""
        venue = Venue()
        member, other = uuid.uuid4(), uuid.uuid4()
        tier_rules: dict[PolicyType, dict[str, object]] = {
            PolicyType.DEVICE: {"max_devices_per_guest": 1},
            PolicyType.SESSION: {
                "session_timeout_minutes": 60,
                "idle_timeout_minutes": 5,
            },
            PolicyType.FUP: {
                "daily_data_limit_mb": 500,
                "daily_time_limit_minutes": 120,
            },
        }
        for policy_type, rules in tier_rules.items():
            policy = await venue.policy(policy_type, "Staff", rules)
            await venue.assign(policy, target_type=MEMBERS)
            await venue.assign(policy, target_type=GUEST, target_id=member)

        device = await venue.rules_for(PolicyType.DEVICE, member)
        assert device["max_devices_per_guest"] == 1
        session = await venue.rules_for(PolicyType.SESSION, member)
        assert session["session_timeout_minutes"] == 60
        assert session["idle_timeout_minutes"] == 5
        fup = await venue.rules_for(PolicyType.FUP, member)
        assert (fup["daily_data_limit_mb"], fup["daily_time_limit_minutes"]) == (
            500,
            120,
        )

        # Everyone else gets the platform's own answer, not the tier's.
        assert (await venue.rules_for(PolicyType.DEVICE, other))[
            "max_devices_per_guest"
        ] != 1
        assert (await venue.rules_for(PolicyType.SESSION, other))[
            "session_timeout_minutes"
        ] != 60
        assert (await venue.rules_for(PolicyType.FUP, other)) == {}

    async def test_a_tier_form_key_the_backend_does_not_know_is_refused(self) -> None:
        """The request schema forbids unknown keys, so a frontend that sends
        one is told so rather than having it dropped."""
        venue = Venue()
        with pytest.raises(PolicyRulesValidationError):
            await venue.policy(
                PolicyType.FUP, "Staff", {"daily_data_limit_mb": 1, "per_session": 1}
            )


class TestResolutionIsDeterministic:
    async def test_equal_candidates_resolve_the_same_way_in_any_row_order(self) -> None:
        venue = Venue()
        first = await venue.policy(PolicyType.BANDWIDTH, "HQ", _speed(40960))
        older = await venue.assign(first, target_type=NONE)
        second = await venue.policy(PolicyType.BANDWIDTH, "HQ v2", _speed(20480))
        newer = await venue.assign(second, target_type=NONE)
        # Identical WHO, WHERE and priority; written in the same instant.
        older.created_at = newer.created_at = _now()
        winner = max(older, newer, key=lambda a: str(a.id))

        for order in ([older, newer], [newer, older]):
            assert venue.service.resolver.resolve(candidates=order) is winner

    async def test_a_member_mapping_outranks_a_newer_default(self) -> None:
        venue, _, tier = await _venue_with_default_and_tier()
        member = uuid.uuid4()
        await venue.assign(tier, target_type=GUEST, target_id=member)
        late = await venue.policy(PolicyType.BANDWIDTH, "HQ later", _speed(81920))
        await venue.assign(late, target_type=NONE)

        assert (await venue.speed_for(member))[0] == 10240
        assert (await venue.speed_for(uuid.uuid4()))[0] == 81920


class _RecordingSession:
    """Stands in for the database session: keeps the statement, returns no
    rows. Enough to read what the real query asks for."""

    def __init__(self) -> None:
        self.statements: list[object] = []

    async def execute(self, statement: object) -> object:
        self.statements.append(statement)
        empty = SimpleNamespace(all=lambda: [], first=lambda: None)
        return SimpleNamespace(scalars=lambda: empty, all=lambda: [])


def _literal_sql(statement: object) -> str:
    return str(
        statement.compile(  # type: ignore[attr-defined]
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


class TestTheRealQueries:
    async def test_a_members_mapping_is_never_selected_as_a_candidate(self) -> None:
        """The fake repository above mirrors the real one by hand. This reads
        the SQL the real one builds, with every target the caller can name."""
        session = _RecordingSession()
        await PolicyRepository(session).list_candidate_assignments(  # type: ignore[arg-type]
            policy_type=PolicyType.BANDWIDTH.value,
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            role_ids=[uuid.uuid4()],
            guest_id=uuid.uuid4(),
        )
        sql = _literal_sql(session.statements[0])

        assert "target_type = 'none'" in sql
        assert "target_type = 'guest'" in sql
        assert "'members'" not in sql

    async def test_members_are_counted_in_one_grouped_statement(self) -> None:
        session = _RecordingSession()
        policy_ids = [uuid.uuid4() for _ in range(25)]
        counts = await PolicyRepository(session).count_active_guest_members(  # type: ignore[arg-type]
            policy_ids
        )
        assert counts == {}
        assert len(session.statements) == 1
        sql = _literal_sql(session.statements[0])
        assert "GROUP BY policy_assignments.policy_id" in sql
        assert "target_type = 'guest'" in sql
        assert "is_active IS true" in sql

    async def test_no_policies_means_no_query(self) -> None:
        session = _RecordingSession()
        assert await PolicyRepository(session).count_active_guest_members([]) == {}  # type: ignore[arg-type]
        assert session.statements == []


# ============================================================================
# Members
# ============================================================================


class TestMembers:
    async def test_the_count_is_the_active_guest_mappings(self) -> None:
        venue, default, tier = await _venue_with_default_and_tier()
        first = await venue.assign(tier, target_type=GUEST, target_id=uuid.uuid4())
        await venue.assign(tier, target_type=GUEST, target_id=uuid.uuid4())

        counts = await venue.service.member_counts([tier.id, default.id])
        assert counts.get(tier.id) == 2
        assert counts.get(default.id, 0) == 0

        await venue.unassign(tier, first.id)
        assert (await venue.service.member_counts([tier.id])).get(tier.id) == 1

    async def test_the_list_response_carries_it(self) -> None:
        venue, _, tier = await _venue_with_default_and_tier()
        await venue.assign(tier, target_type=GUEST, target_id=uuid.uuid4())
        counts = await venue.service.member_counts([tier.id])

        response = policy_router._policy_response(tier, member_count=counts[tier.id])
        assert isinstance(response, PolicyResponse)
        assert response.model_dump()["member_count"] == 1
        # A caller that does not ask gets zero, not a missing key.
        assert policy_router._policy_response(tier).member_count == 0

    async def test_unmapping_a_tier_ends_its_memberships_at_that_location(self) -> None:
        """A membership grants the tier by itself, so one left behind kept
        a guest on the tier at a venue it had been taken off."""
        venue, _, tier = await _venue_with_default_and_tier()
        member = uuid.uuid4()
        await venue.assign(tier, target_type=GUEST, target_id=member)
        elsewhere = venue.locations.add(organization_id=venue.org.id)
        await venue.assign(tier, target_type=MEMBERS, location_id=elsewhere.id)
        kept = await venue.assign(
            tier, target_type=GUEST, target_id=member, location_id=elsewhere.id
        )
        mapping = next(
            a
            for a in venue.repo.assignments.values()
            if a.policy_id == tier.id
            and a.target_type == MEMBERS
            and a.scope_id == venue.location.id
        )

        await venue.unassign(tier, mapping.id)

        assert (await venue.speed_for(member))[0] == 40960
        # The other location's mapping and membership are untouched.
        assert kept.is_active is True
        assert (await venue.service.member_counts([tier.id]))[tier.id] == 1

    async def test_a_tier_still_mapped_another_way_keeps_its_members(self) -> None:
        """A tier mapped before this change holds an untargeted mapping.
        Re-mapping it adds a ``MEMBERS`` row beside that one; removing
        either while the other stands is not an unmap."""
        venue = Venue()
        tier = await venue.policy(PolicyType.BANDWIDTH, "Staff", _speed(10240))
        legacy = await venue.assign(tier, target_type=NONE)
        await venue.assign(tier, target_type=MEMBERS)
        member = uuid.uuid4()
        membership = await venue.assign(tier, target_type=GUEST, target_id=member)

        await venue.unassign(tier, legacy.id)

        assert membership.is_active is True
        assert (await venue.speed_for(member))[0] == 10240
        # ...and with the untargeted row gone, it no longer reaches others.
        assert (await venue.speed_for(uuid.uuid4()))[0] is None

    async def test_removing_one_member_touches_no_other(self) -> None:
        venue, _, tier = await _venue_with_default_and_tier()
        leaving, staying = uuid.uuid4(), uuid.uuid4()
        gone = await venue.assign(tier, target_type=GUEST, target_id=leaving)
        kept = await venue.assign(tier, target_type=GUEST, target_id=staying)

        await venue.unassign(tier, gone.id)

        assert kept.is_active is True
        assert (await venue.speed_for(leaving))[0] == 40960
        assert (await venue.speed_for(staying))[0] == 10240

    async def test_deactivating_a_tier_returns_members_to_the_location(self) -> None:
        venue, _, tier = await _venue_with_default_and_tier()
        member = uuid.uuid4()
        await venue.assign(tier, target_type=GUEST, target_id=member)

        await venue.service.deactivate_policy(
            policy_id=tier.id,
            requesting_organization_id=venue.org.id,
            actor_user_id=None,
        )

        assert (await venue.speed_for(member))[0] == 40960


# ============================================================================
# Re-apply: the queue of a guest who is already online
# ============================================================================


class _SessionGuests:
    """The guest-domain lookup the worker passes: which sessions are live,
    and whose each one is."""

    def __init__(self) -> None:
        self.guest_by_session: dict[uuid.UUID, uuid.UUID | None] = {}
        self.asked: list[set[uuid.UUID]] = []

    async def live_session_ids(self, session_ids) -> set[uuid.UUID]:  # noqa: ANN001
        return set(session_ids) & set(self.guest_by_session)

    async def guest_ids_for_sessions(self, session_ids) -> dict:  # noqa: ANN001
        self.asked.append(set(session_ids))
        return {sid: self.guest_by_session.get(sid) for sid in session_ids}


def _rules(kbps: int) -> dict[str, object]:
    return {
        "download_rate_kbps": kbps,
        "upload_rate_kbps": kbps,
        "burst_download_kbps": None,
        "burst_upload_kbps": None,
        "burst_threshold_kbps": None,
        "burst_time_seconds": None,
        "priority": None,
    }


class _Online:
    """A location with a 40 Mbps default, a 10 Mbps tier member online and a
    non-member online, each with a queue on the router."""

    def __init__(self) -> None:
        self.h = make_harness()
        self.router = self.h.router_lookup.add(_make_router())
        self.scope = (self.router.organization_id, self.router.location_id)
        self.h.policy_lookup.rules_by_scope[self.scope] = _rules(40960)
        self.guests = _SessionGuests()
        self.h.service.session_liveness_lookup = self.guests
        self.member, self.other = uuid.uuid4(), uuid.uuid4()
        self.h.policy_lookup.rules_by_guest[self.member] = _rules(10240)
        self.member_session = uuid.uuid4()
        self.other_session = uuid.uuid4()

    async def sign_in(self) -> None:
        for session_id, guest_id, address in (
            (self.member_session, self.member, "10.0.0.5/32"),
            (self.other_session, self.other, "10.0.0.6/32"),
        ):
            self.guests.guest_by_session[session_id] = guest_id
            await self.h.service.resolve_and_assign_queue(
                requesting_organization_id=self.router.organization_id,
                location_id=self.router.location_id,
                router_id=self.router.id,
                target_type=QueueTargetType.SESSION,
                target_id=session_id,
                device_target=address,
                guest_id=guest_id,
            )

    async def reapply(self) -> dict[str, int]:
        return await self.h.service.reapply_active_sessions_for_location(
            location_id=self.router.location_id,
            requesting_organization_id=self.router.organization_id,
        )

    async def rate(self, session_id: uuid.UUID) -> int:
        active = await self.h.repository.get_active_assignment_for_target(
            target_type=QueueTargetType.SESSION.value, target_id=session_id
        )
        assert active is not None and active.status == QueueStatus.ACTIVE.value
        profile = await self.h.service.get_profile(active.queue_profile_id)
        return profile.download_rate_kbps

    def device_writes(self) -> int:
        return len(self.h.device_adapter.created_ids)


class TestReapplyResolvesForTheSessionsOwnGuest:
    async def test_a_publish_keeps_a_member_on_the_tier_speed(self) -> None:
        """Any policy save re-applies the location. It used to resolve for
        no guest at all, which moved every member to the location speed."""
        online = _Online()
        await online.sign_in()
        assert await online.rate(online.member_session) == 10240
        writes = online.device_writes()

        result = await online.reapply()

        assert result == {"reapplied": 2, "failed": 0}
        assert await online.rate(online.member_session) == 10240
        assert await online.rate(online.other_session) == 40960
        # Nothing changed for either, so the router was not written to.
        assert online.device_writes() == writes
        assert online.guests.asked == [{online.member_session, online.other_session}]
        assert online.h.policy_lookup.guest_ids_seen[-2:] in (
            [online.member, online.other],
            [online.other, online.member],
        )

    async def test_a_new_location_speed_reaches_non_members_only(self) -> None:
        online = _Online()
        await online.sign_in()
        writes = online.device_writes()
        online.h.policy_lookup.rules_by_scope[online.scope] = _rules(20480)

        await online.reapply()

        assert await online.rate(online.other_session) == 20480
        assert await online.rate(online.member_session) == 10240
        assert online.device_writes() == writes + 1

    async def test_adding_a_member_moves_only_that_guest(self) -> None:
        online = _Online()
        await online.sign_in()
        writes = online.device_writes()
        online.h.policy_lookup.rules_by_guest[online.other] = _rules(10240)

        await online.reapply()

        assert await online.rate(online.other_session) == 10240
        assert await online.rate(online.member_session) == 10240
        assert online.device_writes() == writes + 1

    async def test_removing_a_member_returns_that_guest_to_the_location_speed(
        self,
    ) -> None:
        online = _Online()
        await online.sign_in()
        writes = online.device_writes()
        del online.h.policy_lookup.rules_by_guest[online.member]

        await online.reapply()

        assert await online.rate(online.member_session) == 40960
        assert await online.rate(online.other_session) == 40960
        assert online.device_writes() == writes + 1

    async def test_a_second_reapply_writes_nothing(self) -> None:
        online = _Online()
        await online.sign_in()
        online.h.policy_lookup.rules_by_guest[online.member] = _rules(5120)
        await online.reapply()
        writes = online.device_writes()

        await online.reapply()

        assert online.device_writes() == writes

    async def test_a_lookup_that_cannot_say_whose_session_it_is(self) -> None:
        """A deployment without the second question still re-applies, for no
        guest in particular -- what every re-apply did before."""
        online = _Online()
        await online.sign_in()

        class _LivenessOnly:
            async def live_session_ids(self, session_ids):  # noqa: ANN001, ANN202
                return set(session_ids)

        online.h.service.session_liveness_lookup = _LivenessOnly()
        result = await online.reapply()

        assert result == {"reapplied": 2, "failed": 0}
        assert online.h.policy_lookup.guest_ids_seen[-2:] == [None, None]

    def test_the_worker_lookup_answers_the_second_question(self) -> None:
        sql = _literal_sql(
            queue_tasks.GuestSessionLiveness.guest_ids_statement([uuid.uuid4()])
        )
        assert "guest_sessions.guest_id" in sql
        assert "guest_sessions.id IN" in sql


# ============================================================================
# Each change to a tier asks for the re-apply
# ============================================================================


def _assignment(policy_id: uuid.UUID, **fields: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "policy_id": policy_id,
        "scope_type": "location",
        "scope_id": uuid.uuid4(),
        "priority": 0,
        "target_type": "guest",
        "target_id": uuid.uuid4(),
        "is_active": False,
        "created_at": _now(),
    }
    base.update(fields)
    return SimpleNamespace(**base)


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(request_id="t"))


@pytest.fixture
def dispatched(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(
        queue_tasks.reapply_policy_assignments,
        "apply_async",
        lambda **kwargs: sent.append(kwargs),
    )
    return sent


class TestEveryTierChangeAsksForAReapply:
    async def test_removing_a_member_names_the_location(
        self, dispatched: list[dict[str, object]]
    ) -> None:
        """The membership is no longer active, so the task cannot find its
        location from the policy's own mappings -- it has to be told."""
        policy_id = uuid.uuid4()
        removed = _assignment(policy_id)

        class _Service:
            async def deactivate_assignment(self, **fields):  # noqa: ANN003, ANN202
                return removed

        await policy_router.deactivate_policy_assignment(
            request=_request(),
            policy_id=policy_id,
            assignment_id=removed.id,
            user=SimpleNamespace(id=str(uuid.uuid4())),
            requesting_organization_id=uuid.uuid4(),
            service=_Service(),
        )

        assert len(dispatched) == 1
        kwargs = dispatched[0]["kwargs"]
        assert kwargs["policy_id"] == str(policy_id)
        assert kwargs["location_id"] == str(removed.scope_id)
        assert dispatched[0]["countdown"] > 0

    async def test_unmapping_a_tier_names_the_location(
        self, dispatched: list[dict[str, object]]
    ) -> None:
        policy_id = uuid.uuid4()
        unmapped = _assignment(policy_id, target_type=MEMBERS, target_id=None)

        class _Service:
            async def deactivate_assignment(self, **fields):  # noqa: ANN003, ANN202
                return unmapped

        await policy_router.deactivate_policy_assignment(
            request=_request(),
            policy_id=policy_id,
            assignment_id=unmapped.id,
            user=SimpleNamespace(id=str(uuid.uuid4())),
            requesting_organization_id=uuid.uuid4(),
            service=_Service(),
        )

        assert dispatched[0]["kwargs"]["location_id"] == str(unmapped.scope_id)

    async def test_an_organization_scoped_removal_names_no_location(
        self, dispatched: list[dict[str, object]]
    ) -> None:
        policy_id = uuid.uuid4()
        removed = _assignment(policy_id, scope_type="organization")

        class _Service:
            async def deactivate_assignment(self, **fields):  # noqa: ANN003, ANN202
                return removed

        await policy_router.deactivate_policy_assignment(
            request=_request(),
            policy_id=policy_id,
            assignment_id=removed.id,
            user=SimpleNamespace(id=str(uuid.uuid4())),
            requesting_organization_id=uuid.uuid4(),
            service=_Service(),
        )

        assert dispatched[0]["kwargs"]["location_id"] == ""

    async def test_deleting_a_tier_or_a_location_limit_dispatches(
        self, dispatched: list[dict[str, object]]
    ) -> None:
        policy_id = uuid.uuid4()

        class _Service:
            async def deactivate_policy(self, **fields):  # noqa: ANN003, ANN202
                return SimpleNamespace(
                    id=policy_id,
                    organization_id=uuid.uuid4(),
                    policy_type=PolicyType.BANDWIDTH.value,
                    name="Staff",
                    description=None,
                    is_active=False,
                    current_version_id=None,
                    created_by_user_id=None,
                    created_at=_now(),
                    updated_at=_now(),
                )

        await policy_router.deactivate_policy(
            request=_request(),
            policy_id=policy_id,
            user=SimpleNamespace(id=str(uuid.uuid4())),
            requesting_organization_id=uuid.uuid4(),
            service=_Service(),
        )

        assert len(dispatched) == 1
        assert dispatched[0]["kwargs"]["policy_id"] == str(policy_id)

    async def test_adding_a_member_dispatches(
        self, dispatched: list[dict[str, object]]
    ) -> None:
        policy_id = uuid.uuid4()
        added = _assignment(policy_id, is_active=True)

        class _Service:
            async def create_assignment(self, **fields):  # noqa: ANN003, ANN202
                return added

        await policy_router.create_policy_assignment(
            request=_request(),
            policy_id=policy_id,
            payload=PolicyAssignmentCreateRequest(
                scope_type="location",
                scope_id=added.scope_id,
                target_type=GUEST,
                target_id=added.target_id,
            ),
            user=SimpleNamespace(id=str(uuid.uuid4())),
            requesting_organization_id=uuid.uuid4(),
            service=_Service(),
        )

        assert len(dispatched) == 1

    def test_the_task_adds_the_named_location_to_the_ones_it_finds(self) -> None:
        """Read from the source: the worker function is one fresh database
        session end to end, so the property worth pinning is that the
        location it is handed joins the set it re-applies."""
        import inspect

        source = inspect.getsource(queue_tasks._reapply_policy_assignments_async)
        assert "location_ids.add(uuid.UUID(location_id))" in source
        signature = inspect.signature(queue_tasks._reapply_policy_assignments_async)
        assert signature.parameters["location_id"].default == ""
        # An API server one deploy older does not send the argument.
        task_signature = inspect.signature(queue_tasks.reapply_policy_assignments.run)
        assert task_signature.parameters["location_id"].default == ""
