"""Three shipped-but-unreachable behaviours, now reachable.

Each of these had its model, its validator, its typed rules and its scoping
already built and tested in isolation -- and no caller. The website sells all
three. They are grouped in one file because they are one class of defect:
plumbing that terminates in nothing.

* **Open Hours.** ``captive_portal.validators.is_open_now`` was evaluated on
  exactly one line in the backend -- an advisory boolean on the portal's
  config-resolve response. No login path consulted it, so a guest hitting the
  login endpoint outside opening hours was authenticated normally.
* **Per-location session length.** All four non-voucher login paths passed the
  platform-wide ``DEFAULT_SESSION_TIMEOUT_MINUTES`` (240). ``PolicyType.SESSION``,
  ``SessionPolicyRules.session_timeout_minutes`` and LOCATION-scoped
  ``PolicyAssignment`` all existed; the type was simply never passed to
  ``resolve_effective_policy`` anywhere in ``app/``.
* **Guest-team shared data limit.** ``check_shared_quota`` had no caller at
  all, so a team with a 5 GB pooled cap could use 50 GB.

Plain-``assert``/native-``async def`` style, in-memory fakes, no live
Postgres -- same convention as the rest of this suite.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.captive_portal.validators import is_open_now
from app.domains.guest.constants import (
    DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST,
    DEFAULT_MAX_DEVICES_PER_GUEST,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
)
from app.domains.guest.exceptions import (
    ConcurrentSessionLimitExceededError,
    GuestTeamSharedQuotaExceededError,
    MacAddressNotAuthorizedError,
    VenueClosedError,
)
from app.domains.guest.service import GuestService
from app.domains.guest_teams.quota import SharedQuotaResolver
from app.domains.policy.constants import PolicyType

# ---------------------------------------------------------------------------
# Open Hours
# ---------------------------------------------------------------------------

_ALWAYS_CLOSED = {
    day: {"open": False, "start": "09:00", "end": "17:00"}
    for day in (
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    )
}
_ALWAYS_OPEN = {
    day: {"open": True, "start": "00:00", "end": "23:59"}
    for day in (
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    )
}


def _portal_config(
    *,
    business_hours_enabled: bool = False,
    schedule: dict | None = None,
    closed_message: str | None = None,
):
    return SimpleNamespace(
        organization_id=uuid.uuid4(),
        otp_sms_enabled=True,
        otp_email_enabled=True,
        otp_whatsapp_enabled=True,
        voucher_enabled=True,
        username_password_enabled=True,
        pin_login_enabled=True,
        business_hours_enabled=business_hours_enabled,
        business_hours_timezone="Asia/Kolkata",
        business_hours_schedule=schedule if schedule is not None else _ALWAYS_OPEN,
        business_hours_closed_message=closed_message,
    )


class _FakePortalService:
    def __init__(self, config) -> None:
        self._config = config

    async def resolve_portal_config(self, *, organization_id, location_id):
        return SimpleNamespace(config=self._config)


def _guest_service(config, **kwargs) -> GuestService:
    return GuestService(
        None,  # repository
        None,  # otp_service
        None,  # voucher_service
        _FakePortalService(config),
        None,  # router_lookup
        **kwargs,
    )


class TestOpenHoursGatesLogin:
    async def test_login_is_refused_while_the_venue_is_closed(self) -> None:
        from app.domains.guest.constants import GuestAuthMethod

        service = _guest_service(
            _portal_config(business_hours_enabled=True, schedule=_ALWAYS_CLOSED)
        )

        with pytest.raises(VenueClosedError):
            await service._require_method_enabled(
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                auth_method=GuestAuthMethod.OTP_SMS,
            )

    async def test_the_venues_own_closed_message_is_what_the_guest_sees(self) -> None:
        from app.domains.guest.constants import GuestAuthMethod

        service = _guest_service(
            _portal_config(
                business_hours_enabled=True,
                schedule=_ALWAYS_CLOSED,
                closed_message="We're closed - see you at 8am!",
            )
        )

        try:
            await service._require_method_enabled(
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                auth_method=GuestAuthMethod.OTP_SMS,
            )
        except VenueClosedError as exc:
            assert "see you at 8am" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("closed venue accepted a login")

    async def test_login_is_allowed_while_the_venue_is_open(self) -> None:
        from app.domains.guest.constants import GuestAuthMethod

        service = _guest_service(
            _portal_config(business_hours_enabled=True, schedule=_ALWAYS_OPEN)
        )

        resolved = await service._require_method_enabled(
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            auth_method=GuestAuthMethod.OTP_SMS,
        )
        assert resolved is not None

    async def test_business_hours_disabled_means_always_open(self) -> None:
        """Every venue today has this off. The gate must be a no-op for them."""
        from app.domains.guest.constants import GuestAuthMethod

        service = _guest_service(
            _portal_config(business_hours_enabled=False, schedule=_ALWAYS_CLOSED)
        )

        assert await service._require_method_enabled(
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            auth_method=GuestAuthMethod.OTP_SMS,
        )

    def test_a_broken_timezone_degrades_to_open_not_to_a_lockout(self) -> None:
        """The failure direction has to be "let the guest online". A bad stored
        row must never lock a venue out of its own WiFi."""
        assert is_open_now(
            enabled=True, timezone="Not/AZone", schedule=_ALWAYS_OPEN
        ) is True


# ---------------------------------------------------------------------------
# Per-location session length
# ---------------------------------------------------------------------------


class _FakePolicyLookup:
    def __init__(self, rules: dict, *, raises: Exception | None = None) -> None:
        self.rules = rules
        self.calls: list[dict] = []
        self._raises = raises

    async def resolve_effective_policy(self, **kwargs):
        if self._raises is not None:
            raise self._raises
        self.calls.append(kwargs)
        return SimpleNamespace(rules=self.rules)


class TestSessionLengthIsResolvedPerLocation:
    async def test_a_location_policy_overrides_the_platform_default(self) -> None:
        """A hotel wants a session that covers a three-night stay; a cafe wants
        one that ends about when the coffee does. Both used to get 240."""
        lookup = _FakePolicyLookup({"session_timeout_minutes": 4320})
        service = _guest_service(_portal_config(), policy_lookup=lookup)

        resolved = await service._resolve_session_timeout_minutes(
            organization_id=uuid.uuid4(), location_id=uuid.uuid4()
        )

        assert resolved == 4320

    async def test_it_asks_for_the_session_policy_type(self) -> None:
        """``PolicyType.SESSION`` was never passed to ``resolve_effective_policy``
        anywhere in the application before this."""
        lookup = _FakePolicyLookup({"session_timeout_minutes": 60})
        service = _guest_service(_portal_config(), policy_lookup=lookup)

        await service._resolve_session_timeout_minutes(
            organization_id=uuid.uuid4(), location_id=uuid.uuid4()
        )

        assert lookup.calls[0]["policy_type"] == PolicyType.SESSION

    async def test_the_location_is_part_of_the_lookup(self) -> None:
        lookup = _FakePolicyLookup({"session_timeout_minutes": 60})
        service = _guest_service(_portal_config(), policy_lookup=lookup)
        location_id = uuid.uuid4()

        await service._resolve_session_timeout_minutes(
            organization_id=uuid.uuid4(), location_id=location_id
        )

        assert lookup.calls[0]["location_id"] == location_id

    async def test_no_policy_hook_falls_back_to_todays_behaviour(self) -> None:
        service = _guest_service(_portal_config(), policy_lookup=None)

        resolved = await service._resolve_session_timeout_minutes(
            organization_id=uuid.uuid4(), location_id=uuid.uuid4()
        )

        assert resolved == DEFAULT_SESSION_TIMEOUT_MINUTES

    async def test_a_policy_without_the_field_falls_back(self) -> None:
        service = _guest_service(
            _portal_config(), policy_lookup=_FakePolicyLookup({"something_else": 1})
        )

        resolved = await service._resolve_session_timeout_minutes(
            organization_id=uuid.uuid4(), location_id=uuid.uuid4()
        )

        assert resolved == DEFAULT_SESSION_TIMEOUT_MINUTES

    async def test_a_failing_policy_service_never_blocks_a_login(self) -> None:
        """This resolver sits on the login path. The policy service being
        unreachable must mean "the default session length", never "no WiFi"."""
        service = _guest_service(
            _portal_config(),
            policy_lookup=_FakePolicyLookup({}, raises=RuntimeError("unreachable")),
        )

        resolved = await service._resolve_session_timeout_minutes(
            organization_id=uuid.uuid4(), location_id=uuid.uuid4()
        )

        assert resolved == DEFAULT_SESSION_TIMEOUT_MINUTES


# ---------------------------------------------------------------------------
# Guest-team shared data limit
# ---------------------------------------------------------------------------


class _FakeSession:
    def __init__(self, total: int, status: str = "active") -> None:
        self._total = total
        self.status = status

    def total_bytes(self) -> int:
        return self._total


class _FakeTeamRepo:
    def __init__(self, team, members) -> None:
        self._team = team
        self._members = members

    async def list_active_memberships_for_guest(self, guest_id):
        return (
            [SimpleNamespace(team_id=self._team.id)] if self._team is not None else []
        )

    async def get_team_by_id(self, team_id, **kwargs):
        return self._team

    async def list_active_members(self, team_id):
        return self._members


class _FakeGuestRepo:
    def __init__(self, sessions_by_guest) -> None:
        self._sessions = sessions_by_guest

    async def list_sessions_for_guest(self, guest_id, **kwargs):
        return self._sessions.get(guest_id, [])


_MB = 1024 * 1024


class TestSharedTeamQuotaIsEnforced:
    async def test_a_team_over_its_pooled_limit_is_reported_over(self) -> None:
        member_a, member_b = uuid.uuid4(), uuid.uuid4()
        team = SimpleNamespace(id=uuid.uuid4(), shared_data_limit_mb=10)
        resolver = SharedQuotaResolver(
            _FakeTeamRepo(
                team,
                [
                    SimpleNamespace(guest_id=member_a),
                    SimpleNamespace(guest_id=member_b),
                ],
            ),
            _FakeGuestRepo(
                {
                    member_a: [_FakeSession(6 * _MB)],
                    member_b: [_FakeSession(5 * _MB)],
                }
            ),
        )

        assert await resolver.is_over_shared_quota(member_a) is True

    async def test_usage_is_pooled_across_members_not_counted_per_guest(self) -> None:
        """The point of a *shared* limit: neither member is individually over
        10 MB, but together they are."""
        member_a, member_b = uuid.uuid4(), uuid.uuid4()
        team = SimpleNamespace(id=uuid.uuid4(), shared_data_limit_mb=10)
        resolver = SharedQuotaResolver(
            _FakeTeamRepo(
                team,
                [
                    SimpleNamespace(guest_id=member_a),
                    SimpleNamespace(guest_id=member_b),
                ],
            ),
            _FakeGuestRepo(
                {
                    member_a: [_FakeSession(9 * _MB)],
                    member_b: [_FakeSession(9 * _MB)],
                }
            ),
        )

        assert await resolver.is_over_shared_quota(member_a) is True

    async def test_a_team_under_its_limit_is_allowed(self) -> None:
        member = uuid.uuid4()
        team = SimpleNamespace(id=uuid.uuid4(), shared_data_limit_mb=100)
        resolver = SharedQuotaResolver(
            _FakeTeamRepo(team, [SimpleNamespace(guest_id=member)]),
            _FakeGuestRepo({member: [_FakeSession(1 * _MB)]}),
        )

        assert await resolver.is_over_shared_quota(member) is False

    async def test_only_active_sessions_count(self) -> None:
        member = uuid.uuid4()
        team = SimpleNamespace(id=uuid.uuid4(), shared_data_limit_mb=10)
        resolver = SharedQuotaResolver(
            _FakeTeamRepo(team, [SimpleNamespace(guest_id=member)]),
            _FakeGuestRepo({member: [_FakeSession(50 * _MB, status="ended")]}),
        )

        assert await resolver.is_over_shared_quota(member) is False

    async def test_a_team_with_no_shared_limit_never_blocks(self) -> None:
        member = uuid.uuid4()
        team = SimpleNamespace(id=uuid.uuid4(), shared_data_limit_mb=None)
        resolver = SharedQuotaResolver(
            _FakeTeamRepo(team, [SimpleNamespace(guest_id=member)]),
            _FakeGuestRepo({member: [_FakeSession(999 * _MB)]}),
        )

        assert await resolver.is_over_shared_quota(member) is False

    async def test_a_guest_in_no_team_is_never_over_quota(self) -> None:
        resolver = SharedQuotaResolver(
            _FakeTeamRepo(None, []), _FakeGuestRepo({})
        )

        assert await resolver.is_over_shared_quota(uuid.uuid4()) is False

    async def test_the_login_path_actually_rejects_an_over_quota_guest(self) -> None:
        """The gate, not just the arithmetic: ``check_shared_quota`` was
        correct all along and simply never called."""

        class _OverQuota:
            async def is_over_shared_quota(self, guest_id):
                return True

        service = _guest_service(_portal_config(), team_quota_hook=_OverQuota())

        with pytest.raises(GuestTeamSharedQuotaExceededError):
            await service._enforce_fup_quota(
                guest_id=uuid.uuid4(), organization_id=uuid.uuid4()
            )

    async def test_no_team_hook_wired_is_a_no_op(self) -> None:
        service = _guest_service(_portal_config(), team_quota_hook=None)

        await service._enforce_fup_quota(
            guest_id=uuid.uuid4(), organization_id=uuid.uuid4()
        )


# ---------------------------------------------------------------------------
# The other half of the same SESSION policy: concurrent sessions per guest
# ---------------------------------------------------------------------------


class _FakeSessionCountRepo:
    """Only the one method ``_enforce_concurrent_session_limit`` calls."""

    def __init__(self, active_count: int) -> None:
        self._active_count = active_count

    async def count_active_sessions_for_guest(self, guest_id):
        return self._active_count


def _guest_service_with_sessions(active_count: int, **kwargs) -> GuestService:
    return GuestService(
        _FakeSessionCountRepo(active_count),
        None,  # otp_service
        None,  # voucher_service
        _FakePortalService(_portal_config()),
        None,  # router_lookup
        **kwargs,
    )


class TestConcurrentSessionLimitIsResolvedPerLocation:
    """``PolicyType.SESSION`` carries four fields. Wiring the type in
    resolved ``session_timeout_minutes`` and left the other three reading
    platform constants -- so a venue could publish a SESSION policy, watch
    it resolve, and still have its concurrent-session allowance ignored."""

    async def test_a_location_policy_raises_the_allowance(self) -> None:
        """Three active sessions is the platform limit. A venue that
        published a policy allowing five must get a fourth login."""
        lookup = _FakePolicyLookup({"max_concurrent_sessions_per_guest": 5})
        service = _guest_service_with_sessions(3, policy_lookup=lookup)

        await service._enforce_concurrent_session_limit(
            uuid.uuid4(),
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
        )

    async def test_a_location_policy_lowers_the_allowance(self) -> None:
        lookup = _FakePolicyLookup({"max_concurrent_sessions_per_guest": 2})
        service = _guest_service_with_sessions(2, policy_lookup=lookup)

        with pytest.raises(ConcurrentSessionLimitExceededError):
            await service._enforce_concurrent_session_limit(
                uuid.uuid4(),
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
            )

    async def test_the_error_reports_the_resolved_limit(self) -> None:
        """Not the platform constant -- the guest is told the number that
        actually applied to them."""
        lookup = _FakePolicyLookup({"max_concurrent_sessions_per_guest": 2})
        service = _guest_service_with_sessions(2, policy_lookup=lookup)

        with pytest.raises(ConcurrentSessionLimitExceededError) as excinfo:
            await service._enforce_concurrent_session_limit(
                uuid.uuid4(),
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
            )

        assert "2" in str(excinfo.value)

    async def test_it_asks_for_the_session_policy_type_and_location(self) -> None:
        lookup = _FakePolicyLookup({"max_concurrent_sessions_per_guest": 5})
        service = _guest_service_with_sessions(0, policy_lookup=lookup)
        location_id = uuid.uuid4()

        await service._enforce_concurrent_session_limit(
            uuid.uuid4(), organization_id=uuid.uuid4(), location_id=location_id
        )

        assert lookup.calls[0]["policy_type"] == PolicyType.SESSION
        assert lookup.calls[0]["location_id"] == location_id

    async def test_no_policy_hook_falls_back_to_todays_behaviour(self) -> None:
        service = _guest_service_with_sessions(
            DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST, policy_lookup=None
        )

        with pytest.raises(ConcurrentSessionLimitExceededError):
            await service._enforce_concurrent_session_limit(
                uuid.uuid4(),
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
            )

    async def test_a_policy_without_the_field_falls_back(self) -> None:
        service = _guest_service_with_sessions(
            DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST,
            policy_lookup=_FakePolicyLookup({"session_timeout_minutes": 60}),
        )

        with pytest.raises(ConcurrentSessionLimitExceededError):
            await service._enforce_concurrent_session_limit(
                uuid.uuid4(),
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
            )

    async def test_an_unassigned_venue_keeps_the_real_platform_limit(self) -> None:
        """The production case, and the one that nearly shipped a regression.

        ``resolve_effective_policy`` does not return "nothing" when no policy
        is assigned -- it returns ``PLATFORM_DEFAULT_RULES`` as a real rules
        dict. So this resolver's ``.get(..., DEFAULT)`` fallback never fires
        for an unassigned venue; the platform-default mirror is what it reads.
        That mirror had drifted to 3 while the guest constant was raised to 20
        after a launch incident, so wiring this key naively would have dropped
        every venue's cap from 20 to 3 without a single policy existing."""
        from app.domains.policy.constants import PLATFORM_DEFAULT_RULES

        lookup = _FakePolicyLookup(
            dict(PLATFORM_DEFAULT_RULES[PolicyType.SESSION])
        )
        service = _guest_service_with_sessions(
            DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST - 1, policy_lookup=lookup
        )

        await service._enforce_concurrent_session_limit(
            uuid.uuid4(),
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
        )

    async def test_a_failing_policy_service_never_blocks_a_login(self) -> None:
        """Same contract the session-length resolver keeps: the policy
        service being unreachable means "the default allowance", never a
        500 on a guest login."""
        service = _guest_service_with_sessions(
            0,
            policy_lookup=_FakePolicyLookup({}, raises=RuntimeError("unreachable")),
        )

        await service._enforce_concurrent_session_limit(
            uuid.uuid4(),
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
        )


class TestDeviceLimitSurvivesAFailingPolicyService:
    """``_resolve_device_limit`` sits on the same login path as
    ``_resolve_session_timeout_minutes`` but had none of its never-raise
    guard: any failure inside ``resolve_effective_policy`` -- including the
    real cross-organization location check it performs -- became a 500 on a
    guest login rather than the default device limit."""

    async def test_a_failing_policy_service_falls_back(self) -> None:
        service = _guest_service(
            _portal_config(),
            policy_lookup=_FakePolicyLookup({}, raises=RuntimeError("unreachable")),
        )

        resolved = await service._resolve_device_limit(
            organization_id=uuid.uuid4(), location_id=uuid.uuid4()
        )

        assert resolved == DEFAULT_MAX_DEVICES_PER_GUEST

    async def test_a_working_policy_service_still_wins(self) -> None:
        service = _guest_service(
            _portal_config(),
            policy_lookup=_FakePolicyLookup({"max_devices_per_guest": 9}),
        )

        resolved = await service._resolve_device_limit(
            organization_id=uuid.uuid4(), location_id=uuid.uuid4()
        )

        assert resolved == 9


# ---------------------------------------------------------------------------
# Open Hours: the fifth login method, and the one that skips the chokepoint
# ---------------------------------------------------------------------------


class TestOpenHoursCoversTheMacWhitelistPath:
    """``login_via_mac_whitelist`` deliberately skips
    ``_require_method_enabled`` -- a whitelist entry is its own per-device
    enable signal. Open Hours was bolted onto that same helper, so this path
    silently inherited an exemption nobody chose. It is live: RADIUS authorize
    falls through to this method to originate a session."""

    async def test_a_closed_venue_rejects_a_whitelisted_device(self) -> None:
        service = _guest_service(
            _portal_config(business_hours_enabled=True, schedule=_ALWAYS_CLOSED),
            mac_authorization_hook=None,
        )

        with pytest.raises(VenueClosedError):
            await service.login_via_mac_whitelist(
                mac_address="AA:BB:CC:DD:EE:FF",
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                router_id=uuid.uuid4(),
            )

    async def test_the_venue_check_precedes_the_whitelist_check(self) -> None:
        """Closed must read as "closed", not as "your device is not
        whitelisted" -- the two have very different operator responses."""
        service = _guest_service(
            _portal_config(business_hours_enabled=True, schedule=_ALWAYS_CLOSED),
            mac_authorization_hook=None,
        )

        with pytest.raises(VenueClosedError):
            await service.login_via_mac_whitelist(
                mac_address="AA:BB:CC:DD:EE:FF",
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                router_id=uuid.uuid4(),
            )

    async def test_an_open_venue_still_reaches_the_whitelist_check(self) -> None:
        """The gate must not swallow the ordinary path: with the venue open,
        an unwhitelisted MAC still fails for its own real reason."""
        service = _guest_service(
            _portal_config(business_hours_enabled=True, schedule=_ALWAYS_OPEN),
            mac_authorization_hook=None,
        )

        with pytest.raises(MacAddressNotAuthorizedError):
            await service.login_via_mac_whitelist(
                mac_address="AA:BB:CC:DD:EE:FF",
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                router_id=uuid.uuid4(),
            )

    async def test_business_hours_disabled_is_always_open(self) -> None:
        service = _guest_service(
            _portal_config(business_hours_enabled=False, schedule=_ALWAYS_CLOSED),
            mac_authorization_hook=None,
        )

        with pytest.raises(MacAddressNotAuthorizedError):
            await service.login_via_mac_whitelist(
                mac_address="AA:BB:CC:DD:EE:FF",
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                router_id=uuid.uuid4(),
            )


# ---------------------------------------------------------------------------
# FUP quotas were resolved with location_id hardcoded to None
# ---------------------------------------------------------------------------


class TestFupQuotaResolvesAtLocationScope:
    """``list_candidate_assignments`` only adds its LOCATION-scope predicate
    when a real ``location_id`` arrives, so a location-scoped FUP assignment
    was never a resolution candidate -- creatable, listed, active, inert."""

    async def test_the_location_reaches_the_policy_lookup(self) -> None:
        lookup = _FakePolicyLookup({})
        service = _guest_service(_portal_config(), policy_lookup=lookup)
        location_id = uuid.uuid4()

        await service._enforce_fup_quota(
            guest_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            location_id=location_id,
        )

        assert lookup.calls[0]["policy_type"] == PolicyType.FUP
        assert lookup.calls[0]["location_id"] == location_id

    async def test_no_location_still_resolves_organization_scope(self) -> None:
        """Callers without a location (and every pre-existing test) keep
        resolving exactly as before rather than erroring."""
        lookup = _FakePolicyLookup({})
        service = _guest_service(_portal_config(), policy_lookup=lookup)

        await service._enforce_fup_quota(
            guest_id=uuid.uuid4(), organization_id=uuid.uuid4()
        )

        assert lookup.calls[0]["location_id"] is None


class TestAPartialSessionPolicyIsUsable:
    """``SessionPolicyRules`` used to require all four fields, so a venue
    could not change only its session length. Now that they are optional,
    ``PolicyService`` persists the omitted ones as explicit ``null`` (it
    stores ``model_dump()``), and every reader must treat a null exactly like
    a missing key -- otherwise ``.get(key, DEFAULT)`` returns ``None`` and
    hands it to arithmetic on the login path."""

    async def test_a_null_field_falls_back_to_the_platform_constant(self) -> None:
        lookup = _FakePolicyLookup(
            {
                "session_timeout_minutes": 60,
                "max_concurrent_sessions_per_guest": None,
                "termination_reconnect_cooldown_minutes": None,
                "reconnect_grace_minutes": None,
            }
        )
        service = _guest_service_with_sessions(
            DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST - 1, policy_lookup=lookup
        )

        # The null concurrent-session field must not become the limit.
        await service._enforce_concurrent_session_limit(
            uuid.uuid4(),
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
        )

    async def test_the_field_that_was_set_still_applies(self) -> None:
        service = _guest_service(
            _portal_config(),
            policy_lookup=_FakePolicyLookup(
                {
                    "session_timeout_minutes": 60,
                    "max_concurrent_sessions_per_guest": None,
                    "termination_reconnect_cooldown_minutes": None,
                    "reconnect_grace_minutes": None,
                }
            ),
        )

        resolved = await service._resolve_session_timeout_minutes(
            organization_id=uuid.uuid4(), location_id=uuid.uuid4()
        )

        assert resolved == 60

    async def test_an_all_null_policy_behaves_like_no_policy(self) -> None:
        service = _guest_service(
            _portal_config(),
            policy_lookup=_FakePolicyLookup({"session_timeout_minutes": None}),
        )

        resolved = await service._resolve_session_timeout_minutes(
            organization_id=uuid.uuid4(), location_id=uuid.uuid4()
        )

        assert resolved == DEFAULT_SESSION_TIMEOUT_MINUTES


class TestSessionPolicyRulesAcceptsAPartialPayload:
    def test_only_a_session_timeout_validates(self) -> None:
        """The write a venue changing just its session length would make."""
        from app.domains.policy.constants import PolicyType as _PT
        from app.domains.policy.validators import validate_rules

        stored = validate_rules(_PT.SESSION, {"session_timeout_minutes": 60})

        assert stored["session_timeout_minutes"] == 60
        assert stored["max_concurrent_sessions_per_guest"] is None


class TestSessionPolicyIsResolvedOncePerRequest:
    """A single login reads this policy twice -- the concurrent-session check
    before OTP verification, and the session length after it. Without a memo,
    wiring the second reader doubled a multi-query resolve on the hottest path
    in the product."""

    async def test_two_reads_make_one_lookup(self) -> None:
        """Mirrors the real sequence: both reads in a login carry the same
        guest id (the concurrent check only runs for an already-existing
        guest, and the session-length read uses that same row)."""
        lookup = _FakePolicyLookup({"session_timeout_minutes": 60})
        service = _guest_service_with_sessions(0, policy_lookup=lookup)
        org_id, location_id, guest_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

        await service._enforce_concurrent_session_limit(
            guest_id, organization_id=org_id, location_id=location_id
        )
        await service._resolve_session_timeout_minutes(
            organization_id=org_id, location_id=location_id, guest_id=guest_id
        )

        assert len(lookup.calls) == 1

    async def test_a_different_guest_is_a_different_lookup(self) -> None:
        """A GUEST-targeted assignment can override the location default, so
        the guest id is part of the key, not incidental to it."""
        lookup = _FakePolicyLookup({"session_timeout_minutes": 60})
        service = _guest_service_with_sessions(0, policy_lookup=lookup)
        org_id, location_id = uuid.uuid4(), uuid.uuid4()

        await service._resolve_session_timeout_minutes(
            organization_id=org_id, location_id=location_id, guest_id=uuid.uuid4()
        )
        await service._resolve_session_timeout_minutes(
            organization_id=org_id, location_id=location_id, guest_id=uuid.uuid4()
        )

        assert len(lookup.calls) == 2

    async def test_a_different_location_is_a_different_lookup(self) -> None:
        lookup = _FakePolicyLookup({"session_timeout_minutes": 60})
        service = _guest_service_with_sessions(0, policy_lookup=lookup)
        org_id = uuid.uuid4()

        await service._resolve_session_timeout_minutes(
            organization_id=org_id, location_id=uuid.uuid4()
        )
        await service._resolve_session_timeout_minutes(
            organization_id=org_id, location_id=uuid.uuid4()
        )

        assert len(lookup.calls) == 2

    async def test_a_failed_lookup_is_not_cached(self) -> None:
        """A transient blip must degrade one call, not pin the whole login to
        defaults."""
        lookup = _FakePolicyLookup({}, raises=RuntimeError("unreachable"))
        service = _guest_service(_portal_config(), policy_lookup=lookup)
        org_id, location_id = uuid.uuid4(), uuid.uuid4()

        await service._resolve_session_timeout_minutes(
            organization_id=org_id, location_id=location_id
        )
        await service._resolve_session_timeout_minutes(
            organization_id=org_id, location_id=location_id
        )

        assert service._session_policy_cache == {}
