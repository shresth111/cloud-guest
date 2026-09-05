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
from app.domains.guest.constants import DEFAULT_SESSION_TIMEOUT_MINUTES
from app.domains.guest.exceptions import (
    GuestTeamSharedQuotaExceededError,
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
