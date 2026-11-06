"""Access Tiers -- the policy half: what a tier carries, how its fields map
onto SESSION/DEVICE/FUP, login-hours evaluation, and which tier (if any) a
guest is in (``PolicyService.resolve_access_tier``), including organization
scoping. The guest/RADIUS half (Aruba-only enforcement, MikroTik/Omada
unchanged) is ``test_access_tier_enforcement.py``."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.policy.access_tier import (
    access_tier_from_rules,
    data_limit_to_mb,
    login_hours_standing,
    normalize_reset_period,
    tier_overrides,
)
from app.domains.policy.constants import PolicyAssignmentTargetType, PolicyType
from app.domains.policy.schemas import BandwidthPolicyRules
from app.domains.rbac.enums import ScopeType
from tests.unit.test_policy import (
    _build_service,
    _create_published_bandwidth_policy,
)

_TIER_RULES = {
    "download_rate_kbps": 20480,
    "upload_rate_kbps": 20480,
    "session_timeout_minutes": 60,
    "idle_timeout_minutes": 10,
    "devices_per_user": 2,
    "daily_limit_minutes": 120,
    "login_hours": {"days": ["Mon"], "start_time": "09:00", "end_time": "18:00"},
    "data_limit": {"quota": 2, "unit": "GB", "resets": "Daily"},
}


def _tier(**rules: object):  # noqa: ANN202
    return access_tier_from_rules(uuid.uuid4(), rules)


# ============================================================================
# Parsing
# ============================================================================


class TestParsing:
    def test_every_field_the_dashboard_writes_is_read(self) -> None:
        tier = access_tier_from_rules(uuid.uuid4(), _TIER_RULES, name="Premium")
        assert tier.session_timeout_minutes == 60
        assert tier.idle_timeout_minutes == 10
        assert tier.devices_per_user == 2
        assert tier.daily_limit_minutes == 120
        assert tier.data_limit_mb == 2048
        assert tier.data_limit_period == "daily"
        assert tier.login_hours == _TIER_RULES["login_hours"]
        assert tier.download_rate_kbps == 20480

    def test_a_rate_only_tier_sets_nothing_else(self) -> None:
        tier = _tier(download_rate_kbps=1024, upload_rate_kbps=1024)
        for policy_type in (PolicyType.SESSION, PolicyType.DEVICE, PolicyType.FUP):
            assert tier_overrides(policy_type, tier) == {}

    def test_malformed_fields_read_as_not_set(self) -> None:
        tier = _tier(
            session_timeout_minutes="soon",
            devices_per_user=0,
            data_limit={"quota": 5, "unit": "parsecs", "resets": "Daily"},
            login_hours="9-5",
        )
        assert tier.session_timeout_minutes is None
        assert tier.devices_per_user is None
        assert tier.data_limit_mb is None
        assert tier.data_limit_period is None
        assert tier.login_hours is None

    @pytest.mark.parametrize(
        ("label", "expected"),
        [
            ("Per session", "session"),
            ("per_session", "session"),
            ("Daily", "daily"),
            ("WEEKLY", "weekly"),
            ("Monthly", "monthly"),
            ("Yearly", None),
            (None, None),
        ],
    )
    def test_reset_labels(self, label: object, expected: str | None) -> None:
        assert normalize_reset_period(label) == expected

    def test_units_round_up_never_loosen(self) -> None:
        assert data_limit_to_mb({"quota": 500, "unit": "MB"}) == 500
        assert data_limit_to_mb({"quota": 1.5, "unit": "GB"}) == 1536
        assert data_limit_to_mb({"quota": 0.0001, "unit": "MB"}) == 1
        assert data_limit_to_mb({"quota": -1, "unit": "MB"}) is None

    def test_the_schema_accepts_zero_daily_limit_as_no_limit(self) -> None:
        rules = BandwidthPolicyRules.model_validate(
            {"download_rate_kbps": 0, "upload_rate_kbps": 0, "daily_limit_minutes": 0}
        )
        assert rules.daily_limit_minutes == 0


# ============================================================================
# Field -> policy-type mapping (the precedence)
# ============================================================================


class TestOverrides:
    def test_session(self) -> None:
        tier = _tier(session_timeout_minutes=30, idle_timeout_minutes=5)
        assert tier_overrides(PolicyType.SESSION, tier) == {
            "session_timeout_minutes": 30,
            "idle_timeout_minutes": 5,
        }

    def test_device(self) -> None:
        assert tier_overrides(PolicyType.DEVICE, _tier(devices_per_user=4)) == {
            "max_devices_per_guest": 4
        }

    def test_daily_limit(self) -> None:
        assert tier_overrides(PolicyType.FUP, _tier(daily_limit_minutes=90)) == {
            "daily_time_limit_minutes": 90
        }

    def test_daily_limit_zero_lifts_the_venue_cap(self) -> None:
        """FUP reads 0 as a real zero-minute cap, so "No limit" must land as
        None -- never 0, which would lock the guest out."""
        assert tier_overrides(PolicyType.FUP, _tier(daily_limit_minutes=0)) == {
            "daily_time_limit_minutes": None
        }

    @pytest.mark.parametrize("period", ["Daily", "Weekly", "Monthly"])
    def test_a_data_limit_replaces_every_venue_data_period(self, period: str) -> None:
        out = tier_overrides(
            PolicyType.FUP,
            _tier(data_limit={"quota": 300, "unit": "MB", "resets": period}),
        )
        key = f"{period.lower()}_data_limit_mb"
        assert out[key] == 300
        others = {
            "daily_data_limit_mb",
            "weekly_data_limit_mb",
            "monthly_data_limit_mb",
        } - {key}
        assert all(out[k] is None for k in others)

    def test_per_session_data_limit_is_not_an_fup_period(self) -> None:
        tier = _tier(data_limit={"quota": 300, "unit": "MB", "resets": "Per session"})
        out = tier_overrides(PolicyType.FUP, tier)
        assert out == {
            "daily_data_limit_mb": None,
            "weekly_data_limit_mb": None,
            "monthly_data_limit_mb": None,
        }
        assert tier.session_data_limit_mb == 300

    def test_zero_quota_lifts_venue_data_caps_and_stamps_nothing(self) -> None:
        tier = _tier(data_limit={"quota": 0, "unit": "GB", "resets": "Per session"})
        assert tier.session_data_limit_mb is None
        assert all(v is None for v in tier_overrides(PolicyType.FUP, tier).values())


# ============================================================================
# Login hours
# ============================================================================


# 2026-10-05 is a Monday.
_MON_10 = datetime(2026, 10, 5, 10, 0, tzinfo=UTC)


class TestLoginHours:
    def test_inside_the_window_returns_seconds_to_close(self) -> None:
        hours = {"days": ["Mon"], "start_time": "09:00", "end_time": "18:00"}
        standing = login_hours_standing(hours, tz_name="UTC", now=_MON_10)
        assert standing == 8 * 3600 + 60  # end minute inclusive

    def test_outside_the_window_is_closed(self) -> None:
        hours = {"days": ["Mon"], "start_time": "11:00", "end_time": "18:00"}
        assert login_hours_standing(hours, tz_name="UTC", now=_MON_10) == "closed"

    def test_another_day_is_closed(self) -> None:
        hours = {"days": ["Tue", "Wed"], "start_time": "00:00", "end_time": "23:59"}
        assert login_hours_standing(hours, tz_name="UTC", now=_MON_10) == "closed"

    def test_no_days_means_every_day(self) -> None:
        hours = {"days": [], "start_time": "09:00", "end_time": "18:00"}
        assert isinstance(login_hours_standing(hours, tz_name="UTC", now=_MON_10), int)

    def test_overnight_window_runs_into_the_next_morning(self) -> None:
        hours = {"days": ["Sun"], "start_time": "22:00", "end_time": "11:00"}
        standing = login_hours_standing(hours, tz_name="UTC", now=_MON_10)
        assert standing == 3600 + 60

    def test_overnight_window_does_not_open_the_wrong_morning(self) -> None:
        hours = {"days": ["Mon"], "start_time": "22:00", "end_time": "11:00"}
        assert login_hours_standing(hours, tz_name="UTC", now=_MON_10) == "closed"

    def test_start_equal_end_is_all_day(self) -> None:
        hours = {"days": ["Mon"], "start_time": "00:00", "end_time": "00:00"}
        assert login_hours_standing(hours, tz_name="UTC", now=_MON_10) == 14 * 3600

    def test_the_timezone_is_honoured(self) -> None:
        # 10:00 UTC is 15:30 in Kolkata.
        hours = {"days": ["Mon"], "start_time": "15:00", "end_time": "16:00"}
        assert login_hours_standing(hours, tz_name="Asia/Kolkata", now=_MON_10) == (
            30 * 60 + 60
        )
        assert login_hours_standing(hours, tz_name="UTC", now=_MON_10) == "closed"

    @pytest.mark.parametrize(
        "hours",
        [
            None,
            {},
            {"days": ["Mon"], "start_time": "nine", "end_time": "18:00"},
            {"days": ["Funday"], "start_time": "09:00", "end_time": "18:00"},
        ],
    )
    def test_malformed_is_no_restriction(self, hours: object) -> None:
        assert login_hours_standing(hours, tz_name="UTC", now=_MON_10) is None

    def test_a_bad_timezone_falls_back_to_utc(self) -> None:
        hours = {"days": ["Mon"], "start_time": "09:00", "end_time": "18:00"}
        assert isinstance(
            login_hours_standing(hours, tz_name="Mars/Olympus", now=_MON_10), int
        )


# ============================================================================
# Which tier is a guest in -- PolicyService.resolve_access_tier
# ============================================================================


async def _tier_policy(service, org_id: uuid.UUID, **rules: object):  # noqa: ANN001, ANN202
    policy = await _create_published_bandwidth_policy(
        service, organization_id=org_id, name=f"Tier {uuid.uuid4().hex[:4]}"
    )
    version = await service.create_version(
        policy_id=policy.id,
        requesting_organization_id=org_id,
        actor_user_id=None,
        rules={"download_rate_kbps": 1024, "upload_rate_kbps": 1024, **rules},
    )
    await service.publish_version(
        policy_id=policy.id,
        version_id=version.id,
        requesting_organization_id=org_id,
        actor_user_id=None,
    )
    return policy


async def _map(
    service, policy, org_id, *, scope_type, scope_id, target_type, target_id
):  # noqa: ANN001, ANN202, PLR0913
    return await service.create_assignment(
        policy_id=policy.id,
        requesting_organization_id=org_id,
        actor_user_id=None,
        scope_type=scope_type,
        scope_id=scope_id,
        priority=0,
        target_type=target_type,
        target_id=target_id,
    )


class TestResolveAccessTier:
    async def _setup(self):  # noqa: ANN202
        service, repo, org_lookup, _ = _build_service()
        org = org_lookup.add()
        location = service.location_lookup.add(organization_id=org.id)
        return service, repo, org, location

    async def test_a_guest_mapped_at_this_location_gets_the_tier(self) -> None:
        service, _, org, loc = await self._setup()
        guest_id = uuid.uuid4()
        policy = await _tier_policy(service, org.id, session_timeout_minutes=45)
        await _map(
            service,
            policy,
            org.id,
            scope_type=ScopeType.LOCATION.value,
            scope_id=loc.id,
            target_type=PolicyAssignmentTargetType.GUEST.value,
            target_id=guest_id,
        )
        tier = await service.resolve_access_tier(
            organization_id=org.id, location_id=loc.id, guest_id=guest_id
        )
        assert tier is not None
        assert tier.policy_id == policy.id
        assert tier.session_timeout_minutes == 45

    async def test_a_tier_mapped_to_the_location_for_everyone_is_not_a_tier(
        self,
    ) -> None:
        """target_type=none is the venue-wide speed, not tier membership."""
        service, _, org, loc = await self._setup()
        policy = await _tier_policy(service, org.id, session_timeout_minutes=45)
        await _map(
            service,
            policy,
            org.id,
            scope_type=ScopeType.LOCATION.value,
            scope_id=loc.id,
            target_type=PolicyAssignmentTargetType.NONE.value,
            target_id=None,
        )
        assert (
            await service.resolve_access_tier(
                organization_id=org.id, location_id=loc.id, guest_id=uuid.uuid4()
            )
            is None
        )

    async def test_mapped_at_another_location_does_not_apply_here(self) -> None:
        service, _, org, loc = await self._setup()
        other = service.location_lookup.add(organization_id=org.id)
        guest_id = uuid.uuid4()
        policy = await _tier_policy(service, org.id, session_timeout_minutes=45)
        await _map(
            service,
            policy,
            org.id,
            scope_type=ScopeType.LOCATION.value,
            scope_id=other.id,
            target_type=PolicyAssignmentTargetType.GUEST.value,
            target_id=guest_id,
        )
        assert (
            await service.resolve_access_tier(
                organization_id=org.id, location_id=loc.id, guest_id=guest_id
            )
            is None
        )

    async def test_a_tier_from_another_organization_never_applies(self) -> None:
        """An org can write a GLOBAL-scoped guest-targeted assignment naming
        any guest id (target_id is not validated). The read must refuse it."""
        service, _, org, loc = await self._setup()
        other_org = service.organization_lookup.add()
        guest_id = uuid.uuid4()
        foreign = await _tier_policy(
            service, other_org.id, session_timeout_minutes=5, devices_per_user=1
        )
        await _map(
            service,
            foreign,
            other_org.id,
            scope_type=ScopeType.GLOBAL.value,
            scope_id=None,
            target_type=PolicyAssignmentTargetType.GUEST.value,
            target_id=guest_id,
        )
        assert (
            await service.resolve_access_tier(
                organization_id=org.id, location_id=loc.id, guest_id=guest_id
            )
            is None
        )

    async def test_the_own_org_tier_wins_over_a_foreign_one(self) -> None:
        """The foreign row is written straight to the repository: the service's
        one-guest-one-group check would refuse it after the own mapping, but
        rows like it can exist (written first, or before that check)."""
        service, repo, org, loc = await self._setup()
        other_org = service.organization_lookup.add()
        guest_id = uuid.uuid4()
        own = await _tier_policy(service, org.id, session_timeout_minutes=90)
        await _map(
            service,
            own,
            org.id,
            scope_type=ScopeType.LOCATION.value,
            scope_id=loc.id,
            target_type=PolicyAssignmentTargetType.GUEST.value,
            target_id=guest_id,
        )
        foreign = await _tier_policy(service, other_org.id, session_timeout_minutes=5)
        await repo.create_assignment(
            policy_id=foreign.id,
            scope_type=ScopeType.GLOBAL.value,
            scope_id=None,
            priority=100,
            target_type=PolicyAssignmentTargetType.GUEST.value,
            target_id=guest_id,
            is_active=True,
        )
        tier = await service.resolve_access_tier(
            organization_id=org.id, location_id=loc.id, guest_id=guest_id
        )
        assert tier is not None and tier.policy_id == own.id

    async def test_an_unmapped_guest_has_no_tier(self) -> None:
        service, _, org, loc = await self._setup()
        assert (
            await service.resolve_access_tier(
                organization_id=org.id, location_id=loc.id, guest_id=uuid.uuid4()
            )
            is None
        )

    async def test_a_deactivated_mapping_is_not_a_tier(self) -> None:
        service, _, org, loc = await self._setup()
        guest_id = uuid.uuid4()
        policy = await _tier_policy(service, org.id, session_timeout_minutes=45)
        assignment = await _map(
            service,
            policy,
            org.id,
            scope_type=ScopeType.LOCATION.value,
            scope_id=loc.id,
            target_type=PolicyAssignmentTargetType.GUEST.value,
            target_id=guest_id,
        )
        await service.deactivate_assignment(
            policy_id=policy.id,
            assignment_id=assignment.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
        )
        assert (
            await service.resolve_access_tier(
                organization_id=org.id, location_id=loc.id, guest_id=guest_id
            )
            is None
        )

    async def test_resolve_effective_policy_is_unchanged_by_a_tier(self) -> None:
        """The overlay lives in the Aruba-gated guest path, never in the shared
        resolver -- so MikroTik/Omada resolve SESSION exactly as before."""
        service, _, org, loc = await self._setup()
        guest_id = uuid.uuid4()
        policy = await _tier_policy(service, org.id, session_timeout_minutes=45)
        await _map(
            service,
            policy,
            org.id,
            scope_type=ScopeType.LOCATION.value,
            scope_id=loc.id,
            target_type=PolicyAssignmentTargetType.GUEST.value,
            target_id=guest_id,
        )
        resolved = await service.resolve_effective_policy(
            policy_type=PolicyType.SESSION,
            organization_id=org.id,
            location_id=loc.id,
            guest_id=guest_id,
        )
        assert resolved.source == "platform_default"
        assert resolved.rules["session_timeout_minutes"] == 240


def test_monday_fixture_is_a_monday() -> None:
    assert _MON_10.weekday() == 0
    assert (_MON_10 + timedelta(days=1)).weekday() == 1
