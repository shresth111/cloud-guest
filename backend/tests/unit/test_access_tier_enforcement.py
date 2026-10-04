"""Access Tiers -- the guest half: a guest mapped into a tier gets that tier's
limits at an **Aruba Instant On** venue, through the portal sign-in and the
RADIUS reply; **MikroTik and Omada are byte-for-byte unchanged** (owner,
2026-10-04: "wo jaise hai wese rahenge").

Per field, Aruba: session timeout, idle timeout, devices per user, data
limit (daily + per session), daily (max session per day) limit, login
hours. Each also has a regression: with no tier, the venue's own limits
still apply; and the same tier at a MikroTik/Omada venue changes nothing
(the tier lookup is never even asked).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.guest.constants import (
    GuestAuthMethod,
    GuestSessionStatus,
    QuotaPeriodType,
)
from app.domains.guest.exceptions import (
    AccessTierOutsideLoginHoursError,
    FairUsagePolicyExceededError,
    GuestDeviceLimitExceededError,
)
from app.domains.guest.service import (
    aruba_access_tier_lookup,
    get_or_reset_quota_usage,
    run_fup_time_accrual,
)
from app.domains.policy.access_tier import AccessTier, access_tier_from_rules
from app.domains.policy.constants import PolicyType
from tests.unit.test_aruba_access_rules import (
    _ARUBA,
    _MAC,
    _PHONE,
    _authorize,
    _fixture,
    _register_nas,
    _set_minutes_used,
    _sign_in,
)
from tests.unit.test_guest import BYTES_PER_MB

_VENDORS_UNCHANGED = ["mikrotik", "omada"]
_MAC_2 = "aa:bb:cc:dd:ee:02"


@dataclass
class _TierLookup:
    """Per-type venue rules (like ``_PolicyLookup``) plus Access Tiers keyed by
    ``(organization_id, location_id, guest_id)``. Records every
    ``resolve_access_tier`` call so a test can prove MikroTik/Omada never
    ask."""

    rules: dict[PolicyType, dict[str, object]] = field(default_factory=dict)
    tiers: dict[tuple[uuid.UUID, uuid.UUID, uuid.UUID], AccessTier] = field(
        default_factory=dict
    )
    tier_calls: list[uuid.UUID] = field(default_factory=list)

    async def resolve_effective_policy(
        self,
        *,
        policy_type: object,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        guest_id: uuid.UUID | None = None,
    ):
        class _Resolved:
            def __init__(self, rules: dict[str, object]) -> None:
                self.rules = rules

        return _Resolved(dict(self.rules.get(policy_type, {})))

    async def resolve_access_tier(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        guest_id: uuid.UUID | None,
    ) -> AccessTier | None:
        self.tier_calls.append(guest_id)
        return self.tiers.get((organization_id, location_id, guest_id))


def _map(fx, lookup: _TierLookup, guest_id: uuid.UUID, **rules: object) -> AccessTier:  # noqa: ANN001
    tier = access_tier_from_rules(
        uuid.uuid4(),
        {"download_rate_kbps": 0, "upload_rate_kbps": 0, **rules},
        name="Premium",
    )
    lookup.tiers[(fx.organization_id, fx.location_id, guest_id)] = tier
    return tier


async def _mapped_guest(
    *, vendor: str = _ARUBA, venue: dict | None = None, **tier_rules: object
):  # noqa: ANN202
    """A venue, one signed-in guest, then that guest mapped into a tier. The
    first sign-in is what creates the guest (a brand-new guest cannot be in a
    tier yet), exactly as in the product."""
    lookup = _TierLookup(rules=venue or {})
    fx = _fixture(vendor=vendor, policy_lookup=lookup)
    nas = await _register_nas(fx)
    first = await _sign_in(fx)
    _map(fx, lookup, first.guest.id, **tier_rules)
    return fx, nas, lookup, first


# ============================================================================
# Session timeout
# ============================================================================


class TestSessionTimeout:
    async def test_the_tier_overrides_the_venue_on_the_next_sign_in(self) -> None:
        fx, nas, _, _ = await _mapped_guest(
            venue={PolicyType.SESSION: {"session_timeout_minutes": 240}},
            session_timeout_minutes=30,
        )
        second = await _sign_in(fx)
        assert second.session.session_timeout_minutes == 30
        authz = await _authorize(fx, nas)
        assert authz.authorized is True
        assert 1790 <= authz.session_timeout_seconds <= 1800

    async def test_a_guest_mapped_after_signing_in_is_cut_at_the_tier_length(
        self,
    ) -> None:
        """The session row was stamped with the venue's 240 before the
        mapping; the next Access-Request still caps at the tier's 30."""
        fx, nas, _, first = await _mapped_guest(
            venue={PolicyType.SESSION: {"session_timeout_minutes": 240}},
            session_timeout_minutes=30,
        )
        assert first.session.session_timeout_minutes == 240
        authz = await _authorize(fx, nas)
        assert authz.authorized is True
        assert authz.session_timeout_seconds <= 1800

    async def test_tier_session_time_used_up_refuses_the_access_request(
        self,
    ) -> None:
        fx, nas, _, first = await _mapped_guest(
            venue={PolicyType.SESSION: {"session_timeout_minutes": 240}},
            session_timeout_minutes=30,
        )
        first.session.started_at = datetime.now(UTC) - timedelta(minutes=31)
        assert (await _authorize(fx, nas)).authorized is False
        assert first.session.status == GuestSessionStatus.ACTIVE.value

    async def test_no_tier_keeps_the_venue_session_timeout(self) -> None:
        lookup = _TierLookup(
            rules={PolicyType.SESSION: {"session_timeout_minutes": 60}}
        )
        fx = _fixture(policy_lookup=lookup)
        nas = await _register_nas(fx)
        result = await _sign_in(fx)
        await _sign_in(fx)
        assert result.session.session_timeout_minutes == 60
        assert 3590 <= (await _authorize(fx, nas)).session_timeout_seconds <= 3600


# ============================================================================
# Idle timeout
# ============================================================================


class TestIdleTimeout:
    async def test_the_tier_idle_timeout_is_sent(self) -> None:
        fx, nas, _, _ = await _mapped_guest(
            venue={PolicyType.SESSION: {"idle_timeout_minutes": 30}},
            idle_timeout_minutes=10,
        )
        await _sign_in(fx)
        assert (await _authorize(fx, nas)).idle_timeout_seconds == 600

    async def test_no_tier_keeps_the_venue_idle_timeout(self) -> None:
        fx, nas, _, _ = await _mapped_guest(
            venue={PolicyType.SESSION: {"idle_timeout_minutes": 15}}
        )
        await _sign_in(fx)
        assert (await _authorize(fx, nas)).idle_timeout_seconds == 900


# ============================================================================
# Devices per user
# ============================================================================


class TestDevicesPerUser:
    async def test_a_stricter_tier_refuses_the_second_device(self) -> None:
        fx, _, _, _ = await _mapped_guest(
            venue={PolicyType.DEVICE: {"max_devices_per_guest": 3}},
            devices_per_user=1,
        )
        with pytest.raises(GuestDeviceLimitExceededError):
            await _sign_in(fx, mac=_MAC_2)

    async def test_a_looser_tier_admits_what_the_venue_would_refuse(self) -> None:
        fx, _, _, _ = await _mapped_guest(
            venue={PolicyType.DEVICE: {"max_devices_per_guest": 1}},
            devices_per_user=2,
        )
        result = await _sign_in(fx, mac=_MAC_2)
        assert result.session.status == GuestSessionStatus.ACTIVE.value

    async def test_no_tier_keeps_the_venue_device_limit(self) -> None:
        fx, _, _, _ = await _mapped_guest(
            venue={PolicyType.DEVICE: {"max_devices_per_guest": 1}}
        )
        with pytest.raises(GuestDeviceLimitExceededError):
            await _sign_in(fx, mac=_MAC_2)


# ============================================================================
# Daily (max session per day) limit
# ============================================================================


class TestDailyLimit:
    async def test_session_timeout_is_capped_at_what_is_left_today(self) -> None:
        fx, nas, _, first = await _mapped_guest(daily_limit_minutes=60)
        await _set_minutes_used(fx, first.guest.id, 50)
        authz = await _authorize(fx, nas)
        assert authz.authorized is True
        assert authz.session_timeout_seconds == 10 * 60

    async def test_a_used_up_day_refuses_sign_in_and_access_request(self) -> None:
        fx, nas, _, first = await _mapped_guest(daily_limit_minutes=60)
        await _set_minutes_used(fx, first.guest.id, 60)
        assert (await _authorize(fx, nas)).authorized is False
        with pytest.raises(FairUsagePolicyExceededError) as exc_info:
            await _sign_in(fx)
        assert exc_info.value.metric == "time"

    async def test_a_no_limit_tier_lifts_the_venue_cap(self) -> None:
        fx, nas, _, first = await _mapped_guest(
            venue={PolicyType.FUP: {"daily_time_limit_minutes": 60}},
            daily_limit_minutes=0,
        )
        await _set_minutes_used(fx, first.guest.id, 60)
        assert (await _authorize(fx, nas)).authorized is True
        await _sign_in(fx)

    async def test_no_tier_keeps_the_venue_daily_limit(self) -> None:
        fx, nas, _, first = await _mapped_guest(
            venue={PolicyType.FUP: {"daily_time_limit_minutes": 60}}
        )
        await _set_minutes_used(fx, first.guest.id, 60)
        assert (await _authorize(fx, nas)).authorized is False


# ============================================================================
# Data limit
# ============================================================================


class TestDataLimit:
    async def _use(self, fx, session_id, mb: int) -> None:  # noqa: ANN001
        await fx.guest_service.record_usage(
            session_id=session_id,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=mb * BYTES_PER_MB,
        )

    async def test_a_daily_tier_cap_is_counted_and_refuses_the_next_request(
        self,
    ) -> None:
        fx, nas, _, first = await _mapped_guest(
            data_limit={"quota": 10, "unit": "MB", "resets": "Daily"}
        )
        await self._use(fx, first.session.id, 11)
        # NAS-only: the AP keeps the guest; the row is not faked as ended.
        assert first.session.status == GuestSessionStatus.ACTIVE.value
        assert (await _authorize(fx, nas)).authorized is False
        with pytest.raises(FairUsagePolicyExceededError) as exc_info:
            await _sign_in(fx)
        assert exc_info.value.metric == "data"

    async def test_a_bigger_tier_cap_replaces_the_venue_cap(self) -> None:
        fx, nas, _, first = await _mapped_guest(
            venue={PolicyType.FUP: {"daily_data_limit_mb": 10}},
            data_limit={"quota": 1, "unit": "GB", "resets": "Weekly"},
        )
        await self._use(fx, first.session.id, 11)
        assert (await _authorize(fx, nas)).authorized is True

    async def test_per_session_is_stamped_on_the_session(self) -> None:
        fx, nas, _, _ = await _mapped_guest(
            data_limit={"quota": 50, "unit": "MB", "resets": "Per session"}
        )
        second = await _sign_in(fx)
        assert second.session.data_limit_mb == 50
        assert (await _authorize(fx, nas)).data_limit_mb == 50
        await self._use(fx, second.session.id, 51)
        assert (await _authorize(fx, nas)).authorized is False

    async def test_no_tier_keeps_the_venue_data_cap(self) -> None:
        fx, nas, _, first = await _mapped_guest(
            venue={PolicyType.FUP: {"daily_data_limit_mb": 10}}
        )
        await self._use(fx, first.session.id, 11)
        assert (await _authorize(fx, nas)).authorized is False


# ============================================================================
# Login hours
# ============================================================================


def _closed_now_hours() -> dict:
    """A one-hour window on a weekday that is neither today nor yesterday, so
    it cannot contain "now" whatever the clock says."""
    day = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][
        (datetime.now(UTC).weekday() + 3) % 7
    ]
    return {"days": [day], "start_time": "10:00", "end_time": "11:00"}


class TestLoginHours:
    async def test_sign_in_outside_the_window_is_refused(self) -> None:
        fx, _, _, _ = await _mapped_guest(login_hours=_closed_now_hours())
        with pytest.raises(AccessTierOutsideLoginHoursError) as exc_info:
            await _sign_in(fx)
        assert exc_info.value.data == {"code": "access_tier_outside_login_hours"}

    async def test_the_access_request_outside_the_window_is_refused(self) -> None:
        fx, nas, _, first = await _mapped_guest(login_hours=_closed_now_hours())
        assert (await _authorize(fx, nas)).authorized is False
        assert first.session.status == GuestSessionStatus.ACTIVE.value

    async def test_inside_the_window_session_timeout_is_capped_at_close(self) -> None:
        now = datetime.now(UTC)
        if now.hour == 23 and now.minute >= 30:
            pytest.skip("window would cross midnight")
        closes = now + timedelta(minutes=20)
        hours = {
            "days": [],
            "start_time": "00:00",
            "end_time": closes.strftime("%H:%M"),
        }
        fx, nas, _, _ = await _mapped_guest(login_hours=hours)
        await _sign_in(fx)
        authz = await _authorize(fx, nas)
        assert authz.authorized is True
        assert authz.session_timeout_seconds <= 21 * 60


# ============================================================================
# MikroTik / Omada: unchanged, and the tier is never even looked up
# ============================================================================


_EVERYTHING = {
    "session_timeout_minutes": 30,
    "idle_timeout_minutes": 5,
    "devices_per_user": 1,
    "daily_limit_minutes": 60,
    "login_hours": _closed_now_hours(),
    "data_limit": {"quota": 10, "unit": "MB", "resets": "Per session"},
}


@pytest.mark.parametrize("vendor", _VENDORS_UNCHANGED)
class TestOtherVendorsAreUnchanged:
    async def test_sign_in_ignores_every_tier_field(self, vendor: str) -> None:
        fx, _, lookup, first = await _mapped_guest(
            vendor=vendor,
            venue={
                PolicyType.SESSION: {
                    "session_timeout_minutes": 240,
                    "idle_timeout_minutes": 30,
                },
                PolicyType.DEVICE: {"max_devices_per_guest": 3},
            },
            **_EVERYTHING,
        )
        await _set_minutes_used(fx, first.guest.id, 60)
        # Outside the tier's login hours, over its daily limit, a 2nd device
        # over its device cap: all admitted, on the venue's own limits.
        again = await _sign_in(fx)
        other = await _sign_in(fx, mac=_MAC_2)
        assert again.session.session_timeout_minutes == 240
        assert again.session.idle_timeout_minutes == 30
        assert again.session.data_limit_mb is None
        assert other.session.status == GuestSessionStatus.ACTIVE.value
        assert lookup.tier_calls == []

    async def test_radius_and_usage_ignore_the_tier(self, vendor: str) -> None:
        fx, nas, lookup, first = await _mapped_guest(
            vendor=vendor,
            data_limit={"quota": 10, "unit": "MB", "resets": "Daily"},
        )
        await fx.guest_service.record_usage(
            session_id=first.session.id,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=11 * BYTES_PER_MB,
        )
        assert first.session.status == GuestSessionStatus.ACTIVE.value
        assert (await _authorize(fx, nas)).authorized is True
        assert lookup.tier_calls == []


# ============================================================================
# FUP time-accrual sweep
# ============================================================================


class TestAccrualSweep:
    async def _prime(self, fx, guest_id, now):  # noqa: ANN001, ANN202
        usage = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=guest_id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=now,
        )
        await fx.repository.update_quota_usage(usage, {"last_accrued_at": now})

    async def test_an_aruba_tier_daily_limit_accrues_and_expires(self) -> None:
        fx, _, lookup, first = await _mapped_guest(daily_limit_minutes=60)
        now = datetime.now(UTC)
        await self._prime(fx, first.guest.id, now)
        summary = await run_fup_time_accrual(
            fx.repository,
            lookup,
            now=now + timedelta(minutes=61),
            access_tier_lookup=aruba_access_tier_lookup(
                fx.repository, fx.router_service, lookup
            ),
        )
        assert summary["expired_sessions"] == 1

    @pytest.mark.parametrize("vendor", _VENDORS_UNCHANGED)
    async def test_other_vendors_are_not_accrued_on_a_tier(self, vendor: str) -> None:
        fx, _, lookup, first = await _mapped_guest(
            vendor=vendor, daily_limit_minutes=60
        )
        now = datetime.now(UTC)
        await self._prime(fx, first.guest.id, now)
        summary = await run_fup_time_accrual(
            fx.repository,
            lookup,
            now=now + timedelta(minutes=61),
            access_tier_lookup=aruba_access_tier_lookup(
                fx.repository, fx.router_service, lookup
            ),
        )
        assert summary == {"accrued_rows": 0, "expired_sessions": 0}
        assert lookup.tier_calls == []


# ============================================================================
# Failure direction
# ============================================================================


class TestATierLookupFailureFallsBackToTheVenue:
    async def test_sign_in_and_authorize_still_work(self) -> None:
        lookup = _TierLookup(
            rules={PolicyType.SESSION: {"session_timeout_minutes": 60}}
        )
        fx = _fixture(policy_lookup=lookup)
        nas = await _register_nas(fx)
        await _sign_in(fx)

        async def boom(**_: object) -> None:
            raise RuntimeError("policy tables unreachable")

        lookup.resolve_access_tier = boom  # type: ignore[method-assign]
        result = await _sign_in(fx)
        assert result.session.session_timeout_minutes == 60
        assert (await _authorize(fx, nas)).authorized is True


def test_constants_used_here_are_the_aruba_ones() -> None:
    assert _ARUBA == "aruba_instant_on"
    assert _PHONE and _MAC
    assert GuestAuthMethod.OTP_SMS
