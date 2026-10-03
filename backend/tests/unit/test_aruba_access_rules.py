"""Access Rules at an Aruba Instant On venue: what reaches the guest.

An Instant On access point is a NAS and nothing else -- no router API, no
controller API, no CoA into the venue's NAT. So every rule on the customer
dashboard's Access Rules / Blocking / Guest Allow-list screens can reach a
guest there in exactly two places:

* the **portal sign-in** (``login_via_*``), which is vendor-agnostic and runs
  before the browser ever POSTs to the AP; and
* the **RADIUS reply** to the AP's Access-Request (``RadiusService.authorize``):
  Accept/Reject, ``Session-Timeout`` and ``Idle-Timeout``.

These tests drive both, against an Aruba NAS, for each rule that is
enforceable there -- and pin that a MikroTik NAS given the same fixture
behaves exactly as before. Nothing here may end an Aruba session mid-way: the
platform cannot reach the device, so a row marked ended while the guest is
still online is a lie on the Guests screen.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.domains.guest.constants import (
    GuestAuthMethod,
    GuestSessionStatus,
    QuotaPeriodType,
)
from app.domains.guest.exceptions import (
    FairUsagePolicyExceededError,
    GuestBlockedError,
    GuestDeviceLimitExceededError,
    VenueClosedError,
)
from app.domains.guest.service import get_or_reset_quota_usage
from app.domains.guest.validators import canonicalize_calling_station_id
from app.domains.guest_access.exceptions import (
    GuestAccessDeniedError,
    WhitelistOnlyAccessDeniedError,
)
from app.domains.policy.constants import PolicyType
from app.domains.router.vendor_capabilities import ARUBA_INSTANT_ON_VENDOR
from tests.unit.test_guest import (
    BYTES_PER_MB,
    FakeAccessControlHook,
    _shut_the_venue,
    make_fixture,
)

_ARUBA = ARUBA_INSTANT_ON_VENDOR
_PHONE = "+919811122233"
_MAC = "60:f4:45:0b:28:66"
# What an Aruba AP sends as Calling-Station-Id: bare lower-case hex.
_ARUBA_CSID = canonicalize_calling_station_id("60f4450b2866")


@dataclass
class _PolicyLookup:
    """``PolicyLookupProtocol`` answering per policy type, which the single-
    type fakes in ``test_guest.py`` do not (they hand every type the same
    rules). ``raises`` makes every resolution fail."""

    rules: dict[PolicyType, dict[str, object]] = field(default_factory=dict)
    raises: Exception | None = None

    async def resolve_effective_policy(
        self,
        *,
        policy_type: object,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        guest_id: uuid.UUID | None = None,
    ):
        if self.raises is not None:
            raise self.raises

        class _Resolved:
            def __init__(self, rules: dict[str, object]) -> None:
                self.rules = rules

        return _Resolved(dict(self.rules.get(policy_type, {})))


def _fixture(*, vendor: str = _ARUBA, **kwargs):  # noqa: ANN003, ANN202
    fx = make_fixture(**kwargs)
    fx.router.vendor = vendor
    return fx


async def _register_nas(fx):  # noqa: ANN001, ANN202
    await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier="cg-aruba-test",
        shared_secret="supersecret123",
    )
    return await fx.radius_service.authenticate_nas(
        nas_identifier="cg-aruba-test", shared_secret="supersecret123"
    )


async def _sign_in(fx, *, identifier: str = _PHONE, mac: str | None = _MAC):  # noqa: ANN001, ANN202
    return await fx.guest_service.login_via_otp(
        identifier=identifier,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
        ip_address="192.168.1.50",
    )


async def _authorize(fx, nas, *, identifier: str = _PHONE):  # noqa: ANN001, ANN202
    return await fx.radius_service.authorize(
        nas_client=nas, username=identifier, calling_station_id=_ARUBA_CSID
    )


async def _set_minutes_used(fx, guest_id: uuid.UUID, minutes: int) -> None:  # noqa: ANN001
    usage = await get_or_reset_quota_usage(
        fx.repository,
        guest_id=guest_id,
        organization_id=fx.organization_id,
        period_type=QuotaPeriodType.DAILY,
        tz_name="UTC",
        now=datetime.now(UTC),
    )
    await fx.repository.update_quota_usage(usage, {"minutes_used": minutes})


# ============================================================================
# Deny / allow at sign-in -- the portal half, vendor-agnostic
# ============================================================================


class TestDenyAndAllowAtSignIn:
    async def test_a_blocked_phone_number_cannot_sign_in(self) -> None:
        hook = FakeAccessControlHook()
        hook.deny(identifier=_PHONE)
        fx = _fixture(access_control_hook=hook)
        with pytest.raises(GuestAccessDeniedError):
            await _sign_in(fx)
        assert fx.repository.sessions == {}

    async def test_a_blocked_device_mac_cannot_sign_in(self) -> None:
        hook = FakeAccessControlHook()
        hook.deny(mac_address=_MAC)
        fx = _fixture(access_control_hook=hook)
        with pytest.raises(GuestAccessDeniedError):
            await _sign_in(fx)

    async def test_removing_the_block_lets_them_back_in(self) -> None:
        hook = FakeAccessControlHook()
        hook.deny(identifier=_PHONE)
        fx = _fixture(access_control_hook=hook)
        with pytest.raises(GuestAccessDeniedError):
            await _sign_in(fx)
        hook.denied_identifiers.clear()
        nas = await _register_nas(fx)
        await _sign_in(fx)
        assert (await _authorize(fx, nas)).authorized is True

    async def test_the_refusal_the_guest_reads_does_not_leak_the_operator_note(
        self,
    ) -> None:
        hook = FakeAccessControlHook(denial_reason="owes us money")
        hook.deny(identifier=_PHONE)
        fx = _fixture(access_control_hook=hook)
        with pytest.raises(GuestAccessDeniedError) as exc_info:
            await _sign_in(fx)
        assert "owes us money" not in str(exc_info.value)
        assert exc_info.value.message

    async def test_a_guest_blocked_on_their_profile_cannot_sign_in(self) -> None:
        fx = _fixture()
        first = await _sign_in(fx)
        await fx.guest_service.block_guest(
            actor_user_id=uuid.uuid4(),
            guest_id=first.guest.id,
            requesting_organization_id=None,
            reason="test",
        )
        with pytest.raises(GuestBlockedError):
            await _sign_in(fx)

    async def test_whitelist_only_admits_the_listed_number_and_no_other(
        self,
    ) -> None:
        hook = FakeAccessControlHook()
        hook.allow(identifier=_PHONE)
        fx = _fixture(access_control_hook=hook, whitelist_only_enabled=True)
        nas = await _register_nas(fx)
        await _sign_in(fx)
        assert (await _authorize(fx, nas)).authorized is True
        with pytest.raises(WhitelistOnlyAccessDeniedError):
            await _sign_in(fx, identifier="+919800000001", mac="aa:bb:cc:dd:ee:01")

    async def test_a_closed_venue_refuses_sign_in(self) -> None:
        fx = _fixture()
        _shut_the_venue(fx)
        with pytest.raises(VenueClosedError):
            await _sign_in(fx)


# ============================================================================
# Deny after sign-in -- the RADIUS half
# ============================================================================


class TestABlockWrittenAfterSignInRefusesTheNextAccessRequest:
    async def test_by_phone(self) -> None:
        hook = FakeAccessControlHook()
        fx = _fixture(access_control_hook=hook)
        nas = await _register_nas(fx)
        await _sign_in(fx)
        assert (await _authorize(fx, nas)).authorized is True

        hook.deny(identifier=_PHONE)

        assert (await _authorize(fx, nas)).authorized is False

    async def test_by_the_mac_the_aruba_ap_reports(self) -> None:
        """The AP sends bare hex; the rule was typed with colons. The
        canonicalised Calling-Station-Id is what makes them meet."""
        hook = FakeAccessControlHook()
        fx = _fixture(access_control_hook=hook)
        nas = await _register_nas(fx)
        await _sign_in(fx)
        hook.deny(mac_address=_MAC.upper())
        assert (await _authorize(fx, nas)).authorized is False

    async def test_the_session_is_not_marked_ended(self) -> None:
        """Nothing can take the device off an Instant On AP, so the row stays
        what it is -- the guest is still online until their session ends."""
        hook = FakeAccessControlHook()
        fx = _fixture(access_control_hook=hook)
        nas = await _register_nas(fx)
        result = await _sign_in(fx)
        hook.deny(identifier=_PHONE)
        await _authorize(fx, nas)
        assert result.session.status == GuestSessionStatus.ACTIVE.value


# ============================================================================
# Devices per guest -- the portal half
# ============================================================================


class TestDevicesPerGuest:
    async def test_a_second_device_over_the_limit_is_refused(self) -> None:
        fx = _fixture(
            policy_lookup=_PolicyLookup(
                {PolicyType.DEVICE: {"max_devices_per_guest": 1}}
            )
        )
        await _sign_in(fx, mac="aa:bb:cc:dd:ee:01")
        with pytest.raises(GuestDeviceLimitExceededError):
            await _sign_in(fx, mac="aa:bb:cc:dd:ee:02")

    async def test_the_same_device_signing_in_again_is_not_a_second_device(
        self,
    ) -> None:
        fx = _fixture(
            policy_lookup=_PolicyLookup(
                {PolicyType.DEVICE: {"max_devices_per_guest": 1}}
            )
        )
        nas = await _register_nas(fx)
        await _sign_in(fx)
        await _sign_in(fx)
        assert (await _authorize(fx, nas)).authorized is True


# ============================================================================
# Session length and idle timeout -- the RADIUS reply attributes
# ============================================================================


class TestTimeoutsReachTheAccessPoint:
    async def test_session_timeout_is_sent_as_session_timeout(self) -> None:
        fx = _fixture(
            policy_lookup=_PolicyLookup(
                {
                    PolicyType.SESSION: {
                        "session_timeout_minutes": 60,
                        "idle_timeout_minutes": 15,
                    }
                }
            )
        )
        nas = await _register_nas(fx)
        await _sign_in(fx)
        authz = await _authorize(fx, nas)
        assert authz.authorized is True
        assert 3590 <= authz.session_timeout_seconds <= 3600
        assert authz.idle_timeout_seconds == 15 * 60
        assert authz.rate_limit is None


# ============================================================================
# Max daily session (FUP time) -- sign-in AND Session-Timeout
# ============================================================================


class TestDailyTimeLimit:
    def _lookup(self) -> _PolicyLookup:
        return _PolicyLookup(
            {
                PolicyType.SESSION: {"session_timeout_minutes": 240},
                PolicyType.FUP: {"daily_time_limit_minutes": 60},
            }
        )

    async def test_session_timeout_is_capped_by_what_is_left_today(self) -> None:
        fx = _fixture(policy_lookup=self._lookup())
        nas = await _register_nas(fx)
        result = await _sign_in(fx)
        await _set_minutes_used(fx, result.guest.id, 50)

        authz = await _authorize(fx, nas)

        assert authz.authorized is True
        assert authz.session_timeout_seconds == 10 * 60

    async def test_the_session_length_still_wins_when_it_is_shorter(self) -> None:
        fx = _fixture(
            policy_lookup=_PolicyLookup(
                {
                    PolicyType.SESSION: {"session_timeout_minutes": 30},
                    PolicyType.FUP: {"daily_time_limit_minutes": 600},
                }
            )
        )
        nas = await _register_nas(fx)
        await _sign_in(fx)
        authz = await _authorize(fx, nas)
        assert 1790 <= authz.session_timeout_seconds <= 1800

    async def test_a_used_up_day_refuses_the_access_request(self) -> None:
        fx = _fixture(policy_lookup=self._lookup())
        nas = await _register_nas(fx)
        result = await _sign_in(fx)
        await _set_minutes_used(fx, result.guest.id, 60)

        assert (await _authorize(fx, nas)).authorized is False
        # and the row is left alone: the AP ends it, not us
        assert result.session.status == GuestSessionStatus.ACTIVE.value

    async def test_a_used_up_day_refuses_the_next_sign_in(self) -> None:
        fx = _fixture(policy_lookup=self._lookup())
        result = await _sign_in(fx)
        await _set_minutes_used(fx, result.guest.id, 60)
        with pytest.raises(FairUsagePolicyExceededError):
            await _sign_in(fx)

    async def test_a_mikrotik_nas_is_not_capped_here(self) -> None:
        """Byte-identical for MikroTik: the remaining-allowance cap is a
        NAS-only addition; RouterOS sessions are cut by the accrual sweep."""
        fx = _fixture(vendor="mikrotik", policy_lookup=self._lookup())
        nas = await _register_nas(fx)
        result = await _sign_in(fx)
        await _set_minutes_used(fx, result.guest.id, 50)

        authz = await _authorize(fx, nas)

        assert authz.authorized is True
        assert authz.session_timeout_seconds > 239 * 60

    async def test_a_mikrotik_nas_is_not_refused_here_either(self) -> None:
        fx = _fixture(vendor="mikrotik", policy_lookup=self._lookup())
        nas = await _register_nas(fx)
        result = await _sign_in(fx)
        await _set_minutes_used(fx, result.guest.id, 60)
        assert (await _authorize(fx, nas)).authorized is True


# ============================================================================
# Data limit -- the breach is enforced at the next sign-in, never mid-session
# ============================================================================


class TestDataLimitAtANasOnlyVenue:
    def _lookup(self) -> _PolicyLookup:
        return _PolicyLookup({PolicyType.FUP: {"daily_data_limit_mb": 10}})

    async def _over_the_cap(self, fx):  # noqa: ANN001, ANN202
        result = await _sign_in(fx)
        await fx.guest_service.record_usage(
            session_id=result.session.id,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=11 * BYTES_PER_MB,
        )
        return result

    async def test_crossing_the_cap_leaves_the_session_active(self) -> None:
        """PM_SPEC §3.1 BE requirement: an Interim-Update past the cap must
        not mark an Aruba guest as gone while the AP keeps them online."""
        fx = _fixture(policy_lookup=self._lookup())
        result = await self._over_the_cap(fx)
        session = await fx.repository.get_session_by_id(result.session.id)
        assert session.status == GuestSessionStatus.ACTIVE.value
        assert session.ended_at is None
        assert session.disconnect_reason is None

    async def test_the_next_access_request_is_refused(self) -> None:
        fx = _fixture(policy_lookup=self._lookup())
        nas = await _register_nas(fx)
        await self._over_the_cap(fx)
        assert (await _authorize(fx, nas)).authorized is False

    async def test_the_next_sign_in_is_refused_with_a_reason(self) -> None:
        fx = _fixture(policy_lookup=self._lookup())
        await self._over_the_cap(fx)
        with pytest.raises(FairUsagePolicyExceededError) as exc_info:
            await _sign_in(fx)
        assert exc_info.value.metric == "data"

    async def test_a_session_data_limit_is_treated_the_same(self) -> None:
        """A voucher's own per-session ``data_limit_mb``."""
        fx = _fixture()
        nas = await _register_nas(fx)
        result = await _sign_in(fx)
        result.session.data_limit_mb = 5
        await fx.guest_service.record_usage(
            session_id=result.session.id,
            bytes_uploaded_delta=6 * BYTES_PER_MB,
            bytes_downloaded_delta=0,
        )
        assert result.session.status == GuestSessionStatus.ACTIVE.value
        assert (await _authorize(fx, nas)).authorized is False

    async def test_a_mikrotik_session_is_still_expired_on_the_spot(self) -> None:
        fx = _fixture(vendor="mikrotik", policy_lookup=self._lookup())
        result = await self._over_the_cap(fx)
        session = await fx.repository.get_session_by_id(result.session.id)
        assert session.status == GuestSessionStatus.EXPIRED.value
        assert session.disconnect_reason == "fup_data_quota_exceeded_daily"

    async def test_an_omada_session_is_still_expired_on_the_spot(self) -> None:
        fx = _fixture(vendor="omada", policy_lookup=self._lookup())
        result = await self._over_the_cap(fx)
        session = await fx.repository.get_session_by_id(result.session.id)
        assert session.status == GuestSessionStatus.EXPIRED.value


# ============================================================================
# Failure direction
# ============================================================================


class TestAPolicyOutageDoesNotLockTheVenueOut:
    async def test_authorize_still_accepts_when_the_policy_read_fails(self) -> None:
        lookup = _PolicyLookup()
        fx = _fixture(policy_lookup=lookup)
        nas = await _register_nas(fx)
        await _sign_in(fx)
        lookup.raises = RuntimeError("policy tables unreachable")
        authz = await _authorize(fx, nas)
        assert authz.authorized is True


# ============================================================================
# Blocking a guest who is online right now
# ============================================================================


class TestBlockingAnOnlineGuestAtANasOnlyVenue:
    """The live half of a block cannot happen on an Instant On AP. It must say
    so in the owner's words -- not "could not reach the controller", which
    reads as a fault to repair -- and it must not touch the controller path."""

    async def test_it_raises_the_plain_sentence_without_contacting_anything(
        self,
    ) -> None:
        from app.domains.guest_access.enforcement import LiveSessionTerminator
        from app.domains.guest_access.exceptions import (
            NasOnlyLiveSessionUnreachableError,
        )
        from tests.unit.test_omada_client_management import (
            CLIENT_MAC,
            GUEST_IDENTIFIER,
            _DeviceLookup,
            _mac_only_controller_terminator,
            _Router,
            _RouterLookup,
            _Session,
        )

        reached: list[dict] = []
        terminator = LiveSessionTerminator(
            router_lookup=_RouterLookup(
                _Router(vendor=_ARUBA, api_username=None, management_ip_address=None)
            ),
            device_lookup=_DeviceLookup(mac=CLIENT_MAC),
            controller_terminator=_mac_only_controller_terminator(reached),
        )
        with pytest.raises(NasOnlyLiveSessionUnreachableError) as exc_info:
            await terminator.end_on_router(
                session=_Session(device_id=uuid.uuid4()),
                identifier=GUEST_IDENTIFIER,
                organization_id=uuid.uuid4(),
            )
        assert reached == []
        message = str(exc_info.value.message)
        assert "stops this person signing in again" in message
        assert "controller" not in message.lower()
        assert "RADIUS" not in message
        assert exc_info.value.status_code == 409

    async def test_an_omada_venue_still_goes_to_its_controller(self) -> None:
        from app.domains.guest_access.enforcement import LiveSessionTerminator
        from tests.unit.test_omada_client_management import (
            CLIENT_MAC,
            GUEST_IDENTIFIER,
            _DeviceLookup,
            _mac_only_controller_terminator,
            _Router,
            _RouterLookup,
            _Session,
        )

        reached: list[dict] = []
        terminator = LiveSessionTerminator(
            router_lookup=_RouterLookup(
                _Router(
                    vendor="tplink_omada",
                    api_username=None,
                    management_ip_address=None,
                )
            ),
            device_lookup=_DeviceLookup(mac=CLIENT_MAC),
            controller_terminator=_mac_only_controller_terminator(reached),
        )
        outcome = await terminator.end_on_router(
            session=_Session(device_id=uuid.uuid4()),
            identifier=GUEST_IDENTIFIER,
            organization_id=uuid.uuid4(),
        )
        assert outcome.ended_cleanly is True
        assert len(reached) == 1


# ============================================================================
# Open Hours -- sign-in AND Session-Timeout
# ============================================================================

_WEEKDAYS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)


def _noon_somewhere() -> tuple[str, datetime]:
    """A fixed-offset zone where it is roughly midday right now, so a window
    that closes 30 minutes from now never wraps past midnight whatever time
    the suite runs. ``Etc/GMT-N`` is UTC+N (POSIX sign convention)."""
    from zoneinfo import ZoneInfo

    utc_hour = datetime.now(UTC).hour
    offset = (12 - utc_hour) % 24
    if offset > 14:
        offset -= 24
    name = "Etc/GMT" + (f"-{offset}" if offset > 0 else f"+{-offset}" if offset else "")
    return name, datetime.now(ZoneInfo(name))


def _open_until(fx, minutes_from_now: int) -> None:  # noqa: ANN001
    from datetime import timedelta

    zone, local = _noon_somewhere()
    end = (local + timedelta(minutes=minutes_from_now)).strftime("%H:%M")
    config = fx.captive_portal_service.configs_by_org[fx.organization_id]
    config.business_hours_enabled = True
    config.business_hours_timezone = zone
    config.business_hours_schedule = {
        _WEEKDAYS[local.weekday()]: {"open": True, "start": "00:00", "end": end}
    }


class TestOpenHours:
    async def test_session_timeout_is_capped_at_closing_time(self) -> None:
        fx = _fixture()
        _open_until(fx, 30)
        nas = await _register_nas(fx)
        await _sign_in(fx)

        authz = await _authorize(fx, nas)

        assert authz.authorized is True
        # closes at the END of the minute 30 minutes from now
        assert 29 * 60 <= authz.session_timeout_seconds <= 31 * 60

    async def test_a_venue_that_has_closed_refuses_the_access_request(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        result = await _sign_in(fx)
        _shut_the_venue(fx)

        assert (await _authorize(fx, nas)).authorized is False
        assert result.session.status == GuestSessionStatus.ACTIVE.value

    async def test_a_mikrotik_nas_is_unchanged_by_open_hours(self) -> None:
        fx = _fixture(vendor="mikrotik")
        _open_until(fx, 30)
        nas = await _register_nas(fx)
        await _sign_in(fx)
        authz = await _authorize(fx, nas)
        assert authz.session_timeout_seconds > 31 * 60

        _shut_the_venue(fx)
        assert (await _authorize(fx, nas)).authorized is True


class TestSecondsUntilClosing:
    def _at(self, hhmm: str) -> datetime:
        h, m = (int(x) for x in hhmm.split(":"))
        # 2026-10-05 is a Monday
        return datetime(2026, 10, 5, h, m, 0, tzinfo=UTC)

    def _call(self, now: datetime, schedule: dict, enabled: bool = True):  # noqa: ANN202
        from app.domains.captive_portal.validators import seconds_until_closing

        return seconds_until_closing(
            enabled=enabled, timezone="UTC", schedule=schedule, now=now
        )

    def test_counts_to_the_end_of_the_closing_minute(self) -> None:
        schedule = {"monday": {"open": True, "start": "09:00", "end": "18:00"}}
        assert self._call(self._at("17:00"), schedule) == 3660

    def test_none_when_hours_are_off(self) -> None:
        assert self._call(self._at("17:00"), {}, enabled=False) is None

    def test_none_when_already_closed(self) -> None:
        schedule = {"monday": {"open": True, "start": "09:00", "end": "18:00"}}
        assert self._call(self._at("19:00"), schedule) is None
        assert self._call(self._at("17:00"), {"monday": {"open": False}}) is None
