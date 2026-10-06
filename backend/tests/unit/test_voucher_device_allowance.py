"""A voucher's own device allowance decides how many phones one code admits.

QA on staging, 2026-10-06 (Aruba Instant On venue, Guest WiFi Limits ->
Devices per user = 1): "With voucher also only 1 device is allowed to
connect". Two things stopped the second phone, either one enough on its own:

1. ``login_via_voucher`` ran the venue's per-user device limit, so a guest
   who typed the same phone number on a second phone got a 409
   ("already has 1 device(s) connected") before the code was even looked at.
2. A code's "Max Uses" (default 1) counted *sign-ins*, so the second phone
   -- under any name -- found the code exhausted, and so did the FIRST phone
   if it ever had to sign in again.

The rule now: ``VoucherBatch.max_devices_per_voucher`` (N) is the number of
distinct devices one code admits; at a voucher sign-in it replaces the
venue's "Devices per user"; a device the code already admitted signs in
again without taking a slot; device N+1 is refused; every session a code
admits ends when the code does. At a NAS-only (Aruba) venue each admitted
phone gets its own session and its own Accept, and a phone the code did not
admit is still refused.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.guest.constants import GuestAuthMethod, GuestSessionStatus
from app.domains.guest.exceptions import GuestDeviceLimitExceededError
from app.domains.guest.validators import canonicalize_calling_station_id
from app.domains.policy.constants import PolicyType
from app.domains.router.vendor_capabilities import ARUBA_INSTANT_ON_VENDOR
from app.domains.voucher.exceptions import (
    VoucherExhaustedError,
    VoucherExpiredError,
    VoucherRevokedError,
)
from tests.unit.test_aruba_access_rules import _PolicyLookup, _register_nas
from tests.unit.test_guest import make_fixture
from tests.unit.test_voucher import make_service

_PHONE = "+919811122233"
_MAC_A = "60:f4:45:0b:28:66"
_MAC_B = "60:f4:45:0b:28:77"
_MAC_C = "60:f4:45:0b:28:88"
_VENDORS = ["mikrotik", "omada", ARUBA_INSTANT_ON_VENDOR]


def _one_device_per_user():  # noqa: ANN202
    """The staging venue's Guest WiFi Limits: Devices per user = 1."""
    return _PolicyLookup({PolicyType.DEVICE: {"max_devices_per_guest": 1}})


def _fixture(vendor: str = "mikrotik", **kwargs):  # noqa: ANN003, ANN202
    fx = make_fixture(policy_lookup=_one_device_per_user(), **kwargs)
    fx.router.vendor = vendor
    return fx


async def _voucher(  # noqa: ANN202
    fx,  # noqa: ANN001
    mac: str | None,
    *,
    code: str = "TWOPHONES",
    identifier: str = _PHONE,
):
    return await fx.guest_service.login_via_voucher(
        code=code,
        identifier=identifier,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
        ip_address="192.168.1.50",
    )


async def _otp(fx, mac: str):  # noqa: ANN001, ANN202
    return await fx.guest_service.login_via_otp(
        identifier=_PHONE,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
        ip_address="192.168.1.50",
    )


def _csid(mac: str) -> str:
    return canonicalize_calling_station_id(mac.replace(":", ""))


# ============================================================================
# The portal: every vendor
# ============================================================================


@pytest.mark.parametrize("vendor", _VENDORS)
class TestTheVoucherDecidesHowManyDevices:
    async def test_a_two_device_voucher_admits_two_phones_under_one_number(
        self, vendor: str
    ) -> None:
        """The QA report, exactly: same phone number typed on both phones,
        venue Devices per user = 1, voucher made for 2 devices."""
        fx = _fixture(vendor)
        fx.voucher_service.register(
            "TWOPHONES", data_limit_mb=None, validity_minutes=60, max_devices=2
        )
        first = await _voucher(fx, _MAC_A)
        second = await _voucher(fx, _MAC_B)

        assert first.guest.id == second.guest.id
        assert first.session.id != second.session.id
        assert first.session.status == GuestSessionStatus.ACTIVE.value
        assert second.session.status == GuestSessionStatus.ACTIVE.value

    async def test_the_third_device_is_refused(self, vendor: str) -> None:
        fx = _fixture(vendor)
        fx.voucher_service.register(
            "TWOPHONES", data_limit_mb=None, validity_minutes=60, max_devices=2
        )
        await _voucher(fx, _MAC_A)
        await _voucher(fx, _MAC_B, identifier="+919800000002")
        with pytest.raises(VoucherExhaustedError) as exc_info:
            await _voucher(fx, _MAC_C, identifier="+919800000003")
        assert "maximum number of devices" in exc_info.value.message

    async def test_a_one_device_voucher_admits_one_phone_and_lets_it_back_in(
        self, vendor: str
    ) -> None:
        fx = _fixture(vendor)
        fx.voucher_service.register(
            "ONEPHONE", data_limit_mb=None, validity_minutes=60, max_devices=1
        )
        first = await _voucher(fx, _MAC_A, code="ONEPHONE")
        with pytest.raises(VoucherExhaustedError):
            await _voucher(fx, _MAC_B, code="ONEPHONE", identifier="+919800000002")

        # The admitted phone dropped off and signs in again with the same
        # code: a re-entry, not a second device.
        await fx.repository.update_session(
            first.session, {"status": GuestSessionStatus.DISCONNECTED.value}
        )
        again = await _voucher(fx, _MAC_A, code="ONEPHONE")
        assert again.session.status == GuestSessionStatus.ACTIVE.value

    async def test_a_later_device_gets_only_what_is_left_of_the_voucher(
        self, vendor: str
    ) -> None:
        fx = _fixture(vendor)
        voucher, _batch = fx.voucher_service.register(
            "TWOPHONES", data_limit_mb=None, validity_minutes=60, max_devices=2
        )
        await _voucher(fx, _MAC_A)
        # 20 minutes into the hour.
        voucher.expires_at = datetime.now(UTC) + timedelta(minutes=40)
        second = await _voucher(fx, _MAC_B)
        assert second.session.session_timeout_minutes == 40

    async def test_an_otp_sign_in_still_obeys_devices_per_user(
        self, vendor: str
    ) -> None:
        """The venue limit is unchanged everywhere a voucher is not the
        credential."""
        fx = _fixture(vendor)
        await _otp(fx, _MAC_A)
        with pytest.raises(GuestDeviceLimitExceededError):
            await _otp(fx, _MAC_B)

    async def test_a_voucher_phone_next_to_an_otp_phone(self, vendor: str) -> None:
        """What the tester actually did: phone 1 signed in by OTP, phone 2
        brought a voucher under the same number."""
        fx = _fixture(vendor)
        await _otp(fx, _MAC_A)
        fx.voucher_service.register(
            "ONEPHONE", data_limit_mb=None, validity_minutes=60, max_devices=1
        )
        result = await _voucher(fx, _MAC_B, code="ONEPHONE")
        assert result.session.status == GuestSessionStatus.ACTIVE.value


# ============================================================================
# The real VoucherService behind the guest login
# ============================================================================


async def _real_batch(vfx, *, max_devices: int | None, max_uses: int = 1):  # noqa: ANN001, ANN202
    batch = await vfx.service.create_batch(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=vfx.organization.id,
        organization_id=vfx.organization.id,
        location_id=None,
        name="Front desk",
        quantity=1,
        code_length=8,
        code_prefix=None,
        validity_minutes=60,
        batch_expires_at=None,
        max_uses_per_voucher=max_uses,
        max_devices_per_voucher=max_devices,
        data_limit_mb=None,
        notes=None,
        has_manage_permission=True,
    )
    (voucher,) = [
        v for v in vfx.repository.vouchers.values() if v.batch_id == batch.id
    ]
    return batch, voucher


def _wired(vendor: str = "mikrotik"):  # noqa: ANN202
    fx = _fixture(vendor)
    vfx = make_service()
    fx.guest_service.voucher_service = vfx.service
    return fx, vfx


class TestWithTheRealVoucherService:
    async def test_create_batch_stores_the_allowance_in_both_columns(self) -> None:
        _fx, vfx = _wired()
        batch, _voucher_row = await _real_batch(vfx, max_devices=3)
        assert batch.max_devices_per_voucher == 3
        assert batch.max_uses_per_voucher == 3

    async def test_a_legacy_client_sending_only_max_uses_gets_that_many_devices(
        self,
    ) -> None:
        _fx, vfx = _wired()
        batch, _voucher_row = await _real_batch(vfx, max_devices=None, max_uses=4)
        assert batch.max_devices_per_voucher == 4
        assert batch.device_allowance() == 4

    async def test_two_devices_then_a_refusal_then_a_re_entry(self) -> None:
        fx, vfx = _wired()
        _batch, voucher = await _real_batch(vfx, max_devices=2)

        await _voucher(fx, _MAC_A, code=voucher.code)
        await _voucher(fx, _MAC_B, code=voucher.code)
        assert voucher.use_count == 2
        assert voucher.status == "exhausted"

        with pytest.raises(VoucherExhaustedError):
            await _voucher(fx, _MAC_C, code=voucher.code, identifier="+919800000003")

        again = await _voucher(fx, _MAC_A, code=voucher.code)
        assert again.session.status == GuestSessionStatus.ACTIVE.value
        # A re-entry takes no slot.
        assert voucher.use_count == 2

    async def test_a_sign_in_without_a_mac_is_always_a_new_device(self) -> None:
        fx, vfx = _wired()
        _batch, voucher = await _real_batch(vfx, max_devices=1)
        await _voucher(fx, None, code=voucher.code)
        with pytest.raises(VoucherExhaustedError):
            await _voucher(fx, None, code=voucher.code)

    async def test_an_admitted_device_is_refused_once_the_voucher_expires(
        self,
    ) -> None:
        fx, vfx = _wired()
        _batch, voucher = await _real_batch(vfx, max_devices=1)
        await _voucher(fx, _MAC_A, code=voucher.code)
        voucher.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        with pytest.raises(VoucherExpiredError):
            await _voucher(fx, _MAC_A, code=voucher.code)

    async def test_an_admitted_device_is_refused_once_the_voucher_is_revoked(
        self,
    ) -> None:
        fx, vfx = _wired()
        batch, voucher = await _real_batch(vfx, max_devices=2)
        await _voucher(fx, _MAC_A, code=voucher.code)
        await vfx.service.revoke_batch(
            batch_id=batch.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=vfx.organization.id,
        )
        with pytest.raises(VoucherRevokedError):
            await _voucher(fx, _MAC_A, code=voucher.code)

    async def test_a_full_voucher_past_its_validity_says_expired(self) -> None:
        """Not "in use on the maximum number of devices", which would send
        the guest looking for phones that no longer matter."""
        fx, vfx = _wired()
        _batch, voucher = await _real_batch(vfx, max_devices=1)
        await _voucher(fx, _MAC_A, code=voucher.code)
        voucher.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        with pytest.raises(VoucherExpiredError):
            await _voucher(fx, _MAC_B, code=voucher.code, identifier="+919800000002")

    async def test_validate_reports_device_slots_left(self) -> None:
        fx, vfx = _wired()
        _batch, voucher = await _real_batch(vfx, max_devices=3)
        await _voucher(fx, _MAC_A, code=voucher.code)
        result = await vfx.service.validate_voucher(code=voucher.code, source="t")
        assert result.uses_remaining == 2


# ============================================================================
# Aruba Instant On: each admitted phone gets its own Accept
# ============================================================================


class TestNasOnlyAcceptsEachAdmittedPhone:
    async def test_both_phones_are_accepted_and_a_third_is_not(self) -> None:
        fx = _fixture(ARUBA_INSTANT_ON_VENDOR)
        fx.voucher_service.register(
            "TWOPHONES", data_limit_mb=None, validity_minutes=60, max_devices=2
        )
        nas = await _register_nas(fx)
        first = await _voucher(fx, _MAC_A)
        second = await _voucher(fx, _MAC_B)

        a = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id=_csid(_MAC_A)
        )
        b = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id=_csid(_MAC_B)
        )
        c = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id=_csid(_MAC_C)
        )
        assert a.authorized is True and b.authorized is True
        # A phone that never redeemed the code cannot ride a signed-in
        # guest's number (Instant On ignores the login password).
        assert c.authorized is False
        assert first.session.id != second.session.id

    async def test_a_phone_the_voucher_refused_is_refused_at_radius_too(
        self,
    ) -> None:
        fx = _fixture(ARUBA_INSTANT_ON_VENDOR)
        fx.voucher_service.register(
            "ONEPHONE", data_limit_mb=None, validity_minutes=60, max_devices=1
        )
        nas = await _register_nas(fx)
        await _voucher(fx, _MAC_A, code="ONEPHONE")
        with pytest.raises(VoucherExhaustedError):
            await _voucher(fx, _MAC_B, code="ONEPHONE")
        refused = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id=_csid(_MAC_B)
        )
        assert refused.authorized is False

    async def test_the_first_phone_stays_accepted_after_the_second_leaves(
        self,
    ) -> None:
        """The newest session ending must not lock out an older phone that
        is still online (an AP re-asks after a roam)."""
        fx = _fixture(ARUBA_INSTANT_ON_VENDOR)
        fx.voucher_service.register(
            "TWOPHONES", data_limit_mb=None, validity_minutes=60, max_devices=2
        )
        nas = await _register_nas(fx)
        await _voucher(fx, _MAC_A)
        second = await _voucher(fx, _MAC_B)
        await fx.repository.update_session(
            second.session,
            {
                "status": GuestSessionStatus.DISCONNECTED.value,
                "ended_at": datetime.now(UTC),
            },
        )

        a = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id=_csid(_MAC_A)
        )
        b = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id=_csid(_MAC_B)
        )
        assert a.authorized is True
        assert b.authorized is False
