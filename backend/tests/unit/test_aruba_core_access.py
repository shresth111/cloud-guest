"""Aruba Instant On: the holes left in block, voucher and session timeout."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest_access.exceptions import GuestAccessDeniedError
from app.domains.voucher.constants import VoucherStatus
from tests.unit.test_aruba_access_rules import (
    _MAC,
    _PHONE,
    _authorize,
    _fixture,
    _register_nas,
    _sign_in,
    _sign_in_voucher,
)
from tests.unit.test_guest import FakeAccessControlHook

_ANOTHER_ID = "+919800000002"
_OTHER_MAC = "60:f4:45:0b:28:77"


async def _sign_in_other(fx, mac: str = _MAC):  # noqa: ANN001, ANN202
    return await fx.guest_service.login_via_otp(
        identifier=_ANOTHER_ID,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
        ip_address="192.168.1.50",
    )


async def _voucher_as(fx, identifier: str, mac: str = _MAC):  # noqa: ANN001, ANN202
    return await fx.guest_service.login_via_voucher(
        code="AP21VOUCHER",
        identifier=identifier,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
        ip_address="192.168.1.50",
    )


class TestABlockedPersonsDevice:
    """A block names an identifier. The device they signed in on is the only
    reliable link to the same person typing a different one."""

    async def _blocked_phone_on_mac(self, vendor: str | None = None):  # noqa: ANN202
        hook = FakeAccessControlHook()
        fx = (
            _fixture(access_control_hook=hook)
            if vendor is None
            else _fixture(vendor=vendor, access_control_hook=hook)
        )
        await _sign_in(fx)
        hook.deny(identifier=_PHONE)
        return fx, hook

    async def test_another_identifier_on_that_device_is_refused(self) -> None:
        fx, _ = await self._blocked_phone_on_mac()
        with pytest.raises(GuestAccessDeniedError):
            await _sign_in_other(fx)

    async def test_a_voucher_typed_with_another_identifier_is_refused(self) -> None:
        fx, _ = await self._blocked_phone_on_mac()
        fx.voucher_service.register(
            "AP21VOUCHER", data_limit_mb=None, validity_minutes=60
        )
        with pytest.raises(GuestAccessDeniedError):
            await _voucher_as(fx, "+919800000001")

    async def test_someone_else_on_another_device_is_unaffected(self) -> None:
        fx, _ = await self._blocked_phone_on_mac()
        result = await _sign_in_other(fx, mac=_OTHER_MAC)
        assert result.session.is_active()

    async def test_lifting_the_block_lets_the_device_back(self) -> None:
        fx, hook = await self._blocked_phone_on_mac()
        hook.denied_identifiers.clear()
        assert (await _sign_in_other(fx)).session.is_active()

    @pytest.mark.parametrize("vendor", ["mikrotik", "tplink_omada"])
    async def test_other_vendors_are_unchanged(self, vendor: str) -> None:
        fx, _ = await self._blocked_phone_on_mac(vendor)
        assert (await _sign_in_other(fx)).session.is_active()

    async def test_a_lookup_failure_does_not_lock_the_venue_out(self) -> None:
        fx, _ = await self._blocked_phone_on_mac()

        async def boom(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
            raise RuntimeError("db")

        fx.repository.get_guest_by_id = boom
        assert (await _sign_in_other(fx)).session.is_active()


class TestAnOtpLoginOverAVoucherSession:
    async def _voucher_then_otp(self, vendor: str | None = None):  # noqa: ANN202
        fx = _fixture() if vendor is None else _fixture(vendor=vendor)
        voucher, _batch = fx.voucher_service.register(
            "AP21VOUCHER", data_limit_mb=None, validity_minutes=120
        )
        nas = await _register_nas(fx)
        await _sign_in_voucher(fx)
        result = await _sign_in(fx)
        return fx, nas, voucher, result

    async def test_a_revoked_voucher_no_longer_refuses_the_otp_session(self) -> None:
        fx, nas, voucher, _ = await self._voucher_then_otp()
        voucher.status = VoucherStatus.REVOKED.value
        assert (await _authorize(fx, nas)).authorized is True

    async def test_the_old_voucher_expiry_no_longer_caps_it(self) -> None:
        fx, nas, voucher, result = await self._voucher_then_otp()
        voucher.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        authz = await _authorize(fx, nas)
        assert authz.session_timeout_seconds > 10 * 60
        assert result.session.voucher_id is None

    async def test_mikrotik_keeps_the_voucher_on_the_row(self) -> None:
        _, _, voucher, result = await self._voucher_then_otp("mikrotik")
        assert result.session.voucher_id == voucher.id


class TestSignInAgainDoesNotExtendTime:
    async def test_the_clock_keeps_running_from_the_first_sign_in(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        first = await _sign_in(fx)
        first.session.started_at = datetime.now(UTC) - timedelta(minutes=200)
        started = first.session.started_at
        again = await _sign_in(fx)
        assert again.session.id == first.session.id
        assert again.session.started_at == started
        authz = await _authorize(fx, nas)
        assert authz.session_timeout_seconds <= 40 * 60 + 1
