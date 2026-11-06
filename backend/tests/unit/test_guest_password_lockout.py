"""QA 2026-11-06 M6: per-identifier lockout on guest password login,
mirroring PIN login's."""

from __future__ import annotations

import pytest

from app.domains.guest.constants import PASSWORD_MAX_ATTEMPTS, GuestAuthMethod
from app.domains.guest.exceptions import (
    GuestPasswordLockedError,
    GuestPasswordLoginFailedError,
)
from tests.unit.test_guest import make_fixture

_PHONE = "+15551234567"
_PASSWORD = "Correct-Horse-1!"


async def _guest_with_password(fx):  # noqa: ANN001, ANN202
    otp = await fx.guest_service.login_via_otp(
        identifier=_PHONE,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
    )
    await fx.guest_service.set_guest_password(
        guest_id=otp.guest.id, session_id=otp.session.id, password=_PASSWORD
    )


async def _login(fx, password: str):  # noqa: ANN001, ANN202
    return await fx.guest_service.login_via_password(
        identifier=_PHONE,
        password=password,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac="aa:bb:cc:dd:ee:ff",
    )


class TestPasswordLockout:
    async def test_locks_after_the_cap_even_with_the_right_password(self) -> None:
        fx = make_fixture()
        await _guest_with_password(fx)
        for _ in range(PASSWORD_MAX_ATTEMPTS):
            with pytest.raises(GuestPasswordLoginFailedError):
                await _login(fx, "wrong-password-1!")
        with pytest.raises(GuestPasswordLockedError) as exc:
            await _login(fx, _PASSWORD)
        assert exc.value.status_code == 423

    async def test_a_success_clears_the_counter(self) -> None:
        fx = make_fixture()
        await _guest_with_password(fx)
        for _ in range(PASSWORD_MAX_ATTEMPTS - 1):
            with pytest.raises(GuestPasswordLoginFailedError):
                await _login(fx, "wrong-password-1!")
        await _login(fx, _PASSWORD)
        for _ in range(PASSWORD_MAX_ATTEMPTS - 1):
            with pytest.raises(GuestPasswordLoginFailedError):
                await _login(fx, "wrong-password-1!")
        assert (await _login(fx, _PASSWORD)).guest.identifier == _PHONE

    async def test_unknown_identifiers_count_too(self) -> None:
        """No oracle: a guessed identifier with no account locks the same."""
        fx = make_fixture()
        for _ in range(PASSWORD_MAX_ATTEMPTS):
            with pytest.raises(GuestPasswordLoginFailedError):
                await _login(fx, "whatever-1!")
        with pytest.raises(GuestPasswordLockedError):
            await _login(fx, "whatever-1!")
