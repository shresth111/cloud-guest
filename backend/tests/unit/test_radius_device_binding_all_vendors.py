"""QA 2026-11-06 C2: RADIUS Authorize binds the Accept to the device on
MikroTik and Omada too, not only on NAS-only (Aruba Instant On) APs.

The portal's hotspot hand-off posts ``username=<identifier>`` with a fixed
fallback password, so before this fix any client that knew an online guest's
phone number could submit it from its own device and be admitted on that
guest's session with no OTP and no device-limit check.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.config import get_settings
from app.domains.guest.constants import GuestAuthMethod
from tests.unit.test_guest import make_fixture

_PHONE = "+919811122233"
_MAC = "60:f4:45:0b:28:66"


def _fixture(vendor: str):  # noqa: ANN202
    fx = make_fixture()
    fx.router.vendor = vendor
    return fx


async def _nas(fx):  # noqa: ANN001, ANN202
    await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier="cg-bind-test",
        shared_secret="supersecret123",
    )
    return await fx.radius_service.authenticate_nas(
        nas_identifier="cg-bind-test", shared_secret="supersecret123"
    )


async def _sign_in(fx, mac: str | None = _MAC):  # noqa: ANN001, ANN202
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


_VENDORS = ["mikrotik", "tplink_omada"]


@pytest.fixture(autouse=True)
def _enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shipped default is 'log' (first deploy); these pin enforcement.
    The log-mode behaviour is pinned in ``TestFirstDeployLogMode``."""
    monkeypatch.setattr(
        get_settings(), "radius_authorize_device_binding_mode", "enforce"
    )


@pytest.mark.parametrize("vendor", _VENDORS)
class TestDeviceBinding:
    async def test_the_signed_in_device_is_accepted(self, vendor: str) -> None:
        fx = _fixture(vendor)
        nas = await _nas(fx)
        await _sign_in(fx)
        authz = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id="60:F4:45:0B:28:66"
        )
        assert authz.authorized is True

    @pytest.mark.parametrize(
        "csid", ["60-F4-45-0B-28-66", "60f4.450b.2866", "60f4450b2866"]
    )
    async def test_mac_spelling_never_decides(self, vendor: str, csid: str) -> None:
        """MikroTik sends ``AA:BB:..``, Omada ``AA-BB-..``."""
        fx = _fixture(vendor)
        nas = await _nas(fx)
        await _sign_in(fx)
        authz = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id=csid
        )
        assert authz.authorized is True

    async def test_a_stranger_posting_the_identifier_is_refused(
        self, vendor: str
    ) -> None:
        fx = _fixture(vendor)
        nas = await _nas(fx)
        await _sign_in(fx)
        authz = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id="0A-1B-2C-3D-4E-5F"
        )
        assert authz.authorized is False

    async def test_a_login_without_a_mac_is_still_adopted(self, vendor: str) -> None:
        fx = _fixture(vendor)
        nas = await _nas(fx)
        await _sign_in(fx, mac=None)
        authz = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id="0A:1B:2C:3D:4E:5F"
        )
        assert authz.authorized is True

    async def test_no_calling_station_id_is_not_second_guessed(
        self, vendor: str
    ) -> None:
        fx = _fixture(vendor)
        nas = await _nas(fx)
        await _sign_in(fx)
        for csid in (None, "not-a-mac"):
            authz = await fx.radius_service.authorize(
                nas_client=nas, username=_PHONE, calling_station_id=csid
            )
            assert authz.authorized is True

    async def test_rollback_flag_restores_the_old_behaviour(
        self, vendor: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            get_settings(), "radius_authorize_device_binding_all_vendors", False
        )
        fx = _fixture(vendor)
        nas = await _nas(fx)
        await _sign_in(fx)
        authz = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id="0A:1B:2C:3D:4E:5F"
        )
        assert authz.authorized is True


class TestFirstDeployLogMode:
    @pytest.mark.parametrize("vendor", _VENDORS)
    async def test_log_mode_admits_a_mismatch_on_mikrotik_and_omada(
        self, vendor: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            get_settings(), "radius_authorize_device_binding_mode", "log"
        )
        fx = _fixture(vendor)
        nas = await _nas(fx)
        await _sign_in(fx)
        authz = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id="0A:1B:2C:3D:4E:5F"
        )
        assert authz.authorized is True

    def test_the_first_deploy_default_is_log_only(self) -> None:
        from app.core.config import Settings

        field = Settings.model_fields["radius_authorize_device_binding_mode"]
        assert field.default == "log"
