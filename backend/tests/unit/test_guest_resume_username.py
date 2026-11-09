"""``GET /guest/session/active`` needs no login, so what it returns as the
guest's identity follows ``guest_resume_identifier_mode``. The opaque alias it
offers must behave exactly like the identifier at RADIUS."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.core.config import get_settings
from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.resume_username import (
    apply_resume_identity,
    issue_resume_username,
    session_id_from_resume_username,
)
from tests.unit.test_guest import make_fixture

_PHONE = "+919811122233"
_MAC = "60:f4:45:0b:28:66"


async def _nas(fx):  # noqa: ANN001, ANN202
    await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier="cg-resume-test",
        shared_secret="supersecret123",
    )
    return await fx.radius_service.authenticate_nas(
        nas_identifier="cg-resume-test", shared_secret="supersecret123"
    )


async def _sign_in(fx):  # noqa: ANN001, ANN202
    return await fx.guest_service.login_via_otp(
        identifier=_PHONE,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=_MAC,
        ip_address="192.168.1.50",
    )


def _response() -> SimpleNamespace:
    return SimpleNamespace(identifier=_PHONE, hotspot_username=None)


class TestAlias:
    def test_round_trip(self) -> None:
        session_id = uuid.uuid4()
        assert (
            session_id_from_resume_username(issue_resume_username(session_id))
            == session_id
        )

    def test_it_does_not_contain_the_identifier(self) -> None:
        assert "9811122233" not in issue_resume_username(uuid.uuid4())

    @pytest.mark.parametrize(
        "value", [None, "", _PHONE, "mac:60f4450b2866", "wr1-abc-def"]
    )
    def test_other_usernames_are_not_aliases(self, value: str | None) -> None:
        assert session_id_from_resume_username(value) is None

    def test_a_forged_signature_is_refused(self) -> None:
        forged = f"wr1-{uuid.uuid4().hex}-{'0' * 16}"
        assert session_id_from_resume_username(forged) is None


class TestModes:
    def test_off_changes_nothing(self) -> None:
        response = _response()
        apply_resume_identity(response, uuid.uuid4())
        assert response.identifier == _PHONE
        assert response.hotspot_username is None

    def test_alias_keeps_the_identifier(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(get_settings(), "guest_resume_identifier_mode", "alias")
        response = _response()
        apply_resume_identity(response, uuid.uuid4())
        assert response.identifier == _PHONE
        assert response.hotspot_username.startswith("wr1-")

    def test_masked_hides_the_identifier(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(get_settings(), "guest_resume_identifier_mode", "masked")
        response = _response()
        apply_resume_identity(response, uuid.uuid4())
        assert "9811122233" not in response.identifier
        assert response.hotspot_username.startswith("wr1-")


class TestRadius:
    async def test_authorize_accepts_the_alias(self) -> None:
        fx = make_fixture()
        nas = await _nas(fx)
        result = await _sign_in(fx)
        authz = await fx.radius_service.authorize(
            nas_client=nas,
            username=issue_resume_username(result.session.id),
            calling_station_id=_MAC,
        )
        assert authz.authorized is True

    async def test_accounting_finds_the_session_by_alias(self) -> None:
        fx = make_fixture()
        nas = await _nas(fx)
        result = await _sign_in(fx)
        session = await fx.radius_service._get_session_for_nas(
            nas,
            issue_resume_username(result.session.id),
            calling_station_id=_MAC,
        )
        assert session.id == result.session.id

    async def test_a_forged_alias_is_refused(self) -> None:
        fx = make_fixture()
        nas = await _nas(fx)
        result = await _sign_in(fx)
        authz = await fx.radius_service.authorize(
            nas_client=nas,
            username=f"wr1-{result.session.id.hex}-{'0' * 16}",
            calling_station_id=_MAC,
        )
        assert authz.authorized is False

    async def test_an_alias_from_another_router_is_refused(self) -> None:
        fx = make_fixture()
        nas = await _nas(fx)
        result = await _sign_in(fx)
        result.session.router_id = uuid.uuid4()
        authz = await fx.radius_service.authorize(
            nas_client=nas,
            username=issue_resume_username(result.session.id),
            calling_station_id=_MAC,
        )
        assert authz.authorized is False

    async def test_the_identifier_still_works(self) -> None:
        fx = make_fixture()
        nas = await _nas(fx)
        await _sign_in(fx)
        authz = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id=_MAC
        )
        assert authz.authorized is True
