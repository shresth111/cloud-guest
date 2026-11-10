"""QA 2026-11-06 H1: a real login issues a signed ``session_token``;
``GET /guest/session/active`` never does; the session-mutating guest
endpoints check it, and require it per ``guest_session_token_enforcement``
(``off`` during the transition, so cached portal bundles keep working).
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.core.config import get_settings
from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.exceptions import GuestSessionProofRequiredError
from app.domains.guest.router import (
    _login_payload,
    guest_disconnect_own_session,
    guest_set_password,
)
from app.domains.guest.schemas import (
    GuestDisconnectRequest,
    GuestSetPasswordRequest,
)
from app.domains.guest.session_token import (
    issue_guest_session_token,
    require_guest_session_proof,
    verify_guest_session_token,
)
from tests.unit.test_guest import make_fixture

_PHONE = "+919811122233"
_MAC = "60:F4:45:0B:28:66"


class _Offer:
    async def offer_for(self, result):  # noqa: ANN001, ANN201
        return {"text": "Offers from us?", "text_version": "v1"}


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(request_id="t"), client=None)


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


class TestToken:
    def test_round_trip(self) -> None:
        g, s = uuid.uuid4(), uuid.uuid4()
        token = issue_guest_session_token(g, s)
        assert verify_guest_session_token(token, guest_id=g, session_id=s)

    def test_bound_to_both_ids(self) -> None:
        g, s = uuid.uuid4(), uuid.uuid4()
        token = issue_guest_session_token(g, s)
        assert not verify_guest_session_token(
            token, guest_id=g, session_id=uuid.uuid4()
        )
        assert not verify_guest_session_token(
            token, guest_id=uuid.uuid4(), session_id=s
        )

    def test_expires(self) -> None:
        g, s = uuid.uuid4(), uuid.uuid4()
        token = issue_guest_session_token(g, s, now=0)
        assert not verify_guest_session_token(token, guest_id=g, session_id=s)

    @pytest.mark.parametrize("bad", ["", "x", "a.b", "a.b.c", "!!!.???"])
    def test_garbage_is_refused_without_raising(self, bad: str) -> None:
        assert not verify_guest_session_token(
            bad, guest_id=uuid.uuid4(), session_id=uuid.uuid4()
        )

    def test_tampered_body_is_refused(self) -> None:
        g, s = uuid.uuid4(), uuid.uuid4()
        other = uuid.uuid4()
        body, sig = issue_guest_session_token(g, s).split(".")
        forged_body = issue_guest_session_token(g, other).split(".")[0]
        assert not verify_guest_session_token(
            f"{forged_body}.{sig}", guest_id=g, session_id=other
        )
        assert body != forged_body


class TestEnforcementModes:
    def _call(self, *, token: str | None, sensitive: bool) -> None:
        require_guest_session_proof(
            guest_id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            session_token=token,
            sensitive=sensitive,
        )

    def test_off_is_the_transition_default(self) -> None:
        """Cached portal bundles still send the bare pair."""
        assert get_settings().guest_session_token_enforcement == "off"
        self._call(token=None, sensitive=True)

    def test_sensitive_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            get_settings(), "guest_session_token_enforcement", "sensitive"
        )
        with pytest.raises(GuestSessionProofRequiredError):
            self._call(token=None, sensitive=True)
        self._call(token=None, sensitive=False)

    def test_a_bad_token_is_refused_once_enforcing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for mode in ("sensitive", "all"):
            monkeypatch.setattr(get_settings(), "guest_session_token_enforcement", mode)
            with pytest.raises(GuestSessionProofRequiredError):
                self._call(token="forged.token", sensitive=False)

    def test_off_mode_treats_a_bad_or_expired_token_as_missing(self) -> None:
        """``off`` accepts the bare pair anyway, so refusing a token that fails
        to verify (most often an honest one past its TTL on a long session)
        would only lock real guests out, with no security gained."""
        assert get_settings().guest_session_token_enforcement == "off"
        self._call(token="forged.token", sensitive=True)
        g, sid = uuid.uuid4(), uuid.uuid4()
        expired = issue_guest_session_token(g, sid, now=0)
        require_guest_session_proof(
            guest_id=g, session_id=sid, session_token=expired, sensitive=True
        )

    def test_all_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(get_settings(), "guest_session_token_enforcement", "all")
        with pytest.raises(GuestSessionProofRequiredError):
            self._call(token=None, sensitive=False)


class TestLoginVersusResumePayload:
    async def test_a_login_carries_the_raw_identifier_and_a_token(self) -> None:
        fx = make_fixture()
        result = await _sign_in(fx)
        data = await _login_payload(result, _Offer(), fx.guest_service)
        assert data["identifier"] == _PHONE
        assert verify_guest_session_token(
            data["session_token"],
            guest_id=result.guest.id,
            session_id=result.session.id,
        )

    async def test_session_active_issues_no_token(self) -> None:
        """Anyone who knows a router id and a MAC can call it, so by default it
        returns a masked identifier and an opaque hotspot username."""
        fx = make_fixture()
        result = await _sign_in(fx)
        data = await _login_payload(result, _Offer(), fx.guest_service, resume=True)
        assert data["session_token"] is None
        assert data["identifier"] != _PHONE
        assert data["hotspot_username"].startswith("wr1-")


class TestSetPasswordNeedsTheToken:
    async def test_bare_ids_still_work_during_the_transition(self) -> None:
        fx = make_fixture()
        result = await _sign_in(fx)
        payload = GuestSetPasswordRequest(
            guest_id=result.guest.id,
            session_id=result.session.id,
            password="Correct-Horse-9-Battery",
        )
        await guest_set_password(_request(), payload, service=fx.guest_service)

    async def test_a_forged_token_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            get_settings(), "guest_session_token_enforcement", "sensitive"
        )
        fx = make_fixture()
        result = await _sign_in(fx)
        payload = GuestSetPasswordRequest(
            guest_id=result.guest.id,
            session_id=result.session.id,
            password="Correct-Horse-9-Battery",
            session_token=issue_guest_session_token(result.guest.id, uuid.uuid4()),
        )
        with pytest.raises(GuestSessionProofRequiredError):
            await guest_set_password(_request(), payload, service=fx.guest_service)

    async def test_bare_ids_from_session_active_are_refused_once_enforced(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            get_settings(), "guest_session_token_enforcement", "sensitive"
        )
        fx = make_fixture()
        result = await _sign_in(fx)
        payload = GuestSetPasswordRequest(
            guest_id=result.guest.id,
            session_id=result.session.id,
            password="Correct-Horse-9-Battery",
        )
        with pytest.raises(GuestSessionProofRequiredError):
            await guest_set_password(_request(), payload, service=fx.guest_service)
        guest = await fx.guest_service.repository.get_guest_by_id(result.guest.id)
        assert not guest.hashed_password

    async def test_the_login_token_is_accepted(self) -> None:
        fx = make_fixture()
        result = await _sign_in(fx)
        data = await _login_payload(result, _Offer(), fx.guest_service)
        payload = GuestSetPasswordRequest(
            guest_id=result.guest.id,
            session_id=result.session.id,
            password="Correct-Horse-9-Battery",
            session_token=data["session_token"],
        )
        await guest_set_password(_request(), payload, service=fx.guest_service)
        guest = await fx.guest_service.repository.get_guest_by_id(result.guest.id)
        assert guest.hashed_password


class TestDisconnectInAllMode:
    async def test_refused_without_a_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(get_settings(), "guest_session_token_enforcement", "all")
        fx = make_fixture()
        result = await _sign_in(fx)
        payload = GuestDisconnectRequest(
            guest_id=result.guest.id, session_id=result.session.id
        )
        with pytest.raises(GuestSessionProofRequiredError):
            await guest_disconnect_own_session(
                _request(), payload, service=fx.guest_service
            )
