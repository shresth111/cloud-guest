"""Email required at sign-in (``require_guest_email``, migration 0148), the
known-detail bits the post-connect card reads (``has_name``/``has_email``),
and the post-login sequence column (``post_login_sequence``).

The email twin rides the name gate from #353 (``test_require_guest_name.py``)
exactly: the OTP login still issues the session, the login response names
the missing detail, every network-opening step refuses the session until
``POST /guest/sign-in-details`` stores it, and only OTP sessions are held.
"""

from __future__ import annotations

import uuid

import pytest

from app.domains.captive_portal.exceptions import InvalidPostLoginSequenceError
from app.domains.captive_portal.validators import validate_post_login_sequence
from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.exceptions import (
    GuestEmailInvalidError,
    GuestEmailRequiredError,
    GuestNameRequiredError,
)
from app.domains.guest.router import _login_response
from app.domains.guest.validators import (
    guest_has_email_on_file,
    normalize_guest_email,
    session_missing_required_details,
)

from .test_guest import Fixture, make_fixture
from .test_require_guest_name import MAC, PHONE, _authorized_macs, _nas, _otp_login

EMAIL = "asha@example.com"


async def _email_otp_login(fx: Fixture, *, identifier: str = EMAIL):
    return await fx.guest_service.login_via_otp(
        identifier=identifier,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_EMAIL,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=MAC,
    )


def _enable_email_otp(fx: Fixture) -> None:
    for config in fx.captive_portal_service.configs_by_org.values():
        config.otp_email_enabled = True


class TestTheEmailPredicate:
    def _session(self, method: str):  # noqa: ANN202
        return type("S", (), {"auth_method": method})()

    def _guest(self, *, name=None, email=None, identifier="+15551234567"):  # noqa: ANN001, ANN202
        return type(
            "G", (), {"display_name": name, "email": email, "identifier": identifier}
        )()

    def test_missing_email_is_reported_after_the_name(self) -> None:
        assert session_missing_required_details(
            session=self._session("otp_sms"),
            guest=self._guest(),
            require_guest_name=True,
            require_guest_email=True,
        ) == ("name", "email")

    def test_email_identifier_satisfies_the_email(self) -> None:
        guest = self._guest(identifier="asha@example.com")
        assert guest_has_email_on_file(guest)
        assert (
            session_missing_required_details(
                session=self._session("otp_email"),
                guest=guest,
                require_guest_name=False,
                require_guest_email=True,
            )
            == ()
        )

    @pytest.mark.parametrize("method", ["voucher", "username_password", "pin"])
    def test_non_otp_sessions_are_never_held(self, method: str) -> None:
        assert (
            session_missing_required_details(
                session=self._session(method),
                guest=self._guest(),
                require_guest_name=True,
                require_guest_email=True,
            )
            == ()
        )

    def test_off_means_off(self) -> None:
        assert (
            session_missing_required_details(
                session=self._session("otp_sms"),
                guest=self._guest(),
                require_guest_name=False,
                require_guest_email=False,
            )
            == ()
        )


class TestNormalizeEmail:
    def test_trims_and_lowercases(self) -> None:
        assert normalize_guest_email("  Asha@Example.COM ") == "asha@example.com"

    @pytest.mark.parametrize("raw", [None, "", "   ", "asha@gmail", "a b@c.de"])
    def test_rejects_with_the_stable_code(self, raw: str | None) -> None:
        with pytest.raises(GuestEmailInvalidError) as exc:
            normalize_guest_email(raw)
        assert exc.value.data == {"code": "guest_email_invalid"}


class TestEmailRequired:
    async def test_login_reports_email_required_and_known_bits(self) -> None:
        fx = make_fixture(require_guest_email=True)
        result = await _otp_login(fx)
        assert result.email_required is True
        assert result.name_required is False
        response = _login_response(result)
        assert response.email_required is True
        assert response.has_email is False
        assert result.session.status == "active"

    async def test_every_gate_refuses_until_the_email_is_stored(self) -> None:
        fx = make_fixture(require_guest_email=True)
        login = await _otp_login(fx)
        nas = await _nas(fx)

        assert (
            await fx.radius_service.authorize(nas_client=nas, username=PHONE)
        ).authorized is False
        assert await _authorized_macs(fx) == []
        with pytest.raises(GuestEmailRequiredError) as exc:
            await fx.guest_service.require_session_name(session_id=login.session.id)
        assert exc.value.status_code == 403
        assert exc.value.data == {"code": "guest_email_required"}

        guest = await fx.guest_service.submit_sign_in_details(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name=None,
            email=" Asha@Example.com ",
        )
        assert guest.email == "asha@example.com"
        assert (
            await fx.radius_service.authorize(nas_client=nas, username=PHONE)
        ).authorized is True
        assert await _authorized_macs(fx) == ["AA:BB:CC:DD:EE:FF"]
        await fx.guest_service.require_session_name(session_id=login.session.id)

    async def test_name_error_wins_when_both_are_missing(self) -> None:
        fx = make_fixture(require_guest_name=True, require_guest_email=True)
        login = await _otp_login(fx)
        assert login.name_required and login.email_required
        with pytest.raises(GuestNameRequiredError):
            await fx.guest_service.require_session_name(session_id=login.session.id)
        await fx.guest_service.submit_sign_in_details(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name="Asha",
            email="asha@example.com",
        )
        await fx.guest_service.require_session_name(session_id=login.session.id)

    async def test_bad_email_stores_nothing_not_even_the_name(self) -> None:
        fx = make_fixture(require_guest_name=True, require_guest_email=True)
        login = await _otp_login(fx)
        with pytest.raises(GuestEmailInvalidError):
            await fx.guest_service.submit_sign_in_details(
                guest_id=login.guest.id,
                session_id=login.session.id,
                display_name="Asha",
                email="asha@gmail",
            )
        stored = await fx.repository.get_guest_by_id(login.guest.id)
        assert stored is not None
        assert stored.display_name is None and stored.email is None

    async def test_email_otp_guest_is_not_asked_and_the_email_is_stored(self) -> None:
        fx = make_fixture(require_guest_email=True)
        _enable_email_otp(fx)
        login = await _email_otp_login(fx)
        assert login.email_required is False
        assert login.guest.email == EMAIL
        assert _login_response(login).has_email is True

    async def test_returning_guest_with_details_reports_has_name(self) -> None:
        fx = make_fixture(require_guest_name=True)
        first = await _otp_login(fx)
        await fx.guest_service.submit_sign_in_details(
            guest_id=first.guest.id,
            session_id=first.session.id,
            display_name="Asha",
            email=None,
        )
        again = await _otp_login(fx)
        assert again.name_required is False
        assert _login_response(again).has_name is True

    async def test_email_is_refused_where_the_venue_does_not_collect_it(self) -> None:
        from app.domains.guest.exceptions import GuestProfileFieldNotCollectedError

        fx = make_fixture(collect_guest_email=False)
        login = await _otp_login(fx)
        with pytest.raises(GuestProfileFieldNotCollectedError):
            await fx.guest_service.submit_sign_in_details(
                guest_id=login.guest.id,
                session_id=login.session.id,
                display_name=None,
                email="asha@example.com",
            )

    async def test_off_by_default_is_todays_behaviour(self) -> None:
        fx = make_fixture()
        login = await _otp_login(fx)
        assert login.email_required is False
        assert login.name_required is False

    async def test_reload_reports_the_email_bit(self) -> None:
        fx = make_fixture(require_guest_email=True)
        await _otp_login(fx)
        found = await fx.guest_service.get_active_session_for_device(
            router_id=fx.router.id, device_mac=MAC
        )
        assert found is not None and found.email_required is True


class TestPostLoginSequenceValidation:
    def test_none_is_legal_and_means_derived(self) -> None:
        assert (
            validate_post_login_sequence(None, post_login_html=None, redirect_url=None)
            is None
        )

    def test_a_full_sequence_round_trips_and_drops_unknown_keys(self) -> None:
        stored = validate_post_login_sequence(
            {"steps": ["survey", "offer", "page"], "finish": "redirect", "x": 1},
            post_login_html="<p>hi</p>",
            redirect_url="https://example.com",
        )
        assert stored == {"steps": ["survey", "offer", "page"], "finish": "redirect"}

    @pytest.mark.parametrize(
        ("value", "html", "url"),
        [
            ({"steps": ["coffee"]}, None, None),
            ({"steps": ["survey", "survey"]}, None, None),
            ({"steps": [], "finish": "elsewhere"}, None, None),
            ({"steps": ["page"]}, None, None),
            ({"steps": ["page"]}, "   ", None),
            ({"steps": [], "finish": "redirect"}, None, ""),
            ("survey", None, None),
        ],
    )
    def test_refusals(self, value: object, html: str | None, url: str | None) -> None:
        with pytest.raises(InvalidPostLoginSequenceError) as exc:
            validate_post_login_sequence(value, post_login_html=html, redirect_url=url)
        assert exc.value.status_code == 400


class TestPostLoginSequencePersistence:
    async def _update(self, fx, config, data):  # noqa: ANN001, ANN202
        return await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data=data,
        )

    async def test_update_stores_and_guards_the_sequence(self) -> None:
        from .test_captive_portal import _create_config, make_service

        fx = make_service()
        config = await _create_config(fx)
        assert config.post_login_sequence is None
        updated = await self._update(
            fx,
            config,
            {
                "redirect_url": "https://example.com/welcome",
                "post_login_sequence": {
                    "steps": ["survey", "offer"],
                    "finish": "redirect",
                },
            },
        )
        assert updated.post_login_sequence == {
            "steps": ["survey", "offer"],
            "finish": "redirect",
        }
        # Clearing the URL while the stored sequence still finishes on a
        # redirect is refused against the MERGED values.
        with pytest.raises(InvalidPostLoginSequenceError):
            await self._update(fx, updated, {"redirect_url": None})
        # A page step needs a page that survives sanitising.
        with pytest.raises(InvalidPostLoginSequenceError):
            await self._update(
                fx,
                updated,
                {
                    "post_login_html": "<script>x()</script>",
                    "post_login_sequence": {"steps": ["page"]},
                },
            )
        cleared = await self._update(
            fx,
            updated,
            {"redirect_url": None, "post_login_sequence": {"steps": ["offer"]}},
        )
        assert cleared.post_login_sequence == {
            "steps": ["offer"],
            "finish": "connected",
        }

    async def test_require_email_forces_collect_email(self) -> None:
        from .test_captive_portal import _create_config, make_service

        fx = make_service()
        config = await _create_config(fx)
        updated = await self._update(
            fx, config, {"require_guest_email": True, "collect_guest_email": False}
        )
        assert updated.require_guest_email is True
        assert updated.collect_guest_email is True


class TestKnownDetailBits:
    async def test_profile_declined_is_reported(self) -> None:
        fx = make_fixture()
        login = await _otp_login(fx)
        assert _login_response(login).profile_declined is False
        await fx.guest_service.update_guest_profile(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name=None,
            email=None,
            declined=True,
        )
        again = await _otp_login(fx)
        response = _login_response(again)
        assert response.profile_declined is True
        assert response.has_name is False and response.has_email is False
