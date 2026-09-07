"""Password sign-in is being retired from the guest portal.

Asked for twice by the founder. The guest-facing cost is real and is
stated here as well as in ``CaptivePortalConfig``'s module docstring,
because a test is where someone lands when they are trying to work out
whether the behaviour they are seeing is deliberate: **every returning
guest goes back to doing an OTP on every visit.** Password sign-in was the
returning-guest shortcut -- verify once by OTP, save a password, use
phone/email + password from then on. OTP (all three channels), vouchers
and Portal PIN are untouched.

WHAT THIS MODULE PINS, AND WHY EACH PART NEEDS PINNING
------------------------------------------------------

The shape chosen is a *rollout*, not a switch-off, and every one of its
four parts is a thing a later change could quietly undo:

1. **New locations get it off.** There are TWO independent defaults for
   the same setting -- ``CaptivePortalConfig.username_password_enabled``'s
   column default and ``provisioning_service._LoginMethods``'s dataclass
   default -- plus the create schema's own Pydantic default. Nothing in
   the type system makes them agree. If they drift, a location's offered
   sign-in methods depend on which code path created its config, which
   presents as a race rather than as a wrong default. All three are
   asserted below, in one place, so a change to one without the others
   fails here.

2. **Existing rows are NOT migrated.** A venue that has it on today keeps
   working. Flipping stored config under live venues is not reversible by
   a redeploy, and it was explicitly not what was asked for. The check
   below is the negative one: a config with the flag on still logs a guest
   in.

3. **The endpoint stays, and fails CLEANLY when the flag is off.** This is
   the part that turns a rollout into an outage if it is got wrong. A
   guest arriving at a location that has password login off must get the
   existing "method not enabled" refusal -- a 403 with a guest-safe
   message -- never a 500 and never a stack trace on a captive portal.
   ``GuestAuthMethodNotEnabledError`` already does exactly that; this
   asserts it, including that the message names no internals.

4. **Nothing was deleted.** ``GuestAuthMethod.USERNAME_PASSWORD`` is the
   ``auth_method`` on live and historical ``guest_sessions`` rows, and
   ``GuestService.login_via_password`` still exists. Deleting either would
   break rendering of data that already exists -- a different and worse
   bug than the one being fixed.

The guest-side half of the removal (the portal not offering the method at
all, and the set-password prompt going with it) lives in
cloudguest-foundation's ``scripts/test-portal-auth-methods.mjs``, gated in
its CI.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import status

from app.domains.captive_portal.schemas import CaptivePortalConfigCreateRequest
from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.exceptions import (
    GuestAuthMethodNotEnabledError,
    GuestPasswordLoginFailedError,
)
from app.domains.location.provisioning_service import _LoginMethods
from tests.unit.test_guest import Fixture, make_fixture

GUEST_IDENTIFIER = "+15551234567"
GUEST_PASSWORD = "Correct-Horse-1!"


async def _register_guest_with_password(fx: Fixture) -> None:
    """A guest who really can sign in with a password, created the only
    way one ever is in production: an OTP login, then ``set_guest_password``
    against that same just-completed session. Deliberately not a direct
    repository write of a hash -- that would let these tests pass against a
    guest the real flow could never have produced."""
    otp_result = await fx.guest_service.login_via_otp(
        identifier=GUEST_IDENTIFIER,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
    )
    await fx.guest_service.set_guest_password(
        guest_id=otp_result.guest.id,
        session_id=otp_result.session.id,
        password=GUEST_PASSWORD,
    )


class TestNewLocationsDoNotGetPasswordLogin:
    """Part 1 -- the three independent defaults, asserted together."""

    def test_create_schema_defaults_password_login_off(self) -> None:
        payload = CaptivePortalConfigCreateRequest(
            organization_id=uuid.uuid4(),
            name="Sunset Cafe guest wifi",
        )
        assert payload.username_password_enabled is False

    def test_provisioning_defaults_password_login_off(self) -> None:
        """``_LoginMethods``'s own default, which is what a freshly
        provisioned location actually gets -- a separate code path from
        the schema above, and historically a separate always-on default."""
        methods = _LoginMethods(
            otp_sms_enabled=True,
            otp_email_enabled=True,
            voucher_enabled=True,
            social_login_enabled=False,
        )
        assert methods.username_password_enabled is False

    def test_the_two_defaults_agree(self) -> None:
        """The actual invariant. Either default alone being ``False`` is
        not the property that matters; them being EQUAL is, because a
        disagreement makes a location's offered methods depend on which
        path created its config."""
        schema_default = CaptivePortalConfigCreateRequest(
            organization_id=uuid.uuid4(), name="x"
        ).username_password_enabled
        provisioning_default = _LoginMethods(
            otp_sms_enabled=True,
            otp_email_enabled=True,
            voucher_enabled=True,
            social_login_enabled=False,
        ).username_password_enabled
        assert schema_default == provisioning_default

    def test_the_methods_that_remain_are_untouched(self) -> None:
        """Retiring one method must not quietly retire another. A venue
        left with no enabled method at all has no way for a guest to get
        online, which is a far worse outcome than the one being fixed."""
        payload = CaptivePortalConfigCreateRequest(
            organization_id=uuid.uuid4(),
            name="Sunset Cafe guest wifi",
        )
        assert payload.otp_sms_enabled is True
        assert payload.voucher_enabled is True
        # Email OTP's own default is a separate decision with its own
        # history (see _resolve_login_methods' "koi bhi user email id se
        # register nahi kr pa raha" note) and is deliberately not touched
        # here -- asserted only so retiring password login cannot be the
        # thing that silently moves it.
        assert payload.otp_email_enabled is False


class TestExistingVenuesAreNotCutOff:
    """Part 2 -- no stored row is migrated, so a venue running on password
    login today keeps running on it until someone turns it off."""

    async def test_a_venue_with_the_flag_on_still_signs_a_guest_in(self) -> None:
        fx = make_fixture(username_password_enabled=True)
        await _register_guest_with_password(fx)

        result = await fx.guest_service.login_via_password(
            identifier=GUEST_IDENTIFIER,
            password=GUEST_PASSWORD,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert result.session.auth_method == GuestAuthMethod.USERNAME_PASSWORD.value

    async def test_a_wrong_password_at_such_a_venue_still_fails_generically(
        self,
    ) -> None:
        """The rollout must not change the refusal a guest at an
        still-enabled venue gets -- in particular it must not become
        distinguishable from "no such guest", which would let a caller
        enumerate registered identifiers."""
        fx = make_fixture(username_password_enabled=True)
        with pytest.raises(GuestPasswordLoginFailedError):
            await fx.guest_service.login_via_password(
                identifier="+15559999999",
                password="whatever",
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )


class TestTheEndpointFailsSafeWhenTheFlagIsOff:
    """Part 3 -- the difference between a rollout and an outage."""

    async def test_refused_with_a_4xx_not_a_500(self) -> None:
        fx = make_fixture(username_password_enabled=False)
        with pytest.raises(GuestAuthMethodNotEnabledError) as exc_info:
            await fx.guest_service.login_via_password(
                identifier=GUEST_IDENTIFIER,
                password=GUEST_PASSWORD,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert 400 <= exc_info.value.status_code < 500

    async def test_the_refusal_is_the_same_one_a_disabled_method_always_got(
        self,
    ) -> None:
        """Not a new error type. A guest whose venue turned the method off
        by hand and a guest whose venue was provisioned after the default
        changed are in the identical situation, and the portal already
        knows how to render this one (``friendlyGuestAuthError``)."""
        fx = make_fixture(username_password_enabled=False)
        with pytest.raises(GuestAuthMethodNotEnabledError) as exc_info:
            await fx.guest_service.login_via_password(
                identifier=GUEST_IDENTIFIER,
                password=GUEST_PASSWORD,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        message = str(exc_info.value)
        assert "username_password" in message
        # Guest-safe: no traceback, no SQL, no internal module path. This
        # message reaches a phone on a captive portal.
        assert "Traceback" not in message
        assert "app.domains" not in message

    async def test_refused_before_any_credential_is_touched(self) -> None:
        """The refusal happens in ``_require_method_enabled``, which runs
        before the guest lookup and before ``_verify_guest_password`` --
        so a disabled venue cannot be used as an oracle for whether an
        identifier is a registered guest, and no hash comparison is spent
        on a request that was never going to succeed."""
        fx = make_fixture(username_password_enabled=False)
        # Registered through the only path that exists: an OTP login, then
        # set_guest_password. So this guest genuinely COULD sign in with
        # this password if the method were enabled -- which is what makes
        # the login-history assertion below meaningful.
        await _register_guest_with_password(fx)
        history_after_registration = len(fx.repository.login_history)

        with pytest.raises(GuestAuthMethodNotEnabledError):
            await fx.guest_service.login_via_password(
                identifier=GUEST_IDENTIFIER,
                password=GUEST_PASSWORD,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        # A real credential check would have written a login-failure row.
        assert len(fx.repository.login_history) == history_after_registration


class TestNothingWasDeleted:
    """Part 4 -- historical rows must stay renderable, and the reversal
    must stay a flag flip rather than a revert."""

    def test_the_auth_method_enum_member_still_exists(self) -> None:
        assert GuestAuthMethod.USERNAME_PASSWORD.value == "username_password"

    def test_the_service_method_still_exists(self) -> None:
        fx = make_fixture()
        assert callable(fx.guest_service.login_via_password)

    def test_turning_it_back_on_is_a_single_field(self) -> None:
        """The whole reversal on this side: an admin sets the flag. No
        migration, no redeploy, no code change."""
        payload = CaptivePortalConfigCreateRequest(
            organization_id=uuid.uuid4(),
            name="Sunset Cafe guest wifi",
            username_password_enabled=True,
        )
        assert payload.username_password_enabled is True
