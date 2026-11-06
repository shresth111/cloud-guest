"""Email identifiers are case-insensitive at the captive portal; passwords are not.

The defect this pins: ``normalize_identifier`` only stripped whitespace and
every lookup was exact, so ``Guest@Gmail.com`` and ``guest@gmail.com`` were
two different people. Mobile keyboards capitalise the first letter of a plain
text field (the portal's "Mobile or email" username field is one), so the same
guest routinely arrives in both spellings:

* email-OTP once as ``Guest@Gmail.com``, set a password, then password login
  as ``guest@gmail.com`` -> "wrong password" for a correct password;
* a second email-OTP login in the other case -> a second ``Guest`` row (split
  visit history, double-counted guests, a fresh device/concurrency budget);
* a guest blocked as ``guest@x.com`` signs in again as ``Guest@x.com`` -> a
  new, unblocked row;
* OTP requests in N case variants -> N separate rate-limit windows.

The rule now: an identifier containing ``@`` is ``strip().lower()``-ed at the
one normalizer every path already calls, and lookups compare
``lower(identifier)`` so rows written before the fix (stored as typed) are
still found. Phone numbers and other non-email identifiers are untouched.
Passwords and PINs are never case-folded.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.dialects import postgresql

from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.exceptions import (
    GuestBlockedError,
    GuestPasswordLoginFailedError,
)
from app.domains.guest.repository import guest_identifier_clause
from app.domains.guest.validators import normalize_identifier
from app.domains.guest_access.validators import (
    canonicalize_rule_identifier,
    identifier_match_terms,
    identifiers_match,
)
from app.domains.otp.constants import OtpChannel, OtpPurpose
from app.domains.otp.exceptions import OtpRequestRateLimitExceededError
from tests.unit.test_guest import Fixture, make_fixture
from tests.unit.test_otp import _extract_code, make_service

ORG = uuid.UUID("2f1c9d3e-0000-4000-8000-000000000002")


def _email_fixture() -> Fixture:
    fx = make_fixture()
    fx.captive_portal_service.register(
        fx.organization_id,
        otp_email_enabled=True,
        username_password_enabled=True,
        pin_login_enabled=True,
    )
    return fx


async def _otp_email_login(fx: Fixture, identifier: str, **kwargs: object):
    return await fx.guest_service.login_via_otp(
        identifier=identifier,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_EMAIL,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        **kwargs,
    )


# ============================================================================
# The normalizer
# ============================================================================


class TestNormalizeIdentifier:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Guest@Gmail.com", "guest@gmail.com"),
            ("  GUEST@EXAMPLE.COM \n", "guest@example.com"),
            ("guest@example.com", "guest@example.com"),
        ],
    )
    def test_emails_are_stripped_and_lowercased(self, raw: str, expected: str) -> None:
        assert normalize_identifier(raw) == expected

    @pytest.mark.parametrize(
        "raw", ["+919876543210", "9876543210", "mac:AA:BB:CC:DD:EE:FF", "Room12"]
    )
    def test_non_email_identifiers_keep_their_case(self, raw: str) -> None:
        assert normalize_identifier(f" {raw} ") == raw

    def test_rule_identifiers_follow_the_same_rule(self) -> None:
        assert canonicalize_rule_identifier(" Guest@Gmail.com ") == "guest@gmail.com"


# ============================================================================
# The lookup reaches rows written before the fix (stored as typed)
# ============================================================================


def _rendered(identifier: str) -> tuple[str, list[object]]:
    clause = guest_identifier_clause(organization_id=ORG, identifier=identifier)
    compiled = clause.compile(dialect=postgresql.dialect())
    values: list[object] = []
    for value in compiled.params.values():
        if isinstance(value, list | tuple):
            values.extend(value)
        else:
            values.append(value)
    return str(compiled), values


class TestEmailLookupIsCaseInsensitive:
    def test_guest_lookup_compares_lowercased_column(self) -> None:
        sql, params = _rendered("Guest@Gmail.com")
        assert "lower(guests.identifier)" in sql
        assert "guest@gmail.com" in params
        assert "Guest@Gmail.com" not in params

    def test_phone_lookup_is_not_lowercased(self) -> None:
        """No reason to defeat the unique index for digits."""
        sql, _params = _rendered("+919876543210")
        assert "lower(" not in sql

    def test_match_terms_flag_emails_for_casefolding(self) -> None:
        terms = identifier_match_terms("Guest@Gmail.com")
        assert terms.exact == ("guest@gmail.com",)
        assert terms.casefold is True
        assert identifier_match_terms("+919876543210").casefold is False

    @pytest.mark.parametrize(
        "stored", ["Guest@Gmail.com", "guest@gmail.com", "GUEST@GMAIL.COM"]
    )
    def test_python_mirror_matches_any_stored_case(self, stored: str) -> None:
        assert identifiers_match(stored, "gUeSt@gmail.com") is True

    def test_python_mirror_still_rejects_a_different_address(self) -> None:
        assert identifiers_match("guest@gmail.com", "guest2@gmail.com") is False


# ============================================================================
# Service-level scenarios
# ============================================================================


class TestEmailOtpLoginIdentity:
    async def test_case_variants_resolve_to_one_guest(self) -> None:
        fx = _email_fixture()
        first = await _otp_email_login(fx, "Guest@Gmail.com")
        await fx.guest_service.disconnect_session(session_id=first.session.id)
        second = await _otp_email_login(fx, "guest@gmail.com")

        assert first.guest.identifier == "guest@gmail.com"
        assert second.is_new_guest is False
        assert second.guest.id == first.guest.id
        assert len(fx.repository.guests) == 1

    async def test_a_legacy_mixed_case_row_is_still_found(self) -> None:
        """A row stored as typed before the fix must not be orphaned."""
        fx = _email_fixture()
        first = await _otp_email_login(fx, "seed@example.com")
        await fx.guest_service.disconnect_session(session_id=first.session.id)
        first.guest.identifier = "Legacy.Guest@Example.com"  # pre-fix spelling

        again = await _otp_email_login(fx, "legacy.guest@example.com")
        assert again.is_new_guest is False
        assert again.guest.id == first.guest.id

    async def test_blocked_guest_cannot_evade_by_changing_case(self) -> None:
        fx = _email_fixture()
        first = await _otp_email_login(fx, "guest@x.com")
        await fx.guest_service.disconnect_session(session_id=first.session.id)
        first.guest.is_blocked = True

        with pytest.raises(GuestBlockedError):
            await _otp_email_login(fx, "Guest@X.com")
        assert len(fx.repository.guests) == 1


class TestPasswordLoginCase:
    async def _guest_with_password(self, fx: Fixture, identifier: str) -> None:
        result = await _otp_email_login(fx, identifier)
        await fx.guest_service.set_guest_password(
            guest_id=result.guest.id,
            session_id=result.session.id,
            password="Correct-Horse-1!",
        )
        await fx.guest_service.disconnect_session(session_id=result.session.id)

    async def _login(self, fx: Fixture, identifier: str, password: str):
        return await fx.guest_service.login_via_password(
            identifier=identifier,
            password=password,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )

    @pytest.mark.parametrize(
        ("signed_up_as", "logs_in_as"),
        [
            ("guest@gmail.com", "Guest@gmail.com"),  # iOS auto-capitalised
            ("Guest@Gmail.com", "guest@gmail.com"),
            ("guest@gmail.com", "  GUEST@GMAIL.COM  "),
        ],
    )
    async def test_username_case_does_not_matter(
        self, signed_up_as: str, logs_in_as: str
    ) -> None:
        fx = _email_fixture()
        await self._guest_with_password(fx, signed_up_as)
        result = await self._login(fx, logs_in_as, "Correct-Horse-1!")
        assert result.is_new_guest is False

    async def test_password_stays_case_sensitive(self) -> None:
        fx = _email_fixture()
        await self._guest_with_password(fx, "guest@gmail.com")
        with pytest.raises(GuestPasswordLoginFailedError):
            await self._login(fx, "guest@gmail.com", "correct-horse-1!")
        with pytest.raises(GuestPasswordLoginFailedError):
            await self._login(fx, "Guest@Gmail.com", "CORRECT-HORSE-1!")


class TestRadiusAuthorizeCase:
    async def test_mixed_case_user_name_authorizes_the_session(self) -> None:
        """The portal posts whatever the guest typed to the router's login
        form; the NAS forwards it as User-Name. It must resolve to the same
        guest the portal login just created."""
        fx = _email_fixture()
        await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(),
            router_id=fx.router.id,
            nas_identifier="nas-1",
            shared_secret="supersecret123",
        )
        await _otp_email_login(fx, "Guest@Gmail.com")
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="nas-1", shared_secret="supersecret123"
        )
        for user_name in ("Guest@Gmail.com", "guest@gmail.com", "GUEST@GMAIL.COM"):
            authz = await fx.radius_service.authorize(
                nas_client=nas_client, username=user_name
            )
            assert authz.authorized is True, user_name


# ============================================================================
# OTP request / verify / rate limit
# ============================================================================


class TestOtpEmailCase:
    async def test_request_and_verify_in_different_case_succeeds(self) -> None:
        fx = make_service()
        await fx.service.request_otp(
            identifier="Guest@Gmail.com",
            channel=OtpChannel.EMAIL,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        code = _extract_code(fx.email_provider.sent[0])
        verified = await fx.service.verify_otp(
            identifier="guest@gmail.com", code=code, purpose=OtpPurpose.GUEST_LOGIN
        )
        assert verified.identifier == "guest@gmail.com"

    async def test_code_is_sent_to_the_lowercased_address(self) -> None:
        fx = make_service()
        await fx.service.request_otp(
            identifier=" Guest@Gmail.com ",
            channel=OtpChannel.EMAIL,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=None,
            location_id=None,
        )
        assert fx.email_provider.sent[0][0] == "guest@gmail.com"

    async def test_case_variants_share_one_rate_limit_window(self) -> None:
        fx = make_service(max_requests_per_window=2)
        for variant in ("guest@gmail.com", "Guest@gmail.com"):
            await fx.service.request_otp(
                identifier=variant,
                channel=OtpChannel.EMAIL,
                purpose=OtpPurpose.GUEST_LOGIN,
                organization_id=None,
                location_id=None,
            )
        with pytest.raises(OtpRequestRateLimitExceededError):
            await fx.service.request_otp(
                identifier="GUEST@gmail.com",
                channel=OtpChannel.EMAIL,
                purpose=OtpPurpose.GUEST_LOGIN,
                organization_id=None,
                location_id=None,
            )
        assert len(fx.email_provider.sent) == 2
