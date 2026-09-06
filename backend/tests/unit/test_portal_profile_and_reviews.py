"""The post-connect asks: profile capture, the Google review link, the
private feedback card's dwell gate, and the consent version.

Everything under test here happens **after** the RADIUS session is
authorised and the NAS gate is open. That is not incidental -- it is the
property the whole design rests on, and ``TestNothingHereAffectsAccess``
asserts it rather than leaving it to review.

Same plain-``assert``/native-``async def`` style as ``test_guest.py`` and
``test_captive_portal.py``; the fakes are reused from those modules rather
than rebuilt, so a change to the real service signature breaks here too.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.domains.campaigns.constants import CampaignType
from app.domains.captive_portal.constants import (
    DEFAULT_FEEDBACK_DWELL_MINUTES,
    MIN_FEEDBACK_DWELL_MINUTES,
)
from app.domains.captive_portal.exceptions import (
    InvalidFeedbackDwellMinutesError,
    InvalidReviewUrlError,
)
from app.domains.captive_portal.validators import (
    compute_terms_version,
    validate_feedback_dwell_minutes,
    validate_review_url,
)
from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.exceptions import (
    GuestProfileFieldNotCollectedError,
    GuestProfileUpdateNotAuthorizedError,
    GuestReviewLinkOpenedNotAuthorizedError,
)
from app.domains.guest.models import Guest
from app.domains.guest.validators import (
    guest_has_opened_review_link,
    guest_has_profile,
)

from .test_captive_portal import _create_config, make_service
from .test_guest import Fixture as GuestFixture
from .test_guest import make_fixture

# ============================================================================
# has_profile -- the bit that lets the portal stop reading localStorage
# ============================================================================


def _guest(**overrides: object) -> Guest:
    fields: dict[str, object] = {
        "id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": None,
        "identifier": "+15551234567",
        "display_name": None,
        "email": None,
        "profile_prompt_declined_at": None,
    }
    fields.update(overrides)
    return Guest(**fields)


class TestGuestHasProfile:
    def test_false_for_a_guest_who_has_neither_given_nor_declined(self) -> None:
        assert guest_has_profile(_guest()) is False

    def test_true_once_a_name_is_on_file(self) -> None:
        assert guest_has_profile(_guest(display_name="Priya")) is True

    def test_true_once_an_email_is_on_file(self) -> None:
        assert guest_has_profile(_guest(email="priya@example.com")) is True

    def test_true_once_the_guest_has_declined(self) -> None:
        """The whole reason the column exists: a decline has to be a fact
        on the server, because ``localStorage`` throws inside Apple's
        Captive Network Assistant and a device-local record of a decline
        is no record at all there."""
        assert guest_has_profile(_guest(profile_prompt_declined_at=datetime.now(UTC)))

    def test_does_not_consult_visit_count_or_newness(self) -> None:
        """``is_new_guest`` is the wrong key and this is why.

        A venue that switches the ask on in October has, on day one, a
        guest base of thousands who are all ``is_new_guest == False`` and
        all have no name on file. Under the old gate not one of them could
        ever be asked. ``has_profile`` is false for exactly that guest, so
        they are asked once, then never again.
        """
        long_standing_guest = _guest(total_visit_count=47)
        assert guest_has_profile(long_standing_guest) is False


class TestHasProfileOnTheLoginResponse:
    async def test_login_response_carries_has_profile(self) -> None:
        from app.domains.guest.router import _login_response

        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert _login_response(result).has_profile is False

        await fx.guest_service.update_guest_profile(
            guest_id=result.guest.id,
            session_id=result.session.id,
            display_name="Priya",
            email=None,
        )
        assert _login_response(result).has_profile is True

    async def test_the_same_bit_reaches_the_active_session_response(self) -> None:
        """``GET /guest/session/active`` builds its payload with the same
        ``_login_response``, so the portal gets ``has_profile`` on the
        page-load check as well as on login -- which is the surface that
        matters, since the CNA re-lands guests on the session page as a
        brand-new document."""
        from app.domains.guest.router import _login_response

        fx = make_fixture()
        login = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="aa:bb:cc:dd:ee:ff",
        )
        await fx.guest_service.update_guest_profile(
            guest_id=login.guest.id,
            session_id=login.session.id,
            declined=True,
            display_name=None,
            email=None,
        )
        active = await fx.guest_service.get_active_session_for_device(
            router_id=fx.router.id, device_mac="aa:bb:cc:dd:ee:ff"
        )
        assert active is not None
        assert _login_response(active).has_profile is True


class TestDecline:
    async def _login(self, fx: GuestFixture):
        return await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )

    async def test_declining_records_a_timestamp(self) -> None:
        fx = make_fixture()
        login = await self._login(fx)
        updated = await fx.guest_service.update_guest_profile(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name=None,
            email=None,
            declined=True,
        )
        assert updated.profile_prompt_declined_at is not None
        assert updated.display_name is None
        assert updated.email is None

    async def test_a_second_decline_does_not_move_the_timestamp(self) -> None:
        """The column answers "when did this guest first refuse". A later
        "not now" overwriting it would silently change the answer."""
        fx = make_fixture()
        login = await self._login(fx)
        first = await fx.guest_service.update_guest_profile(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name=None,
            email=None,
            declined=True,
        )
        recorded = first.profile_prompt_declined_at
        second = await fx.guest_service.update_guest_profile(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name=None,
            email=None,
            declined=True,
        )
        assert second.profile_prompt_declined_at == recorded

    async def test_a_decline_is_allowed_even_when_the_venue_collects_nothing(
        self,
    ) -> None:
        """Refusing to record a refusal would be the wrong failure
        direction. A guest can always say no."""
        fx = make_fixture(collect_guest_name=False, collect_guest_email=False)
        login = await self._login(fx)
        updated = await fx.guest_service.update_guest_profile(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name=None,
            email=None,
            declined=True,
        )
        assert updated.profile_prompt_declined_at is not None

    async def test_a_decline_still_needs_a_real_session(self) -> None:
        """The escape hatch is not an authorisation hole -- the same
        proof-of-session check gates it."""
        fx = make_fixture()
        login = await self._login(fx)
        with pytest.raises(GuestProfileUpdateNotAuthorizedError):
            await fx.guest_service.update_guest_profile(
                guest_id=login.guest.id,
                session_id=uuid.uuid4(),
                display_name=None,
                email=None,
                declined=True,
            )


class TestVenueTogglesAreEnforcedOnTheServer:
    """"Off" has to mean off at the write path. A hidden field that still
    accepts a write is how a venue ends up holding data it never agreed to
    hold -- and the venue, not this platform, is the Data Fiduciary."""

    async def _login(self, fx: GuestFixture):
        return await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )

    async def test_name_is_rejected_when_the_venue_does_not_collect_names(
        self,
    ) -> None:
        fx = make_fixture(collect_guest_name=False)
        login = await self._login(fx)
        with pytest.raises(GuestProfileFieldNotCollectedError):
            await fx.guest_service.update_guest_profile(
                guest_id=login.guest.id,
                session_id=login.session.id,
                display_name="Priya",
                email=None,
            )
        stored = await fx.repository.get_guest_by_id(login.guest.id)
        assert stored.display_name is None

    async def test_email_is_rejected_when_the_venue_does_not_collect_emails(
        self,
    ) -> None:
        fx = make_fixture(collect_guest_email=False)
        login = await self._login(fx)
        with pytest.raises(GuestProfileFieldNotCollectedError):
            await fx.guest_service.update_guest_profile(
                guest_id=login.guest.id,
                session_id=login.session.id,
                display_name=None,
                email="priya@example.com",
            )
        stored = await fx.repository.get_guest_by_id(login.guest.id)
        assert stored.email is None

    async def test_each_flag_gates_only_its_own_field(self) -> None:
        """Name-only is a real configuration a salon would choose, and
        email-only is one a co-working space would. Neither may leak into
        the other."""
        fx = make_fixture(collect_guest_name=True, collect_guest_email=False)
        login = await self._login(fx)
        updated = await fx.guest_service.update_guest_profile(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name="Priya",
            email=None,
        )
        assert updated.display_name == "Priya"
        with pytest.raises(GuestProfileFieldNotCollectedError):
            await fx.guest_service.update_guest_profile(
                guest_id=login.guest.id,
                session_id=login.session.id,
                display_name=None,
                email="priya@example.com",
            )

    async def test_the_status_code_says_venue_setting_not_bad_session(self) -> None:
        """A 400, not the 403 an ineligible session raises. The two have
        completely different causes and whoever reads the log needs to be
        able to tell them apart."""
        fx = make_fixture(collect_guest_name=False)
        login = await self._login(fx)
        with pytest.raises(GuestProfileFieldNotCollectedError) as excinfo:
            await fx.guest_service.update_guest_profile(
                guest_id=login.guest.id,
                session_id=login.session.id,
                display_name="Priya",
                email=None,
            )
        assert excinfo.value.status_code == 400


class TestNothingHereAffectsAccess:
    """The load-bearing invariant, asserted rather than reviewed.

    Nothing on the profile path may change whether, how fast, or how long
    a guest is connected. It is what makes the ask lawful under DPDP (a
    service may not be conditioned on non-essential data) and it is what
    makes the "does this cost us connections" question answerable with
    "it cannot, structurally".
    """

    async def test_saving_a_profile_changes_no_session_field(self) -> None:
        fx = make_fixture()
        login = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        before = {
            "status": login.session.status,
            "started_at": login.session.started_at,
            "session_timeout_minutes": login.session.session_timeout_minutes,
            "data_limit_mb": login.session.data_limit_mb,
            "ended_at": login.session.ended_at,
        }
        await fx.guest_service.update_guest_profile(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name="Priya",
            email="priya@example.com",
        )
        session = await fx.repository.get_session_by_id(login.session.id)
        after = {
            "status": session.status,
            "started_at": session.started_at,
            "session_timeout_minutes": session.session_timeout_minutes,
            "data_limit_mb": session.data_limit_mb,
            "ended_at": session.ended_at,
        }
        assert after == before

    async def test_declining_changes_no_session_field(self) -> None:
        fx = make_fixture()
        login = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.guest_service.update_guest_profile(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name=None,
            email=None,
            declined=True,
        )
        session = await fx.repository.get_session_by_id(login.session.id)
        assert session.status == login.session.status
        assert session.ended_at is None
        assert session.session_timeout_minutes == login.session.session_timeout_minutes

    async def test_opening_the_review_link_changes_no_session_field(self) -> None:
        """The one that would be worst to get wrong. Free WiFi is a "free
        good and/or service" under Google's Rating Manipulation policy, so
        nothing about the connection may be conditioned on a review in
        either direction -- not sped up for tapping, not cut short for
        not."""
        fx = make_fixture()
        login = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        before = {
            "status": login.session.status,
            "started_at": login.session.started_at,
            "session_timeout_minutes": login.session.session_timeout_minutes,
            "data_limit_mb": login.session.data_limit_mb,
            "ended_at": login.session.ended_at,
        }
        await fx.guest_service.record_review_link_opened(
            guest_id=login.guest.id, session_id=login.session.id
        )
        session = await fx.repository.get_session_by_id(login.session.id)
        after = {
            "status": session.status,
            "started_at": session.started_at,
            "session_timeout_minutes": session.session_timeout_minutes,
            "data_limit_mb": session.data_limit_mb,
            "ended_at": session.ended_at,
        }
        assert after == before


# ============================================================================
# review_url
# ============================================================================


class TestReviewUrlValidation:
    def test_none_and_blank_pass(self) -> None:
        """Clearing the link is always legal, and no link is the normal
        state -- it is what the guest-side card reads as "render
        nothing"."""
        validate_review_url(None)
        validate_review_url("")
        validate_review_url("   ")

    @pytest.mark.parametrize(
        "url",
        [
            "https://g.page/r/CQ12345abcdef/review",
            "https://search.google.com/local/writereview?placeid=ChIJabc",
            "https://maps.app.goo.gl/abcdefg",
            "https://www.google.co.in/maps/place/Cafe",
            "https://google.com/anything",
        ],
    )
    def test_accepts_the_shapes_in_circulation(self, url: str) -> None:
        validate_review_url(url)

    def test_rejects_http(self) -> None:
        with pytest.raises(InvalidReviewUrlError):
            validate_review_url("http://g.page/r/CQ12345abcdef/review")

    def test_rejects_a_non_google_host(self) -> None:
        with pytest.raises(InvalidReviewUrlError):
            validate_review_url("https://example.com/reviews")

    def test_rejects_a_lookalike_host(self) -> None:
        """Suffix matching is anchored on a dot, so ``notgoogle.com`` does
        not slip through as a subdomain of ``google.com``."""
        with pytest.raises(InvalidReviewUrlError):
            validate_review_url("https://notgoogle.com/review")

    def test_rejects_a_url_with_no_host(self) -> None:
        with pytest.raises(InvalidReviewUrlError):
            validate_review_url("https:///review")

    def test_does_not_check_the_path(self) -> None:
        """Deliberate. ``g.page/r/.../review`` and
        ``search.google.com/local/writereview`` are not documented stable
        contracts, so a path check would start rejecting real links the
        next time one changes."""
        validate_review_url("https://g.page/something-that-is-not-a-review-path")

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.com\\@google.com/",
            "https://google.com\\@evil.com/",
            "https://google.com\\.evil.com/review",
        ],
    )
    def test_rejects_a_backslash(self, url: str) -> None:
        """The parser differential, and the one bypass this allowlist
        actually had.

        WHATWG treats ``\\`` as ``/`` inside the authority of a special
        scheme, so a browser resolves ``https://evil.com\\@google.com/`` to
        host ``evil.com``. ``urlsplit`` ends the netloc only at ``/?#``,
        reads the trailing ``@google.com`` as a host preceded by userinfo,
        and returns ``hostname == "google.com"`` -- which the suffix check
        then approves. The value that passed validation and the value the
        guest's browser resolves are different hosts.

        ``review_url`` is operator-supplied and ends up as a link a guest
        taps from the portal, so that is an open redirect, not a
        curiosity.
        """
        with pytest.raises(InvalidReviewUrlError):
            validate_review_url(url)

    def test_rejects_userinfo(self) -> None:
        """``https://google.com@evil.com`` reads as a Google link to the
        person pasting it and to anyone auditing the stored value."""
        with pytest.raises(InvalidReviewUrlError):
            validate_review_url("https://google.com@evil.com/review")

    @pytest.mark.parametrize(
        "url",
        [
            "https://[::1/review",
            "https://google.com／@evil.com/review",
        ],
    )
    def test_unparseable_input_is_a_400_not_a_500(self, url: str) -> None:
        """``urlsplit`` raises ``ValueError`` on an unclosed IPv6 literal
        and on a netloc that NFKC-normalises into a delimiter. Both are
        things an operator can paste into a dashboard field; an uncaught
        ValueError there is a 500 on a config save."""
        with pytest.raises(InvalidReviewUrlError):
            validate_review_url(url)

    def test_rejects_a_trailing_dot_fqdn(self) -> None:
        """``google.com.`` is the same host to a resolver and a different
        string to ``endswith``. It fails closed, which is the right
        direction -- recorded so that a later "helpful" normalisation does
        not flip it to failing open."""
        with pytest.raises(InvalidReviewUrlError):
            validate_review_url("https://google.com./review")

    def test_rejects_a_google_prefixed_domain(self) -> None:
        """``google.com.evil.com`` -- the suffix has to be at the end, not
        anywhere in the host."""
        with pytest.raises(InvalidReviewUrlError):
            validate_review_url("https://google.com.evil.com/review")

    def test_rejects_a_unicode_lookalike(self) -> None:
        """A fullwidth ``ｇ``. The host is compared as a string, so a
        homograph is simply not the allowlisted host."""
        with pytest.raises(InvalidReviewUrlError):
            validate_review_url("https://gooｇle.com/review")


class TestReviewUrlOnTheConfig:
    async def test_defaults_are_all_off(self) -> None:
        """Every post-connect ask starts off, including for a brand-new
        config. See migration 0114 for why that is not the usual
        "unchanged means unchanged" default."""
        fx = make_service()
        config = await _create_config(fx)
        assert config.collect_guest_name is False
        assert config.collect_guest_email is False
        assert config.review_card_enabled is False
        assert config.review_url is None

    async def test_create_rejects_a_bad_link(self) -> None:
        fx = make_service()
        with pytest.raises(InvalidReviewUrlError):
            await _create_config(fx, review_url="https://example.com/review")

    async def test_update_rejects_a_bad_link(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        with pytest.raises(InvalidReviewUrlError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"review_url": "http://g.page/r/x/review"},
            )

    async def test_update_that_does_not_mention_the_link_is_not_validated(
        self,
    ) -> None:
        """The dashboard PUTs its whole form. A save that never mentions
        the review link must not be able to fail because of it."""
        fx = make_service()
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"name": "Renamed"},
        )
        assert updated.name == "Renamed"

    async def test_stored_verbatim(self) -> None:
        """No normalising, no parameter stripping, no appending. Google
        changes these shapes; a helpful rewrite becomes a broken link."""
        fx = make_service()
        pasted = "https://g.page/r/CQabc123/review?utm_source=venue&hl=en#frag"
        config = await _create_config(fx, review_url=pasted)
        assert config.review_url == pasted

    async def test_the_link_can_be_cleared(self) -> None:
        fx = make_service()
        config = await _create_config(fx, review_url="https://g.page/r/CQabc/review")
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"review_url": None},
        )
        assert updated.review_url is None


class TestReviewIsNotACampaignType:
    def test_there_is_no_review_campaign_type(self) -> None:
        """Modelled as a config flag, not a campaign, on purpose.

        ``get_next_campaign_for_session`` returns exactly one campaign per
        session, so a review campaign would compete with the venue's
        actual promotions for that single slot -- a cafe running a weekend
        offer would silently stop asking for reviews and nobody could tell
        why. Campaigns also render as a full-screen takeover, which is the
        shape a review request must never take.
        """
        assert {t.value for t in CampaignType} == {"survey", "banner", "redirect"}


# ============================================================================
# GuestConsent.terms_version
# ============================================================================


class TestComputeTermsVersion:
    def test_none_when_the_config_has_no_terms_at_all(self) -> None:
        """Honest NULL. With nothing configured, whatever the guest saw
        came from the frontend's hardcoded copy, which this layer cannot
        see -- and a digest of four empty strings would be
        indistinguishable from a real version."""
        assert (
            compute_terms_version(
                terms_and_conditions_text=None,
                terms_and_conditions_url=None,
                privacy_policy_text=None,
                privacy_policy_url=None,
            )
            is None
        )
        assert (
            compute_terms_version(
                terms_and_conditions_text="   ",
                terms_and_conditions_url="",
                privacy_policy_text=None,
                privacy_policy_url=None,
            )
            is None
        )

    def test_deterministic(self) -> None:
        args = {
            "terms_and_conditions_text": "Use the WiFi nicely.",
            "terms_and_conditions_url": None,
            "privacy_policy_text": None,
            "privacy_policy_url": "https://example.com/privacy",
        }
        assert compute_terms_version(**args) == compute_terms_version(**args)

    def test_changes_when_the_text_changes(self) -> None:
        first = compute_terms_version(
            terms_and_conditions_text="Use the WiFi nicely.",
            terms_and_conditions_url=None,
            privacy_policy_text=None,
            privacy_policy_url=None,
        )
        second = compute_terms_version(
            terms_and_conditions_text="Use the WiFi nicely, please.",
            terms_and_conditions_url=None,
            privacy_policy_text=None,
            privacy_policy_url=None,
        )
        assert first != second

    def test_a_privacy_edit_changes_the_version_too(self) -> None:
        """A privacy notice is as much a part of what was consented to as
        the terms."""
        first = compute_terms_version(
            terms_and_conditions_text="Terms",
            terms_and_conditions_url=None,
            privacy_policy_text="Privacy v1",
            privacy_policy_url=None,
        )
        second = compute_terms_version(
            terms_and_conditions_text="Terms",
            terms_and_conditions_url=None,
            privacy_policy_text="Privacy v2",
            privacy_policy_url=None,
        )
        assert first != second

    def test_fields_cannot_be_confused_across_the_boundary(self) -> None:
        """Length-prefixing is why. Without it, ("ab", "c") and ("a",
        "bc") would hash identically and two different configurations
        would claim the same version."""
        first = compute_terms_version(
            terms_and_conditions_text="ab",
            terms_and_conditions_url="c",
            privacy_policy_text=None,
            privacy_policy_url=None,
        )
        second = compute_terms_version(
            terms_and_conditions_text="a",
            terms_and_conditions_url="bc",
            privacy_policy_text=None,
            privacy_policy_url=None,
        )
        assert first != second

    def test_fits_the_column(self) -> None:
        """``guest_consents.terms_version`` is a ``String(50)``."""
        version = compute_terms_version(
            terms_and_conditions_text="x" * 100_000,
            terms_and_conditions_url=None,
            privacy_policy_text=None,
            privacy_policy_url=None,
        )
        assert version is not None
        assert len(version) <= 50


class TestRecordConsentStampsTheVersion:
    async def test_a_consent_now_says_what_was_consented_to(self) -> None:
        """The defect this closes: every consent row in production has
        ``terms_version = NULL``, because the portal posts a guest id and
        a config id and nothing else. The platform could prove *that* a
        guest consented and not *to what*."""
        fx = make_fixture()
        config = fx.captive_portal_service.configs_by_org[fx.organization_id]
        config.terms_and_conditions_text = "Be nice on the WiFi."
        login = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        consent = await fx.guest_service.record_consent(
            guest_id=login.guest.id,
            captive_portal_config_id=config.id,
            terms_version=None,
            ip_address="203.0.113.9",
        )
        assert consent.terms_version == compute_terms_version(
            terms_and_conditions_text="Be nice on the WiFi.",
            terms_and_conditions_url=None,
            privacy_policy_text=None,
            privacy_policy_url=None,
        )

    async def test_an_explicit_version_still_wins(self) -> None:
        """The request-supplied value is the seam an admin backfill or a
        future consent-string registry would use. The portal sends none,
        so in practice the derived path is the one every real consent
        takes."""
        fx = make_fixture()
        config = fx.captive_portal_service.configs_by_org[fx.organization_id]
        config.terms_and_conditions_text = "Be nice on the WiFi."
        login = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        consent = await fx.guest_service.record_consent(
            guest_id=login.guest.id,
            captive_portal_config_id=config.id,
            terms_version="v3-hand-written",
            ip_address=None,
        )
        assert consent.terms_version == "v3-hand-written"

    async def test_no_config_id_leaves_it_null(self) -> None:
        fx = make_fixture()
        login = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        consent = await fx.guest_service.record_consent(
            guest_id=login.guest.id,
            captive_portal_config_id=None,
            terms_version=None,
            ip_address=None,
        )
        assert consent.terms_version is None

    async def test_an_unknown_config_id_leaves_it_null_and_still_records(
        self,
    ) -> None:
        """Wrong failure direction to 404 here: this runs on the sign-in
        path, and losing the consent row entirely is worse than losing the
        version."""
        fx = make_fixture()
        login = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        consent = await fx.guest_service.record_consent(
            guest_id=login.guest.id,
            captive_portal_config_id=uuid.uuid4(),
            terms_version=None,
            ip_address=None,
        )
        assert consent is not None
        assert consent.terms_version is None

    async def test_another_tenants_config_never_stamps_this_guests_consent(
        self,
    ) -> None:
        """``captive_portal_config_id`` arrives from an unauthenticated
        request body and is stored as a plain FK with no tenant check, so
        a caller can name any config on the platform. Stamping this
        guest's consent with another tenant's terms version would be a
        fabricated record -- strictly worse than a NULL, because it looks
        like evidence.
        """
        fx = make_fixture()
        other_org = uuid.uuid4()
        other_config = fx.captive_portal_service.register(other_org)
        other_config.terms_and_conditions_text = "Someone else's terms."
        login = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        consent = await fx.guest_service.record_consent(
            guest_id=login.guest.id,
            captive_portal_config_id=other_config.id,
            terms_version=None,
            ip_address=None,
        )
        assert consent.terms_version is None


# ============================================================================
# The review card's memory, and the feedback card's dwell gate
# ============================================================================


class TestReviewLinkOpened:
    """``POST /guest/review-link-opened``. Without it the review card has
    no memory at all: it renders on arrival, every visit, forever --
    including to the guest who already went and reviewed, which is the one
    guest it must never ask again."""

    async def _login(self, fx: GuestFixture):
        return await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="aa:bb:cc:dd:ee:ff",
        )

    async def test_a_tap_is_recorded_and_is_final(self) -> None:
        fx = make_fixture()
        login = await self._login(fx)
        assert guest_has_opened_review_link(login.guest) is False

        updated = await fx.guest_service.record_review_link_opened(
            guest_id=login.guest.id, session_id=login.session.id
        )
        assert updated.review_link_opened_at is not None
        assert guest_has_opened_review_link(updated) is True

    async def test_the_bit_reaches_both_response_surfaces(self) -> None:
        """The portal reads it on the page-load check as well as on login.
        That is the surface that matters: the NAS re-lands guests on the
        session page as a brand-new document, so a bit that only arrived
        on the login response would be gone by the time it was needed."""
        from app.domains.guest.router import _login_response

        fx = make_fixture()
        login = await self._login(fx)
        assert _login_response(login).has_opened_review_link is False

        await fx.guest_service.record_review_link_opened(
            guest_id=login.guest.id, session_id=login.session.id
        )
        active = await fx.guest_service.get_active_session_for_device(
            router_id=fx.router.id, device_mac="aa:bb:cc:dd:ee:ff"
        )
        assert active is not None
        assert _login_response(active).has_opened_review_link is True

    async def test_a_second_tap_is_not_an_error(self) -> None:
        """The portal calls this fire-and-forget as it navigates away, so
        a retry, a double tap, or a return visit must not 4xx."""
        fx = make_fixture()
        login = await self._login(fx)
        first = await fx.guest_service.record_review_link_opened(
            guest_id=login.guest.id, session_id=login.session.id
        )
        second = await fx.guest_service.record_review_link_opened(
            guest_id=login.guest.id, session_id=login.session.id
        )
        assert second.review_link_opened_at >= first.review_link_opened_at
        assert guest_has_opened_review_link(second) is True

    async def test_it_needs_a_live_session_for_that_guest(self) -> None:
        fx = make_fixture()
        login = await self._login(fx)
        with pytest.raises(GuestReviewLinkOpenedNotAuthorizedError):
            await fx.guest_service.record_review_link_opened(
                guest_id=login.guest.id, session_id=uuid.uuid4()
            )

    async def test_a_non_otp_guest_may_still_record_a_tap(self) -> None:
        """Deliberately weaker than the profile write's check, which also
        requires an OTP method and a 15-minute window. This stores nothing
        about the guest and grants nothing; being strict here would only
        re-nag a voucher guest who did what was asked. See
        ``GuestReviewLinkOpenedNotAuthorizedError``."""
        fx = make_fixture()
        fx.voucher_service.register("VOUCHER1", data_limit_mb=500, validity_minutes=120)
        login = await fx.guest_service.login_via_voucher(
            code="VOUCHER1",
            identifier="guest@example.com",
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        updated = await fx.guest_service.record_review_link_opened(
            guest_id=login.guest.id, session_id=login.session.id
        )
        assert guest_has_opened_review_link(updated) is True

    def test_the_request_body_cannot_name_a_destination(self) -> None:
        """Two ids and nothing else. A URL on this request would let an
        unauthenticated caller name a destination the platform then looks
        to have recorded as its own -- the venue's link is already on the
        config."""
        from app.domains.guest.schemas import GuestReviewLinkOpenedRequest

        assert set(GuestReviewLinkOpenedRequest.model_fields) == {
            "guest_id",
            "session_id",
        }


class TestFeedbackDwell:
    def test_the_bounds_are_the_portals_own(self) -> None:
        """5 and 25 are ``clampFeedbackDwellMinutes``'s numbers in
        ``lib/portal-post-connect.ts``. Mirrored so the server rejects
        what the client would silently have raised -- a venue that sets 2
        and sees the card at 5 has no way to find out why."""
        assert MIN_FEEDBACK_DWELL_MINUTES == 5
        assert DEFAULT_FEEDBACK_DWELL_MINUTES == 25

    @pytest.mark.parametrize("value", [5, 25, 90, 1440])
    def test_accepts_a_plausible_dwell(self, value: int) -> None:
        validate_feedback_dwell_minutes(value)

    @pytest.mark.parametrize("value", [4, 0, -1, 1441, 10000])
    def test_rejects_out_of_range(self, value: int) -> None:
        with pytest.raises(InvalidFeedbackDwellMinutesError):
            validate_feedback_dwell_minutes(value)

    @pytest.mark.parametrize("value", [True, False, 25.5, "25", None])
    def test_rejects_a_non_integer(self, value: object) -> None:
        """``bool`` explicitly, because Python's ``bool`` subclasses
        ``int`` and ``True`` is never a legal number of minutes -- the
        same exclusion ``validate_background_overlay_strength`` makes."""
        with pytest.raises(InvalidFeedbackDwellMinutesError):
            validate_feedback_dwell_minutes(value)

    async def test_the_config_carries_the_feedback_fields(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        assert config.guest_feedback_enabled is False
        assert config.feedback_dwell_minutes == DEFAULT_FEEDBACK_DWELL_MINUTES

    async def test_create_rejects_a_dwell_out_of_range(self) -> None:
        """Enforced in the service, not only by the schema: the
        smart-location provisioning flow builds its arguments in Python
        and never passes through a request model."""
        fx = make_service()
        with pytest.raises(InvalidFeedbackDwellMinutesError):
            await _create_config(fx, feedback_dwell_minutes=2)

    async def test_update_rejects_a_dwell_out_of_range(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        with pytest.raises(InvalidFeedbackDwellMinutesError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"feedback_dwell_minutes": 99999},
            )

    def test_the_two_cards_are_separate_flags(self) -> None:
        """Not one flag with two behaviours. Sequencing a private form on
        the outcome of a public review ask is review gating, which
        Google's Rating Manipulation policy prohibits outright -- so the
        two must be independently switchable and neither may know about
        the other."""
        from app.domains.captive_portal.models import CaptivePortalConfig

        columns = set(CaptivePortalConfig.__table__.columns.keys())
        assert "review_card_enabled" in columns
        assert "guest_feedback_enabled" in columns


class TestTheCacheKeyMovedWithTheFieldSet:
    def test_the_new_config_fields_are_cached_and_the_key_was_bumped(self) -> None:
        """The failure this prevents is a 500 for every guest at every
        venue, not a stale colour: ``_config_from_cache_payload`` indexes
        ``_CACHED_CONFIG_SCALAR_FIELDS`` with ``payload[field_name]``,
        unguarded and deliberately so, and
        ``GET /captive-portal/resolve`` is unauthenticated and is the
        first call every guest device makes. Left at v6, the first resolve
        after deploy reads a payload with none of these keys in it."""
        from app.domains.captive_portal.cache import _CACHE_KEY_TEMPLATE
        from app.domains.captive_portal.service import (
            _CACHED_CONFIG_SCALAR_FIELDS,
        )

        for field in (
            "collect_guest_name",
            "collect_guest_email",
            "review_card_enabled",
            "review_url",
            "guest_feedback_enabled",
            "feedback_dwell_minutes",
        ):
            assert field in _CACHED_CONFIG_SCALAR_FIELDS
        assert _CACHE_KEY_TEMPLATE.split(":")[2] == "v7"
