"""The generated splash headline must never be rejected by the validator
that guards the field it is generated for.

Regression cover for a live 2026-08-27 failure: both provisioning paths
seeded ``f"Welcome to {location.name}"`` and then validated it like
venue-authored text. ``"Welcome to "`` is 11 of the 26-code-point budget,
so any venue name over 15 code points 400'd
``POST /api/v1/locations/provision`` naming ``splash_headline`` -- a field
the operator never filled in.
"""

import pytest

from app.domains.captive_portal.constants import SPLASH_HEADLINE_MAX_LENGTH
from app.domains.captive_portal.exceptions import SplashTextTooLongError
from app.domains.captive_portal.validators import (
    default_splash_headline,
    validate_splash_text_length,
)


def _assert_accepted(headline: str) -> None:
    """The property that actually matters: whatever we generate, the write
    path's own validator accepts it."""
    validate_splash_text_length("splash_headline", headline)


class TestFitsByConstruction:
    @pytest.mark.parametrize(
        "name",
        [
            "Danda Cafe",  # rung 1, short
            "The Hive",
            "50 50 cafe",
            "A" * 15,  # rung 1, exactly at the greeting's limit
            "A" * 16,  # rung 2, the first name the old code rejected
            "Danda Cafe Haldwani",  # rung 2, the real-world failure
            "A" * SPLASH_HEADLINE_MAX_LENGTH,  # rung 2, exactly at ceiling
            "A" * (SPLASH_HEADLINE_MAX_LENGTH + 1),  # rung 3, truncated
            "A" * 200,  # rung 3, absurd
            "  Padded Venue Name Here  ",  # stripped before measuring
            "कैफे हलद्वानी शाखा एक",  # non-Latin, code points not bytes
            "Кафе Хальдвани Филиал",
        ],
    )
    def test_generated_headline_always_passes_validator(self, name: str) -> None:
        headline = default_splash_headline(name)
        _assert_accepted(headline)
        assert len(headline.strip()) <= SPLASH_HEADLINE_MAX_LENGTH

    def test_the_exact_length_that_failed_live(self) -> None:
        """27 code points -- one over the ceiling -- was the reported error."""
        name = "Danda Cafe Haldwani Branch"  # 26; greeted -> 37
        assert len(f"Welcome to {name}") > SPLASH_HEADLINE_MAX_LENGTH
        _assert_accepted(default_splash_headline(name))

    def test_old_behaviour_would_have_failed(self) -> None:
        """Guards the regression itself: the pre-fix expression is still
        rejected, so this test fails loudly if someone reverts to it."""
        with pytest.raises(SplashTextTooLongError):
            validate_splash_text_length(
                "splash_headline", "Welcome to Danda Cafe Haldwani"
            )


class TestPrefersTheFriendliestFormThatFits:
    def test_short_name_keeps_the_greeting(self) -> None:
        assert default_splash_headline("Danda Cafe") == "Welcome to Danda Cafe"

    def test_boundary_keeps_the_greeting_at_exactly_the_ceiling(self) -> None:
        name = "A" * 15
        assert default_splash_headline(name) == f"Welcome to {name}"
        assert len(default_splash_headline(name)) == SPLASH_HEADLINE_MAX_LENGTH

    def test_long_name_drops_the_greeting_rather_than_the_name(self) -> None:
        name = "Danda Cafe Haldwani"
        assert default_splash_headline(name) == name

    def test_name_longer_than_the_ceiling_is_truncated_with_an_ellipsis(self) -> None:
        name = "A" * 40
        result = default_splash_headline(name)
        assert result.endswith("…")
        assert len(result) == SPLASH_HEADLINE_MAX_LENGTH

    def test_truncation_does_not_leave_a_dangling_space(self) -> None:
        # 26th code point lands on a space; the ellipsis must not follow one.
        name = "Averyverylongvenuename ext" + "x" * 20
        result = default_splash_headline(name)
        assert " …" not in result

    def test_surrounding_whitespace_is_not_charged_for(self) -> None:
        assert default_splash_headline("  Danda Cafe  ") == "Welcome to Danda Cafe"
