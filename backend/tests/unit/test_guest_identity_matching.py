"""A guest is identified across phone spellings, not by exact string.

``GuestRepository.get_guest_by_identifier`` was exact equality on
``(organization_id, identifier)`` while ``guest_access`` had already widened
rule matching across "same digits, ignoring a leading ``+`` and up to 3
leading digits" (``identifier_match_terms``, the 2026-09 fix). Identity did
not follow, so a guest who signed in as ``9876543210`` once and
``+919876543210`` later got **two ``Guest`` rows for one person**: split visit
counts, split session history, split reports, and a blocklist rule written
against one spelling catching only half of them.

These tests pin the widened lookup without a database. The repo's guest tests
are in-memory fakes with no shared Postgres, so a widening that lived only
inside an executed method would be a widening nothing could assert --
``guest_identifier_clause`` exists so the ``WHERE`` clause can be compiled and
read instead, the same division of labour
``guest_access.validators.identifiers_match`` performs on the rule side.
"""

from __future__ import annotations

import uuid

from sqlalchemy.dialects import postgresql

from app.domains.guest.repository import guest_identifier_clause
from app.domains.guest_access.validators import (
    identifier_match_terms,
    identifiers_match,
)

ORG = uuid.UUID("2f1c9d3e-0000-4000-8000-000000000001")


def _rendered(identifier: str) -> tuple[str, list[object]]:
    """The compiled SQL, and every scalar it binds.

    ``IN (...)`` binds one list parameter rather than N scalars, so the
    values are flattened here -- a test asking "is this spelling in the
    lookup?" means the spelling, not the list holding it."""
    clause = guest_identifier_clause(organization_id=ORG, identifier=identifier)
    compiled = clause.compile(dialect=postgresql.dialect())
    values: list[object] = []
    for value in compiled.params.values():
        if isinstance(value, list | tuple):
            values.extend(value)
        else:
            values.append(value)
    return str(compiled), values


class TestPhoneSpellingsResolveToOneGuest:
    def test_every_exact_spelling_the_vocabulary_accepts_is_bound(self) -> None:
        """The ``IN (...)`` half: the incoming value's own derived spellings."""
        terms = identifier_match_terms("9876543210")
        _sql, params = _rendered("9876543210")

        for spelling in terms.exact:
            assert spelling in params, (
                f"{spelling!r} is in identifier_match_terms but the lookup "
                "does not ask the database for it"
            )

    def test_a_stored_country_code_is_matched_by_a_like_pattern(self) -> None:
        """The half a loop over derived spellings cannot cover: the incoming
        value is bare digits, the *stored* one carries a country code, so the
        clause has to widen towards the stored form with a pattern."""
        sql, _params = _rendered("9876543210")

        assert "LIKE" in sql.upper()

    def test_the_two_forms_agree_on_the_pairing_this_exists_for(self) -> None:
        """``identifiers_match`` is the pure-Python mirror the rule side uses.
        Pinned here so the guest lookup and the rule lookup are visibly
        answering the same question."""
        assert identifiers_match("+919876543210", "9876543210") is True
        assert identifiers_match("9876543210", "+919876543210") is True


class TestNonPhoneIdentifiersAreNotWidened:
    def test_an_email_matches_exactly_and_only(self) -> None:
        """``identifier_match_terms`` never widens anything it cannot prove is
        a phone number, and ``canonicalize_rule_identifier`` returns emails
        untouched (case preserved). So an email lookup must stay exact."""
        terms = identifier_match_terms("guest@example.com")

        assert terms.exact == ("guest@example.com",)
        assert terms.prefix_patterns == ()

        sql, params = _rendered("guest@example.com")
        assert "LIKE" not in sql.upper()
        assert "guest@example.com" in params

    def test_a_short_digit_string_is_not_widened_into_a_phone(self) -> None:
        """Floored at ``MIN_NATIONAL_DIGITS``: a short numeric string must
        never collapse into a real number's spellings."""
        terms = identifier_match_terms("1234")

        assert terms.prefix_patterns == ()
        assert terms.exact == ("1234",)


class TestTheLookupStaysScoped:
    def test_it_is_scoped_to_one_organization(self) -> None:
        """Widening the *spelling* must not widen the *tenant* -- two venues'
        guests with the same number are different guests."""
        sql, params = _rendered("+919876543210")

        assert "organization_id" in sql
        assert ORG in params

    def test_soft_deleted_guests_are_excluded(self) -> None:
        sql, _params = _rendered("+919876543210")

        assert "is_deleted" in sql
