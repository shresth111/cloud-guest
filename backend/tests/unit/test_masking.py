"""Unit tests for the cross-cutting PII masking layer
(``app.common.masking`` + ``app.middleware.request_context``'s
``MaskingContext``).

Covers: each pure mask function's edge cases (``None``/empty/short
strings/already-masked/non-ASCII names), the ``Masked*`` Pydantic
Annotated types' flag-on/flag-off serialization paths (including that
masking is the fail-closed *default*), the ``accessed_kinds`` audit
bookkeeping those serializers populate, and the pure
``_build_pii_audit_fields`` helper ``RequestContextMiddleware`` uses to
write the one-row-per-request audit entry.
"""

from __future__ import annotations

from pydantic import BaseModel
from starlette.requests import Request

from app.common.masking import (
    MaskedEmail,
    MaskedIdentifier,
    MaskedMac,
    MaskedMobile,
    MaskedName,
    mask_email,
    mask_identifier,
    mask_mac,
    mask_mobile,
    mask_name,
)
from app.middleware.request_context import (
    MaskingContext,
    _build_pii_audit_fields,
    get_masking_context,
    masking_context,
)

# ============================================================================
# mask_mobile
# ============================================================================


class TestMaskMobile:
    def test_masks_a_country_coded_number(self) -> None:
        assert mask_mobile("+91 98765 98647") == "XXXXXXX98647"

    def test_masks_a_bare_ten_digit_number(self) -> None:
        assert mask_mobile("9876598647") == "XXXXX98647"

    def test_null_is_passed_through(self) -> None:
        assert mask_mobile(None) is None

    def test_empty_string_is_passed_through(self) -> None:
        assert mask_mobile("") == ""

    def test_short_string_has_nothing_left_to_mask(self) -> None:
        assert mask_mobile("123") == "123"

    def test_exactly_five_digits_is_unchanged(self) -> None:
        assert mask_mobile("98647") == "98647"

    def test_idempotent_on_already_masked_value(self) -> None:
        assert mask_mobile("XXXXXXX98647") == "XXXXXXX98647"

    def test_non_digit_characters_are_stripped(self) -> None:
        assert mask_mobile("(987) 659-8647") == "XXXXX98647"

    def test_value_with_no_digits_at_all_is_passed_through(self) -> None:
        assert mask_mobile("abc") == "abc"


# ============================================================================
# mask_email
# ============================================================================


class TestMaskEmail:
    def test_masks_local_part_keeping_first_and_last_character(self) -> None:
        assert mask_email("akhilrai@gmail.com") == "a****i@gmail.com"

    def test_null_is_passed_through(self) -> None:
        assert mask_email(None) is None

    def test_empty_string_is_passed_through(self) -> None:
        assert mask_email("") == ""

    def test_single_character_local_part(self) -> None:
        assert mask_email("a@gmail.com") == "a****@gmail.com"

    def test_value_without_at_sign_is_passed_through(self) -> None:
        assert mask_email("not-an-email") == "not-an-email"

    def test_idempotent_on_already_masked_value(self) -> None:
        assert mask_email("a****l@gmail.com") == "a****l@gmail.com"

    def test_domain_is_never_masked(self) -> None:
        assert mask_email("bob@example.org").endswith("@example.org")


# ============================================================================
# mask_name
# ============================================================================


class TestMaskName:
    def test_masks_last_token_to_initial(self) -> None:
        assert mask_name("Akhil Sharma") == "Akhil S."

    def test_null_is_passed_through(self) -> None:
        assert mask_name(None) is None

    def test_empty_string_is_passed_through(self) -> None:
        assert mask_name("") == ""

    def test_single_token_name_is_unchanged(self) -> None:
        assert mask_name("Akhil") == "Akhil"

    def test_idempotent_on_already_masked_value(self) -> None:
        assert mask_name("Akhil S.") == "Akhil S."

    def test_multi_token_first_name_preserved_in_full(self) -> None:
        assert mask_name("Akhil Kumar Sharma") == "Akhil Kumar S."

    def test_non_ascii_name(self) -> None:
        assert mask_name("Priya Śarma") == "Priya Ś."


# ============================================================================
# mask_mac
# ============================================================================


class TestMaskMac:
    def test_masks_first_four_octets(self) -> None:
        assert mask_mac("AA:BB:CC:DD:EE:FF") == "XX:XX:XX:XX:EE:FF"

    def test_preserves_dash_separator(self) -> None:
        assert mask_mac("AA-BB-CC-DD-EE-FF") == "XX-XX-XX-XX-EE-FF"

    def test_null_is_passed_through(self) -> None:
        assert mask_mac(None) is None

    def test_empty_string_is_passed_through(self) -> None:
        assert mask_mac("") == ""

    def test_not_a_mac_address_is_passed_through(self) -> None:
        assert mask_mac("not-a-mac") == "not-a-mac"

    def test_idempotent_on_already_masked_value(self) -> None:
        assert mask_mac("XX:XX:XX:XX:EE:FF") == "XX:XX:XX:XX:EE:FF"


# ============================================================================
# mask_identifier -- dispatches to mask_email/mask_mobile by content shape
# ============================================================================


class TestMaskIdentifier:
    def test_dispatches_to_email_masking(self) -> None:
        assert mask_identifier("akhilrai@gmail.com") == "a****i@gmail.com"

    def test_dispatches_to_mobile_masking(self) -> None:
        assert mask_identifier("+919876598647") == "XXXXXXX98647"

    def test_null_is_passed_through(self) -> None:
        assert mask_identifier(None) is None

    def test_empty_string_is_passed_through(self) -> None:
        assert mask_identifier("") == ""


# ============================================================================
# MaskingContext / get_masking_context safety
# ============================================================================


class TestGetMaskingContext:
    def test_defaults_to_fail_closed_masking_enabled(self) -> None:
        assert get_masking_context().masking_enabled is True

    def test_reading_twice_without_a_set_never_shares_state(self) -> None:
        # The whole point of get_masking_context()'s "or MaskingContext()"
        # fallback: two independent reads outside a .set() context must
        # never be able to mutate each other's accessed_kinds list.
        first = get_masking_context()
        first.accessed_kinds.append("mobile")
        second = get_masking_context()
        assert second.accessed_kinds == []

    def test_a_real_set_context_is_the_same_instance_on_every_get(self) -> None:
        token = masking_context.set(MaskingContext(masking_enabled=False))
        try:
            a = get_masking_context()
            b = get_masking_context()
            assert a is b
            a.accessed_kinds.append("mac")
            assert b.accessed_kinds == ["mac"]
        finally:
            masking_context.reset(token)


# ============================================================================
# Masked* Pydantic types -- flag-on/flag-off serialization
# ============================================================================


class _GuestLikeResponse(BaseModel):
    mobile: MaskedMobile
    email: MaskedEmail
    name: MaskedName
    mac: MaskedMac
    identifier: MaskedIdentifier


def _make_response() -> _GuestLikeResponse:
    return _GuestLikeResponse(
        mobile="+919876598647",
        email="akhilrai@gmail.com",
        name="Akhil Sharma",
        mac="AA:BB:CC:DD:EE:FF",
        identifier="akhilrai@gmail.com",
    )


class TestMaskedTypesSerialization:
    def test_masked_by_default_with_no_context_set(self) -> None:
        dumped = _make_response().model_dump()
        assert dumped == {
            "mobile": "XXXXXXX98647",
            "email": "a****i@gmail.com",
            "name": "Akhil S.",
            "mac": "XX:XX:XX:XX:EE:FF",
            "identifier": "a****i@gmail.com",
        }

    def test_masked_when_context_explicitly_enables_masking(self) -> None:
        token = masking_context.set(MaskingContext(masking_enabled=True))
        try:
            dumped = _make_response().model_dump()
            assert dumped["mobile"] == "XXXXXXX98647"
            assert get_masking_context().accessed_kinds == []
        finally:
            masking_context.reset(token)

    def test_unmasked_when_context_disables_masking(self) -> None:
        context = MaskingContext(masking_enabled=False)
        token = masking_context.set(context)
        try:
            dumped = _make_response().model_dump()
            assert dumped == {
                "mobile": "+919876598647",
                "email": "akhilrai@gmail.com",
                "name": "Akhil Sharma",
                "mac": "AA:BB:CC:DD:EE:FF",
                "identifier": "akhilrai@gmail.com",
            }
        finally:
            masking_context.reset(token)

    def test_unmasked_access_is_recorded_for_every_distinct_kind(self) -> None:
        context = MaskingContext(masking_enabled=False)
        token = masking_context.set(context)
        try:
            _make_response().model_dump()
            assert sorted(context.accessed_kinds) == [
                "email",
                "identifier",
                "mac",
                "mobile",
                "name",
            ]
        finally:
            masking_context.reset(token)

    def test_null_values_pass_through_regardless_of_masking_flag(self) -> None:
        class _Nullable(BaseModel):
            mobile: MaskedMobile

        for enabled in (True, False):
            token = masking_context.set(MaskingContext(masking_enabled=enabled))
            try:
                assert _Nullable(mobile=None).model_dump() == {"mobile": None}
            finally:
                masking_context.reset(token)

    def test_masked_access_is_never_recorded(self) -> None:
        context = MaskingContext(masking_enabled=True)
        token = masking_context.set(context)
        try:
            _make_response().model_dump()
            assert context.accessed_kinds == []
        finally:
            masking_context.reset(token)


# ============================================================================
# _build_pii_audit_fields -- pure, no DB session needed
# ============================================================================


def _make_request(path: str = "/api/v1/guest") -> Request:
    return Request({"type": "http", "method": "GET", "path": path, "headers": []})


class TestBuildPiiAuditFields:
    def test_builds_expected_shape(self) -> None:
        context = MaskingContext(
            masking_enabled=False,
            user_id="11111111-1111-1111-1111-111111111111",
            organization_id="22222222-2222-2222-2222-222222222222",
            accessed_kinds=["mobile", "name", "mobile"],
        )
        fields = _build_pii_audit_fields(_make_request(), context)

        assert str(fields["actor_user_id"]) == context.user_id
        assert str(fields["organization_id"]) == context.organization_id
        assert fields["action"] == "pii_viewed_unmasked"
        assert fields["entity_type"] == "pii_access"
        assert fields["entity_id"] is None
        assert fields["event_metadata"]["kinds"] == ["mobile", "name"]
        assert fields["event_metadata"]["count"] == 3
        assert "GET" in fields["description"]

    def test_missing_user_and_organization_ids_become_none(self) -> None:
        context = MaskingContext(masking_enabled=False, accessed_kinds=["mac"])
        fields = _build_pii_audit_fields(_make_request(), context)
        assert fields["actor_user_id"] is None
        assert fields["organization_id"] is None

    def test_malformed_ids_become_none_rather_than_raising(self) -> None:
        context = MaskingContext(
            masking_enabled=False,
            user_id="not-a-uuid",
            accessed_kinds=["mac"],
        )
        fields = _build_pii_audit_fields(_make_request(), context)
        assert fields["actor_user_id"] is None
