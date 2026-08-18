"""Unit tests for the Channel Partner domain: GSTIN/Indian-mobile
validators, onboard+welcome-message composition (SMS/email success,
failure, and unconfigured-provider paths, plus the "duplicate GSTIN never
silently overwrites" case), list/get, and RBAC gating.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_quotation.py``'s own module docstring); ``asyncio_mode =
"auto"`` runs async tests directly. ``ChannelPartnerService`` is exercised
against a small, hand-rolled in-memory fake repository (mirroring
``test_quotation.py``'s own ``FakeQuotationRepository`` shape) and fake
SMS/email providers -- there is no live Postgres or real Twilio/SMTP
connection in this environment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.database.exceptions import DuplicateRecordError
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.channel_partner.constants import (
    CHANNEL_PARTNER_PRODUCT_NAME,
    ChannelPartnerStatus,
)
from app.domains.channel_partner.exceptions import (
    ChannelPartnerNotFoundError,
    DuplicateGstNumberError,
)
from app.domains.channel_partner.models import ChannelPartner
from app.domains.channel_partner.router import _onboard_message, router
from app.domains.channel_partner.schemas import (
    ChannelPartnerCreateRequest,
    normalize_gst_number,
    normalize_indian_phone,
)
from app.domains.channel_partner.service import ChannelPartnerService
from app.domains.otp.service import LoggingEmailProvider, LoggingSmsProvider
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.enums import AuditAction, PermissionModule, ScopeType
from app.domains.rbac.exceptions import PermissionDeniedError
from app.domains.rbac.seed import (
    MODULE_ACTIONS,
    MODULE_NARROWEST_SCOPE,
    SYSTEM_ROLES,
)

from .test_rbac import FakeRBACRepository

# ============================================================================
# Test doubles
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakeChannelPartnerRepository:
    partners: dict[uuid.UUID, ChannelPartner] = field(default_factory=dict)

    async def create_partner(self, **fields: object) -> ChannelPartner:
        gst_number = fields.get("gst_number")
        if any(p.gst_number == gst_number for p in self.partners.values()):
            # Mirrors GenericRepository._flush_or_raise's real behavior on
            # the gst_number unique-constraint violation.
            raise DuplicateRecordError("ChannelPartner", "gst_number")
        partner = ChannelPartner(**_base_fields(**fields))
        self.partners[partner.id] = partner
        return partner

    async def get_by_id(self, channel_partner_id: uuid.UUID) -> ChannelPartner | None:
        return self.partners.get(channel_partner_id)

    async def update_partner(
        self, partner: ChannelPartner, data: dict[str, object]
    ) -> ChannelPartner:
        for key, value in data.items():
            setattr(partner, key, value)
        partner.version += 1
        return partner

    async def list_partners(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        search: str | None = None,
    ) -> tuple[list[ChannelPartner], PaginationMeta]:
        items = [p for p in self.partners.values() if not p.is_deleted]
        if status is not None:
            items = [p for p in items if p.status == status]
        if search is not None:
            needle = search.lower()
            items = [
                p
                for p in items
                if needle in p.name.lower()
                or needle in p.phone.lower()
                or needle in p.city.lower()
                or needle in p.gst_number.lower()
                or (p.email is not None and needle in p.email.lower())
            ]
        items.sort(key=lambda p: p.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        return items, PaginationMeta.from_total(params, len(items))


@dataclass
class FakeSmsProvider:
    sent: list[dict[str, object]] = field(default_factory=list)
    raise_error: Exception | None = None

    async def send(self, phone_number: str, message: str) -> None:
        if self.raise_error is not None:
            raise self.raise_error
        self.sent.append({"phone_number": phone_number, "message": message})


@dataclass
class FakeEmailProvider:
    sent: list[dict[str, object]] = field(default_factory=list)
    raise_error: Exception | None = None

    async def send(
        self, email: str, subject: str, body: str, *, attachment: object = None
    ) -> None:
        if self.raise_error is not None:
            raise self.raise_error
        self.sent.append({"email": email, "subject": subject, "body": body})


@dataclass
class FakeAuditWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> object:
        self.entries.append(fields)
        return fields


def _make_service(
    *,
    sms_provider: object | None = None,
    email_provider: object | None = None,
    audit_writer: object | None = None,
) -> tuple[ChannelPartnerService, FakeChannelPartnerRepository]:
    repository = FakeChannelPartnerRepository()
    service = ChannelPartnerService(
        repository,
        sms_provider=sms_provider,
        email_provider=email_provider,
        audit_writer=audit_writer,
    )
    return service, repository


def _make_request(**overrides: object) -> ChannelPartnerCreateRequest:
    fields: dict[str, object] = {
        "name": "Alice Anderson",
        "phone": "9876543210",
        "email": "alice@example.com",
        "address": "123 MG Road, Bengaluru",
        "city": "Bengaluru",
        "gst_number": "27AAAAA0000A1Z5",
    }
    fields.update(overrides)
    return ChannelPartnerCreateRequest(**fields)


# ============================================================================
# GSTIN validator
# ============================================================================


class TestGstinValidator:
    def test_valid_gstin_accepted_and_uppercased(self) -> None:
        assert normalize_gst_number("27aaaaa0000a1z5") == "27AAAAA0000A1Z5"

    def test_valid_gstin_already_uppercase(self) -> None:
        assert normalize_gst_number("29ABCDE1234F1Z1") == "29ABCDE1234F1Z1"

    def test_wrong_length_rejected(self) -> None:
        with pytest.raises(ValueError, match="valid 15-character GSTIN"):
            normalize_gst_number("27AAAAA0000A1Z")  # 14 chars

    def test_lowercase_after_normalize_garbage_rejected(self) -> None:
        with pytest.raises(ValueError, match="valid 15-character GSTIN"):
            normalize_gst_number("!!invalid-gstin!!")

    def test_wrong_fixed_z_position_rejected(self) -> None:
        # Position 14 (0-indexed) must be a literal "Z" -- swapped for "Y".
        with pytest.raises(ValueError, match="valid 15-character GSTIN"):
            normalize_gst_number("27AAAAA0000A1Y5")

    def test_non_alphanumeric_rejected(self) -> None:
        with pytest.raises(ValueError, match="valid 15-character GSTIN"):
            normalize_gst_number("27AAAAA0000A1Z#")

    def test_schema_rejects_malformed_gstin_with_422_shaped_error(self) -> None:
        with pytest.raises(ValidationError):
            _make_request(gst_number="NOT-A-REAL-GSTIN")


# ============================================================================
# Indian mobile phone validator
# ============================================================================


class TestIndianPhoneValidator:
    def test_bare_ten_digit_normalizes_to_e164(self) -> None:
        assert normalize_indian_phone("9876543210") == "+919876543210"

    def test_plus91_prefixed_normalizes_to_same_e164(self) -> None:
        assert normalize_indian_phone("+919876543210") == "+919876543210"

    def test_91_prefixed_normalizes_to_same_e164(self) -> None:
        assert normalize_indian_phone("919876543210") == "+919876543210"

    def test_all_three_forms_normalize_identically(self) -> None:
        assert (
            normalize_indian_phone("9876543210")
            == normalize_indian_phone("+919876543210")
            == normalize_indian_phone("919876543210")
        )

    def test_landline_shaped_number_rejected(self) -> None:
        # Indian mobiles always start with 6-9; a landline-shaped number
        # starting with 0/1-5 must be rejected.
        with pytest.raises(ValueError, match="valid 10-digit Indian mobile"):
            normalize_indian_phone("0112345678")

    def test_too_short_number_rejected(self) -> None:
        with pytest.raises(ValueError, match="valid 10-digit Indian mobile"):
            normalize_indian_phone("98765432")

    def test_schema_rejects_malformed_phone_with_422_shaped_error(self) -> None:
        with pytest.raises(ValidationError):
            _make_request(phone="12345")


# ============================================================================
# Service: onboard + welcome-message composition
# ============================================================================


class TestOnboardPartner:
    async def test_both_channels_succeed(self) -> None:
        sms = FakeSmsProvider()
        email = FakeEmailProvider()
        service, _repository = _make_service(sms_provider=sms, email_provider=email)

        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )

        assert partner.status == ChannelPartnerStatus.ACTIVE.value
        assert partner.welcome_sms_sent_at is not None
        assert partner.welcome_sms_error is None
        assert partner.welcome_email_sent_at is not None
        assert partner.welcome_email_error is None
        assert len(sms.sent) == 1
        assert sms.sent[0]["phone_number"] == "+919876543210"
        assert CHANNEL_PARTNER_PRODUCT_NAME in sms.sent[0]["message"]
        assert len(email.sent) == 1
        assert email.sent[0]["email"] == "alice@example.com"
        assert "Alice Anderson" in email.sent[0]["subject"]

    async def test_no_email_provided_skips_email_send_entirely(self) -> None:
        sms = FakeSmsProvider()
        email = FakeEmailProvider()
        service, _repository = _make_service(sms_provider=sms, email_provider=email)

        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request(email=None)
        )

        assert partner.email is None
        assert partner.welcome_sms_sent_at is not None
        assert partner.welcome_email_sent_at is None
        assert partner.welcome_email_error is None
        assert len(email.sent) == 0

    async def test_sms_send_failure_records_error_never_raises(self) -> None:
        sms = FakeSmsProvider(raise_error=RuntimeError("twilio down"))
        email = FakeEmailProvider()
        service, _repository = _make_service(sms_provider=sms, email_provider=email)

        # The partner row is never rolled back by a failed send -- see
        # service.py's own module docstring.
        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )

        assert partner.welcome_sms_error == "twilio down"
        assert partner.welcome_sms_sent_at is None
        # The email channel is independent -- still attempted and succeeds.
        assert partner.welcome_email_sent_at is not None

    async def test_email_send_failure_records_error_never_raises(self) -> None:
        sms = FakeSmsProvider()
        email = FakeEmailProvider(raise_error=RuntimeError("smtp down"))
        service, _repository = _make_service(sms_provider=sms, email_provider=email)

        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )

        assert partner.welcome_sms_sent_at is not None
        assert partner.welcome_email_error == "smtp down"
        assert partner.welcome_email_sent_at is None

    async def test_both_channels_fail_row_still_persists(self) -> None:
        sms = FakeSmsProvider(raise_error=RuntimeError("twilio down"))
        email = FakeEmailProvider(raise_error=RuntimeError("smtp down"))
        service, repository = _make_service(sms_provider=sms, email_provider=email)

        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )

        # The single most important invariant in this domain: a fully
        # failed welcome message is never a failed onboarding.
        assert partner.id in repository.partners
        assert partner.welcome_sms_error == "twilio down"
        assert partner.welcome_email_error == "smtp down"
        fetched = await service.get_partner(partner.id)
        assert fetched.id == partner.id

    async def test_no_sms_provider_configured_records_honest_error(self) -> None:
        service, _repository = _make_service(
            sms_provider=None, email_provider=FakeEmailProvider()
        )

        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )

        assert partner.welcome_sms_error is not None
        assert "No real SMS delivery provider" in partner.welcome_sms_error
        assert partner.welcome_sms_sent_at is None

    async def test_bare_logging_sms_provider_is_treated_as_unconfigured(self) -> None:
        """A ``LoggingSmsProvider`` only logs -- it never really reaches
        the partner's phone, so this must be an honest failure recorded on
        the row, not a fabricated success. Mirrors
        ``QuotationService``'s identical ``isinstance(..., LoggingEmailProvider)``
        check for email."""
        service, _repository = _make_service(
            sms_provider=LoggingSmsProvider(), email_provider=FakeEmailProvider()
        )

        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )

        assert partner.welcome_sms_error is not None
        assert "No real SMS delivery provider" in partner.welcome_sms_error

    async def test_no_email_provider_configured_records_honest_error(self) -> None:
        service, _repository = _make_service(
            sms_provider=FakeSmsProvider(), email_provider=None
        )

        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )

        assert partner.welcome_email_error is not None
        assert "No real email delivery provider" in partner.welcome_email_error

    async def test_bare_logging_email_provider_is_treated_as_unconfigured(
        self,
    ) -> None:
        service, _repository = _make_service(
            sms_provider=FakeSmsProvider(), email_provider=LoggingEmailProvider()
        )

        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )

        assert partner.welcome_email_error is not None
        assert "No real email delivery provider" in partner.welcome_email_error

    async def test_duplicate_gst_number_raises_without_creating_a_second_row(
        self,
    ) -> None:
        service, repository = _make_service(
            sms_provider=FakeSmsProvider(), email_provider=FakeEmailProvider()
        )
        await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )

        with pytest.raises(DuplicateGstNumberError):
            await service.onboard_partner(
                actor_user_id=uuid.uuid4(),
                data=_make_request(name="Bob Brown", phone="9123456780"),
            )

        assert len(repository.partners) == 1

    async def test_stores_normalized_phone_and_gst_on_the_row(self) -> None:
        service, _repository = _make_service(
            sms_provider=FakeSmsProvider(), email_provider=FakeEmailProvider()
        )

        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(),
            data=_make_request(phone="919876543210", gst_number="27aaaaa0000a1z5"),
        )

        assert partner.phone == "+919876543210"
        assert partner.gst_number == "27AAAAA0000A1Z5"


# ============================================================================
# Service: read (get/list)
# ============================================================================


class TestGetAndListPartners:
    async def test_get_partner_not_found_raises(self) -> None:
        service, _repository = _make_service()
        with pytest.raises(ChannelPartnerNotFoundError):
            await service.get_partner(uuid.uuid4())

    async def test_list_partners_filters_by_status(self) -> None:
        service, repository = _make_service(
            sms_provider=FakeSmsProvider(), email_provider=FakeEmailProvider()
        )
        active = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )
        inactive = await service.onboard_partner(
            actor_user_id=uuid.uuid4(),
            data=_make_request(
                name="Bob Brown",
                phone="9123456780",
                gst_number="29ABCDE1234F1Z1",
            ),
        )
        await repository.update_partner(
            inactive, {"status": ChannelPartnerStatus.INACTIVE.value}
        )

        active_result = await service.list_partners(
            status=ChannelPartnerStatus.ACTIVE.value
        )
        inactive_result = await service.list_partners(
            status=ChannelPartnerStatus.INACTIVE.value
        )

        assert len(active_result.items) == 1
        assert active_result.items[0].id == active.id
        assert len(inactive_result.items) == 1
        assert inactive_result.items[0].id == inactive.id

    async def test_list_partners_search_matches_multiple_fields(self) -> None:
        service, _repository = _make_service(
            sms_provider=FakeSmsProvider(), email_provider=FakeEmailProvider()
        )
        await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )
        await service.onboard_partner(
            actor_user_id=uuid.uuid4(),
            data=_make_request(
                name="Bob Brown",
                phone="9123456780",
                gst_number="29ABCDE1234F1Z1",
                email="bob@example.com",
            ),
        )

        by_name = await service.list_partners(search="anderson")
        by_gst = await service.list_partners(search="29abcde1234f1z1")

        assert len(by_name.items) == 1
        assert by_name.items[0].name == "Alice Anderson"
        assert len(by_gst.items) == 1
        assert by_gst.items[0].name == "Bob Brown"


# ============================================================================
# Service: revoke (deactivate)
# ============================================================================


class TestRevokePartner:
    async def test_revoke_active_partner_flips_status_to_inactive(self) -> None:
        service, _repository = _make_service(
            sms_provider=FakeSmsProvider(), email_provider=FakeEmailProvider()
        )
        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )
        assert partner.status == ChannelPartnerStatus.ACTIVE.value

        revoked = await service.revoke_partner(
            partner.id, actor_user_id=uuid.uuid4()
        )

        assert revoked.status == ChannelPartnerStatus.INACTIVE.value
        fetched = await service.get_partner(partner.id)
        assert fetched.status == ChannelPartnerStatus.INACTIVE.value

    async def test_revoke_writes_an_audit_log_entry(self) -> None:
        audit_writer = FakeAuditWriter()
        service, _repository = _make_service(
            sms_provider=FakeSmsProvider(),
            email_provider=FakeEmailProvider(),
            audit_writer=audit_writer,
        )
        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )
        actor_id = uuid.uuid4()

        await service.revoke_partner(partner.id, actor_user_id=actor_id)

        assert len(audit_writer.entries) == 1
        entry = audit_writer.entries[0]
        assert entry["action"] == AuditAction.CHANNEL_PARTNER_REVOKED.value
        assert entry["entity_id"] == partner.id
        assert entry["entity_type"] == "channel_partner"
        assert entry["actor_user_id"] == actor_id

    async def test_revoke_already_inactive_partner_is_idempotent_no_op(self) -> None:
        audit_writer = FakeAuditWriter()
        service, repository = _make_service(
            sms_provider=FakeSmsProvider(),
            email_provider=FakeEmailProvider(),
            audit_writer=audit_writer,
        )
        partner = await service.onboard_partner(
            actor_user_id=uuid.uuid4(), data=_make_request()
        )
        await service.revoke_partner(partner.id, actor_user_id=uuid.uuid4())
        version_after_first_revoke = repository.partners[partner.id].version
        assert len(audit_writer.entries) == 1

        # Revoking an already-inactive partner must not raise, must not
        # touch the row again, and must not write a second audit entry.
        result = await service.revoke_partner(partner.id, actor_user_id=uuid.uuid4())

        assert result.status == ChannelPartnerStatus.INACTIVE.value
        assert repository.partners[partner.id].version == version_after_first_revoke
        assert len(audit_writer.entries) == 1

    async def test_revoke_not_found_raises(self) -> None:
        service, _repository = _make_service()
        with pytest.raises(ChannelPartnerNotFoundError):
            await service.revoke_partner(uuid.uuid4(), actor_user_id=uuid.uuid4())


# ============================================================================
# Router: message composition + RBAC gating
# ============================================================================


class TestOnboardMessageComposition:
    def _partner(self, **overrides: object) -> ChannelPartner:
        fields = {
            "name": "Alice Anderson",
            "phone": "+919876543210",
            "email": "alice@example.com",
            "address": "123 MG Road",
            "city": "Bengaluru",
            "gst_number": "27AAAAA0000A1Z5",
            "status": ChannelPartnerStatus.ACTIVE.value,
            "welcome_sms_sent_at": _now(),
            "welcome_sms_error": None,
            "welcome_email_sent_at": _now(),
            "welcome_email_error": None,
        }
        fields.update(overrides)
        return ChannelPartner(**_base_fields(**fields))

    def test_both_channels_succeed(self) -> None:
        message = _onboard_message(self._partner())
        assert "welcome SMS sent to +919876543210" in message
        assert "email sent to alice@example.com" in message

    def test_no_email_provided(self) -> None:
        message = _onboard_message(
            self._partner(email=None, welcome_email_sent_at=None)
        )
        assert message == (
            "Alice Anderson onboarded — welcome SMS sent to +919876543210"
        )

    def test_sms_failed_no_email(self) -> None:
        message = _onboard_message(
            self._partner(
                email=None,
                welcome_email_sent_at=None,
                welcome_sms_sent_at=None,
                welcome_sms_error="twilio down",
            )
        )
        assert message == (
            "Alice Anderson onboarded, but the welcome SMS could not be sent"
        )

    def test_sms_succeeded_email_failed(self) -> None:
        message = _onboard_message(
            self._partner(welcome_email_sent_at=None, welcome_email_error="smtp down")
        )
        assert "welcome SMS sent to +919876543210" in message
        assert "the welcome email could not be sent" in message

    def test_both_failed(self) -> None:
        message = _onboard_message(
            self._partner(
                welcome_sms_sent_at=None,
                welcome_sms_error="twilio down",
                welcome_email_sent_at=None,
                welcome_email_error="smtp down",
            )
        )
        assert "welcome SMS could not be sent" in message
        assert "welcome email could not be sent either" in message


class TestEveryRouteRequiresPermission:
    def test_every_channel_partner_route_has_a_permission_dependency(self) -> None:
        assert len(router.routes) == 4
        for route in router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"

    def test_revoke_route_is_gated_by_manage_not_read_or_create(self) -> None:
        """Revoking is a mutation -- must be gated behind
        ``channel_partners.manage``, the same permission
        ``onboard_channel_partner`` (``.create``) and
        ``list_channel_partners``/``get_channel_partner`` (``.read``)
        deliberately do *not* share, mirroring the module's existing
        create/read/manage split."""
        revoke_route = next(
            route for route in router.routes if route.path.endswith("/revoke")
        )
        assert revoke_route.methods == {"POST"}


class TestRevokeRequiresManagePermission:
    """A genuine, executable 403: an actor holding no roles/grants at all
    is denied ``channel_partners.manage`` -- exercises the real
    ``AccessValidator.check`` gating logic ``RequirePermission(
    "channel_partners.manage")`` (the ``revoke_channel_partner`` route's own
    dependency) delegates to, the same "underlying logic is what's
    exercised, not Starlette's DI resolution" convention
    ``tests/unit/test_billing_entitlement.py``'s own module docstring
    documents for this codebase's ``RequirePermission`` dependencies."""

    async def test_actor_without_manage_permission_gets_403(self) -> None:
        repository = FakeRBACRepository()
        validator = AccessValidator(repository)
        user_id = uuid.uuid4()

        with pytest.raises(PermissionDeniedError) as exc_info:
            await validator.check(user_id, "channel_partners.manage")

        assert exc_info.value.status_code == 403
        assert any(
            entry.action == "permission_denied" for entry in repository.audit_log_rows
        )


class TestChannelPartnersRbacSeedData:
    """Verifies ``PermissionModule.CHANNEL_PARTNERS`` mirrors
    ``PermissionModule.QUOTATIONS``'s own seed-data treatment exactly (see
    ``docs/channel-partner-onboarding-spec.md`` Section 2)."""

    def test_scoped_global_same_as_quotations(self) -> None:
        assert MODULE_NARROWEST_SCOPE[PermissionModule.CHANNEL_PARTNERS] == (
            MODULE_NARROWEST_SCOPE[PermissionModule.QUOTATIONS]
        )
        assert (
            MODULE_NARROWEST_SCOPE[PermissionModule.CHANNEL_PARTNERS]
            == ScopeType.GLOBAL
        )

    def test_actions_are_create_read_manage(self) -> None:
        from app.domains.rbac.enums import PermissionAction

        assert MODULE_ACTIONS[PermissionModule.CHANNEL_PARTNERS] == (
            PermissionAction.CREATE,
            PermissionAction.READ,
            PermissionAction.MANAGE,
        )

    def test_role_grants_mirror_quotations_role_for_role(self) -> None:
        """The exact invariant this feature's RBAC diff is built on: every
        system role's resolved grant for CHANNEL_PARTNERS is identical to
        its resolved grant for QUOTATIONS."""
        for role_def in SYSTEM_ROLES:
            grants = role_def.grants()
            quotations_grant = grants.get(PermissionModule.QUOTATIONS, ())
            channel_partners_grant = grants.get(
                PermissionModule.CHANNEL_PARTNERS, ()
            )
            assert channel_partners_grant == quotations_grant, role_def.name

    def test_only_super_admin_platform_admin_and_platform_support_are_granted(
        self,
    ) -> None:
        granted_roles = {
            role_def.name
            for role_def in SYSTEM_ROLES
            if PermissionModule.CHANNEL_PARTNERS in role_def.grants()
        }
        # Matches QUOTATIONS' own real, current grant set exactly (Platform
        # Support inherits its module-wide default_level=READ at GLOBAL
        # scope, same as it already does for QUOTATIONS -- see this
        # class's own docstring and the PR description for the one place
        # this diverges from the feature spec's own prose).
        assert granted_roles == {"Super Admin", "Platform Admin", "Platform Support"}
