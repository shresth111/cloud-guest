"""Unit tests for the Guest Access Control domain (Phase 1): pure
precedence resolution (``AccessDecisionResolver``), rule CRUD and
tenant-scoping (``GuestAccessService``), the ``check_access`` decision
path against both guest- and device-keyed rules, and the optional
``GuestService.access_control_hook`` integration.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_guest.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``GuestAccessService`` is exercised against a small, hand-rolled
in-memory fake for its repository -- there is no live Postgres in this
environment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.guest_access.constants import AccessRuleType
from app.domains.guest_access.exceptions import (
    AccessRuleNotFoundError,
    CountryCodeRequiredError,
    CrossOrganizationAccessRuleError,
    InvalidGuestIdentifierError,
    InvalidRuleExpiryError,
    TemporaryRuleRequiresExpiryError,
)
from app.domains.guest_access.models import DeviceAccessRule, GuestAccessRule
from app.domains.guest_access.repository import GuestAccessRepository
from app.domains.guest_access.service import (
    AccessDecision,
    AccessDecisionResolver,
    GuestAccessService,
)
from app.domains.guest_access.validators import (
    canonicalize_rule_identifier,
    identifier_match_terms,
    identifiers_match,
    is_rule_expired,
    validate_identifier_shape,
    validate_rule_expiry,
)

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
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeGuestAccessRepository:
    guest_rules: dict[uuid.UUID, GuestAccessRule] = field(default_factory=dict)
    device_rules: dict[uuid.UUID, DeviceAccessRule] = field(default_factory=dict)

    # -- guest rules -----------------------------------------------------------
    async def create_guest_rule(self, **fields: object) -> GuestAccessRule:
        rule = GuestAccessRule(**_base_fields(**fields))
        self.guest_rules[rule.id] = rule
        return rule

    async def get_guest_rule_by_id(self, rule_id: uuid.UUID) -> GuestAccessRule | None:
        return self.guest_rules.get(rule_id)

    async def update_guest_rule(
        self, rule: GuestAccessRule, data: dict[str, object]
    ) -> GuestAccessRule:
        for key, value in data.items():
            setattr(rule, key, value)
        rule.version += 1
        return rule

    async def delete_guest_rule(self, rule: GuestAccessRule) -> None:
        del self.guest_rules[rule.id]

    async def list_guest_rules(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = "created_at",
        sort_order: object = None,
    ) -> tuple[list[GuestAccessRule], object]:
        items = list(self.guest_rules.values())
        for key, value in (filters or {}).items():
            items = [i for i in items if getattr(i, key) == value]
        total = len(items)

        class _Meta:
            def __init__(self, total_items: int) -> None:
                self.page = page
                self.page_size = page_size
                self.total_items = total_items
                self.total_pages = 1
                self.has_next = False
                self.has_previous = False

        return items, _Meta(total)

    async def list_matching_guest_rules(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        identifier: str,
        now: datetime,
    ) -> list[GuestAccessRule]:
        # ``identifiers_match``, not ``==``: the real repository resolves
        # a guest against every stored spelling of the same number (see
        # ``validators.identifier_match_terms``), and a fake that still
        # compared exactly would keep passing for the exact defect this
        # domain was fixed for.
        return [
            rule
            for rule in self.guest_rules.values()
            if rule.organization_id == organization_id
            and identifiers_match(rule.identifier, identifier)
            and rule.is_active
            and not rule.is_deleted
            and (rule.location_id is None or rule.location_id == location_id)
            and (rule.expires_at is None or rule.expires_at > now)
        ]

    # -- device rules ------------------------------------------------------
    async def create_device_rule(self, **fields: object) -> DeviceAccessRule:
        rule = DeviceAccessRule(**_base_fields(**fields))
        self.device_rules[rule.id] = rule
        return rule

    async def get_device_rule_by_id(
        self, rule_id: uuid.UUID
    ) -> DeviceAccessRule | None:
        return self.device_rules.get(rule_id)

    async def update_device_rule(
        self, rule: DeviceAccessRule, data: dict[str, object]
    ) -> DeviceAccessRule:
        for key, value in data.items():
            setattr(rule, key, value)
        rule.version += 1
        return rule

    async def delete_device_rule(self, rule: DeviceAccessRule) -> None:
        del self.device_rules[rule.id]

    async def list_device_rules(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = "created_at",
        sort_order: object = None,
    ) -> tuple[list[DeviceAccessRule], object]:
        items = list(self.device_rules.values())
        for key, value in (filters or {}).items():
            items = [i for i in items if getattr(i, key) == value]
        total = len(items)

        class _Meta:
            def __init__(self, total_items: int) -> None:
                self.page = page
                self.page_size = page_size
                self.total_items = total_items
                self.total_pages = 1
                self.has_next = False
                self.has_previous = False

        return items, _Meta(total)

    async def list_matching_device_rules(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        mac_address: str,
        now: datetime,
    ) -> list[DeviceAccessRule]:
        return [
            rule
            for rule in self.device_rules.values()
            if rule.organization_id == organization_id
            and rule.mac_address == mac_address
            and rule.is_active
            and not rule.is_deleted
            and (rule.location_id is None or rule.location_id == location_id)
            and (rule.expires_at is None or rule.expires_at > now)
        ]


@dataclass
class Fixture:
    repository: FakeGuestAccessRepository
    audit_writer: FakeAuditLogWriter
    service: GuestAccessService
    organization_id: uuid.UUID
    location_id: uuid.UUID
    actor_user_id: uuid.UUID


def make_fixture() -> Fixture:
    repository = FakeGuestAccessRepository()
    audit_writer = FakeAuditLogWriter()
    # No block enforcer: this module covers rule CRUD, tenant scoping and
    # precedence resolution, none of which touch a device. The
    # device-side half -- blocking a guest actually ending the session
    # they are in -- has its own suite in
    # ``test_guest_access_block_enforcement.py``, including a test that a
    # ``None`` enforcer records ``UNENFORCED`` rather than pretending the
    # block reached a router.
    service = GuestAccessService(
        repository, block_enforcer=None, audit_writer=audit_writer
    )
    return Fixture(
        repository=repository,
        audit_writer=audit_writer,
        service=service,
        organization_id=uuid.uuid4(),
        location_id=uuid.uuid4(),
        actor_user_id=uuid.uuid4(),
    )


# ============================================================================
# Pure validators
# ============================================================================


class TestValidators:
    def test_temporary_rule_without_expiry_rejected(self) -> None:
        with pytest.raises(TemporaryRuleRequiresExpiryError):
            validate_rule_expiry(
                rule_type=AccessRuleType.TEMPORARY, expires_at=None, now=_now()
            )

    def test_temporary_rule_with_future_expiry_accepted(self) -> None:
        validate_rule_expiry(
            rule_type=AccessRuleType.TEMPORARY,
            expires_at=_now() + timedelta(hours=1),
            now=_now(),
        )  # does not raise

    def test_expiry_in_the_past_rejected_for_any_rule_type(self) -> None:
        with pytest.raises(InvalidRuleExpiryError):
            validate_rule_expiry(
                rule_type=AccessRuleType.BLOCKLIST,
                expires_at=_now() - timedelta(hours=1),
                now=_now(),
            )

    def test_permanent_rule_types_may_omit_expiry(self) -> None:
        for rule_type in (
            AccessRuleType.WHITELIST,
            AccessRuleType.BLOCKLIST,
            AccessRuleType.VIP,
        ):
            validate_rule_expiry(rule_type=rule_type, expires_at=None, now=_now())

    def test_is_rule_expired_pure_function(self) -> None:
        now = _now()
        assert is_rule_expired(None, now=now) is False
        assert is_rule_expired(now - timedelta(minutes=1), now=now) is True
        assert is_rule_expired(now + timedelta(minutes=1), now=now) is False

    @pytest.mark.parametrize(
        "identifier",
        [
            "guest@example.com",
            "a@b.co",
            "+919876543210",
            "+14155552671",
        ],
    )
    def test_validate_identifier_shape_accepts_phone_or_email(
        self, identifier: str
    ) -> None:
        validate_identifier_shape(identifier)  # does not raise

    @pytest.mark.parametrize("identifier", ["919876543210", "14155552671"])
    def test_validate_identifier_shape_rejects_missing_country_code(
        self, identifier: str
    ) -> None:
        # These two used to pass -- the old ``_PHONE_RE`` made the "+"
        # optional, which is what let the customer dashboard write rules
        # that could never match a guest (2026-09). A number without a
        # country code is now refused at the door, and with its own
        # exception: it is under-specified, not malformed, and the admin
        # needs different words in front of them.
        with pytest.raises(CountryCodeRequiredError):
            validate_identifier_shape(identifier)

    @pytest.mark.parametrize(
        "identifier",
        [
            "",
            "not-an-identifier",
            "guest@",
            "@example.com",
            "guest@example",
            "12345",  # too short to be a plausible phone number
            "AA:BB:CC:DD:EE:FF",  # a MAC belongs on DeviceAccessRule, not here
        ],
    )
    def test_validate_identifier_shape_rejects_garbage(self, identifier: str) -> None:
        with pytest.raises(InvalidGuestIdentifierError):
            validate_identifier_shape(identifier)


# ============================================================================
# AccessDecisionResolver: pure precedence
# ============================================================================


def _guest_rule(
    rule_type: AccessRuleType, reason: str | None = None
) -> GuestAccessRule:
    return GuestAccessRule(
        **_base_fields(
            organization_id=uuid.uuid4(),
            location_id=None,
            identifier="guest@example.com",
            rule_type=rule_type.value,
            reason=reason,
            expires_at=None,
            is_active=True,
        )
    )


def _device_rule(
    rule_type: AccessRuleType, reason: str | None = None
) -> DeviceAccessRule:
    return DeviceAccessRule(
        **_base_fields(
            organization_id=uuid.uuid4(),
            location_id=None,
            mac_address="AA:BB:CC:DD:EE:FF",
            rule_type=rule_type.value,
            reason=reason,
            expires_at=None,
            is_active=True,
        )
    )


class TestAccessDecisionResolver:
    def test_no_rules_defaults_to_allow(self) -> None:
        resolver = AccessDecisionResolver()
        decision = resolver.resolve(guest_rules=[], device_rules=[])
        assert decision == AccessDecision(
            allowed=True, rule_type=None, matched_rule_id=None, reason=None
        )

    def test_blocklist_denies(self) -> None:
        rule = _guest_rule(AccessRuleType.BLOCKLIST, reason="abuse")
        resolver = AccessDecisionResolver()
        decision = resolver.resolve(guest_rules=[rule], device_rules=[])
        assert decision.allowed is False
        assert decision.rule_type == AccessRuleType.BLOCKLIST
        assert decision.matched_rule_id == rule.id
        assert decision.reason == "abuse"

    def test_whitelist_allows_explicitly(self) -> None:
        rule = _guest_rule(AccessRuleType.WHITELIST)
        resolver = AccessDecisionResolver()
        decision = resolver.resolve(guest_rules=[rule], device_rules=[])
        assert decision.allowed is True
        assert decision.rule_type == AccessRuleType.WHITELIST

    def test_vip_overrides_blocklist_for_the_same_identifier(self) -> None:
        blocklist = _guest_rule(AccessRuleType.BLOCKLIST)
        vip = _guest_rule(AccessRuleType.VIP)
        resolver = AccessDecisionResolver()
        decision = resolver.resolve(guest_rules=[blocklist, vip], device_rules=[])
        assert decision.allowed is True
        assert decision.rule_type == AccessRuleType.VIP

    def test_temporary_outranks_blocklist_but_not_vip(self) -> None:
        resolver = AccessDecisionResolver()
        blocklist = _guest_rule(AccessRuleType.BLOCKLIST)
        temporary = _guest_rule(AccessRuleType.TEMPORARY)
        decision = resolver.resolve(guest_rules=[blocklist, temporary], device_rules=[])
        assert decision.allowed is True
        assert decision.rule_type == AccessRuleType.TEMPORARY

        vip = _guest_rule(AccessRuleType.VIP)
        decision_with_vip = resolver.resolve(
            guest_rules=[blocklist, temporary, vip], device_rules=[]
        )
        assert decision_with_vip.rule_type == AccessRuleType.VIP

    def test_device_vip_overrides_guest_blocklist(self) -> None:
        """A VIP-tagged device outranks a blocklisted guest identity --
        precedence is resolved across both candidate sets together, neither
        table taking blanket priority over the other."""
        guest_blocklist = _guest_rule(AccessRuleType.BLOCKLIST)
        device_vip = _device_rule(AccessRuleType.VIP)
        resolver = AccessDecisionResolver()
        decision = resolver.resolve(
            guest_rules=[guest_blocklist], device_rules=[device_vip]
        )
        assert decision.allowed is True
        assert decision.rule_type == AccessRuleType.VIP
        assert decision.matched_rule_id == device_vip.id

    def test_device_blocklist_denies_even_with_no_guest_rule(self) -> None:
        device_blocklist = _device_rule(AccessRuleType.BLOCKLIST)
        resolver = AccessDecisionResolver()
        decision = resolver.resolve(guest_rules=[], device_rules=[device_blocklist])
        assert decision.allowed is False
        assert decision.rule_type == AccessRuleType.BLOCKLIST


# ============================================================================
# GuestAccessService: guest (identifier-keyed) rule CRUD
# ============================================================================


class TestGuestRuleCrud:
    async def test_create_and_get_guest_rule(self) -> None:
        fx = make_fixture()
        rule = await fx.service.create_guest_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier="  guest@example.com  ",
            rule_type=AccessRuleType.BLOCKLIST,
            reason="repeated abuse",
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        # normalize_identifier (reused from app.domains.guest.validators)
        # only strips surrounding whitespace -- it is deliberately
        # unopinionated about case, matching that function's own docstring.
        assert rule.identifier == "guest@example.com"
        assert rule.rule_type == AccessRuleType.BLOCKLIST.value
        assert rule.is_active is True
        fetched = await fx.service.get_guest_rule(
            rule.id, requesting_organization_id=fx.organization_id
        )
        assert fetched.id == rule.id
        assert len(fx.audit_writer.entries) == 1
        assert fx.audit_writer.entries[0]["action"] == "guest_access_rule_created"

    async def test_create_guest_rule_accepts_phone_identifier(self) -> None:
        # The customer dashboard's Block User dialog can submit either a
        # mobile number or an email address -- both are valid
        # GuestAccessRule.identifier shapes (see validators
        # .validate_identifier_shape's docstring).
        fx = make_fixture()
        rule = await fx.service.create_guest_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier="+919876543210",
            rule_type=AccessRuleType.BLOCKLIST,
            reason="spam",
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        assert rule.identifier == "+919876543210"
        assert rule.rule_type == AccessRuleType.BLOCKLIST.value

    async def test_create_guest_rule_rejects_malformed_identifier(self) -> None:
        fx = make_fixture()
        with pytest.raises(InvalidGuestIdentifierError):
            await fx.service.create_guest_rule(
                organization_id=fx.organization_id,
                requesting_organization_id=fx.organization_id,
                location_id=fx.location_id,
                identifier="not-a-phone-or-email",
                rule_type=AccessRuleType.BLOCKLIST,
                reason=None,
                expires_at=None,
                actor_user_id=fx.actor_user_id,
            )

    async def test_create_temporary_rule_without_expiry_rejected(self) -> None:
        fx = make_fixture()
        with pytest.raises(TemporaryRuleRequiresExpiryError):
            await fx.service.create_guest_rule(
                organization_id=fx.organization_id,
                requesting_organization_id=fx.organization_id,
                location_id=None,
                identifier="temp@example.com",
                rule_type=AccessRuleType.TEMPORARY,
                reason=None,
                expires_at=None,
                actor_user_id=fx.actor_user_id,
            )

    async def test_create_rule_for_another_organization_rejected(self) -> None:
        fx = make_fixture()
        other_org = uuid.uuid4()
        with pytest.raises(CrossOrganizationAccessRuleError):
            await fx.service.create_guest_rule(
                organization_id=other_org,
                requesting_organization_id=fx.organization_id,
                location_id=None,
                identifier="guest@example.com",
                rule_type=AccessRuleType.BLOCKLIST,
                reason=None,
                expires_at=None,
                actor_user_id=fx.actor_user_id,
            )

    async def test_get_rule_not_found(self) -> None:
        fx = make_fixture()
        with pytest.raises(AccessRuleNotFoundError):
            await fx.service.get_guest_rule(uuid.uuid4())

    async def test_get_rule_cross_organization_rejected(self) -> None:
        fx = make_fixture()
        rule = await fx.service.create_guest_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,
            identifier="guest@example.com",
            rule_type=AccessRuleType.BLOCKLIST,
            reason=None,
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        other_org = uuid.uuid4()
        with pytest.raises(CrossOrganizationAccessRuleError):
            await fx.service.get_guest_rule(
                rule.id, requesting_organization_id=other_org
            )

    async def test_deactivate_guest_rule(self) -> None:
        fx = make_fixture()
        rule = await fx.service.create_guest_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,
            identifier="guest@example.com",
            rule_type=AccessRuleType.WHITELIST,
            reason=None,
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        deactivated = await fx.service.deactivate_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=fx.actor_user_id,
        )
        assert deactivated.is_active is False

    async def test_delete_guest_rule(self) -> None:
        fx = make_fixture()
        rule = await fx.service.create_guest_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,
            identifier="guest@example.com",
            rule_type=AccessRuleType.WHITELIST,
            reason=None,
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        await fx.service.delete_guest_rule(
            rule_id=rule.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=fx.actor_user_id,
        )
        with pytest.raises(AccessRuleNotFoundError):
            await fx.service.get_guest_rule(rule.id)
        delete_entries = [
            e
            for e in fx.audit_writer.entries
            if e["action"] == "guest_access_rule_deleted"
        ]
        assert len(delete_entries) == 1

    async def test_list_guest_rules_scoped_to_organization(self) -> None:
        fx = make_fixture()
        await fx.service.create_guest_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,
            identifier="a@example.com",
            rule_type=AccessRuleType.WHITELIST,
            reason=None,
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        other_org = uuid.uuid4()
        await fx.service.create_guest_rule(
            organization_id=other_org,
            requesting_organization_id=other_org,
            location_id=None,
            identifier="b@example.com",
            rule_type=AccessRuleType.WHITELIST,
            reason=None,
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        result = await fx.service.list_guest_rules(
            requesting_organization_id=fx.organization_id
        )
        assert result.meta.total_items == 1
        assert result.items[0].identifier == "a@example.com"


# ============================================================================
# GuestAccessService: check_access decision path
# ============================================================================


class TestCheckAccess:
    async def test_default_allow_when_no_rules_match(self) -> None:
        fx = make_fixture()
        decision = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier="nobody@example.com",
            mac_address=None,
        )
        assert decision.allowed is True
        assert decision.rule_type is None

    async def test_org_wide_blocklist_denies_at_any_location(self) -> None:
        fx = make_fixture()
        await fx.service.create_guest_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,  # org-wide
            identifier="blocked@example.com",
            rule_type=AccessRuleType.BLOCKLIST,
            reason="fraud",
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        decision = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=uuid.uuid4(),  # a different, arbitrary location
            identifier="blocked@example.com",
            mac_address=None,
        )
        assert decision.allowed is False
        assert decision.reason == "fraud"

    async def test_location_scoped_rule_does_not_apply_elsewhere(self) -> None:
        fx = make_fixture()
        await fx.service.create_guest_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier="scoped@example.com",
            rule_type=AccessRuleType.BLOCKLIST,
            reason=None,
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        other_location = uuid.uuid4()
        decision = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=other_location,
            identifier="scoped@example.com",
            mac_address=None,
        )
        assert decision.allowed is True  # rule doesn't apply at this location

    async def test_expired_temporary_rule_no_longer_applies(self) -> None:
        fx = make_fixture()
        rule = await fx.service.create_guest_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,
            identifier="temp@example.com",
            rule_type=AccessRuleType.TEMPORARY,
            reason=None,
            expires_at=_now() + timedelta(minutes=5),
            actor_user_id=fx.actor_user_id,
        )
        # Force it into the past directly on the fake's stored row --
        # simulates time passing without needing to sleep in a test.
        fx.repository.guest_rules[rule.id].expires_at = _now() - timedelta(minutes=1)

        decision = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,
            identifier="temp@example.com",
            mac_address=None,
        )
        assert decision.allowed is True
        assert decision.rule_type is None  # no longer matched -- default allow

    async def test_device_rule_matched_by_mac_address(self) -> None:
        fx = make_fixture()
        await fx.service.create_device_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,
            mac_address="aa:bb:cc:dd:ee:ff",
            rule_type=AccessRuleType.BLOCKLIST,
            reason="stolen device",
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        decision = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,
            identifier=None,
            mac_address="AA:BB:CC:DD:EE:FF",  # normalized to match
        )
        assert decision.allowed is False
        assert decision.reason == "stolen device"

    async def test_check_access_cross_organization_rejected(self) -> None:
        fx = make_fixture()
        other_org = uuid.uuid4()
        with pytest.raises(CrossOrganizationAccessRuleError):
            await fx.service.check_access(
                organization_id=other_org,
                requesting_organization_id=fx.organization_id,
                location_id=None,
                identifier="guest@example.com",
                mac_address=None,
            )


# ============================================================================
# Identifier normalization: the 2026-09 "Always Allowed matches nobody" fix
# ============================================================================


def _legacy_rule(
    fx: Fixture,
    *,
    identifier: str,
    rule_type: AccessRuleType = AccessRuleType.WHITELIST,
    reason: str | None = None,
) -> GuestAccessRule:
    """Writes a rule straight into the repository, bypassing the service.

    Not laziness -- necessity. ``create_guest_rule`` now refuses the very
    shape these tests are about, and this is exactly how those rows got
    into production: the customer dashboard's Always Allowed / Block User
    forms POSTed bare national digits, the API stored them verbatim, and
    nothing downstream could ever match them again.
    """
    rule = GuestAccessRule(
        **_base_fields(
            organization_id=fx.organization_id,
            location_id=None,
            identifier=identifier,
            rule_type=rule_type.value,
            reason=reason,
            email=None,
            expires_at=None,
            is_active=True,
        )
    )
    fx.repository.guest_rules[rule.id] = rule
    return rule


class TestIdentifierCanonicalization:
    def test_bare_national_number_is_refused_not_guessed(self) -> None:
        # Nothing server-side knows which country "9876543210" belongs to.
        # Prefixing one would put the same class of unmatchable row in the
        # table for a new reason, so the write is refused instead.
        with pytest.raises(CountryCodeRequiredError):
            validate_identifier_shape("9876543210")

    def test_rejection_message_tells_the_admin_what_to_do(self) -> None:
        with pytest.raises(CountryCodeRequiredError) as excinfo:
            validate_identifier_shape("9876543210")
        message = str(excinfo.value)
        assert "country code" in message
        assert "+919876543210" in message

    @pytest.mark.parametrize(
        ("submitted", "stored"),
        [
            ("  +919876543210  ", "+919876543210"),
            ("+91 98765 43210", "+919876543210"),
            ("+91-98765-43210", "+919876543210"),
            ("+1 (415) 555-2671", "+14155552671"),
        ],
    )
    def test_human_formatting_is_stripped_not_rejected(
        self, submitted: str, stored: str
    ) -> None:
        # An admin bounced for punctuation retypes the number without the
        # "+" next, which is the one shape this domain must keep out of
        # the table -- so punctuation is absorbed, not punished.
        canonical = canonicalize_rule_identifier(submitted)
        assert canonical == stored
        validate_identifier_shape(canonical)  # does not raise

    def test_email_identifiers_are_left_alone(self) -> None:
        # Case-folding emails would be an unrelated behaviour change to a
        # column ``Guest.identifier`` compares case-sensitively.
        assert canonicalize_rule_identifier("  Guest@Example.com ") == (
            "Guest@Example.com"
        )

    async def test_create_guest_rule_stores_e164(self) -> None:
        fx = make_fixture()
        rule = await fx.service.create_guest_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier="+91 98765 43210",
            rule_type=AccessRuleType.WHITELIST,
            reason="owner's family",
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        assert rule.identifier == "+919876543210"

    async def test_create_guest_rule_refuses_bare_national_number(self) -> None:
        fx = make_fixture()
        with pytest.raises(CountryCodeRequiredError):
            await fx.service.create_guest_rule(
                organization_id=fx.organization_id,
                requesting_organization_id=fx.organization_id,
                location_id=fx.location_id,
                identifier="9876543210",
                rule_type=AccessRuleType.WHITELIST,
                reason=None,
                expires_at=None,
                actor_user_id=fx.actor_user_id,
            )
        assert fx.repository.guest_rules == {}


class TestLegacyIdentifierMatching:
    async def test_bare_digit_rule_matches_e164_guest(self) -> None:
        # The failure that was live: every row the Always Allowed form
        # ever wrote is bare national digits, every guest signs in as
        # E.164, and rules were resolved by string equality -- so no rule
        # that screen wrote could match anybody. Under the per-property
        # whitelist-only mode this same unchanged data refuses every
        # guest at the property, staff included.
        fx = make_fixture()
        _legacy_rule(fx, identifier="9876543210", reason="owner's family")
        decision = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier="+919876543210",
            mac_address=None,
        )
        assert decision.rule_type == AccessRuleType.WHITELIST.value
        assert decision.allowed is True

    async def test_bare_digit_blocklist_rule_still_denies(self) -> None:
        # The same row shape on the deny side: a block written by that
        # form let the blocked guest straight back on.
        fx = make_fixture()
        _legacy_rule(
            fx,
            identifier="9876543210",
            rule_type=AccessRuleType.BLOCKLIST,
            reason="repeated abuse",
        )
        decision = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier="+919876543210",
            mac_address=None,
        )
        assert decision.allowed is False
        assert decision.reason == "repeated abuse"

    async def test_e164_rule_matches_bare_digit_guest(self) -> None:
        # The reverse direction. A canonically-written rule must not go
        # inert the moment a portal (or a NAS forwarding whatever the
        # browser POSTed) sends the number without its country code.
        fx = make_fixture()
        await fx.service.create_guest_rule(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=None,
            identifier="+919876543210",
            rule_type=AccessRuleType.VIP,
            reason="regular",
            expires_at=None,
            actor_user_id=fx.actor_user_id,
        )
        decision = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier="9876543210",
            mac_address=None,
        )
        assert decision.rule_type == AccessRuleType.VIP.value

    async def test_country_code_without_plus_also_matches(self) -> None:
        # The third spelling the old, "+"-optional regex accepted and the
        # table therefore holds.
        fx = make_fixture()
        _legacy_rule(fx, identifier="919876543210")
        decision = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier="+919876543210",
            mac_address=None,
        )
        assert decision.rule_type == AccessRuleType.WHITELIST.value

    async def test_a_different_number_still_does_not_match(self) -> None:
        # The widening is bounded at one country code, not "ends with".
        fx = make_fixture()
        _legacy_rule(fx, identifier="9876543210", rule_type=AccessRuleType.BLOCKLIST)
        decision = await fx.service.check_access(
            organization_id=fx.organization_id,
            requesting_organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier="+919876500000",
            mac_address=None,
        )
        assert decision.allowed is True
        assert decision.rule_type is None

    @pytest.mark.parametrize(
        ("stored", "incoming"),
        [
            ("guest@example.com", "other@example.com"),
            ("guest@example.com", "+919876543210"),
            ("+919876543210", "guest@example.com"),
            # Never widen what cannot be proved to be a phone number.
            ("123456", "+91123456"),
        ],
    )
    def test_non_phone_identifiers_are_never_widened(
        self, stored: str, incoming: str
    ) -> None:
        assert identifiers_match(stored, incoming) is False

    def test_identical_email_still_matches(self) -> None:
        assert identifiers_match("guest@example.com", " guest@example.com ") is True


class TestMatchTermsAndSqlAgree:
    """The Python mirror (``identifiers_match``, used by this module's fake
    repository) and the real SQL clause must not drift -- one of them is
    what the tests above exercise and the other is what production runs,
    and there is no live Postgres here to run both against."""

    async def test_repository_statement_carries_every_match_term(self) -> None:
        captured: list[object] = []

        class _Result:
            def scalars(self) -> _Result:
                return self

            def all(self) -> list[GuestAccessRule]:
                return []

        class _Session:
            async def execute(self, statement: object) -> _Result:
                captured.append(statement)
                return _Result()

        repository = GuestAccessRepository(_Session())  # type: ignore[arg-type]
        await repository.list_matching_guest_rules(
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            identifier="+919876543210",
            now=_now(),
        )
        compiled = str(
            captured[0].compile(  # type: ignore[attr-defined]
                compile_kwargs={"literal_binds": True}
            )
        )
        terms = identifier_match_terms("+919876543210")
        assert "9876543210" in terms.exact  # the legacy shape, spelled out
        for term in terms.exact:
            assert f"'{term}'" in compiled
        for pattern in terms.prefix_patterns:
            assert f"'{pattern}'" in compiled
        assert "LIKE" in compiled.upper()
