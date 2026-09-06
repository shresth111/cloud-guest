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
from pydantic import ValidationError

from app.domains.guest_access.constants import (
    MAX_IMPORT_BATCH_SIZE,
    AccessRuleType,
    GuestRuleImportRejectionCode,
)
from app.domains.guest_access.exceptions import (
    AccessRuleNotFoundError,
    CountryCodeRequiredError,
    CrossOrganizationAccessRuleError,
    InvalidGuestIdentifierError,
    InvalidRuleExpiryError,
    OrganizationRequiredError,
    TemporaryRuleRequiresExpiryError,
)
from app.domains.guest_access.models import DeviceAccessRule, GuestAccessRule
from app.domains.guest_access.repository import GuestAccessRepository
from app.domains.guest_access.router import router as guest_access_router
from app.domains.guest_access.schemas import GuestAccessRuleImportRequest
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

    async def find_guest_rule_for_import(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        identifier: str,
        rule_type: str,
    ) -> GuestAccessRule | None:
        # Mirrors ``GuestAccessRepository.find_guest_rule_for_import``'s
        # candidate set: the canonical spelling plus the "+"-less ones a
        # pre-2026-09 row is in, and deliberately *not* the "+"-carrying
        # widened terms the read path uses. See that method for why a
        # write must match more narrowly than a read.
        candidates = {
            spelling
            for spelling in identifier_match_terms(identifier).exact
            if not spelling.startswith("+")
        } | {identifier}
        matches = [
            rule
            for rule in self.guest_rules.values()
            if rule.organization_id == organization_id
            and rule.location_id == location_id
            and rule.identifier in candidates
            and rule.rule_type == rule_type
            and not rule.is_deleted
        ]
        if not matches:
            return None
        # Canonical first, as the SQL ORDER BY does.
        matches.sort(key=lambda rule: rule.identifier != identifier)
        return matches[0]

    async def list_all_guest_rules_for_organization(
        self, organization_id: uuid.UUID
    ) -> list[GuestAccessRule]:
        return [
            rule
            for rule in self.guest_rules.values()
            if rule.organization_id == organization_id and not rule.is_deleted
        ]

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
            # Excel and Google Sheets autocorrect a typed hyphen into
            # U+2011 without telling anyone, and a bulk import is fed
            # straight out of a spreadsheet.
            ("+91\u201198765\u201143210", "+919876543210"),
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


# ============================================================================
# Bulk import / export
#
# The endpoint exists because a per-property whitelist-only mode makes the
# Always Allowed list the entire guest population of a venue -- a 200-room
# hotel cannot type that in one number at a time. These tests pin the four
# decisions that make it safe to point at a whole property: per-row
# rejection, server-side canonicalisation, upsert-on-repeat, and the
# refusal to bulk-write blocks.
# ============================================================================


async def _import(
    f: Fixture,
    rows: list[dict[str, object]],
    **overrides: object,
) -> object:
    kwargs: dict[str, object] = {
        "organization_id": f.organization_id,
        "requesting_organization_id": f.organization_id,
        "default_location_id": None,
        "default_rule_type": AccessRuleType.WHITELIST,
        "default_expires_at": None,
        "rows": rows,
        "actor_user_id": f.actor_user_id,
    }
    kwargs.update(overrides)
    return await f.service.import_guest_rules(**kwargs)


class TestBulkImport:
    async def test_one_bad_row_does_not_cost_the_batch(self) -> None:
        f = make_fixture()
        result = await _import(
            f,
            [
                {"identifier": "+919876543210"},
                {"identifier": "not a number at all"},
                {"identifier": "+919876543211"},
            ],
        )
        assert result.imported_count == 2
        assert len(result.rejected) == 1
        assert result.rejected[0].row_number == 2
        assert (
            result.rejected[0].code == GuestRuleImportRejectionCode.MALFORMED_IDENTIFIER
        )

    async def test_national_format_row_is_rejected_with_an_instruction(self) -> None:
        f = make_fixture()
        result = await _import(f, [{"identifier": "9876543210"}])
        assert result.imported_count == 0
        assert (
            result.rejected[0].code
            == GuestRuleImportRejectionCode.COUNTRY_CODE_REQUIRED
        )
        # Never accepted-and-stored-wrong: the message has to say what to
        # send instead, because the operator is holding a spreadsheet.
        assert "+91" in result.rejected[0].reason

    async def test_stored_identifier_is_canonical_not_as_submitted(self) -> None:
        f = make_fixture()
        await _import(f, [{"identifier": "+91 98765 43210"}])
        stored = next(iter(f.repository.guest_rules.values()))
        assert stored.identifier == "+919876543210"

    async def test_repeat_row_updates_rather_than_duplicating(self) -> None:
        f = make_fixture()
        first = await _import(f, [{"identifier": "+919876543210"}])
        later = _now() + timedelta(days=1)
        second = await _import(
            f, [{"identifier": "+919876543210"}], default_expires_at=later
        )
        assert first.imported_count == 1
        assert second.imported_count == 0
        assert second.updated_count == 1
        # One row, not two -- otherwise a nightly re-upload grows the table
        # by a full list a night and every login matches N copies.
        assert len(f.repository.guest_rules) == 1
        assert next(iter(f.repository.guest_rules.values())).expires_at == later

    async def test_a_guest_listed_twice_in_one_file_writes_one_row(self) -> None:
        f = make_fixture()
        later = _now() + timedelta(days=2)
        result = await _import(
            f,
            [
                {"identifier": "+919876543210"},
                {"identifier": "+919876543210", "expires_at": later},
            ],
        )
        # A two-sheet spreadsheet really does produce this. One row, last
        # occurrence wins.
        assert result.imported_count == 1
        assert result.updated_count == 1
        assert len(f.repository.guest_rules) == 1
        assert next(iter(f.repository.guest_rules.values())).expires_at == later

    async def test_a_pre_e164_row_is_repaired_not_duplicated(self) -> None:
        # Every rule written before the 2026-09 fix is a bare national
        # number that matches nobody. Without this, the first upload after
        # that fix files a canonical row beside every dead one and the
        # venue ends up holding two rows per guest.
        f = make_fixture()
        legacy = _legacy_rule(f, identifier="9876543210")
        result = await _import(f, [{"identifier": "+919876543210"}])
        assert result.imported_count == 0
        assert result.updated_count == 1
        assert len(f.repository.guest_rules) == 1
        # The import is the one moment a human supplies the country code
        # no migration could invent -- so it is taken.
        assert legacy.identifier == "+919876543210"

    async def test_a_pre_e164_row_of_a_different_number_is_left_alone(self) -> None:
        # The read path treats "+19876543210" (a US number) as a possible
        # spelling of "+919876543210" and accepts that looseness because
        # the alternative is every legacy rule dead. A *write* cannot: a
        # false match here relabels a real person's rule with someone
        # else's number and leaves no record of the old value. Anything
        # already carrying a "+" is already canonical and is never
        # rewritten.
        f = make_fixture()
        someone_else = _legacy_rule(f, identifier="+19876543210")
        result = await _import(f, [{"identifier": "+919876543210"}])
        assert result.imported_count == 1
        assert result.updated_count == 0
        assert someone_else.identifier == "+19876543210"

    async def test_expired_row_is_revived_not_reported_as_duplicate(self) -> None:
        f = make_fixture()
        await _import(f, [{"identifier": "+919876543210"}])
        stored = next(iter(f.repository.guest_rules.values()))
        stored.expires_at = _now() - timedelta(days=1)
        stored.is_active = False
        checkout = _now() + timedelta(days=2)
        result = await _import(
            f, [{"identifier": "+919876543210"}], default_expires_at=checkout
        )
        # A guest who checked out on Tuesday and checks in on Friday is the
        # same person. "Already exists" would leave them offline behind a
        # green success message.
        assert result.updated_count == 1
        assert stored.expires_at == checkout
        assert stored.is_active is True

    async def test_blocklist_rows_are_refused(self) -> None:
        f = make_fixture()
        result = await _import(
            f,
            [{"identifier": "+919876543210", "rule_type": AccessRuleType.BLOCKLIST}],
        )
        assert result.imported_count == 0
        assert (
            result.rejected[0].code
            == GuestRuleImportRejectionCode.RULE_TYPE_NOT_IMPORTABLE
        )

    async def test_unknown_rule_type_is_rejected_per_row(self) -> None:
        f = make_fixture()
        result = await _import(
            f, [{"identifier": "+919876543210", "rule_type": "platinum"}]
        )
        assert result.rejected[0].code == GuestRuleImportRejectionCode.UNKNOWN_RULE_TYPE

    async def test_batch_expiry_applies_to_every_row(self) -> None:
        f = make_fixture()
        checkout = _now() + timedelta(hours=12)
        await _import(
            f,
            [{"identifier": f"+91987654321{n}"} for n in range(3)],
            default_expires_at=checkout,
        )
        assert all(
            rule.expires_at == checkout for rule in f.repository.guest_rules.values()
        )

    async def test_row_expiry_overrides_the_batch_default(self) -> None:
        f = make_fixture()
        batch = _now() + timedelta(hours=12)
        own = _now() + timedelta(days=3)
        await _import(
            f,
            [
                {"identifier": "+919876543210"},
                {"identifier": "+919876543211", "expires_at": own},
            ],
            default_expires_at=batch,
        )
        by_identifier = {
            rule.identifier: rule for rule in f.repository.guest_rules.values()
        }
        assert by_identifier["+919876543210"].expires_at == batch
        assert by_identifier["+919876543211"].expires_at == own

    async def test_a_blank_expiry_cell_inherits_the_batch_expiry(self) -> None:
        # A blank cell arrives as "" from one CSV client and null from the
        # next. Either becoming "permanent" would leave a departed guest on
        # the network indefinitely while every row around them expires.
        f = make_fixture()
        checkout = _now() + timedelta(hours=12)
        await _import(
            f,
            [
                {"identifier": "+919876543210", "expires_at": ""},
                {"identifier": "+919876543211", "expires_at": None},
            ],
            default_expires_at=checkout,
        )
        assert all(
            rule.expires_at == checkout for rule in f.repository.guest_rules.values()
        )

    async def test_a_permanent_staff_list_carries_no_expiry(self) -> None:
        f = make_fixture()
        await _import(f, [{"identifier": "staff@hotel.example"}])
        assert next(iter(f.repository.guest_rules.values())).expires_at is None

    async def test_past_expiry_is_rejected_per_row(self) -> None:
        f = make_fixture()
        result = await _import(
            f,
            [{"identifier": "+919876543210", "expires_at": _now() - timedelta(days=1)}],
        )
        assert result.rejected[0].code == GuestRuleImportRejectionCode.INVALID_EXPIRY

    async def test_temporary_row_without_any_expiry_is_rejected(self) -> None:
        f = make_fixture()
        result = await _import(
            f,
            [{"identifier": "+919876543210", "rule_type": AccessRuleType.TEMPORARY}],
        )
        assert result.rejected[0].code == GuestRuleImportRejectionCode.INVALID_EXPIRY

    async def test_one_bad_cell_never_fails_the_whole_batch(self) -> None:
        # The failure mode a strongly-typed row schema would have caused:
        # FastAPI answering 422 for all 200 rows because one guest's email
        # column picked up a stray character. Every one of these is a row
        # to report, not a batch to lose.
        f = make_fixture()
        result = await _import(
            f,
            [
                {"identifier": "+919876543210"},
                {"identifier": "+919876543211", "email": "not-an-email"},
                {"identifier": "+919876543212", "location_id": "not-a-uuid"},
                {"identifier": "+919876543213", "expires_at": "07/09/2026"},
                {"identifier": ""},
                {"identifier": "+919876543215"},
            ],
        )
        assert result.imported_count == 2
        assert [row.code for row in result.rejected] == [
            GuestRuleImportRejectionCode.INVALID_CONTACT_EMAIL,
            GuestRuleImportRejectionCode.INVALID_LOCATION_ID,
            GuestRuleImportRejectionCode.INVALID_EXPIRY,
            GuestRuleImportRejectionCode.MALFORMED_IDENTIFIER,
        ]
        assert [row.row_number for row in result.rejected] == [2, 3, 4, 5]

    async def test_iso_strings_parse_so_an_export_re_imports(self) -> None:
        f = make_fixture()
        checkout = _now() + timedelta(days=1)
        await _import(
            f,
            [{"identifier": "+919876543210", "expires_at": checkout.isoformat()}],
        )
        stored = next(iter(f.repository.guest_rules.values()))
        assert stored.expires_at == checkout

    async def test_a_naive_expiry_is_read_as_utc_not_crashed_on(self) -> None:
        # A naive datetime compared against datetime.now(UTC) raises
        # TypeError, which escapes CORSMiddleware and reaches the browser
        # as a CORS failure -- see schemas._assume_utc_if_naive.
        f = make_fixture()
        naive = (_now() + timedelta(days=1)).replace(tzinfo=None).isoformat()
        result = await _import(
            f, [{"identifier": "+919876543210", "expires_at": naive}]
        )
        assert result.imported_count == 1
        assert next(iter(f.repository.guest_rules.values())).expires_at.tzinfo

    async def test_cross_organization_import_is_refused_outright(self) -> None:
        f = make_fixture()
        with pytest.raises(CrossOrganizationAccessRuleError):
            await _import(
                f, [{"identifier": "+919876543210"}], organization_id=uuid.uuid4()
            )

    async def test_confined_caller_cannot_import_into_another_site(self) -> None:
        f = make_fixture()
        f.service.caller_location_scope = frozenset({f.location_id})
        other_site = uuid.uuid4()
        result = await _import(
            f,
            [
                {"identifier": "+919876543210", "location_id": f.location_id},
                {"identifier": "+919876543211", "location_id": other_site},
            ],
        )
        # Checked per row on the *effective* location, so row two cannot
        # smuggle a rule to another site behind a well-formed batch default.
        assert result.imported_count == 1
        assert (
            result.rejected[0].code
            == GuestRuleImportRejectionCode.LOCATION_OUT_OF_SCOPE
        )

    async def test_batch_writes_one_audit_row_not_one_per_rule(self) -> None:
        f = make_fixture()
        await _import(f, [{"identifier": f"+91987654321{n}"} for n in range(5)])
        assert len(f.audit_writer.entries) == 1
        assert f.audit_writer.entries[0]["action"] == "guest_access_rules_imported"

    async def test_an_imported_whitelist_never_overrides_a_block(self) -> None:
        f = make_fixture()
        await f.service.create_guest_rule(
            organization_id=f.organization_id,
            requesting_organization_id=f.organization_id,
            location_id=None,
            identifier="+919876543210",
            rule_type=AccessRuleType.BLOCKLIST,
            reason="chargeback",
            expires_at=None,
            actor_user_id=f.actor_user_id,
        )
        await _import(f, [{"identifier": "+919876543210"}])
        decision = await f.service.check_access(
            organization_id=f.organization_id,
            requesting_organization_id=f.organization_id,
            location_id=None,
            identifier="+919876543210",
            mac_address=None,
        )
        # WHITELIST ranks below BLOCKLIST in ACCESS_RULE_TYPE_PRECEDENCE.
        # That is correct and must stay correct: a bulk upload must not be
        # able to un-block someone by accident.
        assert decision.allowed is False


class TestBulkImportRequestBounds:
    def test_a_thousand_rows_is_accepted(self) -> None:
        payload = GuestAccessRuleImportRequest(
            organization_id=uuid.uuid4(),
            rules=[
                {"identifier": f"+9198765{n:05d}"} for n in range(MAX_IMPORT_BATCH_SIZE)
            ],
        )
        assert len(payload.rules) == MAX_IMPORT_BATCH_SIZE

    def test_one_more_is_refused_before_anything_is_written(self) -> None:
        # A 422 out of pydantic, not a partial import of the first 1000.
        with pytest.raises(ValidationError):
            GuestAccessRuleImportRequest(
                organization_id=uuid.uuid4(),
                rules=[
                    {"identifier": f"+9198765{n:05d}"}
                    for n in range(MAX_IMPORT_BATCH_SIZE + 1)
                ],
            )

    def test_an_empty_batch_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            GuestAccessRuleImportRequest(organization_id=uuid.uuid4(), rules=[])


class TestCsvExport:
    async def test_header_matches_the_import_row_so_a_list_round_trips(self) -> None:
        f = make_fixture()
        await _import(f, [{"identifier": "+919876543210"}])
        csv_text = await f.service.export_guest_rules_csv(
            requesting_organization_id=f.organization_id
        )
        lines = csv_text.strip().splitlines()
        assert lines[0].split(",")[:4] == [
            "identifier",
            "rule_type",
            "location_id",
            "expires_at",
        ]
        assert "+919876543210" in lines[1]

    async def test_free_text_is_escaped_but_the_phone_column_is_not(self) -> None:
        f = make_fixture()
        await _import(
            f,
            [{"identifier": "+919876543210", "reason": '=HYPERLINK("http://x")'}],
        )
        csv_text = await f.service.export_guest_rules_csv(
            requesting_organization_id=f.organization_id
        )
        # The operator-typed column is a formula cell on the colleague's
        # machine that opens this file -- see app.common.spreadsheet_safety.
        assert "'=HYPERLINK" in csv_text
        # The identifier column is not escaped, and must not be: an E.164
        # number starts with "+", and "'+919876543210" no longer
        # canonicalizes, so escaping it would make the export unimportable
        # -- which is the entire reason the export exists.
        assert "+919876543210" in csv_text
        assert "'+91" not in csv_text

    async def test_export_without_an_organization_is_refused(self) -> None:
        f = make_fixture()
        # Otherwise a missing X-Organization-Id downloads every tenant's
        # guest list in one file.
        with pytest.raises(OrganizationRequiredError):
            await f.service.export_guest_rules_csv(requesting_organization_id=None)

    async def test_confined_caller_only_exports_its_own_sites(self) -> None:
        f = make_fixture()
        other_site = uuid.uuid4()
        await _import(
            f,
            [
                {"identifier": "+919876543210", "location_id": f.location_id},
                {"identifier": "+919876543211", "location_id": other_site},
                {"identifier": "+919876543212"},
            ],
        )
        f.service.caller_location_scope = frozenset({f.location_id})
        csv_text = await f.service.export_guest_rules_csv(
            requesting_organization_id=f.organization_id
        )
        assert "+919876543210" in csv_text
        assert "+919876543211" not in csv_text
        # An org-wide rule belongs to no location, so it stays visible.
        assert "+919876543212" in csv_text


class TestBulkRoutesRequirePermission:
    def test_import_and_export_carry_their_own_permission(self) -> None:
        wanted = {
            ("/guest-access/rules/import", "POST"),
            ("/guest-access/rules/export", "GET"),
        }
        seen = set()
        for route in guest_access_router.routes:
            for method in getattr(route, "methods", set()):
                key = (route.path, method)
                if key in wanted:
                    seen.add(key)
                    assert (
                        route.dependencies != []
                    ), f"{key} has no permission dependency"
        assert seen == wanted
