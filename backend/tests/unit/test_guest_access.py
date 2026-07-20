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
    CrossOrganizationAccessRuleError,
    InvalidRuleExpiryError,
    TemporaryRuleRequiresExpiryError,
)
from app.domains.guest_access.models import DeviceAccessRule, GuestAccessRule
from app.domains.guest_access.service import (
    AccessDecision,
    AccessDecisionResolver,
    GuestAccessService,
)
from app.domains.guest_access.validators import is_rule_expired, validate_rule_expiry

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
        return [
            rule
            for rule in self.guest_rules.values()
            if rule.organization_id == organization_id
            and rule.identifier == identifier
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
    service = GuestAccessService(repository, audit_writer=audit_writer)
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
