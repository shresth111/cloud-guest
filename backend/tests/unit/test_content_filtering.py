"""Unit tests for the Content Filtering domain: rule CRUD (tenant
isolation, per-router value uniqueness), domain/IP-CIDR validation, and a
structural RBAC check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_firewall.py``); ``asyncio_mode = "auto"`` runs async
tests directly. ``ContentFilterService`` is exercised against small,
hand-rolled in-memory fakes for its own repository and the composed
``RouterLookupProtocol``. This domain has no live device I/O to test in
this pass -- see ``service.py``'s own module docstring (real RouterOS
provisioning happens through ``app.domains.network_config``'s push
pipeline, exercised separately in ``test_network_config.py``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.content_filtering.constants import (
    ContentFilterCategory,
    ContentFilterValueType,
)
from app.domains.content_filtering.exceptions import (
    ContentFilterRuleAlreadyExistsError,
    ContentFilterRuleNotFoundError,
    CrossOrganizationContentFilterRuleAccessError,
    InvalidContentFilterValueError,
)
from app.domains.content_filtering.models import ContentFilterRule
from app.domains.content_filtering.router import router as content_filtering_router
from app.domains.content_filtering.service import ContentFilterService
from app.domains.content_filtering.validators import (
    normalize_domain,
    normalize_ip_cidr,
    normalize_rule_value,
)
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router

# ============================================================================
# Shared helpers
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


def _make_router(
    *, organization_id: uuid.UUID | None = None, location_id: uuid.UUID | None = None
) -> Router:
    return Router(
        **_base_fields(
            organization_id=organization_id or uuid.uuid4(),
            location_id=location_id or uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="RB4011",
            vendor="mikrotik",
            routeros_version=None,
            management_ip_address="10.0.0.1",
            public_ip_address=None,
            status="online",
            last_seen_at=None,
            last_health_check_at=None,
            health_status=None,
            api_username="admin",
            api_credentials_encrypted="encrypted-placeholder",
            settings={},
        )
    )


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeContentFilterRepository:
    rules: dict[uuid.UUID, ContentFilterRule] = field(default_factory=dict)

    async def create_rule(self, **fields: object) -> ContentFilterRule:
        rule = ContentFilterRule(**_base_fields(**fields))
        self.rules[rule.id] = rule
        return rule

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ContentFilterRule | None:
        rule = self.rules.get(rule_id)
        if rule is None or (rule.is_deleted and not include_deleted):
            return None
        return rule

    async def get_rule_by_router_and_value(
        self, router_id: uuid.UUID, value_type: str, value: str
    ) -> ContentFilterRule | None:
        for rule in self.rules.values():
            if (
                not rule.is_deleted
                and rule.router_id == router_id
                and rule.value_type == value_type
                and rule.value == value
            ):
                return rule
        return None

    async def update_rule(
        self, rule: ContentFilterRule, data: dict[str, object]
    ) -> ContentFilterRule:
        for key, value in data.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        rule.version += 1
        return rule

    async def soft_delete_rule(self, rule: ContentFilterRule) -> ContentFilterRule:
        rule.is_deleted = True
        rule.deleted_at = _now()
        return rule

    async def list_rules(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        **_kw: object,
    ):
        values = [v for v in self.rules.values() if not v.is_deleted]
        if requesting_organization_id is not None:
            values = [
                v for v in values if v.organization_id == requesting_organization_id
            ]
        if router_id is not None:
            values = [v for v in values if v.router_id == router_id]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_rules_for_router(
        self, router_id: uuid.UUID
    ) -> list[ContentFilterRule]:
        return [
            v
            for v in self.rules.values()
            if v.router_id == router_id and not v.is_deleted
        ]


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)

    def add(self, router: Router) -> Router:
        self.routers[router.id] = router
        return router

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router:
        router = self.routers.get(router_id)
        if router is None:
            raise RouterNotFoundError(router_id)
        if (
            requesting_organization_id is not None
            and router.organization_id != requesting_organization_id
        ):
            raise RouterNotFoundError(router_id)
        return router


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: ContentFilterService
    repository: FakeContentFilterRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeContentFilterRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    service = ContentFilterService(repository, router_lookup, audit_writer=audit_writer)
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        audit_writer=audit_writer,
    )


async def _create_rule(
    h: Harness,
    router: Router,
    *,
    name: str = "Block Facebook",
    value_type: ContentFilterValueType = ContentFilterValueType.DOMAIN,
    value: str = "facebook.com",
    **kwargs: object,
) -> ContentFilterRule:
    return await h.service.create_rule(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        name=name,
        value_type=value_type,
        value=value,
        **kwargs,
    )


# ============================================================================
# Validators
# ============================================================================


class TestNormalizeDomain:
    def test_lowercases_and_strips_trailing_dot(self) -> None:
        assert normalize_domain("Facebook.COM.") == "facebook.com"

    def test_rejects_a_bare_single_label(self) -> None:
        with pytest.raises(InvalidContentFilterValueError):
            normalize_domain("localhost")

    def test_rejects_a_url_with_a_scheme(self) -> None:
        with pytest.raises(InvalidContentFilterValueError):
            normalize_domain("https://facebook.com")

    def test_rejects_a_url_with_a_path(self) -> None:
        with pytest.raises(InvalidContentFilterValueError):
            normalize_domain("facebook.com/login")

    def test_accepts_a_real_subdomain(self) -> None:
        assert normalize_domain("www.facebook.com") == "www.facebook.com"


class TestNormalizeIpCidr:
    def test_accepts_a_bare_ip(self) -> None:
        assert normalize_ip_cidr("203.0.113.5") == "203.0.113.5/32"

    def test_accepts_a_cidr_block(self) -> None:
        assert normalize_ip_cidr("203.0.113.0/24") == "203.0.113.0/24"

    def test_rejects_garbage(self) -> None:
        with pytest.raises(InvalidContentFilterValueError):
            normalize_ip_cidr("not-an-ip")


class TestNormalizeRuleValue:
    def test_dispatches_on_value_type(self) -> None:
        assert (
            normalize_rule_value(ContentFilterValueType.DOMAIN, "Example.com")
            == "example.com"
        )
        assert (
            normalize_rule_value(ContentFilterValueType.IP_CIDR, "10.0.0.5")
            == "10.0.0.5/32"
        )


# ============================================================================
# Rule CRUD
# ============================================================================


class TestContentFilterRuleCrud:
    async def test_create_domain_rule_defaults(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        assert rule.value_type == ContentFilterValueType.DOMAIN.value
        assert rule.value == "facebook.com"
        assert rule.organization_id == router.organization_id
        assert rule.location_id == router.location_id
        assert rule.is_enabled is True
        assert len(h.audit_writer.entries) == 1

    async def test_create_normalizes_domain_case(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router, value="Facebook.COM")
        assert rule.value == "facebook.com"

    async def test_create_with_invalid_domain_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidContentFilterValueError):
            await _create_rule(h, router, value="not a domain")

    async def test_create_ip_cidr_rule(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(
            h,
            router,
            name="Block Bad Range",
            value_type=ContentFilterValueType.IP_CIDR,
            value="203.0.113.0/24",
        )
        assert rule.value_type == ContentFilterValueType.IP_CIDR.value
        assert rule.value == "203.0.113.0/24"

    async def test_create_with_invalid_ip_cidr_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidContentFilterValueError):
            await _create_rule(
                h, router, value_type=ContentFilterValueType.IP_CIDR, value="garbage"
            )

    async def test_create_stores_category_label(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(
            h, router, category=ContentFilterCategory.SOCIAL_MEDIA
        )
        assert rule.category == ContentFilterCategory.SOCIAL_MEDIA.value

    async def test_create_raises_for_unknown_router(self) -> None:
        h = make_harness()
        with pytest.raises(RouterNotFoundError):
            await _create_rule(h, _make_router())

    async def test_duplicate_value_on_same_router_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, value="facebook.com")
        with pytest.raises(ContentFilterRuleAlreadyExistsError):
            await _create_rule(h, router, name="Block FB Again", value="facebook.com")

    async def test_same_value_on_different_routers_is_allowed(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        rule_a = await _create_rule(h, router_a, value="facebook.com")
        rule_b = await _create_rule(h, router_b, value="facebook.com")
        assert rule_a.router_id != rule_b.router_id

    async def test_get_rule_cross_organization_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        with pytest.raises(CrossOrganizationContentFilterRuleAccessError):
            await h.service.get_rule(rule.id, requesting_organization_id=uuid.uuid4())

    async def test_get_rule_not_found_raises(self) -> None:
        h = make_harness()
        with pytest.raises(ContentFilterRuleNotFoundError):
            await h.service.get_rule(uuid.uuid4())

    async def test_update_rule_revalidates_new_value(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        with pytest.raises(InvalidContentFilterValueError):
            await h.service.update_rule(
                rule.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=router.organization_id,
                value="not a domain",
            )

    async def test_update_rule_success(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        updated = await h.service.update_rule(
            rule.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            is_enabled=False,
        )
        assert updated.is_enabled is False
        assert len(h.audit_writer.entries) == 2

    async def test_update_rule_value_normalizes_and_rechecks_uniqueness(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, value="instagram.com")
        rule_b = await _create_rule(h, router, name="Block TikTok", value="tiktok.com")
        with pytest.raises(ContentFilterRuleAlreadyExistsError):
            await h.service.update_rule(
                rule_b.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=router.organization_id,
                value="instagram.com",
            )

    async def test_delete_rule(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        deleted = await h.service.delete_rule(
            rule.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True

    async def test_list_rules_for_router(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, name="Block A", value="a.example.com")
        await _create_rule(h, router, name="Block B", value="b.example.com")
        rules = await h.service.list_rules_for_router(
            router.id, requesting_organization_id=router.organization_id
        )
        assert {r.value for r in rules} == {"a.example.com", "b.example.com"}

    async def test_list_rules_scopes_to_organization(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_rule(h, router_a)
        await _create_rule(h, router_b, value="other.example.com")
        rules, meta = await h.service.list_rules(
            requesting_organization_id=router_a.organization_id
        )
        assert meta.total_items == 1
        assert rules[0].organization_id == router_a.organization_id


# ============================================================================
# Structural RBAC check
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_content_filtering_route_has_a_permission_dependency(self) -> None:
        assert len(content_filtering_router.routes) == 5
        for route in content_filtering_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
