"""Unit tests for the Content Filtering domain: rule CRUD (tenant
isolation, per-router value uniqueness), domain/IP-CIDR validation, and a
structural RBAC check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_firewall.py``); ``asyncio_mode = "auto"`` runs async
tests directly. ``ContentFilterService`` is exercised against small,
hand-rolled in-memory fakes for its own repository and the composed
``RouterLookupProtocol``, plus a fake device adapter that records what the
service actually asked the router to do -- this domain now has live device
I/O, and the classes at the bottom of this file are about it. The gateway
side (which RouterOS objects a blocked site becomes, and their
idempotency) is tested separately against a fake RouterOS transport in
``vendor/wyfy-device-gateway/tests/test_mikrotik_write_ops.py``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.content_filtering.constants import (
    ContentFilterCategory,
    ContentFilterDevicePushStatus,
    ContentFilterValueType,
)
from app.domains.content_filtering.exceptions import (
    ContentFilterDeviceConnectionError,
    ContentFilterDeviceOperationError,
    ContentFilterMissingCredentialsError,
    ContentFilterRuleAlreadyExistsError,
    ContentFilterRuleNotEnabledError,
    ContentFilterRuleNotFoundError,
    CrossOrganizationContentFilterRuleAccessError,
    InvalidContentFilterValueError,
    UnsupportedContentFilterVendorError,
)
from app.domains.content_filtering.models import ContentFilterRule
from app.domains.content_filtering.router import router as content_filtering_router
from app.domains.content_filtering.service import ContentFilterService
from app.domains.content_filtering.validators import (
    normalize_domain,
    normalize_ip_cidr,
    normalize_rule_value,
)
from app.domains.rbac.enums import AuditAction
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

    #: Counts the explicit commit ``push_rule_to_device`` issues before
    #: re-raising a device failure. Without it the failure record is
    #: discarded by the session rollback and the row still reads "pending"
    #: with a NULL error -- a second silent "blocked" that is not.
    commits: int = 0

    async def commit(self) -> None:
        self.commits += 1

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

    # Really part of the protocol -- the device-push path calls it. The
    # sentinel lets a test blank it out to exercise the missing-credentials
    # guard without hand-building a half-populated Router.
    secret: str | None = "s3cret"

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.secret


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
        assert len(content_filtering_router.routes) == 6
        for route in content_filtering_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"


# ============================================================================
# Device push
#
# Until this existed the whole domain was a database. A customer typed
# facebook.com, got a 201 and a dashboard that said "blocked", and every
# guest on that router kept reaching it -- the feature reported a security
# property it did not have. These tests are about the wire actually being
# there, and about failure being visible when it is not.
# ============================================================================


@dataclass
class FakeContentFilterAdapter:
    """Records what the service actually asked the device to do."""

    vendor: str = "mikrotik"
    calls: list[dict[str, object]] = field(default_factory=list)
    raises: Exception | None = None
    deletes: list[dict[str, object]] = field(default_factory=list)
    delete_raises: Exception | None = None

    async def configure_content_filter_rule(
        self,
        credentials,
        *,
        rule_id: str,
        value_type: str,
        value: str,
        label: str,
    ) -> None:
        self.calls.append(
            {
                "host": credentials.host,
                "username": credentials.username,
                "password": credentials.password,
                "rule_id": rule_id,
                "value_type": value_type,
                "value": value,
                "label": label,
            }
        )
        if self.raises is not None:
            raise self.raises

    async def delete_content_filter_rule(self, credentials, *, rule_id: str) -> None:
        self.deletes.append({"host": credentials.host, "rule_id": rule_id})
        if self.delete_raises is not None:
            raise self.delete_raises


@pytest.fixture
def adapter(monkeypatch: pytest.MonkeyPatch) -> FakeContentFilterAdapter:
    """Replaces the registry lookup the service performs.

    Patched on ``service``'s own reference, not on ``device_adapters`` --
    the service imported the name at module load, so patching the source
    module would leave the bound name untouched and the test would silently
    exercise the real adapter.
    """
    fake = FakeContentFilterAdapter()
    monkeypatch.setattr(
        "app.domains.content_filtering.service.get_content_filter_adapter",
        lambda vendor: fake,
    )
    return fake


class TestContentFilterRuleDevicePush:
    async def test_push_reaches_the_device_and_records_it(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        assert rule.device_push_status == ContentFilterDevicePushStatus.PENDING.value

        pushed = await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert len(adapter.calls) == 1
        call = adapter.calls[0]
        assert call["host"] == "10.0.0.1"
        assert call["username"] == "admin"
        assert call["password"] == "s3cret"
        assert call["value_type"] == "domain"
        assert call["value"] == "facebook.com"
        assert call["label"] == "Block Facebook"

        assert pushed.device_push_status == ContentFilterDevicePushStatus.ACTIVE.value
        assert pushed.device_push_error is None
        assert pushed.device_pushed_at is not None

    async def test_the_rules_own_id_is_what_the_device_is_keyed_on(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        """Not the value and not the name: both are what a customer edits,
        and keying on either leaves the previous sinkhole behind still
        blocking a site they already unblocked."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)

        await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.calls[0]["rule_id"] == str(rule.id)

    async def test_an_ip_cidr_rule_reaches_the_device_with_its_own_type(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        """The type decides which RouterOS mechanism is built, so passing
        the wrong one blocks nothing while reporting success."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(
            h,
            router,
            name="Block bad range",
            value_type=ContentFilterValueType.IP_CIDR,
            value="203.0.113.0/24",
        )

        await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.calls[0]["value_type"] == "ip_cidr"
        assert adapter.calls[0]["value"] == "203.0.113.0/24"

    async def test_the_normalized_value_is_what_reaches_the_device(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        """The row already stores the normalized form; the device has to
        get the same one, or the sinkhole and the dashboard disagree about
        what is blocked."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router, value="  FaceBook.COM.  ")

        await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.calls[0]["value"] == "facebook.com" == rule.value

    async def test_push_writes_a_real_audit_entry(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        before = len(h.audit_writer.entries)

        await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert len(h.audit_writer.entries) == before + 1
        assert (
            h.audit_writer.entries[-1]["action"]
            == AuditAction.CONTENT_FILTER_RULE_PUSHED.value
        )

    async def test_a_device_failure_is_recorded_committed_and_re_raised(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        """The commit is the point. ``GenericRepository.update`` only
        flushes and ``get_db_session`` rolls back on any exception, so
        without an explicit commit the failure record is discarded and the
        row still reads "pending" with a NULL error after a real failure --
        indistinguishable from a rule nobody has pushed yet."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        adapter.raises = ContentFilterDeviceOperationError(
            "configure_content_filter_rule", "already have such item"
        )

        with pytest.raises(ContentFilterDeviceOperationError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert rule.device_push_status == ContentFilterDevicePushStatus.FAILED.value
        assert "already have such item" in (rule.device_push_error or "")
        assert h.repository.commits == 1

    async def test_a_connection_failure_is_a_502_not_a_silent_success(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        """A 200 with ``success: false`` would reach the UI as success --
        the frontend interceptor unwraps ``data`` and never reads the flag.
        On this domain that is the original bug."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        adapter.raises = ContentFilterDeviceConnectionError("10.0.0.1", "timed out")

        with pytest.raises(ContentFilterDeviceConnectionError) as excinfo:
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert excinfo.value.status_code == 502
        assert rule.device_push_status == ContentFilterDevicePushStatus.FAILED.value

    async def test_one_rules_failure_leaves_another_rule_pushed(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        """Why the push is per-rule. A router that refuses one value must
        not strand the other fourteen, and each row's own status is what
        makes "fourteen enforcing, one refused" sayable at all."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        good = await _create_rule(h, router)
        bad = await _create_rule(h, router, value="instagram.com")

        await h.service.push_rule_to_device(
            good.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        adapter.raises = ContentFilterDeviceOperationError(
            "configure_content_filter_rule", "no such item"
        )
        with pytest.raises(ContentFilterDeviceOperationError):
            await h.service.push_rule_to_device(
                bad.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert good.device_push_status == ContentFilterDevicePushStatus.ACTIVE.value
        assert bad.device_push_status == ContentFilterDevicePushStatus.FAILED.value

    async def test_a_disabled_rule_is_refused_before_any_connection(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        """A disabled rule is the customer saying this site should not be
        blocked. Pushing it would block the site the toggle exists to
        unblock."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            is_enabled=False,
        )

        with pytest.raises(ContentFilterRuleNotEnabledError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []

    async def test_a_router_with_no_credentials_is_refused_before_any_connection(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        h.router_lookup.secret = None

        with pytest.raises(ContentFilterMissingCredentialsError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []
        assert rule.device_push_status == ContentFilterDevicePushStatus.PENDING.value

    async def test_another_organizations_rule_cannot_be_pushed(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)

        with pytest.raises(CrossOrganizationContentFilterRuleAccessError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=uuid.uuid4(),
            )
        assert adapter.calls == []


class TestUnsupportedVendorIsATypedError:
    async def test_an_unknown_vendor_gets_a_400_not_a_gateway_error(self) -> None:
        """``Router.vendor`` is a free ``String(50)``, so a row carrying
        "MikroTik" or "mikrotik_routeros" must fail here, typed, rather than
        opaquely inside the gateway's own enum lookup."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        router.vendor = "ubiquiti"
        rule = await _create_rule(h, router)

        with pytest.raises(UnsupportedContentFilterVendorError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )


class TestContentFilterRuleDeleteReachesTheDevice:
    """Deleting a rule used to soft-delete the row and nothing else, so a
    site this platform had blocked stayed blocked after the customer
    unblocked it -- with nothing on either side able to show it."""

    async def _pushed_rule(
        self, h: Harness, router: Router, adapter: FakeContentFilterAdapter
    ) -> ContentFilterRule:
        rule = await _create_rule(h, router)
        await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        adapter.calls.clear()
        return rule

    async def test_deleting_a_pushed_rule_removes_it_from_the_router(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await self._pushed_rule(h, router, adapter)

        deleted = await h.service.delete_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.deletes == [{"host": "10.0.0.1", "rule_id": str(rule.id)}]
        assert deleted.is_deleted is True

    async def test_a_rule_that_never_reached_a_device_skips_the_connection(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        """Opening a connection to delete nothing would make every such
        delete fail whenever a router happened to be unreachable."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        assert rule.device_push_status == ContentFilterDevicePushStatus.PENDING.value

        deleted = await h.service.delete_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.deletes == []
        assert deleted.is_deleted is True

    async def test_a_rule_whose_last_push_failed_skips_the_connection(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        adapter.raises = ContentFilterDeviceConnectionError("10.0.0.1", "timed out")
        with pytest.raises(ContentFilterDeviceConnectionError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        adapter.raises = None

        await h.service.delete_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.deletes == []

    async def test_a_device_failure_aborts_the_delete_and_keeps_the_row(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        """Removing the row while the sinkhole is still answering is exactly
        the drift this closes -- the customer would believe the site was
        reachable again and nothing would ever reconcile it."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await self._pushed_rule(h, router, adapter)
        adapter.delete_raises = ContentFilterDeviceConnectionError(
            "10.0.0.1", "timed out"
        )

        with pytest.raises(ContentFilterDeviceConnectionError):
            await h.service.delete_rule(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert rule.is_deleted is False
        assert await h.repository.get_rule_by_id(rule.id) is not None

    async def test_delete_passes_only_the_rules_identity(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        """A customer who edited a rule and never re-pushed it has objects
        on the device matching the *old* value; matching on the new one is
        exactly how they would be orphaned instead of removed."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await self._pushed_rule(h, router, adapter)
        await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            value="instagram.com",
        )

        await h.service.delete_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.deletes == [{"host": "10.0.0.1", "rule_id": str(rule.id)}]
