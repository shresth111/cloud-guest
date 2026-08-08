"""Unit tests for the URL Shortener domain: code generation (length,
alphabet, collision retry), create across all three sources, tenant
isolation (org A cannot read/modify/list org B's links, a platform-level
caller may act across every org), the anonymous public-create path, update/
revoke semantics (including explicit-null clearing of ``expires_at``), the
Master-console cross-tenant moderation surface, the guest-facing redirect
(including inactive/expired/not-found collapsing into one 404-equivalent
exception and its atomic click-increment), rate limiting (create +
redirect, each under its own budget), and the SSRF/open-redirect
``target_url`` validation.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_otp.py``/``tests/unit/test_voucher.py``);
``asyncio_mode = "auto"`` runs async tests directly. ``ShortLinkService`` is
exercised against a small, hand-rolled in-memory fake for its repository
(mirroring ``test_voucher.py``'s own fake-repository shape) and a
``FakeRedis`` (mirroring ``test_otp.py``'s/``test_voucher.py``'s identical
INCR/EXPIRE/TTL shape) -- there is no live Postgres/Redis in this
environment. The fake repository's own ``record_click`` reimplements the
real repository's atomic "match + increment in one step" contract (not just
a plain read-then-write), so the concurrency-relevant behavior under test
(a not-found/inactive/expired code never increments) is exercised
faithfully even without a real database transaction.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.constants import SortOrder
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.url_shortener.constants import (
    SHORT_LINK_CODE_ALPHABET,
    SHORT_LINK_CODE_LENGTH,
    ShortLinkSource,
)
from app.domains.url_shortener.exceptions import (
    BlockedTargetHostError,
    CrossOrganizationShortLinkAccessError,
    InvalidTargetUrlSchemeError,
    ShortLinkCodeGenerationExhaustedError,
    ShortLinkCreateRateLimitExceededError,
    ShortLinkNotFoundError,
    ShortLinkRedirectRateLimitExceededError,
)
from app.domains.url_shortener.models import ShortLink
from app.domains.url_shortener.router import (
    master_router,
    public_router,
    redirect_router,
)
from app.domains.url_shortener.router import router as short_link_router
from app.domains.url_shortener.service import (
    ShortLinkListFilters,
    ShortLinkRateLimiter,
    ShortLinkService,
)
from app.domains.url_shortener.validators import validate_target_url

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
class FakeShortLinkRepository:
    short_links: dict[uuid.UUID, ShortLink] = field(default_factory=dict)

    async def create(self, **fields: object) -> ShortLink:
        short_link = ShortLink(**_base_fields(**fields))
        self.short_links[short_link.id] = short_link
        return short_link

    async def get_by_id(self, short_link_id: uuid.UUID) -> ShortLink | None:
        return self.short_links.get(short_link_id)

    async def get_by_code(self, code: str) -> ShortLink | None:
        for item in self.short_links.values():
            if item.code == code:
                return item
        return None

    async def find_existing_codes(self, codes: list) -> list[str]:
        existing = {item.code for item in self.short_links.values()}
        return [code for code in codes if code in existing]

    async def update(self, short_link: ShortLink, data: dict[str, object]) -> ShortLink:
        for key, value in data.items():
            setattr(short_link, key, value)
        short_link.version += 1
        return short_link

    async def list_short_links(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = "created_at",
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[ShortLink], PaginationMeta]:
        items = list(self.short_links.values())
        for key, value in (filters or {}).items():
            items = [item for item in items if getattr(item, key) == value]
        items.sort(
            key=lambda item: getattr(item, sort_by),
            reverse=(sort_order == SortOrder.DESC),
        )
        params = PageParams(page=page, page_size=page_size)
        total = len(items)
        page_items = items[params.offset : params.offset + params.page_size]
        return page_items, PaginationMeta.from_total(params, total)

    async def record_click(self, code: str, *, now: datetime) -> ShortLink | None:
        """Reimplements the real repository's atomic
        ``UPDATE ... WHERE is_active AND not expired ... RETURNING``
        contract as a single, non-yielding synchronous check -- a
        not-found/inactive/expired code is rejected in the *same*
        conditional pass that would otherwise increment it, mirroring the
        real SQL statement's own "the WHERE clause and the increment are
        one atomic operation" guarantee (see
        ``app.domains.url_shortener.repository.ShortLinkRepository
        .record_click``'s own docstring)."""
        short_link = await self.get_by_code(code)
        if short_link is None or short_link.is_deleted:
            return None
        if not short_link.is_active:
            return None
        if short_link.expires_at is not None and short_link.expires_at <= now:
            return None
        short_link.click_count += 1
        short_link.last_clicked_at = now
        return short_link


class FakeRedis:
    """Minimal async in-memory stand-in for ``redis.asyncio.Redis`` --
    mirrors ``tests/unit/test_otp.py``'s/``tests/unit/test_voucher.py``'s
    own identical ``FakeRedis``."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._ttls: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]

    async def expire(self, key: str, seconds: int) -> bool:
        self._ttls[key] = seconds
        return True

    async def ttl(self, key: str) -> int:
        return self._ttls.get(key, -1)


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class Fixture:
    repository: FakeShortLinkRepository
    redis: FakeRedis
    audit_writer: FakeAuditLogWriter
    service: ShortLinkService


def make_service(
    *,
    create_max_attempts_per_window: int = 20,
    create_window_minutes: int = 1,
    redirect_max_attempts_per_window: int = 60,
    redirect_window_minutes: int = 1,
) -> Fixture:
    repository = FakeShortLinkRepository()
    redis = FakeRedis()
    audit_writer = FakeAuditLogWriter()
    service = ShortLinkService(
        repository,
        redis,
        audit_writer=audit_writer,
        create_max_attempts_per_window=create_max_attempts_per_window,
        create_window_minutes=create_window_minutes,
        redirect_max_attempts_per_window=redirect_max_attempts_per_window,
        redirect_window_minutes=redirect_window_minutes,
    )
    return Fixture(
        repository=repository, redis=redis, audit_writer=audit_writer, service=service
    )


# ============================================================================
# target_url validation (SSRF / open-redirect guard)
# ============================================================================


class TestTargetUrlValidation:
    def test_valid_https_url_accepted(self) -> None:
        assert validate_target_url("https://example.com/pricing") == (
            "https://example.com/pricing"
        )

    def test_valid_http_url_accepted(self) -> None:
        assert validate_target_url("http://example.com") == "http://example.com"

    @pytest.mark.parametrize(
        "raw_url",
        [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
            "ftp://example.com/file",
            "example.com",  # no scheme at all
            "//example.com/path",  # scheme-relative, no explicit scheme
        ],
    )
    def test_disallowed_scheme_rejected(self, raw_url: str) -> None:
        with pytest.raises(InvalidTargetUrlSchemeError):
            validate_target_url(raw_url)

    @pytest.mark.parametrize(
        "raw_url",
        [
            "http://localhost/admin",
            "http://localhost:8000/",
            "http://127.0.0.1/",
            "http://127.0.0.1:5432/",
            "http://0.0.0.0/",
            "http://10.0.0.5/internal",
            "http://172.16.5.1/",
            "http://172.31.255.255/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",  # cloud metadata IP
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://foo.localhost/",
            "http://service.internal/",
            "http://printer.local/",
        ],
    )
    def test_internal_host_rejected(self, raw_url: str) -> None:
        with pytest.raises(BlockedTargetHostError):
            validate_target_url(raw_url)

    def test_public_ip_literal_is_not_blocked(self) -> None:
        # A real, public IP literal (Google DNS) must not be caught by the
        # private/loopback/link-local guard -- only obviously-internal
        # ranges are rejected.
        assert validate_target_url("http://8.8.8.8/") == "http://8.8.8.8/"

    def test_empty_hostname_rejected(self) -> None:
        with pytest.raises(BlockedTargetHostError):
            validate_target_url("http:///path-with-no-host")

    def test_url_is_returned_unchanged_not_normalized(self) -> None:
        url = "https://example.com/a/b?x=1&y=2#frag"
        assert validate_target_url(url) == url


# ============================================================================
# Code generation
# ============================================================================


class TestCodeGeneration:
    async def test_generated_code_has_expected_length_and_alphabet(self) -> None:
        fx = make_service()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=uuid.uuid4(),
            created_by_user_id=uuid.uuid4(),
        )
        assert len(short_link.code) == SHORT_LINK_CODE_LENGTH
        assert all(c in SHORT_LINK_CODE_ALPHABET for c in short_link.code)

    async def test_codes_are_unique_across_many_creates(self) -> None:
        fx = make_service()
        org_id = uuid.uuid4()
        codes = set()
        for _ in range(25):
            short_link = await fx.service.create_customer_short_link(
                target_url="https://example.com",
                organization_id=org_id,
                created_by_user_id=uuid.uuid4(),
            )
            codes.add(short_link.code)
        assert len(codes) == 25

    async def test_collision_forces_a_retry_round(self, monkeypatch) -> None:
        fx = make_service()
        # Pre-seed the repository with a row whose code every "random"
        # candidate will collide with, to prove _generate_code actually
        # re-checks against the repository rather than trusting the first
        # candidate blindly.
        collided_code = "AAAAAAA"
        await fx.repository.create(
            **_base_fields(
                code=collided_code,
                target_url="https://example.com",
                organization_id=None,
                created_by_user_id=None,
                source=ShortLinkSource.CUSTOMER.value,
                click_count=0,
                last_clicked_at=None,
                is_active=True,
                expires_at=None,
            )
        )
        calls = {"count": 0}
        real_choice = secrets.choice

        def fake_choice(alphabet):
            calls["count"] += 1
            # First SHORT_LINK_CODE_LENGTH calls reproduce the colliding
            # code; every call after that is genuinely random.
            if calls["count"] <= len(collided_code):
                return collided_code[calls["count"] - 1]
            return real_choice(alphabet)

        monkeypatch.setattr(
            "app.domains.url_shortener.service.secrets_choice", fake_choice
        )
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=uuid.uuid4(),
            created_by_user_id=uuid.uuid4(),
        )
        assert short_link.code != collided_code

    async def test_generation_exhausted_raises(self, monkeypatch) -> None:
        fx = make_service()
        monkeypatch.setattr(
            fx.repository,
            "find_existing_codes",
            lambda codes: _always_existing(codes),
        )
        with pytest.raises(ShortLinkCodeGenerationExhaustedError):
            await fx.service.create_customer_short_link(
                target_url="https://example.com",
                organization_id=uuid.uuid4(),
                created_by_user_id=uuid.uuid4(),
            )


async def _always_existing(codes: list) -> list:
    return list(codes)


# ============================================================================
# Create across all three sources
# ============================================================================


class TestCreate:
    async def test_public_create_has_no_organization_or_user(self) -> None:
        fx = make_service()
        short_link = await fx.service.create_public_short_link(
            target_url="https://example.com/promo", source_ip="1.2.3.4"
        )
        assert short_link.source == ShortLinkSource.PUBLIC_SITE.value
        assert short_link.organization_id is None
        assert short_link.created_by_user_id is None
        assert short_link.is_active is True
        assert short_link.click_count == 0

    async def test_public_create_is_never_audited(self) -> None:
        """High-volume, unauthenticated, anonymous create -- see
        app.domains.rbac.enums.AuditAction.SHORT_LINK_CREATED's own
        docstring for the audit-volume judgment call this mirrors from
        OTP."""
        fx = make_service()
        await fx.service.create_public_short_link(
            target_url="https://example.com/promo", source_ip="1.2.3.4"
        )
        assert fx.audit_writer.entries == []

    async def test_customer_create_is_org_scoped_and_audited(self) -> None:
        fx = make_service()
        org_id = uuid.uuid4()
        user_id = uuid.uuid4()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com/promo",
            organization_id=org_id,
            created_by_user_id=user_id,
        )
        assert short_link.source == ShortLinkSource.CUSTOMER.value
        assert short_link.organization_id == org_id
        assert short_link.created_by_user_id == user_id
        assert len(fx.audit_writer.entries) == 1
        assert fx.audit_writer.entries[0]["action"] == "short_link_created"

    async def test_create_rejects_invalid_target_url_before_any_side_effect(
        self,
    ) -> None:
        fx = make_service()
        with pytest.raises(InvalidTargetUrlSchemeError):
            await fx.service.create_customer_short_link(
                target_url="javascript:alert(1)",
                organization_id=uuid.uuid4(),
                created_by_user_id=uuid.uuid4(),
            )
        assert fx.repository.short_links == {}

    async def test_create_with_expiry(self) -> None:
        fx = make_service()
        expires_at = _now() + timedelta(days=7)
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=uuid.uuid4(),
            created_by_user_id=uuid.uuid4(),
            expires_at=expires_at,
        )
        assert short_link.expires_at == expires_at


# ============================================================================
# Tenant isolation
# ============================================================================


class TestTenantIsolation:
    async def test_org_a_cannot_read_org_b_link(self) -> None:
        fx = make_service()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=org_b,
            created_by_user_id=uuid.uuid4(),
        )
        with pytest.raises(CrossOrganizationShortLinkAccessError):
            await fx.service.get_short_link(
                short_link.id, requesting_organization_id=org_a
            )

    async def test_org_a_cannot_update_org_bs_link(self) -> None:
        fx = make_service()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=org_b,
            created_by_user_id=uuid.uuid4(),
        )
        with pytest.raises(CrossOrganizationShortLinkAccessError):
            await fx.service.update_short_link(
                short_link.id,
                requesting_organization_id=org_a,
                data={"is_active": False},
            )

    async def test_org_a_cannot_revoke_org_bs_link(self) -> None:
        fx = make_service()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=org_b,
            created_by_user_id=uuid.uuid4(),
        )
        with pytest.raises(CrossOrganizationShortLinkAccessError):
            await fx.service.revoke_short_link(
                short_link.id, requesting_organization_id=org_a
            )

    async def test_org_scoped_list_never_returns_another_orgs_links(self) -> None:
        fx = make_service()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await fx.service.create_customer_short_link(
            target_url="https://example.com/a",
            organization_id=org_a,
            created_by_user_id=uuid.uuid4(),
        )
        await fx.service.create_customer_short_link(
            target_url="https://example.com/b",
            organization_id=org_b,
            created_by_user_id=uuid.uuid4(),
        )
        items, meta = await fx.service.list_short_links(
            requesting_organization_id=org_a
        )
        assert meta.total_items == 1
        assert all(item.organization_id == org_a for item in items)

    async def test_platform_level_caller_may_access_any_organization(self) -> None:
        fx = make_service()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=uuid.uuid4(),
            created_by_user_id=uuid.uuid4(),
        )
        # requesting_organization_id=None -- the Master-console-style
        # unrestricted read.
        found = await fx.service.get_short_link(
            short_link.id, requesting_organization_id=None
        )
        assert found.id == short_link.id

    async def test_get_unknown_id_raises_not_found(self) -> None:
        fx = make_service()
        with pytest.raises(ShortLinkNotFoundError):
            await fx.service.get_short_link(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )


# ============================================================================
# Update / revoke
# ============================================================================


class TestUpdateAndRevoke:
    async def test_update_target_url_revalidates(self) -> None:
        fx = make_service()
        org_id = uuid.uuid4()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=org_id,
            created_by_user_id=uuid.uuid4(),
        )
        with pytest.raises(InvalidTargetUrlSchemeError):
            await fx.service.update_short_link(
                short_link.id,
                requesting_organization_id=org_id,
                data={"target_url": "javascript:alert(1)"},
            )

    async def test_update_target_url_to_a_valid_url_succeeds(self) -> None:
        fx = make_service()
        org_id = uuid.uuid4()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=org_id,
            created_by_user_id=uuid.uuid4(),
        )
        updated = await fx.service.update_short_link(
            short_link.id,
            requesting_organization_id=org_id,
            data={"target_url": "https://example.com/new-page"},
        )
        assert updated.target_url == "https://example.com/new-page"

    async def test_update_can_explicitly_clear_expires_at(self) -> None:
        fx = make_service()
        org_id = uuid.uuid4()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=org_id,
            created_by_user_id=uuid.uuid4(),
            expires_at=_now() + timedelta(days=1),
        )
        updated = await fx.service.update_short_link(
            short_link.id,
            requesting_organization_id=org_id,
            data={"expires_at": None},
        )
        assert updated.expires_at is None

    async def test_revoke_sets_is_active_false_and_keeps_the_row(self) -> None:
        fx = make_service()
        org_id = uuid.uuid4()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=org_id,
            created_by_user_id=uuid.uuid4(),
        )
        revoked = await fx.service.revoke_short_link(
            short_link.id, requesting_organization_id=org_id, actor_user_id=uuid.uuid4()
        )
        assert revoked.is_active is False
        # Soft revoke, not a row-level soft-delete -- still fully readable.
        assert short_link.id in fx.repository.short_links
        assert fx.repository.short_links[short_link.id].is_deleted is False

    async def test_revoke_is_audited(self) -> None:
        fx = make_service()
        org_id = uuid.uuid4()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=org_id,
            created_by_user_id=uuid.uuid4(),
        )
        await fx.service.revoke_short_link(
            short_link.id, requesting_organization_id=org_id
        )
        actions = [entry["action"] for entry in fx.audit_writer.entries]
        assert "short_link_revoked" in actions


# ============================================================================
# Master-console cross-tenant moderation
# ============================================================================


class TestMasterModeration:
    async def test_master_can_deactivate_any_orgs_link(self) -> None:
        fx = make_service()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=uuid.uuid4(),
            created_by_user_id=uuid.uuid4(),
        )
        moderated = await fx.service.master_moderate_short_link(
            short_link.id, data={"is_active": False}
        )
        assert moderated.is_active is False

    async def test_master_can_deactivate_an_anonymous_public_link(self) -> None:
        fx = make_service()
        short_link = await fx.service.create_public_short_link(
            target_url="https://example.com", source_ip="1.2.3.4"
        )
        moderated = await fx.service.master_moderate_short_link(
            short_link.id, data={"is_active": False}
        )
        assert moderated.is_active is False

    async def test_master_moderation_is_audited(self) -> None:
        fx = make_service()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=uuid.uuid4(),
            created_by_user_id=uuid.uuid4(),
        )
        await fx.service.master_moderate_short_link(
            short_link.id, data={"is_active": False}
        )
        actions = [entry["action"] for entry in fx.audit_writer.entries]
        assert "short_link_moderated" in actions

    async def test_master_moderate_unknown_id_raises_not_found(self) -> None:
        fx = make_service()
        with pytest.raises(ShortLinkNotFoundError):
            await fx.service.master_moderate_short_link(
                uuid.uuid4(), data={"is_active": False}
            )

    async def test_master_list_filters_by_organization_source_and_active(self) -> None:
        fx = make_service()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await fx.service.create_customer_short_link(
            target_url="https://example.com/a",
            organization_id=org_a,
            created_by_user_id=uuid.uuid4(),
        )
        await fx.service.create_customer_short_link(
            target_url="https://example.com/b",
            organization_id=org_b,
            created_by_user_id=uuid.uuid4(),
        )
        await fx.service.create_public_short_link(
            target_url="https://example.com/c", source_ip="9.9.9.9"
        )
        items, meta = await fx.service.list_short_links(
            requesting_organization_id=None,
            extra_filters=ShortLinkListFilters(organization_id=org_a),
        )
        assert meta.total_items == 1
        assert items[0].organization_id == org_a


# ============================================================================
# Guest-facing redirect: not-found / inactive / expired / success
# ============================================================================


class TestRedirect:
    async def test_redirect_resolves_active_link_and_increments_click_count(
        self,
    ) -> None:
        fx = make_service()
        short_link = await fx.service.create_public_short_link(
            target_url="https://example.com/landing", source_ip="1.2.3.4"
        )
        assert short_link.click_count == 0
        assert short_link.last_clicked_at is None

        resolved = await fx.service.resolve_and_record_click(
            short_link.code, source_ip="9.8.7.6"
        )
        assert resolved.target_url == "https://example.com/landing"
        assert resolved.click_count == 1
        assert resolved.last_clicked_at is not None

    async def test_redirect_increments_on_every_call(self) -> None:
        fx = make_service(redirect_max_attempts_per_window=100)
        short_link = await fx.service.create_public_short_link(
            target_url="https://example.com", source_ip="1.2.3.4"
        )
        for expected in range(1, 6):
            resolved = await fx.service.resolve_and_record_click(
                short_link.code, source_ip=f"1.1.1.{expected}"
            )
            assert resolved.click_count == expected

    async def test_unknown_code_raises_not_found(self) -> None:
        fx = make_service()
        with pytest.raises(ShortLinkNotFoundError):
            await fx.service.resolve_and_record_click("NOTREAL", source_ip="1.2.3.4")

    async def test_inactive_link_raises_not_found_and_does_not_increment(self) -> None:
        fx = make_service()
        org_id = uuid.uuid4()
        short_link = await fx.service.create_customer_short_link(
            target_url="https://example.com",
            organization_id=org_id,
            created_by_user_id=uuid.uuid4(),
        )
        await fx.service.revoke_short_link(
            short_link.id, requesting_organization_id=org_id
        )
        with pytest.raises(ShortLinkNotFoundError):
            await fx.service.resolve_and_record_click(
                short_link.code, source_ip="1.2.3.4"
            )
        assert fx.repository.short_links[short_link.id].click_count == 0

    async def test_expired_link_raises_not_found_and_does_not_increment(self) -> None:
        fx = make_service()
        short_link = await fx.service.create_public_short_link(
            target_url="https://example.com", source_ip="1.2.3.4"
        )
        # Force expiry without waiting for the real clock.
        fx.repository.short_links[short_link.id].expires_at = _now() - timedelta(
            seconds=1
        )
        with pytest.raises(ShortLinkNotFoundError):
            await fx.service.resolve_and_record_click(
                short_link.code, source_ip="1.2.3.4"
            )
        assert fx.repository.short_links[short_link.id].click_count == 0

    async def test_future_expiry_still_resolves(self) -> None:
        fx = make_service()
        short_link = await fx.service.create_public_short_link(
            target_url="https://example.com", source_ip="1.2.3.4"
        )
        fx.repository.short_links[short_link.id].expires_at = _now() + timedelta(
            days=1
        )
        resolved = await fx.service.resolve_and_record_click(
            short_link.code, source_ip="1.2.3.4"
        )
        assert resolved.click_count == 1


# ============================================================================
# Rate limiting -- create and redirect, each under its own budget
# ============================================================================


class TestRateLimiting:
    async def test_exceeding_public_create_rate_limit_raises(self) -> None:
        fx = make_service(create_max_attempts_per_window=2)
        for _ in range(2):
            await fx.service.create_public_short_link(
                target_url="https://example.com", source_ip="5.5.5.5"
            )
        with pytest.raises(ShortLinkCreateRateLimitExceededError):
            await fx.service.create_public_short_link(
                target_url="https://example.com", source_ip="5.5.5.5"
            )

    async def test_create_rate_limit_is_scoped_per_source(self) -> None:
        fx = make_service(create_max_attempts_per_window=1)
        await fx.service.create_public_short_link(
            target_url="https://example.com", source_ip="1.1.1.1"
        )
        # A different source is unaffected by the first one's limit.
        await fx.service.create_public_short_link(
            target_url="https://example.com", source_ip="2.2.2.2"
        )

    async def test_exceeding_redirect_rate_limit_raises(self) -> None:
        fx = make_service(redirect_max_attempts_per_window=2)
        short_link = await fx.service.create_public_short_link(
            target_url="https://example.com", source_ip="1.2.3.4"
        )
        for _ in range(2):
            await fx.service.resolve_and_record_click(
                short_link.code, source_ip="6.6.6.6"
            )
        with pytest.raises(ShortLinkRedirectRateLimitExceededError):
            await fx.service.resolve_and_record_click(
                short_link.code, source_ip="6.6.6.6"
            )

    async def test_create_and_redirect_limits_are_independent_budgets(self) -> None:
        """Exhausting the create budget for a source must not affect that
        same source's separate redirect budget, and vice versa -- see
        constants.py's own module docstring for why these are two distinct
        Redis keys/budgets."""
        fx = make_service(
            create_max_attempts_per_window=1, redirect_max_attempts_per_window=1
        )
        short_link = await fx.service.create_public_short_link(
            target_url="https://example.com", source_ip="7.7.7.7"
        )
        with pytest.raises(ShortLinkCreateRateLimitExceededError):
            await fx.service.create_public_short_link(
                target_url="https://example.com", source_ip="7.7.7.7"
            )
        # The redirect budget for the same source is untouched by the
        # create budget above being exhausted.
        resolved = await fx.service.resolve_and_record_click(
            short_link.code, source_ip="7.7.7.7"
        )
        assert resolved.click_count == 1

    async def test_rate_limiter_direct_raises_with_retry_after(self) -> None:
        redis = FakeRedis()
        await ShortLinkRateLimiter.check_create(
            redis, "3.3.3.3", max_attempts=1, window_minutes=1
        )
        with pytest.raises(ShortLinkCreateRateLimitExceededError) as exc_info:
            await ShortLinkRateLimiter.check_create(
                redis, "3.3.3.3", max_attempts=1, window_minutes=1
            )
        assert exc_info.value.retry_after_seconds == 60


# ============================================================================
# Structural RBAC check -- mirrors tests/unit/test_dns.py's own
# TestEveryRouteRequiresPermission precedent: every route on the
# authenticated/master routers must carry a permission dependency; the
# anonymous public-create/redirect routers must carry none (their own
# abuse protection is rate limiting, not RBAC -- see router.py's module
# docstring).
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_org_scoped_route_has_a_permission_dependency(self) -> None:
        assert len(short_link_router.routes) == 5
        for route in short_link_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"

    def test_every_master_route_has_a_permission_dependency(self) -> None:
        assert len(master_router.routes) == 2
        for route in master_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"

    def test_public_create_route_has_no_permission_dependency(self) -> None:
        assert len(public_router.routes) == 1
        for route in public_router.routes:
            assert route.dependencies == []

    def test_redirect_route_has_no_permission_dependency(self) -> None:
        assert len(redirect_router.routes) == 1
        for route in redirect_router.routes:
            assert route.dependencies == []
