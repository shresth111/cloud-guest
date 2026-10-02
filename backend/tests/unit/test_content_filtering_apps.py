"""Block Websites -> Apps: the curated catalogue and the per-app toggles.

An app toggle is a convenience over ordinary content-filter rows and the
existing per-rule push. These tests pin what makes it safe: it creates and
removes only its own rows, never a website the customer blocked by hand; a
partial outcome is a real error; it is scoped like every other rule; and an
Omada venue is refused before anything is written.
"""

from __future__ import annotations

import inspect
import uuid

import pytest

from app.domains.content_filtering.app_catalogue import (
    APP_CATALOGUE,
    SHARED_INFRASTRUCTURE_NAMES,
    app_by_key,
)
from app.domains.content_filtering.constants import (
    ContentFilterDevicePushStatus,
    ContentFilterValueType,
)
from app.domains.content_filtering.exceptions import (
    ContentFilterAppIncompleteError,
    ContentFilterDeviceConnectionError,
    CrossLocationContentFilterRuleAccessError,
    UnknownContentFilterAppError,
)
from app.domains.content_filtering.router import router as content_filtering_router
from app.domains.content_filtering.validators import normalize_rule_value
from app.domains.rbac.enums import ScopeType
from app.domains.router.device_domain_gate import (
    ControllerManagedFeatureUnavailableError,
)
from app.domains.router.exceptions import RouterNotFoundError
from tests.unit.test_content_filtering import (
    FakeContentFilterAdapter,
    _create_rule,
    _make_router,
    make_harness,
)


@pytest.fixture
def adapter(monkeypatch: pytest.MonkeyPatch) -> FakeContentFilterAdapter:
    """Same patch as test_content_filtering's fixture: on the service's own
    bound name, so the real adapter is never reached."""
    fake = FakeContentFilterAdapter()
    monkeypatch.setattr(
        "app.domains.content_filtering.service.get_content_filter_adapter",
        lambda vendor: fake,
    )
    return fake


_ACTIVE = ContentFilterDevicePushStatus.ACTIVE.value
_FAILED = ContentFilterDevicePushStatus.FAILED.value


def _targets(key: str) -> list[str]:
    app = app_by_key(key)
    assert app is not None
    return [*app.domains, *app.cidrs]


# ============================================================================
# The catalogue itself
# ============================================================================


class TestCatalogue:
    def test_the_requested_apps_are_all_there(self) -> None:
        names = " ".join(app.name for app in APP_CATALOGUE)
        for wanted in (
            "YouTube",
            "Instagram",
            "Facebook",
            "WhatsApp",
            "TikTok",
            "Moj",
            "Josh",
            "Netflix",
            "JioHotstar",
            "BGMI",
            "PUBG",
            "Free Fire",
            "Telegram",
            "Snapchat",
            "Torrent",
        ):
            assert wanted in names, wanted

    def test_every_value_passes_the_domains_own_validators(self) -> None:
        for app in APP_CATALOGUE:
            for domain in app.domains:
                assert (
                    normalize_rule_value(ContentFilterValueType.DOMAIN, domain)
                    == domain
                ), (app.key, domain)
            for cidr in app.cidrs:
                normalized = normalize_rule_value(ContentFilterValueType.IP_CIDR, cidr)
                assert normalized == cidr, (app.key, cidr)
                # /ip firewall address-list is IPv4; an IPv6 range would
                # fail on the device.
                assert ":" not in cidr, (app.key, cidr)

    def test_no_name_belongs_to_two_apps(self) -> None:
        """Ownership on unblock must never be ambiguous."""
        seen: dict[str, str] = {}
        for app in APP_CATALOGUE:
            for value in (*app.domains, *app.cidrs):
                assert value not in seen, (value, seen.get(value), app.key)
                seen[value] = app.key

    def test_no_app_blocks_shared_infrastructure(self) -> None:
        """Blocking googleapis.com or fbcdn.net would break Google sign-in,
        Maps or Instagram for a venue that only asked to block one app."""
        for app in APP_CATALOGUE:
            for domain in app.domains:
                assert domain not in SHARED_INFRASTRUCTURE_NAMES, (app.key, domain)

    def test_keys_are_url_safe_and_unique(self) -> None:
        keys = [app.key for app in APP_CATALOGUE]
        assert len(keys) == len(set(keys))
        for key in keys:
            assert key.replace("_", "").isalnum() and key.islower(), key
            assert len(key) <= 40


# ============================================================================
# Block / unblock
# ============================================================================


class TestBlockApp:
    async def test_block_creates_and_pushes_one_rule_per_name(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())

        state = await h.service.block_app(
            router.id,
            "instagram",
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert sorted(c["value"] for c in adapter.calls) == sorted(
            _targets("instagram")
        )
        assert all(c["value_type"] == "domain" for c in adapter.calls)
        rows = list(h.repository.rules.values())
        assert {r.app_key for r in rows} == {"instagram"}
        assert all(r.device_push_status == _ACTIVE for r in rows)
        assert state.state == "blocked"
        assert state.push_status == _ACTIVE

    async def test_telegram_also_blocks_its_published_ranges(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())

        await h.service.block_app(
            router.id,
            "telegram",
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        cidr_calls = [c for c in adapter.calls if c["value_type"] == "ip_cidr"]
        assert "149.154.160.0/20" in {c["value"] for c in cidr_calls}

    async def test_blocking_twice_creates_nothing_and_pushes_nothing(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        kwargs = dict(
            actor_user_id=None, requesting_organization_id=router.organization_id
        )
        await h.service.block_app(router.id, "netflix", **kwargs)
        rows, pushes = len(h.repository.rules), len(adapter.calls)

        await h.service.block_app(router.id, "netflix", **kwargs)

        assert len(h.repository.rules) == rows
        assert len(adapter.calls) == pushes

    async def test_a_name_the_customer_blocked_by_hand_is_counted_and_left_alone(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        mine = await _create_rule(h, router, name="My block", value="netflix.com")
        kwargs = dict(
            actor_user_id=None, requesting_organization_id=router.organization_id
        )

        state = await h.service.block_app(router.id, "netflix", **kwargs)

        assert mine.app_key is None
        assert "netflix.com" not in {c["value"] for c in adapter.calls}
        target = next(t for t in state.targets if t.value == "netflix.com")
        assert target.rule_id == mine.id and target.owned is False
        assert state.state == "blocked"

        await h.service.unblock_app(router.id, "netflix", **kwargs)

        assert not mine.is_deleted
        assert {r.value for r in h.repository.rules.values() if not r.is_deleted} == {
            "netflix.com"
        }

    async def test_a_partial_push_is_a_502_not_a_success(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        adapter.raises = ContentFilterDeviceConnectionError("10.0.0.1", "timed out")

        with pytest.raises(ContentFilterAppIncompleteError) as caught:
            await h.service.block_app(
                router.id,
                "whatsapp",
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert caught.value.status_code == 502
        assert caught.value.data["failed"] == len(_targets("whatsapp"))
        # Every row records its own failure, and the record is committed.
        assert all(r.device_push_status == _FAILED for r in h.repository.rules.values())
        assert h.repository.commits >= 1

    async def test_a_retry_pushes_only_what_did_not_land(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        kwargs = dict(
            actor_user_id=None, requesting_organization_id=router.organization_id
        )
        adapter.raises = ContentFilterDeviceConnectionError("10.0.0.1", "timed out")
        with pytest.raises(ContentFilterAppIncompleteError):
            await h.service.block_app(router.id, "whatsapp", **kwargs)
        adapter.raises = None
        adapter.calls.clear()

        state = await h.service.block_app(router.id, "whatsapp", **kwargs)

        assert len(adapter.calls) == len(_targets("whatsapp"))
        assert state.push_status == _ACTIVE

    async def test_unblock_removes_the_apps_rows_from_device_and_database(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        kwargs = dict(
            actor_user_id=None, requesting_organization_id=router.organization_id
        )
        await h.service.block_app(router.id, "snapchat", **kwargs)
        await h.service.block_app(router.id, "youtube", **kwargs)

        state = await h.service.unblock_app(router.id, "snapchat", **kwargs)

        assert len(adapter.deletes) == len(_targets("snapchat"))
        live = [r for r in h.repository.rules.values() if not r.is_deleted]
        assert {r.app_key for r in live} == {"youtube"}
        assert state.state == "not_blocked"
        assert state.push_status is None

    async def test_an_unblock_the_device_refuses_keeps_the_row_and_is_a_502(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        kwargs = dict(
            actor_user_id=None, requesting_organization_id=router.organization_id
        )
        await h.service.block_app(router.id, "instagram", **kwargs)
        adapter.delete_raises = ContentFilterDeviceConnectionError("10.0.0.1", "down")

        with pytest.raises(ContentFilterAppIncompleteError):
            await h.service.unblock_app(router.id, "instagram", **kwargs)

        assert all(not r.is_deleted for r in h.repository.rules.values())

    async def test_an_unknown_app_is_a_404(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(UnknownContentFilterAppError):
            await h.service.block_app(
                router.id,
                "myspace",
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )


class TestAppScoping:
    async def test_an_omada_venue_is_refused_before_a_row_exists(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        router.vendor = "tplink_omada"

        with pytest.raises(ControllerManagedFeatureUnavailableError):
            await h.service.block_app(
                router.id,
                "youtube",
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert h.repository.rules == {}
        assert adapter.calls == []

    async def test_another_organizations_router_is_not_found(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        for call in (h.service.list_app_states,):
            with pytest.raises(RouterNotFoundError):
                await call(router.id, requesting_organization_id=uuid.uuid4())
        with pytest.raises(RouterNotFoundError):
            await h.service.block_app(
                router.id,
                "youtube",
                actor_user_id=None,
                requesting_organization_id=uuid.uuid4(),
            )

    async def test_a_site_confined_caller_cannot_reach_another_site(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        h.service.caller_location_scope = frozenset({uuid.uuid4()})

        with pytest.raises(CrossLocationContentFilterRuleAccessError):
            await h.service.block_app(
                router.id,
                "youtube",
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        with pytest.raises(CrossLocationContentFilterRuleAccessError):
            await h.service.list_app_states(
                router.id, requesting_organization_id=router.organization_id
            )
        assert adapter.calls == []

    async def test_a_site_confined_caller_can_reach_their_own_site(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        h.service.caller_location_scope = frozenset({router.location_id})

        states = await h.service.list_app_states(
            router.id, requesting_organization_id=router.organization_id
        )
        assert len(states) == len(APP_CATALOGUE)

    def test_app_routes_use_content_filtering_permissions_pinned_to_the_router(
        self,
    ) -> None:
        app_routes = [r for r in content_filtering_router.routes if "/apps" in r.path]
        assert len(app_routes) == 3
        for route in app_routes:
            assert "{router_id}" in route.path
            perms = [d.dependency for d in route.dependencies]
            assert perms, route.path
            for perm in perms:
                bound = inspect.getclosurevars(perm).nonlocals
                assert bound["permission_key"].startswith("content_filtering.")
                # Pinned, so the caller's own headers cannot pick the level.
                assert bound["scope"] is ScopeType.ROUTER, route.path


class TestWebsiteListExcludesAppRows:
    async def test_the_specific_websites_list_can_leave_app_rows_out(
        self, adapter: FakeContentFilterAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, value="example.com")
        await h.service.block_app(
            router.id,
            "youtube",
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        seen: dict[str, object] = {}
        real = h.repository.list_rules

        async def spy(**kwargs: object):
            seen.update(kwargs)
            return await real(**kwargs)

        h.repository.list_rules = spy  # type: ignore[method-assign]
        await h.service.list_rules(
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            exclude_app_rules=True,
        )
        assert seen["exclude_app_rules"] is True

    def test_the_repository_filter_is_app_key_is_null(self) -> None:
        from sqlalchemy import select
        from sqlalchemy.dialects import postgresql

        from app.database.utils.filters import AnyOfOrNull, apply_filters
        from app.domains.content_filtering.models import ContentFilterRule

        statement = apply_filters(
            select(ContentFilterRule),
            ContentFilterRule,
            {"app_key": AnyOfOrNull(values=())},
        )
        sql = str(statement.compile(dialect=postgresql.dialect()))
        assert "content_filter_rules.app_key IS NULL" in sql
