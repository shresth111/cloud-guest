"""The per-router forward-chain lock, and the read-only band status.

What these pin:

* **One writer per router.** A firewall push, a band placement and a
  content-filter push to the same router cannot overlap: the second caller
  gets a 409 ``FIREWALL_PUSH_IN_PROGRESS`` and the device is never called.
  Different routers do not contend.
* **Always released.** After success, after a refusal, after a failure, the
  key is gone. A holder whose TTL lapsed never deletes the lock a later
  holder took (token compare-and-delete).
* **A busy lock records nothing.** Rules keep the status they had: the
  device was not touched.
* **Band status** says ``ready`` / ``missing`` / ``invalid`` with venue text,
  never an ``.id`` or a comment, agrees with the push against the gateway's
  own fake RouterOS API, writes nothing, and is gated like the push.

Redis is an in-memory fake implementing exactly ``SET NX EX`` and the
release script's semantics. No Redis, router or database is contacted.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest
from wyfy_device_gateway.contract import FirewallBandStatus

from app.common.router_firewall_lock import (
    FIREWALL_PUSH_IN_PROGRESS,
    FIREWALL_PUSH_LOCK_REDIS_KEY_TEMPLATE,
    FIREWALL_PUSH_LOCK_TTL_SECONDS,
    router_firewall_lock,
)
from app.domains.content_filtering.exceptions import ContentFilterPushInProgressError
from app.domains.content_filtering.service import ContentFilterService
from app.domains.firewall import service as firewall_service_module
from app.domains.firewall.exceptions import (
    CrossLocationFirewallRuleAccessError,
    FirewallDeviceConnectionError,
    FirewallMissingCredentialsError,
    FirewallPushInProgressError,
    FirewallPushRefusedError,
    UnsupportedFirewallVendorError,
)
from app.domains.firewall.service import FirewallService
from app.domains.rbac.enums import ScopeType
from app.domains.router.device_domain_gate import (
    ControllerManagedFeatureUnavailableError,
)
from tests.unit import test_content_filtering as cf
from tests.unit import test_firewall_device_push as fw
from tests.unit.test_firewall_device_push import (
    FakeAdapter,
    FakeAudit,
    FakeRepo,
    FakeRouters,
    _permission_of,
    _router,
)
from tests.unit.test_firewall_device_push import (
    _rule as _fw_rule,
)

# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeRedis:
    """``SET key value NX EX ttl`` and the release script, nothing else."""

    store: dict[str, str] = field(default_factory=dict)
    ttls: dict[str, int] = field(default_factory=dict)
    evals: int = 0
    eval_raises: Exception | None = None

    async def set(
        self, key: str, value: str, *, nx: bool = False, ex: int | None = None
    ):
        assert nx is True, "the lock must be SET NX"
        assert ex is not None and ex > 0, "the lock must carry a TTL"
        if key in self.store:
            return None
        self.store[key] = value
        self.ttls[key] = ex
        return True

    async def eval(self, script: str, numkeys: int, key: str, token: str) -> int:
        self.evals += 1
        if self.eval_raises is not None:
            raise self.eval_raises
        assert numkeys == 1
        assert "get" in script and "del" in script
        if self.store.get(key) == token:
            del self.store[key]
            self.ttls.pop(key, None)
            return 1
        return 0


@pytest.fixture
def adapter(monkeypatch: pytest.MonkeyPatch) -> FakeAdapter:
    """Same shape as ``test_firewall_device_push``'s fixture of this name."""
    fake = FakeAdapter()

    def _get(vendor: str):
        if vendor != "mikrotik":
            raise UnsupportedFirewallVendorError(vendor)
        return fake

    monkeypatch.setattr(firewall_service_module, "get_firewall_adapter", _get)
    return fake


@pytest.fixture
def device(monkeypatch: pytest.MonkeyPatch):
    """The gateway's own fake RouterOS API behind ``librouteros.connect``."""
    import wyfy_device_gateway.mikrotik_adapter as gateway

    fake_module = fw._gateway_fake_api_module()

    class _Api(fake_module.FakeRouterOSApi):
        _n = 100

        def mint_id(self, row_count: int) -> str:
            type(self)._n += 1
            return f"*N{self._n}"

    def install(*, band: bool):
        api = _Api(menus={("ip", "firewall", "filter"): fw._lab_filter(band=band)})
        monkeypatch.setattr(gateway.librouteros, "connect", lambda **_: api)
        return api

    return install


def _key(router_id: uuid.UUID) -> str:
    return FIREWALL_PUSH_LOCK_REDIS_KEY_TEMPLATE.format(router_id=router_id)


@dataclass
class H:
    service: FirewallService
    repo: FakeRepo
    routers: FakeRouters
    redis: FakeRedis


def _harness(*, redis: FakeRedis | None = None, scope=None) -> H:
    redis = redis or FakeRedis()
    repo, routers = FakeRepo(), FakeRouters()
    service = FirewallService(
        repo,
        routers,
        audit_writer=FakeAudit(),
        caller_location_scope=scope,
        redis=redis,
    )
    return H(service, repo, routers, redis)


async def _push(h: H, router):
    return await h.service.push_rules_to_router(
        router.id,
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
    )


# ============================================================================
# The lock primitive
# ============================================================================


class TestLockPrimitive:
    async def test_taken_with_a_ttl_longer_than_a_slow_push_and_released(self) -> None:
        redis = FakeRedis()
        router_id = uuid.uuid4()
        async with router_firewall_lock(
            redis, router_id, busy_error=lambda: RuntimeError("busy")
        ):
            assert _key(router_id) in redis.store
            assert redis.ttls[_key(router_id)] == FIREWALL_PUSH_LOCK_TTL_SECONDS
        assert redis.store == {}
        # 10 s RouterOS socket timeout x (4N+2) calls, N = 14 rules.
        assert FIREWALL_PUSH_LOCK_TTL_SECONDS >= 10 * (4 * 14 + 2)

    async def test_released_when_the_body_raises(self) -> None:
        redis = FakeRedis()
        with pytest.raises(ValueError):
            async with router_firewall_lock(
                redis, uuid.uuid4(), busy_error=lambda: RuntimeError("busy")
            ):
                raise ValueError("push failed")
        assert redis.store == {}

    async def test_a_held_lock_raises_the_callers_error_and_runs_nothing(self) -> None:
        redis = FakeRedis()
        router_id = uuid.uuid4()
        redis.store[_key(router_id)] = "someone-else"
        ran = False
        with pytest.raises(RuntimeError, match="busy"):
            async with router_firewall_lock(
                redis, router_id, busy_error=lambda: RuntimeError("busy")
            ):
                ran = True
        assert ran is False
        assert redis.store[_key(router_id)] == "someone-else"

    async def test_a_lapsed_holder_never_deletes_a_later_holders_lock(self) -> None:
        redis = FakeRedis()
        router_id = uuid.uuid4()
        async with router_firewall_lock(
            redis, router_id, busy_error=lambda: RuntimeError("busy")
        ):
            # Our TTL lapsed and a second push took the lock.
            redis.store[_key(router_id)] = "second-holder"
        assert redis.store[_key(router_id)] == "second-holder"

    async def test_a_failed_release_does_not_mask_the_outcome(self) -> None:
        redis = FakeRedis(eval_raises=ConnectionError("redis went away"))
        async with router_firewall_lock(
            redis, uuid.uuid4(), busy_error=lambda: RuntimeError("busy")
        ):
            pass  # no exception escapes: the TTL frees it
        with pytest.raises(ValueError, match="the push's own"):
            async with router_firewall_lock(
                FakeRedis(eval_raises=ConnectionError("x")),
                uuid.uuid4(),
                busy_error=lambda: RuntimeError("busy"),
            ):
                raise ValueError("the push's own error")

    async def test_different_routers_do_not_contend(self) -> None:
        redis = FakeRedis()
        async with (
            router_firewall_lock(
                redis, uuid.uuid4(), busy_error=lambda: RuntimeError("busy")
            ),
            router_firewall_lock(
                redis, uuid.uuid4(), busy_error=lambda: RuntimeError("busy")
            ),
        ):
            assert len(redis.store) == 2
        assert redis.store == {}


# ============================================================================
# Firewall push and band placement under the lock
# ============================================================================


class TestFirewallPushLock:
    async def test_a_second_push_is_a_409_and_the_device_is_not_called(
        self, adapter
    ) -> None:
        h = _harness()
        router = h.routers.add(_router())
        rule = await _fw_rule(h, router, priority=10)
        h.redis.store[_key(router.id)] = "first-push"

        with pytest.raises(FirewallPushInProgressError) as caught:
            await _push(h, router)

        assert caught.value.status_code == 409
        assert caught.value.data["code"] == FIREWALL_PUSH_IN_PROGRESS
        assert adapter.syncs == []
        # Nothing was attempted, so nothing is recorded as failed.
        assert rule.device_push_status == "pending"
        assert rule.device_push_error is None
        assert h.repo.commits == 0

    async def test_two_concurrent_pushes_one_runs_one_is_refused(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        await _fw_rule(h, router, priority=10)
        started, release = asyncio.Event(), asyncio.Event()
        original = adapter.sync_firewall_rules

        async def slow_sync(credentials, *, rules, known_rule_ids):
            started.set()
            await release.wait()
            return await original(
                credentials, rules=rules, known_rule_ids=known_rule_ids
            )

        adapter.sync_firewall_rules = slow_sync  # type: ignore[method-assign]

        first = asyncio.create_task(_push(h, router))
        await started.wait()
        with pytest.raises(FirewallPushInProgressError):
            await _push(h, router)
        release.set()
        await first

        assert len(adapter.syncs) == 1
        assert h.redis.store == {}
        # And the router is free again afterwards.
        await _push(h, router)
        assert len(adapter.syncs) == 2

    async def test_released_after_a_refused_push(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        await _fw_rule(h, router, priority=10)
        adapter.raises = FirewallPushRefusedError(
            "ACCESS_RULES_BAND_MISSING", "no band"
        )
        with pytest.raises(FirewallPushRefusedError):
            await _push(h, router)
        assert h.redis.store == {}

    async def test_a_precondition_failure_is_not_masked_by_the_lock(
        self, adapter
    ) -> None:
        """A held lock must not hide a 4xx that names the real problem."""
        h = _harness()
        router = h.routers.add(_router())
        await _fw_rule(h, router, priority=10)
        h.routers.secret = None
        h.redis.store[_key(router.id)] = "first-push"
        with pytest.raises(FirewallMissingCredentialsError):
            await _push(h, router)

    async def test_band_placement_shares_the_lock(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        h.redis.store[_key(router.id)] = "a-push"
        with pytest.raises(FirewallPushInProgressError) as caught:
            await h.service.install_firewall_band(router.id, actor_user_id=None)
        assert caught.value.data["code"] == FIREWALL_PUSH_IN_PROGRESS
        assert adapter.bands == 0

        del h.redis.store[_key(router.id)]
        await h.service.install_firewall_band(router.id, actor_user_id=None)
        assert adapter.bands == 1
        assert h.redis.store == {}

    async def test_another_router_is_not_blocked(self, adapter) -> None:
        h = _harness()
        busy = h.routers.add(_router())
        free = h.routers.add(_router())
        await _fw_rule(h, free, priority=10)
        h.redis.store[_key(busy.id)] = "a-push"
        await _push(h, free)
        assert len(adapter.syncs) == 1


# ============================================================================
# Content filtering shares the router's lock
# ============================================================================


class TestContentFilterSharesTheLock:
    def _cf_harness(self, redis: FakeRedis):
        repo = cf.FakeContentFilterRepository()
        lookup = cf.FakeRouterLookup()
        service = ContentFilterService(
            repo, lookup, audit_writer=cf.FakeAuditLogWriter(), redis=redis
        )
        return cf.Harness(
            service=service,
            repository=repo,
            router_lookup=lookup,
            audit_writer=cf.FakeAuditLogWriter(),
        )

    @pytest.fixture
    def cf_adapter(self, monkeypatch: pytest.MonkeyPatch):
        fake = cf.FakeContentFilterAdapter()
        monkeypatch.setattr(
            "app.domains.content_filtering.service.get_content_filter_adapter",
            lambda vendor: fake,
        )
        return fake

    async def test_a_content_filter_push_waits_for_a_firewall_push(
        self, cf_adapter
    ) -> None:
        redis = FakeRedis()
        h = self._cf_harness(redis)
        router = h.router_lookup.add(cf._make_router())
        rule = await cf._create_rule(h, router)
        redis.store[_key(router.id)] = "firewall-push"

        with pytest.raises(ContentFilterPushInProgressError) as caught:
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert caught.value.status_code == 409
        assert caught.value.data["code"] == FIREWALL_PUSH_IN_PROGRESS
        assert cf_adapter.calls == []
        assert rule.device_push_status == "pending"

    async def test_a_firewall_push_waits_for_a_content_filter_push(
        self, cf_adapter, adapter
    ) -> None:
        redis = FakeRedis()
        cfh = self._cf_harness(redis)
        router = cfh.router_lookup.add(cf._make_router())
        rule = await cf._create_rule(cfh, router)
        fwh = _harness(redis=redis)
        fwh.routers.add(router)

        started, release = asyncio.Event(), asyncio.Event()

        async def slow_configure(credentials, **kwargs: Any) -> None:
            started.set()
            await release.wait()

        cf_adapter.configure_content_filter_rule = slow_configure  # type: ignore[method-assign]
        cf_push = asyncio.create_task(
            cfh.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        )
        await started.wait()
        with pytest.raises(FirewallPushInProgressError):
            await _push(fwh, router)
        release.set()
        await cf_push
        assert adapter.syncs == []
        assert redis.store == {}

    async def test_released_after_a_failed_content_filter_push(
        self, cf_adapter
    ) -> None:
        redis = FakeRedis()
        h = self._cf_harness(redis)
        router = h.router_lookup.add(cf._make_router())
        rule = await cf._create_rule(h, router)
        cf_adapter.raises = RuntimeError("device said no")
        with pytest.raises(RuntimeError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert redis.store == {}


# ============================================================================
# Band status (service)
# ============================================================================


async def _band(h: H, router):
    return await h.service.read_firewall_band_state(
        router.id, requesting_organization_id=router.organization_id
    )


class TestBandStatusService:
    async def test_ready_has_no_reason(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        state = await _band(h, router)
        assert (state.state, state.reason) == ("ready", None)
        assert state.checked_at.tzinfo is not None

    @pytest.mark.parametrize(
        ("state", "code"),
        [
            ("missing", "BAND_NOT_PLACED"),
            ("invalid", "BAND_PARTIAL"),
            ("invalid", "BAND_DUPLICATED"),
            ("invalid", "BAND_INVERTED"),
            ("invalid", "BAND_SENTINEL_NOT_PASSTHROUGH"),
            ("invalid", "SOMETHING_NEW"),
        ],
    )
    async def test_every_reason_is_venue_text_without_device_internals(
        self, adapter, state, code
    ) -> None:
        h = _harness()
        router = h.routers.add(_router())
        adapter.band_status = FirewallBandStatus(state=state, reason=code)
        result = await _band(h, router)
        assert result.state == state
        assert result.reason
        for leak in ("cloudguest-fw", "*", ".id", "passthrough", code):
            assert leak not in result.reason

    async def test_reads_take_no_lock_and_are_not_blocked_by_one(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        h.redis.store[_key(router.id)] = "a-push"
        await _band(h, router)
        assert adapter.band_reads == 1
        assert h.redis.store == {_key(router.id): "a-push"}

    async def test_an_omada_router_is_refused_before_any_read(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router(vendor="tplink_omada"))
        with pytest.raises(ControllerManagedFeatureUnavailableError):
            await _band(h, router)
        assert adapter.band_reads == 0

    async def test_a_site_confined_caller_cannot_read_another_site(
        self, adapter
    ) -> None:
        h = _harness(scope=frozenset({uuid.uuid4()}))
        router = h.routers.add(_router())
        with pytest.raises(CrossLocationFirewallRuleAccessError):
            await _band(h, router)
        assert adapter.band_reads == 0

    async def test_missing_credentials_raise_without_a_connection(
        self, adapter
    ) -> None:
        h = _harness()
        router = h.routers.add(_router())
        h.routers.secret = None
        with pytest.raises(FirewallMissingCredentialsError):
            await _band(h, router)
        assert adapter.band_reads == 0

    async def test_an_unreachable_router_is_a_502(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        adapter.raises = FirewallDeviceConnectionError("10.0.0.1", "timed out")
        with pytest.raises(FirewallDeviceConnectionError) as caught:
            await _band(h, router)
        assert caught.value.status_code == 502


# ============================================================================
# Band status (route)
# ============================================================================


class TestBandStatusRoute:
    def _get_route(self):
        from app.domains.firewall.router import router as firewall_router

        for route in firewall_router.routes:
            if (
                route.path.endswith("/routers/{router_id}/band")
                and "GET" in route.methods
            ):
                return route
        raise AssertionError("GET /routers/{router_id}/band is not registered")

    def test_read_pinned_to_router_scope(self) -> None:
        cells, path = _permission_of(self._get_route())
        assert path == "/firewall-rules/routers/{router_id}/band"
        assert "firewall.read" in cells
        assert ScopeType.ROUTER in cells

    def test_the_response_shape_is_state_reason_checked_at_only(self) -> None:
        from app.domains.firewall.schemas import FirewallBandStatusResponse

        assert set(FirewallBandStatusResponse.model_fields) == {
            "state",
            "reason",
            "checked_at",
        }


# ============================================================================
# Band status end to end: real adapter, vendored gateway, fake RouterOS API
# ============================================================================


class TestBandStatusEndToEnd:
    @pytest.mark.parametrize(
        ("band", "expected"), [(True, "ready"), (False, "missing")]
    )
    async def test_reads_the_band_and_writes_nothing(
        self, device, band, expected
    ) -> None:
        api = device(band=band)
        h = _harness()
        router = h.routers.add(_router())
        state = await _band(h, router)
        assert state.state == expected
        assert api.ops == []

    async def test_ready_agrees_with_a_push_that_goes_through(self, device) -> None:
        device(band=True)
        h = _harness()
        router = h.routers.add(_router())
        await _fw_rule(h, router, priority=10)
        assert (await _band(h, router)).state == "ready"
        outcome = await _push(h, router)
        assert outcome.added == 1

    async def test_missing_agrees_with_a_push_that_is_refused(self, device) -> None:
        device(band=False)
        h = _harness()
        router = h.routers.add(_router())
        await _fw_rule(h, router, priority=10)
        assert (await _band(h, router)).state == "missing"
        with pytest.raises(FirewallPushRefusedError) as caught:
            await _push(h, router)
        assert caught.value.data == {"code": "ACCESS_RULES_BAND_MISSING"}
