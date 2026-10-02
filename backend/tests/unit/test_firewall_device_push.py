"""The firewall push: a router's rules reach the device over 8728.

Two layers are tested here.

1. **The service, against a fake adapter** -- what is sent (enabled rules
   only, in ``forward`` only, protocol ``all`` as "any", every rule id the
   router has ever had as ``known_rule_ids``), what each row says afterwards
   on success and on each failure shape, the Omada refusal, the credential
   and scope gates, and the edit demotion.
2. **End to end through the real adapter and gateway**, with
   ``librouteros.connect`` patched to the gateway's own write-capable fake
   RouterOS API: band present -> rules land in the band in priority order;
   band missing -> a 409 carrying ``ACCESS_RULES_BAND_MISSING`` and not one
   write. The gateway's own ordering/idempotency/marker tests live in
   ``vendor/wyfy-device-gateway/tests/test_mikrotik_firewall.py``.

No router, controller, hub or database is contacted. Nothing here proves the
push on hardware.
"""

from __future__ import annotations

import importlib.util
import pathlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest
from wyfy_device_gateway.contract import (
    FirewallBandResult,
    FirewallBandStatus,
    FirewallSyncResult,
)

from app.domains.firewall import service as firewall_service_module
from app.domains.firewall.constants import (
    DEVICE_CARRIED_FIELDS,
    FirewallAction,
    FirewallChain,
    FirewallDevicePushStatus,
    FirewallProtocol,
)
from app.domains.firewall.exceptions import (
    CrossLocationFirewallRuleAccessError,
    FirewallChainNotPushableError,
    FirewallMissingCredentialsError,
    FirewallPushFailedError,
    FirewallPushRefusedError,
    UnsupportedFirewallVendorError,
)
from app.domains.firewall.models import FirewallRule
from app.domains.firewall.router import router as firewall_router
from app.domains.firewall.service import FirewallService
from app.domains.rbac.enums import AuditAction, ScopeType
from app.domains.router.device_domain_gate import (
    ControllerManagedFeatureUnavailableError,
)
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router


def _now() -> datetime:
    return datetime.now(UTC)


def _base(**overrides: object) -> dict[str, object]:
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


def _router(
    *, vendor: str = "mikrotik", location_id: uuid.UUID | None = None
) -> Router:
    return Router(
        **_base(
            organization_id=uuid.uuid4(),
            location_id=location_id or uuid.uuid4(),
            name="Lobby gateway",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="hEX lite",
            vendor=vendor,
            routeros_version="7.23.3",
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


@dataclass
class FakeRepo:
    rules: dict[uuid.UUID, FirewallRule] = field(default_factory=dict)
    commits: int = 0

    async def create_rule(self, **fields: object) -> FirewallRule:
        rule = FirewallRule(**_base(**fields))
        self.rules[rule.id] = rule
        return rule

    async def get_rule_by_id(self, rule_id, *, include_deleted: bool = False):
        rule = self.rules.get(rule_id)
        if rule is None or (rule.is_deleted and not include_deleted):
            return None
        return rule

    async def update_rule(self, rule: FirewallRule, data: dict[str, object]):
        for key, value in data.items():
            setattr(rule, key, value)
        return rule

    async def soft_delete_rule(self, rule: FirewallRule) -> FirewallRule:
        rule.is_deleted = True
        return rule

    async def list_rules(self, **_kw: object):  # pragma: no cover - unused
        raise NotImplementedError

    async def list_rules_for_router(self, router_id):
        rows = [
            r
            for r in self.rules.values()
            if r.router_id == router_id and not r.is_deleted
        ]
        return sorted(rows, key=lambda r: r.priority)

    async def list_rule_ids_for_router(self, router_id):
        return [r.id for r in self.rules.values() if r.router_id == router_id]

    async def commit(self) -> None:
        self.commits += 1


@dataclass
class FakeRouters:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)
    secret: str | None = "s3cret"

    def add(self, router: Router) -> Router:
        self.routers[router.id] = router
        return router

    async def get_router(
        self, router_id, *, requesting_organization_id=None, include_deleted=False
    ):
        router = self.routers.get(router_id)
        if router is None or (
            requesting_organization_id is not None
            and router.organization_id != requesting_organization_id
        ):
            raise RouterNotFoundError(router_id)
        return router

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.secret


@dataclass
class FakeAudit:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object):
        self.entries.append(fields)
        return fields


@dataclass
class FakeAdapter:
    vendor: str = "mikrotik"
    syncs: list[dict[str, Any]] = field(default_factory=list)
    bands: int = 0
    raises: Exception | None = None
    result: FirewallSyncResult | None = None

    async def sync_firewall_rules(self, credentials, *, rules, known_rule_ids):
        self.syncs.append(
            {
                "host": credentials.host,
                "rules": list(rules),
                "known": list(known_rule_ids),
            }
        )
        if self.raises is not None:
            raise self.raises
        return self.result or FirewallSyncResult(
            added=len(rules),
            removed=0,
            unchanged=0,
            ordered_rule_ids=tuple(r.rule_id for r in rules),
        )

    async def install_firewall_band(self, credentials):
        self.bands += 1
        if self.raises is not None:
            raise self.raises
        return FirewallBandResult(
            created=True, begin_id="*BB", end_id="*BE", anchor_id="*E"
        )

    band_status: FirewallBandStatus = field(
        default_factory=lambda: FirewallBandStatus(state="ready", reason=None)
    )
    band_reads: int = 0

    async def read_firewall_band_status(self, credentials):
        self.band_reads += 1
        if self.raises is not None:
            raise self.raises
        return self.band_status


@dataclass
class H:
    service: FirewallService
    repo: FakeRepo
    routers: FakeRouters
    audit: FakeAudit


def _harness(scope=None) -> H:
    repo, routers, audit = FakeRepo(), FakeRouters(), FakeAudit()
    return H(
        FirewallService(repo, routers, audit_writer=audit, caller_location_scope=scope),
        repo,
        routers,
        audit,
    )


@pytest.fixture
def adapter(monkeypatch: pytest.MonkeyPatch) -> FakeAdapter:
    fake = FakeAdapter()

    def _get(vendor: str):
        if vendor != "mikrotik":
            raise UnsupportedFirewallVendorError(vendor)
        return fake

    monkeypatch.setattr(firewall_service_module, "get_firewall_adapter", _get)
    return fake


async def _rule(
    h: H, router: Router, *, priority: int, **overrides: Any
) -> FirewallRule:
    fields: dict[str, Any] = {
        "chain": FirewallChain.FORWARD,
        "action": FirewallAction.DROP,
        "protocol": FirewallProtocol.ALL,
        "source_address": "10.10.0.0/24",
        "destination_address": "10.20.0.0/24",
    }
    fields.update(overrides)
    return await h.service.create_rule(
        actor_user_id=None,
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        name=f"rule {priority}",
        priority=priority,
        **fields,
    )


async def _push(h: H, router: Router):
    return await h.service.push_rules_to_router(
        router.id,
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
    )


# ============================================================================
# 1. The service
# ============================================================================


class TestWhatIsSent:
    async def test_enabled_rules_go_to_the_router_in_priority_order(
        self, adapter
    ) -> None:
        h = _harness()
        router = h.routers.add(_router())
        late = await _rule(h, router, priority=30)
        early = await _rule(
            h, router, priority=10, protocol=FirewallProtocol.TCP, destination_port=445
        )
        await _rule(h, router, priority=20, is_enabled=False)

        await _push(h, router)

        (call,) = adapter.syncs
        assert [c.rule_id for c in call["rules"]] == [str(early.id), str(late.id)]
        first = call["rules"][0]
        assert (first.chain, first.action, first.protocol, first.dst_port) == (
            "forward",
            "drop",
            "tcp",
            445,
        )
        # "all" is sent as "any", which the writer renders by omitting it.
        assert call["rules"][1].protocol is None
        assert call["host"] == "10.0.0.1"

    async def test_known_ids_include_deleted_rules_so_their_removal_is_not_an_orphan(
        self, adapter
    ) -> None:
        h = _harness()
        router = h.routers.add(_router())
        keep = await _rule(h, router, priority=10)
        gone = await _rule(h, router, priority=20)
        await h.service.delete_rule(
            gone.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        await _push(h, router)

        (call,) = adapter.syncs
        assert [c.rule_id for c in call["rules"]] == [str(keep.id)]
        assert set(call["known"]) == {str(keep.id), str(gone.id)}

    async def test_a_rule_on_another_router_is_never_sent(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        other = h.routers.add(_router())
        await _rule(h, router, priority=10)
        stranger = await _rule(h, other, priority=5)
        await _push(h, router)
        assert str(stranger.id) not in {c.rule_id for c in adapter.syncs[0]["rules"]}
        assert str(stranger.id) not in adapter.syncs[0]["known"]


class TestStatusAfterPush:
    async def test_success_marks_enabled_active_and_disabled_pending(
        self, adapter
    ) -> None:
        h = _harness()
        router = h.routers.add(_router())
        on = await _rule(h, router, priority=10)
        off = await _rule(h, router, priority=20, is_enabled=False)
        off.device_push_status = FirewallDevicePushStatus.ACTIVE.value
        off.device_pushed_at = _now()

        outcome = await _push(h, router)

        assert on.device_push_status == "active"
        assert on.device_pushed_at is not None
        assert on.device_push_error is None
        # The push just took the disabled rule off the router.
        assert off.device_push_status == "pending"
        assert off.device_pushed_at is None
        assert outcome.added == 1
        (entry,) = [
            e
            for e in h.audit.entries
            if e["action"] == AuditAction.FIREWALL_RULES_PUSHED.value
        ]
        assert entry["entity_type"] == "router"
        assert entry["entity_id"] == router.id

    async def test_a_refusal_leaves_active_rules_active_and_fails_the_rest(
        self, adapter
    ) -> None:
        h = _harness()
        router = h.routers.add(_router())
        live = await _rule(h, router, priority=10)
        live.device_push_status = FirewallDevicePushStatus.ACTIVE.value
        new = await _rule(h, router, priority=20)
        adapter.raises = FirewallPushRefusedError(
            "ACCESS_RULES_BAND_MISSING", "no band"
        )

        with pytest.raises(FirewallPushRefusedError) as caught:
            await _push(h, router)

        assert caught.value.status_code == 409
        assert caught.value.data == {"code": "ACCESS_RULES_BAND_MISSING"}
        # Nothing on the device changed, so the live rule is still live.
        assert live.device_push_status == "active"
        assert new.device_push_status == "failed"
        assert "no band" in new.device_push_error
        assert h.repo.commits == 1

    async def test_a_restored_failure_is_treated_like_a_refusal(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        live = await _rule(h, router, priority=10)
        live.device_push_status = FirewallDevicePushStatus.ACTIVE.value
        adapter.raises = FirewallPushFailedError("boom", restored=True)
        with pytest.raises(FirewallPushFailedError) as caught:
            await _push(h, router)
        assert caught.value.data == {
            "code": "ACCESS_RULES_PUSH_FAILED",
            "restored": True,
        }
        assert live.device_push_status == "active"

    async def test_an_unrestored_failure_fails_every_enabled_rule(
        self, adapter
    ) -> None:
        h = _harness()
        router = h.routers.add(_router())
        live = await _rule(h, router, priority=10)
        live.device_push_status = FirewallDevicePushStatus.ACTIVE.value
        other = await _rule(h, router, priority=20)
        adapter.raises = FirewallPushFailedError("connection lost", restored=False)

        with pytest.raises(FirewallPushFailedError):
            await _push(h, router)

        # The device is in an unknown state; no row may still claim "active".
        assert live.device_push_status == "failed"
        assert other.device_push_status == "failed"
        assert h.repo.commits == 1


class TestRefusedBeforeAnySocket:
    async def test_an_omada_router_is_refused_at_create(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router(vendor="tplink_omada"))
        with pytest.raises(ControllerManagedFeatureUnavailableError) as caught:
            await _rule(h, router, priority=10)
        assert "Firewall Rules" in str(caught.value)
        assert h.repo.rules == {}

    async def test_an_omada_router_is_refused_at_push(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        await _rule(h, router, priority=10)
        router.vendor = "tplink_omada"  # a row relabelled after the fact
        with pytest.raises(ControllerManagedFeatureUnavailableError):
            await _push(h, router)
        assert adapter.syncs == []

    async def test_an_omada_router_cannot_have_a_band_placed(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router(vendor="tplink_omada"))
        with pytest.raises(ControllerManagedFeatureUnavailableError):
            await h.service.install_firewall_band(router.id, actor_user_id=None)
        assert adapter.bands == 0

    async def test_an_enabled_input_rule_refuses_the_push_naming_it(
        self, adapter
    ) -> None:
        h = _harness()
        router = h.routers.add(_router())
        await _rule(h, router, priority=10)
        await _rule(h, router, priority=20, chain=FirewallChain.INPUT)
        with pytest.raises(FirewallChainNotPushableError) as caught:
            await _push(h, router)
        assert caught.value.status_code == 422
        assert caught.value.data["rules"] == ["rule 20"]
        assert adapter.syncs == []

    async def test_a_disabled_input_rule_does_not_block_the_push(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        await _rule(h, router, priority=10)
        await _rule(h, router, priority=20, chain=FirewallChain.INPUT, is_enabled=False)
        await _push(h, router)
        assert len(adapter.syncs) == 1

    async def test_missing_credentials_raise_without_a_connection(
        self, adapter
    ) -> None:
        h = _harness()
        router = h.routers.add(_router())
        await _rule(h, router, priority=10)
        h.routers.secret = None
        with pytest.raises(FirewallMissingCredentialsError):
            await _push(h, router)
        assert adapter.syncs == []

    async def test_a_site_confined_caller_cannot_push_another_site(
        self, adapter
    ) -> None:
        h = _harness(scope=frozenset({uuid.uuid4()}))
        router = h.routers.add(_router())
        with pytest.raises(CrossLocationFirewallRuleAccessError):
            await _push(h, router)
        assert adapter.syncs == []

    async def test_an_unknown_vendor_is_a_typed_400(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        await _rule(h, router, priority=10)
        router.vendor = "MikroTik"
        with pytest.raises(UnsupportedFirewallVendorError) as caught:
            await _push(h, router)
        assert caught.value.status_code == 400


class TestEditDemotesALiveRule:
    async def _live(self, h: H, router: Router) -> FirewallRule:
        rule = await _rule(h, router, priority=10)
        rule.device_push_status = FirewallDevicePushStatus.ACTIVE.value
        return rule

    @pytest.mark.parametrize(
        ("field_name", "value"),
        [
            ("destination_address", "10.30.0.0/24"),
            ("priority", 99),
            ("is_enabled", False),
            ("action", FirewallAction.ACCEPT),
        ],
    )
    async def test_a_device_carried_edit_demotes_to_pending(
        self, adapter, field_name, value
    ) -> None:
        h = _harness()
        router = h.routers.add(_router())
        rule = await self._live(h, router)
        await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            **{field_name: value},
        )
        assert rule.device_push_status == "pending"

    async def test_a_rename_does_not(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        rule = await self._live(h, router)
        await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="renamed",
            comment="a note",
        )
        assert rule.device_push_status == "active"

    def test_is_enabled_is_device_carried_here(self) -> None:
        """Unlike every other domain: a disabled rule is removed by the next
        push, so until then the router still carries it."""
        assert "is_enabled" in DEVICE_CARRIED_FIELDS
        assert "name" not in DEVICE_CARRIED_FIELDS
        assert "comment" not in DEVICE_CARRIED_FIELDS


class TestBandService:
    async def test_placing_a_band_is_audited(self, adapter) -> None:
        h = _harness()
        router = h.routers.add(_router())
        result = await h.service.install_firewall_band(router.id, actor_user_id=None)
        assert result.created is True
        assert [e["action"] for e in h.audit.entries] == [
            AuditAction.FIREWALL_BAND_INSTALLED.value
        ]


# ============================================================================
# 2. Routes: permission and pinned scope
# ============================================================================


def _permission_of(route) -> tuple[set[object], str]:
    for dep in route.dependant.dependencies:
        call = dep.call
        if getattr(call, "__qualname__", "").startswith("RequirePermission"):
            cells = {c.cell_contents for c in (call.__closure__ or ())}
            return cells, route.path
    raise AssertionError(f"{route.path} has no RequirePermission")


class TestRoutes:
    def _route(self, suffix: str, method: str = "POST"):
        for route in firewall_router.routes:
            if route.path.endswith(suffix) and method in route.methods:
                return route
        raise AssertionError(suffix)

    def test_push_is_execute_pinned_to_router_scope(self) -> None:
        cells, _ = _permission_of(self._route("/routers/{router_id}/push"))
        assert "firewall.execute" in cells
        assert ScopeType.ROUTER in cells

    def test_band_is_manage_pinned_to_global_scope(self) -> None:
        """A venue can never place or move the band -- only a platform grant."""
        cells, _ = _permission_of(self._route("/routers/{router_id}/band"))
        assert "firewall.manage" in cells
        assert ScopeType.GLOBAL in cells

    def test_no_new_permission_key_was_needed(self) -> None:
        from app.domains.rbac.enums import PermissionAction, PermissionModule
        from app.domains.rbac.seed import MODULE_ACTIONS

        actions = MODULE_ACTIONS[PermissionModule.FIREWALL]
        assert PermissionAction.EXECUTE in actions
        assert PermissionAction.MANAGE in actions


# ============================================================================
# 3. End to end through the real adapter and the vendored gateway
# ============================================================================


def _gateway_fake_api_module():
    """The gateway's own write-capable fake, loaded by path: from the backend
    root ``tests`` is this suite's package, not the gateway's."""
    path = (
        pathlib.Path(__file__).parents[2]
        / "vendor"
        / "wyfy-device-gateway"
        / "tests"
        / "fake_write_transport.py"
    )
    spec = importlib.util.spec_from_file_location("_gateway_fake_write_transport", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _lab_filter(*, band: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [
        {
            ".id": "*W",
            "chain": "input",
            "action": "accept",
            "in-interface": "wg-cloudguard",
            "comment": "cloudguest-fw-allow-wg-mgmt",
        },
        {
            ".id": "*D1",
            "chain": "forward",
            "action": "jump",
            "jump-target": "hs-unauth",
            "dynamic": True,
        },
    ]
    if band:
        rows += [
            {
                ".id": "*BB",
                "chain": "forward",
                "action": "passthrough",
                "comment": "cloudguest-fw-band-begin",
            },
            {
                ".id": "*BE",
                "chain": "forward",
                "action": "passthrough",
                "comment": "cloudguest-fw-band-end",
            },
        ]
    rows.append(
        {
            ".id": "*E",
            "chain": "forward",
            "action": "accept",
            "connection-state": "established,related",
            "comment": "cloudguest-fw-fwd-established",
        }
    )
    return rows


@pytest.fixture
def device(monkeypatch: pytest.MonkeyPatch):
    import wyfy_device_gateway.mikrotik_adapter as gateway

    fake_module = _gateway_fake_api_module()

    class _Api(fake_module.FakeRouterOSApi):
        _n = 100

        def mint_id(self, row_count: int) -> str:
            type(self)._n += 1
            return f"*N{self._n}"

    holder: dict[str, Any] = {}

    def install(*, band: bool):
        api = _Api(menus={("ip", "firewall", "filter"): _lab_filter(band=band)})
        monkeypatch.setattr(gateway.librouteros, "connect", lambda **_: api)
        holder["api"] = api
        return api

    return install


class TestEndToEnd:
    async def test_rules_land_in_the_band_in_priority_order(self, device) -> None:
        api = device(band=True)
        h = _harness()
        router = h.routers.add(_router())
        second = await _rule(h, router, priority=20)
        first = await _rule(
            h,
            router,
            priority=10,
            action=FirewallAction.REJECT,
            protocol=FirewallProtocol.TCP,
            destination_port=445,
        )

        outcome = await _push(h, router)

        forward = [
            r for r in api.path("ip", "firewall", "filter") if r["chain"] == "forward"
        ]
        comments = [r.get("comment") for r in forward]
        begin = comments.index("cloudguest-fw-band-begin")
        end = comments.index("cloudguest-fw-band-end")
        assert comments[begin + 1 : end] == [
            f"cloudguest-fw:{first.id}",
            f"cloudguest-fw:{second.id}",
        ]
        assert comments[end + 1] == "cloudguest-fw-fwd-established"
        assert first.device_push_status == second.device_push_status == "active"
        assert (outcome.added, outcome.removed, outcome.unchanged) == (2, 0, 0)

        api.ops.clear()
        again = await _push(h, router)
        assert api.ops == []
        assert (again.added, again.unchanged) == (0, 2)

    async def test_no_band_is_a_409_with_the_code_and_no_write(self, device) -> None:
        api = device(band=False)
        h = _harness()
        router = h.routers.add(_router())
        rule = await _rule(h, router, priority=10)

        with pytest.raises(FirewallPushRefusedError) as caught:
            await _push(h, router)

        assert caught.value.status_code == 409
        assert caught.value.data == {"code": "ACCESS_RULES_BAND_MISSING"}
        assert api.ops == []
        assert rule.device_push_status == "failed"
        assert "ACCESS_RULES_BAND_MISSING" in rule.device_push_error

    async def test_band_install_then_push(self, device) -> None:
        api = device(band=False)
        h = _harness()
        router = h.routers.add(_router())
        rule = await _rule(h, router, priority=10)

        band = await h.service.install_firewall_band(router.id, actor_user_id=None)
        assert band.created is True and band.anchor_id == "*E"
        await _push(h, router)

        comments = [
            r.get("comment")
            for r in api.path("ip", "firewall", "filter")
            if r["chain"] == "forward"
        ]
        assert comments.index(f"cloudguest-fw:{rule.id}") < comments.index(
            "cloudguest-fw-fwd-established"
        )
        # The input chain -- where the management accept lives -- is untouched.
        assert all(f["chain"] == "forward" for _, f in api.add_calls)
