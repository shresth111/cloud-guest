"""A blocked device is really cut off on the venue's MikroTik routers.

The defect: a ``BLOCKLIST`` device rule (block this MAC) was a sign-in check
only. A device already online stayed online, and a device the venue had
bypassed never met the check at all. These tests drive
``GuestAccessService`` with the real ``RouterDeviceBlocker``, the real
``MikroTikGuestAccessAdapter`` and the vendored gateway, against the
gateway's own write-capable fake RouterOS API, and assert what the fake
router's tables hold afterwards:

* block -> one ``type=blocked`` ip-binding with ``cloudguest-devblock:<rule>``
  on each MikroTik router in scope, and the device's live session gone;
* unblock (deactivate or delete) -> exactly that binding removed;
* an unreachable router is recorded ``failed`` without failing the rule;
* an Omada (controller-managed) router is never written to;
* a non-blocklist rule touches no router.

No router is contacted.
"""

from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import pytest

from app.domains.guest_access import dependencies as guest_access_dependencies
from app.domains.guest_access.constants import AccessRuleType
from app.domains.guest_access.device_blocking import RouterDeviceBlocker
from app.domains.guest_access.models import DeviceAccessRouterBlock, DeviceAccessRule
from app.domains.guest_access.router import router as guest_access_router
from app.domains.guest_access.schemas import DeviceAccessRuleResponse
from app.domains.guest_access.service import GuestAccessService
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router

from .test_firewall_device_push import _base, _gateway_fake_api_module
from .test_guest_access import (
    FakeAuditLogWriter,
    FakeGuestAccessRepository,
    FakeLocationLookup,
)

MAC = "02:00:00:00:00:99"
_BINDING = ("ip", "hotspot", "ip-binding")
_ACTIVE = ("ip", "hotspot", "active")


@dataclass
class _Repo(FakeGuestAccessRepository):
    router_blocks: list[DeviceAccessRouterBlock] = field(default_factory=list)
    commits: int = 0

    async def commit(self) -> None:
        self.commits += 1

    async def delete_device_rule(self, rule: DeviceAccessRule) -> None:
        rule.is_deleted = True

    async def record_router_block(self, rule, *, router_id, **fields):
        for block in self.router_blocks:
            if block.rule_id == rule.id and block.router_id == router_id:
                for key, value in {
                    **fields,
                    "cleared_at": None,
                    "release_error": None,
                }.items():
                    setattr(block, key, value)
                return block
        block = DeviceAccessRouterBlock(
            **_base(rule_id=rule.id, router_id=router_id, **fields)
        )
        self.router_blocks.append(block)
        rule.router_blocks.append(block)
        return block

    async def update_router_block(self, block, data):
        for key, value in data.items():
            setattr(block, key, value)
        return block

    async def list_open_router_blocks(self, *, rule_id):
        return [
            b
            for b in self.router_blocks
            if b.rule_id == rule_id
            and b.status != "not_applicable"
            and b.cleared_at is None
        ]

    async def list_open_router_blocks_for_expired_rules(
        self, *, now: datetime, limit: int
    ):  # pragma: no cover - SQL, exercised in the repository
        return []


@dataclass
class _Routers:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)
    secret: str | None = "s3cret"

    def add(self, router: Router) -> Router:
        self.routers[router.id] = router
        return router

    async def list_routers_in_scope(self, *, organization_id, location_id):
        return [
            r
            for r in self.routers.values()
            if r.organization_id == organization_id
            and (location_id is None or r.location_id == location_id)
            and not r.is_deleted
        ]

    async def get_router(
        self, router_id, *, requesting_organization_id=None, include_deleted=False
    ):
        router = self.routers.get(router_id)
        if router is None:
            raise RouterNotFoundError(router_id)
        return router

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.secret


def _router(org: uuid.UUID, location: uuid.UUID, *, vendor="mikrotik", host="10.0.0.1"):
    return Router(
        **_base(
            organization_id=org,
            location_id=location,
            name="Hall Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="hEX",
            vendor=vendor,
            routeros_version="7.23.3",
            management_ip_address=host,
            public_ip_address=None,
            status="online",
            last_seen_at=None,
            last_health_check_at=None,
            health_status=None,
            api_username="admin",
            api_credentials_encrypted="x",
            settings={},
        )
    )


@pytest.fixture
def devices(monkeypatch: pytest.MonkeyPatch):
    """One fake RouterOS per host, so two routers are two devices."""
    import librouteros
    import wyfy_device_gateway.mikrotik_adapter as gateway

    fake = _gateway_fake_api_module()

    class _Api(fake.FakeRouterOSApi):
        _n = 900

        def mint_id(self, row_count: int) -> str:
            type(self)._n += 1
            return f"*N{self._n}"

    apis: dict[str, Any] = {}
    unreachable: set[str] = set()

    def connect(**kwargs: Any):
        host = kwargs["host"]
        if host in unreachable:
            raise librouteros.exceptions.ConnectionClosed("timed out")
        if host not in apis:
            apis[host] = _Api(
                menus={
                    ("ip", "hotspot"): [{".id": "*1", "name": "hs1"}],
                    _BINDING: [
                        {
                            ".id": "*B1",
                            "mac-address": "AA:AA:AA:AA:AA:01",
                            "type": "bypassed",
                            "comment": "venue AP",
                        },
                    ],
                    _ACTIVE: [
                        {".id": "*S1", "mac-address": MAC, "user": "+919999999999"},
                        {".id": "*S2", "mac-address": "AA:BB:CC:DD:EE:02", "user": "x"},
                    ],
                    ("radius", "incoming"): [{"accept": False, "port": "3799"}],
                }
            )
        return apis[host]

    monkeypatch.setattr(gateway.librouteros, "connect", connect)
    return apis, unreachable


@dataclass
class H:
    service: GuestAccessService
    repo: _Repo
    routers: _Routers
    org: uuid.UUID
    location: uuid.UUID


def _harness() -> H:
    org, location = uuid.uuid4(), uuid.uuid4()
    repo, routers = _Repo(), _Routers()
    lookup = FakeLocationLookup()
    lookup.add(location, org)
    service = GuestAccessService(
        repo,
        block_enforcer=None,
        location_lookup=lookup,
        audit_writer=FakeAuditLogWriter(),
        device_blocker=RouterDeviceBlocker(router_lookup=routers),
    )
    return H(service, repo, routers, org, location)


async def _block(h: H, *, location=..., rule_type=AccessRuleType.BLOCKLIST):
    return await h.service.create_device_rule(
        organization_id=h.org,
        requesting_organization_id=h.org,
        location_id=h.location if location is ... else location,
        mac_address="02-00-00-00-00-99",
        rule_type=rule_type,
        reason="stolen laptop",
        expires_at=None,
        actor_user_id=uuid.uuid4(),
    )


def _bindings_for(api: Any, rule_id: uuid.UUID) -> list[dict[str, Any]]:
    return [
        r
        for r in api.path(*_BINDING)
        if r.get("comment") == f"cloudguest-devblock:{rule_id}"
    ]


class TestBlock:
    async def test_the_router_drops_the_device_now_and_on_reconnect(
        self, devices
    ) -> None:
        apis, _ = devices
        h = _harness()
        h.routers.add(_router(h.org, h.location))

        rule = await _block(h)

        api = apis["10.0.0.1"]
        binding = _bindings_for(api, rule.id)
        assert len(binding) == 1
        assert binding[0]["type"] == "blocked"
        assert binding[0]["mac-address"] == MAC
        assert [r[".id"] for r in api.path(*_ACTIVE)] == ["*S2"]
        assert [b.status for b in rule.router_blocks] == ["enforced"]
        assert rule.router_blocks[0].sessions_ended == 1
        assert rule.router_blocks[0].blocked_at is not None
        # Committed before the router was touched, and after it answered.
        assert h.repo.commits == 2
        response = DeviceAccessRuleResponse.model_validate(rule)
        assert response.router_blocks[0].status == "enforced"

    async def test_every_mikrotik_in_scope_and_never_an_omada_row(
        self, devices
    ) -> None:
        apis, _ = devices
        h = _harness()
        h.routers.add(_router(h.org, h.location, host="10.0.0.1"))
        h.routers.add(_router(h.org, h.location, host="10.0.0.2"))
        h.routers.add(
            _router(h.org, h.location, vendor="tplink_omada", host="10.0.0.3")
        )
        h.routers.add(_router(h.org, uuid.uuid4(), host="10.0.0.4"))  # another venue

        rule = await _block(h)

        assert set(apis) == {"10.0.0.1", "10.0.0.2"}
        assert len(rule.router_blocks) == 2

    async def test_an_organization_wide_rule_reaches_every_venue(self, devices) -> None:
        apis, _ = devices
        h = _harness()
        h.routers.add(_router(h.org, h.location, host="10.0.0.1"))
        h.routers.add(_router(h.org, uuid.uuid4(), host="10.0.0.4"))
        await _block(h, location=None)
        assert set(apis) == {"10.0.0.1", "10.0.0.4"}

    async def test_an_unreachable_router_is_recorded_not_raised(self, devices) -> None:
        apis, unreachable = devices
        unreachable.add("10.0.0.2")
        h = _harness()
        h.routers.add(_router(h.org, h.location, host="10.0.0.1"))
        h.routers.add(_router(h.org, h.location, host="10.0.0.2"))

        rule = await _block(h)

        statuses = sorted(b.status for b in rule.router_blocks)
        assert statuses == ["enforced", "failed"]
        failed = next(b for b in rule.router_blocks if b.status == "failed")
        assert failed.error_message
        assert rule.is_active

    async def test_no_credentials_is_failed_with_a_reason(self, devices) -> None:
        apis, _ = devices
        h = _harness()
        h.routers.secret = None
        h.routers.add(_router(h.org, h.location))
        rule = await _block(h)
        assert apis == {}
        assert rule.router_blocks[0].status == "failed"
        assert "credentials" in rule.router_blocks[0].error_message

    async def test_an_allow_rule_touches_no_router(self, devices) -> None:
        apis, _ = devices
        h = _harness()
        h.routers.add(_router(h.org, h.location))
        rule = await _block(h, rule_type=AccessRuleType.WHITELIST)
        assert apis == {} and rule.router_blocks == []

    async def test_retry_is_idempotent_on_the_router(self, devices) -> None:
        apis, _ = devices
        h = _harness()
        h.routers.add(_router(h.org, h.location))
        rule = await _block(h)
        api = apis["10.0.0.1"]
        writes = [op for op in api.ops if op[0] in ("add", "remove")]

        await h.service.enforce_device_rule(
            rule_id=rule.id, requesting_organization_id=h.org, actor_user_id=None
        )

        assert [op for op in api.ops if op[0] in ("add", "remove")] == writes
        assert len(_bindings_for(api, rule.id)) == 1
        assert len(rule.router_blocks) == 1


class TestUnblock:
    @pytest.mark.parametrize("how", ["deactivate", "delete"])
    async def test_unblock_removes_exactly_our_binding(self, devices, how) -> None:
        apis, _ = devices
        h = _harness()
        h.routers.add(_router(h.org, h.location))
        rule = await _block(h)
        api = apis["10.0.0.1"]

        method = getattr(h.service, f"{how}_device_rule")
        await method(
            rule_id=rule.id, requesting_organization_id=h.org, actor_user_id=None
        )

        assert _bindings_for(api, rule.id) == []
        assert [r[".id"] for r in api.path(*_BINDING)] == ["*B1"]
        assert rule.router_blocks[0].cleared_at is not None
        assert rule.router_blocks[0].release_error is None

    async def test_a_release_that_cannot_reach_the_router_stays_open(
        self, devices
    ) -> None:
        apis, unreachable = devices
        h = _harness()
        h.routers.add(_router(h.org, h.location))
        rule = await _block(h)
        unreachable.add("10.0.0.1")

        await h.service.deactivate_device_rule(
            rule_id=rule.id, requesting_organization_id=h.org, actor_user_id=None
        )

        block = rule.router_blocks[0]
        assert block.cleared_at is None and block.release_error
        assert not rule.is_active  # the unblock itself still happened
        assert await h.repo.list_open_router_blocks(rule_id=rule.id) == [block]


class TestWiring:
    def test_the_api_service_is_built_with_a_device_blocker(self) -> None:
        source = inspect.getsource(guest_access_dependencies.get_guest_access_service)
        assert "device_blocker=device_blocker" in source
        assert isinstance(
            guest_access_dependencies.get_device_blocker(router_service=_Routers()),
            RouterDeviceBlocker,
        )

    def test_the_retry_route_exists(self) -> None:
        paths = {(r.path, m) for r in guest_access_router.routes for m in r.methods}
        assert ("/guest-access/device-rules/{rule_id}/enforce", "POST") in paths
