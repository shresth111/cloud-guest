"""Unit tests for the QoS & VOIP Priority domain: rule CRUD (tenant
isolation), traffic-match validation (exactly one of port-range/DSCP
required, port-range ordering/bounds, DSCP 0-63 bounds), priority bounds
(reusing ``app.domains.queue_management``'s own 1-8 range), the
unpaginated ``list_rules_for_router`` read path Network Configuration
Management composes, the real device-push path
(``push_rule_to_device``/``delete_rule``'s own device cleanup), and a
structural RBAC check that every route carries a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_hotspot.py``); ``asyncio_mode = "auto"`` runs async
tests directly. ``QosService`` is exercised against small, hand-rolled
in-memory fakes for its own repository, the composed
``RouterLookupProtocol``, and (new) the composed device-adapter boundary
(``FakeQosDeviceAdapter``) -- mirrors ``test_hotspot.py``'s own identical
"fake the narrow Protocol boundary" precedent, and, for the device-push
tests specifically, the exact same "mock at the gateway boundary" shape
``tests/unit/test_queue_management_adapters.py``/
``tests/unit/test_qos_device_adapters.py`` use for the real RouterOS
command layer one level below this one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.qos.constants import MAX_PRIORITY, MIN_PRIORITY, QosDevicePushStatus
from app.domains.qos.device_adapters import QosCredentials
from app.domains.qos.exceptions import (
    AmbiguousTrafficMatchError,
    CrossOrganizationQosTrafficRuleAccessError,
    InvalidDscpValueError,
    InvalidPortRangeError,
    InvalidPriorityError,
    NoTrafficMatchError,
    QosDeviceConnectionError,
    QosMissingCredentialsError,
    QosTrafficRuleNotEnabledError,
    QosTrafficRuleNotFoundError,
)
from app.domains.qos.identifiers import qos_packet_mark_identifier
from app.domains.qos.models import QosTrafficRule
from app.domains.qos.router import router as qos_router
from app.domains.qos.service import QosService
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
class FakeQosRepository:
    rules: dict[uuid.UUID, QosTrafficRule] = field(default_factory=dict)

    async def create_rule(self, **fields: object) -> QosTrafficRule:
        # Mirrors the real column defaults a live DB flush would apply
        # (mapped_column(default=...) is only realized at flush time by
        # the real ORM, never at plain Python construction) -- see
        # models.py's own new "Real device push state" columns.
        device_push_defaults: dict[str, object] = {
            "device_queue_id": None,
            "device_packet_mark": None,
            "device_push_status": QosDevicePushStatus.PENDING.value,
            "device_push_error": None,
            "device_pushed_at": None,
        }
        rule = QosTrafficRule(**_base_fields(**{**device_push_defaults, **fields}))
        self.rules[rule.id] = rule
        return rule

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> QosTrafficRule | None:
        rule = self.rules.get(rule_id)
        if rule is None or (rule.is_deleted and not include_deleted):
            return None
        return rule

    async def update_rule(
        self, rule: QosTrafficRule, data: dict[str, object]
    ) -> QosTrafficRule:
        for key, value in data.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        rule.version += 1
        return rule

    async def soft_delete_rule(self, rule: QosTrafficRule) -> QosTrafficRule:
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
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_rules_for_router(self, router_id: uuid.UUID) -> list[QosTrafficRule]:
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
    # None means "no decrypted secret available" (mirrors a router with
    # incomplete/never-configured device credentials) -- the real
    # RouterService.get_decrypted_api_secret's own "returns None, doesn't
    # raise" contract for that case.
    decrypted_secret: str | None = "secret"

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

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return self.decrypted_secret


@dataclass
class FakeQosDeviceAdapter:
    """Fakes ``app.domains.qos.device_adapters.BaseQosPriorityQueueAdapter``
    -- mocks at the gateway boundary this domain's real
    ``MikroTikQosQueueAdapter`` sits behind, the same "fake the adapter
    Protocol, not the RouterOS wire format" boundary
    ``tests/unit/test_qos_device_adapters.py`` exists to separately, more
    thoroughly cover for the real command shapes."""

    vendor: str = "mikrotik"
    created: list[dict[str, object]] = field(default_factory=list)
    priority_updates: list[dict[str, object]] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    fail_create: Exception | None = None
    fail_set_priority: Exception | None = None
    _id_counter: int = 0

    async def create_priority_queue(
        self, credentials: QosCredentials, *, name: str, packet_mark: str, priority: int
    ) -> str:
        if self.fail_create is not None:
            raise self.fail_create
        self._id_counter += 1
        device_id = f"*{self._id_counter}"
        self.created.append(
            {"device_queue_id": device_id, "name": name, "packet_mark": packet_mark,
             "priority": priority}
        )
        return device_id

    async def set_priority(
        self, credentials: QosCredentials, *, device_queue_id: str, priority: int
    ) -> None:
        if self.fail_set_priority is not None:
            raise self.fail_set_priority
        self.priority_updates.append(
            {"device_queue_id": device_queue_id, "priority": priority}
        )

    async def remove_priority_queue(
        self, credentials: QosCredentials, *, device_queue_id: str
    ) -> None:
        self.removed.append(device_queue_id)


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: QosService
    repository: FakeQosRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter
    device_adapter: FakeQosDeviceAdapter


def make_harness(*, decrypted_secret: str | None = "secret") -> Harness:
    repository = FakeQosRepository()
    router_lookup = FakeRouterLookup(decrypted_secret=decrypted_secret)
    audit_writer = FakeAuditLogWriter()
    device_adapter = FakeQosDeviceAdapter()
    service = QosService(
        repository,
        router_lookup,
        audit_writer=audit_writer,
        device_adapter_resolver=lambda vendor: device_adapter,
    )
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        audit_writer=audit_writer,
        device_adapter=device_adapter,
    )


async def _create_rule(
    h: Harness,
    router: Router,
    *,
    name: str = "SIP Signaling",
    protocol: str | None = "udp",
    port_range_start: int | None = 5060,
    port_range_end: int | None = 5061,
    dscp_value: int | None = None,
    priority: int = 1,
) -> QosTrafficRule:
    return await h.service.create_rule(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        name=name,
        protocol=protocol,
        port_range_start=port_range_start,
        port_range_end=port_range_end,
        dscp_value=dscp_value,
        priority=priority,
    )


# ============================================================================
# Rule CRUD
# ============================================================================


class TestQosTrafficRuleCrud:
    async def test_create_rule_succeeds(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)

        rule = await _create_rule(h, router)

        assert rule.router_id == router.id
        assert rule.organization_id == router.organization_id
        assert rule.location_id == router.location_id
        assert rule.name == "SIP Signaling"
        assert rule.protocol == "udp"
        assert rule.port_range_start == 5060
        assert rule.port_range_end == 5061
        assert rule.dscp_value is None
        assert rule.priority == 1
        assert rule.is_enabled is True
        assert len(h.audit_writer.entries) == 1

    async def test_create_rule_for_unknown_router_raises(self) -> None:
        h = make_harness()
        with pytest.raises(RouterNotFoundError):
            await _create_rule(h, _make_router())

    async def test_get_rule_returns_created_rule(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        fetched = await h.service.get_rule(
            rule.id, requesting_organization_id=router.organization_id
        )
        assert fetched.id == rule.id

    async def test_get_rule_not_found_raises(self) -> None:
        h = make_harness()
        with pytest.raises(QosTrafficRuleNotFoundError):
            await h.service.get_rule(uuid.uuid4())

    async def test_get_rule_cross_organization_raises(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        with pytest.raises(CrossOrganizationQosTrafficRuleAccessError):
            await h.service.get_rule(rule.id, requesting_organization_id=uuid.uuid4())

    async def test_list_rules_filters_by_router(self) -> None:
        h = make_harness()
        router_a = _make_router()
        router_b = _make_router()
        h.router_lookup.add(router_a)
        h.router_lookup.add(router_b)
        rule_a = await _create_rule(h, router_a)
        await _create_rule(h, router_b)

        rules, meta = await h.service.list_rules(
            requesting_organization_id=None, router_id=router_a.id
        )
        assert meta.total_items == 1
        assert rules[0].id == rule_a.id

    async def test_update_rule_changes_fields(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        updated = await h.service.update_rule(
            rule.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            priority=3,
            is_enabled=False,
        )
        assert updated.priority == 3
        assert updated.is_enabled is False
        assert len(h.audit_writer.entries) == 2

    async def test_delete_rule_soft_deletes(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        deleted = await h.service.delete_rule(
            rule.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True
        with pytest.raises(QosTrafficRuleNotFoundError):
            await h.service.get_rule(rule.id)


# ============================================================================
# Traffic-match validation
# ============================================================================


class TestTrafficMatchValidation:
    async def test_accepts_a_port_range_match(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(
            h, router, port_range_start=10000, port_range_end=20000, dscp_value=None
        )
        assert rule.port_range_start == 10000
        assert rule.dscp_value is None

    async def test_accepts_a_dscp_match(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(
            h,
            router,
            protocol=None,
            port_range_start=None,
            port_range_end=None,
            dscp_value=46,
        )
        assert rule.dscp_value == 46
        assert rule.port_range_start is None

    async def test_rejects_both_port_range_and_dscp(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(AmbiguousTrafficMatchError):
            await _create_rule(h, router, dscp_value=46)

    async def test_rejects_neither_port_range_nor_dscp(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(NoTrafficMatchError):
            await _create_rule(
                h,
                router,
                protocol=None,
                port_range_start=None,
                port_range_end=None,
                dscp_value=None,
            )

    async def test_rejects_a_reversed_port_range(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(InvalidPortRangeError):
            await _create_rule(h, router, port_range_start=20000, port_range_end=10000)

    async def test_rejects_dscp_out_of_range(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(InvalidDscpValueError):
            await _create_rule(
                h,
                router,
                protocol=None,
                port_range_start=None,
                port_range_end=None,
                dscp_value=64,
            )

    async def test_update_revalidates_traffic_match(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        with pytest.raises(AmbiguousTrafficMatchError):
            await h.service.update_rule(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                dscp_value=10,
            )


# ============================================================================
# Priority validation
# ============================================================================


class TestPriorityValidation:
    async def test_accepts_priority_within_bounds(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router, priority=MIN_PRIORITY)
        assert rule.priority == MIN_PRIORITY

    async def test_rejects_priority_below_minimum(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(InvalidPriorityError):
            await _create_rule(h, router, priority=MIN_PRIORITY - 1)

    async def test_rejects_priority_above_maximum(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(InvalidPriorityError):
            await _create_rule(h, router, priority=MAX_PRIORITY + 1)

    async def test_update_revalidates_priority(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        with pytest.raises(InvalidPriorityError):
            await h.service.update_rule(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                priority=MAX_PRIORITY + 1,
            )


# ============================================================================
# list_rules_for_router -- the real read source Network Configuration
# Management composes to render a router's full QoS mangle config
# ============================================================================


class TestListRulesForRouter:
    async def test_returns_every_non_deleted_rule_for_the_router(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule_a = await _create_rule(h, router, name="Rule A")
        rule_b = await _create_rule(
            h, router, name="Rule B", port_range_start=6000, port_range_end=6001
        )
        await h.service.delete_rule(
            rule_b.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        rules = await h.service.list_rules_for_router(
            router.id, requesting_organization_id=router.organization_id
        )

        assert [r.id for r in rules] == [rule_a.id]

    async def test_raises_for_a_router_outside_the_requesting_organization(
        self,
    ) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)

        with pytest.raises(RouterNotFoundError):
            await h.service.list_rules_for_router(
                router.id, requesting_organization_id=uuid.uuid4()
            )


# ============================================================================
# Real device push -- push_rule_to_device (the fix this task exists for)
# ============================================================================


class TestPushRuleToDevice:
    async def test_first_push_creates_a_priority_queue(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router, priority=2)

        pushed = await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )

        assert len(h.device_adapter.created) == 1
        call = h.device_adapter.created[0]
        assert call["priority"] == 2
        assert call["packet_mark"] == qos_packet_mark_identifier(rule)
        assert pushed.device_queue_id == call["device_queue_id"]
        assert pushed.device_packet_mark == qos_packet_mark_identifier(rule)
        assert pushed.device_push_status == QosDevicePushStatus.ACTIVE.value
        assert pushed.device_push_error is None
        assert pushed.device_pushed_at is not None
        assert len(h.audit_writer.entries) == 2  # create + push

    async def test_repush_with_unchanged_identifier_uses_set_priority(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router, priority=5)
        first = await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        updated = await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            priority=1,
        )
        repushed = await h.service.push_rule_to_device(
            updated.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        # Same device_queue_id, no second create_priority_queue call --
        # only the cheap set_priority path, per this method's own
        # docstring.
        assert len(h.device_adapter.created) == 1
        assert h.device_adapter.priority_updates == [
            {"device_queue_id": first.device_queue_id, "priority": 1}
        ]
        assert repushed.device_queue_id == first.device_queue_id

    async def test_rename_changes_the_identifier_and_recreates_the_queue(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router, name="SIP Signaling")
        first = await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        # Snapshot the id now -- the fake repository mutates rows in
        # place, so `first` and every later fetch of the same row id are
        # literally the same Python object; reading first.device_queue_id
        # *after* the re-push below would see the new value, not the one
        # that was actually live at push time.
        first_device_queue_id = first.device_queue_id

        renamed = await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="SIP Signaling Renamed",
        )
        repushed = await h.service.push_rule_to_device(
            renamed.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        # The old device queue is removed and a new one created against
        # the rule's new packet-mark identifier -- set_priority alone
        # cannot change packet-mark, see this method's own docstring.
        assert h.device_adapter.removed == [first_device_queue_id]
        assert len(h.device_adapter.created) == 2
        assert repushed.device_queue_id != first_device_queue_id
        assert repushed.device_packet_mark == qos_packet_mark_identifier(renamed)

    async def test_pushing_a_disabled_rule_raises(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)
        await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            is_enabled=False,
        )

        with pytest.raises(QosTrafficRuleNotEnabledError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert h.device_adapter.created == []

    async def test_missing_credentials_raises_and_never_touches_the_device(
        self,
    ) -> None:
        h = make_harness(decrypted_secret=None)
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        with pytest.raises(QosMissingCredentialsError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert h.device_adapter.created == []

    async def test_device_connection_failure_is_recorded_then_reraised(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)
        h.device_adapter.fail_create = QosDeviceConnectionError(
            "10.0.0.1", "connection refused"
        )

        with pytest.raises(QosDeviceConnectionError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        failed = await h.service.get_rule(rule.id)
        assert failed.device_push_status == QosDevicePushStatus.FAILED.value
        assert failed.device_push_error is not None
        assert failed.device_queue_id is None


# ============================================================================
# delete_rule -- real device cleanup for an already-pushed rule
# ============================================================================


class TestDeleteRuleDeviceCleanup:
    async def test_delete_removes_a_never_pushed_rule_with_no_device_call(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)

        await h.service.delete_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert h.device_adapter.removed == []

    async def test_delete_removes_the_live_device_queue_when_pushed(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)
        pushed = await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        # Snapshot now -- delete_rule below clears device_queue_id on this
        # same (in-place-mutated) row object once removal succeeds. See
        # the identical note in TestPushRuleToDevice
        # .test_rename_changes_the_identifier_and_recreates_the_queue.
        pushed_device_queue_id = pushed.device_queue_id

        deleted = await h.service.delete_rule(
            pushed.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert h.device_adapter.removed == [pushed_device_queue_id]
        assert deleted.is_deleted is True
        assert deleted.device_queue_id is None

    async def test_delete_device_failure_is_never_swallowed_and_row_stays(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule = await _create_rule(h, router)
        pushed = await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        class ExplodingRemove(FakeQosDeviceAdapter):
            async def remove_priority_queue(
                self, credentials: QosCredentials, *, device_queue_id: str
            ) -> None:
                raise QosDeviceConnectionError("10.0.0.1", "unreachable")

        h.service._get_device_adapter = lambda vendor: ExplodingRemove()

        with pytest.raises(QosDeviceConnectionError):
            await h.service.delete_rule(
                pushed.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        still_there = await h.service.get_rule(pushed.id)
        assert still_there.is_deleted is False


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_qos_route_has_a_permission_dependency(self) -> None:
        # CRUD (create/list/get/update/delete) + the new POST .../push
        # device-action route -- see router.py's own module docstring.
        assert len(qos_router.routes) == 6
        for route in qos_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
