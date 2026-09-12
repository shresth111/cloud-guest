"""Unit tests for the Port Forwarding Management domain: rule CRUD
(tenant isolation), port-range validation, address validation
(source/destination CIDR-or-IP, internal single-host-only), conflict
detection (overlap rejected when protocol+destination_address+
destination_port overlap on the same router, allowed across different
ports/protocols/addresses or different routers, re-checked on update
excluding the rule itself), the live device push and its preconditions,
and a structural RBAC check that every route carries a permission
dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_dhcp.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``PortForwardingService`` is exercised against small,
hand-rolled in-memory fakes for its own repository and the composed
``RouterLookupProtocol`` -- mirrors ``test_dhcp.py``'s own identical "fake
the narrow Protocol boundary" precedent. The device-push tests fake the
adapter at the same boundary: what is under test here is what the service
asks a device to do and what it records afterwards, not the RouterOS
command shapes (those are covered against a fake transport in
``vendor/wyfy-device-gateway/tests/test_mikrotik_write_ops.py``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.port_forwarding.constants import (
    PortForwardingDevicePushStatus,
    PortForwardingProtocol,
)
from app.domains.port_forwarding.exceptions import (
    CrossOrganizationPortForwardingRuleAccessError,
    InvalidAddressError,
    InvalidPortError,
    PortForwardingConflictError,
    PortForwardingDeviceConnectionError,
    PortForwardingDeviceOperationError,
    PortForwardingMissingCredentialsError,
    PortForwardingRuleNotEnabledError,
    PortForwardingRuleNotFoundError,
    UnsupportedPortForwardingVendorError,
)
from app.domains.port_forwarding.models import PortForwardingRule
from app.domains.port_forwarding.router import router as port_forwarding_router
from app.domains.port_forwarding.service import PortForwardingService
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
class FakePortForwardingRepository:
    rules: dict[uuid.UUID, PortForwardingRule] = field(default_factory=dict)

    async def create_rule(self, **fields: object) -> PortForwardingRule:
        rule = PortForwardingRule(**_base_fields(**fields))
        self.rules[rule.id] = rule
        return rule

    async def get_rule_by_id(
        self, rule_id: uuid.UUID, *, include_deleted: bool = False
    ) -> PortForwardingRule | None:
        rule = self.rules.get(rule_id)
        if rule is None or (rule.is_deleted and not include_deleted):
            return None
        return rule

    async def update_rule(
        self, rule: PortForwardingRule, data: dict[str, object]
    ) -> PortForwardingRule:
        for key, value in data.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        rule.version += 1
        return rule

    async def soft_delete_rule(self, rule: PortForwardingRule) -> PortForwardingRule:
        rule.is_deleted = True
        rule.deleted_at = _now()
        return rule

    #: Counts the explicit commit ``push_rule_to_device`` issues before
    #: re-raising a device failure. Without it the failure record is
    #: discarded by the session rollback and the row still reads "pending".
    commits: int = 0

    async def commit(self) -> None:
        self.commits += 1

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

    async def list_rules_for_router(
        self, router_id: uuid.UUID
    ) -> list[PortForwardingRule]:
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
    service: PortForwardingService
    repository: FakePortForwardingRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakePortForwardingRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    service = PortForwardingService(
        repository, router_lookup, audit_writer=audit_writer
    )
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
    destination_port: int = 8080,
    protocol: PortForwardingProtocol = PortForwardingProtocol.TCP,
    destination_address: str | None = None,
) -> PortForwardingRule:
    return await h.service.create_rule(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        name="Web Server",
        protocol=protocol,
        destination_address=destination_address,
        destination_port=destination_port,
        internal_address="192.168.1.10",
        internal_port=80,
    )


# ============================================================================
# Rule CRUD
# ============================================================================


class TestPortForwardingRuleCrud:
    async def test_create_rule(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        assert rule.destination_port == 8080
        assert rule.internal_address == "192.168.1.10"
        assert rule.organization_id == router.organization_id
        assert rule.location_id == router.location_id
        assert len(h.audit_writer.entries) == 1

    async def test_create_with_invalid_destination_port_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidPortError):
            await h.service.create_rule(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                name="Bad Rule",
                destination_port=70000,
                internal_address="192.168.1.10",
                internal_port=80,
            )

    async def test_create_with_invalid_internal_address_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidAddressError):
            await h.service.create_rule(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                name="Bad Rule",
                destination_port=8080,
                internal_address="bogus",
                internal_port=80,
            )

    async def test_create_with_cidr_internal_address_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        with pytest.raises(InvalidAddressError):
            await h.service.create_rule(
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                router_id=router.id,
                name="Bad Rule",
                destination_port=8080,
                internal_address="192.168.1.0/24",
                internal_port=80,
            )

    async def test_cross_organization_read_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        with pytest.raises(CrossOrganizationPortForwardingRuleAccessError):
            await h.service.get_rule(rule.id, requesting_organization_id=uuid.uuid4())

    async def test_get_missing_rule_raises(self) -> None:
        h = make_harness()
        with pytest.raises(PortForwardingRuleNotFoundError):
            await h.service.get_rule(uuid.uuid4())

    async def test_list_rules_scoped_to_router(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_rule(h, router_a, destination_port=8080)
        await _create_rule(h, router_b, destination_port=8081)
        rules, meta = await h.service.list_rules(
            requesting_organization_id=router_a.organization_id, router_id=router_a.id
        )
        assert meta.total_items == 1
        assert rules[0].router_id == router_a.id

    async def test_delete_soft_deletes(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        deleted = await h.service.delete_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True


# ============================================================================
# Conflict detection
# ============================================================================


class TestPortForwardingConflict:
    async def test_same_port_and_protocol_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(
            h, router, destination_port=8080, protocol=PortForwardingProtocol.TCP
        )
        with pytest.raises(PortForwardingConflictError):
            await _create_rule(
                h, router, destination_port=8080, protocol=PortForwardingProtocol.TCP
            )

    async def test_different_port_is_allowed(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, destination_port=8080)
        second = await _create_rule(h, router, destination_port=8081)
        assert second.destination_port == 8081

    async def test_different_protocol_is_allowed(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(
            h, router, destination_port=8080, protocol=PortForwardingProtocol.TCP
        )
        second = await _create_rule(
            h, router, destination_port=8080, protocol=PortForwardingProtocol.UDP
        )
        assert second.protocol == PortForwardingProtocol.UDP.value

    async def test_both_protocol_conflicts_with_tcp(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(
            h, router, destination_port=8080, protocol=PortForwardingProtocol.TCP
        )
        with pytest.raises(PortForwardingConflictError):
            await _create_rule(
                h, router, destination_port=8080, protocol=PortForwardingProtocol.BOTH
            )

    async def test_different_destination_address_is_allowed(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(
            h, router, destination_port=8080, destination_address="203.0.113.10"
        )
        second = await _create_rule(
            h, router, destination_port=8080, destination_address="203.0.113.20"
        )
        assert second.destination_address == "203.0.113.20"

    async def test_none_destination_address_conflicts_with_specific_address(
        self,
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, destination_port=8080, destination_address=None)
        with pytest.raises(PortForwardingConflictError):
            await _create_rule(
                h, router, destination_port=8080, destination_address="203.0.113.10"
            )

    async def test_different_router_is_allowed(self) -> None:
        h = make_harness()
        router_a = h.router_lookup.add(_make_router())
        router_b = h.router_lookup.add(_make_router())
        await _create_rule(h, router_a, destination_port=8080)
        second = await _create_rule(h, router_b, destination_port=8080)
        assert second.router_id == router_b.id

    async def test_update_port_rechecks_conflict_excluding_self(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router, destination_port=8080)
        updated = await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            destination_port=8080,
        )
        assert updated.destination_port == 8080

    async def test_update_port_to_conflict_with_another_rule_raises(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        await _create_rule(h, router, destination_port=8080)
        second = await _create_rule(h, router, destination_port=9090)
        with pytest.raises(PortForwardingConflictError):
            await h.service.update_rule(
                second.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                destination_port=8080,
            )


# ============================================================================
# list_rules_for_router -- the real read source Network Configuration
# Management composes to render a router's full port-forwarding config
# ============================================================================


class TestListRulesForRouter:
    async def test_returns_every_non_deleted_rule_for_the_router(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        rule_a = await _create_rule(h, router, destination_port=8080)
        rule_b = await _create_rule(h, router, destination_port=9090)
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
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_port_forwarding_route_has_a_permission_dependency(self) -> None:
        assert len(port_forwarding_router.routes) == 6
        for route in port_forwarding_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"


# ============================================================================
# Device push -- the piece this domain never had. Creating a rule wrote a
# row and contacted nothing, so a service the dashboard listed as published
# on a port answered nothing from outside.
# ============================================================================


@dataclass
class FakePortForwardingAdapter:
    """Records what the service actually asked the device to do."""

    vendor: str = "mikrotik"
    calls: list[dict[str, object]] = field(default_factory=list)
    raises: Exception | None = None
    deletes: list[dict[str, object]] = field(default_factory=list)
    delete_raises: Exception | None = None

    async def configure_port_forward(
        self,
        credentials,
        *,
        rule_id: str,
        protocol: str,
        external_port: int,
        internal_ip: str,
        internal_port: int,
        destination_address: str | None,
        source_address: str | None,
    ) -> None:
        self.calls.append(
            {
                "host": credentials.host,
                "username": credentials.username,
                "password": credentials.password,
                "rule_id": rule_id,
                "protocol": protocol,
                "external_port": external_port,
                "internal_ip": internal_ip,
                "internal_port": internal_port,
                "destination_address": destination_address,
                "source_address": source_address,
            }
        )
        if self.raises is not None:
            raise self.raises

    async def delete_port_forward(self, credentials, *, rule_id: str) -> None:
        self.deletes.append({"host": credentials.host, "rule_id": rule_id})
        if self.delete_raises is not None:
            raise self.delete_raises


@pytest.fixture
def adapter(monkeypatch: pytest.MonkeyPatch) -> FakePortForwardingAdapter:
    """Replaces the registry lookup the service performs.

    Patched on ``service``'s own reference, not on ``device_adapters`` --
    the service imported the name at module load, so patching the source
    module would leave the bound name untouched and the test would silently
    exercise the real adapter.
    """
    fake = FakePortForwardingAdapter()
    monkeypatch.setattr(
        "app.domains.port_forwarding.service.get_port_forwarding_adapter",
        lambda vendor: fake,
    )
    return fake


class TestPortForwardingRuleDevicePush:
    async def test_push_reaches_the_device_with_the_customers_values(
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        assert rule.device_push_status == PortForwardingDevicePushStatus.PENDING.value

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
        assert call["protocol"] == "tcp"
        assert call["external_port"] == 8080
        assert call["internal_ip"] == "192.168.1.10"
        assert call["internal_port"] == 80

        assert pushed.device_push_status == PortForwardingDevicePushStatus.ACTIVE.value
        assert pushed.device_push_error is None
        assert pushed.device_pushed_at is not None

    async def test_the_adapter_is_handed_the_rows_own_id_as_the_identity(
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        """The row id is the only field a customer cannot edit, which is why
        it and not the port or the target is what the device rule is keyed
        on."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)

        await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.calls[0]["rule_id"] == str(rule.id)

    async def test_the_source_restriction_reaches_the_device(
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        """Dropping it on the way would publish a port the operator meant to
        expose to one network to the whole internet."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await h.service.create_rule(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            router_id=router.id,
            name="Restricted",
            protocol=PortForwardingProtocol.TCP,
            source_address="198.51.100.0/24",
            destination_address="203.0.113.9",
            destination_port=8443,
            internal_address="192.168.1.11",
            internal_port=443,
        )

        await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.calls[0]["source_address"] == "198.51.100.0/24"
        assert adapter.calls[0]["destination_address"] == "203.0.113.9"

    async def test_a_both_protocol_rule_is_passed_through_not_rewritten(
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        """Expanding "both" into real transports is a RouterOS fact and
        belongs to the vendor adapter -- this layer must not invent one."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router, protocol=PortForwardingProtocol.BOTH)

        await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.calls[0]["protocol"] == "both"

    async def test_push_writes_a_real_audit_entry(
        self, adapter: FakePortForwardingAdapter
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
            == AuditAction.PORT_FORWARDING_RULE_PUSHED.value
        )

    async def test_a_device_failure_is_recorded_committed_and_re_raised(
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        """The commit is the point. ``GenericRepository.update`` only
        flushes and ``get_db_session`` rolls back on any exception, so
        without an explicit commit the failure record is discarded and the
        row still reads "pending" with a NULL error after a real failure."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        adapter.raises = PortForwardingDeviceOperationError(
            "configure_port_forward", "already have such item"
        )

        with pytest.raises(PortForwardingDeviceOperationError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert rule.device_push_status == PortForwardingDevicePushStatus.FAILED.value
        assert "already have such item" in (rule.device_push_error or "")
        assert h.repository.commits == 1

    async def test_a_connection_failure_is_recorded_the_same_way(
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        adapter.raises = PortForwardingDeviceConnectionError("10.0.0.1", "timed out")

        with pytest.raises(PortForwardingDeviceConnectionError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert rule.device_push_status == PortForwardingDevicePushStatus.FAILED.value
        assert "timed out" in (rule.device_push_error or "")
        assert h.repository.commits == 1

    async def test_a_disabled_rule_is_refused_before_any_connection(
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        """Pushing a disabled rule would open a live inbound path through
        the WAN for a row the operator switched off."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        await h.service.update_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            is_enabled=False,
        )

        with pytest.raises(PortForwardingRuleNotEnabledError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []

    async def test_a_router_with_no_usable_credentials_is_refused(
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        h.router_lookup.secret = None

        with pytest.raises(PortForwardingMissingCredentialsError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        assert adapter.calls == []

    async def test_another_organizations_rule_cannot_be_pushed(
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)

        with pytest.raises(CrossOrganizationPortForwardingRuleAccessError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=uuid.uuid4(),
            )
        assert adapter.calls == []

    async def test_a_missing_rule_is_a_404_not_a_device_call(
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        h = make_harness()

        with pytest.raises(PortForwardingRuleNotFoundError):
            await h.service.push_rule_to_device(
                uuid.uuid4(),
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

        with pytest.raises(UnsupportedPortForwardingVendorError):
            await h.service.push_rule_to_device(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )


class TestPortForwardingDeleteReachesTheDevice:
    """Deleting a rule used to soft-delete the row and nothing else, so a
    DSTNAT rule this platform created went on forwarding a public port into
    the customer's LAN after the operator deleted it -- and with the row
    gone, nothing in the dashboard could ever show it."""

    async def _pushed_rule(
        self, h: Harness, router: Router, adapter: FakePortForwardingAdapter
    ) -> PortForwardingRule:
        rule = await _create_rule(h, router)
        await h.service.push_rule_to_device(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )
        adapter.calls.clear()
        return rule

    async def test_deleting_a_pushed_rule_removes_it_from_the_router(
        self, adapter: FakePortForwardingAdapter
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
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        """Opening a connection to delete nothing would make every such
        delete fail whenever a router happened to be unreachable."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        assert rule.device_push_status == PortForwardingDevicePushStatus.PENDING.value

        deleted = await h.service.delete_rule(
            rule.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        assert adapter.deletes == []
        assert deleted.is_deleted is True

    async def test_a_rule_whose_push_failed_skips_the_connection(
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await _create_rule(h, router)
        adapter.raises = PortForwardingDeviceConnectionError("10.0.0.1", "timed out")
        with pytest.raises(PortForwardingDeviceConnectionError):
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
        self, adapter: FakePortForwardingAdapter
    ) -> None:
        """Removing the row while the forward is still live is exactly the
        drift this closes -- the operator would believe the port was closed
        and nothing would ever reconcile it."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        rule = await self._pushed_rule(h, router, adapter)
        adapter.delete_raises = PortForwardingDeviceConnectionError(
            "10.0.0.1", "timed out"
        )

        with pytest.raises(PortForwardingDeviceConnectionError):
            await h.service.delete_rule(
                rule.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )

        assert rule.is_deleted is False
        assert await h.repository.get_rule_by_id(rule.id) is not None
