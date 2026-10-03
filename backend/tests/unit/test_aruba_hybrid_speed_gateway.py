"""Aruba AP + MikroTik gateway hybrid (``queue_management.speed_gateway``).

Built on the REAL ``QueueManagementService`` (the existing queue writer) over
the in-memory fakes ``test_queue_management`` already uses, with a stateful
``/queue simple`` table standing in for the gateway so read-back means
something: a row that was never written, or was removed, reads as absent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.policy.constants import PolicyType  # noqa: F401 -- fakes import
from app.domains.queue_management.constants import QueueStatus, QueueTargetType
from app.domains.queue_management.device_adapters import QueueDeviceStatus
from app.domains.queue_management.exceptions import QueueDeviceConnectionError
from app.domains.queue_management.models import LocationSpeedGateway
from app.domains.queue_management.service import QueueManagementService
from app.domains.queue_management.speed_gateway import (
    SpeedGatewayError,
    SpeedGatewayService,
    gateway_unusable_reason,
    guest_ip_for_queue,
    release_is_due,
)
from app.domains.router.models import Router
from tests.unit.test_queue_management import (
    FakeAuditLogWriter,
    FakePolicyLookup,
    FakeQueueManagementRepository,
    FakeRouterLookup,
    _base_fields,
)

ORG = uuid.uuid4()
LOC = uuid.uuid4()


def _router(
    *,
    vendor: str = "mikrotik",
    organization_id: uuid.UUID = ORG,
    location_id: uuid.UUID = LOC,
    creds: bool = True,
    name: str = "Gateway",
) -> Router:
    return Router(
        **_base_fields(
            organization_id=organization_id,
            location_id=location_id,
            name=name,
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address=f"AA:BB:CC:{uuid.uuid4().hex[:2]}:EE:FF",
            model="hEX" if vendor == "mikrotik" else "AP21",
            vendor=vendor,
            routeros_version=None,
            management_ip_address="10.20.0.40" if creds else None,
            public_ip_address=None,
            status="online",
            last_seen_at=None,
            last_health_check_at=None,
            health_status=None,
            api_username="wyfy" if creds else None,
            api_credentials_encrypted="enc" if creds else None,
            settings={},
        )
    )


@dataclass
class FakeSession:
    router_id: uuid.UUID
    ip_address: str | None = "192.168.88.23"
    status: str = "active"
    session_timeout_minutes: int | None = 240
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    ended_at: datetime | None = None
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    guest_id: uuid.UUID = field(default_factory=uuid.uuid4)
    organization_id: uuid.UUID = ORG
    location_id: uuid.UUID = LOC

    def is_active(self) -> bool:
        return self.status == "active"


@dataclass
class QueueTable:
    """A gateway's ``/queue simple``: what create/remove/read actually see."""

    rows: dict[str, dict[str, object]] = field(default_factory=dict)
    created: list[dict[str, object]] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    reads: int = 0
    unreachable: bool = False
    _n: int = 0
    vendor: str = "mikrotik"

    def _check(self) -> None:
        if self.unreachable:
            raise QueueDeviceConnectionError("10.20.0.40", "timed out")

    async def create_simple_queue(self, credentials, **kw) -> str:
        self._check()
        self._n += 1
        qid = f"*{self._n:X}"
        self.rows[qid] = {"name": kw["name"], "target": f"{kw['target']}/32"}
        self.created.append(dict(kw))
        return qid

    async def update_simple_queue(self, credentials, *, device_queue_id, **kw) -> None:
        self._check()

    async def remove_queue(self, credentials, *, device_queue_id, **kw) -> None:
        self._check()
        self.rows.pop(device_queue_id)
        self.removed.append(device_queue_id)

    async def read_queue_status(self, credentials, *, device_queue_id, **kw):
        self._check()
        self.reads += 1
        row = self.rows.get(device_queue_id, {})
        return QueueDeviceStatus(
            device_queue_id=device_queue_id,
            name=row.get("name"),
            target=row.get("target"),
            disabled=False,
            bytes_uploaded=None,
            bytes_downloaded=None,
            packets_uploaded=None,
            packets_downloaded=None,
            queued_bytes=None,
        )


@dataclass
class FakeSpeedGatewayRepository:
    queue_repository: FakeQueueManagementRepository
    links: dict[uuid.UUID, LocationSpeedGateway] = field(default_factory=dict)
    sessions: dict[uuid.UUID, FakeSession] = field(default_factory=dict)

    async def get_for_nas_router(self, nas_router_id):
        return self.links.get(nas_router_id)

    async def list_for_location(self, *, location_id, organization_id):
        return [
            link
            for link in self.links.values()
            if link.location_id == location_id
            and link.organization_id == organization_id
        ]

    async def list_for_gateway(self, gateway_router_id):
        return [
            link
            for link in self.links.values()
            if link.gateway_router_id == gateway_router_id
        ]

    async def list_all(self):
        return list(self.links.values())

    async def save(self, **fields):
        row = self.links.get(fields["nas_router_id"]) or LocationSpeedGateway(
            id=uuid.uuid4(), is_deleted=False
        )
        for key, value in fields.items():
            setattr(row, key, value)
        self.links[fields["nas_router_id"]] = row
        return row

    async def delete(self, row):
        self.links.pop(row.nas_router_id, None)

    async def get_guest_session(self, session_id):
        return self.sessions.get(session_id)

    async def list_live_session_assignments(self, *, router_id):
        return [
            a
            for a in self.queue_repository.assignments.values()
            if a.router_id == router_id
            and a.target_type == QueueTargetType.SESSION.value
            and a.status != QueueStatus.EXPIRED.value
        ]


@dataclass
class Rig:
    service: SpeedGatewayService
    queue: QueueManagementService
    table: QueueTable
    repo: FakeSpeedGatewayRepository
    routers: FakeRouterLookup
    nas: Router
    gateway: Router
    policy: FakePolicyLookup


class _RouterLookup(FakeRouterLookup):
    async def list_routers_in_scope(self, *, organization_id, location_id):
        return [
            r
            for r in self.routers.values()
            if r.organization_id == organization_id and r.location_id == location_id
        ]


def make_rig(*, enabled: bool = True, link: bool = True) -> Rig:
    table = QueueTable()
    queue_repo = FakeQueueManagementRepository()
    routers = _RouterLookup()
    policy = FakePolicyLookup()
    policy.rules_by_scope[(ORG, LOC)] = {
        "download_rate_kbps": 2048,
        "upload_rate_kbps": 1024,
    }
    queue = QueueManagementService(
        queue_repo,
        routers,
        policy,
        audit_writer=FakeAuditLogWriter(),
        device_adapter_resolver=lambda vendor: table,
    )
    nas = routers.add(_router(vendor="aruba_instant_on", name="AP21", creds=False))
    gateway = routers.add(_router())
    repo = FakeSpeedGatewayRepository(queue_repository=queue_repo)
    service = SpeedGatewayService(
        repo,
        routers,
        queue_service=queue,
        enabled=enabled,
        adapter_factory=lambda vendor: table,
    )
    if link:
        repo.links[nas.id] = LocationSpeedGateway(
            id=uuid.uuid4(),
            organization_id=ORG,
            location_id=LOC,
            nas_router_id=nas.id,
            gateway_router_id=gateway.id,
            is_deleted=False,
        )
    return Rig(service, queue, table, repo, routers, nas, gateway, policy)


def _guest(rig: Rig, **kw) -> FakeSession:
    session = FakeSession(router_id=kw.pop("router_id", rig.nas.id), **kw)
    rig.repo.sessions[session.id] = session
    return session


# ============================================================================
# Pure rules
# ============================================================================


class TestGatewayUsability:
    def test_same_org_same_location_mikrotik_with_credentials_is_usable(self):
        assert (
            gateway_unusable_reason(_router(), organization_id=ORG, location_id=LOC)
            is None
        )

    @pytest.mark.parametrize("vendor", ["tplink_omada", "aruba_instant_on"])
    def test_a_controller_or_nas_only_router_is_never_a_gateway(self, vendor):
        assert (
            gateway_unusable_reason(
                _router(vendor=vendor), organization_id=ORG, location_id=LOC
            )
            == "SPEED_GATEWAY_WRONG_VENDOR"
        )

    def test_another_tenants_router_is_refused(self):
        foreign = _router(organization_id=uuid.uuid4())
        assert (
            gateway_unusable_reason(foreign, organization_id=ORG, location_id=LOC)
            == "SPEED_GATEWAY_LOCATION_MISMATCH"
        )

    def test_another_location_of_the_same_tenant_is_refused(self):
        elsewhere = _router(location_id=uuid.uuid4())
        assert (
            gateway_unusable_reason(elsewhere, organization_id=ORG, location_id=LOC)
            == "SPEED_GATEWAY_LOCATION_MISMATCH"
        )

    def test_no_api_credentials_is_refused(self):
        assert (
            gateway_unusable_reason(
                _router(creds=False), organization_id=ORG, location_id=LOC
            )
            == "SPEED_GATEWAY_NO_CREDENTIALS"
        )


class TestGuestIp:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("192.168.88.23", "192.168.88.23"),
            (" 172.16.0.4 ", "172.16.0.4"),
            ("", None),
            (None, None),
            ("0.0.0.0", None),
            ("127.0.0.1", None),
            ("169.254.1.1", None),
            ("fe80::1", None),
            ("not-an-ip", None),
        ],
    )
    def test_only_a_usable_ipv4_becomes_a_queue_target(self, raw, expected):
        assert guest_ip_for_queue(raw) == expected


class TestReleaseIsDue:
    NOW = datetime(2026, 10, 3, 18, 0, tzinfo=UTC)

    def test_an_active_session_is_never_released(self):
        s = FakeSession(router_id=uuid.uuid4(), started_at=self.NOW - timedelta(days=2))
        assert release_is_due(s, now=self.NOW) is False

    def test_an_ended_session_is_kept_until_the_aps_session_timeout_has_fired(self):
        """A block at an AP-only venue leaves the guest online until the AP's
        own Session-Timeout. Removing the queue earlier would make them
        unlimited."""
        s = FakeSession(
            router_id=uuid.uuid4(),
            status="terminated",
            session_timeout_minutes=60,
            started_at=self.NOW - timedelta(minutes=30),
            ended_at=self.NOW - timedelta(minutes=29),
        )
        assert release_is_due(s, now=self.NOW) is False
        assert release_is_due(s, now=self.NOW + timedelta(minutes=36)) is True

    def test_an_unbounded_session_is_released_a_day_after_it_ended(self):
        s = FakeSession(
            router_id=uuid.uuid4(),
            status="expired",
            session_timeout_minutes=None,
            started_at=self.NOW - timedelta(hours=3),
            ended_at=self.NOW - timedelta(hours=1),
        )
        assert release_is_due(s, now=self.NOW) is False
        assert release_is_due(s, now=self.NOW + timedelta(hours=24)) is True


# ============================================================================
# Apply
# ============================================================================


class TestApply:
    async def test_writes_one_queue_on_the_gateway_keyed_on_the_framed_ip(self):
        rig = make_rig()
        guest = _guest(rig, ip_address="192.168.88.23")

        out = await rig.service.apply_for_session(
            session_id=guest.id,
            nas_router_id=rig.nas.id,
            framed_ip="192.168.88.50",
            verify=True,
        )

        assert out.action == "applied" and out.verified is True
        assert len(rig.table.created) == 1
        call = rig.table.created[0]
        assert call["target"] == "192.168.88.50"
        assert call["download_rate_kbps"] == 2048
        assert call["upload_rate_kbps"] == 1024
        assignment = rig.queue.repository.assignments[out.assignment_id]
        assert assignment.router_id == rig.gateway.id
        assert assignment.target_type == QueueTargetType.SESSION.value
        assert assignment.target_id == guest.id
        assert assignment.status == QueueStatus.ACTIVE.value
        assert call["name"] == f"cloudguest-{assignment.id}"

    async def test_falls_back_to_the_portal_recorded_ip(self):
        rig = make_rig()
        guest = _guest(rig, ip_address="192.168.88.23")
        out = await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id, framed_ip=None
        )
        assert out.action == "applied"
        assert rig.table.created[0]["target"] == "192.168.88.23"

    async def test_is_idempotent_an_interim_with_nothing_changed_touches_nothing(self):
        rig = make_rig()
        guest = _guest(rig)
        await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id, verify=True
        )
        reads = rig.table.reads

        out = await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id
        )

        assert out.action == "unchanged"
        assert len(rig.table.created) == 1
        assert rig.table.reads == reads  # no device I/O at all
        assert len(rig.table.rows) == 1

    async def test_a_start_reads_back_even_when_nothing_changed(self):
        rig = make_rig()
        guest = _guest(rig)
        await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id
        )
        reads = rig.table.reads
        out = await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id, verify=True
        )
        assert out.action == "applied" and rig.table.reads == reads + 1

    async def test_a_queue_removed_out_of_band_is_recreated_once_and_verified(self):
        rig = make_rig()
        guest = _guest(rig)
        await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id
        )
        rig.table.rows.clear()  # someone cleaned /queue simple by hand

        out = await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id, verify=True
        )

        assert out.action == "applied" and out.verified is True
        assert len(rig.table.rows) == 1
        live = [
            a
            for a in rig.queue.repository.assignments.values()
            if a.status == QueueStatus.ACTIVE.value
        ]
        assert len(live) == 1

    async def test_a_new_dhcp_lease_moves_the_queue_and_leaves_one_row(self):
        rig = make_rig()
        guest = _guest(rig)
        await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id, framed_ip="192.168.88.50"
        )
        out = await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id, framed_ip="192.168.88.51"
        )
        assert out.action == "applied"
        assert [r["target"] for r in rig.table.rows.values()] == ["192.168.88.51/32"]

    async def test_the_previous_holder_of_an_ip_is_superseded_not_stacked(self):
        """The queue-accumulation trap: first match wins on RouterOS, so a
        stale row for a reused IP must not survive."""
        rig = make_rig()
        first = _guest(rig)
        await rig.service.apply_for_session(
            session_id=first.id, nas_router_id=rig.nas.id, framed_ip="192.168.88.50"
        )
        first.status = "expired"
        second = _guest(rig)
        await rig.service.apply_for_session(
            session_id=second.id, nas_router_id=rig.nas.id, framed_ip="192.168.88.50"
        )
        assert len(rig.table.rows) == 1

    async def test_a_readback_mismatch_is_reported_and_recorded(self):
        rig = make_rig()
        guest = _guest(rig)
        original = rig.table.create_simple_queue

        async def wrong_target(credentials, **kw):
            qid = await original(credentials, **kw)
            rig.table.rows[qid]["target"] = "192.168.88.99/32"
            return qid

        rig.table.create_simple_queue = wrong_target  # type: ignore[method-assign]
        out = await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id
        )
        assert out.action == "failed" and out.reason == "target_mismatch"
        assignment = rig.queue.repository.assignments[out.assignment_id]
        assert "read-back" in (assignment.error_message or "")

    @pytest.mark.parametrize(
        ("setup", "reason"),
        [
            ("disabled", "disabled"),
            ("unlinked", "no_gateway"),
            ("ended", "session_not_active"),
            ("other_router", "router_mismatch"),
            ("no_ip", "no_guest_ip"),
            ("gateway_moved", "no_gateway"),
        ],
    )
    async def test_skips_write_nothing(self, setup, reason):
        rig = make_rig(enabled=setup != "disabled", link=setup != "unlinked")
        guest = _guest(rig, ip_address=None if setup == "no_ip" else "192.168.88.23")
        if setup == "ended":
            guest.status = "expired"
        nas_id = uuid.uuid4() if setup == "other_router" else rig.nas.id
        if setup == "gateway_moved":
            rig.gateway.location_id = uuid.uuid4()
        out = await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=nas_id
        )
        assert (out.action, out.reason) == ("skipped", reason)
        assert rig.table.created == [] and rig.queue.repository.assignments == {}


class TestVendorGate:
    """Regression: a pure-MikroTik or Omada session never reaches the
    hybrid path, even with the flag on and a link present."""

    @pytest.mark.parametrize("vendor", ["mikrotik", "tplink_omada"])
    async def test_a_session_on_a_non_nas_only_router_is_untouched(self, vendor):
        rig = make_rig()
        router = rig.routers.add(_router(vendor=vendor, name="venue router"))
        # Even a (bogus) link row keyed on it does nothing.
        rig.repo.links[router.id] = LocationSpeedGateway(
            id=uuid.uuid4(),
            organization_id=ORG,
            location_id=LOC,
            nas_router_id=router.id,
            gateway_router_id=rig.gateway.id,
            is_deleted=False,
        )
        guest = _guest(rig, router_id=router.id)
        out = await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=router.id
        )
        assert (out.action, out.reason) == ("skipped", "no_gateway")
        assert rig.table.created == []

    async def test_release_never_touches_the_gateways_own_hotspot_guests(self):
        """The gateway may also run a MikroTik hotspot. Those sessions' queues
        belong to the normal MikroTik path, not to this module."""
        rig = make_rig()
        own = _guest(rig, router_id=rig.gateway.id, status="expired")
        assignment = await rig.queue.resolve_and_assign_queue(
            requesting_organization_id=ORG,
            location_id=LOC,
            router_id=rig.gateway.id,
            target_type=QueueTargetType.SESSION,
            target_id=own.id,
            device_target="192.168.88.77",
        )
        out = await rig.service.release_for_session(session_id=own.id)
        assert out.action == "skipped"
        result = await rig.service.reconcile()
        assert result["checked"] == 0
        assert assignment.device_queue_id in rig.table.rows


# ============================================================================
# Release + reconcile
# ============================================================================


class TestRelease:
    async def _applied(self, rig: Rig, **kw) -> tuple[FakeSession, uuid.UUID]:
        guest = _guest(rig, **kw)
        out = await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id
        )
        return guest, out.assignment_id

    async def test_stop_removes_the_queue_reads_back_and_expires_the_row(self):
        rig = make_rig()
        guest, assignment_id = await self._applied(rig)
        guest.status = "expired"

        out = await rig.service.release_for_session(session_id=guest.id)

        assert out.action == "released"
        assert rig.table.rows == {}
        assert len(rig.table.removed) == 1
        assignment = rig.queue.repository.assignments[assignment_id]
        assert assignment.status == QueueStatus.EXPIRED.value

    async def test_release_is_idempotent(self):
        rig = make_rig()
        guest, _ = await self._applied(rig)
        await rig.service.release_for_session(session_id=guest.id)
        out = await rig.service.release_for_session(session_id=guest.id)
        assert (out.action, out.reason) == ("skipped", "nothing_to_release")
        assert len(rig.table.removed) == 1

    async def test_an_unreachable_gateway_keeps_the_row_active_for_the_sweep(self):
        rig = make_rig()
        guest, assignment_id = await self._applied(rig)
        rig.table.unreachable = True
        with pytest.raises(QueueDeviceConnectionError):
            await rig.service.release_for_session(session_id=guest.id)
        assert (
            rig.queue.repository.assignments[assignment_id].status
            == QueueStatus.ACTIVE.value
        )

    async def test_a_row_already_gone_from_the_device_is_expired_without_a_remove(self):
        rig = make_rig()
        guest, assignment_id = await self._applied(rig)
        rig.table.rows.clear()
        out = await rig.service.release_for_session(session_id=guest.id)
        assert out.action == "released"
        assert rig.table.removed == []
        assert (
            rig.queue.repository.assignments[assignment_id].status
            == QueueStatus.EXPIRED.value
        )

    async def test_the_sweep_releases_only_sessions_the_ap_has_certainly_dropped(self):
        rig = make_rig()
        long_gone, _ = await self._applied(rig, ip_address="192.168.88.10")
        long_gone.status = "terminated"
        long_gone.session_timeout_minutes = 30
        long_gone.started_at = datetime.now(UTC) - timedelta(hours=2)

        blocked_now, _ = await self._applied(rig, ip_address="192.168.88.11")
        blocked_now.status = "terminated"  # AP still forwarding it

        online, _ = await self._applied(rig, ip_address="192.168.88.12")

        result = await rig.service.reconcile()

        assert result == {"checked": 3, "released": 1, "failed": 0, "kept": 2}
        targets = sorted(r["target"] for r in rig.table.rows.values())
        assert targets == ["192.168.88.11/32", "192.168.88.12/32"]
        assert online.is_active()

    async def test_the_sweep_does_nothing_with_the_flag_off(self):
        rig = make_rig()
        guest, _ = await self._applied(rig)
        guest.status = "expired"
        guest.started_at = datetime.now(UTC) - timedelta(days=2)
        rig.service.enabled = False
        assert (await rig.service.reconcile())["checked"] == 0
        assert len(rig.table.rows) == 1


# ============================================================================
# Master link
# ============================================================================


class TestLink:
    async def test_link_copies_org_and_location_from_the_access_point(self):
        rig = make_rig(link=False)
        status = await rig.service.link(
            nas_router_id=rig.nas.id,
            gateway_router_id=rig.gateway.id,
            actor_user_id=None,
        )
        row = rig.repo.links[rig.nas.id]
        assert (row.organization_id, row.location_id) == (ORG, LOC)
        assert status["per_guest_speed_active"] is True
        assert status["gateway"]["router_id"] == str(rig.gateway.id)
        assert [c["router_id"] for c in status["candidates"]] == [str(rig.gateway.id)]

    async def test_status_reports_the_flag_honestly(self):
        rig = make_rig(enabled=False)
        status = await rig.service.status(rig.nas.id)
        assert status["feature_enabled"] is False
        assert status["per_guest_speed_active"] is False

    @pytest.mark.parametrize(
        ("kind", "code"),
        [
            ("foreign_org", "SPEED_GATEWAY_LOCATION_MISMATCH"),
            ("other_location", "SPEED_GATEWAY_LOCATION_MISMATCH"),
            ("omada", "SPEED_GATEWAY_WRONG_VENDOR"),
            ("no_creds", "SPEED_GATEWAY_NO_CREDENTIALS"),
            ("missing", "SPEED_GATEWAY_ROUTER_NOT_FOUND"),
        ],
    )
    async def test_link_refuses(self, kind, code):
        rig = make_rig(link=False)
        target = {
            "foreign_org": lambda: rig.routers.add(
                _router(organization_id=uuid.uuid4())
            ),
            "other_location": lambda: rig.routers.add(
                _router(location_id=uuid.uuid4())
            ),
            "omada": lambda: rig.routers.add(_router(vendor="tplink_omada")),
            "no_creds": lambda: rig.routers.add(_router(creds=False)),
            "missing": lambda: _router(),
        }[kind]()
        with pytest.raises(SpeedGatewayError) as exc:
            await rig.service.link(
                nas_router_id=rig.nas.id,
                gateway_router_id=target.id,
                actor_user_id=None,
            )
        assert exc.value.data["code"] == code
        assert rig.repo.links == {}

    async def test_a_gateway_cannot_be_linked_to_a_non_aruba_router(self):
        rig = make_rig(link=False)
        with pytest.raises(SpeedGatewayError) as exc:
            await rig.service.link(
                nas_router_id=rig.gateway.id,
                gateway_router_id=rig.gateway.id,
                actor_user_id=None,
            )
        assert exc.value.data["code"] == "SPEED_GATEWAY_NOT_NAS_ONLY"

    async def test_unlink_removes_the_queues_it_put_there(self):
        rig = make_rig()
        guest = _guest(rig)
        await rig.service.apply_for_session(
            session_id=guest.id, nas_router_id=rig.nas.id
        )
        status = await rig.service.unlink(nas_router_id=rig.nas.id, actor_user_id=None)
        assert status["gateway"] is None and status["per_guest_speed_active"] is False
        assert rig.table.rows == {}
        assert rig.repo.links == {}

    async def test_customer_view_never_reads_another_tenants_location(self):
        rig = make_rig()
        assert await rig.service.customer_per_guest_speed(
            location_id=LOC, organization_id=ORG
        )
        assert not await rig.service.customer_per_guest_speed(
            location_id=LOC, organization_id=uuid.uuid4()
        )
        rig.service.enabled = False
        assert not await rig.service.customer_per_guest_speed(
            location_id=LOC, organization_id=ORG
        )


# ============================================================================
# Wire shape + routes
# ============================================================================


class TestWire:
    def test_rest_conf_accounting_carries_framed_ip_and_the_model_reads_it(self):
        import json
        import re
        from pathlib import Path

        from app.domains.guest.schemas import RadiusAccountingRequest

        rest = (
            Path(__file__).resolve().parents[2] / "ops" / "freeradius" / "rest.conf"
        ).read_text()
        template = re.search(
            r'data\s*=\s*"(.*)"', rest.split("accounting {", 1)[1]
        ).group(1)
        body = template.replace('\\"', '"')
        for expansion, value in (
            ("%{control:Tmp-String-0}", "start"),
            ("%{User-Name}", "+919999999999"),
            ("%{Calling-Station-Id}", "4ee9e5ceb96a"),
            ("%{Acct-Session-Id}", "x"),
            ("%{control:Tmp-Integer64-0}", "0"),
            ("%{control:Tmp-Integer64-1}", "0"),
            ("%{control:Tmp-String-1}", ""),
            ("%{Framed-IP-Address}", "172.16.0.4"),
        ):
            body = body.replace(expansion, value)
        request = RadiusAccountingRequest(**json.loads(body))
        assert request.framed_ip_address == "172.16.0.4"

    @pytest.mark.parametrize("raw", ["", "garbage", None])
    def test_a_missing_or_bad_framed_ip_never_fails_accounting(self, raw):
        from app.domains.guest.schemas import RadiusAccountingRequest

        request = RadiusAccountingRequest(
            status_type="interim-update", username="u", framed_ip_address=raw
        )
        assert request.framed_ip_address is None

    def test_master_routes_are_pinned_global_and_the_customer_route_is_org(self):
        from app.domains.queue_management.speed_gateway_router import (
            speed_gateway_customer_router,
            speed_gateway_platform_router,
        )
        from app.domains.rbac.enums import ScopeType

        def gates(router):
            found = []
            for route in router.routes:
                for dep in route.dependencies:
                    call = dep.dependency
                    if "RequirePermission" not in getattr(call, "__qualname__", ""):
                        continue
                    names = call.__code__.co_freevars
                    cells = dict(
                        zip(
                            names,
                            (c.cell_contents for c in call.__closure__),
                            strict=True,
                        )
                    )
                    found.append((cells["permission_key"], cells["scope"]))
            return found

        platform = gates(speed_gateway_platform_router)
        assert len(platform) == 3
        assert all(scope == ScopeType.GLOBAL for _, scope in platform)
        assert {key for key, _ in platform} == {
            "network_integrations.read",
            "network_integrations.update",
        }
        assert gates(speed_gateway_customer_router) == [
            ("locations.read", ScopeType.ORGANIZATION)
        ]


# ============================================================================
# The accounting trigger (shared Aruba listener only)
# ============================================================================


class TestAccountingDispatch:
    @pytest.fixture
    def dispatch(self, monkeypatch):  # noqa: ANN001, ANN201
        from types import SimpleNamespace

        from app.domains.guest import router as guest_router
        from app.domains.queue_management import speed_gateway, tasks

        calls: list[tuple[str, dict]] = []
        state = {"enabled": True, "linked": True}

        monkeypatch.setattr(
            guest_router,
            "get_settings",
            lambda: SimpleNamespace(
                aruba_hybrid_speed_gateway_enabled=state["enabled"]
            ),
        )

        async def _get_for_nas_router(self, nas_router_id):  # noqa: ANN001, ANN202
            return object() if state["linked"] else None

        monkeypatch.setattr(
            speed_gateway.SpeedGatewayRepository,
            "get_for_nas_router",
            _get_for_nas_router,
        )

        async def _apply(**kw):  # noqa: ANN003, ANN202
            calls.append(("apply", kw))

        async def _release(**kw):  # noqa: ANN003, ANN202
            calls.append(("release", kw))

        monkeypatch.setattr(tasks, "enqueue_aruba_hybrid_apply", _apply)
        monkeypatch.setattr(tasks, "enqueue_aruba_hybrid_release", _release)
        service = SimpleNamespace(repository=SimpleNamespace(session=object()))
        nas = SimpleNamespace(router_id=uuid.uuid4())
        return guest_router, calls, state, service, nas

    async def _send(
        self, dispatch, status_type: str, framed: str | None = "192.168.88.50"
    ):  # noqa: ANN001
        from app.domains.guest.schemas import (
            RadiusAccountingRequest,
            RadiusAccountingResponse,
        )

        guest_router, calls, _, service, nas = dispatch
        sid = uuid.uuid4()
        await guest_router._dispatch_aruba_hybrid_speed(
            RadiusAccountingRequest(
                status_type=status_type, username="u", framed_ip_address=framed
            ),
            nas,
            RadiusAccountingResponse(session_id=str(sid), status="active"),
            service,
        )
        return sid

    async def test_start_enqueues_a_verified_apply_with_the_framed_ip(self, dispatch):
        sid = await self._send(dispatch, "start")
        ((kind, kw),) = dispatch[1]
        assert kind == "apply"
        assert kw["session_id"] == sid and kw["framed_ip"] == "192.168.88.50"
        assert kw["verify"] is True and kw["nas_router_id"] == dispatch[4].router_id

    async def test_interim_enqueues_an_unverified_apply(self, dispatch):
        await self._send(dispatch, "interim-update")
        assert dispatch[1][0][1]["verify"] is False

    async def test_stop_enqueues_a_release(self, dispatch):
        sid = await self._send(dispatch, "stop")
        assert dispatch[1] == [("release", {"session_id": sid})]

    async def test_flag_off_or_no_link_enqueues_nothing(self, dispatch):
        dispatch[2]["enabled"] = False
        await self._send(dispatch, "start")
        dispatch[2]["enabled"] = True
        dispatch[2]["linked"] = False
        await self._send(dispatch, "start")
        await self._send(dispatch, "stop")
        assert dispatch[1] == []

    def test_only_the_shared_aruba_listener_dispatches(self):
        """Regression for MikroTik/Omada: the per-venue /radius/accounting
        route never reaches the hybrid trigger."""
        import inspect

        from app.domains.guest import router as guest_router

        assert "_dispatch_aruba_hybrid_speed" in inspect.getsource(
            guest_router.radius_aruba_shared_accounting
        )
        for fn in (guest_router.radius_accounting, guest_router._radius_accounting):
            assert "_dispatch_aruba_hybrid_speed" not in inspect.getsource(fn)
