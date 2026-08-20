"""Unit tests for Wave 1 Step 6 WAN verification (P7 / R8)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.domains.isp.constants import IspConnectionMode, IspLinkRole
from app.domains.isp.device_adapters import PingResult
from app.domains.isp.exceptions import IspDeviceConnectionError
from app.domains.isp.models import IspLink
from app.domains.provisioning_engine.planner.constants import (
    VerificationCheckStatus,
    VerificationScope,
    WanVerificationOverall,
)
from app.domains.provisioning_engine.planner.exceptions import NoWanLinksToVerifyError
from app.domains.provisioning_engine.planner.verification_models import VerificationRun
from app.domains.provisioning_engine.planner.verification_service import (
    WanVerificationService,
)
from app.domains.provisioning_engine.planner.wan_verification import (
    WanLinkVerificationInput,
    evaluate_wan_link_verification,
    wan_verification_gate_passes,
)
from app.domains.router.models import Router
from tests.unit.test_isp import FakeRouterLookup, _base_fields, _make_router


def _make_isp_link(**overrides: object) -> IspLink:
    fields = {
        "router_id": uuid.uuid4(),
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "provider_name": "Airtel",
        "link_type": "fiber",
        "connection_mode": IspConnectionMode.DHCP.value,
        "role": IspLinkRole.PRIMARY.value,
        "is_active_uplink": True,
        "auto_failback": True,
        "is_enabled": True,
        "priority": 0,
        "interface": "ether1",
        "routing_interface": "ether1",
        "gateway_ip_address": "203.0.113.1",
        "dns_primary": None,
        "dns_secondary": None,
        "download_bandwidth_mbps": None,
        "upload_bandwidth_mbps": None,
        "health_status": "unknown",
        "health_status_source": "automated",
        "latency_ms": None,
        "packet_loss_percentage": None,
        "last_checked_at": None,
        "consecutive_unhealthy_count": 0,
    }
    fields.update(overrides)
    return IspLink(**_base_fields(**fields))


def _healthy_ping(**overrides: object) -> PingResult:
    fields = {
        "sent": 3,
        "received": 3,
        "packet_loss_percentage": 0.0,
        "avg_rtt_ms": 12.5,
    }
    fields.update(overrides)
    return PingResult(**fields)


class TestEvaluateWanLinkVerification:
    def test_disabled_link_returns_disabled_overall(self) -> None:
        link = _make_isp_link(is_enabled=False)
        overall, checks = evaluate_wan_link_verification(
            WanLinkVerificationInput(link=link, slot=1)
        )
        assert overall is WanVerificationOverall.DISABLED
        assert len(checks) == 1
        assert checks[0].name == "link_enabled"
        assert checks[0].status is VerificationCheckStatus.PASS

    def test_ping_error_returns_error_overall(self) -> None:
        link = _make_isp_link()
        overall, checks = evaluate_wan_link_verification(
            WanLinkVerificationInput(
                link=link,
                slot=1,
                error_message="device unreachable",
            )
        )
        assert overall is WanVerificationOverall.ERROR
        assert any(c.name == "gateway_ping" for c in checks)

    def test_missing_interface_returns_error(self) -> None:
        link = _make_isp_link(interface=None, routing_interface=None)
        overall, checks = evaluate_wan_link_verification(
            WanLinkVerificationInput(link=link, slot=1, ping=_healthy_ping())
        )
        assert overall is WanVerificationOverall.ERROR
        assert any(c.name == "link_up" for c in checks)

    def test_dhcp_online_when_gateway_reachable(self) -> None:
        link = _make_isp_link(connection_mode=IspConnectionMode.DHCP.value)
        overall, checks = evaluate_wan_link_verification(
            WanLinkVerificationInput(link=link, slot=1, ping=_healthy_ping())
        )
        assert overall is WanVerificationOverall.ONLINE
        names = [c.name for c in checks]
        assert names == [
            "link_enabled",
            "link_up",
            "gateway_ping",
            "address_acquired",
        ]

    def test_static_offline_on_total_packet_loss(self) -> None:
        link = _make_isp_link(connection_mode=IspConnectionMode.STATIC.value)
        overall, _checks = evaluate_wan_link_verification(
            WanLinkVerificationInput(
                link=link,
                slot=1,
                ping=PingResult(
                    sent=3, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
                ),
            )
        )
        assert overall is WanVerificationOverall.OFFLINE

    def test_pppoe_online_when_session_up(self) -> None:
        link = _make_isp_link(
            connection_mode=IspConnectionMode.PPPOE.value,
            interface="ether1",
            routing_interface="pppoe-wan1",
        )
        overall, checks = evaluate_wan_link_verification(
            WanLinkVerificationInput(link=link, slot=1, ping=_healthy_ping())
        )
        assert overall is WanVerificationOverall.ONLINE
        assert any(c.name == "address_acquired" for c in checks)

    def test_pppoe_offline_when_session_down(self) -> None:
        link = _make_isp_link(
            connection_mode=IspConnectionMode.PPPOE.value,
            routing_interface="pppoe-wan1",
        )
        overall, _checks = evaluate_wan_link_verification(
            WanLinkVerificationInput(
                link=link,
                slot=1,
                ping=PingResult(
                    sent=3, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
                ),
            )
        )
        assert overall is WanVerificationOverall.OFFLINE

    def test_high_latency_yields_warning_but_online(self) -> None:
        link = _make_isp_link()
        overall, checks = evaluate_wan_link_verification(
            WanLinkVerificationInput(
                link=link,
                slot=1,
                ping=_healthy_ping(avg_rtt_ms=600.0),
            )
        )
        assert overall is WanVerificationOverall.ONLINE
        ping_check = next(c for c in checks if c.name == "gateway_ping")
        assert ping_check.status is VerificationCheckStatus.WARNING


class TestWanVerificationGate:
    def test_gate_passes_when_all_enabled_links_online(self) -> None:
        link_a = uuid.uuid4()
        link_b = uuid.uuid4()
        runs = [
            _fake_run(link_a, WanVerificationOverall.ONLINE.value),
            _fake_run(link_b, WanVerificationOverall.ONLINE.value),
        ]
        assert wan_verification_gate_passes(
            enabled_link_ids={link_a, link_b}, runs=runs
        )

    def test_gate_fails_when_any_link_missing_or_not_online(self) -> None:
        link_a = uuid.uuid4()
        link_b = uuid.uuid4()
        runs = [_fake_run(link_a, WanVerificationOverall.ONLINE.value)]
        assert not wan_verification_gate_passes(
            enabled_link_ids={link_a, link_b}, runs=runs
        )

        runs = [
            _fake_run(link_a, WanVerificationOverall.ONLINE.value),
            _fake_run(link_b, WanVerificationOverall.OFFLINE.value),
        ]
        assert not wan_verification_gate_passes(
            enabled_link_ids={link_a, link_b}, runs=runs
        )

    def test_gate_fails_when_no_enabled_links(self) -> None:
        assert not wan_verification_gate_passes(enabled_link_ids=set(), runs=[])


def _fake_run(link_id: uuid.UUID, overall: str) -> VerificationRun:
    return VerificationRun(
        **_base_fields(
            router_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            scope=VerificationScope.WAN.value,
            run_group_id=uuid.uuid4(),
            plan_id=None,
            isp_link_id=link_id,
            overall=overall,
            checks=[],
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
    )


@dataclass
class FakeVerificationRepository:
    rows: list[VerificationRun] = field(default_factory=list)

    async def create(self, data: dict[str, object]) -> VerificationRun:
        row = VerificationRun(**_base_fields(**data))
        self.rows.append(row)
        return row

    async def list_for_run_group(
        self, router_id: uuid.UUID, run_group_id: uuid.UUID
    ) -> list[VerificationRun]:
        return [
            row
            for row in self.rows
            if row.router_id == router_id and row.run_group_id == run_group_id
        ]

    async def get_latest_run_group_id(
        self, router_id: uuid.UUID, *, scope: str
    ) -> uuid.UUID | None:
        scoped = [
            row
            for row in self.rows
            if row.router_id == router_id and row.scope == scope
        ]
        if not scoped:
            return None
        scoped.sort(key=lambda row: row.started_at, reverse=True)
        return scoped[0].run_group_id

    async def list_latest_group_for_router(
        self, router_id: uuid.UUID, *, scope: str
    ) -> list[VerificationRun]:
        group_id = await self.get_latest_run_group_id(router_id, scope=scope)
        if group_id is None:
            return []
        return await self.list_for_run_group(router_id, group_id)


@dataclass
class FakeIspLinkLookup:
    links: list[IspLink]

    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        values = list(self.links)
        if router_id is not None:
            values = [link for link in values if link.router_id == router_id]
        return values, object()


@dataclass
class FakeIspPing:
    next_result: PingResult | None = None
    error: Exception | None = None

    async def ping_link(self, link: IspLink) -> PingResult:
        if self.error is not None:
            raise self.error
        return self.next_result or _healthy_ping()


@pytest.mark.asyncio
async def test_verify_wan_persists_runs_and_sets_gate() -> None:
    router = _make_router()
    primary = _make_isp_link(
        router_id=router.id,
        organization_id=router.organization_id,
        location_id=router.location_id,
        role=IspLinkRole.PRIMARY.value,
        priority=0,
    )
    backup = _make_isp_link(
        router_id=router.id,
        organization_id=router.organization_id,
        location_id=router.location_id,
        role=IspLinkRole.BACKUP.value,
        priority=1,
        interface="ether2",
        routing_interface="ether2",
    )
    repo = FakeVerificationRepository()
    router_lookup = FakeRouterLookup()
    router_lookup.add(router)
    service = WanVerificationService(
        repository=repo,
        router_lookup=router_lookup,
        isp_link_lookup=FakeIspLinkLookup(links=[backup, primary]),
        isp_ping=FakeIspPing(),
    )

    result = await service.verify_wan(
        router.id, actor_user_id=uuid.uuid4(), requesting_organization_id=None
    )

    assert len(repo.rows) == 2
    assert result.gate_passes is True
    assert len(result.links) == 2
    assert result.links[0].slot == 1
    assert result.links[0].overall is WanVerificationOverall.ONLINE


@pytest.mark.asyncio
async def test_verify_wan_raises_when_no_enabled_links() -> None:
    router = _make_router()
    disabled = _make_isp_link(router_id=router.id, is_enabled=False)
    router_lookup = FakeRouterLookup()
    router_lookup.add(router)
    service = WanVerificationService(
        repository=FakeVerificationRepository(),
        router_lookup=router_lookup,
        isp_link_lookup=FakeIspLinkLookup(links=[disabled]),
        isp_ping=FakeIspPing(),
    )
    with pytest.raises(NoWanLinksToVerifyError):
        await service.verify_wan(
            router.id, actor_user_id=None, requesting_organization_id=None
        )


@pytest.mark.asyncio
async def test_verify_wan_captures_ping_errors() -> None:
    router = _make_router()
    link = _make_isp_link(router_id=router.id)
    repo = FakeVerificationRepository()
    router_lookup = FakeRouterLookup()
    router_lookup.add(router)
    service = WanVerificationService(
        repository=repo,
        router_lookup=router_lookup,
        isp_link_lookup=FakeIspLinkLookup(links=[link]),
        isp_ping=FakeIspPing(error=IspDeviceConnectionError("10.0.0.1", "timeout")),
    )

    result = await service.verify_wan(
        router.id, actor_user_id=None, requesting_organization_id=None
    )

    assert result.gate_passes is False
    assert result.links[0].overall is WanVerificationOverall.ERROR


@pytest.mark.asyncio
async def test_get_wan_gate_reads_latest_run_group() -> None:
    router = _make_router()
    link = _make_isp_link(router_id=router.id)
    repo = FakeVerificationRepository()
    group_id = uuid.uuid4()
    repo.rows.append(
        _fake_run_with_group(
            router=router,
            link_id=link.id,
            run_group_id=group_id,
            overall=WanVerificationOverall.ONLINE.value,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    router_lookup = FakeRouterLookup()
    router_lookup.add(router)
    service = WanVerificationService(
        repository=repo,
        router_lookup=router_lookup,
        isp_link_lookup=FakeIspLinkLookup(links=[link]),
        isp_ping=FakeIspPing(),
    )

    gate = await service.get_wan_gate(router.id, requesting_organization_id=None)

    assert gate.passes is True
    assert gate.run_group_id == str(group_id)


def _fake_run_with_group(
    *,
    router: Router,
    link_id: uuid.UUID,
    run_group_id: uuid.UUID,
    overall: str,
    started_at: datetime,
) -> VerificationRun:
    return VerificationRun(
        **_base_fields(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            scope=VerificationScope.WAN.value,
            run_group_id=run_group_id,
            plan_id=None,
            isp_link_id=link_id,
            overall=overall,
            checks=[],
            started_at=started_at,
            completed_at=started_at,
        )
    )
