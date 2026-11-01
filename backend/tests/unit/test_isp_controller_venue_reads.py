"""CI-INTEG: controller-managed venues (Omada / Aruba Instant On rows with no
agent evidence) never read as broken hardware in the ISP partner console.

Covers the four round-2 reads that judge a router: J14 Telegram UP/DOWN
(``automation._device_statuses``), the NAT-feed banner state
(``compliance_logic.nat_feed_state``), the incidents health headline
(``IspIncidentsService.health``) and the NETMON-2 traffic-card reason
(``netmon.readability``). A MikroTik mislabelled as Omada that has agent
evidence (it once checked in) must still be treated as a real router.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from app.domains.isp_partner import compliance_logic, netmon
from app.domains.isp_partner.automation import _device_statuses
from app.domains.isp_partner.incidents_service import IspIncidentsService

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
ORG = uuid.uuid4()


def _router(name: str, vendor: str, status: str, *, evidence: bool) -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        name=name,
        vendor=vendor,
        status=status,
        organization_id=ORG,
        last_seen_at=NOW - timedelta(days=1) if evidence else None,
        routeros_version="7.16" if evidence else None,
        last_health_check_at=None,
        api_credentials_encrypted=None,
    )


MIKROTIK_DOWN = _router("hEX", "mikrotik", "offline", evidence=True)
OMADA = _router("Omada ctl", "tplink_omada", "offline", evidence=False)
ARUBA = _router("Instant On", "aruba_instant_on", "online", evidence=False)
MISLABELLED = _router("RB750 typed as Omada", "tplink_omada", "offline", evidence=True)
ALL = [MIKROTIK_DOWN, OMADA, ARUBA, MISLABELLED]


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[Any]:
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)


class _Session:
    """Answers every select with the fixture routers (the WHERE on status /
    org is not what is under test; the controller skip is)."""

    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows

    async def execute(self, _stmt: Any) -> _Result:
        return _Result(self.rows)


async def test_telegram_skips_controller_venues_but_not_a_mislabelled_mikrotik() -> (
    None
):
    out = await _device_statuses(_Session(ALL), [ORG], include_aps=False)
    names = {name: state for _k, _id, name, state, _c in out}
    assert names == {"hEX": "down", "RB750 typed as Omada": "down"}


async def test_incidents_health_keeps_controller_venues_out_of_up_down() -> None:
    svc = IspIncidentsService(session=_Session(ALL), clock=lambda: NOW)

    async def _list(*_a: Any, **_k: Any) -> dict:
        return {"summary": {"open": 0}}

    svc.list = _list  # type: ignore[method-assign]

    async def _children() -> list[uuid.UUID]:
        return [ORG]

    isp = SimpleNamespace(child_ids=_children)
    h = await svc.health(isp)
    assert h["routers_controller_managed"] == 2
    assert (h["routers_up"], h["routers_down"], h["routers_total"]) == (0, 2, 2)
    assert h["health_percent"] == 0.0
    assert "vendor controller" in h["basis"]


def test_nat_feed_controller_venue_is_not_applicable_and_never_alerts() -> None:
    state = compliance_logic.nat_feed_state(
        last_nat_at=None,
        export_configured=False,
        router_online=False,
        now=NOW,
        stale_after=timedelta(minutes=30),
        controller_managed=True,
    )
    assert state == compliance_logic.FEED_NOT_APPLICABLE
    assert state not in compliance_logic.FEED_ALERTING
    # Unchanged for an agent-managed router.
    assert (
        compliance_logic.nat_feed_state(
            last_nat_at=None,
            export_configured=False,
            router_online=True,
            now=NOW,
            stale_after=timedelta(minutes=30),
        )
        == compliance_logic.FEED_NOT_CONFIGURED
    )


def test_nat_feed_fresh_data_still_reads_ok_for_any_vendor() -> None:
    assert (
        compliance_logic.nat_feed_state(
            last_nat_at=NOW - timedelta(minutes=1),
            export_configured=True,
            router_online=True,
            now=NOW,
            stale_after=timedelta(minutes=30),
            controller_managed=True,
        )
        == compliance_logic.FEED_OK
    )


def test_netmon_controller_venue_gets_its_own_reason_without_platform_words() -> None:
    readable, reason, hint = netmon.readability(
        status="pending_provisioning",
        last_seen_at=None,
        snmp_enabled=False,
        snmp_last_poll_status=None,
        has_series=False,
        now=NOW,
        controller_managed=True,
    )
    assert (readable, reason) == (False, "controller_managed")
    assert hint and not any(w in hint.lower() for w in netmon.FORBIDDEN_HINT_WORDS)
    # A MikroTik that never finished setup still gets the setup hint.
    assert (
        netmon.readability(
            status="pending_provisioning",
            last_seen_at=None,
            snmp_enabled=False,
            snmp_last_poll_status=None,
            has_series=False,
            now=NOW,
        )[1]
        == "not_set_up"
    )
