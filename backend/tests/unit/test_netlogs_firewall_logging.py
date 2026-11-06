"""Firewall logging into NetLogs (``WYFY-FW``): the line shape, the flag
gating, the per-router toggle, the re-converge hook every forward-chain
writer calls, and the route scope.

The RouterOS side (which rows, where, limit, idempotency, removal, read-back)
is pinned in the gateway's own ``tests/test_mikrotik_firewall_logging.py``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.domains.device_logs import router as dl_router
from app.domains.device_logs.classifier import (
    WYFY_FIREWALL_LOG_PREFIX,
    classification_columns,
    classify,
    summary_for,
)
from app.domains.device_logs.constants import (
    FIREWALL_LOG_MAX_COMPANIONS,
    FIREWALL_LOG_MAX_LINES_PER_MINUTE,
    FIREWALL_LOG_PER_RULE_LIMIT,
)
from app.domains.device_logs.exceptions import (
    DeviceLogsDeviceError,
    DeviceLogsDisabledError,
    FirewallLoggingNeedsRemoteLoggingError,
    FirewallLoggingSwitchedOffError,
)
from app.domains.device_logs.models import RouterRemoteLogging
from app.domains.device_logs.parser import parse_line
from app.domains.device_logs.schemas import FirewallLoggingState
from app.domains.device_logs.service import (
    DeviceLogsService,
    DeviceWriteFailed,
    FirewallLoggingVerdict,
)
from app.domains.firewall.service import FirewallService
from tests.unit.test_device_logs import (
    NOW,
    ROUTER_ID,
    FakeRepo,
    FakeWriter,
    _ctx,
    _router,
    _settings,
)

ACTOR = uuid.uuid4()

# -- the line ----------------------------------------------------------------

_TCP = (
    "WYFY-FW forward: in:bridge-guest out:ether1, connection-state:new "
    "src-mac 3c:22:fb:11:22:33, proto TCP (SYN), "
    "10.5.50.12:51544->1.1.1.1:443, len 60"
)


class TestLineShape:
    def test_tcp_line_is_a_blocked_firewall_event(self) -> None:
        c = classify(_TCP)
        assert (c.category, c.protocol, c.src_ip, c.dst_ip, c.status) == (
            "firewall",
            "TCP",
            "10.5.50.12",
            "1.1.1.1",
            "blocked",
        )
        assert c.device_mac == "3C:22:FB:11:22:33"
        assert summary_for(c.category, c.status) == "Traffic denied"

    @pytest.mark.parametrize(
        ("body", "proto", "dst"),
        [
            (
                "WYFY-FW forward: in:bridge-guest out:ether1, connection-state:new "
                "src-mac 3c:22:fb:11:22:33, proto UDP, 10.5.50.12:5353->"
                "8.8.4.4:853, len 70",
                "UDP",
                "8.8.4.4",
            ),
            (
                "WYFY-FW forward: in:bridge-guest out:bridge-guest, "
                "connection-state:new src-mac 3c:22:fb:11:22:33, proto ICMP "
                "(type 8, code 0), 10.5.50.12->10.5.50.40, len 84",
                "ICMP",
                "10.5.50.40",
            ),
        ],
    )
    def test_udp_and_icmp_lines(self, body: str, proto: str, dst: str) -> None:
        c = classify(body)
        assert (c.protocol, c.dst_ip, c.status) == (proto, dst, "blocked")

    def test_full_syslog_line_through_parser_and_classifier(self) -> None:
        raw = (
            "<174>Oct 18 11:29:58 Office Router wyfy-412d5133 " + _TCP
        )
        parsed = parse_line(raw, received_at=datetime(2026, 10, 18, 6, 0, tzinfo=UTC))
        assert parsed.tag == "412d5133"
        assert parsed.hostname == "Office Router"
        cols = classification_columns(parsed.message, topics=parsed.topics)
        assert cols == {
            "category": "firewall",
            "protocol": "TCP",
            "src_ip": "10.5.50.12",
            "dst_ip": "1.1.1.1",
            "status": "blocked",
            "device_mac": "3C:22:FB:11:22:33",
        }

    def test_without_the_prefix_status_is_still_not_guessed(self) -> None:
        c = classify(_TCP.replace("WYFY-FW ", "", 1))
        assert c.category == "firewall" and c.status is None

    def test_constants_mirror_the_gateway(self) -> None:
        from wyfy_device_gateway import mikrotik_firewall_logging as gw

        assert WYFY_FIREWALL_LOG_PREFIX == gw.LOG_PREFIX
        assert FIREWALL_LOG_PER_RULE_LIMIT == gw.LOG_LIMIT
        assert FIREWALL_LOG_MAX_COMPANIONS == gw.MAX_COMPANIONS
        # Bounded well under the collector's 3000/min per-router throttle.
        assert FIREWALL_LOG_MAX_LINES_PER_MINUTE == 1200


# -- service -----------------------------------------------------------------


class FakeFirewallWriter:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.synced: list[bool] = []
        self.reads = 0

    def _verdict(self, enabled: bool) -> FirewallLoggingVerdict:
        return FirewallLoggingVerdict(
            enabled=enabled,
            ok=True,
            band_state="ready",
            targets=2 if enabled else 0,
            companions=2 if enabled else 0,
            skipped=(),
            detail="verified" if enabled else "removed",
        )

    async def sync(self, creds: Any, *, enabled: bool) -> FirewallLoggingVerdict:
        if self.fail:
            raise DeviceWriteFailed("timed out")
        self.synced.append(enabled)
        return self._verdict(enabled)

    async def read(self, creds: Any) -> FirewallLoggingVerdict:
        self.reads += 1
        return self._verdict(bool(self.synced and self.synced[-1]))


def _row(*, enabled: bool = True, fw: bool = False) -> RouterRemoteLogging:
    return RouterRemoteLogging(
        router_id=ROUTER_ID,
        remote_host="10.20.0.1",
        remote_port=514,
        src_address="10.20.0.31",
        tag="8a199617",
        enabled=enabled,
        firewall_logging_enabled=fw,
    )


def _service(
    repo: FakeRepo, fw: FakeFirewallWriter, *, platform: bool = True, **over: Any
) -> DeviceLogsService:
    return DeviceLogsService(
        repo,
        _settings(device_logs_firewall_logging_enabled=platform, **over),
        writer=FakeWriter(),
        firewall_writer=fw,
        clock=lambda: NOW,
    )


@pytest.fixture
def repo(monkeypatch) -> FakeRepo:
    monkeypatch.setattr(
        "app.domains.device_logs.service.decrypt_secret", lambda _c: "pw"
    )
    r = FakeRepo()
    r.context = _ctx(_router())
    return r


class TestToggle:
    @pytest.mark.asyncio
    async def test_platform_switch_off_refuses_on_and_writes_nothing(
        self, repo
    ) -> None:
        repo.config = _row()
        fw = FakeFirewallWriter()
        with pytest.raises(FirewallLoggingSwitchedOffError):
            await _service(repo, fw, platform=False).set_firewall_logging(
                ROUTER_ID, enabled=True, actor_user_id=ACTOR
            )
        assert fw.synced == [] and repo.config.firewall_logging_enabled is False

    @pytest.mark.asyncio
    async def test_feature_off_refuses_on(self, repo) -> None:
        repo.config = _row()
        fw = FakeFirewallWriter()
        with pytest.raises(DeviceLogsDisabledError):
            await _service(repo, fw, device_logs_enabled=False).set_firewall_logging(
                ROUTER_ID, enabled=True, actor_user_id=ACTOR
            )
        assert fw.synced == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("config", [None, "removed"])
    async def test_needs_remote_logging_first(self, repo, config) -> None:
        repo.config = _row(enabled=False) if config else None
        fw = FakeFirewallWriter()
        with pytest.raises(FirewallLoggingNeedsRemoteLoggingError):
            await _service(repo, fw).set_firewall_logging(
                ROUTER_ID, enabled=True, actor_user_id=ACTOR
            )
        assert fw.synced == []

    @pytest.mark.asyncio
    async def test_on_writes_and_records_the_read_back(self, repo) -> None:
        repo.config = _row()
        fw = FakeFirewallWriter()
        state = await _service(repo, fw).set_firewall_logging(
            ROUTER_ID, enabled=True, actor_user_id=ACTOR
        )
        assert fw.synced == [True]
        assert repo.config.firewall_logging_enabled is True
        assert repo.config.firewall_logging_verified_ok is True
        assert state["active"] is True and state["device"]["companions"] == 2
        FirewallLoggingState.model_validate(state)

    @pytest.mark.asyncio
    async def test_off_always_removes_even_with_the_platform_switch_off(
        self, repo
    ) -> None:
        repo.config = _row(fw=True)
        fw = FakeFirewallWriter()
        state = await _service(repo, fw, platform=False).set_firewall_logging(
            ROUTER_ID, enabled=False, actor_user_id=ACTOR
        )
        assert fw.synced == [False]
        assert repo.config.firewall_logging_enabled is False
        assert state["active"] is False

    @pytest.mark.asyncio
    async def test_device_failure_is_a_502(self, repo) -> None:
        repo.config = _row()
        with pytest.raises(DeviceLogsDeviceError):
            await _service(repo, FakeFirewallWriter(fail=True)).set_firewall_logging(
                ROUTER_ID, enabled=True, actor_user_id=ACTOR
            )

    @pytest.mark.asyncio
    async def test_state_reads_the_device_and_writes_nothing(self, repo) -> None:
        repo.config = _row(fw=True)
        fw = FakeFirewallWriter()
        state = await _service(repo, fw).firewall_logging_state(ROUTER_ID)
        assert fw.reads == 1 and fw.synced == [] and repo.saved == []
        assert state["router_enabled"] and state["active"]
        FirewallLoggingState.model_validate(state)


class TestReconvergeHook:
    @pytest.mark.asyncio
    async def test_router_never_turned_on_costs_no_device_call(self, repo) -> None:
        fw = FakeFirewallWriter()
        repo.config = None
        await _service(repo, fw).after_firewall_write(ROUTER_ID)
        repo.config = _row(fw=False)
        await _service(repo, fw).after_firewall_write(ROUTER_ID)
        assert fw.synced == []

    @pytest.mark.asyncio
    async def test_on_router_is_reconverged(self, repo) -> None:
        repo.config = _row(fw=True)
        fw = FakeFirewallWriter()
        await _service(repo, fw).after_firewall_write(ROUTER_ID)
        assert fw.synced == [True]

    @pytest.mark.asyncio
    async def test_platform_switch_off_is_a_kill_switch(self, repo) -> None:
        repo.config = _row(fw=True)
        fw = FakeFirewallWriter()
        await _service(repo, fw, platform=False).after_firewall_write(ROUTER_ID)
        assert fw.synced == [False]

    @pytest.mark.asyncio
    async def test_hook_never_raises(self, repo) -> None:
        repo.config = _row(fw=True)
        await _service(repo, FakeFirewallWriter(fail=True)).after_firewall_write(
            ROUTER_ID
        )

    @pytest.mark.asyncio
    async def test_remote_logging_apply_and_remove_reconverge(self, repo) -> None:
        repo.config = _row(fw=True)
        fw = FakeFirewallWriter()
        service = _service(repo, fw)
        await service.apply(ROUTER_ID, actor_user_id=ACTOR)
        await service.remove(ROUTER_ID, actor_user_id=ACTOR)
        # Re-applied with remote logging, taken off when it went away; the
        # intent survives for the next apply.
        assert fw.synced == [True, False]
        assert repo.config.firewall_logging_enabled is True

    @pytest.mark.asyncio
    async def test_remote_logging_apply_survives_a_firewall_logging_failure(
        self, repo
    ) -> None:
        repo.config = _row(fw=True)
        service = _service(repo, FakeFirewallWriter(fail=True))
        await service.apply(ROUTER_ID, actor_user_id=ACTOR)
        assert repo.config.verified_ok is True
        assert repo.config.firewall_logging_verified_ok is False
        assert "not synced" in (repo.config.firewall_logging_detail or "")


class _Listener:
    def __init__(self) -> None:
        self.calls: list[uuid.UUID] = []

    async def after_firewall_write(self, router_id: uuid.UUID) -> None:
        self.calls.append(router_id)


class TestFirewallServiceCallsTheHook:
    @pytest.mark.asyncio
    async def test_listener_runs_after_success_and_after_failure(self) -> None:
        listener = _Listener()
        service = FirewallService(
            None,  # type: ignore[arg-type]
            None,  # type: ignore[arg-type]
            write_listener=listener,
        )
        async with service._router_write(ROUTER_ID):
            pass
        with pytest.raises(RuntimeError):
            async with service._router_write(ROUTER_ID):
                raise RuntimeError("push failed")
        assert listener.calls == [ROUTER_ID, ROUTER_ID]

    def test_every_forward_chain_writer_goes_through_the_hook(self) -> None:
        import inspect

        source = inspect.getsource(FirewallService)
        # The one remaining direct use is inside _router_write itself.
        assert source.count("async with self._router_lock(") == 1
        assert source.count("async with self._router_write(") == 4


class TestRoutes:
    def test_firewall_logging_routes_are_global_and_toggle_needs_manage(
        self,
    ) -> None:
        routes = [
            r
            for r in dl_router.device_logs_platform_router.routes
            if r.path.endswith("/firewall-logging")
        ]
        assert {m for r in routes for m in r.methods} == {"GET", "PUT"}
        for route in routes:
            (dep,) = [d.dependency for d in route.dependencies]
            closure = {str(c.cell_contents) for c in (dep.__closure__ or ())}
            assert "global" in closure
            wanted = "device_logs.manage" if "PUT" in route.methods else (
                "device_logs.read"
            )
            assert wanted in closure
