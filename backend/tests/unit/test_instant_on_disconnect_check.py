"""After an Instant On disconnect, the worker records what the AP's client list
says. Read-only evidence: it must never affect the block or the release."""

from __future__ import annotations

import logging
import uuid
from typing import Any

import pytest

from app.core.config import Settings
from app.domains.network_integration import instant_on_control as control
from app.domains.network_integration import instant_on_disconnect_check as check
from app.domains.network_integration.providers.aruba_instant_on_client import (
    InstantOnError,
)
from app.domains.network_integration.providers.aruba_instant_on_control import (
    BlockResult,
)

MAC = "aa:bb:cc:dd:1f:2e"
ROUTER = uuid.uuid4()
ORG = uuid.uuid4()
TARGET = control.ControlTarget(
    router_id=ROUTER,
    organization_id=ORG,
    location_id=uuid.uuid4(),
    site_id="site-1",
    secret_arn="arn",
)


def _settings(**over: Any) -> Settings:
    base: dict[str, Any] = {"instant_on_disconnect_hold_seconds": 30}
    base.update(over)
    return Settings(**base)


class _Client:
    def __init__(self, row: dict | None = None, error: Exception | None = None) -> None:
        self.row, self.error, self.calls = row, error, []

    async def get_client(self, site_id: str, mac: str) -> dict | None:
        self.calls.append(("get_client", site_id, mac))
        if self.error:
            raise self.error
        return self.row

    async def block_client(self, site_id: str, mac: str) -> BlockResult:
        self.calls.append(("block", site_id, mac))
        return BlockResult(mac=mac, blocked=True, created=True, entry_id="e1")


class _Redis:
    def __init__(self, count: int = 0, fail: bool = False) -> None:
        self.count, self.fail, self.expiry, self.sets = count, fail, [], []

    async def incr(self, key: str) -> int:
        if self.fail:
            raise ConnectionError("down")
        self.count += 1
        return self.count

    async def expire(self, key: str, seconds: int) -> None:
        self.expiry.append(seconds)

    async def set(self, *a: Any, **k: Any) -> None:
        self.sets.append((a, k))


@pytest.fixture
def wired(monkeypatch):  # noqa: ANN001, ANN201
    state: dict[str, Any] = {"client": _Client(), "target": TARGET}

    async def resolve(*_: Any, **__: Any) -> Any:
        return state["target"]

    async def with_client(_t: Any, _s: Any, action: Any) -> Any:
        return await action(state["client"])

    monkeypatch.setattr(control, "resolve_control_target", resolve)
    monkeypatch.setattr(control, "_with_client", with_client)
    return state


def _events(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r for r in caplog.records if r.getMessage() == "instant_on_disconnect_check"
    ]


class TestPlan:
    def test_covers_block_hold_and_after_unblock(self) -> None:
        assert check.phase_plan(30) == (
            ("after_block", 5),
            ("before_unblock", 25),
            ("after_unblock_60s", 90),
            ("after_unblock_5m", 330),
        )

    @pytest.mark.parametrize("hold", [5, 6, 10, 600])
    def test_before_unblock_really_is_before_it_and_order_holds(
        self, hold: int
    ) -> None:
        plan = check.phase_plan(hold)
        delays = [d for _, d in plan]
        assert delays == sorted(delays) and len(set(delays)) == 4
        assert dict(plan)["before_unblock"] < hold


class TestOneCheck:
    async def test_present_client(self, wired, caplog) -> None:  # noqa: ANN001
        wired["client"] = _Client(
            {
                "status": "up",
                "isBlocked": True,
                "wirelessNetworkId": "net-1",
                "wirelessNetworkName": "WYFY_ARUBA",
                "connectionDurationInSeconds": 44,
                "hostName": "+919800000000",
                "macAddress": MAC,
                "ipAddress": "172.16.0.9",
            }
        )
        caplog.set_level(logging.INFO)
        assert (
            await check.check_disconnected_client(
                None,
                organization_id=ORG,
                router_id=ROUTER,
                mac=MAC,
                phase="after_block",
                seconds_since_block=5,
                settings=_settings(),
            )
            == "present"
        )
        event = _events(caplog)[0]
        assert event.client_state == "present"
        assert event.phase == "after_block"
        assert event.seconds_since_block == 5
        assert event.mac_last4 == "1f2e"
        assert event.network_name == "WYFY_ARUBA"
        assert event.network_id == "net-1"
        assert event.ap_status == "up"
        assert event.ap_is_blocked is True
        assert event.connection_seconds == 44
        assert event.missing_fields == []
        text = str(event.__dict__)
        assert MAC not in text
        assert "+919800000000" not in text
        assert "172.16.0.9" not in text

    async def test_absent_client(self, wired, caplog) -> None:  # noqa: ANN001
        wired["client"] = _Client(None)
        caplog.set_level(logging.INFO)
        result = await check.check_disconnected_client(
            None,
            organization_id=ORG,
            router_id=ROUTER,
            mac=MAC,
            phase="after_unblock_60s",
            seconds_since_block=90,
            settings=_settings(),
        )
        assert result == "absent"
        assert _events(caplog)[0].client_state == "absent"

    async def test_a_row_without_the_expected_fields_says_so(
        self, wired, caplog
    ) -> None:  # noqa: ANN001
        wired["client"] = _Client({"macAddress": MAC})
        caplog.set_level(logging.INFO)
        await check.check_disconnected_client(
            None,
            organization_id=ORG,
            router_id=ROUTER,
            mac=MAC,
            phase="after_block",
            seconds_since_block=5,
            settings=_settings(),
        )
        event = _events(caplog)[0]
        assert event.client_state == "present"
        assert set(event.missing_fields) >= {"status", "wirelessNetworkName"}

    @pytest.mark.parametrize(
        "error", [InstantOnError("boom", reason="x"), RuntimeError("boom")]
    )
    async def test_a_failed_read_is_unknown_never_gone(
        self, wired, caplog, error: Exception
    ) -> None:  # noqa: ANN001
        wired["client"] = _Client(error=error)
        caplog.set_level(logging.INFO)
        result = await check.check_disconnected_client(
            None,
            organization_id=ORG,
            router_id=ROUTER,
            mac=MAC,
            phase="before_unblock",
            seconds_since_block=25,
            settings=_settings(),
        )
        assert result == "unknown"
        assert _events(caplog)[0].client_state == "unknown"

    async def test_a_venue_without_cloud_control_reads_nothing(
        self, wired, caplog
    ) -> None:  # noqa: ANN001
        """MikroTik and Omada never resolve a control target, so they never read."""
        wired["target"] = None
        caplog.set_level(logging.INFO)
        result = await check.check_disconnected_client(
            None,
            organization_id=ORG,
            router_id=ROUTER,
            mac=MAC,
            phase="after_block",
            seconds_since_block=5,
            settings=_settings(),
        )
        assert result == "not_available"
        assert wired["client"].calls == []
        assert _events(caplog) == []

    async def test_only_reads(self, wired) -> None:  # noqa: ANN001
        wired["client"] = _Client(None)
        await check.check_disconnected_client(
            None,
            organization_id=ORG,
            router_id=ROUTER,
            mac=MAC,
            phase="after_block",
            seconds_since_block=5,
            settings=_settings(),
        )
        assert [c[0] for c in wired["client"].calls] == ["get_client"]


class TestChain:
    def _run(self, monkeypatch, outcome: Any, index: int) -> list[dict]:  # noqa: ANN001
        published: list[dict] = []

        async def fake_async(**_: Any) -> str:
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        monkeypatch.setattr(check, "_check_async", fake_async)
        monkeypatch.setattr(check, "run_celery_task", lambda coro: _drive(coro))
        monkeypatch.setattr(
            check.check_disconnected_client_task,
            "apply_async",
            lambda **kw: published.append(kw),
        )
        check.check_disconnected_client_task(
            organization_id=str(ORG),
            router_id=str(ROUTER),
            mac=MAC,
            blocked_at=check.time.time(),
            hold_seconds=30,
            index=index,
        )
        return published

    def test_each_step_schedules_the_next(self, monkeypatch) -> None:  # noqa: ANN001
        published = self._run(monkeypatch, "present", 0)
        assert published[0]["kwargs"]["index"] == 1
        assert 19 <= published[0]["countdown"] <= 25
        assert published[0]["retry"] is False

    def test_the_chain_survives_a_crashed_check(self, monkeypatch) -> None:  # noqa: ANN001
        assert len(self._run(monkeypatch, RuntimeError("boom"), 1)) == 1

    def test_the_last_step_ends_the_chain(self, monkeypatch) -> None:  # noqa: ANN001
        assert self._run(monkeypatch, "absent", 3) == []


def _drive(coro: Any) -> Any:
    import asyncio

    return asyncio.new_event_loop().run_until_complete(coro)


class TestScheduling:
    async def test_cap_per_site_per_hour(self, monkeypatch) -> None:  # noqa: ANN001
        published: list[dict] = []
        monkeypatch.setattr(
            check.check_disconnected_client_task,
            "apply_async",
            lambda **kw: published.append(kw),
        )
        redis = _Redis(count=0)
        settings = _settings(instant_on_disconnect_check_max_per_hour=2)
        for _ in range(3):
            await check.schedule_disconnect_checks(TARGET, MAC, redis, settings)
        assert len(published) == 2
        assert redis.expiry == [3600]
        assert published[0]["countdown"] == 5
        assert published[0]["retry"] is False

    async def test_off_switch(self, monkeypatch) -> None:  # noqa: ANN001
        published: list[dict] = []
        monkeypatch.setattr(
            check.check_disconnected_client_task,
            "apply_async",
            lambda **kw: published.append(kw),
        )
        await check.schedule_disconnect_checks(
            TARGET, MAC, _Redis(), _settings(instant_on_disconnect_check_enabled=False)
        )
        assert published == []


class TestDisconnectIsUntouched:
    @pytest.mark.parametrize("failure", ["redis", "publish", "import"])
    async def test_release_is_scheduled_and_true_returned_when_checks_fail(
        self, wired, monkeypatch, failure: str
    ) -> None:  # noqa: ANN001
        released: list[Any] = []
        redis = _Redis()
        monkeypatch.setattr(control, "_redis", lambda: redis)
        monkeypatch.setattr(control, "_schedule_release", lambda *a: released.append(a))

        async def boom(*_: Any, **__: Any) -> None:
            raise RuntimeError(failure)

        monkeypatch.setattr(check, "schedule_disconnect_checks", boom)
        ok = await control.end_nas_only_session(
            None,
            router_id=ROUTER,
            organization_id=ORG,
            client_mac=MAC,
            settings=_settings(),
        )
        assert ok is True
        assert len(released) == 1
        assert [c[0] for c in wired["client"].calls] == ["block"]

    async def test_checks_are_scheduled_after_a_new_transient_block(
        self, wired, monkeypatch
    ) -> None:  # noqa: ANN001
        scheduled: list[Any] = []
        redis = _Redis()
        monkeypatch.setattr(control, "_redis", lambda: redis)
        monkeypatch.setattr(control, "_schedule_release", lambda *a: None)

        async def record(*a: Any, **_: Any) -> None:
            scheduled.append(a)

        monkeypatch.setattr(check, "schedule_disconnect_checks", record)
        await control.end_nas_only_session(
            None,
            router_id=ROUTER,
            organization_id=ORG,
            client_mac=MAC,
            settings=_settings(),
        )
        assert len(scheduled) == 1
