"""A NAS-only guest over their data cap is cut from the worker, not from the
accounting request: rlm_rest gives that request less time than Instant On can
take, and a request that overruns gets no Accounting-Response."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.domains.guest import dependencies as guest_dependencies
from app.domains.guest import tasks as guest_tasks
from app.domains.guest.constants import GuestSessionStatus
from app.domains.policy.constants import PolicyType
from tests.unit.test_aruba_access_rules import _fixture, _PolicyLookup, _sign_in
from tests.unit.test_guest import BYTES_PER_MB
from tests.unit.test_instant_on_cloud_control import _CloudHook


class _Dispatcher:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


async def _over_cap(vendor: str = "aruba_instant_on"):  # noqa: ANN202
    fx = _fixture(
        vendor=vendor,
        policy_lookup=_PolicyLookup({PolicyType.FUP: {"daily_data_limit_mb": 10}}),
    )
    hook = _CloudHook(works=True)
    dispatcher = _Dispatcher()
    fx.guest_service.session_end_hook = hook
    fx.guest_service.nas_only_usage_cut_dispatcher = dispatcher
    result = await _sign_in(fx)
    await fx.guest_service.record_usage(
        session_id=result.session.id,
        bytes_uploaded_delta=0,
        bytes_downloaded_delta=11 * BYTES_PER_MB,
    )
    session = await fx.repository.get_session_by_id(result.session.id)
    return session, hook, dispatcher


class TestAccountingRequest:
    async def test_aruba_publishes_and_makes_no_instant_on_call(self) -> None:
        session, hook, dispatcher = await _over_cap()
        assert hook.calls == 0
        assert session.status == GuestSessionStatus.ACTIVE.value
        assert dispatcher.calls == [
            {
                "router_id": session.router_id,
                "session_id": session.id,
                "reason": "fup_data_quota_exceeded_daily",
            }
        ]

    @pytest.mark.parametrize("vendor", ["mikrotik", "omada"])
    async def test_other_vendors_never_publish_and_still_expire(
        self, vendor: str
    ) -> None:
        session, _hook, dispatcher = await _over_cap(vendor)
        assert dispatcher.calls == []
        assert session.status == GuestSessionStatus.EXPIRED.value

    def test_the_api_path_is_wired_with_the_dispatcher(self) -> None:
        import inspect

        source = inspect.getsource(guest_dependencies)
        assert "nas_only_usage_cut_dispatcher=enqueue_nas_only_usage_cut" in source


class TestEnqueue:
    @pytest.fixture
    def published(self, monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(
            guest_tasks.enforce_nas_only_usage_cut,
            "apply_async",
            lambda **kw: calls.append(kw),
        )
        return calls

    @staticmethod
    def _gate(monkeypatch: pytest.MonkeyPatch, *, open_: bool) -> None:
        from app.domains.network_integration import instant_on_control

        monkeypatch.setattr(
            instant_on_control, "cloud_control_allowed", lambda *_: open_
        )

    async def test_gate_closed_publishes_nothing(
        self, monkeypatch: pytest.MonkeyPatch, published: list[dict[str, Any]]
    ) -> None:
        self._gate(monkeypatch, open_=False)
        await guest_tasks.enqueue_nas_only_usage_cut(
            router_id=uuid.uuid4(), session_id=uuid.uuid4(), reason="r"
        )
        assert published == []

    async def test_gate_open_publishes(
        self, monkeypatch: pytest.MonkeyPatch, published: list[dict[str, Any]]
    ) -> None:
        self._gate(monkeypatch, open_=True)
        session_id = uuid.uuid4()
        await guest_tasks.enqueue_nas_only_usage_cut(
            router_id=uuid.uuid4(), session_id=session_id, reason="r"
        )
        assert published == [{"kwargs": {"session_id": str(session_id), "reason": "r"}}]

    async def test_a_broker_failure_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._gate(monkeypatch, open_=True)

        def boom(**_: Any) -> None:
            raise ConnectionError("broker down")

        monkeypatch.setattr(guest_tasks.enforce_nas_only_usage_cut, "apply_async", boom)
        await guest_tasks.enqueue_nas_only_usage_cut(
            router_id=uuid.uuid4(), session_id=uuid.uuid4(), reason="r"
        )


class _Db:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    async def __aenter__(self) -> _Db:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


class TestWorker:
    @staticmethod
    async def _run(
        monkeypatch: pytest.MonkeyPatch, hook: _CloudHook, *, end_first: bool = False
    ):  # noqa: ANN205
        fx = _fixture()
        result = await _sign_in(fx)
        if end_first:
            await fx.repository.update_session(
                result.session, {"status": GuestSessionStatus.EXPIRED.value}
            )
        db = _Db()
        monkeypatch.setattr(guest_tasks, "SessionLocal", lambda: db)
        monkeypatch.setattr(guest_tasks, "GuestRepository", lambda _: fx.repository)
        monkeypatch.setattr(guest_tasks, "_build_session_terminator", lambda *_: hook)
        outcome = await guest_tasks._enforce_nas_only_usage_cut_async(
            str(result.session.id), "data_limit_exceeded"
        )
        row = await fx.repository.get_session_by_id(result.session.id)
        return outcome, row, db

    async def test_confirmed_cut_expires_the_row(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        outcome, row, db = await self._run(monkeypatch, _CloudHook(works=True))
        assert outcome == "ended"
        assert row.status == GuestSessionStatus.EXPIRED.value
        assert row.disconnect_reason == "data_limit_exceeded"
        assert row.disconnect_enforced is True
        assert db.commits == 1

    async def test_failed_cut_leaves_the_row_active(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        outcome, row, db = await self._run(monkeypatch, _CloudHook(works=False))
        assert outcome == "not_delivered"
        assert row.status == GuestSessionStatus.ACTIVE.value
        assert row.ended_at is None
        assert db.commits == 0

    async def test_a_row_already_ended_makes_no_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hook = _CloudHook(works=True)
        outcome, _row, _db = await self._run(monkeypatch, hook, end_first=True)
        assert outcome == "not_active"
        assert hook.calls == 0
