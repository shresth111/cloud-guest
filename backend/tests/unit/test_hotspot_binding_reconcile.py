"""Taking a session bypass back off the router
(``guest.hotspot_binding_reconcile``).

The router's own script was meant to remove its ``cloudguest-authmac``
binding once a MAC is no longer on ``GET /agent/authorized-macs``, and on
most of the fleet never does. This is the platform doing it. What is pinned
here is everything that keeps a removal from being wrong:

* **parity** -- after a run the tagged rows left on the router are exactly
  the MACs the endpoint lists, for every kind of session and for Trusted
  Devices;
* **nothing untagged is touched**, and nothing is ever added;
* **the list is read again before each removal**, so a guest who signs in
  again in between is kept;
* **any doubt about the list removes nothing**;
* **the cap** on removals per run, and that hitting it is loud;
* **isolation** -- one router failing does not stop the next, and nothing
  here can fail a disconnect, a block or a dashboard edit;
* **vendor gating**, and that a router with no scheduler is reconciled too;
* **default-off** and the per-router allow-list.

What the router does with one removal (the re-check by ``.id``, the host
row) is the gateway's own test:
``vendor/wyfy-device-gateway/tests/test_mikrotik_bypass_binding_removal.py``.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from wyfy_device_gateway.mikrotik_adapter import MikroTikConnectionError

from app.core.celery_app import celery_app
from app.core.config import Settings
from app.domains.guest import hotspot_binding_events, hotspot_binding_reconcile
from app.domains.guest import tasks as guest_tasks
from app.domains.guest.constants import (
    TASK_RECONCILE_HOTSPOT_BINDINGS,
    TASK_RECONCILE_HOTSPOT_BINDINGS_FOR_SCOPE,
    TASK_RUN_HOTSPOT_BINDING_RECONCILE_SWEEP,
    GuestAuthMethod,
)
from app.domains.guest.hotspot_binding_reconcile import (
    OUTCOME_LIST_UNAVAILABLE,
    OUTCOME_RECONCILED,
    reconcile_hotspot_bindings_for_router,
)
from app.domains.guest.hotspot_gate import (
    OUTCOME_NO_CREDENTIALS,
    OUTCOME_ROUTER_NOT_FOUND,
    OUTCOME_UNSUPPORTED_VENDOR,
)
from app.domains.guest_access.enforcement import BlocklistEnforcer
from app.domains.router_agent.dependencies import AgentIdentity
from app.domains.router_agent.router import agent_authorized_macs

from .test_guest import FakeAccessControlHook, Fixture, make_fixture
from .test_mac_authorization import _create_entry, make_harness

TAG = "cloudguest-authmac"
PHONES = [f"+1555000000{i}" for i in range(1, 9)]
MACS = [f"AA:BB:CC:DD:EE:0{i}" for i in range(1, 9)]


@dataclass
class _Trusted:
    macs: list[str] = field(default_factory=list)
    raises: Exception | None = None

    async def list_active_entries_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[object]:
        if self.raises is not None:
            raise self.raises
        return [SimpleNamespace(mac_address=mac) for mac in self.macs]


@dataclass
class _Device:
    """A router's ip-binding table. ``read`` shows only rows tagged exactly,
    as the gateway does; ``remove`` takes one row away by id."""

    rows: list[dict[str, str]] = field(default_factory=list)
    scheduler_enabled: bool = True
    read_raises: Exception | None = None
    reads: int = 0
    removals: list[str] = field(default_factory=list)
    #: Called with the id about to be removed, after the caller's re-check.
    after_remove: Callable[[str], Any] | None = None
    drop_host_seen: list[bool] = field(default_factory=list)

    def bind(self, mac: str, comment: str = TAG) -> str:
        row_id = f"*{len(self.rows) + 1}"
        self.rows.append({".id": row_id, "mac": mac, "comment": comment})
        return row_id

    def tagged_macs(self) -> list[str]:
        return sorted(r["mac"] for r in self.rows if r["comment"] == TAG)

    async def read_hotspot_bypass_bindings(self, creds: Any):
        self.reads += 1
        if self.read_raises is not None:
            raise self.read_raises
        return SimpleNamespace(
            hotspot_servers=1,
            reconciler_enabled=self.scheduler_enabled,
            unreadable=0,
            bindings=tuple(
                SimpleNamespace(
                    binding_id=r[".id"], mac_address=r["mac"], disabled=False
                )
                for r in self.rows
                if r["comment"] == TAG
            ),
        )

    async def remove_hotspot_bypass_binding(
        self,
        creds: Any,
        *,
        binding_id: str,
        mac_address: str,
        drop_bypassed_host: bool = True,
    ):
        self.drop_host_seen.append(drop_bypassed_host)
        row = next((r for r in self.rows if r[".id"] == binding_id), None)
        if row is None:
            return SimpleNamespace(removed=False, outcome="gone", hosts_removed=0)
        assert row["comment"] == TAG and row["mac"] == mac_address
        self.rows.remove(row)
        self.removals.append(binding_id)
        if self.after_remove is not None:
            await self.after_remove(binding_id)
        return SimpleNamespace(
            removed=True,
            outcome="removed",
            hosts_removed=1,
            host_before="bypassed",
            host_after="bypassed",
        )


def _fixture(**kwargs: Any) -> tuple[Fixture, FakeAccessControlHook]:
    hook = FakeAccessControlHook()
    fx = make_fixture(access_control_hook=hook, **kwargs)
    fx.router.management_ip_address = "10.20.0.99"
    fx.router.api_username = "wyfy-api"
    fx.router.api_credentials_encrypted = "ciphertext"
    return fx, hook


async def _login(fx: Fixture, n: int, *, mac: str | None = None):
    return await fx.guest_service.login_via_otp(
        identifier=PHONES[n],
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac or MACS[n],
    )


async def _noop_sleep(seconds: float) -> None:
    return None


async def _run(
    fx: Fixture,
    hook: object,
    device: _Device,
    *,
    trusted: _Trusted | None = None,
    max_removals: int = 20,
    router_id: uuid.UUID | None = None,
    **kwargs: Any,
):
    kwargs.setdefault("sleep", _noop_sleep)
    kwargs.setdefault("grace_seconds", 0)
    return await reconcile_hotspot_bindings_for_router(
        router_id=router_id or fx.router.id,
        guest_repository=fx.repository,
        mac_authorization_service=trusted or _Trusted(),
        access_decision_service=hook,
        captive_portal_service=fx.captive_portal_service,
        router_lookup=fx.router_service,
        adapter=device,
        max_removals=max_removals,
        **kwargs,
    )


async def _endpoint(fx: Fixture, hook: object, trusted: _Trusted) -> list[str]:
    response = await agent_authorized_macs(
        identity=AgentIdentity(router=fx.router, credential=None),  # type: ignore[arg-type]
        guest_repository=fx.repository,
        mac_authorization_service=trusted,  # type: ignore[arg-type]
        access_decision_service=hook,  # type: ignore[arg-type]
        captive_portal_service=fx.captive_portal_service,  # type: ignore[arg-type]
    )
    return response.mac_addresses


# ============================================================================
# What is removed is exactly what the endpoint no longer lists
# ============================================================================


class TestParityWithTheAuthorizedList:
    async def test_what_is_left_on_the_router_is_what_the_endpoint_lists(self) -> None:
        """One venue with every kind of case at once."""
        fx, hook = _fixture()
        device = _Device()
        active = await _login(fx, 0)
        ended = await _login(fx, 1)
        blocked_guest = await _login(fx, 2)
        blocked_device = await _login(fx, 3)
        del active, blocked_guest, blocked_device
        await fx.guest_service.disconnect_session(session_id=ended.session.id)
        hook.deny(identifier=PHONES[2])
        hook.deny(mac_address=MACS[3])
        trusted = _Trusted(macs=["aa-bb-cc-dd-ee-05"])
        for mac in (*MACS[:5], MACS[6]):  # MACS[6] was never signed in at all
            device.bind(mac)

        result = await _run(fx, hook, device, trusted=trusted)

        assert device.tagged_macs() == await _endpoint(fx, hook, trusted)
        assert device.tagged_macs() == [MACS[0], MACS[4]]
        assert result.outcome == OUTCOME_RECONCILED
        assert (result.tagged, result.stale, result.removed) == (6, 4, 4)

    async def test_a_session_awaiting_its_required_name_loses_a_leftover_bypass(
        self,
    ) -> None:
        fx, hook = _fixture(require_guest_name=True)
        device = _Device()
        login = await _login(fx, 0)
        assert login.name_required
        device.bind(MACS[0])

        await _run(fx, hook, device)
        assert device.tagged_macs() == [] == await _endpoint(fx, hook, _Trusted())

        await fx.guest_service.submit_sign_in_name(
            guest_id=login.guest.id, session_id=login.session.id, display_name="Asha"
        )
        device.bind(MACS[0])
        await _run(fx, hook, device)
        assert device.tagged_macs() == [MACS[0]]

    async def test_a_listed_mac_is_matched_whatever_spelling_was_recorded(
        self,
    ) -> None:
        fx, hook = _fixture()
        device = _Device()
        await _login(fx, 0, mac="aa-bb-cc-dd-ee-01")
        device.bind(MACS[0])
        result = await _run(fx, hook, device)
        assert result.removed == 0 and device.tagged_macs() == [MACS[0]]

    async def test_a_deleted_trusted_device_loses_its_bypass(self) -> None:
        """The case seen on hardware: entries deleted in the dashboard, their
        bindings still on the router hours later."""
        fx, hook = _fixture()
        device = _Device()
        device.bind(MACS[0])
        device.bind(MACS[1])
        trusted = _Trusted(macs=[MACS[0], MACS[1]])
        assert (await _run(fx, hook, device, trusted=trusted)).removed == 0

        trusted.macs.remove(MACS[1])
        result = await _run(fx, hook, device, trusted=trusted)

        assert result.removed == 1 and device.tagged_macs() == [MACS[0]]

    async def test_nobody_signed_in_is_an_answer_and_clears_the_router(self) -> None:
        """An EMPTY list is legitimate -- unlike a list that could not be
        built -- and must run the removal, or the last guest to leave a
        venue keeps their bypass for good."""
        fx, hook = _fixture()
        device = _Device()
        device.bind(MACS[0])
        device.bind(MACS[1])
        result = await _run(fx, hook, device)
        assert result.removed == 2 and device.tagged_macs() == []


# ============================================================================
# Rows that are not this platform's; and nothing is ever added
# ============================================================================


class TestOnlyItsOwnRows:
    async def test_untagged_rows_for_an_unlisted_mac_are_never_touched(self) -> None:
        fx, hook = _fixture()
        device = _Device()
        others = [
            device.bind(MACS[0], "venue AP"),
            device.bind(MACS[0], ""),
            device.bind(MACS[0], "cloudguest-trusted:x"),
            device.bind(MACS[0], "cloudguest-devblock:abc"),
            device.bind(MACS[0], "cloudguest-authmac-old"),
        ]
        ours = device.bind(MACS[0])

        result = await _run(fx, hook, device)

        assert device.removals == [ours] and result.removed == 1
        assert [r[".id"] for r in device.rows] == others

    async def test_a_listed_mac_with_no_binding_is_not_given_one(self) -> None:
        fx, hook = _fixture()
        device = _Device()
        await _login(fx, 0)
        result = await _run(fx, hook, device)
        assert device.rows == [] and result.tagged == 0

    async def test_the_remover_has_no_way_to_add(self) -> None:
        """Adding stays with the router's scheduler and the sign-in push."""
        assert not hasattr(_Device, "ensure_hotspot_bypass_binding")
        source = hotspot_binding_reconcile.__dict__
        assert "open_hotspot_gate_for_session" not in source
        import inspect

        body = inspect.getsource(reconcile_hotspot_bindings_for_router)
        assert "ensure_hotspot_bypass_binding" not in body and ".add(" not in body


# ============================================================================
# A guest who signs in again must not be dropped
# ============================================================================


class TestTheListIsReadAgainBeforeEachRemoval:
    async def test_a_guest_who_signs_in_again_during_the_grace_is_kept(self) -> None:
        fx, hook = _fixture()
        device = _Device()
        first = await _login(fx, 0)
        await fx.guest_service.disconnect_session(session_id=first.session.id)
        device.bind(MACS[0])
        slept: list[float] = []

        async def _sign_in_again(seconds: float) -> None:
            slept.append(seconds)
            await _login(fx, 0)

        result = await _run(fx, hook, device, sleep=_sign_in_again, grace_seconds=3)

        assert slept == [3]
        assert (result.stale, result.relisted, result.removed) == (1, 1, 0)
        assert device.tagged_macs() == [MACS[0]] and device.removals == []

    async def test_each_removal_gets_its_own_fresh_read(self) -> None:
        """Two stale rows; the second guest signs in again while the first
        row is being removed. One read for the whole batch would drop them."""
        fx, hook = _fixture()
        device = _Device()
        for n in (0, 1):
            login = await _login(fx, n)
            await fx.guest_service.disconnect_session(session_id=login.session.id)
            device.bind(MACS[n])

        async def _second_guest_returns(binding_id: str) -> None:
            await _login(fx, 1)

        device.after_remove = _second_guest_returns
        refreshed: list[int] = []

        result = await _run(fx, hook, device, refresh=lambda: refreshed.append(1))

        assert (result.removed, result.relisted) == (1, 1)
        assert device.tagged_macs() == [MACS[1]]
        # The ORM is told to forget what it loaded before every re-read.
        assert len(refreshed) == 2

    async def test_no_grace_is_slept_when_there_is_nothing_to_remove(self) -> None:
        fx, hook = _fixture()
        device = _Device()
        await _login(fx, 0)
        device.bind(MACS[0])
        slept: list[float] = []

        async def _sleep(seconds: float) -> None:
            slept.append(seconds)

        await _run(fx, hook, device, sleep=_sleep, grace_seconds=3)
        assert slept == []


# ============================================================================
# Any doubt about the list removes nothing
# ============================================================================


class TestDoubtRemovesNothing:
    async def test_a_list_that_cannot_be_built_never_reaches_the_router(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        fx, hook = _fixture()
        device = _Device()
        device.bind(MACS[0])
        trusted = _Trusted(raises=RuntimeError("connection reset"))

        with caplog.at_level("WARNING"):
            result = await _run(fx, hook, device, trusted=trusted)

        assert result.outcome == OUTCOME_LIST_UNAVAILABLE
        assert device.reads == 0 and device.removals == []
        assert device.tagged_macs() == [MACS[0]]
        assert "guest_hotspot_binding_reconcile_list_unavailable" in caplog.text

    async def test_a_session_query_that_fails_never_reaches_the_router(self) -> None:
        fx, hook = _fixture()
        device = _Device()
        device.bind(MACS[0])
        with patch.object(
            fx.repository,
            "list_active_sessions_for_router",
            AsyncMock(side_effect=RuntimeError("db down")),
        ):
            result = await _run(fx, hook, device)
        assert result.outcome == OUTCOME_LIST_UNAVAILABLE and device.reads == 0

    async def test_a_list_that_fails_part_way_stops_the_run_there(self) -> None:
        fx, hook = _fixture()
        device = _Device()
        for mac in MACS[:3]:
            device.bind(mac)
        trusted = _Trusted()

        async def _then_break(binding_id: str) -> None:
            trusted.raises = RuntimeError("db down")

        device.after_remove = _then_break

        result = await _run(fx, hook, device, trusted=trusted)

        assert result.aborted and result.removed == 1
        assert device.tagged_macs() == MACS[1:3]

    async def test_a_blocklist_lookup_that_fails_keeps_the_guest(self) -> None:
        """Inside the list, a lookup that fails errs towards listing."""
        fx, hook = _fixture()
        device = _Device()
        await _login(fx, 0)
        device.bind(MACS[0])
        hook.raises = RuntimeError("rule lookup unavailable")
        result = await _run(fx, hook, device)
        assert result.removed == 0 and device.tagged_macs() == [MACS[0]]


# ============================================================================
# The cap
# ============================================================================


class TestCap:
    async def test_no_more_than_the_cap_is_removed_and_it_is_loud(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        fx, hook = _fixture()
        device = _Device()
        for mac in MACS[:5]:
            device.bind(mac)

        with caplog.at_level("ERROR"):
            result = await _run(fx, hook, device, max_removals=2)

        assert (result.stale, result.removed, result.deferred) == (5, 2, 3)
        assert len(device.tagged_macs()) == 3
        hit = [
            r for r in caplog.records
            if r.msg == "guest_hotspot_binding_reconcile_cap_hit"
        ]
        assert len(hit) == 1 and hit[0].levelname == "ERROR"
        assert (hit[0].stale, hit[0].cap) == (5, 2)

    async def test_the_next_run_takes_the_rest(self) -> None:
        fx, hook = _fixture()
        device = _Device()
        for mac in MACS[:5]:
            device.bind(mac)
        await _run(fx, hook, device, max_removals=3)
        result = await _run(fx, hook, device, max_removals=3)
        assert result.removed == 2 and result.deferred == 0
        assert device.tagged_macs() == []

    async def test_under_the_cap_says_nothing(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        fx, hook = _fixture()
        device = _Device()
        device.bind(MACS[0])
        with caplog.at_level("ERROR"):
            await _run(fx, hook, device, max_removals=1)
        assert "cap_hit" not in caplog.text

    async def test_a_cap_of_zero_is_a_dry_run(self) -> None:
        fx, hook = _fixture()
        device = _Device()
        device.bind(MACS[0])
        result = await _run(fx, hook, device, max_removals=0)
        assert (result.stale, result.removed, result.deferred) == (1, 0, 1)
        assert device.removals == []


# ============================================================================
# Which routers
# ============================================================================


class TestWhichRouters:
    @pytest.mark.parametrize("vendor", ["tplink_omada", "aruba_instant_on"])
    async def test_a_venue_this_platform_does_not_log_in_to_is_never_read(
        self, vendor: str
    ) -> None:
        fx, hook = _fixture()
        fx.router.vendor = vendor
        device = _Device()
        device.bind(MACS[0])
        result = await _run(fx, hook, device)
        assert result.outcome == OUTCOME_UNSUPPORTED_VENDOR
        assert device.reads == 0 and device.removals == []

    async def test_a_router_with_no_scheduler_is_reconciled_all_the_same(
        self,
    ) -> None:
        """Unlike the sign-in push, which refuses such a router. This is the
        router where nothing else would ever remove the row."""
        fx, hook = _fixture()
        device = _Device(scheduler_enabled=False)
        await _login(fx, 0)
        device.bind(MACS[0])
        device.bind(MACS[1])
        result = await _run(fx, hook, device)
        assert result.reconciler_enabled is False
        assert result.removed == 1 and device.tagged_macs() == [MACS[0]]

    async def test_no_credentials_is_not_connected_to(self) -> None:
        fx, hook = _fixture()
        fx.router.api_credentials_encrypted = None
        device = _Device()
        result = await _run(fx, hook, device)
        assert result.outcome == OUTCOME_NO_CREDENTIALS and device.reads == 0

    async def test_a_router_that_no_longer_exists_is_an_outcome(self) -> None:
        fx, hook = _fixture()
        result = await _run(fx, hook, _Device(), router_id=uuid.uuid4())
        assert result.outcome == OUTCOME_ROUTER_NOT_FOUND

    async def test_the_host_choice_is_passed_through(self) -> None:
        fx, hook = _fixture()
        device = _Device()
        device.bind(MACS[0])
        result = await _run(fx, hook, device, drop_bypassed_host=False)
        assert device.drop_host_seen == [False]
        assert result.host_transitions == ["bypassed->bypassed"]

    async def test_an_unreachable_router_raises_and_removes_nothing(self) -> None:
        fx, hook = _fixture()
        device = _Device(read_raises=MikroTikConnectionError("router", "timed out"))
        device.bind(MACS[0])
        with pytest.raises(MikroTikConnectionError):
            await _run(fx, hook, device)
        assert device.removals == []


# ============================================================================
# The worker: isolation, wiring, the sweep
# ============================================================================


def _settings(
    enabled: bool = False, *, router_ids: str = "", delay: float = 5.0, cap: int = 20
) -> SimpleNamespace:
    return SimpleNamespace(
        guest_hotspot_gate_remove_enabled=enabled,
        guest_hotspot_gate_remove_router_ids=router_ids,
        guest_hotspot_gate_remove_delay_seconds=delay,
        guest_hotspot_gate_remove_max_per_run=cap,
        guest_hotspot_gate_remove_drop_host=True,
    )


class _Session:
    def __init__(self) -> None:
        self.rollbacks = 0

    async def rollback(self) -> None:
        self.rollbacks += 1

    def expire_all(self) -> None:
        return None


class TestWorker:
    async def test_one_router_failing_does_not_stop_the_next(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        bad, good = uuid.uuid4(), uuid.uuid4()
        seen: list[uuid.UUID] = []

        async def _reconcile(*, router_id: uuid.UUID, **kwargs: Any):
            seen.append(router_id)
            if router_id == bad:
                raise MikroTikConnectionError("router", "timed out")
            return hotspot_binding_reconcile.HotspotBindingReconcileResult(
                OUTCOME_RECONCILED, tagged=2, stale=1, removed=1
            )

        session = _Session()
        with (
            patch("app.core.config.get_settings", return_value=_settings(True)),
            patch.object(
                guest_tasks, "_build_hotspot_binding_reconcile_kwargs", return_value={}
            ),
            patch.object(
                hotspot_binding_reconcile,
                "reconcile_hotspot_bindings_for_router",
                _reconcile,
            ),
            caplog.at_level("WARNING"),
        ):
            totals = await guest_tasks._reconcile_hotspot_bindings_for_routers(
                session, [bad, good], trigger="sweep"  # type: ignore[arg-type]
            )

        # Each tried exactly once, in order; the failure is counted and logged.
        assert seen == [bad, good]
        assert totals == {"routers": 2, "removed": 1, "failed": 1, "deferred": 0}
        assert session.rollbacks == 1
        assert "guest_hotspot_binding_reconcile_failed" in caplog.text

    async def test_only_routers_it_is_switched_on_for_are_run(self) -> None:
        listed, other = uuid.uuid4(), uuid.uuid4()
        seen: list[uuid.UUID] = []

        async def _reconcile(*, router_id: uuid.UUID, **kwargs: Any):
            seen.append(router_id)
            assert kwargs["max_removals"] == 7
            return hotspot_binding_reconcile.HotspotBindingReconcileResult(
                OUTCOME_RECONCILED
            )

        with (
            patch(
                "app.core.config.get_settings",
                return_value=_settings(router_ids=str(listed), cap=7),
            ),
            patch.object(
                guest_tasks, "_build_hotspot_binding_reconcile_kwargs", return_value={}
            ),
            patch.object(
                hotspot_binding_reconcile,
                "reconcile_hotspot_bindings_for_router",
                _reconcile,
            ),
        ):
            await guest_tasks._reconcile_hotspot_bindings_for_routers(
                _Session(), [other, listed], trigger="scope"  # type: ignore[arg-type]
            )
        assert seen == [listed]

    def test_trusted_devices_are_read_with_a_router_lookup(self) -> None:
        """Without one, ``list_active_entries_for_router`` answers "no
        trusted devices" -- and every trusted device's bypass, which carries
        the same tag as a guest's, would be removed."""
        session = _Session()
        kwargs = guest_tasks._build_hotspot_binding_reconcile_kwargs(session)  # type: ignore[arg-type]
        mac_service = kwargs["mac_authorization_service"]
        assert mac_service.router_lookup is not None  # type: ignore[attr-defined]
        assert mac_service.router_lookup is kwargs["router_lookup"]  # type: ignore[attr-defined]
        assert kwargs["refresh"] == session.expire_all

    async def test_the_sweep_switched_off_reads_nothing(self) -> None:
        with (
            patch("app.core.config.get_settings", return_value=_settings()),
            patch.object(
                guest_tasks, "SessionLocal", side_effect=AssertionError("no DB")
            ),
        ):
            totals = await guest_tasks._run_hotspot_binding_reconcile_sweep_async()
        assert totals == {"routers": 0, "removed": 0, "failed": 0, "deferred": 0}

    def test_it_is_scheduled_and_the_sweep_runs_on_the_device_queue(self) -> None:
        scheduled = {e["task"] for e in celery_app.conf.beat_schedule.values()}
        assert TASK_RUN_HOTSPOT_BINDING_RECONCILE_SWEEP in scheduled
        routes = celery_app.conf.task_routes
        assert TASK_RUN_HOTSPOT_BINDING_RECONCILE_SWEEP in routes
        assert TASK_RECONCILE_HOTSPOT_BINDINGS_FOR_SCOPE in routes
        # The event-driven one must not queue behind fleet polls.
        assert TASK_RECONCILE_HOTSPOT_BINDINGS not in routes


# ============================================================================
# Switched off by default; the allow-list; the enqueue
# ============================================================================


class _Redis:
    def __init__(self, *, first: bool = True, raises: Exception | None = None) -> None:
        self.first, self.raises = first, raises
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def set(self, key: str, value: str, **kwargs: Any) -> bool | None:
        self.calls.append((key, kwargs))
        if self.raises is not None:
            raise self.raises
        return True if self.first else None


class TestRollout:
    def test_it_ships_switched_off(self) -> None:
        fields = Settings.model_fields
        assert fields["guest_hotspot_gate_remove_enabled"].default is False
        assert fields["guest_hotspot_gate_remove_router_ids"].default == ""
        assert fields["guest_hotspot_gate_remove_max_per_run"].default == 20

    def test_the_two_ways_it_is_switched_on(self) -> None:
        listed, other = uuid.uuid4(), uuid.uuid4()
        applies = guest_tasks.hotspot_gate_remove_applies
        assert not applies(listed, _settings())
        assert applies(listed, _settings(True))
        only = _settings(router_ids=f" {str(listed).upper()} , junk,")
        assert applies(listed, only) and not applies(other, only)

    def test_it_is_independent_of_the_push(self) -> None:
        """Turning the sign-in push on for a router does not turn removal on."""
        router_id = uuid.uuid4()
        settings = _settings()
        settings.guest_hotspot_gate_push_enabled = True
        settings.guest_hotspot_gate_push_router_ids = str(router_id)
        assert not guest_tasks.hotspot_gate_remove_applies(router_id, settings)

    async def _enqueue(self, settings: SimpleNamespace, redis: _Redis, **kwargs: Any):
        router_id = uuid.uuid4()
        if settings.guest_hotspot_gate_remove_router_ids == "<this>":
            settings.guest_hotspot_gate_remove_router_ids = str(router_id)
        with (
            patch("app.core.config.get_settings", return_value=settings),
            patch("app.database.redis.redis_client", redis),
            patch.object(
                guest_tasks.reconcile_hotspot_bindings, "apply_async", **kwargs
            ) as publish,
        ):
            await guest_tasks.enqueue_hotspot_binding_reconcile(router_id=router_id)
        return router_id, publish

    async def test_switched_off_publishes_nothing_and_asks_redis_nothing(
        self,
    ) -> None:
        redis = _Redis()
        _, publish = await self._enqueue(_settings(), redis)
        publish.assert_not_called()
        assert redis.calls == []

    async def test_an_allow_listed_router_is_published_after_the_delay(self) -> None:
        redis = _Redis()
        router_id, publish = await self._enqueue(
            _settings(router_ids="<this>", delay=7.0), redis
        )
        publish.assert_called_once_with(
            kwargs={"router_id": str(router_id)}, countdown=7.0
        )
        key, options = redis.calls[0]
        assert str(router_id) in key and options == {"nx": True, "ex": 7}

    async def test_a_second_request_inside_the_window_publishes_nothing(
        self,
    ) -> None:
        _, publish = await self._enqueue(_settings(True), _Redis(first=False))
        publish.assert_not_called()

    async def test_redis_being_down_publishes_anyway(self) -> None:
        """A duplicate run finds nothing to do; a dropped one leaves a guest
        online."""
        _, publish = await self._enqueue(
            _settings(True), _Redis(raises=ConnectionError("redis down"))
        )
        publish.assert_called_once()

    async def test_a_broker_failure_is_swallowed(self) -> None:
        await self._enqueue(
            _settings(True), _Redis(), side_effect=ConnectionError("broker down")
        )

    async def test_the_scope_request_follows_the_same_switch(self) -> None:
        organization_id, location_id = uuid.uuid4(), uuid.uuid4()
        task = guest_tasks.reconcile_hotspot_bindings_for_scope
        with (
            patch("app.core.config.get_settings", return_value=_settings()),
            patch.object(task, "apply_async") as publish,
        ):
            await guest_tasks.enqueue_hotspot_binding_reconcile_for_scope(
                organization_id=organization_id, location_id=location_id
            )
            publish.assert_not_called()
        with (
            patch(
                "app.core.config.get_settings",
                return_value=_settings(router_ids=str(uuid.uuid4())),
            ),
            patch.object(task, "apply_async") as publish,
        ):
            await guest_tasks.enqueue_hotspot_binding_reconcile_for_scope(
                organization_id=organization_id, location_id=None
            )
            publish.assert_called_once_with(
                kwargs={"organization_id": str(organization_id), "location_id": None},
                countdown=5.0,
            )


# ============================================================================
# The triggers -- and that none of them can fail what triggered it
# ============================================================================


class TestTriggers:
    async def test_a_dashboard_disconnect_asks_for_that_router(self) -> None:
        fx, _ = _fixture()
        login = await _login(fx, 0)
        with patch(
            "app.domains.guest.service.request_hotspot_binding_reconcile", AsyncMock()
        ) as request:
            await fx.guest_service.disconnect_session(
                session_id=login.session.id, actor_user_id=uuid.uuid4()
            )
        request.assert_awaited_once_with(fx.router.id)

    async def test_a_termination_asks_too(self) -> None:
        fx, _ = _fixture()
        login = await _login(fx, 0)
        with patch(
            "app.domains.guest.service.request_hotspot_binding_reconcile", AsyncMock()
        ) as request:
            await fx.guest_service.terminate_session(
                session_id=login.session.id, actor_user_id=uuid.uuid4()
            )
        request.assert_awaited_once_with(fx.router.id)

    async def test_a_session_the_nas_itself_ended_asks_too(self) -> None:
        """RADIUS Accounting-Stop skips the device call, not this: the
        binding is a different object from the live session."""
        fx, _ = _fixture()
        login = await _login(fx, 0)
        with patch(
            "app.domains.guest.service.request_hotspot_binding_reconcile", AsyncMock()
        ) as request:
            await fx.guest_service.disconnect_session(
                session_id=login.session.id, already_ended_on_device=True
            )
        request.assert_awaited_once_with(fx.router.id)

    async def test_a_block_asks_for_each_router_it_ended_a_session_on(self) -> None:
        routers = {uuid.uuid4(), uuid.uuid4()}
        with patch.object(
            hotspot_binding_events, "request_hotspot_binding_reconcile", AsyncMock()
        ) as request:
            await BlocklistEnforcer._request_binding_reconcile(routers)
        assert {call.args[0] for call in request.await_args_list} == routers
        import inspect

        assert "_request_binding_reconcile(contacted_routers)" in inspect.getsource(
            BlocklistEnforcer.enforce
        )

    async def test_deleting_a_trusted_device_asks_for_its_scope(self) -> None:
        h = make_harness()
        organization_id = uuid.uuid4()
        entry = await _create_entry(h, organization_id)
        with patch.object(
            hotspot_binding_events,
            "request_hotspot_binding_reconcile_for_scope",
            AsyncMock(),
        ) as request:
            await h.service.delete_entry(
                entry.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=organization_id,
            )
        request.assert_awaited_once_with(
            organization_id=organization_id, location_id=entry.location_id
        )

    async def test_disabling_a_trusted_device_asks_for_its_scope(self) -> None:
        h = make_harness()
        organization_id = uuid.uuid4()
        entry = await _create_entry(h, organization_id)
        with patch.object(
            hotspot_binding_events,
            "request_hotspot_binding_reconcile_for_scope",
            AsyncMock(),
        ) as request:
            await h.service.update_entry(
                entry.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=organization_id,
                is_enabled=False,
            )
        request.assert_awaited_once_with(
            organization_id=organization_id, location_id=entry.location_id
        )

    async def test_a_request_that_blows_up_fails_nothing(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        boom = AsyncMock(side_effect=RuntimeError("anything at all"))
        with (
            patch.object(guest_tasks, "enqueue_hotspot_binding_reconcile", boom),
            patch.object(
                guest_tasks, "enqueue_hotspot_binding_reconcile_for_scope", boom
            ),
            caplog.at_level("WARNING"),
        ):
            await hotspot_binding_events.request_hotspot_binding_reconcile(uuid.uuid4())
            await hotspot_binding_events.request_hotspot_binding_reconcile_for_scope(
                organization_id=uuid.uuid4(), location_id=None
            )
        assert boom.await_count == 2
        assert caplog.text.count("guest_hotspot_binding_reconcile_request_failed") == 2

    async def test_a_session_with_no_router_asks_for_nothing(self) -> None:
        with patch.object(
            guest_tasks, "enqueue_hotspot_binding_reconcile", AsyncMock()
        ) as enqueue:
            await hotspot_binding_events.request_hotspot_binding_reconcile(None)
        enqueue.assert_not_awaited()

    async def test_a_disconnect_still_succeeds_with_the_real_request_path(
        self,
    ) -> None:
        """Nothing patched but the settings: the real lazy import, the real
        gate, switched off -- and the disconnect is unaffected."""
        fx, _ = _fixture()
        login = await _login(fx, 0)
        with patch("app.core.config.get_settings", return_value=_settings()):
            ended = await fx.guest_service.disconnect_session(
                session_id=login.session.id
            )
        assert ended.status == "disconnected"
