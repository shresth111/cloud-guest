"""Opening the router's hotspot gate at sign-in (``guest.hotspot_gate``).

The router's own ``cloudguest-authmac-sched`` stays the reconciler: once a
minute it adds a ``type=bypassed`` binding for every MAC that
``GET /agent/authorized-macs`` lists and removes its own binding for every
MAC that is no longer listed. The sign-in push writes one of those rows
early. So the properties pinned here are the ones that keep the two from
disagreeing, and the ones that keep a router out of the login:

* **parity** -- the push admits a session exactly when the list carries a
  MAC because of that session, and under the same spelling;
* **vendor gating** -- nothing is enqueued, and nothing is written, for a
  venue this platform does not log in to;
* **failure isolation** -- a dispatcher, a broker or a router that fails
  does not fail a login, and the task gives up rather than raising;
* **never ahead of the browser** -- a task that starts sooner than the
  configured delay after the *latest* request for its session touches
  nothing and re-schedules itself, and a Redis that cannot be asked changes
  nothing at all;
* **a device an admin has just trusted** gets the same row by the same
  rules, on the routers its entry applies at and nowhere else.

What the router itself does with the row (idempotence, rows that are not
ours, the missing scheduler) is the gateway's own test:
``vendor/wyfy-device-gateway/tests/test_mikrotik_bypass_binding.py``.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from celery.exceptions import Retry
from wyfy_device_gateway.mikrotik_adapter import MikroTikConnectionError

from app.core.celery_app import celery_app
from app.domains.guest import hotspot_binding_events, hotspot_gate
from app.domains.guest import tasks as guest_tasks
from app.domains.guest.constants import (
    OPEN_HOTSPOT_GATE_MAX_RETRIES,
    TASK_OPEN_HOTSPOT_GATE_FOR_TRUSTED_DEVICE,
    TRUSTED_DEVICE_HOTSPOT_GATE_DELAY_SECONDS,
    GuestAuthMethod,
)
from app.domains.guest.hotspot_gate import (
    OUTCOME_HELD,
    OUTCOME_NO_CREDENTIALS,
    OUTCOME_ROUTER_NOT_FOUND,
    OUTCOME_UNSUPPORTED_VENDOR,
    HotspotGateResult,
    open_hotspot_gate_for_session,
    open_hotspot_gate_for_trusted_entry,
)
from app.domains.mac_authorization.service import MacAuthorizationService
from app.domains.router_agent.authorized_macs import (
    SessionGateReason,
    list_authorized_macs,
    resolve_session_gate,
)
from app.domains.router_agent.dependencies import AgentIdentity
from app.domains.router_agent.router import agent_authorized_macs

from .test_guest import FakeAccessControlHook, Fixture, make_fixture
from .test_mac_authorization import FakeMacAuthorizationRepository, make_harness

PHONE = "+15550000001"
MAC = "AA:BB:CC:DD:EE:01"
TRUSTED_MAC = "AA:BB:CC:00:00:01"


@dataclass
class _Redis:
    """Stand-in for both Redis clients the hold uses: the request side's
    shared one (``set``) and the worker's fresh one (``get``/``aclose``)."""

    value: str | None = None
    raises: Exception | None = None
    sets: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    gets: list[str] = field(default_factory=list)
    closed: int = 0

    async def set(self, key: str, value: str, **kwargs: Any) -> bool:
        if self.raises is not None:
            raise self.raises
        self.sets.append((key, value, kwargs))
        return True

    async def get(self, key: str) -> str | None:
        self.gets.append(key)
        if self.raises is not None:
            raise self.raises
        return self.value

    async def aclose(self) -> None:
        self.closed += 1


@pytest.fixture(autouse=True)
def redis() -> Any:
    """No test here talks to a real Redis: the request side records the
    "not before" instant on this fake unless a test swaps in its own."""
    fake = _Redis()
    with patch("app.database.redis.redis_client", fake):
        yield fake


@dataclass
class _Trusted:
    macs: list[str] = field(default_factory=list)

    async def list_active_entries_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[object]:
        return [SimpleNamespace(mac_address=mac) for mac in self.macs]


@dataclass
class _Dispatcher:
    calls: list[dict[str, uuid.UUID]] = field(default_factory=list)
    raises: Exception | None = None

    async def __call__(self, *, router_id: uuid.UUID, session_id: uuid.UUID) -> None:
        self.calls.append({"router_id": router_id, "session_id": session_id})
        if self.raises is not None:
            raise self.raises


@dataclass
class _Writer:
    """Stand-in for the gateway adapter: records the one call it may get."""

    outcome: str = "created"
    raises: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def ensure_hotspot_bypass_binding(self, creds: Any, *, mac_address: str):
        self.calls.append({"creds": creds, "mac_address": mac_address})
        if self.raises is not None:
            raise self.raises
        return SimpleNamespace(
            outcome=self.outcome,
            created=self.outcome == "created",
            host_state="absent" if self.outcome == "created" else None,
            existing_bindings=(),
        )


def _fixture(**kwargs: Any) -> tuple[Fixture, FakeAccessControlHook]:
    hook = FakeAccessControlHook()
    fx = make_fixture(access_control_hook=hook, **kwargs)
    # A router this platform can log in to.
    fx.router.management_ip_address = "10.20.0.99"
    fx.router.api_username = "wyfy-api"
    fx.router.api_credentials_encrypted = "ciphertext"
    return fx, hook


async def _login(fx: Fixture, identifier: str = PHONE, mac: str | None = MAC):
    return await fx.guest_service.login_via_otp(
        identifier=identifier,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
    )


def _deps(fx: Fixture, hook: object) -> dict[str, Any]:
    return {
        "guest_repository": fx.repository,
        "access_decision_service": hook,
        "captive_portal_service": fx.captive_portal_service,
    }


async def _listed(fx: Fixture, hook: object, trusted: _Trusted | None = None):
    return await list_authorized_macs(
        fx.router.id, mac_authorization_service=trusted or _Trusted(), **_deps(fx, hook)
    )


async def _gate(fx: Fixture, hook: object, session_id: uuid.UUID):
    return await resolve_session_gate(session_id, fx.router.id, **_deps(fx, hook))


async def _open(fx: Fixture, hook: object, session_id: uuid.UUID, writer: _Writer):
    return await open_hotspot_gate_for_session(
        session_id=session_id,
        router_id=fx.router.id,
        router_lookup=fx.router_service,
        adapter=writer,
        **_deps(fx, hook),
    )


# ============================================================================
# Parity with GET /agent/authorized-macs
# ============================================================================


class TestEligibilityIsTheListsOwn:
    async def _assert_parity(
        self, fx: Fixture, hook: object, session_id: uuid.UUID, *, expect: str | None
    ) -> None:
        """The push admits ``session_id`` iff the list (with no trusted
        devices, so that only sessions can put a MAC on it) carries a MAC,
        and then it is the same string."""
        decision = await _gate(fx, hook, session_id)
        listed = await _listed(fx, hook)
        if expect is None:
            assert not decision.authorized and decision.mac_address is None
            assert listed.mac_addresses == ()
        else:
            assert decision.authorized and decision.mac_address == expect
            assert listed.mac_addresses == (expect,)

    async def test_an_active_session_is_admitted_under_the_lists_spelling(
        self,
    ) -> None:
        fx, hook = _fixture()
        login = await _login(fx, mac="aa-bb-cc-dd-ee-01")
        await self._assert_parity(fx, hook, login.session.id, expect=MAC)

    async def test_the_endpoint_returns_what_the_shared_function_lists(self) -> None:
        fx, hook = _fixture()
        await _login(fx)
        await _login(fx, "+15550000002", "aa:bb:cc:dd:ee:02")
        response = await agent_authorized_macs(
            identity=AgentIdentity(router=fx.router, credential=None),  # type: ignore[arg-type]
            mac_authorization_service=_Trusted(macs=["AA-BB-CC-DD-EE-03"]),  # type: ignore[arg-type]
            **_deps(fx, hook),
        )
        listed = await _listed(fx, hook, _Trusted(macs=["AA-BB-CC-DD-EE-03"]))
        assert response.mac_addresses == list(listed.mac_addresses)
        assert response.mac_addresses == [MAC, "AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"]

    async def test_a_blocklisted_guest_is_refused_by_both(self) -> None:
        fx, hook = _fixture()
        login = await _login(fx)
        hook.deny(identifier=PHONE)
        await self._assert_parity(fx, hook, login.session.id, expect=None)
        assert (await _gate(fx, hook, login.session.id)).reason is (
            SessionGateReason.BLOCKLISTED
        )

    async def test_a_blocklisted_device_is_refused_by_both(self) -> None:
        fx, hook = _fixture()
        login = await _login(fx)
        hook.deny(mac_address=MAC)
        await self._assert_parity(fx, hook, login.session.id, expect=None)

    async def test_a_session_awaiting_its_required_name_is_refused_by_both(
        self,
    ) -> None:
        fx, hook = _fixture(require_guest_name=True)
        login = await _login(fx)
        assert login.name_required
        await self._assert_parity(fx, hook, login.session.id, expect=None)
        assert (await _gate(fx, hook, login.session.id)).reason is (
            SessionGateReason.AWAITING_NAME
        )

        await fx.guest_service.submit_sign_in_name(
            guest_id=login.guest.id, session_id=login.session.id, display_name="Asha"
        )
        await self._assert_parity(fx, hook, login.session.id, expect=MAC)

    async def test_a_session_with_no_device_is_refused_by_both(self) -> None:
        fx, hook = _fixture()
        login = await _login(fx, mac=None)
        await self._assert_parity(fx, hook, login.session.id, expect=None)
        assert (await _gate(fx, hook, login.session.id)).reason is (
            SessionGateReason.NO_DEVICE
        )

    async def test_a_recorded_value_that_is_not_a_mac_is_refused_by_both(
        self,
    ) -> None:
        fx, hook = _fixture()
        login = await _login(fx, mac="not-a-mac")
        await self._assert_parity(fx, hook, login.session.id, expect=None)
        assert (await _gate(fx, hook, login.session.id)).reason is (
            SessionGateReason.MALFORMED_MAC
        )
        assert (await _listed(fx, hook)).dropped == 1

    async def test_an_ended_session_is_not_listed_by_either(self) -> None:
        fx, hook = _fixture()
        login = await _login(fx)
        await fx.guest_service.disconnect_session(session_id=login.session.id)
        await self._assert_parity(fx, hook, login.session.id, expect=None)
        assert (await _gate(fx, hook, login.session.id)).reason is (
            SessionGateReason.NOT_LISTED
        )

    async def test_a_session_on_another_router_is_not_this_routers(self) -> None:
        fx, hook = _fixture()
        login = await _login(fx)
        decision = await resolve_session_gate(
            login.session.id, uuid.uuid4(), **_deps(fx, hook)
        )
        assert decision.reason is SessionGateReason.NOT_LISTED

    async def test_a_session_that_does_not_exist_yet_is_not_listed(self) -> None:
        """The sign-in request's commit may not have landed when the worker
        looks. That is ``NOT_LISTED`` -- the one answer the task retries."""
        fx, hook = _fixture()
        decision = await _gate(fx, hook, uuid.uuid4())
        assert decision.reason is SessionGateReason.NOT_LISTED

    async def test_a_trusted_device_does_not_admit_a_refused_session(self) -> None:
        """The list is a union with Trusted Devices. The push answers for the
        session only: a held session is not pushed just because an admin
        trusted the same device -- the router's poll still lists it."""
        fx, hook = _fixture()
        login = await _login(fx)
        hook.deny(identifier=PHONE)
        listed = await _listed(fx, hook, _Trusted(macs=[MAC]))
        assert listed.mac_addresses == (MAC,)
        assert not (await _gate(fx, hook, login.session.id)).authorized


# ============================================================================
# One attempt: who reaches the router, and with what
# ============================================================================


class TestOneAttempt:
    async def test_an_admitted_session_writes_its_canonical_mac(self) -> None:
        fx, hook = _fixture()
        login = await _login(fx, mac="aa-bb-cc-dd-ee-01")
        writer = _Writer()

        result = await _open(fx, hook, login.session.id, writer)

        assert result == HotspotGateResult("created", wrote=True, host_state="absent")
        assert len(writer.calls) == 1
        call = writer.calls[0]
        assert call["mac_address"] == MAC
        assert call["creds"].host == "10.20.0.99"
        assert call["creds"].username == "wyfy-api"
        assert call["creds"].timeout_seconds <= 5

    @pytest.mark.parametrize(
        "outcome",
        ["already_bound", "active_session", "no_hotspot", "no_reconciler", "raced"],
    )
    async def test_a_router_that_declines_is_reported_not_retried(
        self, outcome: str
    ) -> None:
        fx, hook = _fixture()
        login = await _login(fx)
        result = await _open(fx, hook, login.session.id, _Writer(outcome=outcome))
        assert result.outcome == outcome
        assert not result.wrote and not result.retry

    @pytest.mark.parametrize("vendor", ["tplink_omada", "aruba_instant_on"])
    async def test_a_venue_this_platform_does_not_log_in_to_is_never_written(
        self, vendor: str
    ) -> None:
        fx, hook = _fixture()
        login = await _login(fx)
        fx.router.vendor = vendor
        writer = _Writer()

        result = await _open(fx, hook, login.session.id, writer)

        assert result.outcome == OUTCOME_UNSUPPORTED_VENDOR
        assert writer.calls == []

    @pytest.mark.parametrize(
        "refuse",
        ["blocklisted", "awaiting_name", "ended", "no_device"],
    )
    async def test_a_session_the_list_leaves_out_never_reaches_the_router(
        self, refuse: str
    ) -> None:
        fx, hook = _fixture(require_guest_name=refuse == "awaiting_name")
        login = await _login(fx, mac=None if refuse == "no_device" else MAC)
        if refuse == "blocklisted":
            hook.deny(identifier=PHONE)
        if refuse == "ended":
            await fx.guest_service.disconnect_session(session_id=login.session.id)
        writer = _Writer()

        result = await _open(fx, hook, login.session.id, writer)

        assert writer.calls == []
        assert not result.wrote
        # Only "not among the router's active sessions" is worth a retry.
        assert result.retry is (refuse == "ended")

    async def test_a_session_blocked_after_sign_in_is_refused_at_write_time(
        self,
    ) -> None:
        """Eligibility is asked in the worker, immediately before the write
        -- never carried over from the login request."""
        fx, hook = _fixture()
        login = await _login(fx)
        hook.deny(mac_address=MAC)
        writer = _Writer()
        result = await _open(fx, hook, login.session.id, writer)
        assert result.outcome == "blocklisted" and writer.calls == []

    async def test_a_router_with_no_credentials_is_not_connected_to(self) -> None:
        fx, hook = _fixture()
        login = await _login(fx)
        fx.router.api_credentials_encrypted = None
        writer = _Writer()
        result = await _open(fx, hook, login.session.id, writer)
        assert result.outcome == OUTCOME_NO_CREDENTIALS and writer.calls == []

    async def test_a_router_that_no_longer_exists_is_an_outcome(self) -> None:
        fx, hook = _fixture()
        result = await open_hotspot_gate_for_session(
            session_id=uuid.uuid4(),
            router_id=uuid.uuid4(),
            router_lookup=fx.router_service,
            adapter=_Writer(),
            **_deps(fx, hook),
        )
        assert result.outcome == OUTCOME_ROUTER_NOT_FOUND


# ============================================================================
# The login itself
# ============================================================================


class TestLoginDispatch:
    async def test_a_login_asks_for_the_gate_with_two_ids_and_nothing_else(
        self,
    ) -> None:
        fx, _ = _fixture()
        fx.guest_service.hotspot_gate_dispatcher = dispatcher = _Dispatcher()
        login = await _login(fx)
        assert dispatcher.calls == [
            {"router_id": fx.router.id, "session_id": login.session.id}
        ]

    async def test_a_repeat_login_on_a_reused_session_asks_again(self) -> None:
        fx, _ = _fixture()
        fx.guest_service.hotspot_gate_dispatcher = dispatcher = _Dispatcher()
        first = await _login(fx)
        second = await _login(fx)
        assert second.session.id == first.session.id
        assert len(dispatcher.calls) == 2

    @pytest.mark.parametrize("vendor", ["tplink_omada", "aruba_instant_on"])
    async def test_a_controller_or_nas_only_venue_enqueues_nothing(
        self, vendor: str
    ) -> None:
        fx, _ = _fixture()
        fx.router.vendor = vendor
        fx.guest_service.hotspot_gate_dispatcher = dispatcher = _Dispatcher()
        await _login(fx)
        assert dispatcher.calls == []

    async def test_a_login_with_no_device_mac_enqueues_nothing(self) -> None:
        fx, _ = _fixture()
        fx.guest_service.hotspot_gate_dispatcher = dispatcher = _Dispatcher()
        await _login(fx, mac=None)
        assert dispatcher.calls == []

    async def test_a_dispatcher_that_raises_does_not_fail_the_login(self) -> None:
        fx, _ = _fixture()
        fx.guest_service.hotspot_gate_dispatcher = _Dispatcher(
            raises=RuntimeError("broker down")
        )
        login = await _login(fx)
        assert login.session.status == "active"

    async def test_no_dispatcher_wired_is_a_no_op(self) -> None:
        fx, _ = _fixture()
        assert fx.guest_service.hotspot_gate_dispatcher is None
        assert (await _login(fx)).session is not None

    async def test_giving_the_required_name_asks_for_the_gate_again(self) -> None:
        """The login's own request was refused in the worker for want of a
        name; storing the name is the moment the answer changes."""
        fx, _ = _fixture(require_guest_name=True)
        fx.guest_service.hotspot_gate_dispatcher = dispatcher = _Dispatcher()
        login = await _login(fx)
        assert len(dispatcher.calls) == 1

        await fx.guest_service.submit_sign_in_name(
            guest_id=login.guest.id, session_id=login.session.id, display_name="Asha"
        )

        assert dispatcher.calls[1] == {
            "router_id": fx.router.id,
            "session_id": login.session.id,
        }


# ============================================================================
# The dispatcher and the task: off the request path, and best-effort
# ============================================================================


def _settings(
    enabled: bool = True, *, delay: float = 3.0, router_ids: str = ""
) -> SimpleNamespace:
    return SimpleNamespace(
        guest_hotspot_gate_push_enabled=enabled,
        guest_hotspot_gate_push_router_ids=router_ids,
        guest_hotspot_gate_push_delay_seconds=delay,
    )


class TestEnqueue:
    async def test_publishes_with_the_configured_delay(self) -> None:
        session_id, router_id = uuid.uuid4(), uuid.uuid4()
        with (
            patch("app.core.config.get_settings", return_value=_settings(delay=2.5)),
            patch.object(guest_tasks.open_hotspot_gate, "apply_async") as publish,
        ):
            await guest_tasks.enqueue_hotspot_gate_open(
                router_id=router_id, session_id=session_id
            )
        publish.assert_called_once_with(
            kwargs={"session_id": str(session_id), "router_id": str(router_id)},
            countdown=2.5,
        )

    async def test_switched_off_publishes_nothing(self) -> None:
        with (
            patch("app.core.config.get_settings", return_value=_settings(False)),
            patch.object(guest_tasks.open_hotspot_gate, "apply_async") as publish,
        ):
            await guest_tasks.enqueue_hotspot_gate_open(
                router_id=uuid.uuid4(), session_id=uuid.uuid4()
            )
        publish.assert_not_called()

    def test_it_ships_switched_off(self) -> None:
        """Merging this must not start writing to routers. See the settings'
        own note for the two ways it is switched on."""
        from app.core.config import Settings

        fields = Settings.model_fields
        assert fields["guest_hotspot_gate_push_enabled"].default is False
        assert fields["guest_hotspot_gate_push_router_ids"].default == ""

    async def test_an_allow_listed_router_is_pushed_and_no_other(self) -> None:
        listed, other = uuid.uuid4(), uuid.uuid4()
        settings = _settings(False, router_ids=f" {str(listed).upper()} , junk,")
        with (
            patch("app.core.config.get_settings", return_value=settings),
            patch.object(guest_tasks.open_hotspot_gate, "apply_async") as publish,
        ):
            await guest_tasks.enqueue_hotspot_gate_open(
                router_id=other, session_id=uuid.uuid4()
            )
            publish.assert_not_called()
            await guest_tasks.enqueue_hotspot_gate_open(
                router_id=listed, session_id=uuid.uuid4()
            )
            publish.assert_called_once()

    async def test_a_broker_failure_is_swallowed(self) -> None:
        with (
            patch("app.core.config.get_settings", return_value=_settings()),
            patch.object(
                guest_tasks.open_hotspot_gate,
                "apply_async",
                side_effect=ConnectionError("redis down"),
            ),
        ):
            await guest_tasks.enqueue_hotspot_gate_open(
                router_id=uuid.uuid4(), session_id=uuid.uuid4()
            )

    async def _enqueue(self, settings: SimpleNamespace, redis: _Redis):
        session_id = uuid.uuid4()
        with (
            patch("app.core.config.get_settings", return_value=settings),
            patch("app.database.redis.redis_client", redis),
            patch.object(guest_tasks.open_hotspot_gate, "apply_async") as publish,
        ):
            await guest_tasks.enqueue_hotspot_gate_open(
                router_id=uuid.uuid4(), session_id=session_id
            )
        return session_id, publish

    async def test_every_request_moves_the_sessions_not_before_instant(
        self,
    ) -> None:
        redis = _Redis()
        before = time.time()
        session_id, publish = await self._enqueue(_settings(delay=2.5), redis)
        after = time.time()

        publish.assert_called_once()
        ((key, value, options),) = redis.sets
        assert str(session_id) in key
        assert before + 2.5 <= float(value) <= after + 2.5
        # Outlives the delay it records, and not by much.
        assert options == {"ex": 3}

    async def test_switched_off_asks_redis_nothing(self) -> None:
        redis = _Redis()
        _, publish = await self._enqueue(_settings(False), redis)
        publish.assert_not_called()
        assert redis.sets == []

    async def test_no_delay_records_no_instant(self) -> None:
        redis = _Redis()
        _, publish = await self._enqueue(_settings(delay=0), redis)
        publish.assert_called_once()
        assert redis.sets == []

    async def test_redis_being_down_publishes_anyway(self) -> None:
        """The hold is an improvement on the countdown, never a condition
        of the push."""
        session_id, publish = await self._enqueue(
            _settings(), _Redis(raises=ConnectionError("redis down"))
        )
        publish.assert_called_once()
        assert publish.call_args.kwargs["kwargs"]["session_id"] == str(session_id)
        assert publish.call_args.kwargs["countdown"] == 3.0

    def test_the_real_service_is_wired_with_it(self) -> None:
        import inspect

        from app.domains.guest import dependencies

        source = inspect.getsource(dependencies.get_guest_service)
        assert "hotspot_gate_dispatcher=enqueue_hotspot_gate_open" in source


def _run_task(
    result: object,
    *,
    retries: int = 0,
    task: Any = None,
    kwargs: dict[str, object] | None = None,
) -> dict[str, object]:
    """Runs the task body in-process with ``retries`` already spent.
    ``result`` is what the one attempt returns, or raises if an exception."""

    def _attempt(coro: Any) -> object:
        coro.close()
        if isinstance(result, BaseException):
            raise result
        return result

    task = task or guest_tasks.open_hotspot_gate
    kwargs = kwargs or {
        "session_id": str(uuid.uuid4()),
        "router_id": str(uuid.uuid4()),
    }
    # ``is_eager`` makes ``self.retry`` raise ``Retry`` here instead of
    # publishing the retry to a broker.
    task.push_request(
        retries=retries, called_directly=False, is_eager=True, args=(), kwargs=kwargs
    )
    try:
        with patch.object(guest_tasks, "run_celery_task", side_effect=_attempt):
            return task.run(**kwargs)
    finally:
        task.pop_request()


class TestTask:
    def test_a_write_completes(self) -> None:
        out = _run_task(HotspotGateResult("created", wrote=True, host_state="absent"))
        assert out["outcome"] == "created"

    def test_a_refusal_completes_without_retrying(self) -> None:
        assert _run_task(HotspotGateResult("blocklisted"))["outcome"] == "blocklisted"

    def test_not_yet_listed_is_retried(self) -> None:
        with pytest.raises(Retry):
            _run_task(HotspotGateResult("not_listed", retry=True))

    def test_not_listed_on_the_last_attempt_gives_up_quietly(self) -> None:
        out = _run_task(
            HotspotGateResult("not_listed", retry=True),
            retries=OPEN_HOTSPOT_GATE_MAX_RETRIES,
        )
        assert out["outcome"] == "not_listed"

    def test_an_unreachable_router_is_retried_then_given_up_on(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        error = MikroTikConnectionError("router", "timed out")
        with pytest.raises(Retry):
            _run_task(error)

        with caplog.at_level("WARNING"):
            out = _run_task(error, retries=OPEN_HOTSPOT_GATE_MAX_RETRIES)

        # The last attempt returns: nothing propagates out of the task.
        assert out["outcome"] == "device_error"
        failed = [
            r for r in caplog.records if r.msg == "guest_task_open_hotspot_gate_failed"
        ]
        assert failed and failed[-1].gave_up is True

    async def test_a_device_failure_in_one_attempt_is_the_devices_own_error(
        self,
    ) -> None:
        fx, hook = _fixture()
        login = await _login(fx)
        writer = _Writer(raises=MikroTikConnectionError("router", "timed out"))
        with pytest.raises(MikroTikConnectionError):
            await _open(fx, hook, login.session.id, writer)
        # The session is untouched by a router that did not answer.
        session = await fx.repository.get_session_by_id(login.session.id)
        assert session is not None and session.status == "active"


# ============================================================================
# Never ahead of the browser: the hold
# ============================================================================


class _DbSession:
    """What ``SessionLocal()`` hands the worker; the services built on it
    are never asked anything, because the attempt itself is replaced."""

    async def __aenter__(self) -> _DbSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None


class TestHold:
    async def _remaining(self, redis: _Redis, *, delay: float = 3.0) -> float:
        with (
            patch("app.core.config.get_settings", return_value=_settings(delay=delay)),
            patch("app.database.redis.create_redis_client", return_value=redis),
        ):
            return await guest_tasks._hotspot_gate_hold_remaining(str(uuid.uuid4()))

    async def test_an_instant_still_ahead_is_how_long_is_left(self) -> None:
        redis = _Redis(value=repr(time.time() + 2.0))
        remaining = await self._remaining(redis)
        assert 1.5 < remaining <= 2.0
        # A fresh client, closed in the loop that opened it.
        assert redis.closed == 1

    @pytest.mark.parametrize("value", [None, "not-a-number"])
    async def test_no_instant_or_an_unreadable_one_is_no_hold(
        self, value: str | None
    ) -> None:
        assert await self._remaining(_Redis(value=value)) == 0.0

    async def test_an_instant_that_has_passed_is_no_hold(self) -> None:
        assert await self._remaining(_Redis(value=repr(time.time() - 0.1))) == 0.0

    async def test_redis_being_down_is_no_hold(self) -> None:
        redis = _Redis(raises=ConnectionError("redis down"))
        assert await self._remaining(redis) == 0.0
        assert redis.closed == 1

    async def test_a_hold_is_never_longer_than_the_delay(self) -> None:
        """A clock that disagrees with the one that wrote the value must not
        park the task."""
        redis = _Redis(value=repr(time.time() + 3600))
        assert await self._remaining(redis, delay=3.0) == 3.0

    async def test_no_delay_asks_redis_nothing(self) -> None:
        redis = _Redis(value=repr(time.time() + 5))
        assert await self._remaining(redis, delay=0) == 0.0
        assert redis.gets == []

    async def _attempt(self, redis: _Redis) -> tuple[Any, AsyncMock, _Writer]:
        """``_open_hotspot_gate_async`` with the one attempt replaced by a
        stand-in that goes straight to the adapter."""
        writer = _Writer()

        async def _write(**kwargs: Any) -> HotspotGateResult:
            await writer.ensure_hotspot_bypass_binding(None, mac_address=MAC)
            return HotspotGateResult("created", wrote=True)

        attempt = AsyncMock(side_effect=_write)
        with (
            patch("app.core.config.get_settings", return_value=_settings()),
            patch("app.database.redis.create_redis_client", return_value=redis),
            patch.object(guest_tasks, "SessionLocal", _DbSession),
            patch.object(guest_tasks, "_build_access_decision_service"),
            patch.object(guest_tasks, "_build_captive_portal_service"),
            patch.object(hotspot_gate, "open_hotspot_gate_for_session", attempt),
        ):
            result = await guest_tasks._open_hotspot_gate_async(
                session_id=str(uuid.uuid4()), router_id=str(uuid.uuid4())
            )
        return result, attempt, writer

    async def test_a_task_that_starts_too_soon_touches_nothing(self) -> None:
        """The measured case: the task from sign-in starts just after the
        name was given, which moved the instant ~3 s on."""
        result, attempt, writer = await self._attempt(
            _Redis(value=repr(time.time() + 2.4))
        )
        assert result.outcome == OUTCOME_HELD and not result.wrote
        assert 2.0 < result.hold_seconds <= 2.4
        attempt.assert_not_awaited()
        assert writer.calls == []

    async def test_a_task_that_starts_after_the_instant_writes(self) -> None:
        result, attempt, writer = await self._attempt(
            _Redis(value=repr(time.time() - 0.01))
        )
        assert result.outcome == "created"
        attempt.assert_awaited_once()
        assert len(writer.calls) == 1

    async def test_redis_being_down_falls_through_to_the_write(self) -> None:
        result, attempt, writer = await self._attempt(
            _Redis(raises=ConnectionError("redis down"))
        )
        assert result.outcome == "created" and result.wrote
        attempt.assert_awaited_once()
        assert len(writer.calls) == 1

    @pytest.mark.parametrize("retries", [0, OPEN_HOTSPOT_GATE_MAX_RETRIES])
    def test_a_held_task_is_published_again_for_the_instant_not_retried(
        self, retries: int
    ) -> None:
        """A new task, so the hold costs none of the attempts kept for a
        session that is not visible yet or a router that does not answer --
        and so it is re-scheduled even when those are already spent."""
        kwargs = {"session_id": str(uuid.uuid4()), "router_id": str(uuid.uuid4())}
        with patch.object(guest_tasks.open_hotspot_gate, "apply_async") as publish:
            out = _run_task(
                HotspotGateResult(OUTCOME_HELD, hold_seconds=2.4),
                retries=retries,
                kwargs=kwargs,
            )
        assert out == {"session_id": kwargs["session_id"], "outcome": "held"}
        publish.assert_called_once_with(kwargs=kwargs, countdown=2.4)

    def test_a_held_task_that_cannot_be_published_again_gives_up_quietly(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with (
            patch.object(
                guest_tasks.open_hotspot_gate,
                "apply_async",
                side_effect=ConnectionError("broker down"),
            ),
            caplog.at_level("WARNING"),
        ):
            out = _run_task(HotspotGateResult(OUTCOME_HELD, hold_seconds=1.0))
        assert out["outcome"] == "held"
        assert "guest_task_open_hotspot_gate_hold_reschedule_failed" in caplog.text

    def test_a_task_that_is_not_held_publishes_nothing_more(self) -> None:
        with patch.object(guest_tasks.open_hotspot_gate, "apply_async") as publish:
            _run_task(HotspotGateResult("created", wrote=True))
        publish.assert_not_called()


# ============================================================================
# A device an admin has just trusted
# ============================================================================


def _trusted(fx: Fixture) -> MacAuthorizationService:
    """The real service over a fake repository, resolving the router the
    way the worker's does -- so "applies at this router, enabled, not
    expired, not deleted" is the service's own rule, not a test's."""
    return MacAuthorizationService(
        FakeMacAuthorizationRepository(), router_lookup=fx.router_service
    )


async def _trust(
    fx: Fixture,
    service: MacAuthorizationService,
    *,
    mac: str = TRUSTED_MAC,
    location_id: uuid.UUID | None = None,
    is_enabled: bool = True,
):
    return await service.create_entry(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=fx.router.organization_id,
        mac_address=mac,
        location_id=location_id,
        is_enabled=is_enabled,
    )


async def _open_trusted(
    fx: Fixture,
    service: MacAuthorizationService,
    entry_id: uuid.UUID,
    writer: _Writer,
    *,
    router_id: uuid.UUID | None = None,
):
    return await open_hotspot_gate_for_trusted_entry(
        entry_id=entry_id,
        router_id=router_id or fx.router.id,
        mac_authorization_service=service,
        router_lookup=fx.router_service,
        adapter=writer,
    )


class TestTrustedEntryOneAttempt:
    async def test_an_active_entry_writes_its_canonical_mac(self) -> None:
        fx, hook = _fixture()
        service = _trusted(fx)
        entry = await _trust(fx, service, mac="aa-bb-cc-00-00-01")
        writer = _Writer()

        result = await _open_trusted(fx, service, entry.id, writer)

        assert result == HotspotGateResult("created", wrote=True, host_state="absent")
        (call,) = writer.calls
        assert call["mac_address"] == TRUSTED_MAC
        assert call["creds"].host == "10.20.0.99"
        assert call["creds"].timeout_seconds <= 5
        # ...and it is a MAC the list carries, under the same spelling.
        listed = await list_authorized_macs(
            fx.router.id, mac_authorization_service=service, **_deps(fx, hook)
        )
        assert listed.mac_addresses == (TRUSTED_MAC,)

    async def test_an_entry_for_the_routers_own_location_is_written(self) -> None:
        fx, _ = _fixture()
        service = _trusted(fx)
        entry = await _trust(fx, service, location_id=fx.router.location_id)
        writer = _Writer()
        assert (await _open_trusted(fx, service, entry.id, writer)).wrote
        assert len(writer.calls) == 1

    @pytest.mark.parametrize(
        "refuse", ["disabled", "deleted", "expired", "other_location", "unknown"]
    )
    async def test_an_entry_the_list_leaves_out_never_reaches_the_router(
        self, refuse: str
    ) -> None:
        """Asked in the worker, immediately before the write: an entry
        switched off or removed since it was saved gets no binding."""
        fx, hook = _fixture()
        service = _trusted(fx)
        entry = await _trust(
            fx,
            service,
            location_id=uuid.uuid4() if refuse == "other_location" else None,
        )
        entry_id = entry.id
        if refuse == "disabled":
            entry.is_enabled = False
        if refuse == "deleted":
            entry.is_deleted = True
        if refuse == "expired":
            entry.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        if refuse == "unknown":
            entry_id = uuid.uuid4()
        writer = _Writer()

        result = await _open_trusted(fx, service, entry_id, writer)

        assert writer.calls == []
        assert result.outcome == "not_listed" and not result.wrote
        # "Not visible yet" looks the same, so it is worth another look.
        assert result.retry
        if refuse != "unknown":
            listed = await list_authorized_macs(
                fx.router.id, mac_authorization_service=service, **_deps(fx, hook)
            )
            assert listed.mac_addresses == ()

    @pytest.mark.parametrize("vendor", ["tplink_omada", "aruba_instant_on"])
    async def test_a_venue_this_platform_does_not_log_in_to_is_never_written(
        self, vendor: str
    ) -> None:
        fx, _ = _fixture()
        service = _trusted(fx)
        entry = await _trust(fx, service)
        fx.router.vendor = vendor
        writer = _Writer()
        result = await _open_trusted(fx, service, entry.id, writer)
        assert result.outcome == OUTCOME_UNSUPPORTED_VENDOR and writer.calls == []

    @pytest.mark.parametrize(
        "outcome", ["already_bound", "active_session", "no_reconciler"]
    )
    async def test_the_gateways_own_rules_still_decide(self, outcome: str) -> None:
        fx, _ = _fixture()
        service = _trusted(fx)
        entry = await _trust(fx, service)
        result = await _open_trusted(fx, service, entry.id, _Writer(outcome=outcome))
        assert result.outcome == outcome
        assert not result.wrote and not result.retry

    async def test_a_router_with_no_credentials_is_not_connected_to(self) -> None:
        fx, _ = _fixture()
        service = _trusted(fx)
        entry = await _trust(fx, service)
        fx.router.api_credentials_encrypted = None
        writer = _Writer()
        result = await _open_trusted(fx, service, entry.id, writer)
        assert result.outcome == OUTCOME_NO_CREDENTIALS and writer.calls == []

    async def test_a_router_that_no_longer_exists_is_an_outcome(self) -> None:
        fx, _ = _fixture()
        service = _trusted(fx)
        entry = await _trust(fx, service)
        result = await _open_trusted(
            fx, service, entry.id, _Writer(), router_id=uuid.uuid4()
        )
        assert result.outcome == OUTCOME_ROUTER_NOT_FOUND


class _WorkerSession:
    def __init__(self) -> None:
        self.rollbacks = 0

    async def rollback(self) -> None:
        self.rollbacks += 1


class TestTrustedEntryWorker:
    async def _run(
        self,
        fx: Fixture,
        settings: SimpleNamespace,
        writer: _Writer,
        router_ids: list[uuid.UUID],
        *,
        entry_id: uuid.UUID | None = None,
    ) -> tuple[dict[str, int], _WorkerSession]:
        service = _trusted(fx)
        entry = await _trust(fx, service)
        session = _WorkerSession()
        with patch("app.core.config.get_settings", return_value=settings):
            totals = await guest_tasks._open_trusted_device_gate_on_routers(
                session,  # type: ignore[arg-type]
                router_ids,
                entry_id=entry_id or entry.id,
                mac_authorization_service=service,
                router_lookup=fx.router_service,
                adapter=writer,
            )
        return totals, session

    async def test_a_router_the_push_is_on_for_is_written(self) -> None:
        fx, _ = _fixture()
        writer = _Writer()
        totals, _ = await self._run(fx, _settings(), writer, [fx.router.id])
        assert totals == {"routers": 1, "wrote": 1, "failed": 0, "not_listed": 0}
        assert [call["mac_address"] for call in writer.calls] == [TRUSTED_MAC]

    async def test_a_router_the_push_is_off_for_is_not_even_looked_up(
        self,
    ) -> None:
        """The sign-in push's own two settings: an allow-list naming another
        router leaves this one to its poll."""
        fx, _ = _fixture()
        writer = _Writer()
        settings = _settings(False, router_ids=str(uuid.uuid4()))
        totals, _ = await self._run(fx, settings, writer, [fx.router.id])
        assert totals == {"routers": 0, "wrote": 0, "failed": 0, "not_listed": 0}
        assert writer.calls == []

    async def test_an_allow_listed_router_is_written_and_no_other(self) -> None:
        fx, _ = _fixture()
        other = fx.router_service.add(
            organization_id=fx.router.organization_id,
            location_id=fx.router.location_id,
            management_ip_address="10.20.0.98",
        )
        other.api_username, other.api_credentials_encrypted = "wyfy-api", "ciphertext"
        writer = _Writer()
        settings = _settings(False, router_ids=str(other.id))
        totals, _ = await self._run(fx, settings, writer, [fx.router.id, other.id])
        assert totals["routers"] == 1 and totals["wrote"] == 1
        assert [call["creds"].host for call in writer.calls] == ["10.20.0.98"]

    async def test_one_router_failing_does_not_stop_the_next(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        fx, _ = _fixture()
        other = fx.router_service.add(
            organization_id=fx.router.organization_id,
            location_id=fx.router.location_id,
            management_ip_address="10.20.0.98",
        )
        other.api_username, other.api_credentials_encrypted = "wyfy-api", "ciphertext"

        @dataclass
        class _FirstFails(_Writer):
            async def ensure_hotspot_bypass_binding(self, creds: Any, **kwargs: Any):
                if creds.host == "10.20.0.99":
                    self.calls.append({"creds": creds, **kwargs})
                    raise MikroTikConnectionError("router", "timed out")
                return await _Writer.ensure_hotspot_bypass_binding(
                    self, creds, **kwargs
                )

        writer = _FirstFails()
        with caplog.at_level("WARNING"):
            totals, session = await self._run(
                fx, _settings(), writer, [fx.router.id, other.id]
            )

        assert totals == {"routers": 2, "wrote": 1, "failed": 1, "not_listed": 0}
        assert [c["creds"].host for c in writer.calls] == ["10.20.0.99", "10.20.0.98"]
        assert session.rollbacks == 1
        assert "guest_hotspot_gate_trusted_device_failed" in caplog.text

    async def test_an_entry_that_is_not_visible_yet_is_counted(self) -> None:
        fx, _ = _fixture()
        writer = _Writer()
        totals, _ = await self._run(
            fx, _settings(), writer, [fx.router.id], entry_id=uuid.uuid4()
        )
        assert totals == {"routers": 1, "wrote": 0, "failed": 0, "not_listed": 1}
        assert writer.calls == []


def _run_trusted_task(result: object, *, retries: int = 0) -> dict[str, object]:
    return _run_task(
        result,
        retries=retries,
        task=guest_tasks.open_hotspot_gate_for_trusted_device,
        kwargs={
            "entry_id": str(uuid.uuid4()),
            "organization_id": str(uuid.uuid4()),
            "location_id": None,
        },
    )


class TestTrustedEntryTask:
    def test_a_write_completes(self) -> None:
        totals = {"routers": 2, "wrote": 2, "failed": 0, "not_listed": 0}
        out = _run_trusted_task(totals)
        assert out["wrote"] == 2 and out["routers"] == 2

    def test_a_router_that_did_not_answer_is_not_retried(self) -> None:
        """Its own poll adds the binding; a retry would reconnect to every
        router that did answer."""
        out = _run_trusted_task(
            {"routers": 2, "wrote": 1, "failed": 1, "not_listed": 0}
        )
        assert out["failed"] == 1

    def test_an_entry_not_yet_visible_is_retried_then_given_up_on(self) -> None:
        totals = {"routers": 1, "wrote": 0, "failed": 0, "not_listed": 1}
        with pytest.raises(Retry):
            _run_trusted_task(totals)
        out = _run_trusted_task(totals, retries=OPEN_HOTSPOT_GATE_MAX_RETRIES)
        assert out["not_listed"] == 1

    def test_a_run_that_fails_is_retried_then_given_up_on(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        error = RuntimeError("database unavailable")
        with pytest.raises(Retry):
            _run_trusted_task(error)
        with caplog.at_level("WARNING"):
            out = _run_trusted_task(error, retries=OPEN_HOTSPOT_GATE_MAX_RETRIES)
        # The last attempt returns: nothing propagates out of the task.
        assert out["outcome"] == "error"
        assert "guest_task_open_hotspot_gate_for_trusted_device_failed" in caplog.text

    def test_it_does_not_queue_behind_fleet_polls(self) -> None:
        """It is what makes "add a Trusted Device" prompt."""
        assert TASK_OPEN_HOTSPOT_GATE_FOR_TRUSTED_DEVICE not in (
            celery_app.conf.task_routes
        )


class TestTrustedEntryEnqueue:
    async def _enqueue(self, settings: SimpleNamespace, **kwargs: Any):
        ids = {
            "entry_id": uuid.uuid4(),
            "organization_id": uuid.uuid4(),
            "location_id": kwargs.pop("location_id", None),
        }
        task = guest_tasks.open_hotspot_gate_for_trusted_device
        with (
            patch("app.core.config.get_settings", return_value=settings),
            patch.object(task, "apply_async", **kwargs) as publish,
        ):
            await guest_tasks.enqueue_trusted_device_hotspot_gate_open(**ids)
        return ids, publish

    async def test_publishes_the_entry_and_its_scope_at_once(self) -> None:
        location_id = uuid.uuid4()
        ids, publish = await self._enqueue(_settings(), location_id=location_id)
        publish.assert_called_once_with(
            kwargs={
                "entry_id": str(ids["entry_id"]),
                "organization_id": str(ids["organization_id"]),
                "location_id": str(location_id),
            },
            countdown=TRUSTED_DEVICE_HOTSPOT_GATE_DELAY_SECONDS,
        )
        # Long enough for a commit; nothing like the router's minute.
        assert 0 < TRUSTED_DEVICE_HOTSPOT_GATE_DELAY_SECONDS <= 2

    async def test_an_organization_wide_entry_carries_no_location(self) -> None:
        _, publish = await self._enqueue(_settings())
        assert publish.call_args.kwargs["kwargs"]["location_id"] is None

    async def test_switched_off_publishes_nothing(self) -> None:
        _, publish = await self._enqueue(_settings(False))
        publish.assert_not_called()

    async def test_an_allow_list_alone_publishes(self) -> None:
        """Which routers is the worker's question; here only "anywhere"."""
        _, publish = await self._enqueue(_settings(False, router_ids=str(uuid.uuid4())))
        publish.assert_called_once()

    async def test_a_broker_failure_is_swallowed(self) -> None:
        await self._enqueue(_settings(), side_effect=ConnectionError("broker down"))


class TestTrustedEntryTriggers:
    """``MacAuthorizationService`` asks; ``hotspot_binding_events`` never
    lets the asking fail the dashboard request."""

    async def _create(self, **kwargs: Any):
        h, organization_id = make_harness(), uuid.uuid4()
        with patch.object(
            hotspot_binding_events,
            "request_trusted_device_hotspot_gate_open",
            AsyncMock(),
        ) as request:
            entry = await h.service.create_entry(
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=organization_id,
                mac_address=TRUSTED_MAC,
                **kwargs,
            )
        return h, entry, request

    async def _update(self, created: dict[str, Any], **fields: Any):
        h, entry, _ = await self._create(**created)
        with patch.object(
            hotspot_binding_events,
            "request_trusted_device_hotspot_gate_open",
            AsyncMock(),
        ) as request:
            updated = await h.service.update_entry(
                entry.id,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=entry.organization_id,
                **fields,
            )
        return updated, request

    async def test_creating_one_asks_for_its_entry_and_scope(self) -> None:
        location_id = uuid.uuid4()
        _, entry, request = await self._create(location_id=location_id)
        request.assert_awaited_once_with(
            entry_id=entry.id,
            organization_id=entry.organization_id,
            location_id=location_id,
        )

    async def test_creating_one_disabled_asks_for_nothing(self) -> None:
        _, _, request = await self._create(is_enabled=False)
        request.assert_not_awaited()

    async def test_a_bulk_import_asks_for_nothing(self) -> None:
        """One task per row, each connecting to every router in scope, is
        not what an import should cost; the routers' poll adds them."""
        h = make_harness()
        with patch.object(
            hotspot_binding_events,
            "request_trusted_device_hotspot_gate_open",
            AsyncMock(),
        ) as request:
            result = await h.service.import_entries(
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=uuid.uuid4(),
                entries=[{"mac_address": TRUSTED_MAC}],
            )
        assert result.imported_count == 1
        request.assert_not_awaited()

    async def test_enabling_one_asks(self) -> None:
        updated, request = await self._update({"is_enabled": False}, is_enabled=True)
        request.assert_awaited_once_with(
            entry_id=updated.id,
            organization_id=updated.organization_id,
            location_id=None,
        )

    async def test_changing_its_mac_asks(self) -> None:
        updated, request = await self._update({}, mac_address="aa:bb:cc:00:00:02")
        assert updated.mac_address == "AA:BB:CC:00:00:02"
        request.assert_awaited_once()

    async def test_moving_it_to_another_location_asks_for_the_new_one(self) -> None:
        new_location = uuid.uuid4()
        updated, request = await self._update(
            {"location_id": uuid.uuid4()}, location_id=new_location
        )
        assert request.await_args.kwargs["location_id"] == new_location
        assert updated.location_id == new_location

    @pytest.mark.parametrize("fields", [{"comment": "lobby TV"}, {"is_enabled": False}])
    async def test_an_edit_that_lists_nothing_new_asks_for_nothing(
        self, fields: dict[str, Any]
    ) -> None:
        _, request = await self._update({}, **fields)
        request.assert_not_awaited()

    async def test_changing_the_mac_of_a_disabled_one_asks_for_nothing(
        self,
    ) -> None:
        _, request = await self._update(
            {"is_enabled": False}, mac_address="aa:bb:cc:00:00:02"
        )
        request.assert_not_awaited()

    async def test_a_request_that_blows_up_fails_nothing(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        boom = AsyncMock(side_effect=RuntimeError("anything at all"))
        h, organization_id = make_harness(), uuid.uuid4()
        with (
            patch.object(guest_tasks, "enqueue_trusted_device_hotspot_gate_open", boom),
            caplog.at_level("WARNING"),
        ):
            entry = await h.service.create_entry(
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=organization_id,
                mac_address=TRUSTED_MAC,
            )
        assert entry.mac_address == TRUSTED_MAC
        boom.assert_awaited_once()
        assert "guest_hotspot_gate_trusted_device_request_failed" in caplog.text

    async def test_creating_one_still_succeeds_with_the_real_request_path(
        self,
    ) -> None:
        """Nothing patched but the settings and the publish: the real lazy
        import, the real switch -- off publishes nothing, on publishes the
        entry that was just saved."""
        task = guest_tasks.open_hotspot_gate_for_trusted_device
        for settings, published in ((_settings(False), 0), (_settings(), 1)):
            h, organization_id = make_harness(), uuid.uuid4()
            with (
                patch("app.core.config.get_settings", return_value=settings),
                patch.object(task, "apply_async") as publish,
            ):
                entry = await h.service.create_entry(
                    actor_user_id=uuid.uuid4(),
                    requesting_organization_id=organization_id,
                    mac_address=TRUSTED_MAC,
                )
            assert publish.call_count == published
            if published:
                assert publish.call_args.kwargs["kwargs"] == {
                    "entry_id": str(entry.id),
                    "organization_id": str(organization_id),
                    "location_id": None,
                }


# ---------------------------------------------------------------------------
# A device marked Trusted while it was signed in: bound when the session ends
# ---------------------------------------------------------------------------


class TestEndedSessionTrustedDevice:
    async def _lookup(self, fx: Fixture, service: MacAuthorizationService, session_id):
        from app.domains.guest.hotspot_gate import trusted_entry_for_session_device

        return await trusted_entry_for_session_device(
            session_id=session_id,
            router_id=fx.router.id,
            guest_repository=fx.repository,
            mac_authorization_service=service,
        )

    async def test_the_entry_for_the_sessions_device_is_found(self) -> None:
        fx, _ = _fixture()
        service = _trusted(fx)
        result = await _login(fx, mac=TRUSTED_MAC.lower())
        entry = await _trust(fx, service)
        assert await self._lookup(fx, service, result.session.id) == entry.id

    async def test_a_device_nobody_trusted_has_none(self) -> None:
        fx, _ = _fixture()
        service = _trusted(fx)
        result = await _login(fx)
        await _trust(fx, service)
        assert await self._lookup(fx, service, result.session.id) is None

    async def test_a_disabled_entry_is_not_one(self) -> None:
        fx, _ = _fixture()
        service = _trusted(fx)
        result = await _login(fx, mac=TRUSTED_MAC)
        await _trust(fx, service, is_enabled=False)
        assert await self._lookup(fx, service, result.session.id) is None

    async def test_an_unknown_session_has_none(self) -> None:
        fx, _ = _fixture()
        assert await self._lookup(fx, _trusted(fx), uuid.uuid4()) is None

    async def _enqueue(self, settings: SimpleNamespace, **kwargs: Any):
        ids = {"session_id": uuid.uuid4(), "router_id": uuid.uuid4()}
        task = guest_tasks.open_hotspot_gate_for_ended_session_device
        with (
            patch("app.core.config.get_settings", return_value=settings),
            patch.object(task, "apply_async", **kwargs) as publish,
        ):
            await guest_tasks.enqueue_ended_session_trusted_gate_open(**ids)
        return ids, publish

    async def test_publishes_when_the_push_is_on_for_the_router(self) -> None:
        ids, publish = await self._enqueue(_settings())
        publish.assert_called_once()
        assert publish.call_args.kwargs["kwargs"] == {
            "session_id": str(ids["session_id"]),
            "router_id": str(ids["router_id"]),
        }
        assert publish.call_args.kwargs["countdown"] > 0

    async def test_publishes_nothing_when_the_push_is_off(self) -> None:
        _, publish = await self._enqueue(_settings(enabled=False))
        publish.assert_not_called()

    async def test_a_broker_failure_is_swallowed(self) -> None:
        _, publish = await self._enqueue(
            _settings(), side_effect=RuntimeError("broker down")
        )
        publish.assert_called_once()

    def test_the_task_never_raises(self) -> None:
        task = guest_tasks.open_hotspot_gate_for_ended_session_device
        with patch.object(
            guest_tasks, "run_celery_task", side_effect=RuntimeError("db down")
        ):
            out = task.run(session_id=str(uuid.uuid4()), router_id=str(uuid.uuid4()))
        assert out["outcome"] == "error"

    async def test_ending_a_session_asks_for_it(self) -> None:
        fx, _ = _fixture()
        result = await _login(fx)
        with patch(
            "app.domains.guest.service."
            "request_trusted_device_hotspot_gate_open_for_ended_session"
        ) as ask:
            await fx.guest_service.disconnect_session(
                session_id=result.session.id,
                requesting_organization_id=fx.router.organization_id,
            )
        ask.assert_called_once_with(
            session_id=result.session.id, router_id=fx.router.id
        )
