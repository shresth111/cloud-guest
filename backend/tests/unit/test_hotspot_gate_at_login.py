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
  does not fail a login, and the task gives up rather than raising.

What the router itself does with the row (idempotence, rows that are not
ours, the missing scheduler) is the gateway's own test:
``vendor/wyfy-device-gateway/tests/test_mikrotik_bypass_binding.py``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from celery.exceptions import Retry
from wyfy_device_gateway.mikrotik_adapter import MikroTikConnectionError

from app.domains.guest import tasks as guest_tasks
from app.domains.guest.constants import (
    OPEN_HOTSPOT_GATE_MAX_RETRIES,
    GuestAuthMethod,
)
from app.domains.guest.hotspot_gate import (
    OUTCOME_NO_CREDENTIALS,
    OUTCOME_ROUTER_NOT_FOUND,
    OUTCOME_UNSUPPORTED_VENDOR,
    HotspotGateResult,
    open_hotspot_gate_for_session,
)
from app.domains.router_agent.authorized_macs import (
    SessionGateReason,
    list_authorized_macs,
    resolve_session_gate,
)
from app.domains.router_agent.dependencies import AgentIdentity
from app.domains.router_agent.router import agent_authorized_macs

from .test_guest import FakeAccessControlHook, Fixture, make_fixture

PHONE = "+15550000001"
MAC = "AA:BB:CC:DD:EE:01"


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

    def test_the_real_service_is_wired_with_it(self) -> None:
        import inspect

        from app.domains.guest import dependencies

        source = inspect.getsource(dependencies.get_guest_service)
        assert "hotspot_gate_dispatcher=enqueue_hotspot_gate_open" in source


def _run_task(result: object, *, retries: int = 0) -> dict[str, object]:
    """Runs the task body in-process with ``retries`` already spent.
    ``result`` is what the one attempt returns, or raises if an exception."""

    def _attempt(coro: Any) -> object:
        coro.close()
        if isinstance(result, BaseException):
            raise result
        return result

    task = guest_tasks.open_hotspot_gate
    kwargs = {"session_id": str(uuid.uuid4()), "router_id": str(uuid.uuid4())}
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
