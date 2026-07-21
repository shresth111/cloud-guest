"""Unit tests for BE-011 Part 3's Real-Time Engine: the Redis pub/sub
broadcast hooks inside ``MonitoringService``/``AlertService`` (health-status
transitions, alert trigger/resolve), the additive guest-session-start hook
inside ``app.domains.guest.service.GuestService``, and the two WebSocket
endpoints (``/monitoring/ws/dashboard``/``/monitoring/ws/sessions``) --
connect/receive-a-relayed-broadcast/message-type-filtering/disconnect-
cleanup, exercised end-to-end via FastAPI's ``TestClient`` WebSocket
support against a small, hand-rolled, thread-safe in-memory fake Redis
pub/sub (there is no live Redis in this environment).

Follows this project's established convention (plain ``assert``/native
``async def`` for service-layer tests; see ``test_monitoring.py``/
``test_monitoring_alerts.py``) plus, for the two WebSocket endpoints
specifically, plain synchronous ``def test_*`` functions using
``fastapi.testclient.TestClient``'s WebSocket support -- the one new
testing pattern this part introduces, since Part 1/Part 2 never needed a
real ASGI transport (see ``test_monitoring_alerts.py``'s own docstring:
"no route ever gets exercised via a real HTTP call/TestClient anywhere in
this codebase" -- WebSocket support is exactly the reason this part
finally needs one).
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.core.config import Settings
from app.database.redis import get_redis_client
from app.domains.auth.dependencies import get_auth_repository
from app.domains.auth.jwt import JWTManager
from app.domains.guest.constants import GuestAuthMethod
from app.domains.monitoring.constants import (
    MONITORING_LIVE_CHANNEL,
    AlertTriggerType,
    RealtimeMessageType,
)
from app.domains.monitoring.models import ServiceHealth
from app.domains.monitoring.service import AlertService, MonitoringService
from app.domains.rbac.dependencies import get_access_validator
from app.main import create_app
from tests.unit.test_guest import make_fixture
from tests.unit.test_monitoring import (
    FakeAuthRepository,
    FakeMonitoringRepository,
    FakeWireGuardService,
    _base_fields,
)
from tests.unit.test_monitoring_alerts import FakeRepository, _alert_rule_fields
from tests.unit.test_monitoring_alerts import _now as _alerts_now


def _now() -> datetime:
    return datetime.now(UTC)


# ============================================================================
# Test doubles: Redis client (service-layer broadcast tests)
# ============================================================================


@dataclass
class RecordingRedisClient:
    """Captures every ``publish`` call -- enough for the service-layer
    broadcast tests below, which only assert *what* would have been
    published, not an end-to-end relay (that is what the WebSocket section
    covers, against ``FakeRedisBus``)."""

    published: list[tuple[str, dict[str, object]]] = field(default_factory=list)

    async def publish(self, channel: str, message: str) -> int:
        self.published.append((channel, json.loads(message)))
        return 1


# ============================================================================
# Test doubles: a real, thread-safe in-memory Redis pub/sub (WebSocket tests)
# ============================================================================


class FakeRedisPubSub:
    """Stand-in for ``redis.asyncio.client.PubSub``. Bound to whichever
    ``asyncio`` event loop is running when it is created (mirrors real
    redis-py: ``pubsub()`` is called from inside the request-handling
    coroutine) -- ``deliver`` (called from a *different* thread, the test's
    own, since ``fastapi.testclient.TestClient`` runs the ASGI app in a
    background thread) uses ``loop.call_soon_threadsafe`` to safely inject a
    message across that thread boundary, the standard correct pattern for
    cross-thread ``asyncio`` communication."""

    def __init__(self, bus: FakeRedisBus) -> None:
        self.bus = bus
        self._queue: asyncio.Queue = asyncio.Queue()
        self._loop = asyncio.get_event_loop()
        self._channels: set[str] = set()

    async def subscribe(self, *channels: str) -> None:
        for channel in channels:
            self._channels.add(channel)
            self.bus.register(channel, self)

    async def unsubscribe(self, *channels: str) -> None:
        target = channels or tuple(self._channels)
        for channel in target:
            self.bus.unregister(channel, self)
            self._channels.discard(channel)

    async def aclose(self) -> None:
        await self.unsubscribe()

    async def listen(self):
        while True:
            item = await self._queue.get()
            if item is None:
                return
            yield item

    def deliver(self, channel: str, data: str) -> None:
        self._loop.call_soon_threadsafe(
            self._queue.put_nowait,
            {"type": "message", "channel": channel, "data": data},
        )


class FakeRedisBus:
    """Stand-in for ``redis.asyncio.Redis`` -- just enough surface
    (``pubsub()``/``publish()``) for the WebSocket relay code in
    ``router.py``."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[FakeRedisPubSub]] = {}
        self._lock = threading.Lock()

    def pubsub(self) -> FakeRedisPubSub:
        return FakeRedisPubSub(self)

    def register(self, channel: str, sub: FakeRedisPubSub) -> None:
        with self._lock:
            self._subscribers.setdefault(channel, []).append(sub)

    def unregister(self, channel: str, sub: FakeRedisPubSub) -> None:
        with self._lock:
            subs = self._subscribers.get(channel, [])
            if sub in subs:
                subs.remove(sub)

    def subscriber_count(self, channel: str) -> int:
        with self._lock:
            return len(self._subscribers.get(channel, []))

    async def publish(self, channel: str, message: str) -> int:
        with self._lock:
            subs = list(self._subscribers.get(channel, []))
        for sub in subs:
            sub.deliver(channel, message)
        return len(subs)


@dataclass
class FakeUser:
    id: uuid.UUID
    email: str = "user@example.com"
    username: str | None = "user"
    is_active: bool = True
    is_verified: bool = True
    data_masking_enabled: bool = True
    mfa_enabled: bool = False


@dataclass
class FakeWsAuthRepository:
    users: dict[uuid.UUID, FakeUser] = field(default_factory=dict)

    async def get_user_by_id(self, user_id: uuid.UUID) -> FakeUser | None:
        return self.users.get(user_id)


@dataclass
class FakeAccessValidator:
    allowed_keys: set[str] = field(default_factory=set)

    async def has_permission(
        self, user_id, permission_key, *, scope_type=None, scope_context=None
    ) -> bool:
        return permission_key in self.allowed_keys


def _publish(bus: FakeRedisBus, message: dict[str, object]) -> None:
    asyncio.run(bus.publish(MONITORING_LIVE_CHANNEL, json.dumps(message)))


def _make_ws_client(*, allowed_keys: set[str]) -> tuple[TestClient, FakeRedisBus, str]:
    app = create_app()
    bus = FakeRedisBus()
    auth_repo = FakeWsAuthRepository()
    validator = FakeAccessValidator(allowed_keys=allowed_keys)
    user_id = uuid.uuid4()
    auth_repo.users[user_id] = FakeUser(id=user_id)

    app.dependency_overrides[get_redis_client] = lambda: bus
    app.dependency_overrides[get_auth_repository] = lambda: auth_repo
    app.dependency_overrides[get_access_validator] = lambda: validator

    token, _ = JWTManager.create_access_token(str(user_id), "user@example.com")
    return TestClient(app), bus, token


# ============================================================================
# Service-layer: Health Engine broadcast
# ============================================================================


async def test_health_status_transition_publishes_live_message():
    repo = FakeMonitoringRepository()
    redis_client = RecordingRedisClient()
    service = MonitoringService(
        repo,
        redis_client,
        Settings(),
        auth_repository=FakeAuthRepository(),
        wireguard_service=FakeWireGuardService(),
    )
    result = await service.check_database_health()
    await service._persist_result(result)

    health_messages = [
        payload
        for channel, payload in redis_client.published
        if channel == MONITORING_LIVE_CHANNEL
        and payload["type"] == RealtimeMessageType.HEALTH_TRANSITION.value
    ]
    assert len(health_messages) == 1
    assert health_messages[0]["payload"]["component"] == "database"
    assert health_messages[0]["payload"]["new_status"] == "healthy"
    assert health_messages[0]["payload"]["previous_status"] is None


async def test_health_status_no_transition_does_not_publish_twice():
    repo = FakeMonitoringRepository()
    redis_client = RecordingRedisClient()
    service = MonitoringService(
        repo,
        redis_client,
        Settings(),
        auth_repository=FakeAuthRepository(),
        wireguard_service=FakeWireGuardService(),
    )
    result = await service.check_database_health()
    await service._persist_result(result)
    await service._persist_result(result)  # same status again -- no transition

    health_messages = [
        payload
        for channel, payload in redis_client.published
        if payload["type"] == RealtimeMessageType.HEALTH_TRANSITION.value
    ]
    assert len(health_messages) == 1


# ============================================================================
# Service-layer: Alert Engine broadcast
# ============================================================================


async def test_alert_triggered_publishes_live_message():
    repo = FakeRepository()
    redis_client = RecordingRedisClient()
    service = AlertService(repo, redis_client=redis_client)
    rule = await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component="database",
            condition_config={"expected_status": "unhealthy"},
        )
    )
    repo.service_health_rows["database"] = ServiceHealth(
        **_base_fields(
            component="database",
            status="unhealthy",
            last_checked_at=_alerts_now(),
            consecutive_failure_count=1,
        )
    )

    result = await service.evaluate_alert_rules()
    assert len(result.triggered) == 1

    triggered_messages = [
        payload
        for channel, payload in redis_client.published
        if payload["type"] == RealtimeMessageType.ALERT_TRIGGERED.value
    ]
    assert len(triggered_messages) == 1
    assert triggered_messages[0]["payload"]["rule_id"] == str(rule.id)


async def test_alert_auto_resolved_publishes_live_message():
    repo = FakeRepository()
    redis_client = RecordingRedisClient()
    service = AlertService(repo, redis_client=redis_client)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component="database",
            condition_config={"expected_status": "unhealthy"},
        )
    )
    repo.service_health_rows["database"] = ServiceHealth(
        **_base_fields(
            component="database",
            status="unhealthy",
            last_checked_at=_alerts_now(),
            consecutive_failure_count=1,
        )
    )
    await service.evaluate_alert_rules()
    redis_client.published.clear()

    repo.service_health_rows["database"].status = "healthy"
    result = await service.evaluate_alert_rules()
    assert len(result.resolved) == 1

    resolved_messages = [
        payload
        for channel, payload in redis_client.published
        if payload["type"] == RealtimeMessageType.ALERT_RESOLVED.value
    ]
    assert len(resolved_messages) == 1
    assert resolved_messages[0]["payload"]["auto_resolved"] is True


async def test_alert_service_without_redis_client_never_raises():
    """Regression: ``redis_client`` defaults to ``None`` -- every existing
    caller/test that constructs ``AlertService`` without one (all of
    ``test_monitoring_alerts.py``) must keep behaving exactly as before."""
    repo = FakeRepository()
    service = AlertService(repo)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component="database",
            condition_config={"expected_status": "unhealthy"},
        )
    )
    repo.service_health_rows["database"] = ServiceHealth(
        **_base_fields(
            component="database",
            status="unhealthy",
            last_checked_at=_alerts_now(),
            consecutive_failure_count=1,
        )
    )
    result = await service.evaluate_alert_rules()
    assert len(result.triggered) == 1


# ============================================================================
# Guest-session broadcast hook (app.domains.guest.service.GuestService)
# ============================================================================


@dataclass
class FakeMonitoringHook:
    calls: list[dict[str, object]] = field(default_factory=list)
    should_raise: bool = False

    async def broadcast_guest_session_event(self, **kwargs: object) -> None:
        if self.should_raise:
            raise RuntimeError("boom")
        self.calls.append(kwargs)


async def test_login_via_otp_fires_monitoring_hook_without_altering_result():
    fx = make_fixture()
    hook = FakeMonitoringHook()
    fx.guest_service.monitoring_hook = hook

    result = await fx.guest_service.login_via_otp(
        identifier="+15551234567",
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac="aa:bb:cc:dd:ee:ff",
    )

    # The hook must never change login's own existing return contract.
    assert result.is_new_guest is True
    assert result.session.status == "active"

    assert len(hook.calls) == 1
    call = hook.calls[0]
    assert call["message_type"] == RealtimeMessageType.GUEST_SESSION_STARTED
    assert call["session_id"] == result.session.id
    assert call["guest_id"] == result.guest.id
    assert call["router_id"] == fx.router.id
    assert call["location_id"] == fx.location_id
    assert call["is_new_guest"] is True


async def test_login_via_voucher_fires_monitoring_hook():
    fx = make_fixture()
    hook = FakeMonitoringHook()
    fx.guest_service.monitoring_hook = hook
    fx.voucher_service.register("VOUCHER1", data_limit_mb=500, validity_minutes=120)

    result = await fx.guest_service.login_via_voucher(
        code="VOUCHER1",
        identifier="voucher-guest@example.com",
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
    )

    assert len(hook.calls) == 1
    assert hook.calls[0]["session_id"] == result.session.id
    assert hook.calls[0]["auth_method"] == "voucher"


async def test_monitoring_hook_failure_never_breaks_login():
    fx = make_fixture()
    hook = FakeMonitoringHook(should_raise=True)
    fx.guest_service.monitoring_hook = hook

    result = await fx.guest_service.login_via_otp(
        identifier="+15559998888",
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
    )
    # Login succeeded despite the hook raising.
    assert result.session.status == "active"


async def test_login_without_monitoring_hook_still_works():
    """Regression: the default (``monitoring_hook=None``, i.e. every
    pre-existing ``make_fixture()`` caller in ``test_guest.py``) behaves
    exactly as before -- no broadcast attempt, no error."""
    fx = make_fixture()
    assert fx.guest_service.monitoring_hook is None

    result = await fx.guest_service.login_via_otp(
        identifier="+15551110000",
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
    )
    assert result.session.status == "active"


# ============================================================================
# WebSocket endpoints: connect / relay / filter / auth / disconnect cleanup
# ============================================================================


def test_dashboard_websocket_relays_matching_and_filters_session_messages():
    client, bus, token = _make_ws_client(allowed_keys={"monitoring.read"})
    with client.websocket_connect(
        f"/api/v1/monitoring/ws/dashboard?token={token}"
    ) as websocket:
        _publish(
            bus,
            {
                "type": RealtimeMessageType.HEALTH_TRANSITION.value,
                "payload": {"component": "database", "new_status": "unhealthy"},
                "occurred_at": _now().isoformat(),
            },
        )
        received = websocket.receive_json()
        assert received["type"] == RealtimeMessageType.HEALTH_TRANSITION.value

        # A session-only message must NOT be relayed to this endpoint.
        _publish(
            bus,
            {
                "type": RealtimeMessageType.GUEST_SESSION_STARTED.value,
                "payload": {"session_id": str(uuid.uuid4())},
                "occurred_at": _now().isoformat(),
            },
        )
        _publish(
            bus,
            {
                "type": RealtimeMessageType.ALERT_TRIGGERED.value,
                "payload": {"alert_id": str(uuid.uuid4())},
                "occurred_at": _now().isoformat(),
            },
        )
        received_next = websocket.receive_json()
        assert received_next["type"] == RealtimeMessageType.ALERT_TRIGGERED.value


def test_sessions_websocket_relays_only_session_messages():
    client, bus, token = _make_ws_client(allowed_keys={"guest_sessions.read"})
    with client.websocket_connect(
        f"/api/v1/monitoring/ws/sessions?token={token}"
    ) as websocket:
        _publish(
            bus,
            {
                "type": RealtimeMessageType.HEALTH_TRANSITION.value,
                "payload": {},
                "occurred_at": _now().isoformat(),
            },
        )
        _publish(
            bus,
            {
                "type": RealtimeMessageType.GUEST_SESSION_STARTED.value,
                "payload": {"session_id": str(uuid.uuid4())},
                "occurred_at": _now().isoformat(),
            },
        )
        received = websocket.receive_json()
        assert received["type"] == RealtimeMessageType.GUEST_SESSION_STARTED.value


def test_websocket_rejects_missing_token():
    client, _bus, _token = _make_ws_client(allowed_keys={"monitoring.read"})
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect("/api/v1/monitoring/ws/dashboard") as websocket,
    ):
        websocket.receive_json()


def test_websocket_rejects_insufficient_permission():
    client, _bus, token = _make_ws_client(allowed_keys=set())
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect(
            f"/api/v1/monitoring/ws/dashboard?token={token}"
        ) as websocket,
    ):
        websocket.receive_json()


def test_websocket_disconnect_unsubscribes_from_redis_channel():
    client, bus, token = _make_ws_client(allowed_keys={"monitoring.read"})
    with client.websocket_connect(f"/api/v1/monitoring/ws/dashboard?token={token}"):
        assert bus.subscriber_count(MONITORING_LIVE_CHANNEL) == 1

    # Cleanup (unsubscribe/close) happens in a `finally` block on the
    # server side after the disconnect is detected -- poll briefly rather
    # than assume it has already completed the instant the client-side
    # context manager returns.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if bus.subscriber_count(MONITORING_LIVE_CHANNEL) == 0:
            break
        time.sleep(0.02)
    assert bus.subscriber_count(MONITORING_LIVE_CHANNEL) == 0
