"""Security detection sweep engine and the telemetry hooks it relies on.

No database: rules are stubbed, the session is a recorder. The SQL of each
rule is exercised against a real Postgres in
``test_security_detections_postgres.py``.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from app.common.exceptions import CloudGuestError, register_exception_handlers
from app.core.celery_app import celery_app
from app.core.config import Settings
from app.domains.monitoring import security_detections as sd
from app.domains.monitoring.security_detection_constants import (
    TASK_SECURITY_DETECTION_SWEEP,
)
from app.domains.rbac.repository import _with_impersonator
from app.middleware.rate_limit import _key_type
from app.middleware.request_context import (
    MaskingContext,
    RequestContextMiddleware,
    get_masking_context,
    masking_context,
)

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key: str):
        return self.store.get(key)

    async def set(self, key: str, value: str, *, nx: bool = False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def delete(self, *keys: str) -> int:
        return sum(self.store.pop(k, None) is not None for k in keys)


class FakeSession:
    def __init__(self, sink: list, *, fail_commit: bool = False) -> None:
        self.sink = sink
        self.fail_commit = fail_commit
        self.statements: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def execute(self, statement, params=None):
        self.statements.append(str(statement))

    async def rollback(self) -> None:
        return None

    def add(self, obj) -> None:
        self.sink.append(obj)

    async def commit(self) -> None:
        if self.fail_commit:
            raise RuntimeError("db down")


class Factory:
    def __init__(self, *, fail_commit: bool = False) -> None:
        self.events: list = []
        self.sessions: list[FakeSession] = []
        self.fail_commit = fail_commit

    def __call__(self) -> FakeSession:
        session = FakeSession(self.events, fail_commit=self.fail_commit)
        self.sessions.append(session)
        return session


class EmailSpy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, subject: str, body: str) -> int:
        self.calls.append((subject, body))
        return 1


def settings(**overrides) -> SimpleNamespace:
    values = {
        name: info.default
        for name, info in Settings.model_fields.items()
        if name.startswith("security_detection_")
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def hit(rule="r", subject="s", priority=sd.P1, **details) -> sd.DetectionHit:
    return sd.DetectionHit(
        rule=rule,
        subject=subject,
        priority=priority,
        title=f"title {rule}",
        message=f"message {rule}",
        organization_id="org-1",
        details=details,
    )


def static_rule(name: str, hits: list[sd.DetectionHit], **kwargs) -> sd.DetectionRule:
    async def run(session, window, cfg):
        return list(hits)

    return sd.DetectionRule(name, run, **kwargs)


async def sweep(factory, redis, email, rules, now=NOW, **overrides):
    return await sd.run_security_detection_sweep(
        session_factory=factory,
        redis=redis,
        settings=settings(**overrides),
        send_email=email,
        rules=rules,
        now=now,
    )


# ============================================================================
# Sweep engine
# ============================================================================


class TestSweep:
    async def test_hit_writes_security_event_and_emails(self) -> None:
        factory, redis, email = Factory(), FakeRedis(), EmailSpy()
        result = await sweep(factory, redis, email, [static_rule("a", [hit("a")])])
        assert result.new_hits == 1 and result.events_written == 1
        [event] = factory.events
        assert event.category == "security"
        assert event.event_type == "security.a"
        assert event.severity == "critical"
        assert event.organization_id is None
        assert event.event_metadata["organization_id"] == "org-1"
        assert event.event_metadata["subject_hash"] != "s"
        assert len(email.calls) == 1

    async def test_clean_rules_write_nothing(self) -> None:
        factory, email = Factory(), EmailSpy()
        result = await sweep(factory, FakeRedis(), email, [static_rule("a", [])])
        assert result.hits == 0
        assert factory.events == []
        assert email.calls == []

    async def test_dedup_within_and_across_sweeps(self) -> None:
        factory, redis, email = Factory(), FakeRedis(), EmailSpy()
        rules = [static_rule("a", [hit("a", "x"), hit("a", "x")])]
        first = await sweep(factory, redis, email, rules)
        second = await sweep(
            factory, redis, email, rules, now=NOW + timedelta(minutes=5)
        )
        assert (first.new_hits, second.new_hits) == (1, 0)
        assert len(factory.events) == 1
        assert len(email.calls) == 1
        [dedup_key] = [k for k in redis.store if ":dedup:" in k]
        assert redis.ttls[dedup_key] == 24 * 3600
        assert "x" not in dedup_key.rsplit(":", 1)[1]  # subject is hashed

    async def test_dedup_is_per_rule_and_subject(self) -> None:
        factory, redis, email = Factory(), FakeRedis(), EmailSpy()
        await sweep(
            factory,
            redis,
            email,
            [
                static_rule("a", [hit("a", "x"), hit("a", "y")]),
                static_rule("b", [hit("b", "x")]),
            ],
        )
        assert len(factory.events) == 3
        assert len(email.calls) == 1  # one digest, not one email per hit

    async def test_dedup_expiry_reports_again(self) -> None:
        factory, redis, email = Factory(), FakeRedis(), EmailSpy()
        rules = [static_rule("a", [hit("a", "x")])]
        await sweep(factory, redis, email, rules)
        for key in [k for k in redis.store if ":dedup:" in k]:
            del redis.store[key]  # what the 24h TTL does
        again = await sweep(factory, redis, email, rules, now=NOW + timedelta(days=1))
        assert again.new_hits == 1
        assert len(email.calls) == 2

    async def test_disabled_flag_runs_nothing(self) -> None:
        factory, email = Factory(), EmailSpy()
        result = await sweep(
            factory,
            FakeRedis(),
            email,
            [static_rule("a", [hit("a")])],
            security_detection_enabled=False,
        )
        assert result.status == "disabled"
        assert factory.sessions == []

    async def test_overlapping_sweep_is_skipped(self) -> None:
        factory, redis, email = Factory(), FakeRedis(), EmailSpy()
        await redis.set("security_detection:lock", "1", nx=True, ex=60)
        result = await sweep(factory, redis, email, [static_rule("a", [hit("a")])])
        assert result.status == "locked"
        assert factory.sessions == []

    async def test_lock_released_after_run(self) -> None:
        redis = FakeRedis()
        await sweep(Factory(), redis, EmailSpy(), [static_rule("a", [])])
        assert "security_detection:lock" not in redis.store

    async def test_rule_runs_read_only_with_statement_timeout(self) -> None:
        factory = Factory()
        await sweep(
            factory,
            FakeRedis(),
            EmailSpy(),
            [static_rule("a", [])],
            security_detection_statement_timeout_ms=1234,
        )
        statements = factory.sessions[0].statements
        assert statements[:2] == [
            "SET TRANSACTION READ ONLY",
            "SET LOCAL statement_timeout = 1234",
        ]

    async def test_failing_rule_is_isolated_and_keeps_its_watermark(self) -> None:
        async def boom(session, window, cfg):
            raise RuntimeError("canceling statement due to statement timeout")

        factory, redis, email = Factory(), FakeRedis(), EmailSpy()
        result = await sweep(
            factory,
            redis,
            email,
            [sd.DetectionRule("bad", boom), static_rule("good", [hit("good")])],
        )
        assert result.rule_errors == {"bad": "RuntimeError"}
        assert result.new_hits == 1
        assert "security_detection:watermark:good" in redis.store
        assert "security_detection:watermark:bad" not in redis.store

    async def test_event_write_failure_releases_dedup_claims(self) -> None:
        redis = FakeRedis()
        with pytest.raises(RuntimeError):
            await sweep(
                Factory(fail_commit=True),
                redis,
                EmailSpy(),
                [static_rule("a", [hit("a")])],
            )
        assert not [k for k in redis.store if ":dedup:" in k]
        retry = await sweep(
            Factory(), redis, EmailSpy(), [static_rule("a", [hit("a")])]
        )
        assert retry.new_hits == 1

    async def test_hits_per_rule_are_capped(self) -> None:
        many = [hit("a", str(i)) for i in range(10)]
        factory = Factory()
        await sweep(
            factory,
            FakeRedis(),
            EmailSpy(),
            [static_rule("a", many)],
            security_detection_max_hits_per_rule=3,
        )
        assert len(factory.events) == 3


class TestWindow:
    async def _window(self, redis, rule, now=NOW, lookback=60):
        captured = {}

        async def run(session, window, cfg):
            captured["w"] = window
            return []

        await sweep(
            Factory(),
            redis,
            EmailSpy(),
            [sd.DetectionRule("w", run, windowed=rule)],
            now=now,
            security_detection_max_lookback_minutes=lookback,
        )
        return captured["w"]

    async def test_first_run_looks_back_15_minutes(self) -> None:
        window = await self._window(FakeRedis(), True)
        assert window.since == NOW - timedelta(minutes=15)

    async def test_watermark_minus_overlap(self) -> None:
        redis = FakeRedis()
        redis.store["security_detection:watermark:w"] = (
            NOW - timedelta(minutes=5)
        ).isoformat()
        window = await self._window(redis, True)
        assert window.since == NOW - timedelta(minutes=7)
        assert redis.store["security_detection:watermark:w"] == NOW.isoformat()

    async def test_stale_watermark_is_clamped(self) -> None:
        redis = FakeRedis()
        redis.store["security_detection:watermark:w"] = (
            NOW - timedelta(days=3)
        ).isoformat()
        window = await self._window(redis, True, lookback=60)
        assert window.since == NOW - timedelta(minutes=60)

    async def test_rolling_rules_ignore_watermark(self) -> None:
        redis = FakeRedis()
        window = await self._window(redis, False)
        assert window.now == NOW
        assert "security_detection:watermark:w" not in redis.store


class TestEmail:
    def test_digest_orders_by_priority_and_skips_none(self) -> None:
        subject, body = sd.format_alert_email(
            [
                hit("low", priority=sd.P2, account="v****n@example.com"),
                hit("high", priority=sd.P1, router_id=None),
            ]
        )
        assert subject == "[Wyfy security] P1: 2 new detections -- title high"
        assert body.index("title high") < body.index("title low")
        assert "account: v****n@example.com" in body
        assert "router_id" not in body

    async def test_platform_email_goes_to_every_recipient(self, monkeypatch) -> None:
        sent: list[str] = []

        class Provider:
            async def send(self, to, subject, body):
                if to == "bad@x.com":
                    raise RuntimeError("smtp")
                sent.append(to)

        monkeypatch.setattr(
            sd,
            "get_settings",
            lambda: SimpleNamespace(
                platform_alert_email_list=("a@x.com", "bad@x.com", "b@x.com")
            ),
        )
        monkeypatch.setattr(
            "app.domains.otp.service.get_configured_email_provider",
            lambda settings: Provider(),
        )
        assert await sd.send_platform_alert_email("s", "b") == 2
        assert sent == ["a@x.com", "b@x.com"]


class TestWiring:
    def test_thresholds_come_from_settings(self) -> None:
        cfg = sd.Thresholds.from_settings(settings(security_detection_sms_hourly_max=7))
        assert cfg.sms_hourly_max == 7
        assert cfg.venueless_otp_hourly_max == 20

    def test_defaults(self) -> None:
        defaults = settings()
        assert defaults.security_detection_enabled is True
        assert defaults.security_detection_dedup_hours == 24

    def test_beat_schedule_every_five_minutes(self) -> None:
        entry = celery_app.conf.beat_schedule["security-detection-sweep"]
        assert entry["task"] == TASK_SECURITY_DETECTION_SWEEP
        assert entry["schedule"] == 300.0
        assert TASK_SECURITY_DETECTION_SWEEP in celery_app.tasks

    def test_every_p1_rule_from_the_report_is_registered(self) -> None:
        names = {rule.name for rule in sd.RULES}
        assert {
            "tenant_role_platform_key",
            "tenant_role_global_scope",
            "tenant_role_inherits_platform_role",
            "credential_reveal_by_non_operator",
            "platform_action_by_tenant",
            "otp_sms_volume",
            "otp_venueless_volume",
            "billing_webhook_unmatched",
            "voucher_cross_tenant",
        } <= names


# ============================================================================
# Telemetry hooks
# ============================================================================


class TestImpersonatorOnAudit:
    def test_adds_impersonator_inside_impersonated_request(self) -> None:
        token = masking_context.set(MaskingContext(impersonator_user_id="op-1"))
        try:
            fields = _with_impersonator(
                {"action": "router_credentials_revealed", "event_metadata": {"a": 1}}
            )
        finally:
            masking_context.reset(token)
        assert fields["event_metadata"] == {"a": 1, "impersonator_user_id": "op-1"}

    def test_handles_missing_metadata(self) -> None:
        token = masking_context.set(MaskingContext(impersonator_user_id="op-1"))
        try:
            fields = _with_impersonator({"action": "x"})
        finally:
            masking_context.reset(token)
        assert fields["event_metadata"] == {"impersonator_user_id": "op-1"}

    def test_noop_without_impersonation(self) -> None:
        fields = {"action": "x", "event_metadata": {"a": 1}}
        assert _with_impersonator(fields) is fields


class TestImpersonatorFromToken:
    async def test_jwt_impersonation_claim_reaches_the_context(self) -> None:
        from fastapi.security import HTTPAuthorizationCredentials

        from app.domains.auth.dependencies import _resolve_user_from_jwt
        from app.domains.auth.jwt import JWTManager

        target = uuid.uuid4()
        token, _ = JWTManager.create_access_token(
            str(target),
            "target@cafe.example",
            additional_claims={"impersonation": {"actor_user_id": "op-9"}},
        )

        class Repo:
            async def get_user_by_id(self, user_id):
                return SimpleNamespace(
                    id=user_id, is_active=True, tokens_invalidated_at=None
                )

        context = MaskingContext()
        reset = masking_context.set(context)
        try:
            await _resolve_user_from_jwt(
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=token),
                repository=Repo(),
            )
        finally:
            masking_context.reset(reset)
        assert context.impersonator_user_id == "op-9"


class TestRateLimitKeyType:
    def test_key_types_never_carry_the_value(self) -> None:
        assert _key_type("rate_limit:1.2.3.4:/api/v1/otp/request") == "ip_path"
        assert _key_type("rate_limit:portal_resolve:venue:loc:abc") == (
            "portal_resolve_venue"
        )
        assert _key_type("rate_limit:portal_resolve:ip:1.2.3.4") == "portal_resolve_ip"


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestContextMiddleware)
    register_exception_handlers(app)

    @app.get("/ok")
    async def ok(request: Request):
        get_masking_context().user_id = "token-user"
        get_masking_context().impersonator_user_id = "op-1"
        return PlainTextResponse("ok")

    @app.get("/limited")
    async def limited():
        raise CloudGuestError("slow down", status_code=429)

    return app


def _records(caplog, message: str):
    return [r for r in caplog.records if r.getMessage() == message]


class TestRequestLog:
    def test_completed_log_has_status_ip_and_token_user(self, caplog) -> None:
        caplog.set_level(logging.INFO)
        client = TestClient(_app())
        response = client.get(
            "/ok",
            headers={"X-User-ID": str(uuid.uuid4()), "X-Forwarded-For": "9.9.9.9"},
        )
        assert response.status_code == 200
        [record] = _records(caplog, "http_request_completed")
        assert record.status_code == 200
        assert record.client_ip == "testclient"
        assert record.forwarded_for == "9.9.9.9"
        assert record.user_id == "token-user"
        assert record.impersonator_user_id == "op-1"

    def test_forwarded_for_logs_only_ip_addresses(self, caplog) -> None:
        """X-Forwarded-For is client-supplied: a phone number or token put
        there must never reach the log."""
        caplog.set_level(logging.INFO)
        TestClient(_app()).get(
            "/ok",
            headers={
                "X-Forwarded-For": "+919811122233, tok.abc.def, 2001:db8::1, 9.9.9.9"
            },
        )
        [record] = _records(caplog, "http_request_completed")
        assert record.forwarded_for == "-, -, 2001:db8::1, 9.9.9.9"
        assert "919811122233" not in caplog.text

    def test_spoofed_user_header_is_not_logged(self, caplog) -> None:
        caplog.set_level(logging.INFO)
        spoofed = str(uuid.uuid4())
        TestClient(_app()).get("/limited", headers={"X-User-ID": spoofed})
        assert spoofed not in caplog.text

    def test_429_logged_with_key_type(self, caplog) -> None:
        caplog.set_level(logging.INFO)
        response = TestClient(_app()).get("/limited")
        assert response.status_code == 429
        [record] = _records(caplog, "rate_limit_exceeded")
        assert record.key_type == "CloudGuestError"
        [done] = _records(caplog, "http_request_completed")
        assert done.status_code == 429
