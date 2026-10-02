"""Aruba Instant On client + token manager + mapping.

No network: every request goes to an ``httpx.MockTransport`` that answers
with the recorded-shape fixtures in ``instant_on_fixtures``. No secret, real
token or credential appears here.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import inspect
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from app.domains.network_integration.providers.aruba_instant_on import (
    ArubaInstantOnProvider,
    map_access_point,
    map_alert,
    map_client,
    map_client_usage,
    map_health,
    map_network,
)
from app.domains.network_integration.providers.aruba_instant_on_client import (
    InstantOnApiDriftError,
    InstantOnAuthConfig,
    InstantOnAuthError,
    InstantOnClient,
    InstantOnForbiddenError,
    InstantOnNotConfiguredError,
    InstantOnRateLimitedError,
    InstantOnTokenManager,
    InstantOnTokenState,
    InstantOnUpstreamError,
    SecretsManagerCredentialSource,
    _parse_credential_secret,
)
from tests.unit import instant_on_fixtures as fx

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
API = "https://portal.instant-on.hpe.com/api"
SSO = "https://sso.arubainstanton.com"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeStore:
    def __init__(
        self, state: InstantOnTokenState | None = None, log: list | None = None
    ):
        self.state = state or InstantOnTokenState()
        self.saves: list[InstantOnTokenState] = []
        self.log = log if log is not None else []

    async def load(self) -> InstantOnTokenState:
        return self.state

    async def save(self, state: InstantOnTokenState) -> None:
        self.state = state
        self.saves.append(state)
        self.log.append(("save", state.access_token, state.refresh_token))


class FakeLock:
    """Counts entries; ``on_acquire`` simulates another worker that renewed
    the token while we were waiting for the lock."""

    def __init__(self, on_acquire=None) -> None:  # noqa: ANN001
        self.acquired = 0
        self.held = False
        self.on_acquire = on_acquire

    @contextlib.asynccontextmanager
    async def hold(self):  # noqa: ANN201
        assert not self.held, "lock re-entered: not single-flight"
        self.held = True
        self.acquired += 1
        if self.on_acquire is not None:
            self.on_acquire()
        try:
            yield
        finally:
            self.held = False


class FakeCredentials:
    def __init__(self, username: str = "svc@example.test", password: str = "pw-test"):
        self.calls = 0
        self.username = username
        self.password = password

    async def get(self) -> tuple[str, str]:
        self.calls += 1
        return self.username, self.password


def _valid(
    access: str = "access-1", refresh: str | None = "refresh-1"
) -> InstantOnTokenState:
    return InstantOnTokenState(
        access_token=access,
        access_expires_at=NOW + timedelta(seconds=1800),
        refresh_token=refresh,
        auth_state="ok",
    )


def _expired(refresh: str | None = "refresh-1") -> InstantOnTokenState:
    return InstantOnTokenState(
        access_token="access-old",
        access_expires_at=NOW + timedelta(seconds=30),  # inside the renew margin
        refresh_token=refresh,
        auth_state="ok",
    )


class Harness:
    def __init__(
        self,
        handler,  # noqa: ANN001
        *,
        state: InstantOnTokenState | None = None,
        lock: FakeLock | None = None,
        credentials: FakeCredentials | None = None,
        api_version: int = 28,
        client_id: str = "test-public-client-id",
    ) -> None:
        self.requests: list[httpx.Request] = []
        self.log: list[tuple] = []
        self.sleeps: list[float] = []

        def recording(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            self.log.append(("http", request.method, request.url.path))
            return handler(request)

        self.http = httpx.AsyncClient(transport=httpx.MockTransport(recording))
        self.store = FakeStore(state, self.log)
        self.lock = lock or FakeLock()
        self.credentials = credentials or FakeCredentials()
        self.tokens = InstantOnTokenManager(
            http=self.http,
            store=self.store,
            lock=self.lock,
            credentials=self.credentials,
            config=InstantOnAuthConfig(
                api_base_url=API,
                sso_base_url=SSO,
                client_id=client_id,
                auth_failure_cooldown_seconds=1800,
            ),
            clock=lambda: NOW,
        )

        async def fake_sleep(seconds: float) -> None:
            self.sleeps.append(seconds)

        self.client = InstantOnClient(
            http=self.http,
            tokens=self.tokens,
            api_base_url=API,
            api_version=api_version,
            sleep=fake_sleep,
            clock=lambda: NOW,
        )

    def api_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == "portal.instant-on.hpe.com"]

    def sso_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == "sso.arubainstanton.com"]


def _form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def _token_response(access: str, refresh: str | None = None, expires: int = 1800):  # noqa: ANN202
    body: dict[str, Any] = {"access_token": access, "expires_in": expires}
    if refresh is not None:
        body["refresh_token"] = refresh
    return httpx.Response(200, json=body)


def _resource_handler(
    *, token_ok: str | None = None, refresh_to: tuple[str, str | None] | None = None
):  # noqa: ANN202
    """Answers API GETs with fixtures (401 unless the bearer is ``token_ok``
    when given) and the refresh grant with ``refresh_to``."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "sso.arubainstanton.com":
            assert refresh_to is not None, "unexpected SSO call"
            return _token_response(*refresh_to)
        if (
            token_ok is not None
            and request.headers["Authorization"] != f"Bearer {token_ok}"
        ):
            return httpx.Response(401)
        tail = request.url.path.rsplit("/", 1)[-1]
        if tail == "sites":
            return httpx.Response(200, json=fx.SITES)
        return httpx.Response(200, json=fx.RESOURCE_BODIES[tail])

    return handler


# ---------------------------------------------------------------------------
# Tokens: refresh, rotation, persistence order, single-flight
# ---------------------------------------------------------------------------


class TestTokenRefresh:
    async def test_a_valid_token_is_used_as_is(self) -> None:
        h = Harness(_resource_handler(token_ok="access-1"), state=_valid())
        await h.client.get_inventory(fx.SITE_ID)
        assert h.sso_requests() == []
        (request,) = h.api_requests()
        assert request.method == "GET"
        assert request.headers["Authorization"] == "Bearer access-1"
        assert request.headers["x-ion-api-version"] == "28"
        assert request.url.path == f"/api/sites/{fx.SITE_ID}/inventory"

    async def test_api_version_header_comes_from_config(self) -> None:
        h = Harness(_resource_handler(), state=_valid(), api_version=22)
        await h.client.get_inventory(fx.SITE_ID)
        assert h.api_requests()[0].headers["x-ion-api-version"] == "22"

    async def test_refresh_grant_sends_client_id_and_refresh_token(self) -> None:
        h = Harness(
            _resource_handler(
                token_ok="access-2", refresh_to=("access-2", "refresh-2")
            ),
            state=_expired(),
        )
        await h.client.get_inventory(fx.SITE_ID)
        (refresh,) = h.sso_requests()
        assert refresh.method == "POST"
        assert refresh.url.path == "/as/token.oauth2"
        assert _form(refresh) == {
            "grant_type": "refresh_token",
            "client_id": "test-public-client-id",
            "refresh_token": "refresh-1",
        }

    async def test_rotated_refresh_token_is_persisted_before_the_access_token_is_used(
        self,
    ) -> None:
        h = Harness(
            _resource_handler(
                token_ok="access-2", refresh_to=("access-2", "refresh-2")
            ),
            state=_expired(),
        )
        await h.client.get_inventory(fx.SITE_ID)
        assert h.store.state.refresh_token == "refresh-2"
        assert h.store.state.access_token == "access-2"
        assert h.store.state.access_expires_at == NOW + timedelta(seconds=1800)
        assert h.store.state.refresh_obtained_at == NOW
        save_at = h.log.index(("save", "access-2", "refresh-2"))
        api_at = next(
            i
            for i, e in enumerate(h.log)
            if e[0] == "http" and e[2].endswith("/inventory")
        )
        assert save_at < api_at

    async def test_a_refresh_that_does_not_rotate_keeps_the_old_refresh_token(
        self,
    ) -> None:
        h = Harness(_resource_handler(refresh_to=("access-2", None)), state=_expired())
        await h.client.get_inventory(fx.SITE_ID)
        assert h.store.state.refresh_token == "refresh-1"

    async def test_concurrent_callers_cause_exactly_one_refresh(self) -> None:
        h = Harness(
            _resource_handler(refresh_to=("access-2", "refresh-2")), state=_expired()
        )
        tokens = await asyncio.gather(*(h.tokens.get_access_token() for _ in range(20)))
        assert set(tokens) == {"access-2"}
        assert len(h.sso_requests()) == 1

    async def test_a_token_renewed_by_another_worker_while_waiting_is_reused(
        self,
    ) -> None:
        h: Harness

        def other_worker_refreshed() -> None:
            h.store.state = _valid(access="access-from-worker-b", refresh="refresh-b")

        h = Harness(
            _resource_handler(refresh_to=("never", "never")),
            state=_expired(),
            lock=FakeLock(on_acquire=other_worker_refreshed),
        )
        assert await h.tokens.get_access_token() == "access-from-worker-b"
        assert h.sso_requests() == []

    async def test_refresh_happens_under_the_cross_process_lock(self) -> None:
        lock = FakeLock()
        h = Harness(
            _resource_handler(refresh_to=("access-2", "refresh-2")),
            state=_expired(),
            lock=lock,
        )
        await h.tokens.get_access_token()
        assert lock.acquired == 1


# ---------------------------------------------------------------------------
# 401 handling
# ---------------------------------------------------------------------------


class TestUnauthorized:
    async def test_401_refreshes_once_and_retries(self) -> None:
        h = Harness(
            _resource_handler(
                token_ok="access-2", refresh_to=("access-2", "refresh-2")
            ),
            state=_valid(access="access-revoked"),
        )
        elements = await h.client.get_inventory(fx.SITE_ID)
        assert elements == fx.INVENTORY["elements"]
        assert len(h.sso_requests()) == 1
        assert [r.headers["Authorization"] for r in h.api_requests()] == [
            "Bearer access-revoked",
            "Bearer access-2",
        ]

    async def test_401_after_refresh_marks_auth_failed(self) -> None:
        h = Harness(
            _resource_handler(
                token_ok="nothing-works", refresh_to=("access-2", "refresh-2")
            ),
            state=_valid(access="access-revoked"),
        )
        with pytest.raises(InstantOnAuthError) as caught:
            await h.client.get_inventory(fx.SITE_ID)
        assert caught.value.code == "auth_failed"
        assert len(h.sso_requests()) == 1  # refreshed exactly once
        assert len(h.api_requests()) == 2
        assert h.store.state.auth_state == "auth_failed"
        assert h.store.state.access_token is None
        assert h.store.state.refresh_token is None
        assert h.store.state.login_blocked_until == NOW + timedelta(seconds=1800)

    async def test_after_auth_failure_nothing_is_sent_during_the_cooldown(self) -> None:
        h = Harness(
            _resource_handler(),
            state=InstantOnTokenState(
                auth_state="auth_failed",
                auth_error_code="login_rejected",
                login_blocked_until=NOW + timedelta(minutes=10),
            ),
        )
        with pytest.raises(InstantOnAuthError):
            await h.client.get_inventory(fx.SITE_ID)
        assert h.requests == []
        assert h.credentials.calls == 0

    async def test_401_when_another_worker_already_refreshed_uses_their_token(
        self,
    ) -> None:
        h: Harness

        def other_worker_refreshed() -> None:
            h.store.state = _valid(access="access-b", refresh="refresh-b")

        h = Harness(
            _resource_handler(token_ok="access-b", refresh_to=("never", "never")),
            state=_valid(access="access-revoked"),
            lock=FakeLock(on_acquire=other_worker_refreshed),
        )
        await h.client.get_inventory(fx.SITE_ID)
        assert h.sso_requests() == []


# ---------------------------------------------------------------------------
# Full login (initial auth / dead refresh token)
# ---------------------------------------------------------------------------


def _login_handler(
    *,
    refresh_status: int = 400,
    validate_status: int = 200,
    validate_body: dict | None = None,
    authorize_redirect: bool = True,
):  # noqa: ANN202
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.host == "sso.arubainstanton.com":
            if path == "/as/token.oauth2":
                form = _form(request)
                if form["grant_type"] == "refresh_token":
                    return httpx.Response(
                        refresh_status, json={"error": "invalid_grant"}
                    )
                seen["exchange"] = form
                return _token_response("access-login", "refresh-login")
            if path == "/aio/api/v1/mfa/validate/full":
                seen["validate"] = _form(request)
                return httpx.Response(
                    validate_status,
                    json=validate_body
                    if validate_body is not None
                    else {"access_token": "sess-1"},
                )
            if path == "/as/authorization.oauth2":
                params = {
                    k: v[0] for k, v in parse_qs(request.url.query.decode()).items()
                }
                seen["authorize"] = params
                if not authorize_redirect:
                    return httpx.Response(200, text="<html>captcha</html>")
                return httpx.Response(
                    302,
                    headers={
                        "location": "https://portal.instant-on.hpe.com/?code=code-1"
                        f"&state={params['state']}"
                    },
                )
        return httpx.Response(200, json=fx.INVENTORY)

    return handler, seen


class TestLogin:
    async def test_dead_refresh_token_falls_back_to_one_pkce_login(self) -> None:
        handler, seen = _login_handler()
        h = Harness(handler, state=_expired())
        await h.client.get_inventory(fx.SITE_ID)

        assert seen["validate"] == {
            "username": "svc@example.test",
            "password": "pw-test",
        }
        authorize = seen["authorize"]
        assert authorize["sessionToken"] == "sess-1"
        assert authorize["code_challenge_method"] == "S256"
        verifier = seen["exchange"]["code_verifier"]
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        assert authorize["code_challenge"] == expected
        assert seen["exchange"]["code"] == "code-1"
        assert seen["exchange"]["grant_type"] == "authorization_code"
        assert h.store.state.refresh_token == "refresh-login"
        assert h.store.state.auth_state == "ok"

    async def test_first_start_with_no_tokens_logs_in(self) -> None:
        handler, seen = _login_handler()
        h = Harness(handler, state=InstantOnTokenState())
        assert await h.tokens.get_access_token() == "access-login"
        assert "validate" in seen and h.credentials.calls == 1

    async def test_rejected_login_sets_cooldown_and_is_not_retried(self) -> None:
        handler, _seen = _login_handler(validate_status=401)
        h = Harness(handler, state=InstantOnTokenState())
        with pytest.raises(InstantOnAuthError) as caught:
            await h.tokens.get_access_token()
        assert caught.value.reason == "login_rejected"
        assert h.store.state.login_blocked_until == NOW + timedelta(seconds=1800)
        sent = len(h.requests)
        with pytest.raises(InstantOnAuthError):
            await h.tokens.get_access_token()
        assert len(h.requests) == sent  # no second login inside the cooldown

    async def test_a_challenge_is_not_answered(self) -> None:
        handler, _seen = _login_handler(validate_body={"mfaRequired": True})
        h = Harness(handler, state=InstantOnTokenState())
        with pytest.raises(InstantOnAuthError) as caught:
            await h.tokens.get_access_token()
        assert caught.value.reason == "login_challenge"

    async def test_no_authorization_code_is_auth_failed(self) -> None:
        handler, _seen = _login_handler(authorize_redirect=False)
        h = Harness(handler, state=InstantOnTokenState())
        with pytest.raises(InstantOnAuthError) as caught:
            await h.tokens.get_access_token()
        assert caught.value.reason == "authorization_code_missing"

    async def test_client_id_is_discovered_from_portal_settings_when_unset(
        self,
    ) -> None:
        handler, seen = _login_handler()

        def with_settings(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/settings.json":
                return httpx.Response(200, json=fx.PORTAL_SETTINGS)
            return handler(request)

        h = Harness(with_settings, state=InstantOnTokenState(), client_id="")
        await h.tokens.get_access_token()
        assert seen["exchange"]["client_id"] == "test-public-client-id"
        settings_get = [r for r in h.requests if r.url.path == "/settings.json"]
        assert settings_get and settings_get[0].method == "GET"


class TestCredentialSource:
    async def test_no_arn_is_not_configured_and_makes_no_call(self) -> None:
        source = SecretsManagerCredentialSource(secret_arn="", region_name="ap-south-1")
        with pytest.raises(InstantOnNotConfiguredError):
            await source.get()

    def test_secret_shape(self) -> None:
        assert _parse_credential_secret('{"username": "u", "password": "p"}') == (
            "u",
            "p",
        )
        assert _parse_credential_secret('{"email": "u", "password": "p"}') == ("u", "p")
        for bad in (
            "not json",
            "[]",
            '{"username": "u"}',
            '{"username": "", "password": "p"}',
        ):
            with pytest.raises(InstantOnNotConfiguredError):
                _parse_credential_secret(bad)

    def test_tokens_never_appear_in_a_repr(self) -> None:
        state = InstantOnTokenState(access_token="SECRET-A", refresh_token="SECRET-R")
        assert "SECRET" not in repr(state)


# ---------------------------------------------------------------------------
# 429 / 5xx / timeouts / drift / forbidden
# ---------------------------------------------------------------------------


def _sequence(*responses):  # noqa: ANN202
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    return handler


class TestTransientAndDrift:
    async def test_short_retry_after_is_waited_inline_once(self) -> None:
        h = Harness(
            _sequence(
                httpx.Response(429, headers={"Retry-After": "2"}),
                httpx.Response(200, json=fx.INVENTORY),
            ),
            state=_valid(),
        )
        assert await h.client.get_inventory(fx.SITE_ID) == fx.INVENTORY["elements"]
        assert h.sleeps == [2]

    async def test_long_retry_after_is_returned_as_rate_limited(self) -> None:
        h = Harness(
            _sequence(httpx.Response(429, headers={"Retry-After": "120"})),
            state=_valid(),
        )
        with pytest.raises(InstantOnRateLimitedError) as caught:
            await h.client.get_inventory(fx.SITE_ID)
        assert caught.value.retry_after_seconds == 120
        assert caught.value.code == "rate_limited"
        assert h.sleeps == []

    async def test_retry_after_as_an_http_date(self) -> None:
        when = (NOW + timedelta(seconds=300)).strftime("%a, %d %b %Y %H:%M:%S GMT")
        h = Harness(
            _sequence(httpx.Response(429, headers={"Retry-After": when})),
            state=_valid(),
        )
        with pytest.raises(InstantOnRateLimitedError) as caught:
            await h.client.get_inventory(fx.SITE_ID)
        assert caught.value.retry_after_seconds == 300

    async def test_429_without_retry_after_backs_off_a_default(self) -> None:
        h = Harness(_sequence(httpx.Response(429)), state=_valid())
        with pytest.raises(InstantOnRateLimitedError) as caught:
            await h.client.get_inventory(fx.SITE_ID)
        assert caught.value.retry_after_seconds == 60

    async def test_5xx_is_retried_once_then_upstream_error(self) -> None:
        h = Harness(_sequence(httpx.Response(502), httpx.Response(503)), state=_valid())
        with pytest.raises(InstantOnUpstreamError):
            await h.client.get_inventory(fx.SITE_ID)
        assert len(h.api_requests()) == 2

    async def test_5xx_then_success(self) -> None:
        h = Harness(
            _sequence(httpx.Response(500), httpx.Response(200, json=fx.INVENTORY)),
            state=_valid(),
        )
        assert await h.client.get_inventory(fx.SITE_ID) == fx.INVENTORY["elements"]

    async def test_timeouts_are_retried_once_then_upstream_error(self) -> None:
        h = Harness(
            _sequence(httpx.ReadTimeout("t"), httpx.ReadTimeout("t")), state=_valid()
        )
        with pytest.raises(InstantOnUpstreamError) as caught:
            await h.client.get_inventory(fx.SITE_ID)
        assert caught.value.reason == "timeout"

    @pytest.mark.parametrize("status", [400, 406, 410, 412, 415, 422, 302])
    async def test_a_refused_known_read_is_drift(self, status: int) -> None:
        h = Harness(_sequence(httpx.Response(status)), state=_valid())
        with pytest.raises(InstantOnApiDriftError) as caught:
            await h.client.get_inventory(fx.SITE_ID)
        assert caught.value.code == "incompatible"

    @pytest.mark.parametrize(
        "body",
        [
            {"items": []},
            {"elements": "nope"},
            {"elements": [1, 2]},
            [],
        ],
    )
    async def test_an_unexpected_shape_is_drift(self, body: Any) -> None:
        h = Harness(_sequence(httpx.Response(200, json=body)), state=_valid())
        with pytest.raises(InstantOnApiDriftError):
            await h.client.get_inventory(fx.SITE_ID)

    async def test_a_non_json_body_is_drift(self) -> None:
        h = Harness(_sequence(httpx.Response(200, text="<html>")), state=_valid())
        with pytest.raises(InstantOnApiDriftError) as caught:
            await h.client.get_inventory(fx.SITE_ID)
        assert caught.value.reason == "non_json"

    async def test_drift_is_logged_under_one_alertable_event_name(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        from app.domains.network_integration.providers import aruba_instant_on_client

        events: list[tuple[str, dict]] = []
        monkeypatch.setattr(
            aruba_instant_on_client.logger,
            "error",
            lambda event, extra=None: events.append((event, extra or {})),
        )
        h = Harness(_sequence(httpx.Response(406)), state=_valid())
        with pytest.raises(InstantOnApiDriftError):
            await h.client.get_inventory(fx.SITE_ID)
        assert events and events[0][0] == "instant_on_api_drift"
        assert events[0][1]["reason"] == "http_406"

    @pytest.mark.parametrize("status", [403, 404])
    async def test_forbidden_or_unknown_site_is_not_invited(self, status: int) -> None:
        h = Harness(_sequence(httpx.Response(status)), state=_valid())
        with pytest.raises(InstantOnForbiddenError) as caught:
            await h.client.get_inventory(fx.SITE_ID)
        assert caught.value.code == "not_invited"

    @pytest.mark.parametrize("site_id", ["../admin", "a/b", "", "x" * 200, "a?b=c"])
    async def test_a_malformed_site_id_never_reaches_the_wire(
        self, site_id: str
    ) -> None:
        h = Harness(_resource_handler(), state=_valid())
        with pytest.raises(ValueError):
            await h.client.get_inventory(site_id)
        assert h.requests == []


# ---------------------------------------------------------------------------
# Read-only, structurally
# ---------------------------------------------------------------------------

_WRITE_WORDS = (
    "post",
    "put",
    "patch",
    "delete",
    "create",
    "update",
    "set",
    "write",
    "block",
    "unblock",
    "authorize",
    "deauthorize",
    "configure",
    "disconnect",
    "request",
    "send",
    "execute",
    "action",
    "reboot",
    "upgrade",
)


class TestNoWriteMethods:
    def test_the_client_exposes_only_reads(self) -> None:
        public = [
            n for n, _ in inspect.getmembers(InstantOnClient) if not n.startswith("_")
        ]
        assert public, "no public methods found"
        for name in public:
            assert name.startswith(("get_", "list_")), name
            assert not any(
                word in name for word in _WRITE_WORDS if word not in ("set",)
            ), name

    def test_the_request_primitive_takes_no_method(self) -> None:
        params = inspect.signature(InstantOnClient._get_json).parameters
        assert "method" not in params

    async def test_every_public_method_sends_only_get_to_the_api(self) -> None:
        h = Harness(_resource_handler(), state=_valid())
        for name, member in inspect.getmembers(h.client, inspect.ismethod):
            if name.startswith("_"):
                continue
            args = [] if name == "list_sites" else [fx.SITE_ID]
            await member(*args)
        assert h.api_requests()
        assert {r.method for r in h.api_requests()} == {"GET"}

    def test_the_provider_has_no_write_half(self) -> None:
        for name in (
            "authorize_guest",
            "authorize_guest_via_radius_portal",
            "deauthorize_guest",
            "configure_controller",
            "set_client_rate_limit",
            "clear_client_rate_limit",
            "block_client",
            "unblock_client",
            "list_blocked_clients",
            "inspect_tls",
        ):
            assert not hasattr(ArubaInstantOnProvider, name), name

    def test_the_provider_is_not_in_the_integration_registry(self) -> None:
        from app.domains.network_integration.exceptions import (
            UnsupportedNetworkProviderError,
        )
        from app.domains.network_integration.providers import (
            get_network_provider,
            list_supported_providers,
        )

        assert "aruba_instant_on" not in list_supported_providers()
        with pytest.raises(UnsupportedNetworkProviderError):
            get_network_provider("aruba_instant_on")

    def test_client_capabilities_say_cannot(self) -> None:
        caps = ArubaInstantOnProvider(client=None).client_capabilities()  # type: ignore[arg-type]
        for field_name in caps.__slots__:
            capability = getattr(caps, field_name)
            assert capability.supported is False
            assert "Instant On" in (capability.reason or "")


# ---------------------------------------------------------------------------
# Mapping (recorded-shape fixtures)
# ---------------------------------------------------------------------------


class TestMapping:
    def test_access_point(self) -> None:
        ap = map_access_point(fx.INVENTORY["elements"][0])
        assert ap.mac == "02:00:5E:10:00:01"
        assert ap.serial_number == "TESTSERIAL01"
        assert ap.model == "AP-503"
        assert ap.status == "online" and ap.status_raw == "up"
        assert ap.firmware_version == "3.4.2.0-97182"
        assert ap.uptime_seconds == 7215
        assert ap.ip_address == "192.0.2.10"

    def test_access_point_alternate_spellings_from_the_live_read(self) -> None:
        ap = map_access_point(
            {"name": "x", "operationalState": "down", "firmwareVersion": "1.0"}
        )
        assert ap.status == "offline" and ap.firmware_version == "1.0"
        assert map_access_point({"name": "x", "status": "weird"}).status == "unknown"

    def test_access_point_without_identity_is_drift(self) -> None:
        with pytest.raises(InstantOnApiDriftError):
            map_access_point({"status": "up"})

    def test_wireless_client(self) -> None:
        c = map_client(fx.CLIENT_SUMMARY["elements"][0])
        assert c.mac == "02:11:22:33:44:55"
        assert c.connection == "wireless"
        assert c.ssid == "WYFY_ARUBA" and c.ssid_id == "net-1"
        assert c.name == "Guest-Phone" and c.hostname == "guest-phone"
        assert c.bands == ("fiveGHz",)
        assert c.signal_quality == "good" and c.snr_db == 38
        assert c.signal_dbm is None  # no dBm field until H1
        assert c.downstream_bytes == 1048576 and c.upstream_bytes == 262144
        assert c.downstream_bps == 800000 and c.upstream_bps == 120000
        assert c.connected_seconds == 600

    def test_wired_client_and_dash_mac(self) -> None:
        c = map_client(fx.CLIENT_SUMMARY["elements"][1])
        assert c.connection == "wired" and c.mac == "02:AA:BB:CC:DD:EE"
        # Missing counters stay None -- never a zero.
        assert c.downstream_bytes is None and c.snr_db is None

    def test_client_without_mac_is_drift(self) -> None:
        with pytest.raises(InstantOnApiDriftError):
            map_client({"ipAddress": "1.2.3.4"})

    def test_network_alert_usage_health(self) -> None:
        n = map_network(fx.NETWORKS_SUMMARY["elements"][0])
        assert (n.name, n.enabled, n.network_type, n.guest_portal_enabled) == (
            "WYFY_ARUBA",
            True,
            "guest",
            True,
        )
        a = map_alert(fx.ALERTS["elements"][0])
        assert a.type == "deviceDown" and a.is_cleared is True
        assert a.raised_at is not None and a.raised_at.startswith("2025-10-02")
        assert a.cleared_at == "2026-10-02T01:30:00+00:00"
        u = map_client_usage(fx.CLIENT_USAGE["elements"][0])
        assert u.bytes_last_24h == 5242880 and u.currently_active is True
        h = map_health(fx.SYSTEM_HEALTH)
        assert (h.score, h.status) == (100, "good")

    def test_unparseable_alert_time_is_none_not_drift(self) -> None:
        assert map_alert({"type": "x", "raisedTime": "yesterday"}).raised_at is None

    def test_empty_shapes_are_drift(self) -> None:
        with pytest.raises(InstantOnApiDriftError):
            map_network({"isEnabled": True})
        with pytest.raises(InstantOnApiDriftError):
            map_alert({"severity": "major"})
        with pytest.raises(InstantOnApiDriftError):
            map_client_usage({"bytes": 1})
        with pytest.raises(InstantOnApiDriftError):
            map_health({})

    async def test_provider_list_clients_is_wireless_only(self) -> None:
        h = Harness(_resource_handler(), state=_valid())
        provider = ArubaInstantOnProvider(h.client)
        clients = await provider.list_clients(None, fx.SITE_ID)
        assert [c.mac for c in clients] == ["02:11:22:33:44:55"]
        assert clients[0].signal_dbm is None
        devices = await provider.list_devices(None, fx.SITE_ID)
        assert devices[0].device_type == "ap" and devices[0].status == "online"
        sites = await provider.list_sites()
        assert sites[0].site_id == fx.SITE_ID and sites[0].name == "test-site"
        found = await provider.get_client(None, fx.SITE_ID, "02-11-22-33-44-55")
        assert found is not None and found.ssid == "WYFY_ARUBA"


def test_fixture_bodies_are_json_round_trippable() -> None:
    for body in fx.RESOURCE_BODIES.values():
        assert json.loads(json.dumps(body)) == body


def test_replace_keeps_secret_fields_out_of_repr() -> None:
    state = replace(InstantOnTokenState(), refresh_token="SECRET-R")
    assert "SECRET" not in repr(state)


class _FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.evals: list[tuple] = []

    async def set(self, key: str, value: str, *, nx: bool, px: int) -> bool:
        assert nx and px > 0
        if key in self.values:
            return False
        self.values[key] = value
        return True

    async def eval(self, script: str, numkeys: int, key: str, owner: str) -> int:
        self.evals.append((key, owner))
        if self.values.get(key) == owner:
            del self.values[key]
            return 1
        return 0


class TestRedisRefreshLock:
    async def test_held_lock_blocks_then_times_out_without_proceeding(self) -> None:
        from app.domains.network_integration.providers.aruba_instant_on_client import (
            RedisRefreshLock,
        )

        redis = _FakeRedis()
        redis.values["k"] = "someone-else"
        lock = RedisRefreshLock(redis, key="k", wait_seconds=0.05, poll_seconds=0.01)
        entered = False
        with pytest.raises(InstantOnUpstreamError) as caught:
            async with lock.hold():
                entered = True
        assert not entered
        assert caught.value.reason == "token_refresh_contended"
        assert redis.values["k"] == "someone-else"  # never deleted another's lock

    async def test_release_is_compare_and_delete(self) -> None:
        from app.domains.network_integration.providers.aruba_instant_on_client import (
            RedisRefreshLock,
        )

        redis = _FakeRedis()
        lock = RedisRefreshLock(redis, key="k")
        async with lock.hold():
            owner = redis.values["k"]
        assert "k" not in redis.values
        assert redis.evals == [("k", owner)]
