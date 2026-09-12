"""Both auth modes, session caching, and the re-login behaviour."""

from __future__ import annotations

import dataclasses
import random

import pytest

from wyfy_device_gateway.controller_contract import ControllerAuthMode
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter
from wyfy_device_gateway.omada.auth import (
    CSRF_HEADER,
    LEGACY_AUTHORIZE_PATH,
    LEGACY_LOGIN_PATH,
    OPENAPI_TOKEN_PATH,
    SessionCache,
    session_key,
)
from wyfy_device_gateway.omada.client import OmadaHttpClient
from wyfy_device_gateway.omada.errors import OmadaAuthError, OmadaSessionExpiredError

from omada_support import (
    ACCESS_TOKEN,
    CSRF_TOKEN,
    OMADAC_ID,
    SESSION_COOKIE_VALUE,
    FakeOmadaController,
    make_creds,
    no_sleep,
)


def _adapter(controller: FakeOmadaController, **kw) -> OmadaControllerAdapter:
    return OmadaControllerAdapter(
        transport=controller.transport(),
        sleep=no_sleep,
        rng=random.Random(1234),
        **kw,
    )


# --- endpoint paths: the contract section 1a verdict, locked in -----------


def test_operator_login_and_authorize_use_the_documented_paths():
    """The transposition resolved in auth.py's docstring, asserted in code.

    TP-Link's own PHP sample has these two swapped; the prose in every doc
    generation has them this way round. If someone "fixes" the client to
    match the sample, this fails.
    """
    assert LEGACY_LOGIN_PATH == "/{omadac_id}/api/v2/hotspot/login"
    assert LEGACY_AUTHORIZE_PATH == "/{omadac_id}/api/v2/hotspot/extPortal/auth"
    assert OPENAPI_TOKEN_PATH == "/openapi/authorize/token"


# --- legacy mode -----------------------------------------------------------


async def test_legacy_login_sends_name_and_password_and_captures_csrf():
    controller = FakeOmadaController()
    creds = make_creds(ControllerAuthMode.LEGACY)

    async with OmadaHttpClient(creds, cache=SessionCache(), transport=controller.transport()) as client:
        state = await client.ensure_authenticated()

    body = controller.body_for("/api/v2/hotspot/login")
    assert body == {"name": creds.username, "password": creds.password}
    # CSRF token comes from result.token and rides as the Csrf-Token header.
    assert state.headers[CSRF_HEADER] == CSRF_TOKEN
    assert state.cookies["TPOMADA_SESSIONID"] == SESSION_COOKIE_VALUE


async def test_legacy_login_failure_raises_auth_error_with_controller_message():
    controller = FakeOmadaController()
    controller.login_error_code = -30109
    creds = make_creds(ControllerAuthMode.LEGACY)

    async with OmadaHttpClient(creds, cache=SessionCache(), transport=controller.transport()) as client:
        with pytest.raises(OmadaAuthError) as excinfo:
            await client.ensure_authenticated()

    assert excinfo.value.code == "OMADA_AUTH_FAILED"
    assert excinfo.value.provider_code == -30109
    # The controller's own short message is useful and safe, so it survives.
    assert "Login failed." in str(excinfo.value)


async def test_legacy_mode_without_credentials_is_an_auth_error():
    controller = FakeOmadaController()
    creds = make_creds(ControllerAuthMode.LEGACY, username=None, password=None)

    async with OmadaHttpClient(creds, cache=SessionCache(), transport=controller.transport()) as client:
        with pytest.raises(OmadaAuthError):
            await client.ensure_authenticated()


async def test_legacy_login_without_token_in_result_is_an_auth_error():
    """errorCode 0 but no result.token: fail now, not on the next call."""
    controller = FakeOmadaController()
    controller.handler_override = lambda request: __import__("httpx").Response(
        200, json={"errorCode": 0, "msg": "ok", "result": {}}
    )
    creds = make_creds(ControllerAuthMode.LEGACY)

    async with OmadaHttpClient(creds, cache=SessionCache(), transport=controller.transport()) as client:
        with pytest.raises(OmadaAuthError):
            await client.ensure_authenticated()


# --- openapi mode ----------------------------------------------------------


async def test_openapi_token_request_shape_and_authorization_header():
    controller = FakeOmadaController()
    creds = make_creds(ControllerAuthMode.OPENAPI)

    async with OmadaHttpClient(creds, cache=SessionCache(), transport=controller.transport()) as client:
        state = await client.ensure_authenticated()

    request = controller.request_for(OPENAPI_TOKEN_PATH)
    assert request.url.params.get("grant_type") == "client_credentials"
    assert controller.body_for(OPENAPI_TOKEN_PATH) == {
        "omadacId": OMADAC_ID,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
    }
    # VERIFIED against TP-Link doc 109315: the prefix is "AccessToken=",
    # emphatically not "Bearer".
    assert state.headers["Authorization"] == f"AccessToken={ACCESS_TOKEN}"
    assert not state.headers["Authorization"].startswith("Bearer")


async def test_openapi_without_client_credentials_is_an_auth_error():
    controller = FakeOmadaController()
    creds = make_creds(ControllerAuthMode.OPENAPI, client_id=None, client_secret=None)

    async with OmadaHttpClient(creds, cache=SessionCache(), transport=controller.transport()) as client:
        with pytest.raises(OmadaAuthError):
            await client.ensure_authenticated()


async def test_openapi_token_failure_raises_auth_error():
    controller = FakeOmadaController()
    controller.token_error_code = -44106
    creds = make_creds(ControllerAuthMode.OPENAPI)

    async with OmadaHttpClient(creds, cache=SessionCache(), transport=controller.transport()) as client:
        with pytest.raises(OmadaAuthError) as excinfo:
            await client.ensure_authenticated()
    assert excinfo.value.provider_code == -44106


# --- caching ---------------------------------------------------------------


async def test_token_is_reused_across_calls_on_one_adapter():
    """One login should serve many calls -- that is the point of the cache."""
    controller = FakeOmadaController()
    adapter = _adapter(controller)
    creds = make_creds(ControllerAuthMode.OPENAPI)

    await adapter.list_sites(creds)
    await adapter.list_sites(creds)
    await adapter.list_sites(creds)

    assert controller.token_count == 1


async def test_cache_key_uses_a_fingerprint_and_never_the_secret():
    creds = make_creds(ControllerAuthMode.OPENAPI)
    key = session_key(creds, OMADAC_ID)

    flat = "\x00".join(str(part) for part in key)
    assert creds.client_secret not in flat
    assert creds.client_id not in flat
    assert OMADAC_ID in flat
    assert creds.base_url in flat


async def test_rotating_a_credential_does_not_reuse_the_old_session():
    """A changed secret must produce a different cache key, or a rotation
    would keep silently working off the session issued to the old one."""
    original = make_creds(ControllerAuthMode.OPENAPI)
    rotated = make_creds(ControllerAuthMode.OPENAPI, client_secret="a-new-secret")

    assert session_key(original, OMADAC_ID) != session_key(rotated, OMADAC_ID)

    controller = FakeOmadaController()
    adapter = _adapter(controller)
    await adapter.list_sites(original)
    await adapter.list_sites(rotated)
    assert controller.token_count == 2


async def test_cache_entry_expires_and_forces_a_new_login():
    controller = FakeOmadaController()
    cache = SessionCache()
    adapter = _adapter(controller, cache=cache)
    creds = make_creds(ControllerAuthMode.OPENAPI)

    await adapter.list_sites(creds)
    assert controller.token_count == 1

    # Expire it the way time would.
    key = session_key(creds, OMADAC_ID)
    stale = cache.get(key)
    assert stale is not None
    cache.set(key, dataclasses.replace(stale, expires_at=0.0))
    assert cache.get(key) is None  # a stale entry is dropped, not returned

    await adapter.list_sites(creds)
    assert controller.token_count == 2


# --- session expiry -> re-login -------------------------------------------


async def test_session_expiry_triggers_one_relogin_then_succeeds():
    controller = FakeOmadaController()
    controller.expire_sessions = 1  # first authenticated call is rejected
    adapter = _adapter(controller)
    creds = make_creds(ControllerAuthMode.OPENAPI)

    sites = await adapter.list_sites(creds)

    assert sites == []
    # One initial client_credentials grant, then one re-login. The re-login
    # spends the refresh token rather than the client secret, which is why
    # this asserts on total auth calls rather than on token_count alone.
    assert controller.auth_calls == 2
    assert controller.token_count == 1
    assert controller.refresh_count == 1


async def test_relogin_that_also_expires_gives_up_rather_than_looping():
    controller = FakeOmadaController()
    controller.expire_sessions = 99  # every authenticated call is rejected
    adapter = _adapter(controller)
    creds = make_creds(ControllerAuthMode.OPENAPI)

    with pytest.raises(OmadaSessionExpiredError) as excinfo:
        await adapter.list_sites(creds)

    assert excinfo.value.code == "OMADA_SESSION_EXPIRED"
    # Exactly one re-login was attempted -- we do not spin.
    assert controller.auth_calls == 2


async def test_http_401_on_an_authenticated_call_triggers_relogin():
    """A 401 is a session problem, not a credential problem, on a non-auth
    request -- the credentials already worked at the token endpoint."""
    import httpx

    controller = FakeOmadaController()
    creds = make_creds(ControllerAuthMode.OPENAPI)
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/openapi/authorize/token":
            # _token_response already updates the counters; incrementing
            # here too would double-count and make the assertion lie.
            return controller._token_response(request)
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(401, json={"errorCode": -1, "msg": "no"})
        return httpx.Response(200, json={"errorCode": 0, "msg": "ok", "result": {"data": []}})

    controller.handler_override = handler
    adapter = _adapter(controller)

    assert await adapter.list_sites(creds) == []
    assert controller.auth_calls == 2


async def test_401_at_the_token_endpoint_is_an_auth_error_and_is_not_retried():
    """Never hammer a controller with credentials it just rejected."""
    import httpx

    controller = FakeOmadaController()
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/openapi/authorize/token":
            calls["n"] += 1
            return httpx.Response(401, json={"errorCode": -1, "msg": "denied"})
        return httpx.Response(200, json={"errorCode": 0, "result": {"data": []}})

    controller.handler_override = handler
    adapter = _adapter(controller)

    with pytest.raises(OmadaAuthError):
        await adapter.list_sites(make_creds(ControllerAuthMode.OPENAPI))

    assert calls["n"] == 1


async def test_openapi_refresh_token_is_used_before_a_full_relogin():
    controller = FakeOmadaController()
    controller.expire_sessions = 1
    adapter = _adapter(controller)

    await adapter.list_sites(make_creds(ControllerAuthMode.OPENAPI))

    # The re-login went through the refresh grant, not a fresh
    # client_credentials round trip.
    assert controller.refresh_count == 1
    assert controller.token_count == 1
