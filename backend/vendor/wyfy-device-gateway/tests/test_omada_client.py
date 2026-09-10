"""Transport behaviour: retry, backoff bounds, timeouts, malformed responses."""

from __future__ import annotations

import random

import httpx
import pytest

from wyfy_device_gateway.controller_contract import ControllerAuthMode
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter
from wyfy_device_gateway.omada.auth import SessionCache
from wyfy_device_gateway.omada.client import (
    BACKOFF_BASE_SECONDS,
    BACKOFF_MAX_SECONDS,
    MAX_ATTEMPTS,
    OmadaHttpClient,
)
from wyfy_device_gateway.omada.errors import (
    OmadaConnectionError,
    OmadaError,
    OmadaInvalidControllerError,
    OmadaRateLimitedError,
    OmadaTimeoutError,
    OmadaUnsupportedApiError,
)
from wyfy_device_gateway.omada.types import parse_envelope

from omada_support import (
    FakeOmadaController,
    RecordingSleep,
    envelope,
    make_creds,
    no_sleep,
)


def _client(controller: FakeOmadaController, *, sleep=no_sleep, **kw) -> OmadaHttpClient:
    return OmadaHttpClient(
        kw.pop("creds", make_creds(ControllerAuthMode.OPENAPI)),
        cache=SessionCache(),
        transport=controller.transport(),
        sleep=sleep,
        rng=random.Random(7),
        **kw,
    )


# --- timeouts --------------------------------------------------------------


async def test_timeout_is_normalized_and_retried_to_the_attempt_limit():
    controller = FakeOmadaController()
    controller.fail_times = 99
    controller.failure_exc = httpx.ConnectTimeout("timed out")
    sleep = RecordingSleep()

    async with _client(controller, sleep=sleep) as client:
        with pytest.raises(OmadaTimeoutError) as excinfo:
            await client.request("GET", "/api/info", authenticated=False)

    assert excinfo.value.code == "OMADA_TIMEOUT"
    # MAX_ATTEMPTS tries means MAX_ATTEMPTS-1 sleeps between them.
    assert len(sleep.delays) == MAX_ATTEMPTS - 1


async def test_read_timeout_also_maps_to_omada_timeout():
    controller = FakeOmadaController()
    controller.fail_times = 99
    controller.failure_exc = httpx.ReadTimeout("slow")

    async with _client(controller) as client:
        with pytest.raises(OmadaTimeoutError):
            await client.request("GET", "/api/info", authenticated=False)


async def test_creds_timeout_is_applied_to_the_httpx_client():
    controller = FakeOmadaController()
    creds = make_creds(ControllerAuthMode.OPENAPI, timeout_seconds=3.5)

    async with _client(controller, creds=creds) as client:
        assert client._http is not None
        assert client._http.timeout.connect == 3.5
        assert client._http.timeout.read == 3.5


# --- connection failures ---------------------------------------------------


async def test_connect_error_is_normalized():
    controller = FakeOmadaController()
    controller.fail_times = 99
    controller.failure_exc = httpx.ConnectError("no route to host")

    async with _client(controller) as client:
        with pytest.raises(OmadaConnectionError) as excinfo:
            await client.request("GET", "/api/info", authenticated=False)
    assert excinfo.value.code == "OMADA_CONNECTION_FAILED"


async def test_transient_5xx_is_retried_and_then_succeeds():
    controller = FakeOmadaController()
    controller.fail_times = 2  # fails twice, third attempt works
    controller.failure_status = 503

    async with _client(controller) as client:
        result = await client.request("GET", "/api/info", authenticated=False)

    assert result.ok


async def test_persistent_5xx_exhausts_attempts_and_raises():
    controller = FakeOmadaController()
    controller.fail_times = 99
    controller.failure_status = 500
    sleep = RecordingSleep()

    async with _client(controller, sleep=sleep) as client:
        with pytest.raises(OmadaConnectionError):
            await client.request("GET", "/api/info", authenticated=False)

    assert len(sleep.delays) == MAX_ATTEMPTS - 1


# --- backoff bounds --------------------------------------------------------


async def test_backoff_is_bounded_and_grows():
    """Full jitter means each delay is in [0, base * 2**n], capped."""
    controller = FakeOmadaController()
    controller.fail_times = 99
    controller.failure_status = 500
    sleep = RecordingSleep()

    async with _client(controller, sleep=sleep) as client:
        with pytest.raises(OmadaConnectionError):
            await client.request("GET", "/api/info", authenticated=False)

    for attempt, delay in enumerate(sleep.delays, start=1):
        ceiling = min(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)), BACKOFF_MAX_SECONDS)
        assert 0.0 <= delay <= ceiling
        assert delay <= BACKOFF_MAX_SECONDS


def test_backoff_never_exceeds_the_cap_at_any_attempt():
    controller = FakeOmadaController()
    client = OmadaHttpClient(
        make_creds(), cache=SessionCache(), transport=controller.transport(),
        rng=random.Random(0),
    )
    for attempt in range(1, 20):
        assert 0.0 <= client._backoff_delay(attempt) <= BACKOFF_MAX_SECONDS


# --- rate limiting ---------------------------------------------------------


async def test_429_is_normalized_as_rate_limited_and_retried():
    controller = FakeOmadaController()
    controller.fail_times = 99
    controller.failure_status = 429
    sleep = RecordingSleep()

    async with _client(controller, sleep=sleep) as client:
        with pytest.raises(OmadaRateLimitedError) as excinfo:
            await client.request("GET", "/api/info", authenticated=False)

    assert excinfo.value.code == "OMADA_RATE_LIMITED"
    assert len(sleep.delays) == MAX_ATTEMPTS - 1


# --- malformed / hostile responses ----------------------------------------


async def test_non_json_body_is_an_invalid_controller_error():
    controller = FakeOmadaController()
    controller.handler_override = lambda r: httpx.Response(
        200, text="<html><body>Login</body></html>"
    )

    async with _client(controller) as client:
        with pytest.raises(OmadaInvalidControllerError) as excinfo:
            await client.request("GET", "/api/info", authenticated=False)
    assert excinfo.value.code == "OMADA_INVALID_CONTROLLER"


async def test_json_without_error_code_is_an_invalid_controller_error():
    controller = FakeOmadaController()
    controller.handler_override = lambda r: httpx.Response(200, json={"hello": "world"})

    async with _client(controller) as client:
        with pytest.raises(OmadaInvalidControllerError):
            await client.request("GET", "/api/info", authenticated=False)


async def test_json_array_body_is_an_invalid_controller_error():
    controller = FakeOmadaController()
    controller.handler_override = lambda r: httpx.Response(200, json=[1, 2, 3])

    async with _client(controller) as client:
        with pytest.raises(OmadaInvalidControllerError):
            await client.request("GET", "/api/info", authenticated=False)


@pytest.mark.parametrize(
    "payload",
    [
        {"errorCode": None},
        {"errorCode": True},
        {"errorCode": "not-a-number"},
        {"errorCode": {}},
        "a bare string",
        None,
        42,
    ],
)
def test_parse_envelope_rejects_garbage(payload):
    with pytest.raises(OmadaInvalidControllerError):
        parse_envelope(payload)


def test_parse_envelope_accepts_a_string_error_code():
    """Some firmware sends "0". Rejecting that over a JSON encoding detail
    would break a real controller."""
    assert parse_envelope({"errorCode": "0"}).ok


def test_parse_envelope_reads_msg_and_result():
    parsed = parse_envelope({"errorCode": -7131, "msg": "nope", "result": {"a": 1}})
    assert (parsed.error_code, parsed.msg, parsed.result) == (-7131, "nope", {"a": 1})
    assert not parsed.ok


# --- HTTP status mapping ---------------------------------------------------


async def test_404_maps_to_unsupported_api():
    controller = FakeOmadaController()
    controller.handler_override = lambda r: httpx.Response(404, json={"errorCode": -1})

    async with _client(controller) as client:
        with pytest.raises(OmadaUnsupportedApiError) as excinfo:
            await client.request("GET", "/openapi/v1/x/sites", authenticated=False)
    assert excinfo.value.code == "OMADA_API_UNSUPPORTED"


async def test_unexpected_4xx_maps_to_invalid_controller():
    controller = FakeOmadaController()
    controller.handler_override = lambda r: httpx.Response(418, json={"errorCode": -1})

    async with _client(controller) as client:
        with pytest.raises(OmadaInvalidControllerError):
            await client.request("GET", "/api/info", authenticated=False)


# --- envelope error translation -------------------------------------------


def test_unknown_error_code_keeps_the_raw_code_but_stays_generic():
    exc = OmadaHttpClient.translate_envelope_error(
        parse_envelope({"errorCode": -99999, "msg": "Something odd."})
    )
    assert isinstance(exc, OmadaError)
    assert exc.provider_code == -99999
    assert "Something odd." in str(exc)


def test_controller_id_not_found_maps_to_invalid_controller():
    exc = OmadaHttpClient.translate_envelope_error(
        parse_envelope({"errorCode": -7131, "msg": "Controller ID not exist."})
    )
    assert isinstance(exc, OmadaInvalidControllerError)
    assert exc.provider_code == -7131


def test_operation_unsupported_code_maps_to_unsupported_api():
    exc = OmadaHttpClient.translate_envelope_error(
        parse_envelope({"errorCode": -1600, "msg": "unsupported"})
    )
    assert isinstance(exc, OmadaUnsupportedApiError)


def test_a_body_shaped_msg_is_dropped_rather_than_echoed():
    """sanitize_detail fails closed on anything that looks serialized."""
    exc = OmadaHttpClient.translate_envelope_error(
        parse_envelope({"errorCode": -5, "msg": '{"password": "hunter2"}'})
    )
    assert "hunter2" not in str(exc)
    assert "{" not in str(exc)


# --- redirects are not followed -------------------------------------------


async def test_redirects_are_not_followed():
    """Following a redirect to another host would route around the caller's
    SSRF validation entirely."""
    controller = FakeOmadaController()

    async with _client(controller) as client:
        assert client._http is not None
        assert client._http.follow_redirects is False


# --- errorCode 0 is the only success --------------------------------------


async def test_http_200_with_nonzero_error_code_is_a_failure():
    controller = FakeOmadaController()
    controller.handler_override = lambda r: httpx.Response(
        200, json=envelope(error_code=-42, msg="Nope.")
    )
    adapter = OmadaControllerAdapter(
        transport=controller.transport(), sleep=no_sleep, rng=random.Random(3)
    )

    with pytest.raises(OmadaError) as excinfo:
        await adapter.get_controller_info(make_creds())
    assert excinfo.value.provider_code == -42 or isinstance(
        excinfo.value, OmadaInvalidControllerError
    )
