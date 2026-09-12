"""No secret may ever reach a log record or an exception string.

This is the file that enforces contract section 2's hardest requirement. The
approach is deliberately end-to-end rather than unit-only: the tests below
drive real adapter calls through failing scenarios with ``caplog`` capturing
everything at DEBUG, then assert that not one of the known secret values
appears anywhere in any log record or in ``str(exc)``/``repr(exc)``.

Asserting on the *values* rather than on the redaction functions is the
point. A unit test of ``redact_text`` proves the function works; it does not
prove every call site uses it. Only sweeping real output can do that.
"""

from __future__ import annotations

import logging
import random

import httpx
import pytest

from wyfy_device_gateway.controller_contract import ControllerAuthMode
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter
from wyfy_device_gateway.omada.errors import ALL_ERRORS, OmadaError
from wyfy_device_gateway.omada.redaction import (
    REDACTED,
    credential_fingerprint,
    is_sensitive_key,
    redact_mapping,
    redact_text,
    sanitize_detail,
)

from omada_support import (
    ACCESS_TOKEN,
    ALL_SECRETS,
    CLIENT_SECRET,
    CSRF_TOKEN,
    OPERATOR_PASSWORD,
    REFRESH_TOKEN,
    SESSION_COOKIE_VALUE,
    FakeOmadaController,
    envelope,
    make_creds,
    no_sleep,
    paged,
)


def _adapter(controller: FakeOmadaController) -> OmadaControllerAdapter:
    return OmadaControllerAdapter(
        transport=controller.transport(), sleep=no_sleep, rng=random.Random(2)
    )


def _all_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Everything a log record could possibly carry, flattened."""
    chunks: list[str] = []
    for record in caplog.records:
        chunks.append(str(record.getMessage()))
        chunks.append(str(record.msg))
        chunks.append(str(record.args))
        for key, value in record.__dict__.items():
            chunks.append(f"{key}={value!r}")
    return "\n".join(chunks)


def _assert_no_secrets(text: str) -> None:
    for secret in ALL_SECRETS:
        assert secret not in text, f"secret leaked: {secret!r}"


# --- end-to-end sweeps -----------------------------------------------------


async def test_successful_flow_logs_no_secrets(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.DEBUG)
    controller = FakeOmadaController()
    controller.routes["/sites"] = paged([{"siteId": "s1", "name": "Lobby"}])

    await _adapter(controller).list_sites(make_creds(ControllerAuthMode.OPENAPI))

    _assert_no_secrets(_all_log_text(caplog))


async def test_portal_authorize_logs_no_secrets(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.DEBUG)
    controller = FakeOmadaController()
    from test_omada_portal import EAP_CTX

    await _adapter(controller).authorize_guest(
        make_creds(ControllerAuthMode.LEGACY), EAP_CTX, duration_seconds=600
    )

    _assert_no_secrets(_all_log_text(caplog))


async def test_failing_flows_log_no_secrets(caplog: pytest.LogCaptureFixture):
    """Failure paths log the most, so they are the likeliest to leak."""
    caplog.set_level(logging.DEBUG)

    scenarios = []

    bad_login = FakeOmadaController()
    bad_login.login_error_code = -30109
    scenarios.append((bad_login, ControllerAuthMode.LEGACY))

    bad_token = FakeOmadaController()
    bad_token.token_error_code = -44106
    scenarios.append((bad_token, ControllerAuthMode.OPENAPI))

    timeout = FakeOmadaController()
    timeout.fail_times = 99
    timeout.failure_exc = httpx.ConnectTimeout("boom")
    scenarios.append((timeout, ControllerAuthMode.OPENAPI))

    server_error = FakeOmadaController()
    server_error.fail_times = 99
    server_error.failure_status = 500
    scenarios.append((server_error, ControllerAuthMode.OPENAPI))

    expired = FakeOmadaController()
    expired.expire_sessions = 99
    scenarios.append((expired, ControllerAuthMode.OPENAPI))

    for controller, mode in scenarios:
        with pytest.raises(Exception) as excinfo:  # noqa: PT011 - sweeping on purpose
            await _adapter(controller).list_sites(make_creds(mode))
        _assert_no_secrets(str(excinfo.value))
        _assert_no_secrets(repr(excinfo.value))

    _assert_no_secrets(_all_log_text(caplog))


async def test_a_controller_that_echoes_secrets_back_cannot_leak_them(
    caplog: pytest.LogCaptureFixture,
):
    """The nastiest realistic case: the controller puts our own credential
    into its error message. We must still not surface it."""
    caplog.set_level(logging.DEBUG)
    controller = FakeOmadaController()
    controller.handler_override = lambda r: httpx.Response(
        200,
        json=envelope(
            error_code=-9,
            msg=f"bad login for password={OPERATOR_PASSWORD} token={ACCESS_TOKEN}",
        ),
    )

    with pytest.raises(OmadaError) as excinfo:
        await _adapter(controller).get_controller_info(make_creds())

    _assert_no_secrets(str(excinfo.value))
    _assert_no_secrets(repr(excinfo.value))
    _assert_no_secrets(_all_log_text(caplog))


async def test_response_bodies_are_never_logged(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.DEBUG)
    controller = FakeOmadaController()
    marker = "UNIQUE-BODY-MARKER-9d2f"
    controller.handler_override = lambda r: httpx.Response(
        200, json=envelope({"accessToken": ACCESS_TOKEN, "note": marker})
    )

    await _adapter(controller).get_controller_info(make_creds())

    assert marker not in _all_log_text(caplog)


# --- exception hygiene -----------------------------------------------------


def test_every_error_class_has_a_safe_default_message():
    for error_class in ALL_ERRORS:
        exc = error_class()
        message = str(exc)
        assert message, f"{error_class.__name__} has an empty message"
        # Reads like a sentence for a human, not a stack trace or a body.
        assert "{" not in message
        assert "Traceback" not in message
        _assert_no_secrets(message)


def test_every_error_class_exposes_its_contract_code():
    expected = {
        "OmadaAuthError": "OMADA_AUTH_FAILED",
        "OmadaConnectionError": "OMADA_CONNECTION_FAILED",
        "OmadaTlsTrustError": "OMADA_TLS_UNTRUSTED",
        "OmadaTlsPinMismatchError": "OMADA_TLS_PIN_MISMATCH",
        "OmadaTimeoutError": "OMADA_TIMEOUT",
        "OmadaRateLimitedError": "OMADA_RATE_LIMITED",
        "OmadaInvalidControllerError": "OMADA_INVALID_CONTROLLER",
        "OmadaSiteNotFoundError": "OMADA_SITE_NOT_FOUND",
        "OmadaClientNotFoundError": "OMADA_CLIENT_NOT_FOUND",
        "OmadaAuthorizationError": "OMADA_AUTHORIZATION_FAILED",
        "OmadaUnsupportedApiError": "OMADA_API_UNSUPPORTED",
        "OmadaSessionExpiredError": "OMADA_SESSION_EXPIRED",
        # Omada -1005/-1505: the Open API app's role or site privileges do
        # not cover the call. Codes from the 5.15.24.19 controller's own
        # Open API Access Guide.
        "OmadaPermissionDeniedError": "OMADA_PERMISSION_DENIED",
    }
    actual = {cls.__name__: cls.code for cls in ALL_ERRORS}
    assert actual == expected
    assert len(set(actual.values())) == len(expected)  # codes are unique


def test_repr_does_not_widen_the_exposure():
    exc = OmadaError(f"leak {ACCESS_TOKEN}", provider_code=-1)
    # str() carries whatever was passed in, so callers must pass safe text --
    # but repr() must not add anything beyond it.
    assert repr(exc).count(ACCESS_TOKEN) <= str(exc).count(ACCESS_TOKEN)


# --- redaction primitives --------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["password", "Password", "client_secret", "clientSecret", "Csrf-Token",
     "csrf_token", "Cookie", "set-cookie", "Authorization", "accessToken",
     "refreshToken", "token", "apiKey", "sessionId"],
)
def test_sensitive_keys_are_recognised_regardless_of_spelling(key):
    assert is_sensitive_key(key)


@pytest.mark.parametrize("key", ["msg", "errorCode", "site", "clientMac", "name"])
def test_ordinary_keys_are_not_treated_as_sensitive(key):
    assert not is_sensitive_key(key)


def test_redact_mapping_recurses_into_nested_structures():
    redacted = redact_mapping(
        {
            "result": {"token": CSRF_TOKEN, "accessToken": ACCESS_TOKEN},
            "rows": [{"password": OPERATOR_PASSWORD}, {"mac": "AA-BB"}],
            "msg": f"Cookie: TPOMADA_SESSIONID={SESSION_COOKIE_VALUE}",
            "count": 3,
        }
    )
    flat = repr(redacted)
    _assert_no_secrets(flat)
    assert redacted["result"]["token"] == REDACTED
    assert redacted["rows"][0]["password"] == REDACTED
    assert redacted["rows"][1]["mac"] == "AA-BB"  # untouched
    assert redacted["count"] == 3


@pytest.mark.parametrize(
    "text",
    [
        f"Authorization: AccessToken={ACCESS_TOKEN}",
        f"Bearer {ACCESS_TOKEN}",
        f"TPOMADA_SESSIONID={SESSION_COOKIE_VALUE}",
        f"Csrf-Token: {CSRF_TOKEN}",
        f"password={OPERATOR_PASSWORD}",
        f"client_secret: {CLIENT_SECRET}",
        f"token is {REFRESH_TOKEN} ok",
    ],
)
def test_redact_text_catches_secret_shapes(text):
    _assert_no_secrets(redact_text(text))


def test_sanitize_detail_keeps_useful_short_prose():
    assert sanitize_detail("Controller ID not exist.") == "Controller ID not exist."


@pytest.mark.parametrize(
    "detail",
    [
        '{"password": "hunter2"}',           # a body, not a sentence
        "[1, 2, 3]",                          # ditto
        "x" * 500,                            # too long to eyeball
        f"password={OPERATOR_PASSWORD}",      # contains a secret
        "",
        None,
        12345,
    ],
)
def test_sanitize_detail_fails_closed(detail):
    assert sanitize_detail(detail) is None


# --- fingerprints ----------------------------------------------------------


def test_fingerprint_is_stable_and_not_reversible():
    a = credential_fingerprint("legacy", "user", OPERATOR_PASSWORD)
    b = credential_fingerprint("legacy", "user", OPERATOR_PASSWORD)
    assert a == b
    assert OPERATOR_PASSWORD not in a
    assert len(a) == 32


def test_fingerprint_changes_when_any_part_changes():
    base = credential_fingerprint("legacy", "user", "pw")
    assert base != credential_fingerprint("legacy", "user", "pw2")
    assert base != credential_fingerprint("legacy", "user2", "pw")
    assert base != credential_fingerprint("openapi", "user", "pw")


def test_fingerprint_distinguishes_none_from_empty_string():
    assert credential_fingerprint(None) != credential_fingerprint("")


def test_fingerprint_is_not_confusable_by_concatenation():
    """Without a separator, ("ab","c") and ("a","bc") would collide."""
    assert credential_fingerprint("ab", "c") != credential_fingerprint("a", "bc")
