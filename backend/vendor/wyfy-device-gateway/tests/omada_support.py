"""Test doubles for the Omada adapter -- a scriptable fake controller.

No test in this package may touch a network or a real controller. Everything
runs through ``httpx.MockTransport``, which intercepts at the transport layer,
so the whole real stack above it -- ``httpx.AsyncClient``, our timeout
config, header and cookie handling, JSON encoding, our retry loop -- executes
for real. Only the socket is replaced.

``FakeOmadaController`` models the parts of controller behaviour the client
actually depends on: the ``errorCode`` envelope, the operator-login CSRF
token, the session cookie, Open API bearer tokens, and pagination. It records
every request so a test can assert on the exact wire body -- which matters
most for the portal authorize call, where a wrong field name is the
difference between a guest getting internet and not.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx

from wyfy_device_gateway.controller_contract import (
    ControllerAuthMode,
    ControllerCredentials,
    ControllerVendor,
)

BASE_URL = "https://omada.example.test:8043"
OMADAC_ID = "abcdef0123456789abcdef0123456789"

OPERATOR_USERNAME = "wyfy-operator"
OPERATOR_PASSWORD = "s3cr3t-operator-pw"
CLIENT_ID = "omada-client-id"
CLIENT_SECRET = "s3cr3t-client-secret"

CSRF_TOKEN = "csrf-token-value-0123456789"
SESSION_COOKIE_VALUE = "TPOMADA-SESSION-VALUE-XYZ"
ACCESS_TOKEN = "AT-accesstokenvalue0123456789"
REFRESH_TOKEN = "RT-refreshtokenvalue0123456789"

#: Every secret string a test should assert never appears in logs/exceptions.
ALL_SECRETS: tuple[str, ...] = (
    OPERATOR_PASSWORD,
    CLIENT_SECRET,
    CSRF_TOKEN,
    SESSION_COOKIE_VALUE,
    ACCESS_TOKEN,
    REFRESH_TOKEN,
)


#: Sentinel so a test can pass ``username=None`` to mean "genuinely absent"
#: rather than "give me the default". Using ``None`` as the default here was
#: a real bug: it made the missing-credential tests silently pass full
#: credentials and assert nothing.
UNSET: Any = object()


def make_creds(
    auth_mode: ControllerAuthMode = ControllerAuthMode.OPENAPI,
    *,
    omadac_id: str | None = OMADAC_ID,
    username: Any = UNSET,
    password: Any = UNSET,
    client_id: Any = UNSET,
    client_secret: Any = UNSET,
    timeout_seconds: float = 15.0,
) -> ControllerCredentials:
    """Credentials with sensible per-mode defaults.

    Passing ``username``/``password`` explicitly on an ``openapi`` credential
    is how a test exercises the "Open API for inventory, operator account for
    the portal" configuration that real deployments use.
    """
    if auth_mode == ControllerAuthMode.LEGACY:
        username = OPERATOR_USERNAME if username is UNSET else username
        password = OPERATOR_PASSWORD if password is UNSET else password
        client_id = None if client_id is UNSET else client_id
        client_secret = None if client_secret is UNSET else client_secret
    else:
        client_id = CLIENT_ID if client_id is UNSET else client_id
        client_secret = CLIENT_SECRET if client_secret is UNSET else client_secret
        username = None if username is UNSET else username
        password = None if password is UNSET else password

    return ControllerCredentials(
        vendor=ControllerVendor.TPLINK_OMADA,
        base_url=BASE_URL,
        auth_mode=auth_mode,
        client_id=client_id,
        client_secret=client_secret,
        username=username,
        password=password,
        omadac_id=omadac_id,
        verify_tls=True,
        timeout_seconds=timeout_seconds,
    )


def envelope(result: Any = None, *, error_code: int = 0, msg: str = "Success.") -> dict[str, Any]:
    return {"errorCode": error_code, "msg": msg, "result": result}


def paged(rows: list[dict[str, Any]], *, total: int | None = None) -> dict[str, Any]:
    return {
        "data": rows,
        "totalRows": len(rows) if total is None else total,
        "currentPage": 1,
        "currentSize": len(rows),
    }


class FakeOmadaController:
    """A scriptable Omada controller behind ``httpx.MockTransport``.

    Attributes let a test bend behaviour without subclassing:

    ``login_error_code``   non-zero to make the operator login fail.
    ``token_error_code``   non-zero to make the Open API token call fail.
    ``expire_sessions``    how many authenticated calls to answer with a
                           session-expired error before accepting one. This
                           is the knob that drives the re-login tests.
    ``fail_times``         how many leading requests to answer with the
                           ``failure_status``/``failure_exc`` below, for the
                           retry/backoff tests.
    ``routes``            extra ``path -> payload`` entries for resource calls.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.bodies: list[Any] = []

        self.login_error_code = 0
        self.token_error_code = 0
        self.expire_sessions = 0
        self.session_expiry_code = -44112

        #: Non-zero to make ``extPortal/auth`` refuse with that errorCode.
        #: The real controller answers -41500 for a bad ``authType`` and
        #: -41501 for literally everything else it dislikes.
        self.authorize_error_code = 0
        self.authorize_error_msg: str | None = None

        self.fail_times = 0
        self.failure_status: int | None = 500
        self.failure_exc: Exception | None = None

        self.login_count = 0
        self.token_count = 0
        self.refresh_count = 0

        self.controller_version = "5.15.24.18"
        self.info_payload: dict[str, Any] | None = None

        self.routes: dict[str, Any] = {}
        #: Set to a callable taking the request and returning a
        #: ``httpx.Response`` to take over entirely.
        self.handler_override: Callable[[httpx.Request], httpx.Response] | None = None

    # -- transport ---------------------------------------------------------

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _record(self, request: httpx.Request) -> Any:
        self.requests.append(request)
        body: Any = None
        if request.content:
            try:
                body = json.loads(request.content)
            except ValueError:
                body = request.content
        self.bodies.append(body)
        return body

    def _handle(self, request: httpx.Request) -> httpx.Response:
        body = self._record(request)

        if self.handler_override is not None:
            return self.handler_override(request)

        # Injected transport-level / server-level failures come first so the
        # retry tests see them regardless of which endpoint is hit.
        if self.fail_times > 0:
            self.fail_times -= 1
            if self.failure_exc is not None:
                raise self.failure_exc
            return httpx.Response(
                self.failure_status or 500, json=envelope(msg="server error")
            )

        path = request.url.path

        if path == "/api/info":
            return self._info_response()
        if path.endswith("/api/v2/hotspot/login"):
            return self._login_response(body)
        if path.endswith("/api/v2/hotspot/extPortal/auth"):
            return self._authorize_response()
        if path == "/openapi/authorize/token":
            return self._token_response(request)

        return self._resource_response(request, path)

    # -- endpoints ---------------------------------------------------------

    def _info_response(self) -> httpx.Response:
        if self.info_payload is not None:
            return httpx.Response(200, json=envelope(self.info_payload))
        return httpx.Response(
            200,
            json=envelope(
                {
                    "controllerVer": self.controller_version,
                    "omadacId": OMADAC_ID,
                    "type": "Omada Software Controller",
                }
            ),
        )

    def _login_response(self, body: Any) -> httpx.Response:
        self.login_count += 1
        if self.login_error_code:
            return httpx.Response(
                200,
                json=envelope(error_code=self.login_error_code, msg="Login failed."),
            )
        if not isinstance(body, dict) or body.get("password") != OPERATOR_PASSWORD:
            return httpx.Response(
                200, json=envelope(error_code=-30109, msg="Invalid operator.")
            )
        return httpx.Response(
            200,
            json=envelope({"token": CSRF_TOKEN}, msg="Hotspot log in successfully."),
            headers=[
                (
                    "set-cookie",
                    f"TPOMADA_SESSIONID={SESSION_COOKIE_VALUE}; Path=/; HttpOnly",
                )
            ],
        )

    def _token_response(self, request: httpx.Request) -> httpx.Response:
        grant = request.url.params.get("grant_type")
        if grant == "refresh_token":
            self.refresh_count += 1
        else:
            self.token_count += 1
        if self.token_error_code:
            return httpx.Response(
                200,
                json=envelope(
                    error_code=self.token_error_code, msg="Token request failed."
                ),
            )
        return httpx.Response(
            200,
            json=envelope(
                {
                    "accessToken": ACCESS_TOKEN,
                    "refreshToken": REFRESH_TOKEN,
                    "expiresIn": 7200,
                    "tokenType": "AccessToken",
                }
            ),
        )

    def _authorize_response(self) -> httpx.Response:
        if self.expire_sessions > 0:
            self.expire_sessions -= 1
            return httpx.Response(
                200,
                json=envelope(
                    error_code=self.session_expiry_code, msg="Session timeout."
                ),
            )
        if self.authorize_error_code:
            return httpx.Response(
                200,
                json=envelope(
                    error_code=self.authorize_error_code,
                    msg=self.authorize_error_msg,
                ),
            )
        return httpx.Response(200, json={"errorCode": 0})

    def _resource_response(self, request: httpx.Request, path: str) -> httpx.Response:
        if self.expire_sessions > 0:
            self.expire_sessions -= 1
            return httpx.Response(
                200,
                json=envelope(
                    error_code=self.session_expiry_code, msg="Token expired."
                ),
            )
        for suffix, payload in self.routes.items():
            if path.endswith(suffix):
                if callable(payload):
                    return payload(request)
                return httpx.Response(200, json=envelope(payload))
        return httpx.Response(200, json=envelope(paged([])))

    # -- assertions helpers -------------------------------------------------

    @property
    def auth_calls(self) -> int:
        """Every credential-spending round trip: operator logins, token
        grants and refresh grants. Tests assert on this rather than on one
        counter, because a re-login legitimately takes the refresh path."""
        return self.login_count + self.token_count + self.refresh_count

    def paths(self) -> list[str]:
        return [str(r.url.path) for r in self.requests]

    def body_for(self, suffix: str) -> Any:
        """The JSON body of the last request whose path ends with ``suffix``."""
        for request, body in zip(reversed(self.requests), reversed(self.bodies)):
            if str(request.url.path).endswith(suffix):
                return body
        raise AssertionError(f"no request recorded for path ending {suffix!r}")

    def request_for(self, suffix: str) -> httpx.Request:
        for request in reversed(self.requests):
            if str(request.url.path).endswith(suffix):
                return request
        raise AssertionError(f"no request recorded for path ending {suffix!r}")


async def no_sleep(_seconds: float) -> None:
    """Backoff without the wait, so retry tests stay fast."""
    return None


class RecordingSleep:
    """Captures backoff delays instead of sleeping, so bounds can be asserted."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)
