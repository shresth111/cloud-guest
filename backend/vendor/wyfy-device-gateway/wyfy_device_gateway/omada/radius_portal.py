"""RADIUS portal mode (``authType 2``): the server-side ``browserauth`` submit.

This is the *other* Omada captive-portal contract, and it is not a variant of
``portal.py``'s -- it is a different endpoint, a different encoding, a
different authentication model and a different success signal. ``portal.py``
speaks to ``/{omadacId}/api/v2/hotspot/extPortal/auth`` with an operator
session and reads an ``{"errorCode": 0}`` envelope. Nothing in this module
logs in, and nothing here parses an envelope on the success path, because
success is not a body at all -- it is a ``302``.

## Why the platform makes this call at all, when the guest's browser could

It could, and it did, and on real hardware it does not work. The submit
target is the controller's own portal port, which on every self-hosted Omada
install answers with a self-signed ``CN=localhost`` certificate. Android
refuses to POST a form to it. Every venue's controller has its own such
certificate, so there is no fix that scales -- the browser has to be taken
out of the path.

**Measured on hardware 2026-09-17**: the ``browserauth`` call does NOT have
to originate from the guest's browser. A request from an unrelated third
machine, carrying the guest's real ``clientMac``/``clientIp`` and a username
with an ACTIVE session, returned ``302 Location: http://neverssl.com/`` and
the controller then reported that client as ``authStatus 2 / authType 2`` --
authorized, by RADIUS. The gate opens for whoever sends the right body; the
controller identifies the *client* by the MAC in the body, not by the peer
address of the HTTP connection.

That is what makes this module possible, and it is also the reason the
caller's session and MAC checks matter so much: the controller is doing no
authentication of the requester whatsoever.

## The request, verbatim (VERIFIED 2026-09-17)

::

    POST https://<controller>:8843/portal/radius/browserauth
    Content-Type: application/x-www-form-urlencoded

    clientMac=26-79-94-B5-24-D9&clientIp=192.168.1.121
    &apMac=B8-FB-B3-5D-64-3E&gatewayMac=&ssidName=WyfyRadTest&vid=
    &radioId=1&authType=2&originUrl=http://neverssl.com/
    &username=<guest identifier>&password=<placeholder>

``application/x-www-form-urlencoded`` is required here and is *rejected* by
the sibling XHR endpoint ``/portal/radius/auth`` (which answers ``-1001``
for it). The two endpoints are not interchangeable in either direction.

## Reading the answer -- the one thing an implementation gets wrong

+------------------------------+-------------------------------------------+
| ``302`` + ``Location``       | **success.** The RADIUS server answered   |
|                              | Access-Accept and the gate is open.       |
+------------------------------+-------------------------------------------+
| ``200`` + ``application/     | **failure**, and the JSON says which:     |
| json``                       | ``-41529`` Access-Reject, ``-41530``      |
|                              | the controller could not reach the RADIUS |
|                              | server, ``-41501`` generic failure.       |
+------------------------------+-------------------------------------------+
| ``400``                      | a required field was missing from the     |
|                              | body. Our bug, never the guest's.         |
+------------------------------+-------------------------------------------+

An earlier measurement appeared to show ``302`` on a reject too -- a
silent-success disaster. It was taken with ``radiusAccountingEnable`` on,
which fails every auth in a different way and never exercised the reject.
Re-measured cleanly, the two outcomes are cleanly distinguishable. The
correction is recorded rather than the first answer, because "302 means
success" is load-bearing for every caller of this module.

**Redirects are never followed.** Beyond the usual SSRF reason (contract
section 6: the caller validated one host, and a redirect to another routes
around that), following the ``302`` here would destroy the *only* success
signal this endpoint has and turn an authorization into whatever
``originUrl`` happens to serve.

## Trust, and which certificate is actually being checked

Nothing new is invented. The caller hands this module the same
``ControllerCredentials`` every other call uses -- same ``tls_mode``, same
``tls_pinned_sha256`` -- with ``base_url`` already pointed at the portal
origin, and the ordinary machinery in ``tls.py`` applies unchanged: a
preflight handshake before any byte is sent in ``PINNED`` mode, plus the
per-response check on the connection the answer arrived on.

**The honest caveat**: the portal port (8843) and the API port (8043) are two
different listeners. On the controller measured here they present the same
self-signed certificate out of the same keystore, so a pin captured on 8043
matches 8843. That is an observation about one controller, not a guarantee
about the product. If some deployment ever serves a different certificate on
the portal port, this call fails closed with ``OMADA_TLS_PIN_MISMATCH`` --
loudly, and without sending the body. Failing closed on an unverified
assumption is the correct shape; silently widening trust to "whatever the
portal port presents" would not be.

## No credential of ours goes to this endpoint

``username`` is the guest's own identifier and ``password`` is a placeholder
this product's RADIUS server never checks (it authorizes by session lookup).
There is no operator login, no Open API secret and no session cookie on this
path, which is why this module does not use ``OmadaHttpClient`` at all.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..controller_contract import ControllerCredentials, ControllerTlsMode
from .errors import (
    OmadaConnectionError,
    OmadaTimeoutError,
)
from .tls import (
    PinVerifyingTransport,
    assert_peer_certificate_matches,
    require_pin,
    ssl_verify_argument,
)

logger = logging.getLogger(__name__)

__all__ = [
    "AUTH_TYPE_EXTERNAL_RADIUS",
    "DEFAULT_PORTAL_PORTS",
    "RADIUS_BROWSERAUTH_PATH",
    "RadiusBrowserAuthResult",
    "RadiusPortalContext",
    "build_browserauth_body",
    "resolve_portal_origin",
    "submit_browserauth",
]

#: VERIFIED on the live controller and in TP-Link's own OpenAPI spec:
#: ``2`` is *External RADIUS Server* in the ``authType`` enumeration.
AUTH_TYPE_EXTERNAL_RADIUS = 2

#: The form-POST endpoint. Its XHR sibling ``/portal/radius/auth`` is
#: deliberately not reachable from this module -- it rejects form encoding,
#: and its answer is unreadable cross-origin, which is what sent this whole
#: flow server-side in the first place.
RADIUS_BROWSERAUTH_PATH = "/portal/radius/browserauth"

#: Which port the portal listener answers on, by scheme. VERIFIED on Omada
#: Software Controller 5.15.24.19: ``8843`` https, ``8088`` http -- both
#: distinct from the management API's ``8043``.
#:
#: This table is the ONLY place a port for this call may come from, other
#: than an explicit operator override on the integration row. It is never
#: taken from the request that triggered the call: see
#: :func:`resolve_portal_origin`.
DEFAULT_PORTAL_PORTS = {"https": 8843, "http": 8088}

#: One retry, and one only. The controller's own answer already costs a
#: RADIUS round trip; a second retry against a venue's hardware multiplies
#: the load exactly when it is least able to take it.
_MAX_ATTEMPTS = 2


@dataclass(frozen=True, slots=True)
class RadiusPortalContext:
    """Exactly the values Omada put on its own ``authType 2`` redirect.

    Field names mirror the controller's query parameters 1:1, as
    ``PortalAuthContext`` does for the other contract. Note what is NOT here
    and cannot be: this redirect carries no ``site`` and no ``t``, so a
    caller has nothing in the message identifying the venue. That is the
    reason the platform resolves the venue from the guest's session instead.

    ``origin_url`` is where the controller sends the browser on success. It
    comes back to the caller as the ``Location`` of the ``302``, which is how
    the caller knows the gate opened.
    """

    client_mac: str
    client_ip: str | None = None
    ap_mac: str | None = None
    gateway_mac: str | None = None
    ssid_name: str | None = None
    radio_id: int | None = None
    vid: int | None = None
    origin_url: str | None = None


@dataclass(frozen=True, slots=True)
class RadiusBrowserAuthResult:
    """What the controller answered.

    ``authorized`` is true only for ``302`` + ``Location``. Every other
    answer the controller gives is a refusal, and ``provider_code`` carries
    its raw ``errorCode`` integer when there was one -- the only part of the
    controller's response body that is allowed to survive, for the same
    reason as everywhere else in this package: an integer cannot smuggle a
    credential.

    ``http_status`` is kept because ``400`` (a field missing from OUR body)
    and ``200`` (the controller answering a well-formed request with a
    refusal) are different bugs with different owners.
    """

    authorized: bool
    landing_url: str | None = None
    provider_code: int | None = None
    http_status: int | None = None


def resolve_portal_origin(base_url: str, portal_port: int | None = None) -> str:
    """``("https://host:8043", None)`` -> ``"https://host:8843"``.

    **This function is the SSRF boundary in this package.** The host and the
    scheme come from ``base_url`` -- the address stored on the integration
    row, validated when it was written and re-validated by the caller
    immediately before this call. Nothing a guest's browser sent can reach
    either of them. The port is an explicit operator override or the
    documented default for the scheme, and is likewise never taken from a
    request.

    The temptation this exists to refuse is real: the controller's own
    redirect *tells the guest's page* where to submit, in ``target`` /
    ``targetPort`` / ``scheme``, and those values arrive back at the platform
    through the guest's browser. Building the URL from them would mean any
    caller could point this platform's HTTP client, holding this platform's
    TLS trust decision, at an address of their choosing.
    """
    parts = urlsplit(base_url)
    scheme = (parts.scheme or "https").lower()
    host = parts.hostname
    if not host:
        raise OmadaConnectionError()
    port = portal_port or DEFAULT_PORTAL_PORTS.get(scheme, 8843)
    # An IPv6 literal has to go back inside brackets or the URL is unparseable.
    rendered = f"[{host}]" if ":" in host else host
    return f"{scheme}://{rendered}:{int(port)}"


def build_browserauth_body(
    ctx: RadiusPortalContext, *, username: str, password: str
) -> dict[str, str]:
    """The exact form body, as a pure function.

    Pure and separate from the request for the same reason
    ``portal.build_authorize_body`` is: this is the one payload where a wrong
    field name means a guest with no internet, so it has to be assertable in
    a test with no HTTP in the way.

    Present-only, never defaulted. The controller treats a missing optional
    field and an empty one differently on some firmware and we have measured
    neither, so a value that did not arrive does not travel. The one
    exception is the pair that is *ours* -- ``username``/``password`` -- and
    ``authType``, which is a constant.
    """
    body: dict[str, str] = {
        "authType": str(AUTH_TYPE_EXTERNAL_RADIUS),
        "username": username,
        "password": password,
    }
    optional: list[tuple[str, Any]] = [
        ("clientMac", ctx.client_mac),
        ("clientIp", ctx.client_ip),
        ("apMac", ctx.ap_mac),
        ("gatewayMac", ctx.gateway_mac),
        ("ssidName", ctx.ssid_name),
        ("vid", ctx.vid),
        ("radioId", ctx.radio_id),
        ("originUrl", ctx.origin_url),
    ]
    for name, value in optional:
        if value is None:
            continue
        rendered = str(value)
        if rendered == "":
            continue
        body[name] = rendered
    return body


def _provider_code(response: httpx.Response) -> int | None:
    """The controller's ``errorCode``, as an integer, or ``None``.

    Deliberately tolerant: the body is only ever read for this one number.
    Nothing else from it -- not ``msg``, not the raw text -- is returned to
    the caller or logged, because on this endpoint the body is what a
    rejected guest's browser would have rendered and it is the controller's
    prose, not ours.
    """
    try:
        payload = json.loads(response.text)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    raw = payload.get("errorCode")
    if isinstance(raw, bool) or not isinstance(raw, int):
        return None
    return raw


async def submit_browserauth(
    creds: ControllerCredentials,
    ctx: RadiusPortalContext,
    *,
    username: str,
    password: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> RadiusBrowserAuthResult:
    """POST the form and classify the answer. Never follows a redirect.

    ``creds.base_url`` must already BE the portal origin -- the caller builds
    it with :func:`resolve_portal_origin` and re-validates it, so that this
    module's TLS handling (including the ``PINNED`` preflight, which reads
    ``base_url``) applies to the socket that is actually opened.

    Retries once, and only on a transport failure. A controller that
    *answered* is never retried: re-sending an Access-Request after a
    ``-41529`` would ask a venue's RADIUS server to reject the same guest
    twice, and re-sending after a ``302`` would authorize them twice.
    """
    body = build_browserauth_body(ctx, username=username, password=password)
    timeout = httpx.Timeout(
        connect=creds.timeout_seconds,
        read=creds.timeout_seconds,
        write=creds.timeout_seconds,
        pool=creds.timeout_seconds,
    )
    verify = ssl_verify_argument(creds)

    last_error: Exception | None = None
    for attempt in range(_MAX_ATTEMPTS):
        active = transport
        if creds.tls_mode is ControllerTlsMode.PINNED:
            pin = require_pin(creds)
            if active is None:
                # Before a single byte of the body -- which names a real
                # guest's MAC and identifier -- goes to the socket.
                await assert_peer_certificate_matches(creds, pin)
                active = httpx.AsyncHTTPTransport(verify=verify)
            active = PinVerifyingTransport(active, pin)
        try:
            async with httpx.AsyncClient(
                base_url=creds.base_url.rstrip("/"),
                timeout=timeout,
                verify=verify,
                transport=active,
                # See the module docstring: following the 302 would destroy
                # the only success signal this endpoint has, on top of the
                # ordinary SSRF reason.
                follow_redirects=False,
            ) as http:
                response = await http.post(
                    RADIUS_BROWSERAUTH_PATH,
                    data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
        except httpx.TimeoutException as exc:
            last_error = OmadaTimeoutError()
            last_error.__cause__ = exc
        except httpx.HTTPError as exc:
            last_error = OmadaConnectionError()
            last_error.__cause__ = exc
        else:
            if response.is_redirect:
                return RadiusBrowserAuthResult(
                    authorized=True,
                    landing_url=response.headers.get("location"),
                    http_status=response.status_code,
                )
            return RadiusBrowserAuthResult(
                authorized=False,
                provider_code=_provider_code(response),
                http_status=response.status_code,
            )
        logger.warning(
            "omada_radius_browserauth_transport_failure",
            extra={"attempt": attempt + 1, "error_code": last_error.code},
        )

    raise last_error if last_error is not None else OmadaConnectionError()
