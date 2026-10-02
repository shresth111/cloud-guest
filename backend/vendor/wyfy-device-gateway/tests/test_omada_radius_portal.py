"""RADIUS portal mode (``authType 2``) -- the server-side ``browserauth`` POST.

The second Omada captive-portal contract, and the one whose *answer* is the
easy thing to get wrong: success is a ``302``, not a body. An earlier
measurement appeared to show ``302`` on a rejection too (taken with RADIUS
accounting enabled, which fails every auth in a different way), and encoding
that first reading would have made every rejected guest look authorized. The
corrected reading is asserted here in both directions.

Everything else worth pinning is the wire body -- measured on Omada Software
Controller 5.15.24.19 on 2026-09-17, where it returned ``302`` and moved the
client to ``authStatus 2 / authType 2`` -- and the port resolution, which is
this package's half of an SSRF boundary.
"""

from __future__ import annotations

import httpx
import pytest

from wyfy_device_gateway.controller_contract import ControllerTlsMode
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter
from wyfy_device_gateway.omada.errors import (
    OmadaConnectionError,
    OmadaTimeoutError,
    OmadaTlsPinMismatchError,
)
from wyfy_device_gateway.omada.radius_portal import (
    DEFAULT_PORTAL_PORTS,
    RADIUS_BROWSERAUTH_PATH,
    RadiusPortalContext,
    build_browserauth_body,
    resolve_portal_origin,
    submit_browserauth,
)

from omada_support import make_creds

# The body that opened the gate on real hardware, verbatim from
# RADIUS-PORTAL-MODE.md.
MEASURED_CTX = RadiusPortalContext(
    client_mac="26-79-94-B5-24-D9",
    client_ip="192.168.1.121",
    ap_mac="B8-FB-B3-5D-64-3E",
    gateway_mac="",
    ssid_name="WyfyRadTest",
    vid="",
    radio_id=1,
    origin_url="http://neverssl.com/",
)


# --- the body --------------------------------------------------------------


def test_the_body_is_the_one_measured_on_hardware() -> None:
    assert build_browserauth_body(
        MEASURED_CTX, username="guest@example.com", password="welcome123"
    ) == {
        "clientMac": "26-79-94-B5-24-D9",
        "clientIp": "192.168.1.121",
        "apMac": "B8-FB-B3-5D-64-3E",
        "ssidName": "WyfyRadTest",
        "radioId": "1",
        "authType": "2",
        "originUrl": "http://neverssl.com/",
        "username": "guest@example.com",
        "password": "welcome123",
    }


def test_an_empty_field_does_not_travel() -> None:
    """``gatewayMac=`` and ``vid=`` are on the redirect and are empty. Sent
    as absent rather than as empty strings: some firmware distinguishes the
    two and we have measured neither, so we send only what has a value."""
    body = build_browserauth_body(MEASURED_CTX, username="u", password="p")
    assert "gatewayMac" not in body
    assert "vid" not in body


def test_a_bare_context_sends_only_what_it_has() -> None:
    body = build_browserauth_body(
        RadiusPortalContext(client_mac="AA-BB-CC-DD-EE-FF"),
        username="u",
        password="p",
    )
    assert set(body) == {"clientMac", "authType", "username", "password"}


def test_auth_type_is_two_and_a_string() -> None:
    """``2`` is External RADIUS Server. The other contract sends ``"4"``; the
    two must never be confused, because a portal configured for one will not
    answer the other."""
    body = build_browserauth_body(MEASURED_CTX, username="u", password="p")
    assert body["authType"] == "2"


# --- the address -----------------------------------------------------------


def test_the_portal_origin_comes_from_the_stored_url() -> None:
    """The management API is on 8043 and the portal listener is on 8843.
    Only the *port* changes; host and scheme are the stored ones."""
    assert (
        resolve_portal_origin("https://omada.example.test:8043")
        == "https://omada.example.test:8843"
    )
    assert (
        resolve_portal_origin("http://omada.example.test:8088")
        == "http://omada.example.test:8088"
    )


def test_an_explicit_port_overrides_the_default() -> None:
    assert (
        resolve_portal_origin("https://omada.example.test:8043", 9443)
        == "https://omada.example.test:9443"
    )


def test_an_ipv6_host_survives_the_round_trip() -> None:
    assert resolve_portal_origin("https://[2001:db8::1]:8043") == (
        "https://[2001:db8::1]:8843"
    )


def test_the_default_ports_are_the_measured_ones() -> None:
    assert DEFAULT_PORTAL_PORTS == {"https": 8843, "http": 8088}


# --- the answer ------------------------------------------------------------


async def _submit(handler, **creds_kwargs):
    return await submit_browserauth(
        make_creds(**creds_kwargs),
        RadiusPortalContext(client_mac="AA-BB-CC-DD-EE-FF"),
        username="u",
        password="p",
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_a_302_is_success_and_carries_the_landing_url() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == RADIUS_BROWSERAUTH_PATH
        assert request.headers["content-type"] == (
            "application/x-www-form-urlencoded"
        )
        return httpx.Response(302, headers={"location": "http://neverssl.com/"})

    result = await _submit(handler)
    assert result.authorized is True
    assert result.landing_url == "http://neverssl.com/"


@pytest.mark.asyncio
async def test_the_redirect_is_not_followed() -> None:
    """Two reasons, either sufficient. Following it would destroy the only
    success signal this endpoint has, and it would route around the SSRF
    validation the caller performed on one specific host."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://neverssl.com/"})

    await _submit(handler)
    assert len(seen) == 1
    assert "neverssl" not in seen[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [-41501, -41529, -41530])
async def test_a_200_with_json_is_a_refusal_and_keeps_the_code(code: int) -> None:
    """The corrected reading. This is the assertion that would have caught
    the first, wrong measurement."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"errorCode": code, "msg": "..."})

    result = await _submit(handler)
    assert result.authorized is False
    assert result.provider_code == code
    assert result.http_status == 200


@pytest.mark.asyncio
async def test_a_400_means_a_field_is_missing_from_our_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="")

    result = await _submit(handler)
    assert result.authorized is False
    assert result.http_status == 400
    assert result.provider_code is None


@pytest.mark.asyncio
async def test_an_unparseable_body_is_still_a_refusal() -> None:
    """Fails closed. A body we cannot read is never read as success, and the
    controller's prose is never carried out of this module either way."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>nope</html>")

    result = await _submit(handler)
    assert result.authorized is False
    assert result.provider_code is None


# --- retries ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_timeout_is_retried_once_then_raised() -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(OmadaTimeoutError):
        await _submit(handler)
    assert len(attempts) == 2


@pytest.mark.asyncio
async def test_a_connect_failure_is_retried_once_then_raised() -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(OmadaConnectionError):
        await _submit(handler)
    assert len(attempts) == 2


@pytest.mark.asyncio
async def test_an_answered_call_is_never_retried() -> None:
    """Re-sending after a reject makes a venue's RADIUS server reject the
    same guest twice; after a 302 it authorizes them twice."""
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(200, json={"errorCode": -41529})

    await _submit(handler)
    assert len(attempts) == 1


# --- trust -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_pinning_with_no_fingerprint_refuses_before_the_request() -> None:
    """An integration that says it pins and does not is a lie told at exactly
    the moment the pin mattered. Same rule as every other call on this
    controller -- this module adds no relaxation of its own."""
    with pytest.raises(OmadaTlsPinMismatchError):
        await _submit(
            lambda request: httpx.Response(302, headers={"location": "/x"}),
            tls_mode=ControllerTlsMode.PINNED,
            tls_pinned_sha256=None,
        )


# --- through the adapter ---------------------------------------------------


@pytest.mark.asyncio
async def test_the_adapter_repoints_the_port_and_leaves_the_host_alone() -> None:
    """The adapter is handed the controller's *management* URL, exactly as
    every other method is, and is the layer that knows the portal answers
    somewhere else."""
    seen: list[httpx.URL] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        return httpx.Response(302, headers={"location": "/done"})

    adapter = OmadaControllerAdapter(transport=httpx.MockTransport(handler))
    result = await adapter.authorize_guest_via_radius_portal(
        make_creds(),
        MEASURED_CTX,
        username="u",
        password="p",
    )
    assert result.authorized is True
    assert seen[0].host == "omada.example.test"
    assert seen[0].port == 8843
    assert seen[0].path == RADIUS_BROWSERAUTH_PATH


@pytest.mark.asyncio
async def test_the_adapter_honours_an_explicit_portal_port() -> None:
    seen: list[httpx.URL] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        return httpx.Response(302, headers={"location": "/done"})

    adapter = OmadaControllerAdapter(transport=httpx.MockTransport(handler))
    await adapter.authorize_guest_via_radius_portal(
        make_creds(),
        MEASURED_CTX,
        username="u",
        password="p",
        portal_port=9443,
    )
    assert seen[0].port == 9443


@pytest.mark.asyncio
async def test_no_operator_credential_is_sent_on_this_path() -> None:
    """There is no login leg here at all: ``username`` is the guest's own
    identifier and this platform's RADIUS server authorizes by session
    lookup. One request goes out, and it carries no cookie and no token."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "/done"})

    adapter = OmadaControllerAdapter(transport=httpx.MockTransport(handler))
    await adapter.authorize_guest_via_radius_portal(
        make_creds(), MEASURED_CTX, username="guest@example.com", password="p"
    )
    assert len(seen) == 1
    assert "cookie" not in {key.lower() for key in seen[0].headers}
    assert "csrf-token" not in {key.lower() for key in seen[0].headers}
