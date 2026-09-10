"""Guest authorization -- the EAP path, the gateway path, and deauthorization.

This is the one flow with primary TP-Link documentation behind it, and the
one where a wrong field name means a paying guest has no internet. The wire
body is therefore asserted field by field, against the bodies quoted
verbatim in TP-Link's docs.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime

import httpx
import pytest

from wyfy_device_gateway.controller_contract import (
    ControllerAuthMode,
    PortalAuthContext,
)
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter
from wyfy_device_gateway.omada.errors import (
    OmadaAuthorizationError,
    OmadaError,
    OmadaUnsupportedApiError,
)
from wyfy_device_gateway.omada.portal import MAX_DURATION_SECONDS, build_authorize_body

from omada_support import (
    CSRF_TOKEN,
    OMADAC_ID,
    SESSION_COOKIE_VALUE,
    FakeOmadaController,
    envelope,
    make_creds,
    no_sleep,
)

AUTHORIZE_PATH = "/api/v2/hotspot/extPortal/auth"
FIXED_NOW = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)

EAP_CTX = PortalAuthContext(
    client_mac="AA-BB-CC-DD-EE-FF",
    site="Default",
    ap_mac="11-22-33-44-55-66",
    ssid_name="Wyfy Guest",
    radio_id=1,
    t="1725945600000",
    redirect_url="https://wyfyguest.com/welcome",
)

GATEWAY_CTX = PortalAuthContext(
    client_mac="AA-BB-CC-DD-EE-FF",
    site="Default",
    gateway_mac="99-88-77-66-55-44",
    vid=30,
    t="1725945600000",
)


def _adapter(controller: FakeOmadaController) -> OmadaControllerAdapter:
    return OmadaControllerAdapter(
        transport=controller.transport(),
        sleep=no_sleep,
        rng=random.Random(5),
        clock=lambda: FIXED_NOW,
    )


# --- EAP path --------------------------------------------------------------


async def test_authorize_eap_posts_the_documented_body_to_extportal_auth():
    controller = FakeOmadaController()
    creds = make_creds(ControllerAuthMode.LEGACY)

    result = await _adapter(controller).authorize_guest(
        creds, EAP_CTX, duration_seconds=3600
    )

    # It logged in first, then authorized -- in that order, at those paths.
    paths = controller.paths()
    assert paths.index(f"/{OMADAC_ID}/api/v2/hotspot/login") < paths.index(
        f"/{OMADAC_ID}/api/v2/hotspot/extPortal/auth"
    )

    body = controller.body_for(AUTHORIZE_PATH)
    assert body == {
        "clientMac": "AA-BB-CC-DD-EE-FF",
        "time": 3_600_000,  # duration in MILLISECONDS
        "authType": "4",
        "apMac": "11-22-33-44-55-66",
        "ssidName": "Wyfy Guest",
        "radioId": 1,
        "site": "Default",
    }
    assert result.authorized is True
    assert result.expires_at == datetime(2026, 9, 10, 13, 0, tzinfo=UTC)


async def test_authorize_sends_csrf_header_and_session_cookie():
    controller = FakeOmadaController()
    await _adapter(controller).authorize_guest(
        make_creds(ControllerAuthMode.LEGACY), EAP_CTX, duration_seconds=600
    )

    request = controller.request_for(AUTHORIZE_PATH)
    assert request.headers["Csrf-Token"] == CSRF_TOKEN
    assert SESSION_COOKIE_VALUE in request.headers.get("cookie", "")


async def test_eap_body_never_carries_gateway_fields():
    controller = FakeOmadaController()
    await _adapter(controller).authorize_guest(
        make_creds(ControllerAuthMode.LEGACY), EAP_CTX, duration_seconds=600
    )
    body = controller.body_for(AUTHORIZE_PATH)
    assert "gatewayMac" not in body
    assert "vid" not in body


# --- gateway path ----------------------------------------------------------


async def test_authorize_gateway_posts_the_gateway_shaped_body():
    controller = FakeOmadaController()
    await _adapter(controller).authorize_guest(
        make_creds(ControllerAuthMode.LEGACY), GATEWAY_CTX, duration_seconds=1800
    )

    body = controller.body_for(AUTHORIZE_PATH)
    assert body == {
        "clientMac": "AA-BB-CC-DD-EE-FF",
        "time": 1_800_000,
        "authType": "4",
        "gatewayMac": "99-88-77-66-55-44",
        "vid": 30,
        "site": "Default",
    }
    assert "apMac" not in body
    assert "ssidName" not in body
    assert "radioId" not in body


# --- bandwidth limits (v6.2.10+) ------------------------------------------


async def test_rate_limits_are_sent_only_when_requested():
    controller = FakeOmadaController()
    await _adapter(controller).authorize_guest(
        make_creds(ControllerAuthMode.LEGACY),
        EAP_CTX,
        duration_seconds=600,
        down_kbps=20_000,
        up_kbps=5_000,
    )
    body = controller.body_for(AUTHORIZE_PATH)
    assert body["downloadRateLimitKbps"] == 20_000
    assert body["uploadRateLimitKbps"] == 5_000


async def test_rate_limit_fields_are_absent_when_not_requested():
    """These fields only exist from v6.2.10; do not send them to an older
    controller unless the caller actually asked for a limit."""
    controller = FakeOmadaController()
    await _adapter(controller).authorize_guest(
        make_creds(ControllerAuthMode.LEGACY), EAP_CTX, duration_seconds=600
    )
    body = controller.body_for(AUTHORIZE_PATH)
    assert "downloadRateLimitKbps" not in body
    assert "uploadRateLimitKbps" not in body
    assert "totalTrafficLimitBytes" not in body


# --- body builder edge cases ----------------------------------------------


def test_duration_is_converted_to_milliseconds():
    assert build_authorize_body(EAP_CTX, duration_seconds=1)["time"] == 1000
    assert build_authorize_body(EAP_CTX, duration_seconds=7200)["time"] == 7_200_000


def test_duration_is_capped_at_the_sanity_ceiling():
    body = build_authorize_body(EAP_CTX, duration_seconds=999_999_999)
    assert body["time"] == MAX_DURATION_SECONDS * 1000


@pytest.mark.parametrize("bad", [0, -1, -3600])
def test_non_positive_duration_is_rejected(bad):
    with pytest.raises(OmadaAuthorizationError):
        build_authorize_body(EAP_CTX, duration_seconds=bad)


def test_auth_type_is_the_documented_value():
    assert build_authorize_body(EAP_CTX, duration_seconds=60)["authType"] == "4"


def test_a_context_with_only_vid_still_takes_the_gateway_path():
    ctx = PortalAuthContext(client_mac="AA-BB-CC-DD-EE-FF", site="S", vid=10)
    body = build_authorize_body(ctx, duration_seconds=60)
    assert body["vid"] == 10
    assert "apMac" not in body


def test_zero_rate_limits_are_treated_as_no_limit():
    body = build_authorize_body(EAP_CTX, duration_seconds=60, down_kbps=0, up_kbps=0)
    assert "downloadRateLimitKbps" not in body
    assert "uploadRateLimitKbps" not in body


# --- openapi mode + operator credentials ----------------------------------


async def test_openapi_integration_with_operator_credentials_can_authorize():
    """The expected real-world config: Open API for inventory, an operator
    account for the portal."""
    controller = FakeOmadaController()
    creds = make_creds(
        ControllerAuthMode.OPENAPI,
        username="wyfy-operator",
        password="s3cr3t-operator-pw",
    )

    result = await _adapter(controller).authorize_guest(
        creds, EAP_CTX, duration_seconds=900
    )

    assert result.authorized is True
    # It used the operator login, not the Open API token.
    assert controller.login_count == 1
    assert controller.token_count == 0


async def test_authorize_without_operator_credentials_is_unsupported_not_a_guess():
    """No primary-sourced Open API portal-auth endpoint exists, so we refuse
    rather than invent one."""
    controller = FakeOmadaController()
    creds = make_creds(ControllerAuthMode.OPENAPI)  # no username/password

    with pytest.raises(OmadaUnsupportedApiError) as excinfo:
        await _adapter(controller).authorize_guest(creds, EAP_CTX, duration_seconds=600)

    assert excinfo.value.code == "OMADA_API_UNSUPPORTED"
    assert "operator" in str(excinfo.value).lower()
    assert controller.requests == []


# --- session expiry during authorization ----------------------------------


async def test_authorize_recovers_from_an_expired_operator_session():
    controller = FakeOmadaController()
    controller.expire_sessions = 1
    controller.session_expiry_code = -1200

    result = await _adapter(controller).authorize_guest(
        make_creds(ControllerAuthMode.LEGACY), EAP_CTX, duration_seconds=600
    )

    assert result.authorized is True
    assert controller.login_count == 2


# --- deauthorization -------------------------------------------------------


async def test_deauthorize_calls_tp_links_documented_unauth_endpoint():
    """CR-001 said no deauthorization endpoint exists anywhere. It does:
    ``cancelAuthClient`` in TP-Link's own published OpenAPI specification."""
    controller = FakeOmadaController()

    result = await _adapter(controller).deauthorize_guest(
        make_creds(ControllerAuthMode.OPENAPI), "SITE-1", "AA-BB-CC-DD-EE-FF"
    )

    assert result is True
    request = controller.requests[-1]
    assert request.method == "POST"
    assert request.url.path == (
        f"/openapi/v1/{OMADAC_ID}/sites/SITE-1/hotspot/clients/"
        "AA-BB-CC-DD-EE-FF/unauth"
    )
    # The spec documents no request body for this operation, and sending one
    # we invented is exactly the failure mode CR-001 was trying to avoid.
    assert not request.content


async def test_deauthorize_normalizes_the_mac_to_omadas_documented_form():
    """The spec spells the path parameter out as "format: AA-BB-CC-DD-EE-FF".
    A caller holding colon-separated lower case must still address the same
    client rather than silently revoking nobody."""
    controller = FakeOmadaController()

    await _adapter(controller).deauthorize_guest(
        make_creds(ControllerAuthMode.OPENAPI), "SITE-1", "aa:bb:cc:dd:ee:ff"
    )

    assert controller.requests[-1].url.path.endswith(
        "/clients/AA-BB-CC-DD-EE-FF/unauth"
    )


async def test_deauthorize_refuses_in_legacy_mode_without_sending_anything():
    """``cancelAuthClient`` is an Open API operation. A hotspot operator
    credential cannot make it, and pretending otherwise would report a
    revocation that never happened."""
    controller = FakeOmadaController()

    with pytest.raises(OmadaUnsupportedApiError) as excinfo:
        await _adapter(controller).deauthorize_guest(
            make_creds(ControllerAuthMode.LEGACY), "Default", "AA-BB-CC-DD-EE-FF"
        )

    assert excinfo.value.code == "OMADA_API_UNSUPPORTED"
    assert "open api" in str(excinfo.value).lower()
    assert controller.requests == []


async def test_deauthorize_propagates_a_controller_refusal():
    """A non-zero errorCode must not come back as ``True``."""
    controller = FakeOmadaController()
    controller.routes["/unauth"] = lambda request: httpx.Response(
        200, json=envelope(error_code=-1600, msg="Operation not supported.")
    )

    with pytest.raises(OmadaError):
        await _adapter(controller).deauthorize_guest(
            make_creds(ControllerAuthMode.OPENAPI), "SITE-1", "AA-BB-CC-DD-EE-FF"
        )


# --- clientIp: required on v6.2.10+, absent before it -----------------------
# VERIFIED against TP-Link doc 132060 ("API and Code Samples for External
# Portal Server (Omada Controller v6.2.10 or Above)"), which lists clientIp
# among the parameters the body "must contain" for both the EAP and the
# Gateway shape, and against doc 13080 (v5.0.15-v6.2.0), which does not
# contain the string at all.


def test_client_ip_is_sent_when_the_redirect_carried_it():
    body = build_authorize_body(
        PortalAuthContext(
            client_mac="AA-BB-CC-DD-EE-FF",
            site="Default",
            ap_mac="11-22-33-44-55-66",
            ssid_name="Wyfy Guest",
            radio_id=1,
            client_ip="10.0.0.99",
        ),
        duration_seconds=600,
    )
    assert body["clientIp"] == "10.0.0.99"


def test_client_ip_is_omitted_entirely_on_an_older_controllers_redirect():
    """A v5 controller never sends clientIp, so we must not invent one --
    an empty string or a guessed peer address is a value the controller
    would try to match against a real pending session and fail."""
    body = build_authorize_body(
        PortalAuthContext(
            client_mac="AA-BB-CC-DD-EE-FF",
            site="Default",
            gateway_mac="11-22-33-44-55-66",
            vid=30,
        ),
        duration_seconds=600,
    )
    assert "clientIp" not in body


async def test_client_ip_reaches_the_controller_on_the_authorize_call():
    controller = FakeOmadaController()
    ctx = PortalAuthContext(
        client_mac="AA-BB-CC-DD-EE-FF",
        site="Default",
        ap_mac="11-22-33-44-55-66",
        ssid_name="Wyfy Guest",
        radio_id=1,
        client_ip="10.0.0.99",
    )

    await _adapter(controller).authorize_guest(
        make_creds(ControllerAuthMode.LEGACY), ctx, duration_seconds=600
    )

    authorize_body = controller.bodies[-1]
    assert authorize_body["clientIp"] == "10.0.0.99"
    assert authorize_body["clientMac"] == "AA-BB-CC-DD-EE-FF"
    assert authorize_body["authType"] == "4"
    assert authorize_body["time"] == 600_000
