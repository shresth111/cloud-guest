"""Guest authorization -- the EAP path, the gateway path, and deauthorization.

This is the one flow with primary TP-Link documentation behind it, and the
one where a wrong field name means a paying guest has no internet. The wire
body is therefore asserted field by field, against the bodies quoted
verbatim in TP-Link's docs.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime

import pytest

from wyfy_device_gateway.controller_contract import (
    ControllerAuthMode,
    PortalAuthContext,
)
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter
from wyfy_device_gateway.omada.errors import (
    OmadaAuthorizationError,
    OmadaUnsupportedApiError,
)
from wyfy_device_gateway.omada.portal import MAX_DURATION_SECONDS, build_authorize_body

from omada_support import (
    CSRF_TOKEN,
    OMADAC_ID,
    SESSION_COOKIE_VALUE,
    FakeOmadaController,
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


async def test_deauthorize_reports_unsupported_rather_than_guessing():
    """TP-Link publishes no deauthorization endpoint. We say so with a
    normalized, catchable code instead of repurposing the blocklist."""
    controller = FakeOmadaController()

    with pytest.raises(OmadaUnsupportedApiError) as excinfo:
        await _adapter(controller).deauthorize_guest(
            make_creds(ControllerAuthMode.LEGACY), "Default", "AA-BB-CC-DD-EE-FF"
        )

    assert excinfo.value.code == "OMADA_API_UNSUPPORTED"
    assert "expires" in str(excinfo.value).lower()
    # Crucially: it never sent a write to the controller.
    assert controller.requests == []


async def test_deauthorize_is_unsupported_in_openapi_mode_too():
    controller = FakeOmadaController()
    with pytest.raises(OmadaUnsupportedApiError):
        await _adapter(controller).deauthorize_guest(
            make_creds(ControllerAuthMode.OPENAPI), "Default", "AA-BB-CC-DD-EE-FF"
        )
    assert controller.requests == []
