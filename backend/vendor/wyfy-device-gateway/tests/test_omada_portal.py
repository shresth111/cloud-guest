"""Guest authorization -- the EAP path, the gateway path, and its undo.

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
        # Doc 132060's "must contain" list, carried from the redirect's
        # `redirectUrl`. See `omada/portal.py`'s docstring.
        "originUrl": "https://wyfyguest.com/welcome",
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


# --- the two v6.2.10+ "must contain" fields the redirect supplies ----------
#
# `clientIp` and `originUrl` are the two body fields doc 132060 adds to doc
# 13080's shape and lists as required. Neither can be derived locally and
# both arrive on the controller's own redirect. Until these tests existed
# `clientIp` had no coverage at all and `originUrl` was never sent -- and
# neither omission was detectable from a controller's reply, because a
# 6.3.0.100 controller answers every body fault with the same `-41501`.


def test_client_ip_is_sent_when_the_redirect_carried_one():
    ctx = PortalAuthContext(
        client_mac="AA-BB-CC-DD-EE-FF", site="S", client_ip="10.0.5.23"
    )
    assert build_authorize_body(ctx, duration_seconds=60)["clientIp"] == "10.0.5.23"


def test_client_ip_is_absent_rather_than_guessed_when_the_redirect_had_none():
    ctx = PortalAuthContext(client_mac="AA-BB-CC-DD-EE-FF", site="S")
    assert "clientIp" not in build_authorize_body(ctx, duration_seconds=60)


def test_origin_url_is_sent_from_the_redirects_own_landing_page():
    ctx = PortalAuthContext(
        client_mac="AA-BB-CC-DD-EE-FF", site="S", redirect_url="http://neverssl.com/"
    )
    assert (
        build_authorize_body(ctx, duration_seconds=60)["originUrl"]
        == "http://neverssl.com/"
    )


def test_origin_url_is_absent_when_the_redirect_carried_none():
    ctx = PortalAuthContext(client_mac="AA-BB-CC-DD-EE-FF", site="S")
    assert "originUrl" not in build_authorize_body(ctx, duration_seconds=60)


def test_origin_url_is_sent_on_the_gateway_shape_too():
    """Doc 132060 elides the tail of the Gateway body with `...`, and the
    field is not EAP-specific in any reading of it. The gateway path gets the
    same treatment rather than a second rule nobody can source."""
    ctx = PortalAuthContext(
        client_mac="AA-BB-CC-DD-EE-FF",
        site="S",
        gateway_mac="99-88-77-66-55-44",
        vid=30,
        redirect_url="http://neverssl.com/",
    )
    body = build_authorize_body(ctx, duration_seconds=60)
    assert body["originUrl"] == "http://neverssl.com/"
    assert "apMac" not in body


def test_the_redirects_t_is_never_put_in_the_authorize_body():
    """`t` is the redirect's timestamp; `time` is the duration we are asking
    for. They are different values with confusable names, and EAP_CTX carries
    a `t` precisely so this test can prove it does not leak into the body --
    putting it there would ask the controller for a session lasting until the
    year 56000."""
    body = build_authorize_body(EAP_CTX, duration_seconds=3600)
    assert "t" not in body
    assert body["time"] == 3_600_000


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


async def test_an_operator_credential_can_undo_what_it_did():
    """The symmetry, asserted where the authorization itself is asserted.

    These two tests used to say the opposite -- that deauthorization was
    impossible in both modes, on CR-001's claim that TP-Link publishes no
    endpoint for it. TP-Link publishes none; the controller has one, and
    it rides this same operator session. The full behaviour lives in
    ``test_omada_deauth.py``; what is pinned *here* is the property that
    matters next to ``authorize_guest``: any credential that can put a
    guest on the network can also take them off it.
    """
    controller = FakeOmadaController()
    # No rows: "already not authorized" is the end state asked for, so this
    # is a success, and it exercises the credential check rather than the
    # table walk.
    result = await _adapter(controller).deauthorize_guest(
        make_creds(ControllerAuthMode.LEGACY), "Default", "AA-BB-CC-DD-EE-FF"
    )

    assert result is True


async def test_open_api_credentials_alone_can_neither_authorize_nor_deauthorize():
    """The one refusal left, and it refuses in both directions.

    Asserted as a pair deliberately: a build where only one of these
    refused would be a build that could strand a guest on a network it
    could not remove them from.
    """
    controller = FakeOmadaController()
    creds = make_creds(ControllerAuthMode.OPENAPI)

    with pytest.raises(OmadaUnsupportedApiError):
        await _adapter(controller).authorize_guest(
            creds, EAP_CTX, duration_seconds=3600
        )
    with pytest.raises(OmadaUnsupportedApiError):
        await _adapter(controller).deauthorize_guest(
            creds, "Default", "AA-BB-CC-DD-EE-FF"
        )

    assert controller.requests == []


# --- What the controller says when it refuses ------------------------------
#
# MEASURED against a live 6.3.0.100 cloud controller on 2026-09-11, varying
# one body field at a time against a non-existent client MAC. `authType` is
# the only fault the endpoint names; every other one -- a missing `clientMac`
# included, which is beyond argument required -- comes back as a bare -41501.


@pytest.mark.parametrize(
    ("error_code", "msg"),
    [
        (-41500, "Invalid authentication type."),
        (-41501, "Failed to authenticate."),
    ],
)
async def test_a_refused_authorization_is_an_authorization_error_not_a_network_one(
    error_code: int, msg: str
):
    """Both codes used to fall through to the generic ``OmadaError``, whose
    ``OMADA_ERROR`` the backend does not recognise and therefore files under
    ``OMADA_CONNECTION_FAILED`` -- "could not reach the network controller",
    said about a controller that had just answered. That sends whoever reads
    it to look at the network instead of at the request.
    """
    controller = FakeOmadaController()
    controller.authorize_error_code = error_code
    controller.authorize_error_msg = msg
    creds = make_creds(ControllerAuthMode.LEGACY)

    with pytest.raises(OmadaAuthorizationError) as excinfo:
        await _adapter(controller).authorize_guest(
            creds, EAP_CTX, duration_seconds=3600
        )

    assert excinfo.value.code == "OMADA_AUTHORIZATION_FAILED"
    # The raw integer is the only thing that survives the normalization, and
    # it is the only thing that tells the two apart afterwards.
    assert excinfo.value.provider_code == error_code


async def test_the_two_refusal_codes_stay_distinguishable():
    """-41500 names the field that is wrong. -41501 is a catch-all covering a
    wrong MAC, a stale time, an unknown site, an AP that never saw the client
    and a missing required field. Collapsing them would throw away the one
    discrimination this endpoint offers."""
    codes = []
    for error_code in (-41500, -41501):
        controller = FakeOmadaController()
        controller.authorize_error_code = error_code
        with pytest.raises(OmadaAuthorizationError) as excinfo:
            await _adapter(controller).authorize_guest(
                make_creds(ControllerAuthMode.LEGACY), EAP_CTX, duration_seconds=3600
            )
        codes.append(excinfo.value.provider_code)
    assert codes == [-41500, -41501]


async def test_a_refusal_message_carries_no_response_body():
    """``str(exc)`` is rendered into the customer dashboard. The controller's
    own ``msg`` is allowed through ``sanitize_detail``; the body is not."""
    controller = FakeOmadaController()
    controller.authorize_error_code = -41501
    controller.authorize_error_msg = "Failed to authenticate."

    with pytest.raises(OmadaAuthorizationError) as excinfo:
        await _adapter(controller).authorize_guest(
            make_creds(ControllerAuthMode.LEGACY), EAP_CTX, duration_seconds=3600
        )

    rendered = str(excinfo.value)
    assert "Failed to authenticate." in rendered
    assert SESSION_COOKIE_VALUE not in rendered
    assert CSRF_TOKEN not in rendered


async def test_an_unrelated_error_code_is_still_generic():
    """The new branch is scoped to the two portal codes. A code from some
    other endpoint must not be relabelled an authorization refusal."""
    from wyfy_device_gateway.omada.errors import OmadaError

    controller = FakeOmadaController()
    controller.authorize_error_code = -33333

    with pytest.raises(OmadaError) as excinfo:
        await _adapter(controller).authorize_guest(
            make_creds(ControllerAuthMode.LEGACY), EAP_CTX, duration_seconds=3600
        )

    assert excinfo.value.code == "OMADA_ERROR"
    assert excinfo.value.provider_code == -33333
