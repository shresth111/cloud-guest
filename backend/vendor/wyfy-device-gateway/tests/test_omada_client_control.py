"""Per-client control: rate limit encoding, the clamp, block and unblock.

The encoding tests are the load-bearing ones. TP-Link's spec bounds
``upLimit``/``downLimit`` at 1-1024 and the controller was measured *not* to
enforce it -- it accepted, stored and returned ``downLimit: 5000`` with the
Mbps unit. So the clamp is ours, and if it regresses nothing downstream will
notice until a venue is quietly holding a limit its access points ignore.
"""

from __future__ import annotations

import random

import pytest
from omada_support import (
    OMADAC_ID,
    FakeOmadaController,
    envelope,
    make_creds,
    no_sleep,
)
from wyfy_device_gateway.controller_contract import ControllerAuthMode
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter
from wyfy_device_gateway.omada.client_control import (
    MAX_LIMIT,
    UNIT_KBPS,
    UNIT_MBPS,
    build_rate_limit_body,
    decode_rate,
    encode_rate,
)
from wyfy_device_gateway.omada.errors import (
    OmadaClientNotFoundError,
    OmadaUnsupportedApiError,
)

SITE_ID = "site-abc123"
CLIENT_MAC = "aa:bb:cc:dd:ee:ff"
WIRE_MAC = "AA-BB-CC-DD-EE-FF"


def _adapter(controller: FakeOmadaController) -> OmadaControllerAdapter:
    return OmadaControllerAdapter(
        transport=controller.transport(), sleep=no_sleep, rng=random.Random(7)
    )


# --- the encoding ----------------------------------------------------------


def test_a_rate_inside_the_kbps_range_is_sent_as_kbps_unchanged():
    assert encode_rate(512) == (UNIT_KBPS, 512, False)
    assert encode_rate(MAX_LIMIT) == (UNIT_KBPS, MAX_LIMIT, False)


def test_a_rate_above_the_kbps_range_switches_to_mbps():
    # 10 Mbps. Exactly representable, so nothing is clamped.
    assert encode_rate(10_000) == (UNIT_MBPS, 10, False)


def test_a_rate_mbps_cannot_express_is_rounded_down_and_says_so():
    """1500 kbps is not a whole number of Mbps, so the applied limit is not
    the requested one -- and the caller is told, rather than being shown the
    number they typed while the controller holds a different one.

    It rounds **down**. Rounding to nearest sent 2 Mbps for a 1500 kbps
    request: a 2000 kbps cap for a venue that asked for 1500, reachable from
    any saved ``QueueProfile``. A cap is a ceiling, and a ceiling that came
    back 33% higher than the one that was set is not one.
    """
    unit, limit, clamped = encode_rate(1_500)
    assert (unit, limit) == (UNIT_MBPS, 1)
    assert clamped is True


def test_no_rate_ever_encodes_to_more_than_was_asked_for():
    """The property, not one example: over the whole span where the Mbps
    unit is in play, what goes on the wire never exceeds the request."""
    for requested in range(MAX_LIMIT + 1, 40_000, 7):
        unit, limit, _ = encode_rate(requested)
        assert decode_rate(unit, limit) <= requested


def test_a_rate_just_above_the_kbps_range_floors_to_one_mbps():
    """1025 kbps cannot be sent as Kbps (the number exceeds 1024) and is not
    yet 2 Mbps. Flooring puts it at 1 Mbps -- under the request, which is the
    safe direction, and ``clamped`` says the number moved."""
    unit, limit, clamped = encode_rate(1_025)
    assert (unit, limit) == (UNIT_MBPS, 1)
    assert clamped is True


def test_a_rate_above_the_documented_ceiling_is_clamped_to_1024_mbps():
    """The controller stored 5000 Mbps when asked (measured 2026-09-17). It
    is not asked: the documented contract is 1-1024 and we have no evidence
    an access point honours anything above it."""
    unit, limit, clamped = encode_rate(5_000_000)
    assert (unit, limit) == (UNIT_MBPS, MAX_LIMIT)
    assert clamped is True


def test_the_body_never_carries_a_rate_limit_profile_id():
    """``rateLimitId`` points a client at a *shared site profile*. Editing
    that profile changes the limit for everything bound to it -- a venue-wide
    write wearing a per-client mask. Only custom values are ever sent."""
    body, _ = build_rate_limit_body(down_kbps=10_000, up_kbps=5_000)
    assert "rateLimitId" not in body


def test_limiting_one_direction_leaves_the_other_unlimited():
    body, applied = build_rate_limit_body(down_kbps=10_000, up_kbps=None)
    assert body["downEnable"] is True
    assert body["upEnable"] is False
    assert applied.down_kbps == 10_000
    # None, not 0: "unlimited upstream" is not "zero upstream".
    assert applied.up_kbps is None


def test_limiting_neither_direction_disables_the_limit_entirely():
    """An enabled rate limit with both directions off reads as "throttled" in
    the controller's own UI and throttles nothing."""
    body, applied = build_rate_limit_body(down_kbps=0, up_kbps=0)
    assert body["enable"] is False
    assert applied.enabled is False


# --- the calls -------------------------------------------------------------


async def test_setting_a_rate_limit_patches_the_client_ratelimit_path():
    controller = FakeOmadaController()
    controller.routes["/ratelimit"] = lambda _r: __import__("httpx").Response(
        200, json=envelope()
    )

    applied = await _adapter(controller).set_client_rate_limit(
        make_creds(), SITE_ID, CLIENT_MAC, down_kbps=10_000, up_kbps=2_000
    )

    assert (
        f"/openapi/v1/{OMADAC_ID}/sites/{SITE_ID}/clients/{WIRE_MAC}/ratelimit"
        in controller.paths()
    )
    assert controller.request_for("/ratelimit").method == "PATCH"
    body = controller.body_for("/ratelimit")
    # The Open API envelope, measured on 5.15.24.19: this endpoint takes
    # `mode` + `customRateLimit`, NOT the flat object internal v2 takes at
    # `PATCH .../clients/{mac}`. Sending v2's shape here answers
    # `200 {"errorCode": -1001, "Invalid request parameters."}` -- an error
    # inside a success status, which is why it read as a permissions problem
    # for a day. Assert the envelope, not just the numbers inside it.
    assert body["mode"] == 0
    assert set(body) == {"mode", "customRateLimit"}
    limits = body["customRateLimit"]
    assert limits["downUnit"] == UNIT_MBPS
    assert limits["downLimit"] == 10
    assert limits["upLimit"] == 2
    assert applied.enabled is True
    assert applied.down_kbps == 10_000


async def test_the_mac_reaches_the_path_in_omadas_own_spelling():
    """The MAC is in the URL path, so its spelling is load-bearing: a
    colon-separated MAC is a different path, not a different format."""
    controller = FakeOmadaController()
    await _adapter(controller).block_client(make_creds(), SITE_ID, "aabbccddeeff")
    assert any(WIRE_MAC in path for path in controller.paths())


async def test_clearing_a_rate_limit_sends_the_off_state():
    controller = FakeOmadaController()
    applied = await _adapter(controller).clear_client_rate_limit(
        make_creds(), SITE_ID, CLIENT_MAC
    )
    body = controller.body_for("/ratelimit")
    assert body["mode"] == 0
    limits = body["customRateLimit"]
    assert limits["enable"] is False
    assert limits["downEnable"] is False and limits["upEnable"] is False
    # Not zero, though an untouched client reads back zero. The Open API
    # validates the 1..1024 range BEFORE it looks at `enable`, so a clear
    # carrying 0 is refused with -1001 "Value of down limit is from 1 to
    # 1024." -- measured. The number is inert; `enable: false` is what makes
    # it not a limit.
    assert limits["downLimit"] >= 1 and limits["upLimit"] >= 1
    assert applied.enabled is False
    assert applied.down_kbps is None


async def test_block_and_unblock_hit_their_own_distinct_paths():
    controller = FakeOmadaController()
    adapter = _adapter(controller)
    await adapter.block_client(make_creds(), SITE_ID, CLIENT_MAC)
    await adapter.unblock_client(make_creds(), SITE_ID, CLIENT_MAC)

    base = f"/openapi/v1/{OMADAC_ID}/sites/{SITE_ID}/clients/{WIRE_MAC}"
    assert f"{base}/block" in controller.paths()
    assert f"{base}/unblock" in controller.paths()
    assert controller.request_for("/block").method == "POST"


async def test_blocking_twice_is_not_an_error():
    """Measured on the controller: a second block returned ``errorCode 0``.
    A console that offers a Block button must be safe to double-click."""
    controller = FakeOmadaController()
    adapter = _adapter(controller)
    assert await adapter.block_client(make_creds(), SITE_ID, CLIENT_MAC) is True
    assert await adapter.block_client(make_creds(), SITE_ID, CLIENT_MAC) is True


async def test_a_mac_the_site_does_not_know_is_a_client_not_found_error():
    """Three different codes come back for config/block/unblock and all three
    mean the same thing to us. Without this mapping they fall through to the
    generic error, which the backend files under "could not reach the network
    controller" -- false about a controller that just answered."""
    import httpx

    controller = FakeOmadaController()
    controller.routes["/block"] = lambda _r: httpx.Response(
        200, json=envelope(error_code=-41002, msg="This client does not exist.")
    )
    with pytest.raises(OmadaClientNotFoundError):
        await _adapter(controller).block_client(make_creds(), SITE_ID, CLIENT_MAC)


# --- the legacy refusal ----------------------------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "set_client_rate_limit",
        "clear_client_rate_limit",
        "block_client",
        "unblock_client",
    ],
)
async def test_a_hotspot_operator_credential_is_refused_before_any_request(method):
    """A ``legacy`` integration can do none of this, and the refusal happens
    here rather than as a controller error that reads like a wrong password.
    There is no fallback: the client record lives in the site tree and a
    hotspot-operator session reaches the portal tree only."""
    controller = FakeOmadaController()
    adapter = _adapter(controller)
    creds = make_creds(ControllerAuthMode.LEGACY)

    with pytest.raises(OmadaUnsupportedApiError) as excinfo:
        await getattr(adapter, method)(creds, SITE_ID, CLIENT_MAC)

    assert "Open API" in str(excinfo.value)
    # Refused before a socket was opened -- not even a login was attempted.
    assert controller.requests == []
