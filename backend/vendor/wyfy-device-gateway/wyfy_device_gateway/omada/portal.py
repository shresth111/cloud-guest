"""External-portal client authorization -- the one flow with primary sources.

This is the Omada equivalent of the MikroTik ``link-login-only`` POST the
platform already performs: the network-enforcement step that follows a guest
having already been authenticated by OTP/voucher/consent elsewhere. Nothing
in this module authenticates anybody.

## Endpoint (VERIFIED against TP-Link documentation)

``POST /{omadacId}/api/v2/hotspot/extPortal/auth``, sent with the
``Csrf-Token`` header from the operator login and the session cookie the
controller set. See ``auth.py``'s module docstring for the full three-source
resolution of which of ``/hotspot/login`` and ``/hotspot/extPortal/auth`` is
which, including why TP-Link's own PHP sample has them swapped.

Primary sources:

* v5.0.15-v6.2.0: <https://support.omadanetworks.com/us/document/13080/>
* v6.2.10+: <https://support.omadanetworks.com/en/document/132060/>
* v4.1.5-v4.4.6: <https://support.omadanetworks.com/us/document/13023/>

## Two body shapes, chosen by which device enforces the portal

Verbatim from doc 13080:

    For EAP: {"clientMac","apMac","ssidName","radioId","site","time","authType":"4"}
    For Gateway: {"clientMac","gatewayMac","vid","site","time","authType":"4"}

``authType: 4`` is external-portal authentication. The shape is selected by
inspecting ``PortalAuthContext``: a populated ``gateway_mac`` or ``vid``
means the gateway path, otherwise the EAP path. We never mix them -- sending
an ``apMac`` alongside a ``gatewayMac`` would give the controller a body it
cannot match to a real pending session.

## ``time`` is a DURATION IN MILLISECONDS, not an expiry timestamp

This is the single easiest thing to get wrong here, and TP-Link's docs
actively mislead on it. The parameter table calls it "Authentication
Expiration time", which reads like an absolute epoch. It is not:

* The v6.2.10 doc's table says "Unit here is **millisecond**"
  (<https://support.omadanetworks.com/en/document/132060/>), while the
  older v5 doc's table says "microsecond" -- a documentation error that
  TP-Link corrected in the newer revision.
* Both docs' PHP samples settle it by naming the parameter:
  ``authorize($clientMac, $apMac, $ssidName, $radioId, $milliseconds)`` with
  ``'time' => $milliseconds``. A variable named ``$milliseconds`` passed
  straight through is a duration, not a date.

So ``duration_seconds`` is multiplied by 1000 and sent as ``time``.

**INFERRED, unverified:** that ``time`` is a *duration* rather than an
absolute epoch-milliseconds expiry is an inference from the sample code's
parameter name and from the redirect's separate ``t`` parameter already
carrying "current timestamp in milliseconds". We could not find a sentence
in any TP-Link document that states it outright. If this inference is wrong,
authorizations would be granted for an interval ending in 1970 and would be
rejected or expire instantly -- a loud, immediately-obvious failure on first
contact with real hardware, not a silent one. That is the main reason it is
safe to ship the inference and verify it on the first real controller.

## Bandwidth limits are v6.2.10+ only

``downloadRateLimitKbps`` / ``uploadRateLimitKbps`` /
``totalTrafficLimitBytes`` appear in the v6.2.10 document's body and **not**
in the v5.0.15-v6.2.0 one. They are therefore sent only when the caller
actually asks for a limit. Omada's own external-portal API ignores unknown
JSON fields in the bodies we have seen, but sending version-specific fields
unconditionally to an older controller is an avoidable risk on the one call
in this package that a paying guest's internet access depends on.

## Revoking one of these

TP-Link publishes no way to revoke an external-portal authorization, and
that used to be the end of the sentence. It is not: the controller has a
disconnect in the Hotspot Manager tree, reachable with the same operator
session this module's call uses, and it is implemented in ``deauth.py``.
Nothing about the authorize body changes because of it -- an authorization
is still granted for ``time`` milliseconds and still lapses on its own --
but the grant is no longer irrevocable. See ``adapter.deauthorize_guest``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from ..controller_contract import AuthorizationResult, PortalAuthContext
from .auth import LEGACY_AUTHORIZE_PATH
from .client import OmadaHttpClient
from .errors import OmadaAuthorizationError
from .redaction import sanitize_detail

#: VERIFIED (TP-Link docs 13080 / 132060): external portal / RADIUS-free auth.
AUTH_TYPE_EXTERNAL_PORTAL = 4

#: Sanity ceiling on a single authorization. A caller passing a nonsense
#: duration (a timestamp mistaken for a duration, say) would otherwise ask
#: the controller for a session lasting decades.
#:
#: This is deliberately **not** the platform's policy ceiling. That one is
#: ``network_integration.constants.MAX_SESSION_DURATION_SECONDS`` and is much
#: lower; it rejects rather than caps, so an operator is told the number they
#: asked for is not allowed. Keeping this bound above it is what stops the two
#: from disagreeing silently -- when they were both 24h, raising the policy
#: ceiling alone would have had the platform promise a week and the controller
#: quietly receive a day.
MAX_DURATION_SECONDS = 30 * 24 * 60 * 60


def build_authorize_body(
    ctx: PortalAuthContext,
    *,
    duration_seconds: int,
    down_kbps: int | None = None,
    up_kbps: int | None = None,
) -> dict[str, Any]:
    """Build the ``extPortal/auth`` request body for whichever path applies.

    Kept as a pure function, separate from the request, so the exact wire
    body can be asserted in tests without any HTTP in the way -- this is the
    one payload in the package where a wrong field name means a guest with no
    internet, so it is worth being able to test directly.
    """
    if duration_seconds <= 0:
        raise OmadaAuthorizationError(
            "The requested access duration must be greater than zero."
        )
    capped = min(int(duration_seconds), MAX_DURATION_SECONDS)

    body: dict[str, Any] = {
        "clientMac": ctx.client_mac,
        # VERIFIED: milliseconds. See this module's docstring.
        "time": capped * 1000,
        # Sent as the string "4": that is how both the v5 and v6.2.10 docs
        # write it in the JSON body (``"authType":"4"``), even though the
        # PHP sample passes the integer 4. The string matches the documented
        # body exactly, and Omada accepts it either way in every report we
        # have seen.
        "authType": str(AUTH_TYPE_EXTERNAL_PORTAL),
    }

    is_gateway_path = ctx.gateway_mac is not None or ctx.vid is not None
    if is_gateway_path:
        if ctx.gateway_mac is not None:
            body["gatewayMac"] = ctx.gateway_mac
        if ctx.vid is not None:
            body["vid"] = ctx.vid
    else:
        if ctx.ap_mac is not None:
            body["apMac"] = ctx.ap_mac
        if ctx.ssid_name is not None:
            body["ssidName"] = ctx.ssid_name
        if ctx.radio_id is not None:
            body["radioId"] = ctx.radio_id

    # ``site`` is documented in the v5 doc's bodies for both paths and
    # omitted from the v6.2.10 doc's. Sent whenever we have it: an extra
    # field the newer controller ignores is harmless, whereas omitting it on
    # a v5 controller that wants it is not.
    if ctx.site:
        body["site"] = ctx.site

    # v6.2.10+ only -- sent only when a limit was actually requested.
    if down_kbps is not None and down_kbps > 0:
        body["downloadRateLimitKbps"] = int(down_kbps)
    if up_kbps is not None and up_kbps > 0:
        body["uploadRateLimitKbps"] = int(up_kbps)

    return body


async def authorize_client(
    client: OmadaHttpClient,
    omadac_id: str,
    ctx: PortalAuthContext,
    *,
    duration_seconds: int,
    down_kbps: int | None = None,
    up_kbps: int | None = None,
    now: datetime | None = None,
) -> AuthorizationResult:
    """Authorize one client for network access through the external portal.

    On success the controller replies with ``{"errorCode": 0}`` and nothing
    else -- no session id, no confirmed expiry. ``expires_at`` is therefore
    computed locally from the duration we asked for and is an expectation
    rather than an observation (see ``AuthorizationResult``'s docstring).
    """
    body = build_authorize_body(
        ctx,
        duration_seconds=duration_seconds,
        down_kbps=down_kbps,
        up_kbps=up_kbps,
    )
    capped_seconds = int(body["time"]) // 1000

    # Errors propagate untouched. ``client.request`` has already normalized
    # them, and the backend needs to keep telling "controller unreachable"
    # apart from "controller said no" -- wrapping everything in
    # ``OmadaAuthorizationError`` here would destroy that distinction.
    envelope = await client.request(
        "POST",
        LEGACY_AUTHORIZE_PATH.format(omadac_id=omadac_id),
        json=body,
    )

    detail = sanitize_detail(envelope.msg)
    started = now or datetime.now(tz=UTC)
    return AuthorizationResult(
        authorized=True,
        expires_at=started + timedelta(seconds=capped_seconds),
        provider_code=detail,
    )


__all__ = [
    "AUTH_TYPE_EXTERNAL_PORTAL",
    "MAX_DURATION_SECONDS",
    "authorize_client",
    "build_authorize_body",
]
