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

**VERIFIED** (2026-09-12). This used to be tagged INFERRED because no
*current* TP-Link document states it outright. The older ones in the same
document family do, verbatim and unambiguously:

* *API and Code Sample for External Portal Server (Omada Controller 2.5.4
  or below)*, <https://support.omadanetworks.com/en/document/12916/>:
  "The **time** parameter here is the number of seconds before client
  authentication expires. This parameter is defined by the portal server."
* *(Omada Controller 2.6.0 to 3.2.17)*,
  <https://support.omadanetworks.com/us/document/12990/>: the identical
  sentence.

"the number of seconds before client authentication expires" is a duration,
and the same pages set it against ``t=time_since_epoch`` -- their name for a
value that genuinely *is* absolute. That contrast survives every later
revision: 13023, 13080 and 132060 all still document the redirect's ``t`` as
``TIME_SINCE_EPOCH`` while documenting the body's ``time`` only as
"Authentication Expiration time", never as an epoch. What changed at v4.1.5
is the *unit*, seconds -> milliseconds (13023's sample renames the same
argument ``$seconds`` -> ``$milliseconds``), not the meaning.

Corroborated a second way from TP-Link's own Open API specification, where
the same product calls a duration a "timestamp" in exactly this style --
``ExtendOpenApiVO.period`` (``POST .../hotspot/authed-records/{id}/period``,
extend an authorization): "Extended timestamp. Unit:ms. Period should be
within the range of 60000 to 86400000000000(60s to 1000000days)." A minimum
of 60000 glossed as "60s" cannot be an epoch.

Caveat kept deliberately: the explicit sentence is from documents predating
the v4.1.5 rename of the endpoint and of every other field
(``cid``/``ap``/``ssid``/``rid`` -> ``clientMac``/``apMac``/``ssidName``/
``radioId``), so this is a chain of primary documents rather than one
sentence about this exact endpoint. Confirm it anyway on the first real
controller -- ``OMADA_HARDWARE_VERIFICATION.md`` test 1, which is designed
to tell the two readings apart in one call. If it were wrong,
authorizations would be granted for an interval ending in 1970 and would be
rejected or expire instantly: a loud failure on first contact with real
hardware, not a silent one.

Note that a community implementation sending an absolute epoch here is not
evidence against this. Both readings "succeed" for anyone who sends a large
number (either a far-future expiry or a ~55,000-year duration); only the
small numbers this module sends can tell them apart.

## ``clientIp`` is required on v6.2.10+ and absent before it

**VERIFIED**, and a genuine version split. Doc 132060 (v6.2.10 or above)
says the body "must contain the following parameters" and lists
``clientIp`` second in both the EAP and the Gateway shape:

    For EAP: {"clientMac":"...","clientIp":"...","apMac":"...","ssidName":
    "...","radioId":"...","time":"...","authType":"4","originUrl":"", ...}

and the redirect it documents carries it too
(``...?clientMac=...&clientIp=CLIENT_IP&apMac=...``). Doc 13080
(v5.0.15-v6.2.0) does not contain the string ``clientIp`` at all -- not in
the redirect, not in the body, not in the parameter table.

So it is sent only when ``PortalAuthContext.client_ip`` is populated, which
is exactly when the controller itself supplied it on the redirect. That
makes the same code correct on both sides of the split without us having to
predict a version.

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
#: The full enumeration is VERIFIED from TP-Link's own OpenAPI 3.0.1
#: specification (<https://use1-omada-northbound.tplinkcloud.com/v3/api-docs>),
#: which gives it twice, from the two sides of the API:
#:
#: * ``AuthClientOpenApiVO.authType`` (what an authorization record reports):
#:   "0: No Auth; 1: Simple Password; 2: Exrternal Radius; 3: Voucher;
#:   4: External Portal Server; 5: Local User; 6: SMS; 7: Facebook;
#:   8: Hotspot Radius; 9: Mac Auth (with fail over); 10: Admin auth;
#:   12: Form auth" (TP-Link's spelling of "Exrternal" preserved);
#: * ``PortalSetting.authType`` (what a portal may be configured as):
#:   "0: No Authentication; 1: Simple Password; 2: External RADIUS Server;
#:   4: External Portal Server; 11: Hotspot; 15: Ldap; 16: Social Login".
#:
#: 4 is the only value this package ever sends, and it is the only one that
#: means "an external server has already decided this client may pass".
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
        # VERIFIED: a DURATION, in milliseconds -- not an epoch expiry. Both
        # halves of that are sourced in this module's docstring (TP-Link docs
        # 12916/12990 for "duration", 132060 for "millisecond").
        "time": capped * 1000,
        # Sent as the string "4": that is how both the v5 and v6.2.10 docs
        # write it in the JSON body (``"authType":"4"``), even though the
        # PHP sample passes the integer 4. The string matches the documented
        # body exactly, and Omada accepts it either way in every report we
        # have seen.
        "authType": str(AUTH_TYPE_EXTERNAL_PORTAL),
    }

    # VERIFIED (doc 132060): required on v6.2.10+, and absent from doc 13080
    # entirely. Sent only when the redirect actually carried it, which is the
    # only situation in which we have a trustworthy value -- see
    # ``PortalAuthContext.client_ip``.
    if ctx.client_ip:
        body["clientIp"] = ctx.client_ip

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
# NOTE: the Open API revocation path (`POST .../hotspot/clients/{mac}/unauth`,
# `operationId: cancelAuthClient`) is real and is sourced in CHANGE-REQUESTS.md
# CR-001. It is deliberately NOT implemented here. `adapter.deauthorize_guest`
# revokes through the legacy hotspot session instead -- the path that was
# actually run against a controller -- and this module briefly carried a second
# `deauthorize_client` of the same name that nothing called. Wiring the Open API
# path is its own change, and it needs its own run against real hardware before
# anything claims it works.

__all__ = [
    "AUTH_TYPE_EXTERNAL_PORTAL",
    "MAX_DURATION_SECONDS",
    "authorize_client",
    "build_authorize_body",
]
