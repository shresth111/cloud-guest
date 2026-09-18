"""Per-client control on one Omada site: rate limit, block, unblock.

Separate from ``clients.py`` on purpose. That module *reads* the client grid;
this one *writes* to a client record, and the two have different failure
stories, different error codes and different surfaces. Keeping them apart is
what lets ``clients.py`` stay a pure parser.

## Provenance -- read this before changing a path

Everything here was probed against **Omada Software Controller 5.15.24.19**
on 2026-09-17 (``wyfy-omada/CAPABILITY-MATRIX.md``), and the provenance of
each path is not uniform. Say which you are relying on before you trust it:

* **MEASURED, on the controller-internal v2 surface.** The full set/read-back/
  change/restore cycle for ``rateLimit`` and the block -> idempotent block ->
  unblock -> idempotent unblock cycle were both performed, verbatim responses
  recorded, and the client restored byte-identically. Those calls went to
  ``PATCH /{cid}/api/v2/sites/{siteId}/clients/{mac}`` and
  ``POST /{cid}/api/v2/sites/{siteId}/cmd/clients/{mac}/(un)block``.
* **SPEC-PRESENT, on the Open API surface, and NOT measured.** The Open API
  twins below appear in this controller's own ``/v3/api-docs`` (2.88 MB,
  1224 paths, served by the 5.15.24.19 box itself), with the request bodies
  and ranges quoted in the constants. Nobody has executed them, because this
  deployment has no Open API app credential on that controller.

**This module implements the Open API twins, not the v2 calls it measured**,
and that is a deliberate, uncomfortable choice. This package speaks
``/openapi/v1`` and nothing else: it holds no admin username/password session
for the internal v2 surface, and adding one would mean a second auth flow, a
second session cache and a credential class this platform does not store. So
the honest statement is: *the capability is proven on the controller; the
surface we reach it through is documented but unexercised.* A caller must not
describe it as measured. See ``CAPABILITY-MATRIX.md`` sections 3.1 and 4.

## The clamp, and why it is ours rather than the controller's

TP-Link's own spec says ``upLimit``/``downLimit`` are "within the range of
1-1024". The controller **does not enforce that**: a ``downLimit`` of 5000
with ``downUnit: 2`` (Mbps) was accepted, stored and read back. We have
evidence the *controller* stores 5000 Mbps and no evidence at all that the
*AP* honours it. So the spec's range is the contract this module enforces,
on our side, before the request leaves. See :func:`encode_rate`.

## What this module does NOT do

No "list blocked clients". The block flag lives on the known-client record
and is exposed by ``GET .../insight/clients`` on the **internal v2** surface,
where ``filters.blocked=true`` was measured to be *silently ignored* (it
returned all six rows, every one ``block: false``). The Open API client grid
this package reads carries no block field at all. Returning an empty list
would be a false statement about the venue, so nothing here returns one --
the capability is refused upstream with a named reason instead.
"""

from __future__ import annotations

from typing import Any

from ..controller_contract import ClientRateLimit
from .client import OmadaHttpClient
from .types import normalize_mac

#: SPEC-PRESENT (this controller's ``/v3/api-docs``, "Set ratelimit setting
#: for given client"). Body is ``Client Rate Limit Setting``; see
#: :func:`build_rate_limit_body`.
RATE_LIMIT_PATH = (
    "/openapi/v1/{omadac_id}/sites/{site_id}/clients/{client_mac}/ratelimit"
)

#: SPEC-PRESENT (this controller's ``/v3/api-docs``). The v2 twins
#: ``POST /{cid}/api/v2/sites/{siteId}/cmd/clients/{mac}/block`` and
#: ``.../unblock`` are the ones that were actually measured, including their
#: idempotency -- a second block and a second unblock each returned
#: ``errorCode 0`` rather than an error.
BLOCK_PATH = "/openapi/v1/{omadac_id}/sites/{site_id}/clients/{client_mac}/block"
UNBLOCK_PATH = "/openapi/v1/{omadac_id}/sites/{site_id}/clients/{client_mac}/unblock"

#: ``upUnit``/``downUnit`` values. VERIFIED in the spec and confirmed by the
#: measured v2 write, which stored ``downUnit: 2, downLimit: 10`` and read
#: back as a 10 Mbps limit.
UNIT_KBPS = 1
UNIT_MBPS = 2

#: The documented range for ``upLimit``/``downLimit``, whatever the unit.
#: Enforced here because the controller does not enforce it (see docstring).
MIN_LIMIT = 1
MAX_LIMIT = 1024

#: Kbps per Mbps, for the unit choice below. Omada's own UI labels these
#: "Kbps" and "Mbps" with no note about 1024, so the decimal factor is the
#: reading that matches the label.
KBPS_PER_MBPS = 1000

#: The largest rate this encoding can express: 1024 in the Mbps unit.
MAX_RATE_KBPS = MAX_LIMIT * KBPS_PER_MBPS


def encode_rate(rate_kbps: int) -> tuple[int, int, bool]:
    """``rate_kbps`` -> ``(unit, limit, was_clamped)``.

    The range 1-1024 applies to the *number*, not to the bandwidth, so the
    unit is chosen to keep the number inside it: anything up to 1024 kbps is
    sent as-is in the Kbps unit, and anything above is converted to Mbps and
    rounded to the nearest whole Mbps.

    **Rounding is lossy and the caller is told.** 1500 kbps becomes 2 Mbps,
    which is more than was asked for. That is reported through the third
    element and through :class:`~..controller_contract.ClientRateLimit`'s
    own applied values, so a UI can show what the controller was actually
    given rather than what the operator typed. Silently applying a different
    number than the one on the screen is the failure mode this exists to
    avoid.

    ``was_clamped`` is ``True`` whenever the value that goes on the wire is
    not the value that came in -- whether from the 1024 Mbps ceiling, the
    1 Kbps floor, or the Mbps rounding.
    """
    requested = int(rate_kbps)
    if requested <= 0:
        # Callers mean "unlimited" by 0 (RouterOS's own `max-limit` semantics,
        # which is where this platform's kbps vocabulary comes from). There is
        # no Omada encoding for "unlimited but enabled"; the caller clears the
        # limit instead, and reaching here with 0 is a bug, so it is floored
        # rather than silently turned into no limit at all.
        return UNIT_KBPS, MIN_LIMIT, True

    if requested <= MAX_LIMIT:
        return UNIT_KBPS, requested, False

    clamped = min(requested, MAX_RATE_KBPS)
    mbps = round(clamped / KBPS_PER_MBPS)
    limit = max(MIN_LIMIT, min(MAX_LIMIT, mbps))
    effective_kbps = limit * KBPS_PER_MBPS
    return UNIT_MBPS, limit, effective_kbps != requested


def decode_rate(unit: int, limit: int) -> int:
    """The inverse of :func:`encode_rate`, in kbps."""
    return int(limit) * (KBPS_PER_MBPS if int(unit) == UNIT_MBPS else 1)


def build_rate_limit_body(
    *, down_kbps: int | None, up_kbps: int | None
) -> tuple[dict[str, Any], ClientRateLimit]:
    """The ``Client Rate Limit Setting`` body, and what it really applies.

    Returns both because they are not the same thing: the body is what goes
    on the wire and the :class:`ClientRateLimit` is the honest read-back of
    what that body means in this platform's own kbps vocabulary, including
    any clamping :func:`encode_rate` had to do.

    ``rateLimitId`` is deliberately **never** sent. The spec says it is
    "Rate limit profile ID. Nullable when ratelimit type is custom" -- and a
    client whose limit points at a shared site profile is a venue-wide
    setting wearing a per-client mask: editing that profile changes the limit
    for everything bound to it. Writing only custom values means this call
    can never reach beyond the one client it names.
    """
    body: dict[str, Any] = {"enable": True}
    clamped = False

    if down_kbps is not None and int(down_kbps) > 0:
        unit, limit, was_clamped = encode_rate(int(down_kbps))
        body["downEnable"] = True
        body["downUnit"] = unit
        body["downLimit"] = limit
        applied_down: int | None = decode_rate(unit, limit)
        clamped = clamped or was_clamped
    else:
        body["downEnable"] = False
        applied_down = None

    if up_kbps is not None and int(up_kbps) > 0:
        unit, limit, was_clamped = encode_rate(int(up_kbps))
        body["upEnable"] = True
        body["upUnit"] = unit
        body["upLimit"] = limit
        applied_up: int | None = decode_rate(unit, limit)
        clamped = clamped or was_clamped
    else:
        body["upEnable"] = False
        applied_up = None

    if not body["downEnable"] and not body["upEnable"]:
        # Neither direction limited is not a limit at all. Sending
        # `enable: true` with both directions off would leave the controller
        # holding an enabled-but-empty rate limit, which reads as "throttled"
        # in its own UI and throttles nothing.
        body["enable"] = False

    return body, ClientRateLimit(
        enabled=bool(body["enable"]),
        down_kbps=applied_down,
        up_kbps=applied_up,
        clamped=clamped,
    )


#: The body that removes a limit. ``enable: false`` rather than deleting the
#: object: the ``rateLimit`` block is present on every client record whether
#: or not it is in use (an untouched client reads back
#: ``{"enable": false, ..., "downLimit": 0}``), so "no limit" is a state of
#: the object, not its absence.
#: The limit values a disabled rate limit carries. **Not zero**, though zero
#: is what an untouched client reads back: the Open API validates the range
#: before it looks at ``enable``, so a body carrying ``0`` is refused with
#: ``-1001 "Value of down limit is from 1 to 1024."`` even when the limit is
#: being switched off. Measured on 5.15.24.19 -- zeros refused, ones
#: accepted, and omitting the fields entirely answers ``-1 General error``.
#: The number is inert; ``enable: false`` is what makes it not a limit.
CLEAR_RATE_LIMIT_VALUE = 1

CLEAR_RATE_LIMIT_BODY: dict[str, Any] = {
    "enable": False,
    "upEnable": False,
    "upUnit": UNIT_MBPS,
    "upLimit": CLEAR_RATE_LIMIT_VALUE,
    "downEnable": False,
    "downUnit": UNIT_MBPS,
    "downLimit": CLEAR_RATE_LIMIT_VALUE,
}


#: Rate-limit selector on the Open API request. ``0`` is a custom per-client
#: limit; ``1`` names a site-wide profile, which
#: :func:`build_rate_limit_body` deliberately never writes.
RATE_LIMIT_MODE_CUSTOM = 0


def _ratelimit_request(limits: dict[str, Any]) -> dict[str, Any]:
    """Wrap a rate-limit object for the **Open API** endpoint.

    The two APIs disagree about the envelope and the difference is silent.
    Internal v2 takes ``PATCH …/clients/{mac}`` with ``{"rateLimit": {...}}``;
    the Open API's ``…/clients/{mac}/ratelimit`` takes ``mode`` plus
    ``customRateLimit``, and answers a body in the other shape with
    ``-1001 "Invalid request parameters."`` -- a 200 with an error code, which
    is why this looked like a permissions problem for a day. Measured against
    the 5.15.24.19 controller: flat and ``{"rateLimit": …}`` both refused,
    ``{"mode": 0, "customRateLimit": …}`` returned ``errorCode 0``.
    """
    return {"mode": RATE_LIMIT_MODE_CUSTOM, "customRateLimit": limits}


def _mac(client_mac: str) -> str:
    """Omada's own spelling of a MAC: upper-case, hyphen-separated.

    The path carries the MAC, so the spelling is load-bearing in a way it is
    not for a body field -- a colon-separated MAC in a URL path is a
    different path.
    """
    normalized = normalize_mac(client_mac)
    return normalized if normalized is not None else client_mac


async def set_client_rate_limit(
    client: OmadaHttpClient,
    omadac_id: str,
    site_id: str,
    client_mac: str,
    *,
    down_kbps: int | None,
    up_kbps: int | None,
) -> ClientRateLimit:
    """Apply a per-client rate limit and return what was actually applied.

    ``retry_on_transport_error`` is left at its default. This is a PATCH that
    overwrites one field of one record with a value computed entirely from
    the arguments, so replaying it after a timeout cannot produce a second
    anything -- unlike the creates that flag exists for.
    """
    body, applied = build_rate_limit_body(down_kbps=down_kbps, up_kbps=up_kbps)
    await client.request(
        "PATCH",
        RATE_LIMIT_PATH.format(
            omadac_id=omadac_id, site_id=site_id, client_mac=_mac(client_mac)
        ),
        json=_ratelimit_request(body),
    )
    return applied


async def clear_client_rate_limit(
    client: OmadaHttpClient, omadac_id: str, site_id: str, client_mac: str
) -> ClientRateLimit:
    """Remove a per-client rate limit. Idempotent by construction: the body
    is the same "off" state whether or not a limit was in place.

    **The controller keeps ``rateLimit.enable: true`` afterwards, and there
    is no Open API call that clears it.** Both directions come back
    ``upEnable: false`` / ``downEnable: false``, so nothing is throttled --
    which is why :class:`ClientRateLimit` reports ``enabled=False``, a true
    statement about the *effect*. But a pristine client reads back
    ``enable: false``, so a cleared one is distinguishable from an untouched
    one in the venue's own Omada UI, where it may read as "rate limited"
    while limiting nothing.

    Measured 2026-09-18 on 5.15.24.19, six bodies across three endpoints:
    ``…/clients/{mac}/ratelimit`` with Mbps units, with Kbps units, with
    ``mode: 1``, and with no ``customRateLimit``; the batch
    ``…/clients/config`` with ``rateLimit`` and with ``mode`` +
    ``customRateLimit``; and ``PATCH …/clients/{mac}`` (405 -- Open API does
    not expose it). Every accepted body left the flag on. The controller's
    **internal v2** ``PATCH /api/v2/sites/{siteId}/clients/{mac}`` does clear
    it, and this platform deliberately does not hold the admin session that
    endpoint needs.

    So this is a controller behaviour to state plainly, not a bug to keep
    hunting: do not "fix" it by asking for admin credentials.
    """
    await client.request(
        "PATCH",
        RATE_LIMIT_PATH.format(
            omadac_id=omadac_id, site_id=site_id, client_mac=_mac(client_mac)
        ),
        json=_ratelimit_request(dict(CLEAR_RATE_LIMIT_BODY)),
    )
    return ClientRateLimit(enabled=False, down_kbps=None, up_kbps=None, clamped=False)


async def block_client(
    client: OmadaHttpClient, omadac_id: str, site_id: str, client_mac: str
) -> bool:
    """Block one MAC on one site. Returns ``True`` when the controller
    accepted it.

    **Measured as idempotent** on the v2 twin: blocking an already-blocked
    client returned ``errorCode 0``, not an error. Also measured to work on
    an *offline* MAC, which is the fact that proves the flag lives on the
    known-client record rather than on a live association -- so there is
    nothing for a reconnect to clear.

    What it does to a client that currently holds a portal authorization is
    **UNMEASURED** (CAPABILITY-MATRIX 4.6). Callers must not assert that a
    block ends a live session.
    """
    await client.request(
        "POST",
        BLOCK_PATH.format(
            omadac_id=omadac_id, site_id=site_id, client_mac=_mac(client_mac)
        ),
        retry_on_transport_error=False,
    )
    return True


async def unblock_client(
    client: OmadaHttpClient, omadac_id: str, site_id: str, client_mac: str
) -> bool:
    """Unblock one MAC on one site. Measured idempotent, same as the block."""
    await client.request(
        "POST",
        UNBLOCK_PATH.format(
            omadac_id=omadac_id, site_id=site_id, client_mac=_mac(client_mac)
        ),
        retry_on_transport_error=False,
    )
    return True


__all__ = [
    "BLOCK_PATH",
    "CLEAR_RATE_LIMIT_BODY",
    "KBPS_PER_MBPS",
    "MAX_LIMIT",
    "MAX_RATE_KBPS",
    "MIN_LIMIT",
    "RATE_LIMIT_PATH",
    "UNBLOCK_PATH",
    "UNIT_KBPS",
    "UNIT_MBPS",
    "block_client",
    "build_rate_limit_body",
    "clear_client_rate_limit",
    "decode_rate",
    "encode_rate",
    "set_client_rate_limit",
    "unblock_client",
]
