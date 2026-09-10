"""Response-envelope parsing and the coercion helpers every resource shares.

## Why parsing is centralized and paranoid

Both Omada APIs wrap everything in the same envelope::

    {"errorCode": 0, "msg": "Success.", "result": {...}}

``errorCode == 0`` means success; anything else is a failure *carried inside
an HTTP 200*. That is the single most important fact about this API: you
cannot judge success from the HTTP status alone, and a client that only
checks ``response.status_code`` will cheerfully treat "your credentials are
wrong" as a successful empty result. Every response in this package therefore
goes through ``parse_envelope``.

The coercion helpers exist because the two APIs, and different firmware
generations of each, disagree about types for the same field: ``radioId``
arrives as ``1`` or ``"1"``, ``vid`` as an int or a numeric string, ``status``
as an int enum in Open API and occasionally as a string elsewhere. Rather
than sprinkle ``int(x) if x else None`` across five modules, everything funnels
through ``coerce_int`` / ``coerce_str`` / ``coerce_bool``, which never raise --
a field we cannot interpret becomes ``None``, which every contract dataclass
already models as legal. A malformed field must degrade one attribute, never
fail a whole sync.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .errors import OmadaInvalidControllerError

#: Success sentinel. Verified in TP-Link's own external-portal docs, which
#: show ``{"errorCode": 0}`` as the accepted-authorization reply, and used
#: identically by the Open API.
ERROR_CODE_SUCCESS = 0

# --- Open API error codes -------------------------------------------------
# Corroborated from community client code and TP-Link forum threads (see the
# package docstring for URLs), NOT from a primary TP-Link specification --
# the authoritative list lives only in the "Online API Document" served by a
# running controller, which we have no access to. They are used only to pick
# a *reaction* (re-login vs fail), and every one of them has a safe fallback
# path, so a wrong guess degrades to a normal error rather than misbehaving.
OPENAPI_ERROR_ACCESS_TOKEN_EXPIRED = -44112
OPENAPI_ERROR_ACCESS_TOKEN_INVALID = -44113
OPENAPI_ERROR_REFRESH_TOKEN_INVALID = -44114
OPENAPI_ERROR_TOKEN_OTHER = (-44106, -44111)
OPENAPI_ERROR_CONTROLLER_ID_NOT_FOUND = -7131
OPENAPI_ERROR_OPERATION_UNSUPPORTED = -1600

#: Codes that mean "your token is no good any more, get another one". These
#: drive the single automatic re-login.
SESSION_EXPIRED_ERROR_CODES: frozenset[int] = frozenset(
    {
        OPENAPI_ERROR_ACCESS_TOKEN_EXPIRED,
        OPENAPI_ERROR_ACCESS_TOKEN_INVALID,
        *OPENAPI_ERROR_TOKEN_OTHER,
        # INFERRED, unverified: -1200 is widely reported as the legacy
        # controller API's "session timeout / not logged in" code, but it
        # does not appear in any TP-Link document we could retrieve. It is
        # listed here only to trigger a re-login attempt; if the guess is
        # wrong the re-login simply does not help and the original error
        # surfaces unchanged one attempt later.
        -1200,
    }
)


@dataclass(frozen=True, slots=True)
class OmadaEnvelope:
    """A parsed ``{"errorCode", "msg", "result"}`` response.

    ``result`` is ``Any`` because Omada uses the same envelope for a dict
    (``/sites/{id}``), a paginated dict (``{"data": [...], "totalRows": n}``)
    and occasionally a bare list. Resource modules narrow it; the envelope
    layer does not pretend to know.
    """

    error_code: int
    msg: str | None
    result: Any

    @property
    def ok(self) -> bool:
        return self.error_code == ERROR_CODE_SUCCESS


def parse_envelope(payload: object) -> OmadaEnvelope:
    """Parse a decoded JSON body into an ``OmadaEnvelope``.

    Raises ``OmadaInvalidControllerError`` when the body is not an object or
    has no integer ``errorCode``. That is the correct error for this: if the
    thing at the other end of the URL is not returning Omada's envelope, the
    user has almost certainly pointed us at something that is not an Omada
    controller -- a reverse proxy's HTML error page, a captive portal of
    their own, a completely unrelated service -- and telling them "invalid
    controller" is far more actionable than "unexpected response".

    Note the deliberate leniency about ``errorCode``'s own type: some
    firmware returns it as the string ``"0"``. Rejecting that would break a
    real controller over a JSON-encoding detail.
    """
    if not isinstance(payload, dict):
        raise OmadaInvalidControllerError()

    raw_code = payload.get("errorCode")
    if isinstance(raw_code, bool) or raw_code is None:
        raise OmadaInvalidControllerError()
    try:
        error_code = int(raw_code)
    except (TypeError, ValueError):
        raise OmadaInvalidControllerError() from None

    raw_msg = payload.get("msg")
    return OmadaEnvelope(
        error_code=error_code,
        msg=raw_msg if isinstance(raw_msg, str) else None,
        result=payload.get("result"),
    )


def coerce_int(value: object) -> int | None:
    """Best-effort int. Never raises; unusable input becomes ``None``.

    ``bool`` is rejected explicitly -- it is an ``int`` subclass in Python, so
    a stray ``True`` would silently become ``1`` and land in something like
    ``vlan_id``.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            try:
                return int(float(text))
            except ValueError:
                return None
    return None


def coerce_str(value: object) -> str | None:
    """Best-effort non-empty string; whitespace-only becomes ``None``."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def coerce_bool(value: object) -> bool | None:
    """Best-effort tri-state bool.

    Tri-state matters: for ``is_authorized``, "the controller said false" and
    "the controller did not tell us" are different facts, and collapsing the
    second into ``False`` would let the dashboard state something the
    controller never claimed.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"true", "yes", "1"}:
            return True
        if text in {"false", "no", "0"}:
            return False
    return None


def normalize_mac(value: object) -> str | None:
    """Normalize a MAC to upper-case hyphen-separated form (``AA-BB-...``).

    Omada is inconsistent here: portal redirects use hyphens, some Open API
    responses use colons, and a few paths return lower case. The platform
    stores and compares these as strings, so a client that looks up
    ``aa:bb:...`` against a stored ``AA-BB-...`` finds nothing. Hyphen-upper
    is chosen because that is the form Omada puts on the portal redirect --
    the value that arrives first and that everything downstream is keyed on.

    Anything that is not 12 hex digits with optional separators is returned
    trimmed but otherwise untouched, rather than dropped: a MAC we do not
    recognise is still better identification than ``None``.
    """
    text = coerce_str(value)
    if text is None:
        return None
    stripped = text.replace(":", "").replace("-", "").replace(".", "").strip()
    if len(stripped) == 12:
        try:
            int(stripped, 16)
        except ValueError:
            return text
        upper = stripped.upper()
        return "-".join(upper[i : i + 2] for i in range(0, 12, 2))
    return text


_DEVICE_TYPE_BY_NAME: dict[str, str] = {
    "ap": "ap",
    "eap": "ap",
    "accesspoint": "ap",
    "switch": "switch",
    "sw": "switch",
    "gateway": "gateway",
    "gw": "gateway",
    "router": "gateway",
}

# INFERRED, unverified: Open API returns device `type` as a string ("ap",
# "switch", "gateway") in every sample we could find, so the string map above
# is the primary path. Some firmware is reported to send an integer enum
# instead; this mapping of that enum is a guess and is only reached when the
# value is not a recognised string. A wrong guess mislabels a device in the
# UI -- it never affects authorization or any write.
_DEVICE_TYPE_BY_CODE: dict[int, str] = {0: "ap", 1: "switch", 2: "gateway"}


def normalize_device_type(value: object) -> str:
    """Map Omada's device type onto the contract's closed vocabulary."""
    text = coerce_str(value)
    if text is not None:
        key = text.replace(" ", "").replace("_", "").replace("-", "").lower()
        if key in _DEVICE_TYPE_BY_NAME:
            return _DEVICE_TYPE_BY_NAME[key]
    code = coerce_int(value)
    if code is not None and code in _DEVICE_TYPE_BY_CODE:
        return _DEVICE_TYPE_BY_CODE[code]
    return "unknown"


_DEVICE_STATUS_BY_NAME: dict[str, str] = {
    "connected": "connected",
    "online": "connected",
    "disconnected": "disconnected",
    "offline": "disconnected",
    "pending": "pending",
    "adopting": "pending",
    "provisioning": "pending",
    "configuring": "pending",
    "heartbeatmissed": "disconnected",
    "isolated": "disconnected",
}

# VERIFIED (TP-Link's OpenAPI spec, ``DeviceInfo.status``): "Device status
# should be a value as follows: 0: Disconnected; 1: Connected; 2: Pending;
# 3: Heartbeat Missed; 4: Isolated".
#
# Note this map used to send 3 and 4 to "pending", which contradicted the
# name map right above it -- that one has always sent "heartbeatmissed" and
# "isolated" to "disconnected". The name map was right and the code map was
# wrong, and since the spec types ``status`` as an *integer* the wrong branch
# is the one that would actually have run. A heartbeat-missed AP is an AP
# that has stopped answering; calling it "pending" reads as "still being
# adopted, give it a minute" and would have hidden a real outage on the
# customer's own inventory table.
#
# 5 is not in TP-Link's enumeration and is kept only as a harmless catch for
# a firmware that extends it; anything unrecognised falls through to
# "unknown" rather than being guessed at.
_DEVICE_STATUS_BY_CODE: dict[int, str] = {
    0: "disconnected",
    1: "connected",
    2: "pending",
    3: "disconnected",
    4: "disconnected",
    5: "pending",
}


def normalize_device_status(value: object) -> str:
    """Map Omada's device status onto the contract's closed vocabulary."""
    text = coerce_str(value)
    if text is not None:
        key = text.replace(" ", "").replace("_", "").replace("-", "").lower()
        if key in _DEVICE_STATUS_BY_NAME:
            return _DEVICE_STATUS_BY_NAME[key]
    code = coerce_int(value)
    if code is not None and code in _DEVICE_STATUS_BY_CODE:
        return _DEVICE_STATUS_BY_CODE[code]
    return "unknown"


def epoch_to_utc(value: object) -> datetime | None:
    """Convert an Omada epoch timestamp to a tz-aware UTC ``datetime``.

    Omada mixes seconds and milliseconds across fields and versions with no
    marker distinguishing them, so the magnitude decides: anything at or above
    1e11 is treated as milliseconds. That threshold sits between "year 5138 in
    seconds" and "March 1973 in milliseconds", so the only values it
    misclassifies are ones that are already nonsense.

    Out-of-range values return ``None`` rather than raising -- a bogus
    timestamp should blank one field, not abort a client list.
    """
    number = coerce_int(value)
    if number is None or number <= 0:
        return None
    seconds = number / 1000.0 if number >= 100_000_000_000 else float(number)
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def extract_page(result: object) -> list[dict[str, Any]]:
    """Pull the row list out of whatever shape a list endpoint returned.

    Open API list endpoints normally return
    ``{"data": [...], "totalRows": n, "currentPage": p, "currentSize": s}``,
    but a few return a bare list, and an empty site can return ``None``.
    All three are legal inputs here and all three yield a list.
    """
    if isinstance(result, list):
        return [row for row in result if isinstance(row, dict)]
    if isinstance(result, dict):
        data = result.get("data")
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
    return []


def extract_total_rows(result: object) -> int | None:
    """``totalRows`` from a paginated envelope, when it is present."""
    if isinstance(result, dict):
        return coerce_int(result.get("totalRows"))
    return None


__all__ = [
    "ERROR_CODE_SUCCESS",
    "OPENAPI_ERROR_ACCESS_TOKEN_EXPIRED",
    "OPENAPI_ERROR_ACCESS_TOKEN_INVALID",
    "OPENAPI_ERROR_CONTROLLER_ID_NOT_FOUND",
    "OPENAPI_ERROR_OPERATION_UNSUPPORTED",
    "OPENAPI_ERROR_REFRESH_TOKEN_INVALID",
    "SESSION_EXPIRED_ERROR_CODES",
    "OmadaEnvelope",
    "coerce_bool",
    "coerce_int",
    "coerce_str",
    "epoch_to_utc",
    "extract_page",
    "extract_total_rows",
    "normalize_device_status",
    "normalize_device_type",
    "normalize_mac",
    "parse_envelope",
]
