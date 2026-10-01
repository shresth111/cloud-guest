"""The AAA trail's vocabulary: event types, reason codes, and the plain
words a venue owner reads instead of RADIUS attribute names.

Stored rows carry machine codes (``GuestSessionEvent.reason_code``,
``GuestLoginHistory.failure_reason``); plain words are derived here at read
time, so improving a sentence never needs a backfill.
"""

from __future__ import annotations

import re
from enum import StrEnum

__all__ = [
    "AuthRejectReason",
    "SessionEventType",
    "build_timeline_entries",
    "describe_auth_method",
    "describe_grant",
    "describe_disconnect_reason",
    "describe_login_failure",
    "describe_reject_reason",
    "humanize_code",
]


class SessionEventType(StrEnum):
    AUTH_ACCEPT = "auth_accept"
    AUTH_REJECT = "auth_reject"
    ACCT_START = "acct_start"
    ACCT_INTERIM = "acct_interim"
    ACCT_STOP = "acct_stop"
    NAS_REBOOT = "nas_reboot"


class AuthRejectReason(StrEnum):
    """Why ``RadiusService.authorize`` said no. RADIUS itself carries no
    reason -- these are this platform's own diagnosis of the reject."""

    NOT_SIGNED_IN = "not_signed_in"
    SESSION_ENDED = "session_ended"
    SIGNED_IN_ELSEWHERE = "signed_in_elsewhere"
    TIME_LIMIT_REACHED = "time_limit_reached"
    GUEST_BLOCKED = "guest_blocked"
    DEVICE_BLOCKED = "device_blocked"


_REJECT_TEXT: dict[str, str] = {
    AuthRejectReason.NOT_SIGNED_IN: (
        "This device had not signed in on the WiFi login page, so the router "
        "was told not to let it on."
    ),
    AuthRejectReason.SESSION_ENDED: (
        "The guest's earlier session had already ended, so they had to sign "
        "in again."
    ),
    AuthRejectReason.SIGNED_IN_ELSEWHERE: (
        "The guest's current session is on a different router at your venue."
    ),
    AuthRejectReason.TIME_LIMIT_REACHED: "The guest had used up their time allowance.",
    AuthRejectReason.GUEST_BLOCKED: "This guest is blocked at your venue.",
    AuthRejectReason.DEVICE_BLOCKED: "This device is blocked at your venue.",
}

# GuestLoginHistory.failure_reason is the exception class name raised by the
# login path (``type(exc).__name__``) or one of the named constants below.
_LOGIN_FAILURE_TEXT: dict[str, str] = {
    "OtpCodeMismatchError": "Wrong OTP entered.",
    "OtpExpiredError": "The OTP had expired.",
    "OtpNotFoundError": "No OTP had been sent to this number, or it was already used.",
    "OtpAttemptsExceededError": "Too many wrong OTP attempts.",
    "OtpAlreadyConsumedError": "That OTP had already been used.",
    "OtpRequestRateLimitExceededError": "Too many OTP requests in a short time.",
    "VoucherNotFoundError": "The voucher code does not exist.",
    "VoucherExpiredError": "The voucher has expired.",
    "VoucherExhaustedError": "The voucher has already been used up.",
    "VoucherRevokedError": "The voucher was cancelled.",
    "VoucherBatchNotActiveError": "The voucher's batch is not active.",
    "VoucherRedemptionRateLimitExceededError": (
        "Too many voucher attempts in a short time."
    ),
    "GuestPasswordLoginFailedError": "Wrong password.",
    "GuestPinLoginFailedError": "Wrong PIN.",
    "GuestPinLockedError": "Too many wrong PINs; the PIN is locked for now.",
    "GuestAccessDeniedError": "This device or guest is blocked at your venue.",
    "GuestBlockedError": "This guest is blocked at your venue.",
    "WhitelistOnlyAccessDeniedError": (
        "Only pre-approved guests may sign in at this venue right now."
    ),
}

_DISCONNECT_TEXT: dict[str, str] = {
    # RADIUS Acct-Terminate-Cause (RFC 2866 s5.10), as RouterOS/Omada send it.
    "user-request": "The guest logged out.",
    "lost-carrier": "The device left the WiFi.",
    "lost-service": "The connection was lost.",
    "idle-timeout": "The device was idle for too long.",
    "session-timeout": "The guest's time allowance ran out.",
    "admin-reset": "Disconnected by the router administrator.",
    "admin-reboot": "The router was restarted by an administrator.",
    "nas-reboot": "The router restarted.",
    "nas-request": "The router ended the session.",
    "nas-error": "The router hit an error.",
    "port-error": "A network error ended the session.",
    "user-error": "The device sent an error.",
    "host-request": "The device ended the session.",
    "service-unavailable": "The service was unavailable.",
    # This platform's own reasons.
    "radius_accounting_stop": "The router reported the session ended.",
    "radius_accounting_on": "The router restarted, which ended every session on it.",
    "radius_accounting_off": (
        "The router was shut down, which ended every session on it."
    ),
    "session_time_limit_reached": "The guest's time allowance ran out.",
    "inactivity_timeout": "The device was idle for too long.",
    "device_left_network": "The device left the WiFi.",
    "venue_closed": "Your venue's opening hours ended.",
    "whitelist_only": "Only pre-approved guests may stay connected right now.",
    "guest_team_revoked": "The guest's team access was removed.",
    "removed_from_guest_team": "The guest was removed from their team.",
}

_CAMEL = re.compile(r"(?<!^)(?=[A-Z])")


def humanize_code(code: str) -> str:
    """Last-resort plain words for a code nobody mapped: ``OtpFooError`` ->
    ``Otp foo``, ``data_limit_reached`` -> ``Data limit reached``. Honest
    rather than pretty -- better than showing the class name."""
    text = code.strip()
    if text.endswith("Error"):
        text = text[: -len("Error")]
    if "_" not in text and "-" not in text and " " not in text:
        text = _CAMEL.sub(" ", text)
    text = text.replace("_", " ").replace("-", " ").strip().lower()
    return (text[:1].upper() + text[1:] + ".") if text else ""


def describe_reject_reason(code: str | None) -> str | None:
    if not code:
        return None
    return _REJECT_TEXT.get(code) or describe_login_failure(code)


def describe_login_failure(code: str | None) -> str | None:
    if not code:
        return None
    return _LOGIN_FAILURE_TEXT.get(code) or humanize_code(code)


def describe_disconnect_reason(code: str | None) -> str | None:
    if not code:
        return None
    key = code.strip()
    return (
        _DISCONNECT_TEXT.get(key)
        or _DISCONNECT_TEXT.get(key.lower())
        or _DISCONNECT_TEXT.get(key.lower().replace("_", "-"))
        # Free text an operator typed ("Disconnected by venue staff") is
        # already plain words; only codes get humanized.
        or (key if " " in key else humanize_code(key))
    )


# ============================================================================
# Timeline assembly (pure -- the service loads rows, this turns them into the
# A/A/A story a venue owner reads)
# ============================================================================

_AUTH_METHOD_TEXT: dict[str, str] = {
    "otp_sms": "OTP by SMS",
    "otp_email": "OTP by email",
    "otp_whatsapp": "OTP by WhatsApp",
    "voucher": "voucher",
    "username_password": "username and password",
    "mac_whitelist": "trusted device (no sign-in needed)",
    "pin": "PIN",
}

#: Only these keys from ``raw`` reach the details expander. ``User-Name`` is
#: deliberately absent: it is the guest's phone/email and is returned in its
#: own masked field instead.
_RAW_DISPLAY_KEYS = (
    "Auth-Type",
    "Calling-Station-Id",
    "Session-Timeout",
    "Idle-Timeout",
    "Mikrotik-Rate-Limit",
    "Acct-Status-Type",
    "Acct-Session-Id",
    "Framed-IP-Address",
    "NAS-IP-Address",
    "Acct-Session-Time",
    "Acct-Input-Octets (total)",
    "Acct-Output-Octets (total)",
    "Acct-Terminate-Cause",
    "sessions_closed",
)


def describe_auth_method(method: str | None) -> str | None:
    if not method:
        return None
    return _AUTH_METHOD_TEXT.get(method) or humanize_code(method).rstrip(".")


def format_bytes(value: int | None) -> str | None:
    if value is None:
        return None
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1000 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1000
    return f"{size:.1f} TB"  # pragma: no cover -- loop always returns


def format_duration(seconds: int | float | None) -> str | None:
    if seconds is None:
        return None
    total = max(0, int(seconds))
    hours, rem = divmod(total, 3600)
    minutes = rem // 60
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes} min"
    return f"{total}s"


def describe_grant(granted: dict | None) -> str:
    """``granted`` (what an Accept carried) as one plain sentence."""
    if not granted:
        return "Allowed on."
    parts: list[str] = []
    if granted.get("session_timeout_seconds"):
        parts.append(f"time left {format_duration(granted['session_timeout_seconds'])}")
    else:
        parts.append("no time limit")
    if granted.get("idle_timeout_seconds"):
        parts.append(
            f"disconnects after {format_duration(granted['idle_timeout_seconds'])} idle"
        )
    if granted.get("data_limit_mb"):
        parts.append(f"data cap {granted['data_limit_mb']} MB")
    if granted.get("rate_limit"):
        parts.append(f"speed limit {describe_rate_limit(granted['rate_limit'])}")
    return "Allowed on: " + ", ".join(parts) + "."


def describe_rate_limit(value: str) -> str:
    """``Mikrotik-Rate-Limit`` is ``rx/tx`` from the *router's* side: rx is
    what the guest uploads, tx what they download."""
    first = str(value).split()[0] if value else ""
    if "/" in first:
        up, down = first.split("/", 1)
        return f"{down} down / {up} up"
    return first or str(value)


def _display_raw(raw: dict | None) -> dict[str, object]:
    if not raw:
        return {}
    return {k: raw[k] for k in _RAW_DISPLAY_KEYS if raw.get(k) not in (None, "")}


def _entry(
    *,
    at,
    phase: str,
    kind: str,
    outcome: str,
    title: str,
    detail: str | None = None,
    repeat_count: int = 1,
    raw: dict | None = None,
    first_seen_at=None,
) -> dict:
    return {
        "at": at,
        "first_seen_at": first_seen_at,
        "phase": phase,
        "kind": kind,
        "outcome": outcome,
        "title": title,
        "detail": detail,
        "repeat_count": repeat_count,
        "raw": raw or {},
    }


def build_timeline_entries(
    *,
    session,
    login_attempts,
    events,
) -> list[dict]:
    """Merge portal sign-in attempts, the session row itself, and the
    RADIUS trail into one time-ordered list.

    The session row stands in for an accounting start/stop the router never
    sent (a venue whose hub has no accounting, an Omada controller in
    external-portal mode, a session the platform ended itself) -- so a
    timeline is never empty just because RADIUS was silent, and each
    stand-in says it is the platform's own record.
    """
    entries: list[dict] = []
    for attempt in login_attempts:
        method = describe_auth_method(attempt.auth_method)
        if attempt.success:
            entries.append(
                _entry(
                    at=attempt.attempted_at,
                    phase="authentication",
                    kind="portal_login_success",
                    outcome="success",
                    title="Signed in on the WiFi login page",
                    detail=f"Using {method}." if method else None,
                    raw={"ip_address": attempt.ip_address}
                    if attempt.ip_address
                    else None,
                )
            )
        else:
            entries.append(
                _entry(
                    at=attempt.attempted_at,
                    phase="authentication",
                    kind="portal_login_failed",
                    outcome="failure",
                    title="Sign-in failed on the WiFi login page",
                    detail=describe_login_failure(attempt.failure_reason),
                    raw={
                        k: v
                        for k, v in (
                            ("reason_code", attempt.failure_reason),
                            ("method", attempt.auth_method),
                            ("ip_address", attempt.ip_address),
                        )
                        if v
                    },
                )
            )

    has_start = False
    has_stop = False
    for event in events:
        raw = _display_raw(event.raw)
        common = {
            "at": event.occurred_at,
            "first_seen_at": event.first_seen_at,
            "repeat_count": event.repeat_count or 1,
            "raw": raw,
        }
        kind = event.event_type
        if kind == SessionEventType.AUTH_ACCEPT:
            entries.append(
                _entry(
                    phase="authorization",
                    kind=kind,
                    outcome="success",
                    title="Router checked with Wyfy: allowed on",
                    detail=describe_grant(event.granted),
                    **common,
                )
            )
        elif kind == SessionEventType.AUTH_REJECT:
            entries.append(
                _entry(
                    phase="authentication",
                    kind=kind,
                    outcome="failure",
                    title="Router checked with Wyfy: refused",
                    detail=describe_reject_reason(event.reason_code),
                    **common,
                )
            )
        elif kind == SessionEventType.ACCT_START:
            has_start = True
            bits = [
                f"Device address {event.framed_ip_address}"
                if event.framed_ip_address
                else None,
                f"venue public IP {event.venue_public_ip}"
                if event.venue_public_ip
                else None,
            ]
            entries.append(
                _entry(
                    phase="accounting",
                    kind=kind,
                    outcome="info",
                    title="Router started counting this connection",
                    detail=", ".join(b for b in bits if b) + "." if any(bits) else None,
                    **common,
                )
            )
        elif kind == SessionEventType.ACCT_INTERIM:
            up = format_bytes(event.bytes_uploaded_total)
            down = format_bytes(event.bytes_downloaded_total)
            count = event.repeat_count or 1
            entries.append(
                _entry(
                    phase="accounting",
                    kind=kind,
                    outcome="info",
                    title=(
                        "Usage update from the router"
                        if count == 1
                        else f"{count} usage updates from the router"
                    ),
                    detail=(
                        f"So far: {down} downloaded, {up} uploaded."
                        if up is not None and down is not None
                        else None
                    ),
                    **common,
                )
            )
        elif kind == SessionEventType.ACCT_STOP:
            has_stop = True
            parts = [describe_disconnect_reason(event.reason_code)]
            if event.session_time_seconds is not None:
                parts.append(
                    f"Connected for {format_duration(event.session_time_seconds)}."
                )
            if event.bytes_downloaded_total is not None:
                parts.append(
                    f"Total: {format_bytes(event.bytes_downloaded_total)} downloaded, "
                    f"{format_bytes(event.bytes_uploaded_total or 0)} uploaded."
                )
            entries.append(
                _entry(
                    phase="accounting",
                    kind=kind,
                    outcome="info",
                    title="Router reported the connection ended",
                    detail=" ".join(p for p in parts if p) or None,
                    **common,
                )
            )
        elif kind == SessionEventType.NAS_REBOOT:
            entries.append(
                _entry(
                    phase="accounting",
                    kind=kind,
                    outcome="info",
                    title="The router restarted",
                    detail=describe_disconnect_reason(event.reason_code),
                    **common,
                )
            )

    if not has_start:
        entries.append(
            _entry(
                at=session.started_at,
                phase="accounting",
                kind="session_started",
                outcome="info",
                title="Session started (Wyfy's record)",
                detail=(
                    f"Device address {session.ip_address}."
                    if session.ip_address
                    else None
                ),
            )
        )
    if session.ended_at is not None and not has_stop:
        entries.append(
            _entry(
                at=session.ended_at,
                phase="accounting",
                kind="session_ended",
                outcome="info",
                title="Session ended (Wyfy's record)",
                detail=describe_disconnect_reason(session.disconnect_reason),
                raw={"reason_code": session.disconnect_reason}
                if session.disconnect_reason
                else None,
            )
        )

    entries.sort(key=lambda e: (e["at"], _PHASE_ORDER.get(e["phase"], 9)))
    return entries


_PHASE_ORDER = {"authentication": 0, "authorization": 1, "accounting": 2}
