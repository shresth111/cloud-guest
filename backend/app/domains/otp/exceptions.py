"""OTP domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.

## Error specificity vs. information-leakage (judgment call)

``verify_otp`` raises distinct exceptions for "no OTP was ever requested for
this identifier/purpose", "the latest one expired", "the latest one was
already consumed", "too many wrong guesses against this one code", and "the
presented code is simply wrong" -- deliberately **not** collapsed into one
generic "verification failed" error, unlike
``app.domains.auth.service.InvalidCredentialsError``, which intentionally
collapses "no such user" and "wrong password" into a single message to
prevent username enumeration against a *persistent* account.

That collapsing exists to protect a fact an attacker does not already know
(whether a given email belongs to a real account). An OTP ``identifier``
here is different: it is a phone number or email address the guest
themselves supplied moments earlier, in the very same flow, via
``POST /otp/request`` -- there is no persistent "account" being enumerated,
and nothing a distinct ``/otp/verify`` error teaches an attacker that they
did not already know by virtue of being the party who (claims to have)
requested a code for that exact identifier. Clear, distinct errors are
therefore better guest-facing UX ("your code expired, request a new one"
vs. "wrong code, try again") with no meaningful security cost.

What must never leak, and never does, is the code's own value or anything
that narrows the brute-force search space below what
``OtpRequest.max_attempts`` already bounds -- ``OtpCodeMismatchError``'s
message never echoes the presented or expected code, only an
``attempts_remaining`` count (which the guest can already infer by simply
counting their own tries).
"""

from __future__ import annotations

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "OtpPurposeNotAllowedError",
    "OtpVenueRequiredError",
    "OtpDailyCapReachedError",
    "OtpVenueSendFailedError",
    "OtpError",
    "InvalidOtpIdentifierError",
    "OtpRequestRateLimitExceededError",
    "OtpNotFoundError",
    "OtpExpiredError",
    "OtpAlreadyConsumedError",
    "OtpAttemptsExceededError",
    "OtpCodeMismatchError",
]


class OtpError(CloudGuestError):
    """Base exception for OTP domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class InvalidOtpIdentifierError(OtpError):
    """The identifier is not a plausible phone number (``SMS``) or email
    address (``EMAIL``) for the requested channel."""

    def __init__(self, channel: str, identifier: str) -> None:
        super().__init__(
            f"'{identifier}' is not a valid identifier for channel '{channel}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class OtpRequestRateLimitExceededError(OtpError):
    """This identifier has requested too many OTP codes within the
    configured rolling window (``Settings.otp_max_requests_per_window`` /
    ``Settings.otp_request_window_minutes``) -- protects the delivery
    channel (a real phone/email inbox) from spam, distinct from
    ``OtpAttemptsExceededError``'s per-code brute-force protection. See
    ``service.OtpRateLimiter``'s docstring for the full reasoning."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Too many OTP requests. Try again in {retry_after_seconds} seconds.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            data={"retry_after_seconds": retry_after_seconds},
        )


class OtpNotFoundError(OtpError):
    """No ``OtpRequest`` at all exists for this identifier/purpose pair."""

    def __init__(self, identifier: str, purpose: str) -> None:
        super().__init__(
            "No OTP was requested for this identifier. Request a new code.",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class OtpExpiredError(OtpError):
    """The latest matching ``OtpRequest`` exists but its ``expires_at`` has
    passed."""

    def __init__(self) -> None:
        super().__init__(
            "This verification code has expired. Request a new code.",
            status_code=status.HTTP_410_GONE,
        )


class OtpAlreadyConsumedError(OtpError):
    """The latest matching ``OtpRequest`` was already successfully verified
    once -- ``is_consumed`` is one-way, a verified OTP can never be reused."""

    def __init__(self) -> None:
        super().__init__(
            "This verification code has already been used. Request a new code.",
            status_code=status.HTTP_409_CONFLICT,
        )


class OtpAttemptsExceededError(OtpError):
    """``attempt_count`` has already reached ``max_attempts`` for this
    ``OtpRequest`` -- a distinct, per-code brute-force lockout, separate
    from ``OtpRequestRateLimitExceededError``'s per-identifier request
    throttling."""

    def __init__(self) -> None:
        super().__init__(
            "Maximum verification attempts exceeded for this code. "
            "Request a new code.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )


class OtpCodeMismatchError(OtpError):
    """The presented code does not hash-match the stored ``code_hash``."""

    def __init__(self, *, attempts_remaining: int) -> None:
        super().__init__(
            "Incorrect verification code.",
            status_code=status.HTTP_400_BAD_REQUEST,
            data={"attempts_remaining": attempts_remaining},
        )


class OtpPurposeNotAllowedError(OtpError):
    """The public ``/otp/request`` and ``/otp/verify`` serve guest login
    only (QA 2026-11-06, M3). ``account_data_masking`` codes are requested
    and verified by the authenticated ``/users/me`` endpoints, with the
    identifier taken from the caller's session; through the public routes
    anyone could mail any user a masking code, replace their live one, or
    burn their attempts."""

    def __init__(self, purpose: str) -> None:
        super().__init__(
            "This kind of verification code cannot be requested here.",
            status_code=status.HTTP_400_BAD_REQUEST,
            data={"code": "OTP_PURPOSE_NOT_ALLOWED", "purpose": purpose},
        )


class OtpVenueRequiredError(OtpError):
    """``/otp/request`` named no ``location_id`` (QA 2026-11-06, H4).
    Without a venue every venue gate (whitelist, channel enabled, open
    hours) is a no-op, and any caller could spend the platform's SMS
    credit on any number. The portal always sends the venue."""

    def __init__(self) -> None:
        super().__init__(
            "Open the WiFi sign-in page of the venue you are at and try again.",
            status_code=status.HTTP_400_BAD_REQUEST,
            data={"code": "OTP_VENUE_REQUIRED"},
        )


class OtpDailyCapReachedError(OtpError):
    """A daily OTP send cap was reached (QA 2026-11-06, H4): per venue
    (``Settings.otp_daily_cap_per_location``) or platform-wide
    (``Settings.otp_daily_cap_platform``). The backstop against SMS
    pumping that the per-identifier and per-IP limits cannot be, since a
    pumper rotates numbers."""

    def __init__(self, scope: str) -> None:
        super().__init__(
            "Sign-in codes are temporarily unavailable here. Please ask the "
            "venue staff for help.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            data={"code": "OTP_DAILY_CAP_REACHED", "scope": scope},
        )


class OtpVenueSendFailedError(OtpError):
    """The venue's own login-code provider failed, and the venue is set to
    send ONLY through it (``fallback_to_platform_default`` off on its row,
    ``app.domains.guest_messaging``). The code is not sent through Wyfy
    Guest's default; the guest is asked to try again. ``vendor_error`` is the
    provider's error code (never its raw text), for support."""

    def __init__(self, *, provider_type: str, error_code: str) -> None:
        super().__init__(
            "We couldn't send your code. Please try again.",
            status_code=status.HTTP_502_BAD_GATEWAY,
            data={
                "code": "OTP_SEND_FAILED",
                "provider_type": provider_type,
                "vendor_error": error_code[:80],
            },
        )
        self.provider_type = provider_type
        self.error_code = error_code
