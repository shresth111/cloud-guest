"""URL Shortener domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation. ``GET /s/{code}`` (the one endpoint that itself returns a raw
redirect, not ``ApiResponse``, on success) still goes through this same
handler on failure -- see ``router.py``'s own module docstring for why that
is not a contradiction (mirrors
``app.domains.voucher.router.export_voucher_batch``'s identical posture).

## ``ShortLinkNotFoundError`` deliberately covers not-found, inactive, *and*
## expired -- one collapsed 404, not three distinct errors

Unlike voucher's own ``VoucherNotFoundError``/``VoucherRevokedError``/
``VoucherExpiredError`` split (distinct errors for a guest reading a
physical/verbally-communicated code, where "this code is expired" vs. "this
code doesn't exist" is genuinely useful feedback), a short-link code is a
public routing key embedded directly in a URL an anonymous browser follows
with no human in the loop to read a distinct error message -- there is no
UX benefit to telling an anonymous visitor of a dead link *why* it is dead,
and collapsing the three cases removes any (admittedly marginal, since the
code itself is unguessable at 62^7) signal a prober could use to distinguish
"this code was never issued" from "this code existed and is now inactive/
expired". ``GET /s/{code}`` therefore raises this one exception for all
three reasons -- see ``service.py``'s ``resolve_and_record_click``.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "ShortLinkError",
    "ShortLinkNotFoundError",
    "CrossOrganizationShortLinkAccessError",
    "InvalidTargetUrlSchemeError",
    "BlockedTargetHostError",
    "ShortLinkCodeGenerationExhaustedError",
    "ShortLinkCreateRateLimitExceededError",
    "ShortLinkRedirectRateLimitExceededError",
]


class ShortLinkError(CloudGuestError):
    """Base exception for URL Shortener domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class ShortLinkNotFoundError(ShortLinkError):
    """No short link exists for this id/code, or it is currently
    inactive/expired -- see module docstring for why these three reasons
    are deliberately collapsed into one 404 rather than kept distinct."""

    def __init__(self, identifier: uuid.UUID | str | None = None) -> None:
        super().__init__("Short link not found", status_code=status.HTTP_404_NOT_FOUND)


class CrossOrganizationShortLinkAccessError(ShortLinkError):
    """A caller acting within organization A attempted to read/mutate a
    short link belonging to organization B -- mirrors
    ``app.domains.voucher.exceptions.CrossOrganizationVoucherBatchAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a short link belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidTargetUrlSchemeError(ShortLinkError):
    """``target_url`` has a missing or disallowed scheme -- only ``http``/
    ``https`` may be shortened. See ``validators.validate_target_url``."""

    def __init__(self, scheme: str) -> None:
        super().__init__(
            f"target_url scheme '{scheme}' is not allowed -- only http/https "
            "URLs may be shortened",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class BlockedTargetHostError(ShortLinkError):
    """``target_url``'s hostname is an obviously-internal target
    (localhost/loopback/private/link-local/reserved) -- see
    ``validators.validate_target_url``'s module docstring for the full
    "basic guard, not complete SSRF immunity" scope note."""

    def __init__(self, hostname: str) -> None:
        super().__init__(
            "target_url points at an internal/private network address, "
            "which cannot be shortened",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ShortLinkCodeGenerationExhaustedError(ShortLinkError):
    """Could not generate a unique code within
    ``constants.CODE_GENERATION_MAX_ROUNDS`` rounds -- a defensive
    backstop, not expected in practice given base62^7's own combinatorial
    space. Mirrors
    ``app.domains.voucher.exceptions.VoucherCodeGenerationExhaustedError``."""

    def __init__(self) -> None:
        super().__init__(
            "Could not generate a unique short-link code -- please retry",
            status_code=status.HTTP_409_CONFLICT,
        )


class ShortLinkCreateRateLimitExceededError(ShortLinkError):
    """This source has attempted too many short-link creations within the
    configured rolling window. See ``service.ShortLinkRateLimiter``."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Too many short links created. Try again in "
            f"{retry_after_seconds} seconds.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            data={"retry_after_seconds": retry_after_seconds},
        )


class ShortLinkRedirectRateLimitExceededError(ShortLinkError):
    """This source has attempted too many redirect lookups within the
    configured rolling window. See ``service.ShortLinkRateLimiter``."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Too many requests. Try again in {retry_after_seconds} seconds.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            data={"retry_after_seconds": retry_after_seconds},
        )
