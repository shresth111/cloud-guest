"""Guest domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.

This module never re-raises ``app.domains.otp``'s or
``app.domains.voucher``'s own exceptions under a different name -- a caller
of ``login_via_otp``/``login_via_voucher`` sees exactly the same
``OtpCodeMismatchError``/``VoucherExpiredError``/etc. those services already
raise (composition, not translation). The exceptions defined here cover only
what is genuinely new at this module's own layer: guest/session lifecycle,
tenant isolation, and the RADIUS/NAS authentication boundary.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "GuestError",
    "GuestNotFoundError",
    "CrossOrganizationGuestAccessError",
    "GuestBlockedError",
    "GuestSessionNotFoundError",
    "GuestAuthMethodNotEnabledError",
    "RouterNotEligibleForGuestSessionError",
    "InvalidSessionStatusTransitionError",
    "SessionTerminationCooldownError",
    "NoReconnectableSessionError",
    "RadiusNasClientNotFoundError",
    "RadiusNasAuthenticationError",
    "RadiusNasAlreadyRegisteredError",
    "InvalidAnalyticsDateRangeError",
]


class GuestError(CloudGuestError):
    """Base exception for Guest domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class GuestNotFoundError(GuestError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Guest not found: {identifier}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationGuestAccessError(GuestError):
    """A caller acting within organization A attempted to read/mutate a
    guest (or guest session) belonging to organization B -- mirrors
    ``app.domains.voucher.exceptions.CrossOrganizationVoucherBatchAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a guest belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class GuestBlockedError(GuestError):
    """The guest identified by this identifier has ``is_blocked=True`` --
    an admin-set ban. Raised before any OTP/voucher verification is even
    attempted, so a blocked guest never learns whether their code/voucher
    would otherwise have been valid."""

    def __init__(self, reason: str | None = None) -> None:
        message = "This guest has been blocked from guest WiFi access"
        if reason:
            message += f": {reason}"
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class GuestSessionNotFoundError(GuestError):
    def __init__(self, session_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Guest session not found: {session_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class GuestAuthMethodNotEnabledError(GuestError):
    """The resolved captive portal config for this location does not have
    the requested auth method enabled -- composes with
    ``CaptivePortalService.resolve_portal_config``, never re-implements
    that lookup."""

    def __init__(self, auth_method: str) -> None:
        super().__init__(
            f"Auth method '{auth_method}' is not enabled for this location's "
            "captive portal",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class RouterNotEligibleForGuestSessionError(GuestError):
    """The requested router is not in a status that may host a guest
    session (e.g. ``decommissioned``/``suspended``) -- composes with
    ``app.domains.router.enums.RouterStatus``, never re-implements it."""

    def __init__(self, router_id: uuid.UUID | str, router_status: str) -> None:
        super().__init__(
            f"Router {router_id} is not eligible to host a guest session "
            f"(status={router_status})",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidSessionStatusTransitionError(GuestError):
    """Raised when a requested status change is not a legal edge in
    ``app.domains.guest.constants.GUEST_SESSION_STATUS_TRANSITIONS``."""

    def __init__(self, current_status: str, requested_status: str) -> None:
        super().__init__(
            f"Cannot transition guest session from '{current_status}' to "
            f"'{requested_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class SessionTerminationCooldownError(GuestError):
    """The guest's most recent session was ``terminate_session``'d (a
    punitive, admin-driven kill) within
    ``constants.TERMINATION_RECONNECT_COOLDOWN_MINUTES`` -- see
    ``service.GuestService.terminate_session``'s docstring for why this is
    distinct from an ordinary ``disconnect_session``, which imposes no such
    cooldown."""

    def __init__(self, retry_after_minutes: int) -> None:
        self.retry_after_minutes = retry_after_minutes
        super().__init__(
            "This guest's access was terminated and cannot reconnect for "
            f"{retry_after_minutes} more minute(s)",
            status_code=status.HTTP_403_FORBIDDEN,
            data={"retry_after_minutes": retry_after_minutes},
        )


class NoReconnectableSessionError(GuestError):
    """``reconnect`` found no eligible prior session to derive a new session
    from -- either this guest has never logged in before, or their most
    recent session ended further in the past than
    ``constants.RECONNECT_GRACE_MINUTES`` ago. Either way, the guest must
    use ``login_via_otp``/``login_via_voucher`` instead."""

    def __init__(self, guest_id: uuid.UUID | str) -> None:
        super().__init__(
            f"No reconnectable session found for guest {guest_id} (none "
            "exists, or the prior session is outside the reconnect grace "
            "window)",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class RadiusNasClientNotFoundError(GuestError):
    def __init__(self, nas_identifier: str) -> None:
        super().__init__(
            f"No RADIUS NAS client registered for nas_identifier "
            f"'{nas_identifier}'",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class RadiusNasAuthenticationError(GuestError):
    """The presented shared secret did not match the registered NAS
    client's decrypted ``shared_secret_encrypted``, or the NAS client is
    inactive -- see ``service.py``'s module docstring for why this is a
    shared-secret comparison, not RBAC's ``RequirePermission`` (FreeRADIUS
    has no platform-user identity)."""

    def __init__(self) -> None:
        super().__init__(
            "RADIUS NAS authentication failed", status_code=status.HTTP_401_UNAUTHORIZED
        )


class RadiusNasAlreadyRegisteredError(GuestError):
    """A router may only have one ``RadiusNasClient`` (one-to-one) -- see
    ``models.RadiusNasClient``'s module docstring."""

    def __init__(self, router_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Router {router_id} already has a registered RADIUS NAS client",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidAnalyticsDateRangeError(GuestError):
    def __init__(self) -> None:
        super().__init__(
            "start_date must be before or equal to end_date",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
