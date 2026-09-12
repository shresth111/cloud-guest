"""Network Diagnostics domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "NetworkDiagnosticsError",
    "DiagnosticRunNotFoundError",
    "CrossOrganizationDiagnosticRunAccessError",
    "MissingDiagnosticsCredentialsError",
    "DiagnosticsDeviceConnectionError",
    "DiagnosticsDeviceOperationError",
    "UnsupportedDiagnosticsVendorError",
    "InvalidDiagnosticTargetError",
    "DiagnosticCooldownError",
    "DiagnosticRateLimitExceededError",
]


class NetworkDiagnosticsError(CloudGuestError):
    """Base exception for Network Diagnostics domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class DiagnosticRunNotFoundError(NetworkDiagnosticsError):
    def __init__(self, run_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Diagnostic run not found: {run_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationDiagnosticRunAccessError(NetworkDiagnosticsError):
    """A caller acting within organization A attempted to read a
    diagnostic run belonging to organization B -- mirrors
    ``app.domains.device_sync.exceptions
    .CrossOrganizationDeviceSyncRunAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a diagnostic run belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class MissingDiagnosticsCredentialsError(NetworkDiagnosticsError):
    """Raised when a router has no management IP/username/decrypted
    secret stored -- mirrors ``app.domains.isp.exceptions
    .IspMissingCredentialsError``. Unlike a device-connection failure
    (a real, honest diagnostic outcome, recorded as a ``FAILED`` run),
    this is a configuration problem -- raised directly, never recorded
    as a diagnostic result."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class DiagnosticsDeviceConnectionError(NetworkDiagnosticsError):
    """Could not open a real RouterOS API connection to the router at
    all -- mirrors ``app.domains.isp.exceptions.IspDeviceConnectionError``.
    Caught by ``service.py`` and recorded as a ``FAILED``
    :class:`~.models.DiagnosticRun`, never raised to the caller directly
    -- a real network failure is exactly what this domain exists to
    surface, not an HTTP error that discards the attempt."""

    def __init__(self, host: str, reason: str) -> None:
        super().__init__(
            f"Could not connect to router at '{host}': {reason}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class DiagnosticsDeviceOperationError(NetworkDiagnosticsError):
    """A connection was opened, but the RouterOS command itself failed --
    mirrors ``app.domains.isp.exceptions.IspDeviceOperationError``. Same
    "caught and recorded, not raised" handling as
    :class:`DiagnosticsDeviceConnectionError`."""

    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(
            f"Diagnostics operation '{operation}' failed: {reason}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class UnsupportedDiagnosticsVendorError(NetworkDiagnosticsError):
    """No diagnostics adapter is registered for this router's own
    ``vendor`` -- mirrors
    ``app.domains.isp.exceptions.UnsupportedIspVendorError``."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            f"No diagnostics adapter registered for vendor '{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidDiagnosticTargetError(NetworkDiagnosticsError):
    """The caller asked to run a diagnostic against something that is not a
    real, probeable destination -- see ``validators.normalize_target`` for
    exactly what is and is not enforceable here (and why a public target
    cannot honestly be checked against "is this the customer's own to
    probe").

    A 422, not a diagnostic outcome: nothing was attempted, so -- like
    :class:`MissingDiagnosticsCredentialsError` -- no ``DiagnosticRun`` row
    is recorded."""

    def __init__(self, target: str, reason: str) -> None:
        super().__init__(
            f"Invalid diagnostic target '{target}': {reason}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class DiagnosticCooldownError(NetworkDiagnosticsError):
    """A diagnostic against this router ran too recently -- mirrors
    ``app.domains.isp.exceptions.IspSpeedTestCooldownError`` exactly,
    including reporting the real, live remaining TTL rather than a fixed
    guess, and refusing rather than silently queueing.

    See ``constants.py``'s abuse-controls section for why a per-router
    cooldown and a per-organization window are two different controls
    doing two different jobs."""

    def __init__(self, router_id: uuid.UUID, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"A diagnostic was run against router '{router_id}' too recently; "
            f"retry in {retry_after_seconds}s",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            data={"retry_after_seconds": retry_after_seconds},
        )


class DiagnosticRateLimitExceededError(NetworkDiagnosticsError):
    """This organization has run its allowance of diagnostics for the
    current window (``constants.DIAGNOSTIC_ORG_MAX_RUNS_PER_WINDOW``).

    Keyed on the organization rather than the router or the caller's IP:
    the router is caller-chosen and therefore rotatable, and an office
    behind one NAT would share an IP bucket between every admin in it.
    ``CurrentOrganization`` validates membership, so the organization is
    the one component of this request the caller cannot vary to mint a
    fresh bucket -- the same reasoning ``app.middleware.rate_limit``
    documents for its own venue/IP pair."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            "This organization has run too many diagnostics recently; "
            f"retry in {retry_after_seconds}s",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            data={"retry_after_seconds": retry_after_seconds},
        )
