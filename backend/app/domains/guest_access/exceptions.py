"""Guest Access Control domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "GuestAccessError",
    "AccessRuleNotFoundError",
    "CrossOrganizationAccessRuleError",
    "TemporaryRuleRequiresExpiryError",
    "InvalidRuleExpiryError",
    "InvalidGuestIdentifierError",
    "GuestAccessDeniedError",
    "BlockEnforcementMissingCredentialsError",
    "UnsupportedGuestAccessVendorError",
    "GuestAccessDeviceConnectionError",
    "GuestAccessDeviceOperationError",
    "RouterHasNoHotspotError",
    "SessionStillActiveOnDeviceError",
]


class GuestAccessError(CloudGuestError):
    """Base exception for Guest Access Control domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class AccessRuleNotFoundError(GuestAccessError):
    def __init__(self, rule_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Access rule not found: {rule_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationAccessRuleError(GuestAccessError):
    """A caller acting within organization A attempted to read/mutate an
    access rule belonging to organization B -- mirrors
    ``app.domains.guest.exceptions.CrossOrganizationGuestAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a rule belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class TemporaryRuleRequiresExpiryError(GuestAccessError):
    """A ``rule_type=TEMPORARY`` rule was submitted with no ``expires_at``
    -- see ``constants.AccessRuleType.TEMPORARY``'s docstring for why this
    is rejected rather than silently treated as permanent."""

    def __init__(self) -> None:
        super().__init__(
            "A temporary access rule must include an expires_at",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidRuleExpiryError(GuestAccessError):
    def __init__(self) -> None:
        super().__init__(
            "expires_at must be in the future", status_code=status.HTTP_400_BAD_REQUEST
        )


class InvalidGuestIdentifierError(GuestAccessError):
    """A guest-rule ``identifier`` is neither phone-shaped nor
    email-shaped -- see ``validators.validate_identifier_shape`` for the
    two accepted shapes. Device (MAC-keyed) rules never raise this; only
    ``GuestAccessService.create_guest_rule`` calls the validator that
    raises it."""

    def __init__(self, identifier: str) -> None:
        super().__init__(
            f"'{identifier}' is not a valid phone number or email address",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class GuestAccessDeniedError(GuestAccessError):
    """Raised by ``AccessDecisionResolver``-driven enforcement (the
    optional hook composed into ``app.domains.guest.service.GuestService``
    -- see that module's own docstring for the composition) when the
    resolved decision for a login attempt is ``BLOCKLIST``. Carries the
    matched rule's ``reason`` (if any) so the caller can surface it exactly
    as ``app.domains.guest.exceptions.GuestBlockedError`` already does for
    the guest-level ``Guest.is_blocked`` flag."""

    def __init__(self, reason: str | None = None) -> None:
        message = "Access denied by an active guest access control rule"
        if reason:
            message += f": {reason}"
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


# ---------------------------------------------------------------------------
# Block enforcement
#
# Everything below is raised while making a BLOCKLIST rule true on the
# device -- see ``enforcement.BlocklistEnforcer``.
#
# They all subclass ``CloudGuestError``, so the app-wide handler turns them
# into a real non-2xx response. That matters more than it looks: the
# frontend's response interceptor (``cloudguest-foundation/src/services/
# api.ts``) unwraps ``response.data.data`` and never reads
# ``envelope.success``, so a handler that "reported failure honestly" with
# ``200 {"success": false}`` would be indistinguishable from success to
# every caller in the app -- which is the exact shape of the bug this
# enforcement path exists to remove. Failure has to live in the status
# code.
#
# Every one of them is raised *after* the rule row and its failure record
# have been committed. The block itself always persists: a guest whose
# live session could not be cut is still barred from signing in again, and
# an operator retrying the push must not have to re-enter the block.
# ---------------------------------------------------------------------------


class BlockEnforcementMissingCredentialsError(GuestAccessError):
    """The router carrying the blocked guest's live session has no
    management IP / API username / decryptable secret stored.

    Raise rather than guess -- ``VlanService._resolve_device_credentials``'s
    own rule. There is no safe default host to connect to, and a block that
    silently skipped the device would be the original defect again.
    """

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router '{router_id}' is missing device connection credentials "
            "(management IP, API username, or API secret), so the blocked "
            "guest's live session could not be ended",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class UnsupportedGuestAccessVendorError(GuestAccessError):
    """No session-control adapter is registered for the router's vendor."""

    def __init__(self, vendor: str) -> None:
        super().__init__(
            f"No guest access device adapter is registered for vendor '{vendor}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class GuestAccessDeviceConnectionError(GuestAccessError):
    """A real connection attempt (RouterOS API, port 8728) failed.

    The block is recorded and the guest cannot sign in again; their current
    session is still live. Named separately from an operation failure
    because the operator's next step differs -- a connection failure is
    usually the tunnel, not the router's configuration.
    """

    def __init__(self, host: str, detail: str) -> None:
        super().__init__(
            f"Could not connect to device at '{host}' to end the blocked "
            f"guest's session: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class GuestAccessDeviceOperationError(GuestAccessError):
    """A device session-control operation failed after a connection was
    established."""

    def __init__(self, operation: str, detail: str) -> None:
        super().__init__(
            f"Device operation '{operation}' failed: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class RouterHasNoHotspotError(GuestAccessError):
    """The blocked guest's session is recorded against a router that runs
    no captive portal at all.

    Refused rather than reported as a clean block. With no ``/ip hotspot``
    server there is no ``/ip hotspot active`` table, so "we removed zero
    rows" and "this guest was never online here" are the same observation
    -- and a platform that cannot tell them apart must not claim the
    stronger one. Something is wrong with the session's ``router_id`` or
    with that router's provisioning, and an operator needs to know which.
    """

    def __init__(self, router_id: uuid.UUID, host: str) -> None:
        super().__init__(
            f"Router '{router_id}' ({host}) runs no captive portal, so this "
            "platform cannot confirm the blocked guest's session was ended "
            "there",
            status_code=status.HTTP_409_CONFLICT,
        )


class SessionStillActiveOnDeviceError(GuestAccessError):
    """The removal was issued, the router raised nothing, and a second
    read still shows the guest logged in.

    This is the failure that must never be a green toast. The guest is
    blocked from signing in again and is, right now, still online.

    ``coa_accept`` is carried into the message because it is the operator's
    next lever and because it is read from *this* router rather than
    inferred: with ``/radius incoming accept=yes`` a RADIUS
    Disconnect-Request becomes available as a second mechanism, and with
    ``accept=no`` it is not, whatever this platform believes it configured.
    """

    def __init__(
        self,
        *,
        identifier: str,
        host: str,
        still_active: int,
        coa_accept: bool,
        coa_port: int | None,
    ) -> None:
        coa = (
            f"this router accepts RADIUS Disconnect-Requests on port {coa_port}"
            if coa_accept
            else (
                "this router does not accept RADIUS Disconnect-Requests "
                "(/radius incoming accept=no), so there is no second "
                "mechanism to fall back on"
            )
        )
        super().__init__(
            f"'{identifier}' is blocked from signing in again, but "
            f"{still_active} live session(s) on '{host}' did not end -- "
            f"{coa}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )
