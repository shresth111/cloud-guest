"""Router domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy does -- no route needs its own
try/except translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "RouterError",
    "RouterNotFoundError",
    "DuplicateSerialNumberError",
    "DuplicateMacAddressError",
    "RouterDecommissionedError",
    "InvalidRouterStatusTransitionError",
    "CrossOrganizationRouterAccessError",
    "RouterLocationImmutableError",
    "ProvisioningTokenNotFoundError",
    "ProvisioningTokenExpiredError",
    "ProvisioningTokenAlreadyUsedError",
    "ProvisioningTokenRouterStateError",
    "ProvisioningTokenGenerationNotAllowedError",
    "RouterLiveCredentialRotationFailedError",
]


class RouterError(CloudGuestError):
    """Base exception for router domain errors."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code)


class RouterNotFoundError(RouterError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Router not found: {identifier}", status_code=status.HTTP_404_NOT_FOUND
        )


class DuplicateSerialNumberError(RouterError):
    def __init__(self, serial_number: str) -> None:
        super().__init__(
            f"A router with serial number '{serial_number}' already exists",
            status_code=status.HTTP_409_CONFLICT,
        )


class DuplicateMacAddressError(RouterError):
    def __init__(self, mac_address: str) -> None:
        super().__init__(
            f"A router with MAC address '{mac_address}' already exists",
            status_code=status.HTTP_409_CONFLICT,
        )


class RouterDecommissionedError(RouterError):
    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id} is decommissioned and cannot be modified",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidRouterStatusTransitionError(RouterError):
    """Raised when a requested status change is not a legal edge in
    ``app.domains.router.enums.ROUTER_STATUS_TRANSITIONS`` -- e.g. jumping
    straight from ``pending_provisioning`` to ``online`` without passing
    through ``provisioning``."""

    def __init__(self, current_status: str, requested_status: str) -> None:
        super().__init__(
            f"Cannot transition router from '{current_status}' to "
            f"'{requested_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class CrossOrganizationRouterAccessError(RouterError):
    """A caller acting within organization A attempted to read/mutate a
    router belonging to organization B, where B is neither A itself nor a
    child of A (mirrors ``location.exceptions
    .CrossOrganizationLocationAccessError``)."""

    def __init__(
        self,
        message: str = "Cannot access a router outside your own organization scope",
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class RouterLocationImmutableError(RouterError):
    """A router's ``location_id``/``organization_id`` cannot be changed after
    creation -- see ``docs/router/ROUTER_ARCHITECTURE.md`` §1."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id}'s location cannot be changed after creation",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ProvisioningTokenNotFoundError(RouterError):
    def __init__(self) -> None:
        super().__init__(
            "Provisioning token is invalid", status_code=status.HTTP_401_UNAUTHORIZED
        )


class ProvisioningTokenExpiredError(RouterError):
    def __init__(self) -> None:
        super().__init__(
            "Provisioning token has expired", status_code=status.HTTP_401_UNAUTHORIZED
        )


class ProvisioningTokenAlreadyUsedError(RouterError):
    def __init__(self) -> None:
        super().__init__(
            "Provisioning token has already been used",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class ProvisioningTokenRouterStateError(RouterError):
    """The token is otherwise valid, but the router it belongs to is not in
    a state that can accept a check-in (e.g. already decommissioned)."""

    def __init__(self, router_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Router {router_id} cannot check in from status '{current_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class BootstrapLocationCodeMissingError(RouterError):
    """Bootstrap script rendering requires a ``location_code`` on the
    router's location row."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id}'s location has no location_code -- cannot "
            "render bootstrap script",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class RemoteBootstrapNeverEnrolledError(RouterError):
    """Remote-mode bootstrap re-provisions a *live* tunnel -- a router that
    has never checked in (``last_seen_at IS NULL``) has no tunnel to
    protect, no transport to deliver the script through, and the remote
    script's own on-device guards would refuse it anyway. The on-site
    script is the only correct path for first enrollment."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id} has never checked in -- remote bootstrap "
            "re-provisions a live tunnel; use the on-site (default) "
            "bootstrap script for first enrollment",
            status_code=status.HTTP_409_CONFLICT,
        )


class ProvisioningTokenGenerationNotAllowedError(RouterError):
    """A provisioning token may only be generated while a router is still
    ``pending_provisioning`` -- see ``docs/router/ROUTER_ARCHITECTURE.md``
    §5."""

    def __init__(self, router_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Cannot generate a provisioning token for router {router_id} in "
            f"status '{current_status}' -- only allowed while "
            "pending_provisioning",
            status_code=status.HTTP_409_CONFLICT,
        )


class RouterLiveCredentialRotationFailedError(RouterError):
    """Raised by ``RouterService.update_router`` when an ``api_secret``
    change is being applied to a router that already has a *working*
    RouterOS API credential on file (a real host/username/secret already
    stored -- i.e. this is a *rotation*, not first-time issuance), and the
    live push of the new password to the physical device (via
    ``DeviceCredentialRotatorProtocol``) did not succeed.

    This exists specifically to close the gap that caused the
    "Permission denied for user cloudguest-api" production incident:
    Master Console's Setup Script panel regenerates and immediately
    persists a brand-new random ``api_secret`` to the DB every time an
    admin re-runs it against an already-provisioned router, but the
    physical device's RouterOS user password is only ever updated if the
    admin separately re-pastes the resulting "API Access" script chunk in
    WinBox. Any router that had its credential regenerated without that
    manual re-paste step is left with a DB secret that no longer matches
    the device -- silently, until the platform next tries to use it.

    Raising here (instead of persisting the new secret regardless)
    guarantees the DB and the device can never drift out of sync through
    this endpoint: either the live push succeeds and both are updated
    together, or neither is -- the old secret keeps working until the
    device is reachable again. The caller (Master Console's Setup Script
    generator) already treats a failed ``PUT /routers/{id}`` as
    non-fatal -- it shows an error toast and omits the "API Access" chunk
    from the generated script rather than handing out a script chunk the
    platform can't actually use."""

    def __init__(self, router_id: uuid.UUID, detail: str) -> None:
        super().__init__(
            f"Could not rotate the live API credential on router {router_id}'s "
            f"device -- the stored secret was left unchanged: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )
