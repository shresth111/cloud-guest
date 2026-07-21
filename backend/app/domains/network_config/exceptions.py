"""Network Configuration Management domain exceptions.

Every other error condition this domain can hit (router not found, cross-
organization access, unresolved template placeholders, invalid version
transitions) is already a real, tested exception raised by
``app.domains.router_provisioning`` itself -- composed and re-raised
as-is, never re-wrapped, mirroring ``app.domains.controller_logs``'s own
"never re-invent an error a composed domain already raises correctly"
posture. This module adds exactly one exception genuinely new to this
domain's own logic.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = ["NetworkConfigError", "EmptyNetworkConfigError"]


class NetworkConfigError(CloudGuestError):
    """Base exception for Network Configuration Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class EmptyNetworkConfigError(NetworkConfigError):
    """Raised when a router has zero enabled DHCP pools, VLANs, and port-
    forwarding rules -- pushing a blank ``ConfigVersion`` would create a
    real, durable, permanently-empty history row and queue a real
    ``ProvisioningJob`` for a device-side no-op, neither of which is
    useful. Preview is still allowed to return an empty result (with a
    warning), since a caller may reasonably want to see "there is
    currently nothing to push" before disabling this check."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id} has no enabled DHCP pools, VLANs, or "
            "port-forwarding rules to push",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
