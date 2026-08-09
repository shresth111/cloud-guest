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

__all__ = [
    "NetworkConfigError",
    "EmptyNetworkConfigError",
    "NetwatchIntegrationUnavailableError",
    "NoNetwatchTargetsError",
]


class NetworkConfigError(CloudGuestError):
    """Base exception for Network Configuration Management domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class NetwatchIntegrationUnavailableError(NetworkConfigError):
    """``NetworkConfigService.push_isp_netwatch_config`` was called against
    a service instance that was not constructed with its
    ``isp_link_lookup``/``agent_credential_issuer``/``router_lookup``
    composed -- every real production wiring (``dependencies.py``) always
    composes all three, so this only fires for a test/construction path
    that deliberately omits one. A real, honest 500 (a deployment/wiring
    gap), never a silent no-op."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Netwatch integration is not configured for router {router_id} "
            "-- isp_link_lookup/agent_credential_issuer/router_lookup must "
            "all be composed on NetworkConfigService",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class NoNetwatchTargetsError(NetworkConfigError):
    """Raised when a router has zero enabled, ``STATIC``-mode ISP links
    with a known ``gateway_ip_address`` -- pushing an empty Netwatch script
    would create a real, durable, permanently-empty ``ConfigVersion`` row
    and queue a real device-side no-op job, the identical "don't push
    nothing" discipline :class:`EmptyNetworkConfigError` already
    establishes for the main config-push flow."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id} has no enabled, STATIC-mode ISP links with "
            "a known gateway_ip_address to configure Netwatch against",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


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
