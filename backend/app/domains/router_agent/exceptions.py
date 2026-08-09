"""Router Agent domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation. Job-related errors (a job not belonging to this router, an
already-terminal job) are deliberately **not** redefined here -- this module
reuses ``app.domains.router_provisioning.exceptions``'s existing
``ProvisioningJobNotFoundError``/``ProvisioningJobRouterMismatchError``/
``InvalidProvisioningJobStatusTransitionError`` as-is (raised by the very
``RouterProvisioningService`` methods this module calls), rather than
wrapping them in a parallel set of router-agent-specific classes for the
same facts.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "RouterAgentError",
    "AgentCredentialMissingError",
    "AgentCredentialInvalidError",
    "AgentCredentialExpiredError",
    "AgentCredentialRevokedError",
    "AgentRouterNotEligibleError",
    "NoConfigAssignedError",
    "NetwatchLinkNotFoundForRouterError",
]


class RouterAgentError(CloudGuestError):
    """Base exception for router-agent domain errors."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code)


class AgentCredentialMissingError(RouterAgentError):
    def __init__(self) -> None:
        super().__init__(
            "Agent credential required (missing X-Agent-Credential header)",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class AgentCredentialInvalidError(RouterAgentError):
    def __init__(self) -> None:
        super().__init__(
            "Agent credential is invalid", status_code=status.HTTP_401_UNAUTHORIZED
        )


class AgentCredentialExpiredError(RouterAgentError):
    def __init__(self) -> None:
        super().__init__(
            "Agent credential has expired", status_code=status.HTTP_401_UNAUTHORIZED
        )


class AgentCredentialRevokedError(RouterAgentError):
    def __init__(self) -> None:
        super().__init__(
            "Agent credential has been revoked",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class AgentRouterNotEligibleError(RouterAgentError):
    """The credential itself is valid, but the router it belongs to is
    ``decommissioned``/``suspended`` -- composes with BE-008's own
    ``RouterStatus``, not a new lifecycle of its own."""

    def __init__(self, router_id: uuid.UUID, current_status: str) -> None:
        super().__init__(
            f"Router {router_id} in status '{current_status}' cannot use the "
            "agent API",
            status_code=status.HTTP_409_CONFLICT,
        )


class NoConfigAssignedError(RouterAgentError):
    """Raised by the config-pull endpoint when the router has no applied
    ``ConfigVersion`` yet (no profile assigned, or a profile assigned but
    nothing has ever completed application) -- mirrors
    ``router_provisioning.exceptions.NoAppliedConfigToBackupError``'s
    identical "nothing applied yet" semantics."""

    def __init__(self, router_id: uuid.UUID) -> None:
        super().__init__(
            f"Router {router_id} has no applied configuration yet -- nothing "
            "to pull",
            status_code=status.HTTP_409_CONFLICT,
        )


class NetwatchLinkNotFoundForRouterError(RouterAgentError):
    """Raised by ``POST /agent/netwatch-event`` when the reported
    ``isp_link_id`` resolves to a real ``IspLink`` that belongs to a
    *different* router than the one identified by this call's own
    ``X-Agent-Credential`` -- the "exists, but not yours" half of the same
    two-exception shape ``app.domains.router_provisioning.exceptions
    .ProvisioningJobNotFoundError``/``ProvisioningJobRouterMismatchError``
    already establishes for ``complete_action``'s identical ownership
    check (a link that does not exist at all instead raises
    ``app.domains.isp.exceptions.IspLinkNotFoundError``, reused as-is, one
    layer down in ``IspService.get_link`` -- never re-wrapped here).
    Neither this error's message nor that one's reveals which router the
    link actually belongs to."""

    def __init__(self, isp_link_id: str) -> None:
        super().__init__(
            f"ISP link '{isp_link_id}' was not found for this router",
            status_code=status.HTTP_404_NOT_FOUND,
        )
