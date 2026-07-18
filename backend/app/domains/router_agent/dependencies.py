"""FastAPI dependencies for the Router Agent domain.

Wires the repository/service layer, composing with ``app.domains.router``
(BE-008's ``RouterService``/``RouterRepository``) and
``app.domains.router_provisioning`` (Module 009 Part 1's
``RouterProvisioningRepository``/``RouterProvisioningService``) rather than
duplicating any of them.

**``CurrentAgent`` is this module's entire authentication/authorization
mechanism -- deliberately not RBAC's.** Every device-facing endpoint in
``router.py`` depends on it instead of ``RequirePermission``/``CurrentUser``:
a physical device has no platform user identity, session, or JWT, so RBAC's
scope-header/permission-check machinery has nothing to check. ``CurrentAgent``
reads the persistent credential from ``constants.AGENT_CREDENTIAL_HEADER``
(see ``service.py``'s module docstring for why a header, and why not
``Authorization: Bearer``), hash-compares it against
``RouterAgentCredential.credential_hash``, rejects it if expired/revoked, and
resolves + validates the ``Router`` row it is bound to (rejecting
``decommissioned``/``suspended`` routers) -- this **is** the identity
-verification step (see ``service.py``'s module docstring for why no second,
separate "verify identity" endpoint exists). ``router_id`` always comes from
the credential's own FK, never from client-supplied input, so there is
nothing left for a caller to spoof that this dependency doesn't already
resolve server-side.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.router.dependencies import get_router_repository, get_router_service
from app.domains.router.models import Router
from app.domains.router.repository import RouterRepositoryProtocol
from app.domains.router.service import RouterService
from app.domains.router_provisioning.dependencies import (
    get_router_provisioning_repository,
    get_router_provisioning_service,
)
from app.domains.router_provisioning.repository import (
    RouterProvisioningRepositoryProtocol,
)
from app.domains.router_provisioning.service import RouterProvisioningService

from .constants import AGENT_CREDENTIAL_HEADER
from .exceptions import AgentCredentialInvalidError, AgentCredentialMissingError
from .models import RouterAgentCredential
from .repository import RouterAgentRepository, RouterAgentRepositoryProtocol
from .service import RouterAgentService, hash_credential
from .validators import (
    validate_credential_not_expired,
    validate_credential_not_revoked,
    validate_router_eligible_for_agent,
)


def get_router_agent_repository(
    db: AsyncSession = Depends(get_db_session),
) -> RouterAgentRepositoryProtocol:
    return RouterAgentRepository(db)


def get_router_agent_service(
    repository: RouterAgentRepositoryProtocol = Depends(get_router_agent_repository),
    router_service: RouterService = Depends(get_router_service),
    provisioning_repository: RouterProvisioningRepositoryProtocol = Depends(
        get_router_provisioning_repository
    ),
    provisioning_service: RouterProvisioningService = Depends(
        get_router_provisioning_service
    ),
) -> RouterAgentService:
    return RouterAgentService(
        repository,
        router_service,
        provisioning_repository,
        provisioning_repository,
        provisioning_service,
        event_writer=provisioning_repository,
    )


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    """The resolved, validated device identity for one agent request --
    returned by ``CurrentAgent``, consumed by every endpoint in ``router.py``
    exactly the way ``CurrentUser``/``CurrentOrganization`` are consumed by
    every other domain's user-facing endpoints."""

    router: Router
    credential: RouterAgentCredential


async def CurrentAgent(
    request: Request,
    agent_repository: RouterAgentRepositoryProtocol = Depends(
        get_router_agent_repository
    ),
    router_repository: RouterRepositoryProtocol = Depends(get_router_repository),
) -> AgentIdentity:
    """The device identity for this request, resolved from
    ``X-Agent-Credential`` -- see module docstring."""
    raw_credential = request.headers.get(AGENT_CREDENTIAL_HEADER)
    if not raw_credential:
        raise AgentCredentialMissingError()

    credential = await agent_repository.get_by_credential_hash(
        hash_credential(raw_credential)
    )
    if credential is None:
        raise AgentCredentialInvalidError()

    now = datetime.now(UTC)
    validate_credential_not_revoked(credential)
    validate_credential_not_expired(credential, now=now)

    router = await router_repository.get_by_id(
        credential.router_id, include_deleted=True
    )
    if router is None:
        raise AgentCredentialInvalidError()
    validate_router_eligible_for_agent(router)

    await agent_repository.update_credential(credential, {"last_used_at": now})
    return AgentIdentity(router=router, credential=credential)


__all__ = [
    "get_router_agent_repository",
    "get_router_agent_service",
    "AgentIdentity",
    "CurrentAgent",
]
