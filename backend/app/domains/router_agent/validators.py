"""Pure, side-effect-free business-rule checks for the Router Agent domain.

Every function here takes an already-fetched model instance (or plain
value) and either returns ``None`` or raises one of this module's own
``exceptions``. None of these functions perform I/O -- mirrors
``app.domains.router_provisioning.validators``'s identical discipline of
keeping "what is a legal state" centralized and directly testable in
isolation from any database, consumed here by ``dependencies.py``'s agent
-credential-validation dependency (this module's sole identity-verification
mechanism -- see ``dependencies.py``'s module docstring for why no separate
"verify identity" endpoint exists).
"""

from __future__ import annotations

from datetime import datetime

from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router

from .exceptions import (
    AgentCredentialExpiredError,
    AgentCredentialRevokedError,
    AgentRouterNotEligibleError,
)
from .models import RouterAgentCredential

# A router in either of these BE-008 lifecycle statuses has no business
# talking to the agent API: a decommissioned router is permanently retired,
# and a suspended router is administratively frozen pending human action --
# identical reasoning to
# ``router_provisioning.validators._ROUTER_STATUSES_INELIGIBLE_FOR_CONFIG``.
_ROUTER_STATUSES_INELIGIBLE_FOR_AGENT = frozenset(
    {RouterStatus.DECOMMISSIONED.value, RouterStatus.SUSPENDED.value}
)


def validate_router_eligible_for_agent(router: Router) -> None:
    if router.status in _ROUTER_STATUSES_INELIGIBLE_FOR_AGENT:
        raise AgentRouterNotEligibleError(router.id, router.status)


def validate_credential_not_revoked(credential: RouterAgentCredential) -> None:
    if credential.revoked_at is not None:
        raise AgentCredentialRevokedError()


def validate_credential_not_expired(
    credential: RouterAgentCredential, *, now: datetime
) -> None:
    if now > credential.expires_at:
        raise AgentCredentialExpiredError()


__all__ = [
    "validate_router_eligible_for_agent",
    "validate_credential_not_revoked",
    "validate_credential_not_expired",
]
