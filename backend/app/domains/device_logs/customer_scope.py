"""Which of an organization's locations a NetLogs caller may read.

``RequirePermission("network_logs.read", scope=LOCATION)`` proves the
caller holds the key for the one location the request context names (or
organization-wide). It says nothing about the *other* locations a listing
with no ``location_id`` would return. ``rbac.location_scope
.CallerLocationScope`` does not answer that either: it is derived from every
assignment the caller holds, whatever the role -- a user who is Network
Administrator at site A and Reception Staff at site B would get B's logs.

So the confinement here is computed from the caller's effective grants **of
this one permission key**, with the same allow/deny and scope semantics
``AccessValidator.has_permission`` uses:

* a GLOBAL allow, or an ORGANIZATION allow for this organization -> the
  whole organization (``None``), minus any locations a LOCATION deny names;
* otherwise -> exactly the locations named by LOCATION allows;
* a GLOBAL deny, or an ORGANIZATION deny for this organization -> nothing.

The organization filter is applied independently in every query, so a
location from another organization in this set can never widen a result.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from fastapi import Depends

from app.domains.auth.models import AuthUser
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import (
    CurrentUser,
    RequireOrganization,
    get_access_validator,
)
from app.domains.rbac.enums import ScopeType

NETWORK_LOGS_READ = "network_logs.read"


@dataclass(frozen=True)
class LogsConfinement:
    """``allowed`` None = whole organization; ``denied`` is subtracted."""

    allowed: frozenset[uuid.UUID] | None
    denied: frozenset[uuid.UUID] = frozenset()
    #: True when a deny covers the whole organization.
    nothing: bool = False


def confinement_from_grants(
    grants: Any, *, organization_id: uuid.UUID, permission_key: str = NETWORK_LOGS_READ
) -> LogsConfinement:
    def relevant(grant: Any) -> bool:
        return grant.permission_key == permission_key

    def covers_org(scope: Any) -> bool:
        kind = ScopeType(scope.scope_type)
        return kind == ScopeType.GLOBAL or (
            kind == ScopeType.ORGANIZATION and scope.organization_id == organization_id
        )

    denied: set[uuid.UUID] = set()
    for grant in grants.deny:
        if not relevant(grant):
            continue
        if covers_org(grant.scope):
            return LogsConfinement(allowed=frozenset(), nothing=True)
        if ScopeType(grant.scope.scope_type) == ScopeType.LOCATION and (
            grant.scope.location_id is not None
        ):
            denied.add(grant.scope.location_id)

    allowed: set[uuid.UUID] = set()
    for grant in grants.allow:
        if not relevant(grant):
            continue
        if covers_org(grant.scope):
            return LogsConfinement(allowed=None, denied=frozenset(denied))
        if ScopeType(grant.scope.scope_type) == ScopeType.LOCATION and (
            grant.scope.location_id is not None
        ):
            allowed.add(grant.scope.location_id)
    return LogsConfinement(
        allowed=frozenset(allowed - denied), denied=frozenset(denied)
    )


async def NetLogsConfinement(
    user: AuthUser = Depends(CurrentUser),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    access_validator: AccessValidator = Depends(get_access_validator),
) -> LogsConfinement:
    grants = await access_validator.get_effective_grants(uuid.UUID(str(user.id)))
    return confinement_from_grants(grants, organization_id=organization_id)
