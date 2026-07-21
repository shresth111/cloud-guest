"""Policy business logic: policy/version/assignment lifecycle
(``PolicyService``) and the pure scope-precedence resolution that decides
which assignment governs a given organization/location
(``PolicyResolver``).

## ``policy`` is a leaf module

Per ``docs/ARCHITECTURE_DESIGN.md`` §4/§13, this module depends only on
``organization``/``location`` (tenant/hierarchy lookups, via narrow
Protocols) and ``rbac`` (audit logging, and reusing ``ScopeType`` for
``PolicyAssignment.scope_type`` -- both foundational Identity & Access
modules, not feature domains). It has **zero** import of
``app.domains.guest``/``app.domains.guest_access``/``app.domains.voucher``/
etc. -- those modules would depend on ``policy``, never the reverse, so
``policy`` can never be part of an import cycle as more consumers are added.
No consumer has been wired up to actually call this module yet (see
``docs/policy/FLOW.md``'s own "what this module does not do yet" section)
-- this module builds the real, working leaf itself; rewiring
``guest``/``guest_access``/``voucher`` to read from it is explicitly a
separate, future change, out of this module's own directory boundary.

## Versioning: append-only, current-pointer-based rollback

``PolicyVersion`` rows are immutable once created -- ``create_version``
always inserts a new ``DRAFT`` row, never mutates an existing one's
``rules``. ``Policy.current_version_id`` is the single, explicit pointer at
whichever version is "live" -- ``publish_version`` moves it forward,
``rollback`` moves it back to any earlier *already-published* version. This
is deliberately not "delete every version after the rollback target" (that
would destroy the append-only audit trail ``docs/ARCHITECTURE_DESIGN.md``
§6.1 calls for) and not "duplicate the target version's rules into a new
version" (that would create two versions with identical ``rules`` and no
way to tell, from the version history alone, that one was a rollback rather
than an independent edit that happened to match) -- re-pointing the existing
column is the simplest operation that is both correct and fully traceable.

## Resolution: scope specificity, then priority, then platform default

``PolicyResolver.resolve`` is pure (no I/O) -- ``PolicyService
.resolve_effective_policy`` does the actual repository fetch (via
``PolicyRepository.list_candidate_assignments``, the join described in
``repository.py``'s own docstring) and hands the results here. Precedence:
``LOCATION`` > ``ORGANIZATION`` > ``GLOBAL`` (mirrors
``app.domains.rbac.enums.SCOPE_HIERARCHY_ORDER``'s identical broad-to-narrow
ordering, just resolved narrow-first instead of broad-first), tie-broken by
``PolicyAssignment.priority`` (higher wins) for two assignments at the same
scope. If no assignment matches at all, ``resolve_effective_policy`` falls
back to ``constants.PLATFORM_DEFAULT_RULES`` -- the safety net that lets
every organization get a sane, real answer to "what session policy applies
to me" even before anyone has ever configured one, mirroring
``app.domains.guest.constants.DEFAULT_SESSION_TIMEOUT_MINUTES``'s own
previous role as *the* answer before this module existed.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction, ScopeType

from .constants import (
    PLATFORM_DEFAULT_RULES,
    PolicyAssignmentTargetType,
    PolicyType,
    PolicyVersionStatus,
)
from .events import (
    PolicyAssignmentCreated,
    PolicyAssignmentDeactivated,
    PolicyCreated,
    PolicyRolledBack,
    PolicyVersionCreated,
    PolicyVersionPublished,
)
from .exceptions import (
    CrossOrganizationPolicyAccessError,
    PolicyAssignmentNotFoundError,
    PolicyAssignmentRequiresPublishedVersionError,
    PolicyAssignmentTargetRoleNotFoundError,
    PolicyAssignmentTargetUserNotFoundError,
    PolicyNotFoundError,
    PolicyRollbackTargetMismatchError,
    PolicyRollbackTargetNotPublishedError,
    PolicyVersionNotFoundError,
)
from .models import Policy, PolicyAssignment, PolicyVersion
from .repository import PolicyRepositoryProtocol
from .validators import (
    validate_assignment_scope,
    validate_assignment_target,
    validate_rules,
    validate_version_status_transition,
)

logger = logging.getLogger(__name__)

_SCOPE_SPECIFICITY: dict[str, int] = {
    ScopeType.GLOBAL.value: 0,
    ScopeType.ORGANIZATION.value: 1,
    ScopeType.LOCATION.value: 2,
}

# WHO-specificity (Enterprise SaaS Phase F) -- a user-targeted assignment
# always outranks a role-targeted one, which always outranks an untargeted
# one, regardless of which WHERE tier either was defined at (see
# PolicyResolver.resolve's own docstring for the combined ordering).
_TARGET_SPECIFICITY: dict[str, int] = {
    PolicyAssignmentTargetType.NONE.value: 0,
    PolicyAssignmentTargetType.ROLE.value: 1,
    PolicyAssignmentTargetType.USER.value: 2,
}


def _event_extra(event: object) -> dict[str, object]:
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class OrganizationLookupProtocol(Protocol):
    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization: ...


class LocationLookupProtocol(Protocol):
    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class UserLookupProtocol(Protocol):
    """The single method this module needs to validate a ``user``-targeted
    :class:`~.models.PolicyAssignment` actually names a real user --
    satisfied structurally by ``app.domains.auth.repository
    .AuthRepository`` (composition, not a new identity store)."""

    async def get_user_by_id(self, user_id: uuid.UUID) -> object | None: ...


class RoleLookupProtocol(Protocol):
    """The single method this module needs to validate a ``role``-targeted
    :class:`~.models.PolicyAssignment` actually names a real role --
    satisfied structurally by ``app.domains.rbac.repository
    .RBACRepository`` (the same object already composed as this
    service's ``AuditLogWriter``)."""

    async def get_role_by_id(
        self, role_id: uuid.UUID, *, include_deleted: bool = False
    ) -> object | None: ...


# ============================================================================
# Pure resolution
# ============================================================================


class PolicyResolver:
    """Pure precedence resolution over already-fetched candidate
    assignments -- see module docstring.

    Enterprise SaaS Phase F: the WHO axis (``target_type``) is resolved
    *first* -- a user-targeted assignment always wins over a role-targeted
    or untargeted one, regardless of which WHERE tier (``scope_type``)
    either was defined at, since a personalized override is meant to be
    the most specific possible match. The existing WHERE-tier/``priority``
    ordering remains the tiebreaker within the same WHO tier."""

    def resolve(self, *, candidates: list[PolicyAssignment]) -> PolicyAssignment | None:
        if not candidates:
            return None
        return max(
            candidates,
            key=lambda a: (
                _TARGET_SPECIFICITY.get(
                    a.target_type or PolicyAssignmentTargetType.NONE.value, -1
                ),
                _SCOPE_SPECIFICITY.get(a.scope_type, -1),
                a.priority,
            ),
        )


# ============================================================================
# Read models
# ============================================================================


@dataclass(frozen=True, slots=True)
class ResolvedPolicy:
    policy_type: PolicyType
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None
    rules: dict[str, Any]
    source: str
    user_id: uuid.UUID | None = None


# ============================================================================
# Application service
# ============================================================================


class PolicyService:
    """Core Policy business logic -- see module docstring for the full
    design write-up."""

    def __init__(
        self,
        repository: PolicyRepositoryProtocol,
        organization_lookup: OrganizationLookupProtocol,
        location_lookup: LocationLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        user_lookup: UserLookupProtocol | None = None,
        role_lookup: RoleLookupProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.organization_lookup = organization_lookup
        self.location_lookup = location_lookup
        self.audit_writer = audit_writer
        self.user_lookup = user_lookup
        self.role_lookup = role_lookup
        self.resolver = PolicyResolver()

    # ========================================================================
    # Policy lifecycle
    # ========================================================================

    async def create_policy(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        organization_id: uuid.UUID | None,
        policy_type: PolicyType,
        name: str,
        description: str | None,
    ) -> Policy:
        if organization_id is None:
            # Only a platform-level caller (no requesting organization at
            # all) may create a platform-wide policy definition.
            if requesting_organization_id is not None:
                raise CrossOrganizationPolicyAccessError()
        else:
            if (
                requesting_organization_id is not None
                and organization_id != requesting_organization_id
            ):
                raise CrossOrganizationPolicyAccessError()
            await self.organization_lookup.get_organization(organization_id)

        policy = await self.repository.create_policy(
            organization_id=organization_id,
            policy_type=policy_type.value,
            name=name,
            description=description,
            is_active=True,
            current_version_id=None,
            created_by_user_id=actor_user_id,
            created_by=actor_user_id,
        )
        event = PolicyCreated(
            policy_id=policy.id,
            organization_id=organization_id,
            policy_type=policy_type.value,
        )
        logger.info("policy_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.POLICY_CREATED,
            policy_id=policy.id,
            organization_id=organization_id,
            description=f"Policy '{policy.name}' ({policy_type.value}) created",
        )
        return policy

    async def get_policy(
        self,
        policy_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Policy:
        policy = await self.repository.get_policy_by_id(policy_id)
        if policy is None:
            raise PolicyNotFoundError(policy_id)
        self._enforce_read_scope(policy.organization_id, requesting_organization_id)
        return policy

    async def list_policies(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        policy_type: PolicyType | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Policy], object]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if policy_type is not None:
            filters["policy_type"] = policy_type.value
        return await self.repository.list_policies(
            page=page, page_size=page_size, filters=filters or None
        )

    async def deactivate_policy(
        self,
        *,
        policy_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
    ) -> Policy:
        policy = await self.get_policy(
            policy_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update_policy(
            policy, {"is_active": False, "updated_by": actor_user_id}
        )
        await self._audit(
            actor_user_id,
            AuditAction.POLICY_DEACTIVATED,
            policy_id=updated.id,
            organization_id=updated.organization_id,
            description=f"Policy '{updated.name}' deactivated",
        )
        return updated

    # ========================================================================
    # Versioning
    # ========================================================================

    async def create_version(
        self,
        *,
        policy_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
        rules: dict[str, Any],
    ) -> PolicyVersion:
        policy = await self.get_policy(
            policy_id, requesting_organization_id=requesting_organization_id
        )
        validated_rules = validate_rules(PolicyType(policy.policy_type), rules)
        version_number = await self.repository.get_next_version_number(policy.id)
        version = await self.repository.create_version(
            policy_id=policy.id,
            version_number=version_number,
            status=PolicyVersionStatus.DRAFT.value,
            rules=validated_rules,
            published_at=None,
            created_by_user_id=actor_user_id,
            created_by=actor_user_id,
        )
        event = PolicyVersionCreated(
            policy_id=policy.id, version_id=version.id, version_number=version_number
        )
        logger.info("policy_version_created", extra=_event_extra(event))
        return version

    async def publish_version(
        self,
        *,
        policy_id: uuid.UUID,
        version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
    ) -> PolicyVersion:
        policy = await self.get_policy(
            policy_id, requesting_organization_id=requesting_organization_id
        )
        version = await self.repository.get_version_by_id(version_id)
        if version is None or version.policy_id != policy.id:
            raise PolicyVersionNotFoundError(version_id)

        current = PolicyVersionStatus(version.status)
        validate_version_status_transition(
            current=current, target=PolicyVersionStatus.PUBLISHED
        )

        now = datetime.now(UTC)
        updated_version = await self.repository.update_version(
            version,
            {
                "status": PolicyVersionStatus.PUBLISHED.value,
                "published_at": now,
                "updated_by": actor_user_id,
            },
        )
        await self.repository.update_policy(
            policy,
            {"current_version_id": updated_version.id, "updated_by": actor_user_id},
        )
        event = PolicyVersionPublished(
            policy_id=policy.id,
            version_id=updated_version.id,
            version_number=updated_version.version_number,
        )
        logger.info("policy_version_published", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.POLICY_VERSION_PUBLISHED,
            policy_id=policy.id,
            organization_id=policy.organization_id,
            description=(
                f"Policy '{policy.name}' version {updated_version.version_number} "
                "published"
            ),
        )
        return updated_version

    async def rollback(
        self,
        *,
        policy_id: uuid.UUID,
        target_version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
    ) -> Policy:
        policy = await self.get_policy(
            policy_id, requesting_organization_id=requesting_organization_id
        )
        target = await self.repository.get_version_by_id(target_version_id)
        if target is None:
            raise PolicyVersionNotFoundError(target_version_id)
        if target.policy_id != policy.id:
            raise PolicyRollbackTargetMismatchError(policy.id, target_version_id)
        if PolicyVersionStatus(target.status) != PolicyVersionStatus.PUBLISHED:
            raise PolicyRollbackTargetNotPublishedError(target_version_id)

        previous_version_id = policy.current_version_id
        updated_policy = await self.repository.update_policy(
            policy,
            {"current_version_id": target.id, "updated_by": actor_user_id},
        )
        event = PolicyRolledBack(
            policy_id=updated_policy.id,
            from_version_id=previous_version_id,
            to_version_id=target.id,
        )
        logger.info("policy_rolled_back", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.POLICY_ROLLED_BACK,
            policy_id=updated_policy.id,
            organization_id=updated_policy.organization_id,
            description=(
                f"Policy '{updated_policy.name}' rolled back to version "
                f"{target.version_number}"
            ),
        )
        return updated_policy

    # ========================================================================
    # Assignments
    # ========================================================================

    async def create_assignment(
        self,
        *,
        policy_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
        scope_type: str,
        scope_id: uuid.UUID | None,
        priority: int,
        target_type: str = PolicyAssignmentTargetType.NONE.value,
        target_id: uuid.UUID | None = None,
    ) -> PolicyAssignment:
        policy = await self.get_policy(
            policy_id, requesting_organization_id=requesting_organization_id
        )
        if policy.current_version_id is None:
            raise PolicyAssignmentRequiresPublishedVersionError(policy.id)

        validate_assignment_scope(scope_type=scope_type, scope_id=scope_id)
        if scope_type == ScopeType.ORGANIZATION.value and scope_id is not None:
            await self.organization_lookup.get_organization(scope_id)
        elif scope_type == ScopeType.LOCATION.value and scope_id is not None:
            await self.location_lookup.get_location(
                scope_id, requesting_organization_id=requesting_organization_id
            )

        validate_assignment_target(target_type=target_type, target_id=target_id)
        if (
            target_type == PolicyAssignmentTargetType.USER.value
            and target_id is not None
            and self.user_lookup is not None
        ):
            user = await self.user_lookup.get_user_by_id(target_id)
            if user is None:
                raise PolicyAssignmentTargetUserNotFoundError(target_id)
        elif (
            target_type == PolicyAssignmentTargetType.ROLE.value
            and target_id is not None
            and self.role_lookup is not None
        ):
            role = await self.role_lookup.get_role_by_id(target_id)
            if role is None:
                raise PolicyAssignmentTargetRoleNotFoundError(target_id)

        assignment = await self.repository.create_assignment(
            policy_id=policy.id,
            scope_type=scope_type,
            scope_id=scope_id,
            priority=priority,
            target_type=target_type,
            target_id=target_id,
            is_active=True,
            created_by_user_id=actor_user_id,
            created_by=actor_user_id,
        )
        event = PolicyAssignmentCreated(
            assignment_id=assignment.id,
            policy_id=policy.id,
            scope_type=scope_type,
            scope_id=scope_id,
        )
        logger.info("policy_assignment_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.POLICY_ASSIGNMENT_CREATED,
            policy_id=policy.id,
            organization_id=policy.organization_id,
            description=(
                f"Policy '{policy.name}' assigned to {scope_type}"
                + (f" {scope_id}" if scope_id else "")
            ),
        )
        return assignment

    async def list_assignments(
        self,
        *,
        policy_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[PolicyAssignment]:
        policy = await self.get_policy(
            policy_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_assignments_for_policy(policy.id)

    async def deactivate_assignment(
        self,
        *,
        policy_id: uuid.UUID,
        assignment_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
    ) -> PolicyAssignment:
        policy = await self.get_policy(
            policy_id, requesting_organization_id=requesting_organization_id
        )
        assignment = await self.repository.get_assignment_by_id(assignment_id)
        if assignment is None or assignment.policy_id != policy.id:
            raise PolicyAssignmentNotFoundError(assignment_id)

        updated = await self.repository.update_assignment(
            assignment, {"is_active": False, "updated_by": actor_user_id}
        )
        event = PolicyAssignmentDeactivated(
            assignment_id=updated.id, policy_id=policy.id
        )
        logger.info("policy_assignment_deactivated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.POLICY_ASSIGNMENT_DEACTIVATED,
            policy_id=policy.id,
            organization_id=policy.organization_id,
            description=f"Policy assignment {updated.id} deactivated",
        )
        return updated

    # ========================================================================
    # Resolution -- the real "read" API other modules could compose with
    # ========================================================================

    async def resolve_effective_policy(
        self,
        *,
        policy_type: PolicyType,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        user_id: uuid.UUID | None = None,
        role_ids: list[uuid.UUID] | None = None,
    ) -> ResolvedPolicy:
        """See module docstring's "Resolution" write-up. Falls back to
        ``constants.PLATFORM_DEFAULT_RULES`` when no assignment matches at
        all -- always returns a real, usable rule set, never ``None``.

        ``user_id``/``role_ids`` (Enterprise SaaS Phase F) additionally
        surface any per-user or per-role assignment as a resolution
        candidate -- see ``PolicyResolver.resolve``'s own docstring for
        why a matching one always wins over an untargeted match."""
        candidates = await self.repository.list_candidate_assignments(
            policy_type=policy_type.value,
            organization_id=organization_id,
            location_id=location_id,
            user_id=user_id,
            role_ids=role_ids,
        )
        winner = self.resolver.resolve(candidates=candidates)
        if winner is None:
            return ResolvedPolicy(
                policy_type=policy_type,
                organization_id=organization_id,
                location_id=location_id,
                rules=dict(PLATFORM_DEFAULT_RULES.get(policy_type, {})),
                source="platform_default",
                user_id=user_id,
            )

        policy = await self.repository.get_policy_by_id(winner.policy_id)
        if policy is None or policy.current_version_id is None:
            # Defensive -- list_candidate_assignments already filters for
            # is_active + current_version_id is not None, so this should be
            # unreachable outside a concurrent deactivation racing this read.
            return ResolvedPolicy(
                policy_type=policy_type,
                organization_id=organization_id,
                location_id=location_id,
                rules=dict(PLATFORM_DEFAULT_RULES.get(policy_type, {})),
                source="platform_default",
                user_id=user_id,
            )
        version = await self.repository.get_version_by_id(policy.current_version_id)
        rules = dict(version.rules) if version is not None else {}
        winner_target_type = winner.target_type or PolicyAssignmentTargetType.NONE.value
        if winner_target_type != PolicyAssignmentTargetType.NONE.value:
            source = f"{winner_target_type}:{winner.target_id}"
        elif winner.scope_id is not None:
            source = f"{winner.scope_type}:{winner.scope_id}"
        else:
            source = f"{winner.scope_type}:{policy.id}"
        return ResolvedPolicy(
            policy_type=policy_type,
            organization_id=organization_id,
            location_id=location_id,
            rules=rules,
            source=source,
            user_id=user_id,
        )

    # ========================================================================
    # Internal helpers
    # ========================================================================

    def _enforce_read_scope(
        self,
        policy_organization_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        """Platform-wide policies (``organization_id is None``) are readable
        by every caller -- they're resolution candidates for everyone. An
        organization's own custom policy is only readable by that same
        organization (or a platform-level caller)."""
        if (
            policy_organization_id is not None
            and requesting_organization_id is not None
            and policy_organization_id != requesting_organization_id
        ):
            raise CrossOrganizationPolicyAccessError()

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        policy_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="policy",
            entity_id=policy_id,
            description=description,
            organization_id=organization_id,
            location_id=None,
        )


__all__ = [
    "PolicyService",
    "PolicyResolver",
    "ResolvedPolicy",
    "OrganizationLookupProtocol",
    "LocationLookupProtocol",
    "AuditLogWriter",
]
