"""Data access layer for the Policy domain.

Mirrors ``app.domains.guest_teams.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``PolicyRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``PolicyRepository``) wrapping three ``GenericRepository``
instances (one per table), plus hand-written queries for the lookups
``GenericRepository``'s plain equality/IN-filter support cannot express on
its own: the next version number for a policy, and the scope-matching join
``PolicyResolver`` needs (active assignments, for an active policy of a given
type, whose scope matches global/this organization/this location).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.rbac.enums import ScopeType

from .constants import PolicyAssignmentTargetType
from .models import Policy, PolicyAssignment, PolicyVersion


class PolicyRepositoryProtocol(Protocol):
    # -- policies --------------------------------------------------------
    async def create_policy(self, **fields: object) -> Policy: ...

    async def get_policy_by_id(
        self, policy_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Policy | None: ...

    async def update_policy(
        self, policy: Policy, data: dict[str, object]
    ) -> Policy: ...

    async def list_policies(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[Policy], PaginationMeta]: ...

    # -- versions --------------------------------------------------------
    async def create_version(self, **fields: object) -> PolicyVersion: ...

    async def get_version_by_id(
        self, version_id: uuid.UUID
    ) -> PolicyVersion | None: ...

    async def update_version(
        self, version: PolicyVersion, data: dict[str, object]
    ) -> PolicyVersion: ...

    async def list_versions_for_policy(
        self, policy_id: uuid.UUID
    ) -> list[PolicyVersion]: ...

    async def get_next_version_number(self, policy_id: uuid.UUID) -> int: ...

    # -- assignments -------------------------------------------------------
    async def create_assignment(self, **fields: object) -> PolicyAssignment: ...

    async def get_assignment_by_id(
        self, assignment_id: uuid.UUID
    ) -> PolicyAssignment | None: ...

    async def update_assignment(
        self, assignment: PolicyAssignment, data: dict[str, object]
    ) -> PolicyAssignment: ...

    async def list_assignments_for_policy(
        self, policy_id: uuid.UUID
    ) -> list[PolicyAssignment]: ...

    async def list_candidate_assignments(
        self,
        *,
        policy_type: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        user_id: uuid.UUID | None = None,
        role_ids: list[uuid.UUID] | None = None,
    ) -> list[PolicyAssignment]: ...


class PolicyRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``PolicyRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.policies = GenericRepository(Policy, session)
        self.versions = GenericRepository(PolicyVersion, session)
        self.assignments = GenericRepository(PolicyAssignment, session)

    # -- policies --------------------------------------------------------

    async def create_policy(self, **fields: object) -> Policy:
        return await self.policies.create(fields)

    async def get_policy_by_id(
        self, policy_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Policy | None:
        return await self.policies.get_by_id(policy_id, include_deleted=include_deleted)

    async def update_policy(self, policy: Policy, data: dict[str, object]) -> Policy:
        return await self.policies.update(policy, data)

    async def list_policies(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[Policy], PaginationMeta]:
        return await self.policies.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    # -- versions --------------------------------------------------------

    async def create_version(self, **fields: object) -> PolicyVersion:
        return await self.versions.create(fields)

    async def get_version_by_id(self, version_id: uuid.UUID) -> PolicyVersion | None:
        return await self.versions.get_by_id(version_id)

    async def update_version(
        self, version: PolicyVersion, data: dict[str, object]
    ) -> PolicyVersion:
        return await self.versions.update(version, data)

    async def list_versions_for_policy(
        self, policy_id: uuid.UUID
    ) -> list[PolicyVersion]:
        return await self.versions.get_all(
            filters={"policy_id": policy_id},
            sort_by="version_number",
            sort_order=SortOrder.ASC,
        )

    async def get_next_version_number(self, policy_id: uuid.UUID) -> int:
        """``MAX(version_number) + 1`` for this policy, or ``1`` if it has no
        versions yet -- a hand-written aggregate ``GenericRepository``'s
        plain filter/sort surface cannot express."""
        result = await self.session.execute(
            select(func.max(PolicyVersion.version_number)).where(
                PolicyVersion.policy_id == policy_id,
                PolicyVersion.is_deleted.is_(False),
            )
        )
        current_max = result.scalar_one_or_none()
        return (current_max or 0) + 1

    # -- assignments -------------------------------------------------------

    async def create_assignment(self, **fields: object) -> PolicyAssignment:
        return await self.assignments.create(fields)

    async def get_assignment_by_id(
        self, assignment_id: uuid.UUID
    ) -> PolicyAssignment | None:
        return await self.assignments.get_by_id(assignment_id)

    async def update_assignment(
        self, assignment: PolicyAssignment, data: dict[str, object]
    ) -> PolicyAssignment:
        return await self.assignments.update(assignment, data)

    async def list_assignments_for_policy(
        self, policy_id: uuid.UUID
    ) -> list[PolicyAssignment]:
        return await self.assignments.get_all(filters={"policy_id": policy_id})

    async def list_candidate_assignments(
        self,
        *,
        policy_type: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        user_id: uuid.UUID | None = None,
        role_ids: list[uuid.UUID] | None = None,
    ) -> list[PolicyAssignment]:
        """Every currently-active ``PolicyAssignment`` whose policy is
        active/of the requested ``policy_type``, whose WHERE scope matches
        global/this organization/this location, AND whose WHO target
        (Enterprise SaaS Phase F) matches untargeted/this user/one of this
        user's roles -- the join ``PolicyResolver.resolve`` needs, which
        ``GenericRepository``'s plain per-table equality/IN filters cannot
        express (it spans two tables and an OR across scope AND target
        shapes)."""
        scope_conditions = [PolicyAssignment.scope_type == ScopeType.GLOBAL.value]
        if organization_id is not None:
            scope_conditions.append(
                (PolicyAssignment.scope_type == ScopeType.ORGANIZATION.value)
                & (PolicyAssignment.scope_id == organization_id)
            )
        if location_id is not None:
            scope_conditions.append(
                (PolicyAssignment.scope_type == ScopeType.LOCATION.value)
                & (PolicyAssignment.scope_id == location_id)
            )
        target_conditions = [
            PolicyAssignment.target_type == PolicyAssignmentTargetType.NONE.value
        ]
        if user_id is not None:
            target_conditions.append(
                (PolicyAssignment.target_type == PolicyAssignmentTargetType.USER.value)
                & (PolicyAssignment.target_id == user_id)
            )
        if role_ids:
            target_conditions.append(
                (PolicyAssignment.target_type == PolicyAssignmentTargetType.ROLE.value)
                & (PolicyAssignment.target_id.in_(role_ids))
            )
        stmt = (
            select(PolicyAssignment)
            .join(Policy, Policy.id == PolicyAssignment.policy_id)
            .where(
                PolicyAssignment.is_active.is_(True),
                PolicyAssignment.is_deleted.is_(False),
                Policy.is_active.is_(True),
                Policy.is_deleted.is_(False),
                Policy.policy_type == policy_type,
                Policy.current_version_id.is_not(None),
                or_(*scope_conditions),
                or_(*target_conditions),
            )
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


__all__ = ["PolicyRepositoryProtocol", "PolicyRepository"]
