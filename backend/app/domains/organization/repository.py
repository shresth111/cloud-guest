"""Data access layer for the Organization domain.

Mirrors ``app.domains.auth.repository`` / ``app.domains.rbac.repository``'s
shape: a ``Protocol`` describing the operations the service layer needs
(``OrganizationRepositoryProtocol``), and a concrete, ``GenericRepository``
-backed implementation (``OrganizationRepository``). Hand-written queries
are used only where ``GenericRepository``'s equality/IN filters can't
express the need (the MSP "self or child" scoping filter, search-by-ilike,
and the ``parent_organization_id`` ancestry walk for cycle detection).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .models import Organization, OrganizationMember


class OrganizationRepositoryProtocol(Protocol):
    # -- organizations -------------------------------------------------------
    async def get_by_id(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization | None: ...

    async def get_by_slug(self, slug: str) -> Organization | None: ...

    async def create_organization(self, **fields: object) -> Organization: ...

    async def update_organization(
        self, organization: Organization, data: dict[str, object]
    ) -> Organization: ...

    async def soft_delete_organization(
        self, organization: Organization
    ) -> Organization: ...

    async def list_organizations(
        self,
        *,
        page: int,
        page_size: int,
        search: str | None = None,
        status: str | None = None,
        org_type: str | None = None,
        scope_organization_id: uuid.UUID | None = None,
    ) -> tuple[list[Organization], PaginationMeta]: ...

    async def list_children(
        self, parent_organization_id: uuid.UUID
    ) -> list[Organization]: ...

    async def get_parent_chain(
        self, organization_id: uuid.UUID, *, max_depth: int
    ) -> list[Organization]: ...

    # -- membership ------------------------------------------------------------
    async def get_membership(
        self, organization_id: uuid.UUID, user_id: uuid.UUID
    ) -> OrganizationMember | None: ...

    async def get_membership_by_id(
        self, member_id: uuid.UUID
    ) -> OrganizationMember | None: ...

    async def list_members(
        self, organization_id: uuid.UUID, *, status: str | None = None
    ) -> list[OrganizationMember]: ...

    async def list_user_memberships(
        self, user_id: uuid.UUID, *, status: str | None = None
    ) -> list[OrganizationMember]: ...

    async def count_active_members(self, organization_id: uuid.UUID) -> int: ...

    async def create_membership(self, **fields: object) -> OrganizationMember: ...

    async def update_membership(
        self, member: OrganizationMember, data: dict[str, object]
    ) -> OrganizationMember: ...


class OrganizationRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``OrganizationRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.organizations = GenericRepository(Organization, session)
        self.members = GenericRepository(OrganizationMember, session)

    # -- organizations -------------------------------------------------------

    async def get_by_id(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization | None:
        return await self.organizations.get_by_id(
            organization_id, include_deleted=include_deleted
        )

    async def get_by_slug(self, slug: str) -> Organization | None:
        results = await self.organizations.get_all(filters={"slug": slug}, limit=1)
        return results[0] if results else None

    async def create_organization(self, **fields: object) -> Organization:
        return await self.organizations.create(fields)

    async def update_organization(
        self, organization: Organization, data: dict[str, object]
    ) -> Organization:
        return await self.organizations.update(organization, data)

    async def soft_delete_organization(
        self, organization: Organization
    ) -> Organization:
        return await self.organizations.soft_delete(organization)

    async def list_organizations(
        self,
        *,
        page: int,
        page_size: int,
        search: str | None = None,
        status: str | None = None,
        org_type: str | None = None,
        scope_organization_id: uuid.UUID | None = None,
    ) -> tuple[list[Organization], PaginationMeta]:
        params = PageParams(page=page, page_size=page_size)
        conditions = [Organization.is_deleted.is_(False)]
        if status is not None:
            conditions.append(Organization.status == status)
        if org_type is not None:
            conditions.append(Organization.org_type == org_type)
        if search:
            like = f"%{search}%"
            conditions.append(
                or_(Organization.name.ilike(like), Organization.slug.ilike(like))
            )
        if scope_organization_id is not None:
            conditions.append(
                or_(
                    Organization.id == scope_organization_id,
                    Organization.parent_organization_id == scope_organization_id,
                )
            )

        count_statement = (
            select(func.count()).select_from(Organization).where(*conditions)
        )
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        statement = (
            select(Organization)
            .where(*conditions)
            .order_by(Organization.created_at.desc())
        )
        result = await self.session.execute(paginate(statement, params))
        rows = list(result.scalars().all())
        return rows, PaginationMeta.from_total(params, total_items)

    async def list_children(
        self, parent_organization_id: uuid.UUID
    ) -> list[Organization]:
        return await self.organizations.get_all(
            filters={"parent_organization_id": parent_organization_id},
            sort_by="name",
            sort_order=SortOrder.ASC,
        )

    async def get_parent_chain(
        self, organization_id: uuid.UUID, *, max_depth: int
    ) -> list[Organization]:
        """Walk ``parent_organization_id`` upward, stopping at ``max_depth``
        as a defensive backstop (cycles are rejected at write time by the
        service layer, but this guards against any that slip through)."""
        chain: list[Organization] = []
        seen: set[uuid.UUID] = {organization_id}
        current = await self.get_by_id(organization_id)
        depth = 0
        while (
            current is not None and current.parent_organization_id and depth < max_depth
        ):
            parent = await self.get_by_id(current.parent_organization_id)
            if parent is None or parent.id in seen:
                break
            chain.append(parent)
            seen.add(parent.id)
            current = parent
            depth += 1
        return chain

    # -- membership ------------------------------------------------------------

    async def get_membership(
        self, organization_id: uuid.UUID, user_id: uuid.UUID
    ) -> OrganizationMember | None:
        results = await self.members.get_all(
            filters={"organization_id": organization_id, "user_id": user_id},
            sort_by="created_at",
            sort_order=SortOrder.DESC,
            limit=1,
        )
        return results[0] if results else None

    async def get_membership_by_id(
        self, member_id: uuid.UUID
    ) -> OrganizationMember | None:
        return await self.members.get_by_id(member_id)

    async def list_members(
        self, organization_id: uuid.UUID, *, status: str | None = None
    ) -> list[OrganizationMember]:
        filters: dict[str, object] = {"organization_id": organization_id}
        if status is not None:
            filters["status"] = status
        return await self.members.get_all(
            filters=filters, sort_by="created_at", sort_order=SortOrder.DESC
        )

    async def list_user_memberships(
        self, user_id: uuid.UUID, *, status: str | None = None
    ) -> list[OrganizationMember]:
        filters: dict[str, object] = {"user_id": user_id}
        if status is not None:
            filters["status"] = status
        return await self.members.get_all(
            filters=filters, sort_by="created_at", sort_order=SortOrder.DESC
        )

    async def count_active_members(self, organization_id: uuid.UUID) -> int:
        return await self.members.count(
            filters={"organization_id": organization_id, "status": "active"}
        )

    async def create_membership(self, **fields: object) -> OrganizationMember:
        return await self.members.create(fields)

    async def update_membership(
        self, member: OrganizationMember, data: dict[str, object]
    ) -> OrganizationMember:
        return await self.members.update(member, data)
