"""Reads and writes for the ISP partner domain.

Every query that spans customers takes an explicit, server-computed list of
child organization ids. **An empty list matches nothing** -- there is no
"``None`` means all organizations" form anywhere in this module, and the
helpers below assert it rather than trusting callers.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import and_, case, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.auth.models import User
from app.domains.captive_portal.models import CaptivePortalConfig
from app.domains.guest.models import Guest, GuestSession
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationStatus, OrganizationType
from app.domains.organization.models import Organization, OrganizationMember
from app.domains.rbac.models import Role, UserRole
from app.domains.router.models import Router
from app.domains.tr069.models import Tr069AcsCredential, Tr069Device

from .constants import ISP_ROLE_SLUGS
from .models import IspCustomerProfile, IspPartnerProfile, IspStaffCustomerScope


def require_ids(ids: Sequence[uuid.UUID]) -> list[uuid.UUID]:
    """The child-id list a cross-customer query runs over. Never ``None``."""
    if ids is None:  # pragma: no cover -- defensive; typed as a sequence
        raise ValueError("a cross-customer query needs an explicit id list")
    return list(ids)


class IspRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # -- single rows (IspScope's inputs) ---------------------------------
    async def get_profile(self, organization_id: uuid.UUID) -> IspPartnerProfile | None:
        return (
            await self.session.execute(
                select(IspPartnerProfile).where(
                    IspPartnerProfile.organization_id == organization_id,
                    IspPartnerProfile.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def get_organization(self, organization_id: uuid.UUID) -> Organization | None:
        row = await self.session.get(Organization, organization_id)
        if row is None or row.is_deleted:
            return None
        return row

    async def get_location(self, location_id: uuid.UUID) -> Location | None:
        return await self.session.get(Location, location_id)

    async def get_router(self, router_id: uuid.UUID) -> Router | None:
        return await self.session.get(Router, router_id)

    async def get_portal_config(
        self, config_id: uuid.UUID
    ) -> CaptivePortalConfig | None:
        return await self.session.get(CaptivePortalConfig, config_id)

    async def get_cpe(self, cpe_id: uuid.UUID) -> Tr069Device | None:
        return await self.session.get(Tr069Device, cpe_id)

    async def get_user(self, user_id: uuid.UUID) -> User | None:
        return await self.session.get(User, user_id)

    # -- the caller's ISP context ----------------------------------------
    async def confined_customer_ids(
        self, isp_org_id: uuid.UUID, user_id: uuid.UUID
    ) -> set[uuid.UUID]:
        rows = await self.session.execute(
            select(IspStaffCustomerScope.customer_organization_id).where(
                IspStaffCustomerScope.isp_organization_id == isp_org_id,
                IspStaffCustomerScope.user_id == user_id,
                IspStaffCustomerScope.is_deleted.is_(False),
            )
        )
        return set(rows.scalars().all())

    async def child_ids(self, isp_org_id: uuid.UUID) -> list[uuid.UUID]:
        """Non-archived STANDARD children, ordered by name."""
        rows = await self.session.execute(
            select(Organization.id)
            .where(
                Organization.parent_organization_id == isp_org_id,
                Organization.org_type == OrganizationType.STANDARD.value,
                Organization.is_deleted.is_(False),
                Organization.status != OrganizationStatus.ARCHIVED.value,
            )
            .order_by(Organization.name, Organization.id)
        )
        return list(rows.scalars().all())

    # -- customers -------------------------------------------------------
    async def organizations_by_id(
        self, ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, Organization]:
        ids = require_ids(ids)
        if not ids:
            return {}
        rows = await self.session.execute(
            select(Organization).where(Organization.id.in_(ids))
        )
        return {o.id: o for o in rows.scalars().all()}

    async def customer_profiles(
        self, ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, IspCustomerProfile]:
        ids = require_ids(ids)
        if not ids:
            return {}
        rows = await self.session.execute(
            select(IspCustomerProfile).where(
                IspCustomerProfile.customer_organization_id.in_(ids),
                IspCustomerProfile.is_deleted.is_(False),
            )
        )
        return {p.customer_organization_id: p for p in rows.scalars().all()}

    async def list_customers(
        self,
        ids: Sequence[uuid.UUID],
        *,
        status: str | None,
        search: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[Organization], int]:
        ids = require_ids(ids)
        if not ids:
            return [], 0
        conditions: list[Any] = [Organization.id.in_(ids)]
        if status:
            conditions.append(Organization.status == status)
        if search:
            pattern = f"%{search.strip()}%"
            conditions.append(
                or_(
                    Organization.name.ilike(pattern),
                    Organization.slug.ilike(pattern),
                    Organization.contact_email.ilike(pattern),
                    Organization.id.in_(
                        select(IspCustomerProfile.customer_organization_id).where(
                            IspCustomerProfile.external_ref.ilike(pattern)
                        )
                    ),
                )
            )
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(Organization).where(*conditions)
                )
            ).scalar_one()
        )
        rows = await self.session.execute(
            select(Organization)
            .where(*conditions)
            .order_by(Organization.name, Organization.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return list(rows.scalars().all()), total

    async def count_customers(self, isp_org_id: uuid.UUID) -> int:
        return len(await self.child_ids(isp_org_id))

    async def external_ref_taken(
        self,
        isp_org_id: uuid.UUID,
        external_ref: str,
        *,
        except_customer_id: uuid.UUID | None = None,
    ) -> bool:
        conditions = [
            IspCustomerProfile.isp_organization_id == isp_org_id,
            IspCustomerProfile.external_ref == external_ref,
            IspCustomerProfile.deleted_at.is_(None),
        ]
        if except_customer_id is not None:
            conditions.append(
                IspCustomerProfile.customer_organization_id != except_customer_id
            )
        found = await self.session.execute(
            select(IspCustomerProfile.id).where(*conditions).limit(1)
        )
        return found.first() is not None

    async def add(self, row: Any) -> Any:
        self.session.add(row)
        await self.session.flush()
        return row

    async def flush(self) -> None:
        await self.session.flush()

    # -- locations / routers ---------------------------------------------
    async def list_locations(
        self,
        ids: Sequence[uuid.UUID],
        *,
        status: str | None,
        search: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[Location], int]:
        ids = require_ids(ids)
        if not ids:
            return [], 0
        conditions: list[Any] = [
            Location.organization_id.in_(ids),
            Location.is_deleted.is_(False),
        ]
        if status:
            conditions.append(Location.status == status)
        if search:
            pattern = f"%{search.strip()}%"
            conditions.append(
                or_(
                    Location.name.ilike(pattern),
                    Location.city.ilike(pattern),
                    Location.location_code.ilike(pattern),
                )
            )
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(Location).where(*conditions)
                )
            ).scalar_one()
        )
        rows = await self.session.execute(
            select(Location)
            .where(*conditions)
            .order_by(Location.name, Location.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return list(rows.scalars().all()), total

    async def list_routers(
        self,
        ids: Sequence[uuid.UUID],
        *,
        location_id: uuid.UUID | None,
        status: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[Router], int]:
        ids = require_ids(ids)
        if not ids:
            return [], 0
        conditions: list[Any] = [
            Router.organization_id.in_(ids),
            Router.is_deleted.is_(False),
        ]
        if location_id is not None:
            conditions.append(Router.location_id == location_id)
        if status:
            conditions.append(Router.status == status)
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(Router).where(*conditions)
                )
            ).scalar_one()
        )
        rows = await self.session.execute(
            select(Router)
            .where(*conditions)
            .order_by(Router.name, Router.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return list(rows.scalars().all()), total

    async def routers_for_organizations(self, ids: Sequence[uuid.UUID]) -> list[Router]:
        ids = require_ids(ids)
        if not ids:
            return []
        rows = await self.session.execute(
            select(Router).where(
                Router.organization_id.in_(ids), Router.is_deleted.is_(False)
            )
        )
        return list(rows.scalars().all())

    async def locations_for_organizations(
        self, ids: Sequence[uuid.UUID]
    ) -> list[Location]:
        ids = require_ids(ids)
        if not ids:
            return []
        rows = await self.session.execute(
            select(Location).where(
                Location.organization_id.in_(ids), Location.is_deleted.is_(False)
            )
        )
        return list(rows.scalars().all())

    async def names(self, model: Any, ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, str]:
        wanted = [i for i in set(ids) if i is not None]
        if not wanted:
            return {}
        rows = await self.session.execute(
            select(model.id, model.name).where(model.id.in_(wanted))
        )
        return {r[0]: r[1] for r in rows.all()}

    # -- CPEs ------------------------------------------------------------
    async def cpes_for_isp(self, isp_org_id: uuid.UUID) -> list[Tr069Device]:
        rows = await self.session.execute(
            select(Tr069Device).where(
                Tr069Device.isp_organization_id == isp_org_id,
                Tr069Device.is_deleted.is_(False),
            )
        )
        return list(rows.scalars().all())

    async def credentials_for_isp(
        self, isp_org_id: uuid.UUID
    ) -> list[Tr069AcsCredential]:
        rows = await self.session.execute(
            select(Tr069AcsCredential).where(
                Tr069AcsCredential.isp_organization_id == isp_org_id,
                Tr069AcsCredential.is_deleted.is_(False),
            )
        )
        return list(rows.scalars().all())

    # -- guests / sessions -----------------------------------------------
    async def guests_today(
        self, ids: Sequence[uuid.UUID], *, since: datetime
    ) -> dict[uuid.UUID, tuple[int, int]]:
        """``{org: (distinct guests, bytes)}`` for sessions started since."""
        ids = require_ids(ids)
        if not ids:
            return {}
        rows = await self.session.execute(
            select(
                GuestSession.organization_id,
                func.count(func.distinct(GuestSession.guest_id)),
                func.coalesce(
                    func.sum(
                        GuestSession.bytes_uploaded + GuestSession.bytes_downloaded
                    ),
                    0,
                ),
            )
            .where(
                GuestSession.organization_id.in_(ids),
                GuestSession.started_at >= since,
                GuestSession.is_deleted.is_(False),
            )
            .group_by(GuestSession.organization_id)
        )
        return {r[0]: (int(r[1]), int(r[2])) for r in rows.all()}

    async def distinct_guests_since(
        self, ids: Sequence[uuid.UUID], *, since: datetime
    ) -> int:
        ids = require_ids(ids)
        if not ids:
            return 0
        return int(
            (
                await self.session.execute(
                    select(func.count(func.distinct(GuestSession.guest_id))).where(
                        GuestSession.organization_id.in_(ids),
                        GuestSession.started_at >= since,
                        GuestSession.is_deleted.is_(False),
                    )
                )
            ).scalar_one()
        )

    async def active_sessions(self, ids: Sequence[uuid.UUID]) -> int:
        ids = require_ids(ids)
        if not ids:
            return 0
        return int(
            (
                await self.session.execute(
                    select(func.count()).where(
                        GuestSession.organization_id.in_(ids),
                        GuestSession.status == "active",
                        GuestSession.is_deleted.is_(False),
                    )
                )
            ).scalar_one()
        )

    async def list_guests(
        self,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
        search: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[tuple[Guest, int]], int]:
        conditions: list[Any] = [
            Guest.organization_id == organization_id,
            Guest.is_deleted.is_(False),
        ]
        if location_id is not None:
            conditions.append(Guest.location_id == location_id)
        if search:
            pattern = f"%{search.strip()}%"
            conditions.append(
                or_(
                    Guest.display_name.ilike(pattern),
                    Guest.identifier.ilike(pattern),
                    Guest.email.ilike(pattern),
                )
            )
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(Guest).where(*conditions)
                )
            ).scalar_one()
        )
        session_count = (
            select(func.count())
            .where(
                GuestSession.guest_id == Guest.id,
                GuestSession.organization_id == organization_id,
            )
            .scalar_subquery()
        )
        rows = await self.session.execute(
            select(Guest, session_count)
            .where(*conditions)
            .order_by(Guest.last_seen_at.desc(), Guest.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return [(g, int(c or 0)) for g, c in rows.all()], total

    async def list_sessions(
        self,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
        status: str | None,
        since: datetime | None,
        until: datetime | None,
        page: int,
        page_size: int,
    ) -> tuple[list[tuple[GuestSession, str | None]], int]:
        conditions: list[Any] = [
            GuestSession.organization_id == organization_id,
            GuestSession.is_deleted.is_(False),
        ]
        if location_id is not None:
            conditions.append(GuestSession.location_id == location_id)
        if status == "active":
            conditions.append(GuestSession.status == "active")
        elif status == "ended":
            conditions.append(GuestSession.status != "active")
        if since is not None:
            conditions.append(GuestSession.started_at >= since)
        if until is not None:
            conditions.append(GuestSession.started_at < until)
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(GuestSession).where(*conditions)
                )
            ).scalar_one()
        )
        rows = await self.session.execute(
            select(GuestSession, Guest.display_name)
            .outerjoin(Guest, Guest.id == GuestSession.guest_id)
            .where(*conditions)
            .order_by(GuestSession.started_at.desc(), GuestSession.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return [(s, n) for s, n in rows.all()], total

    # -- staff users -----------------------------------------------------
    async def isp_role_assignments(
        self, isp_org_id: uuid.UUID, *, user_id: uuid.UUID | None = None
    ) -> list[tuple[UserRole, Role]]:
        """Active ``isp-*`` assignments on this ISP org (optionally one user)."""
        conditions: list[Any] = [
            UserRole.organization_id == isp_org_id,
            UserRole.is_active.is_(True),
            UserRole.is_deleted.is_(False),
            Role.slug.in_(sorted(ISP_ROLE_SLUGS)),
            Role.organization_id.is_(None),
        ]
        if user_id is not None:
            conditions.append(UserRole.user_id == user_id)
        rows = await self.session.execute(
            select(UserRole, Role)
            .join(Role, Role.id == UserRole.role_id)
            .where(*conditions)
        )
        return [(a, r) for a, r in rows.all()]

    async def list_staff(
        self,
        isp_org_id: uuid.UUID,
        *,
        search: str | None,
        role: str | None,
        status: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[tuple[User, str]], int]:
        conditions: list[Any] = [
            UserRole.organization_id == isp_org_id,
            UserRole.is_active.is_(True),
            UserRole.is_deleted.is_(False),
            Role.slug.in_(sorted(ISP_ROLE_SLUGS)),
            Role.organization_id.is_(None),
            User.is_deleted.is_(False),
        ]
        if role:
            conditions.append(Role.slug == role)
        if status == "active":
            conditions.append(User.is_active.is_(True))
        elif status == "disabled":
            conditions.append(User.is_active.is_(False))
        if search:
            pattern = f"%{search.strip()}%"
            conditions.append(
                or_(
                    User.email.ilike(pattern),
                    User.first_name.ilike(pattern),
                    User.last_name.ilike(pattern),
                    User.username.ilike(pattern),
                )
            )
        base = (
            select(User, Role.slug)
            .join(UserRole, UserRole.user_id == User.id)
            .join(Role, Role.id == UserRole.role_id)
            .where(*conditions)
        )
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(base.subquery())
                )
            ).scalar_one()
        )
        rows = await self.session.execute(
            base.order_by(User.first_name, User.last_name, User.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return [(u, s) for u, s in rows.all()], total

    async def count_active_owners(self, isp_org_id: uuid.UUID) -> int:
        return int(
            (
                await self.session.execute(
                    select(func.count(func.distinct(UserRole.user_id)))
                    .join(Role, Role.id == UserRole.role_id)
                    .join(User, User.id == UserRole.user_id)
                    .where(
                        UserRole.organization_id == isp_org_id,
                        UserRole.is_active.is_(True),
                        UserRole.is_deleted.is_(False),
                        Role.slug == "isp-owner",
                        Role.organization_id.is_(None),
                        User.is_active.is_(True),
                    )
                )
            ).scalar_one()
        )

    async def is_member(self, organization_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        found = await self.session.execute(
            select(OrganizationMember.id)
            .where(
                OrganizationMember.organization_id == organization_id,
                OrganizationMember.user_id == user_id,
                OrganizationMember.status == "active",
            )
            .limit(1)
        )
        return found.first() is not None

    async def scopes_for_users(
        self, isp_org_id: uuid.UUID, user_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, list[uuid.UUID]]:
        if not user_ids:
            return {}
        rows = await self.session.execute(
            select(
                IspStaffCustomerScope.user_id,
                IspStaffCustomerScope.customer_organization_id,
            ).where(
                IspStaffCustomerScope.isp_organization_id == isp_org_id,
                IspStaffCustomerScope.user_id.in_(list(user_ids)),
                IspStaffCustomerScope.is_deleted.is_(False),
            )
        )
        out: dict[uuid.UUID, list[uuid.UUID]] = {}
        for uid, cid in rows.all():
            out.setdefault(uid, []).append(cid)
        return out

    async def replace_scopes(
        self,
        isp_org_id: uuid.UUID,
        user_id: uuid.UUID,
        customer_ids: Sequence[uuid.UUID] | None,
        *,
        actor_user_id: uuid.UUID | None,
    ) -> None:
        await self.session.execute(
            delete(IspStaffCustomerScope).where(
                IspStaffCustomerScope.isp_organization_id == isp_org_id,
                IspStaffCustomerScope.user_id == user_id,
            )
        )
        for customer_id in customer_ids or []:
            self.session.add(
                IspStaffCustomerScope(
                    isp_organization_id=isp_org_id,
                    user_id=user_id,
                    customer_organization_id=customer_id,
                    created_by=actor_user_id,
                )
            )
        await self.session.flush()


# Re-exported for callers building their own aggregates.
__all__ = ["IspRepository", "and_", "case", "require_ids"]
