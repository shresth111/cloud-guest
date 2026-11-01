"""Read/aggregate queries for the Master ISP-partner endpoints.

Platform scope by definition: these count across tenants, and the GLOBAL
permission pin on every route (``platform_router``) is the whole access
control. Nothing here is reachable from ``/isp``.
"""

from __future__ import annotations

import math
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import case, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.auth.models import User
from app.domains.billing.models import Plan
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationStatus, OrganizationType
from app.domains.organization.models import Organization
from app.domains.rbac.models import AuditLogEntry, Role, UserRole
from app.domains.router.models import Router
from app.domains.tr069.models import Tr069AcsCredential, Tr069Device

from .constants import ISP_ROLE_SLUGS, IspRole
from .models import IspPartnerProfile

#: CPE online rule, API_CONTRACT §5:
#: last_inform_at > now - (2 * (periodic_inform_interval_s or 300) + 60) s
_DEFAULT_INFORM_S = 300

AUDIT_ENTITY_ISP_PARTNER = "isp_partner"


@dataclass
class Counts:
    customers: int = 0
    customers_suspended: int = 0
    locations: int = 0
    routers_total: int = 0
    routers_online: int = 0
    cpes_total: int = 0
    cpes_online: int = 0
    users: int = 0


@dataclass
class OwnerRow:
    user_id: uuid.UUID
    name: str
    email: str
    is_active: bool


@dataclass
class PartnerPage:
    rows: list[tuple[IspPartnerProfile, Organization]]
    total: int
    page: int
    page_size: int

    @property
    def pages(self) -> int:
        return math.ceil(self.total / self.page_size) if self.page_size else 0


@dataclass
class PartnerBundle:
    profile: IspPartnerProfile
    organization: Organization
    counts: Counts = field(default_factory=Counts)
    plan_name: str | None = None


def _children_of(isp_ids: Sequence[uuid.UUID]):
    return select(Organization.id, Organization.parent_organization_id).where(
        Organization.parent_organization_id.in_(list(isp_ids)),
        Organization.org_type == OrganizationType.STANDARD.value,
        Organization.is_deleted.is_(False),
        Organization.status != OrganizationStatus.ARCHIVED.value,
    )


class IspPlatformRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # -- one partner ------------------------------------------------------
    async def get(
        self, isp_org_id: uuid.UUID
    ) -> tuple[IspPartnerProfile, Organization] | None:
        row = (
            await self.session.execute(
                select(IspPartnerProfile, Organization)
                .join(
                    Organization, Organization.id == IspPartnerProfile.organization_id
                )
                .where(
                    IspPartnerProfile.organization_id == isp_org_id,
                    IspPartnerProfile.is_deleted.is_(False),
                    Organization.is_deleted.is_(False),
                )
            )
        ).first()
        return (row[0], row[1]) if row else None

    # -- list -------------------------------------------------------------
    async def list(
        self, *, page: int, page_size: int, status: str | None, search: str | None
    ) -> PartnerPage:
        conditions = [
            IspPartnerProfile.is_deleted.is_(False),
            Organization.is_deleted.is_(False),
        ]
        if status:
            conditions.append(IspPartnerProfile.status == status)
        if search and search.strip():
            like = f"%{search.strip().lower()}%"
            conditions.append(
                or_(
                    func.lower(Organization.name).like(like),
                    Organization.slug.like(like),
                )
            )
        base = (
            select(IspPartnerProfile, Organization)
            .join(Organization, Organization.id == IspPartnerProfile.organization_id)
            .where(*conditions)
        )
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(base.subquery())
                )
            ).scalar_one()
        )
        rows = (
            await self.session.execute(
                base.order_by(Organization.name, Organization.id)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
        return PartnerPage(
            rows=[(p, o) for p, o in rows], total=total, page=page, page_size=page_size
        )

    # -- aggregates (batched over the page) -------------------------------
    async def counts(self, isp_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, Counts]:
        ids = list(dict.fromkeys(isp_ids))
        out: dict[uuid.UUID, Counts] = {i: Counts() for i in ids}
        if not ids:
            return out

        children = _children_of(ids).subquery()

        for parent, total, suspended in (
            await self.session.execute(
                select(
                    Organization.parent_organization_id,
                    func.count(Organization.id),
                    func.sum(
                        case(
                            (
                                Organization.status
                                == OrganizationStatus.SUSPENDED.value,
                                1,
                            ),
                            else_=0,
                        )
                    ),
                )
                .where(Organization.id.in_(select(children.c.id)))
                .group_by(Organization.parent_organization_id)
            )
        ).all():
            out[parent].customers = int(total or 0)
            out[parent].customers_suspended = int(suspended or 0)

        for parent, total in (
            await self.session.execute(
                select(children.c.parent_organization_id, func.count(Location.id))
                .join(Location, Location.organization_id == children.c.id)
                .where(Location.is_deleted.is_(False))
                .group_by(children.c.parent_organization_id)
            )
        ).all():
            out[parent].locations = int(total or 0)

        for parent, total, online in (
            await self.session.execute(
                select(
                    children.c.parent_organization_id,
                    func.count(Router.id),
                    func.sum(case((Router.status == "online", 1), else_=0)),
                )
                .join(Router, Router.organization_id == children.c.id)
                .where(Router.is_deleted.is_(False))
                .group_by(children.c.parent_organization_id)
            )
        ).all():
            out[parent].routers_total = int(total or 0)
            out[parent].routers_online = int(online or 0)

        interval = func.coalesce(
            Tr069Device.periodic_inform_interval_s, _DEFAULT_INFORM_S
        )
        online_cpe = Tr069Device.last_inform_at > (
            func.now() - func.make_interval(0, 0, 0, 0, 0, 0, 2 * interval + 60)
        )
        for isp, total, online in (
            await self.session.execute(
                select(
                    Tr069Device.isp_organization_id,
                    func.count(Tr069Device.id),
                    func.sum(case((online_cpe, 1), else_=0)),
                )
                .where(
                    Tr069Device.isp_organization_id.in_(ids),
                    Tr069Device.is_deleted.is_(False),
                )
                .group_by(Tr069Device.isp_organization_id)
            )
        ).all():
            out[isp].cpes_total = int(total or 0)
            out[isp].cpes_online = int(online or 0)

        for isp, total in (
            await self.session.execute(
                select(
                    UserRole.organization_id,
                    func.count(func.distinct(UserRole.user_id)),
                )
                .join(Role, Role.id == UserRole.role_id)
                .where(
                    UserRole.organization_id.in_(ids),
                    UserRole.is_active.is_(True),
                    UserRole.is_deleted.is_(False),
                    Role.slug.in_(sorted(ISP_ROLE_SLUGS)),
                    Role.organization_id.is_(None),
                )
                .group_by(UserRole.organization_id)
            )
        ).all():
            out[isp].users = int(total or 0)
        return out

    async def plan_names(self, plan_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, str]:
        ids = list({p for p in plan_ids if p is not None})
        if not ids:
            return {}
        rows = await self.session.execute(
            select(Plan.id, Plan.name).where(Plan.id.in_(ids))
        )
        return {pid: name for pid, name in rows.all()}

    async def owners(self, isp_org_id: uuid.UUID) -> list[OwnerRow]:
        rows = await self.session.execute(
            select(User)
            .join(UserRole, UserRole.user_id == User.id)
            .join(Role, Role.id == UserRole.role_id)
            .where(
                UserRole.organization_id == isp_org_id,
                UserRole.is_active.is_(True),
                UserRole.is_deleted.is_(False),
                Role.slug == IspRole.OWNER.value,
                Role.organization_id.is_(None),
            )
            .order_by(User.created_at)
        )
        seen: dict[uuid.UUID, OwnerRow] = {}
        for user in rows.scalars().all():
            seen.setdefault(
                user.id,
                OwnerRow(
                    user_id=user.id,
                    name=f"{user.first_name or ''} {user.last_name or ''}".strip()
                    or user.email,
                    email=user.email,
                    is_active=bool(user.is_active),
                ),
            )
        return list(seen.values())

    async def isp_credential(self, isp_org_id: uuid.UUID) -> Tr069AcsCredential | None:
        return (
            await self.session.execute(
                select(Tr069AcsCredential).where(
                    Tr069AcsCredential.isp_organization_id == isp_org_id,
                    Tr069AcsCredential.customer_organization_id.is_(None),
                    Tr069AcsCredential.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    # -- suspension of ACS credentials ------------------------------------
    async def enabled_credential_ids(self, isp_org_id: uuid.UUID) -> list[uuid.UUID]:
        rows = await self.session.execute(
            select(Tr069AcsCredential.id).where(
                Tr069AcsCredential.isp_organization_id == isp_org_id,
                Tr069AcsCredential.enabled.is_(True),
                Tr069AcsCredential.is_deleted.is_(False),
            )
        )
        return list(rows.scalars().all())

    async def set_credentials_enabled(
        self,
        isp_org_id: uuid.UUID,
        credential_ids: Sequence[uuid.UUID],
        enabled: bool,
        *,
        actor_user_id: uuid.UUID | None,
    ) -> int:
        ids = list(credential_ids)
        if not ids:
            return 0
        result = await self.session.execute(
            update(Tr069AcsCredential)
            .where(
                Tr069AcsCredential.id.in_(ids),
                # never touches another ISP's rows, whatever ids came in
                Tr069AcsCredential.isp_organization_id == isp_org_id,
            )
            .values(enabled=enabled, updated_by=actor_user_id)
            .execution_options(synchronize_session=False)
        )
        return int(result.rowcount or 0)

    async def last_suspension_metadata(self, isp_org_id: uuid.UUID) -> dict | None:
        row = (
            await self.session.execute(
                select(AuditLogEntry.event_metadata)
                .where(
                    AuditLogEntry.entity_type == AUDIT_ENTITY_ISP_PARTNER,
                    AuditLogEntry.entity_id == isp_org_id,
                    AuditLogEntry.action == "isp_partner_suspended",
                )
                .order_by(AuditLogEntry.created_at.desc())
                .limit(1)
            )
        ).first()
        return dict(row[0] or {}) if row else None


__all__ = [
    "AUDIT_ENTITY_ISP_PARTNER",
    "Counts",
    "IspPlatformRepository",
    "OwnerRow",
    "PartnerBundle",
    "PartnerPage",
]
