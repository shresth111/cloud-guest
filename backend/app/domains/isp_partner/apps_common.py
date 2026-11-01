"""Shared pieces of the J16 Apps lane: the flag, the enums, the errors, and
the three lookups every Apps route needs (subscriber, assignee, counter).

The flag ``ISP_APPS_ENABLED`` (default OFF) sits on top of
``ISP_PARTNER_ENABLED``: while either is off, every ``/isp/apps`` route is a
plain 404.
"""

from __future__ import annotations

import uuid
from enum import StrEnum
from functools import lru_cache
from typing import Any

from fastapi import HTTPException, status
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from .apps_models import IspAppsCounter
from .constants import ISP_ROLE_SLUGS, UNCONFINABLE_ROLES
from .exceptions import IspError
from .plans_models import IspSubscriber
from .scoping import IspScope

# -- flag ----------------------------------------------------------------------


class IspAppsSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_APPS_", case_sensitive=False, extra="ignore"
    )

    enabled: bool = Field(default=False, description="ISP_APPS_ENABLED")


@lru_cache(maxsize=1)
def get_isp_apps_settings() -> IspAppsSettings:
    return IspAppsSettings()


async def RequireIspAppsEnabled() -> None:
    if not get_isp_apps_settings().enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


# -- permission keys -----------------------------------------------------------
APPS_READ = "isp_apps.read"
APPS_CREATE = "isp_apps.create"
APPS_UPDATE = "isp_apps.update"
APPS_MANAGE = "isp_apps.manage"
APPS_EXPORT = "isp_apps.export"


# -- enums ---------------------------------------------------------------------
class TicketStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    ON_HOLD = "on_hold"
    RESOLVED = "resolved"
    CLOSED = "closed"


OPEN_TICKET_STATUSES = frozenset(
    {TicketStatus.OPEN, TicketStatus.IN_PROGRESS, TicketStatus.ON_HOLD}
)
DONE_TICKET_STATUSES = frozenset({TicketStatus.RESOLVED, TicketStatus.CLOSED})


class TicketSource(StrEnum):
    PHONE = "phone"
    WHATSAPP = "whatsapp"
    WALK_IN = "walk_in"
    EMAIL = "email"
    PORTAL = "portal"
    FIELD = "field"
    OTHER = "other"


class TicketPriority(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class RfoReason(StrEnum):
    """Reason for outage, recorded when a ticket is resolved."""

    FIBER_CUT = "fiber_cut"
    POWER_OLT = "power_olt"
    CPE_FAULT = "cpe_fault"
    UPSTREAM = "upstream"
    OTHER = "other"


class TaskKind(StrEnum):
    INSTALL = "install"
    REPAIR = "repair"
    SURVEY = "survey"
    REMOVAL = "removal"
    OTHER = "other"


class TaskStatus(StrEnum):
    UNCLAIMED = "unclaimed"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class UnitState(StrEnum):
    IN_STOCK = "in_stock"
    ASSIGNED = "assigned"
    RETURNED = "returned"
    FAULTY = "faulty"
    RETIRED = "retired"


class ItemCategory(StrEnum):
    ONT = "ont"
    ROUTER = "router"
    CPE = "cpe"
    AP = "ap"
    SWITCH = "switch"
    OTHER = "other"


class LeadStatus(StrEnum):
    NEW = "new"
    CONTACTED = "contacted"
    FEASIBILITY_PENDING = "feasibility_pending"
    FEASIBLE = "feasible"
    NOT_FEASIBLE = "not_feasible"
    INSTALL_SCHEDULED = "install_scheduled"
    CONVERTED = "converted"
    DROPPED = "dropped"


class LeadSource(StrEnum):
    WALK_IN = "walk_in"
    PHONE = "phone"
    WEBSITE = "website"
    REFERRAL = "referral"
    CAMPAIGN = "campaign"
    OTHER = "other"


class IspAppsEventType(StrEnum):
    """Notification-outbox event type for announcements. The outbox stores
    the string; unknown values route to the default mail identity."""

    ANNOUNCEMENT = "isp_announcement"


def pattern(values: type[StrEnum]) -> str:
    return "^(" + "|".join(v.value for v in values) + ")$"


# -- errors --------------------------------------------------------------------
class IspAppsNotFoundError(IspError):
    code = "ISP_APPS_NOT_FOUND"
    status_code_default = status.HTTP_404_NOT_FOUND
    default_message = "Not found"


class IspAppsInvalidError(IspError):
    code = "ISP_APPS_INVALID"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "That change is not allowed"


class IspAppsConflictError(IspError):
    code = "ISP_APPS_CONFLICT"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "That already exists"


class IspDiscountInvalidError(IspError):
    code = "ISP_DISCOUNT_INVALID"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "This discount code cannot be used"


# -- lookups -------------------------------------------------------------------


async def next_number(session: Any, isp_org_id: uuid.UUID, kind: str) -> int:
    stmt = (
        insert(IspAppsCounter)
        .values(id=uuid.uuid4(), isp_organization_id=isp_org_id, kind=kind, value=1)
        .on_conflict_do_update(
            index_elements=["isp_organization_id", "kind"],
            set_={"value": IspAppsCounter.value + 1},
        )
        .returning(IspAppsCounter.value)
    )
    return int((await session.execute(stmt)).scalar_one())


def fmt_number(prefix: str, n: int) -> str:
    return f"{prefix}-{n:06d}"


async def resolve_subscriber(
    isp: Any,
    session: Any,
    subscriber_id: uuid.UUID,
    *,
    customer_id: uuid.UUID | None = None,
) -> IspSubscriber:
    """The subscriber, if it is this ISP's and its customer is visible to the
    caller (and matches ``customer_id`` when given). Otherwise 404."""
    sub = await session.get(IspSubscriber, subscriber_id)
    if (
        sub is None
        or getattr(sub, "is_deleted", False)
        or sub.isp_organization_id != isp.isp_org_id
        or (customer_id is not None and sub.customer_organization_id != customer_id)
    ):
        raise IspAppsNotFoundError("Subscriber not found")
    await IspScope.assert_customer(isp, sub.customer_organization_id)
    return sub


async def assert_assignee(
    isp: Any, user_id: uuid.UUID, *, customer_id: uuid.UUID | None
) -> None:
    """``user_id`` must hold an active isp-* role on this ISP. A confined
    staff member may only take work for a customer they cover; customer-less
    work (a prospect's survey) goes to unconfined staff only."""
    rows = await isp.repository.isp_role_assignments(isp.isp_org_id, user_id=user_id)
    roles = [r for _a, r in rows if r.slug in ISP_ROLE_SLUGS]
    if not roles:
        raise IspAppsInvalidError("The assignee is not a staff member of this ISP")
    if any(r.slug in UNCONFINABLE_ROLES for r in roles):
        return
    scope = await isp.repository.confined_customer_ids(isp.isp_org_id, user_id)
    if not scope:
        return  # an unconfined noc/technician/billing/viewer
    if customer_id is None or customer_id not in set(scope):
        raise IspAppsInvalidError("The assignee does not cover this customer")


async def visible_customer_filter(
    isp: Any, isp_customer_id: uuid.UUID | None
) -> list[uuid.UUID]:
    """The customer ids a list may show: one (checked) or all visible ones.
    An empty list means "nothing", never "everything"."""
    if isp_customer_id is not None:
        await IspScope.assert_customer(isp, isp_customer_id)
        return [isp_customer_id]
    return await isp.child_ids()


async def user_names(session: Any, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    from app.domains.auth.models import User

    ids = {i for i in ids if i}
    if not ids:
        return {}
    rows = await session.execute(
        select(User.id, User.first_name, User.last_name, User.email).where(
            User.id.in_(ids)
        )
    )
    out: dict[uuid.UUID, str] = {}
    for uid, first, last, email in rows.all():
        name = " ".join(p for p in (first, last) if p).strip()
        out[uid] = name or (email or "")
    return out


async def org_names(session: Any, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    from app.domains.organization.models import Organization

    ids = {i for i in ids if i}
    if not ids:
        return {}
    rows = await session.execute(
        select(Organization.id, Organization.name).where(Organization.id.in_(ids))
    )
    return dict(rows.all())


def subscriber_label(sub: Any) -> str:
    name = " ".join(p for p in (sub.first_name, sub.last_name) if p).strip()
    return name or sub.display_name or sub.identifier
