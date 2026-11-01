"""NetLogs across an ISP's customers.

Reuses ``device_logs.repository.customer_conditions`` -- the exact predicates
the customer NetLogs page applies -- and swaps exactly one of them: the
single-organization equality becomes ``organization_id = ANY(:child_ids)``.
Everything else (``organization_id IS NOT NULL``, the tag-mismatch
exclusion, the mandatory ``received_at`` window that keeps partition pruning,
the keyset cursor) is the same expression object the customer page uses.
``device_logs`` itself is not edited.

``isp_conditions`` refuses to run if the first predicate is ever not the
organization equality it expects, so a future change to
``customer_conditions`` fails loudly here instead of silently widening.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.sql import operators
from sqlalchemy.sql.elements import BinaryExpression

from app.domains.device_logs.models import DeviceLogEvent
from app.domains.device_logs.repository import (
    CustomerFilters,
    CustomerLogsRepository,
    customer_conditions,
)
from app.domains.location.models import Location
from app.domains.router.models import Router


class IspConditionsDriftError(RuntimeError):
    pass


def isp_conditions(
    filters: CustomerFilters, organization_ids: Sequence[uuid.UUID]
) -> list[Any]:
    ids = list(organization_ids)
    if not ids:
        raise ValueError("an ISP NetLogs query needs at least one customer id")
    conditions = customer_conditions(filters)
    first = conditions[0]
    if not (
        isinstance(first, BinaryExpression)
        and first.operator is operators.eq
        and getattr(first.left, "key", None) == "organization_id"
        and getattr(first.left, "table", None) is DeviceLogEvent.__table__
    ):
        raise IspConditionsDriftError(
            "device_logs.customer_conditions no longer starts with the "
            "organization equality; review isp_partner.logs_repository"
        )
    return [DeviceLogEvent.organization_id.in_(ids), *conditions[1:]]


class IspLogsRepository(CustomerLogsRepository):
    """``CustomerLogsRepository`` whose three read queries run over a list
    of customer organizations. Plugged into the unchanged
    ``NetLogsCustomerService`` so the summary formatting is reused as-is."""

    def __init__(self, session: Any, organization_ids: Sequence[uuid.UUID]) -> None:
        super().__init__(session)
        self.organization_ids = list(organization_ids)

    async def list_events(
        self, filters: CustomerFilters, *, limit: int
    ) -> list[dict[str, Any]]:
        if not self.organization_ids:
            return []
        stmt = (
            select(
                DeviceLogEvent,
                Router.name.label("router_name"),
                Location.name.label("location_name"),
            )
            .outerjoin(Router, Router.id == DeviceLogEvent.router_id)
            .outerjoin(Location, Location.id == DeviceLogEvent.location_id)
            .where(*isp_conditions(filters, self.organization_ids))
            .order_by(DeviceLogEvent.received_at.desc(), DeviceLogEvent.id.desc())
            .limit(limit)
        )
        return [
            {"event": e, "router_name": rn, "location_name": ln}
            for e, rn, ln in (await self.session.execute(stmt)).all()
        ]

    async def summary_buckets(
        self, filters: CustomerFilters, *, tz: str
    ) -> list[tuple[Any, str, int | None, int]]:
        if not self.organization_ids:
            return []
        day = func.date(func.timezone(tz, DeviceLogEvent.received_at)).label("day")
        category = func.coalesce(DeviceLogEvent.category, "other").label("category")
        stmt = (
            select(day, category, DeviceLogEvent.severity, func.count())
            .where(*isp_conditions(filters, self.organization_ids))
            .group_by(day, category, DeviceLogEvent.severity)
        )
        return [tuple(r) for r in (await self.session.execute(stmt)).all()]  # type: ignore[misc]

    async def top_routers(
        self, filters: CustomerFilters, *, limit: int
    ) -> list[tuple[Any, ...]]:
        if not self.organization_ids:
            return []
        errors = func.count().filter(DeviceLogEvent.severity <= 3)
        warnings = func.count().filter(DeviceLogEvent.severity == 4)
        total = func.count()
        stmt = (
            select(
                DeviceLogEvent.router_id,
                Router.name,
                Router.location_id,
                Location.name,
                total,
                errors,
                warnings,
            )
            .join(Router, Router.id == DeviceLogEvent.router_id)
            .outerjoin(Location, Location.id == Router.location_id)
            .where(
                *isp_conditions(filters, self.organization_ids),
                DeviceLogEvent.router_id.is_not(None),
            )
            .group_by(
                DeviceLogEvent.router_id, Router.name, Router.location_id, Location.name
            )
            .order_by(total.desc(), DeviceLogEvent.router_id)
            .limit(limit)
        )
        return [tuple(r) for r in (await self.session.execute(stmt)).all()]

    async def by_customer(self, filters: CustomerFilters) -> list[tuple[Any, ...]]:
        """(organization id, total, errors, warnings)."""
        if not self.organization_ids:
            return []
        stmt = (
            select(
                DeviceLogEvent.organization_id,
                func.count(),
                func.count().filter(DeviceLogEvent.severity <= 3),
                func.count().filter(DeviceLogEvent.severity == 4),
            )
            .where(*isp_conditions(filters, self.organization_ids))
            .group_by(DeviceLogEvent.organization_id)
        )
        return [tuple(r) for r in (await self.session.execute(stmt)).all()]
