"""Data access layer for the Billing domain.

Three ``Protocol``/concrete-implementation pairs, mirroring
``app.domains.otp.repository``'s shape: ``PlanRepositoryProtocol``/
``PlanRepository``, ``LicenseRepositoryProtocol``/``LicenseRepository``, and
``UsageRepositoryProtocol``/``UsageRepository``. Every one of this module's
own tables is ``GenericRepository``-backed; hand-written ``select``
statements are used only for (a) shapes ``GenericRepository``'s
equality-only filter support cannot express (a channel-grouped, date-ranged
count) and (b) this module's own cross-domain usage-composition reads.

## Reading other domains' tables directly -- composition, not duplication

``UsageRepository.count_locations``/``count_routers``/
``count_otp_requests_by_channel`` query another domain's *model* directly
(read-only ``SELECT``s), never that domain's service or repository layer.
This is the exact same precedent ``app.domains.analytics.repository``'s own
module docstring already established (itself following
``app.domains.monitoring.repository``'s identical precedent): a narrow,
read-only, cross-domain lookup that does not warrant standing up each
domain's full service layer just to count a few rows. No file inside
``location``/``router``/``otp`` is edited to make this work. Guest/session
counts and bandwidth are deliberately **not** re-derived here the same way --
see ``service.UsageService.record_current_usage``'s module docstring for why
those instead reuse ``app.domains.guest.service.GuestAnalyticsService
.get_summary`` directly (the exact aggregate query
``app.domains.analytics.aggregation`` itself already reuses for the same
figures), rather than adding a fourth independent computation of the same
numbers.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.location.models import Location
from app.domains.otp.models import OtpRequest
from app.domains.router.models import Router

from .models import License, LicenseChangeLog, Plan, PlanFeature, UsageMetric

# ============================================================================
# Plan / PlanFeature
# ============================================================================


class PlanRepositoryProtocol(Protocol):
    async def create_plan(self, **fields: object) -> Plan: ...

    async def get_by_id(
        self, plan_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Plan | None: ...

    async def get_by_slug(self, slug: str) -> Plan | None: ...

    async def update_plan(self, plan: Plan, data: Mapping[str, object]) -> Plan: ...

    async def soft_delete_plan(self, plan: Plan) -> Plan: ...

    async def list_plans(
        self,
        *,
        page: int,
        page_size: int,
        is_public: bool | None = None,
        is_active: bool | None = None,
        plan_type: str | None = None,
    ) -> tuple[list[Plan], PaginationMeta]: ...

    async def create_plan_feature(self, **fields: object) -> PlanFeature: ...

    async def list_plan_features(self, plan_id: uuid.UUID) -> list[PlanFeature]: ...

    async def delete_plan_features(self, plan_id: uuid.UUID) -> None: ...


class PlanRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``PlanRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.plans = GenericRepository(Plan, session)
        self.features = GenericRepository(PlanFeature, session)

    async def create_plan(self, **fields: object) -> Plan:
        return await self.plans.create(fields)

    async def get_by_id(
        self, plan_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Plan | None:
        return await self.plans.get_by_id(plan_id, include_deleted=include_deleted)

    async def get_by_slug(self, slug: str) -> Plan | None:
        results = await self.plans.get_all(filters={"slug": slug}, limit=1)
        return results[0] if results else None

    async def update_plan(self, plan: Plan, data: Mapping[str, object]) -> Plan:
        return await self.plans.update(plan, data)

    async def soft_delete_plan(self, plan: Plan) -> Plan:
        return await self.plans.soft_delete(plan)

    async def list_plans(
        self,
        *,
        page: int,
        page_size: int,
        is_public: bool | None = None,
        is_active: bool | None = None,
        plan_type: str | None = None,
    ) -> tuple[list[Plan], PaginationMeta]:
        filters: dict[str, object] = {}
        if is_public is not None:
            filters["is_public"] = is_public
        if is_active is not None:
            filters["is_active"] = is_active
        if plan_type is not None:
            filters["plan_type"] = plan_type
        return await self.plans.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by="sort_order",
            sort_order=SortOrder.ASC,
        )

    async def create_plan_feature(self, **fields: object) -> PlanFeature:
        return await self.features.create(fields)

    async def list_plan_features(self, plan_id: uuid.UUID) -> list[PlanFeature]:
        return await self.features.get_all(
            filters={"plan_id": plan_id},
            sort_by="feature_key",
            sort_order=SortOrder.ASC,
        )

    async def delete_plan_features(self, plan_id: uuid.UUID) -> None:
        for feature in await self.list_plan_features(plan_id):
            await self.features.delete(feature)


# ============================================================================
# License / LicenseChangeLog
# ============================================================================


class LicenseRepositoryProtocol(Protocol):
    async def create_license(self, **fields: object) -> License: ...

    async def get_by_id(
        self, license_id: uuid.UUID, *, include_deleted: bool = False
    ) -> License | None: ...

    async def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> License | None: ...

    async def update_license(
        self, license_: License, data: Mapping[str, object]
    ) -> License: ...

    async def create_change_log(self, **fields: object) -> LicenseChangeLog: ...

    async def list_change_logs(
        self, license_id: uuid.UUID
    ) -> list[LicenseChangeLog]: ...


class LicenseRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``LicenseRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.licenses = GenericRepository(License, session)
        self.change_logs = GenericRepository(LicenseChangeLog, session)

    async def create_license(self, **fields: object) -> License:
        return await self.licenses.create(fields)

    async def get_by_id(
        self, license_id: uuid.UUID, *, include_deleted: bool = False
    ) -> License | None:
        return await self.licenses.get_by_id(
            license_id, include_deleted=include_deleted
        )

    async def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> License | None:
        results = await self.licenses.get_all(
            filters={"organization_id": organization_id}, limit=1
        )
        return results[0] if results else None

    async def update_license(
        self, license_: License, data: Mapping[str, object]
    ) -> License:
        return await self.licenses.update(license_, data)

    async def create_change_log(self, **fields: object) -> LicenseChangeLog:
        return await self.change_logs.create(fields)

    async def list_change_logs(self, license_id: uuid.UUID) -> list[LicenseChangeLog]:
        return await self.change_logs.get_all(
            filters={"license_id": license_id},
            sort_by="changed_at",
            sort_order=SortOrder.DESC,
        )


# ============================================================================
# Usage
# ============================================================================


class UsageRepositoryProtocol(Protocol):
    async def get_current_period_metric(
        self, organization_id: uuid.UUID, metric_key: str, period_start: datetime
    ) -> UsageMetric | None: ...

    async def list_current_period_metrics(
        self, organization_id: uuid.UUID, period_start: datetime
    ) -> list[UsageMetric]: ...

    async def create_usage_metric(self, **fields: object) -> UsageMetric: ...

    async def update_usage_metric(
        self, metric: UsageMetric, data: Mapping[str, object]
    ) -> UsageMetric: ...

    async def count_locations(self, organization_id: uuid.UUID) -> int: ...

    async def count_routers(self, organization_id: uuid.UUID) -> int: ...

    async def count_otp_requests_by_channel(
        self, organization_id: uuid.UUID, *, start: datetime, end: datetime
    ) -> list[tuple[str, int]]: ...


class UsageRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``UsageRepositoryProtocol``. See module docstring for the "reading other
    domains' tables directly" precedent this class follows for
    ``count_locations``/``count_routers``/``count_otp_requests_by_channel``.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.metrics = GenericRepository(UsageMetric, session)

    async def get_current_period_metric(
        self, organization_id: uuid.UUID, metric_key: str, period_start: datetime
    ) -> UsageMetric | None:
        results = await self.metrics.get_all(
            filters={
                "organization_id": organization_id,
                "metric_key": metric_key,
                "period_start": period_start,
            },
            limit=1,
        )
        return results[0] if results else None

    async def list_current_period_metrics(
        self, organization_id: uuid.UUID, period_start: datetime
    ) -> list[UsageMetric]:
        return await self.metrics.get_all(
            filters={"organization_id": organization_id, "period_start": period_start},
            sort_by="metric_key",
            sort_order=SortOrder.ASC,
        )

    async def create_usage_metric(self, **fields: object) -> UsageMetric:
        return await self.metrics.create(fields)

    async def update_usage_metric(
        self, metric: UsageMetric, data: Mapping[str, object]
    ) -> UsageMetric:
        return await self.metrics.update(metric, data)

    async def count_locations(self, organization_id: uuid.UUID) -> int:
        statement = (
            select(func.count())
            .select_from(Location)
            .where(
                Location.organization_id == organization_id,
                Location.is_deleted.is_(False),
            )
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def count_routers(self, organization_id: uuid.UUID) -> int:
        statement = (
            select(func.count())
            .select_from(Router)
            .where(
                Router.organization_id == organization_id,
                Router.is_deleted.is_(False),
            )
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def count_otp_requests_by_channel(
        self, organization_id: uuid.UUID, *, start: datetime, end: datetime
    ) -> list[tuple[str, int]]:
        statement = (
            select(OtpRequest.channel, func.count())
            .where(
                OtpRequest.organization_id == organization_id,
                OtpRequest.created_at >= start,
                OtpRequest.created_at <= end,
                OtpRequest.is_deleted.is_(False),
            )
            .group_by(OtpRequest.channel)
        )
        result = await self.session.execute(statement)
        return [(row[0], int(row[1])) for row in result.all()]


__all__ = [
    "PlanRepositoryProtocol",
    "PlanRepository",
    "LicenseRepositoryProtocol",
    "LicenseRepository",
    "UsageRepositoryProtocol",
    "UsageRepository",
]
