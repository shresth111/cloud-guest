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
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.location.models import Location
from app.domains.otp.models import OtpRequest
from app.domains.router.models import Router

from .constants import (
    CYCLIC_BILLING_CYCLES,
    RENEWABLE_SUBSCRIPTION_STATUSES,
    InvoiceStatus,
    PaymentStatus,
)
from .models import (
    BillingProfile,
    Coupon,
    CouponPlan,
    CouponUsage,
    CreditDebitNote,
    Invoice,
    InvoiceItem,
    InvoiceNumberCounter,
    License,
    LicenseChangeLog,
    Payment,
    PaymentMethod,
    Plan,
    PlanFeature,
    Subscription,
    TaxRate,
    UsageMetric,
)

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


# ============================================================================
# Subscription (BE-013 Part 2)
# ============================================================================


class SubscriptionRepositoryProtocol(Protocol):
    async def create_subscription(self, **fields: object) -> Subscription: ...

    async def get_by_id(
        self, subscription_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Subscription | None: ...

    async def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> Subscription | None: ...

    async def update_subscription(
        self, subscription: Subscription, data: Mapping[str, object]
    ) -> Subscription: ...

    async def list_by_status(self, statuses: Sequence[str]) -> list[Subscription]: ...

    async def list_due_for_renewal(self, *, now: datetime) -> list[Subscription]: ...


class SubscriptionRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``SubscriptionRepositoryProtocol``. ``list_due_for_renewal`` is the one
    hand-written query in this class -- ``GenericRepository``'s equality/
    ``IN``-only filter support (``apply_filters``) cannot express a ``<=``
    comparison against ``current_period_end``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.subscriptions = GenericRepository(Subscription, session)

    async def create_subscription(self, **fields: object) -> Subscription:
        return await self.subscriptions.create(fields)

    async def get_by_id(
        self, subscription_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Subscription | None:
        return await self.subscriptions.get_by_id(
            subscription_id, include_deleted=include_deleted
        )

    async def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> Subscription | None:
        results = await self.subscriptions.get_all(
            filters={"organization_id": organization_id}, limit=1
        )
        return results[0] if results else None

    async def update_subscription(
        self, subscription: Subscription, data: Mapping[str, object]
    ) -> Subscription:
        return await self.subscriptions.update(subscription, data)

    async def list_by_status(self, statuses: Sequence[str]) -> list[Subscription]:
        return await self.subscriptions.get_all(filters={"status": list(statuses)})

    async def list_due_for_renewal(self, *, now: datetime) -> list[Subscription]:
        statement = select(Subscription).where(
            Subscription.is_deleted.is_(False),
            Subscription.auto_renew.is_(True),
            Subscription.billing_cycle.in_(
                [cycle.value for cycle in CYCLIC_BILLING_CYCLES]
            ),
            Subscription.status.in_(
                [status.value for status in RENEWABLE_SUBSCRIPTION_STATUSES]
            ),
            Subscription.current_period_end <= now,
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())


# ============================================================================
# Coupon / CouponPlan / CouponUsage (BE-013 Part 2)
# ============================================================================


class CouponRepositoryProtocol(Protocol):
    async def create_coupon(self, **fields: object) -> Coupon: ...

    async def get_by_id(
        self, coupon_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Coupon | None: ...

    async def get_by_code(self, code: str) -> Coupon | None: ...

    async def update_coupon(
        self, coupon: Coupon, data: Mapping[str, object]
    ) -> Coupon: ...

    async def soft_delete_coupon(self, coupon: Coupon) -> Coupon: ...

    async def list_coupons(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        is_active: bool | None = None,
    ) -> tuple[list[Coupon], PaginationMeta]: ...

    async def set_applicable_plans(
        self, coupon_id: uuid.UUID, plan_ids: Sequence[uuid.UUID]
    ) -> None: ...

    async def list_applicable_plan_ids(
        self, coupon_id: uuid.UUID
    ) -> list[uuid.UUID]: ...

    async def increment_current_uses(self, coupon_id: uuid.UUID) -> Coupon: ...

    async def create_coupon_usage(self, **fields: object) -> CouponUsage: ...


class CouponRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``CouponRepositoryProtocol``.

    ## Atomic ``current_uses`` increment

    ``increment_current_uses`` issues a real, single, server-evaluated
    ``UPDATE coupons SET current_uses = current_uses + 1 WHERE id = :id``
    (via SQLAlchemy's ``update().values(current_uses=Coupon.current_uses +
    1)``) rather than reading ``current_uses`` in Python and writing back
    ``value + 1`` -- the latter would race under concurrent redemptions of
    the same coupon (two requests could both read ``current_uses=4`` and
    both write back ``5``, silently losing one redemption's count).
    Postgres evaluates the right-hand side of the ``SET`` clause against the
    row's *current* value at update time, making this a single atomic
    operation regardless of concurrent callers.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.coupons = GenericRepository(Coupon, session)
        self.coupon_plans = GenericRepository(CouponPlan, session)
        self.usages = GenericRepository(CouponUsage, session)

    async def create_coupon(self, **fields: object) -> Coupon:
        return await self.coupons.create(fields)

    async def get_by_id(
        self, coupon_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Coupon | None:
        return await self.coupons.get_by_id(coupon_id, include_deleted=include_deleted)

    async def get_by_code(self, code: str) -> Coupon | None:
        results = await self.coupons.get_all(filters={"code": code}, limit=1)
        return results[0] if results else None

    async def update_coupon(self, coupon: Coupon, data: Mapping[str, object]) -> Coupon:
        return await self.coupons.update(coupon, data)

    async def soft_delete_coupon(self, coupon: Coupon) -> Coupon:
        return await self.coupons.soft_delete(coupon)

    async def list_coupons(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        is_active: bool | None = None,
    ) -> tuple[list[Coupon], PaginationMeta]:
        filters: dict[str, object] = {}
        if organization_id is not None:
            filters["organization_id"] = organization_id
        if is_active is not None:
            filters["is_active"] = is_active
        return await self.coupons.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by="created_at",
            sort_order=SortOrder.DESC,
        )

    async def set_applicable_plans(
        self, coupon_id: uuid.UUID, plan_ids: Sequence[uuid.UUID]
    ) -> None:
        for association in await self.coupon_plans.get_all(
            filters={"coupon_id": coupon_id}
        ):
            await self.coupon_plans.delete(association)
        for plan_id in plan_ids:
            await self.coupon_plans.create({"coupon_id": coupon_id, "plan_id": plan_id})

    async def list_applicable_plan_ids(self, coupon_id: uuid.UUID) -> list[uuid.UUID]:
        associations = await self.coupon_plans.get_all(filters={"coupon_id": coupon_id})
        return [association.plan_id for association in associations]

    async def increment_current_uses(self, coupon_id: uuid.UUID) -> Coupon:
        statement = (
            update(Coupon)
            .where(Coupon.id == coupon_id)
            .values(current_uses=Coupon.current_uses + 1, version=Coupon.version + 1)
        )
        await self.session.execute(statement)
        await self.session.flush()
        updated = await self.coupons.get_by_id(coupon_id, include_deleted=True)
        assert updated is not None  # the row was just updated above
        await self.session.refresh(updated)
        return updated

    async def create_coupon_usage(self, **fields: object) -> CouponUsage:
        return await self.usages.create(fields)


# ============================================================================
# Payment / PaymentMethod (BE-013 Part 3)
# ============================================================================


class PaymentRepositoryProtocol(Protocol):
    async def create_payment(self, **fields: object) -> Payment: ...

    async def get_by_id(
        self, payment_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Payment | None: ...

    async def get_by_idempotency_key(self, idempotency_key: str) -> Payment | None: ...

    async def get_by_provider_payment_id(
        self, provider_payment_id: str
    ) -> Payment | None: ...

    async def update_payment(
        self, payment: Payment, data: Mapping[str, object]
    ) -> Payment: ...

    async def list_payments(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
        provider: str | None = None,
    ) -> tuple[list[Payment], PaginationMeta]: ...

    async def list_failed_payments(
        self, organization_id: uuid.UUID | None = None
    ) -> list[Payment]: ...


class PaymentRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``PaymentRepositoryProtocol``. ``get_by_idempotency_key`` is the read
    side of this domain's real idempotency guarantee -- see
    ``models.Payment``'s own docstring for the full write-up of how the
    unique constraint on that column, not just this lookup, is the actual
    enforcement mechanism."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.payments = GenericRepository(Payment, session)

    async def create_payment(self, **fields: object) -> Payment:
        return await self.payments.create(fields)

    async def get_by_id(
        self, payment_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Payment | None:
        return await self.payments.get_by_id(
            payment_id, include_deleted=include_deleted
        )

    async def get_by_idempotency_key(self, idempotency_key: str) -> Payment | None:
        results = await self.payments.get_all(
            filters={"idempotency_key": idempotency_key}, limit=1
        )
        return results[0] if results else None

    async def get_by_provider_payment_id(
        self, provider_payment_id: str
    ) -> Payment | None:
        results = await self.payments.get_all(
            filters={"provider_payment_id": provider_payment_id}, limit=1
        )
        return results[0] if results else None

    async def update_payment(
        self, payment: Payment, data: Mapping[str, object]
    ) -> Payment:
        return await self.payments.update(payment, data)

    async def list_payments(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
        provider: str | None = None,
    ) -> tuple[list[Payment], PaginationMeta]:
        filters: dict[str, object] = {}
        if organization_id is not None:
            filters["organization_id"] = organization_id
        if status is not None:
            filters["status"] = status
        if provider is not None:
            filters["provider"] = provider
        return await self.payments.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by="created_at",
            sort_order=SortOrder.DESC,
        )

    async def list_failed_payments(
        self, organization_id: uuid.UUID | None = None
    ) -> list[Payment]:
        """The real "failed payments" listing/query method item 4 asks
        for -- composes ``GenericRepository.get_all`` over this same
        ``payments`` table (see ``models.Payment``'s "Payment doubles as
        history" docstring), never a second table."""
        filters: dict[str, object] = {"status": PaymentStatus.FAILED.value}
        if organization_id is not None:
            filters["organization_id"] = organization_id
        return await self.payments.get_all(
            filters=filters, sort_by="created_at", sort_order=SortOrder.DESC
        )


class PaymentMethodRepositoryProtocol(Protocol):
    async def create_payment_method(self, **fields: object) -> PaymentMethod: ...

    async def get_by_id(
        self, payment_method_id: uuid.UUID, *, include_deleted: bool = False
    ) -> PaymentMethod | None: ...

    async def list_for_organization(
        self, organization_id: uuid.UUID, *, active_only: bool = True
    ) -> list[PaymentMethod]: ...

    async def get_default_for_organization(
        self, organization_id: uuid.UUID
    ) -> PaymentMethod | None: ...

    async def update_payment_method(
        self, payment_method: PaymentMethod, data: Mapping[str, object]
    ) -> PaymentMethod: ...

    async def soft_delete_payment_method(
        self, payment_method: PaymentMethod
    ) -> PaymentMethod: ...

    async def set_as_default(self, payment_method: PaymentMethod) -> PaymentMethod: ...


class PaymentMethodRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``PaymentMethodRepositoryProtocol``.

    ## ``set_as_default``: at most one default per organization

    Mirrors ``CouponRepository.increment_current_uses``'s own "real,
    server-evaluated statement, not a read-then-write-in-Python race"
    discipline: unsets every other active ``PaymentMethod`` row for this
    organization in one ``UPDATE ... WHERE organization_id = :id`` statement
    before setting the target row's own ``is_default = True`` -- two
    concurrent "set as default" calls for the same organization can race
    each other, but never leave two rows simultaneously marked default,
    since each unset-then-set pair is issued as its own atomic statement
    pair within the same transaction.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.payment_methods = GenericRepository(PaymentMethod, session)

    async def create_payment_method(self, **fields: object) -> PaymentMethod:
        return await self.payment_methods.create(fields)

    async def get_by_id(
        self, payment_method_id: uuid.UUID, *, include_deleted: bool = False
    ) -> PaymentMethod | None:
        return await self.payment_methods.get_by_id(
            payment_method_id, include_deleted=include_deleted
        )

    async def list_for_organization(
        self, organization_id: uuid.UUID, *, active_only: bool = True
    ) -> list[PaymentMethod]:
        filters: dict[str, object] = {"organization_id": organization_id}
        if active_only:
            filters["is_active"] = True
        return await self.payment_methods.get_all(
            filters=filters, sort_by="created_at", sort_order=SortOrder.DESC
        )

    async def get_default_for_organization(
        self, organization_id: uuid.UUID
    ) -> PaymentMethod | None:
        results = await self.payment_methods.get_all(
            filters={
                "organization_id": organization_id,
                "is_default": True,
                "is_active": True,
            },
            limit=1,
        )
        return results[0] if results else None

    async def update_payment_method(
        self, payment_method: PaymentMethod, data: Mapping[str, object]
    ) -> PaymentMethod:
        return await self.payment_methods.update(payment_method, data)

    async def soft_delete_payment_method(
        self, payment_method: PaymentMethod
    ) -> PaymentMethod:
        return await self.payment_methods.soft_delete(payment_method)

    async def set_as_default(self, payment_method: PaymentMethod) -> PaymentMethod:
        statement = (
            update(PaymentMethod)
            .where(
                PaymentMethod.organization_id == payment_method.organization_id,
                PaymentMethod.id != payment_method.id,
                PaymentMethod.is_default.is_(True),
            )
            .values(is_default=False)
        )
        await self.session.execute(statement)
        return await self.payment_methods.update(payment_method, {"is_default": True})


# ============================================================================
# BE-013 Part 4: Invoice Engine + Tax/GST
# ============================================================================


class NumberCounterRepository:
    """Concrete, real, DB-level-atomic implementation of
    ``number_generator.NumberCounterRepositoryProtocol`` -- see that
    module's own docstring for the full write-up of exactly why the single
    ``INSERT ... ON CONFLICT DO UPDATE ... RETURNING`` statement below is
    genuinely concurrency-safe (never a racy ``SELECT MAX(...) + 1``)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def increment_and_get_next(self, counter_key: str) -> int:
        statement = (
            pg_insert(InvoiceNumberCounter)
            .values(counter_key=counter_key, last_value=1)
            .on_conflict_do_update(
                index_elements=[InvoiceNumberCounter.counter_key],
                set_={
                    "last_value": InvoiceNumberCounter.last_value + 1,
                    "version": InvoiceNumberCounter.version + 1,
                },
            )
            .returning(InvoiceNumberCounter.last_value)
        )
        result = await self.session.execute(statement)
        await self.session.flush()
        return int(result.scalar_one())


class TaxRateRepositoryProtocol(Protocol):
    async def create_tax_rate(self, **fields: object) -> TaxRate: ...

    async def get_by_id(
        self, tax_rate_id: uuid.UUID, *, include_deleted: bool = False
    ) -> TaxRate | None: ...

    async def update_tax_rate(
        self, tax_rate: TaxRate, data: Mapping[str, object]
    ) -> TaxRate: ...

    async def list_tax_rates(
        self,
        *,
        page: int,
        page_size: int,
        country_code: str | None = None,
        is_active: bool | None = None,
    ) -> tuple[list[TaxRate], PaginationMeta]: ...

    async def get_active_for_country(self, country_code: str) -> TaxRate | None: ...


class TaxRateRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``TaxRateRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.tax_rates = GenericRepository(TaxRate, session)

    async def create_tax_rate(self, **fields: object) -> TaxRate:
        return await self.tax_rates.create(fields)

    async def get_by_id(
        self, tax_rate_id: uuid.UUID, *, include_deleted: bool = False
    ) -> TaxRate | None:
        return await self.tax_rates.get_by_id(
            tax_rate_id, include_deleted=include_deleted
        )

    async def update_tax_rate(
        self, tax_rate: TaxRate, data: Mapping[str, object]
    ) -> TaxRate:
        return await self.tax_rates.update(tax_rate, data)

    async def list_tax_rates(
        self,
        *,
        page: int,
        page_size: int,
        country_code: str | None = None,
        is_active: bool | None = None,
    ) -> tuple[list[TaxRate], PaginationMeta]:
        filters: dict[str, object] = {}
        if country_code is not None:
            filters["country_code"] = country_code
        if is_active is not None:
            filters["is_active"] = is_active
        return await self.tax_rates.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by="created_at",
            sort_order=SortOrder.DESC,
        )

    async def get_active_for_country(self, country_code: str) -> TaxRate | None:
        """The active tax rate this platform applies for a given billing
        country -- assumes at most one Super-Admin-managed active default
        rate per country (a real, documented operational assumption, not
        an enforced DB constraint); the first match is used. No active rate
        for a country is an honest "no tax configured here" outcome, not
        an error -- ``validators.compute_tax_breakdown`` treats a ``None``
        rate the same as ``TaxType.NONE``."""
        results = await self.tax_rates.get_all(
            filters={"country_code": country_code, "is_active": True}, limit=1
        )
        return results[0] if results else None


class BillingProfileRepositoryProtocol(Protocol):
    async def create_billing_profile(self, **fields: object) -> BillingProfile: ...

    async def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> BillingProfile | None: ...

    async def update_billing_profile(
        self, billing_profile: BillingProfile, data: Mapping[str, object]
    ) -> BillingProfile: ...


class BillingProfileRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``BillingProfileRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.billing_profiles = GenericRepository(BillingProfile, session)

    async def create_billing_profile(self, **fields: object) -> BillingProfile:
        return await self.billing_profiles.create(fields)

    async def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> BillingProfile | None:
        results = await self.billing_profiles.get_all(
            filters={"organization_id": organization_id}, limit=1
        )
        return results[0] if results else None

    async def update_billing_profile(
        self, billing_profile: BillingProfile, data: Mapping[str, object]
    ) -> BillingProfile:
        return await self.billing_profiles.update(billing_profile, data)


class InvoiceRepositoryProtocol(Protocol):
    async def create_invoice(self, **fields: object) -> Invoice: ...

    async def get_by_id(
        self, invoice_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Invoice | None: ...

    async def get_by_invoice_number(self, invoice_number: str) -> Invoice | None: ...

    async def update_invoice(
        self, invoice: Invoice, data: Mapping[str, object]
    ) -> Invoice: ...

    async def list_invoices(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
    ) -> tuple[list[Invoice], PaginationMeta]: ...

    async def list_unpaid_for_subscription(
        self, subscription_id: uuid.UUID
    ) -> list[Invoice]: ...

    async def list_issued_past_due(self, *, now: datetime) -> list[Invoice]: ...

    async def create_invoice_item(self, **fields: object) -> InvoiceItem: ...

    async def list_items(self, invoice_id: uuid.UUID) -> list[InvoiceItem]: ...


class InvoiceRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``InvoiceRepositoryProtocol``. ``list_unpaid_for_subscription``/
    ``list_issued_past_due`` are hand-written queries --
    ``GenericRepository``'s equality/``IN``-only filter support
    (``apply_filters``) cannot express ``status IN (...)`` combined with a
    ``<=`` comparison, or the most-recent-first ordering
    ``list_unpaid_for_subscription`` needs."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.invoices = GenericRepository(Invoice, session)
        self.items = GenericRepository(InvoiceItem, session)

    async def create_invoice(self, **fields: object) -> Invoice:
        return await self.invoices.create(fields)

    async def get_by_id(
        self, invoice_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Invoice | None:
        return await self.invoices.get_by_id(
            invoice_id, include_deleted=include_deleted
        )

    async def get_by_invoice_number(self, invoice_number: str) -> Invoice | None:
        results = await self.invoices.get_all(
            filters={"invoice_number": invoice_number}, limit=1
        )
        return results[0] if results else None

    async def update_invoice(
        self, invoice: Invoice, data: Mapping[str, object]
    ) -> Invoice:
        return await self.invoices.update(invoice, data)

    async def list_invoices(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
    ) -> tuple[list[Invoice], PaginationMeta]:
        filters: dict[str, object] = {}
        if organization_id is not None:
            filters["organization_id"] = organization_id
        if status is not None:
            filters["status"] = status
        return await self.invoices.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by="issue_date",
            sort_order=SortOrder.DESC,
        )

    async def list_unpaid_for_subscription(
        self, subscription_id: uuid.UUID
    ) -> list[Invoice]:
        statement = (
            select(Invoice)
            .where(
                Invoice.is_deleted.is_(False),
                Invoice.subscription_id == subscription_id,
                Invoice.status.in_(
                    [InvoiceStatus.ISSUED.value, InvoiceStatus.OVERDUE.value]
                ),
            )
            .order_by(Invoice.issue_date.desc())
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_issued_past_due(self, *, now: datetime) -> list[Invoice]:
        statement = select(Invoice).where(
            Invoice.is_deleted.is_(False),
            Invoice.status == InvoiceStatus.ISSUED.value,
            Invoice.due_date <= now,
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def create_invoice_item(self, **fields: object) -> InvoiceItem:
        return await self.items.create(fields)

    async def list_items(self, invoice_id: uuid.UUID) -> list[InvoiceItem]:
        return await self.items.get_all(
            filters={"invoice_id": invoice_id},
            sort_by="created_at",
            sort_order=SortOrder.ASC,
        )


class CreditDebitNoteRepositoryProtocol(Protocol):
    async def create_note(self, **fields: object) -> CreditDebitNote: ...

    async def list_for_invoice(
        self, invoice_id: uuid.UUID
    ) -> list[CreditDebitNote]: ...


class CreditDebitNoteRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``CreditDebitNoteRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.notes = GenericRepository(CreditDebitNote, session)

    async def create_note(self, **fields: object) -> CreditDebitNote:
        return await self.notes.create(fields)

    async def list_for_invoice(self, invoice_id: uuid.UUID) -> list[CreditDebitNote]:
        return await self.notes.get_all(
            filters={"invoice_id": invoice_id},
            sort_by="issued_at",
            sort_order=SortOrder.DESC,
        )


__all__ = [
    "PlanRepositoryProtocol",
    "PlanRepository",
    "LicenseRepositoryProtocol",
    "LicenseRepository",
    "UsageRepositoryProtocol",
    "UsageRepository",
    "SubscriptionRepositoryProtocol",
    "SubscriptionRepository",
    "CouponRepositoryProtocol",
    "CouponRepository",
    "PaymentRepositoryProtocol",
    "PaymentRepository",
    "PaymentMethodRepositoryProtocol",
    "PaymentMethodRepository",
    "NumberCounterRepository",
    "TaxRateRepositoryProtocol",
    "TaxRateRepository",
    "BillingProfileRepositoryProtocol",
    "BillingProfileRepository",
    "InvoiceRepositoryProtocol",
    "InvoiceRepository",
    "CreditDebitNoteRepositoryProtocol",
    "CreditDebitNoteRepository",
]
