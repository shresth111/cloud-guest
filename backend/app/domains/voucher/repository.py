"""Data access layer for the Voucher domain.

Mirrors ``app.domains.otp.repository``'s shape: a ``Protocol`` describing
the operations the service layer needs (``VoucherRepositoryProtocol``), and
a concrete, ``GenericRepository``-backed implementation
(``VoucherRepository``) wrapping *four* ``GenericRepository`` instances (one
per table -- ``VoucherPlan``/``VoucherSeries`` (Phase 1 BhaiFi-parity
additions) and the original ``VoucherBatch``/``Voucher``), plus a handful of
hand-written statements for the few queries ``GenericRepository``'s
equality/IN-filter support genuinely can't express: a grouped per-status
count (used by ``VoucherService.get_batch_stats``) and a bulk status update
scoped to a batch (used by ``VoucherService.revoke_batch``'s cascade).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .constants import VoucherStatus
from .models import Voucher, VoucherBatch, VoucherPlan, VoucherSeries


class VoucherRepositoryProtocol(Protocol):
    # -- plans -----------------------------------------------------------------
    async def create_plan(self, **fields: object) -> VoucherPlan: ...

    async def get_plan(self, plan_id: uuid.UUID) -> VoucherPlan | None: ...

    async def update_plan(
        self, plan: VoucherPlan, data: dict[str, object]
    ) -> VoucherPlan: ...

    async def list_plans(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[VoucherPlan], PaginationMeta]: ...

    # -- series ------------------------------------------------------------------
    async def create_series(self, **fields: object) -> VoucherSeries: ...

    async def get_series(self, series_id: uuid.UUID) -> VoucherSeries | None: ...

    async def update_series(
        self, series: VoucherSeries, data: dict[str, object]
    ) -> VoucherSeries: ...

    async def list_series(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[VoucherSeries], PaginationMeta]: ...

    # -- batches -------------------------------------------------------------
    async def create_batch(self, **fields: object) -> VoucherBatch: ...

    async def get_batch(self, batch_id: uuid.UUID) -> VoucherBatch | None: ...

    async def update_batch(
        self, batch: VoucherBatch, data: dict[str, object]
    ) -> VoucherBatch: ...

    async def list_batches(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[VoucherBatch], PaginationMeta]: ...

    # -- vouchers --------------------------------------------------------------
    async def bulk_create_vouchers(
        self, items: Sequence[dict[str, object]]
    ) -> list[Voucher]: ...

    async def get_voucher_by_code(self, code: str) -> Voucher | None: ...

    async def find_existing_codes(self, codes: Sequence[str]) -> list[str]: ...

    async def update_voucher(
        self, voucher: Voucher, data: dict[str, object]
    ) -> Voucher: ...

    async def list_vouchers_for_batch(
        self,
        batch_id: uuid.UUID,
        *,
        page: int,
        page_size: int,
    ) -> tuple[list[Voucher], PaginationMeta]: ...

    async def list_all_vouchers_for_batch(
        self, batch_id: uuid.UUID
    ) -> list[Voucher]: ...

    async def get_batch_status_counts(self, batch_id: uuid.UUID) -> dict[str, int]: ...

    async def bulk_revoke_vouchers_for_batch(self, batch_id: uuid.UUID) -> int: ...

    # -- redemption analytics (Phase 1 BhaiFi-parity) -----------------------------
    async def count_vouchers_issued(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> int: ...

    async def count_vouchers_redeemed(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> int: ...

    async def get_redemption_counts_by_plan(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[uuid.UUID | None, int]]: ...


class VoucherRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``VoucherRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.plans = GenericRepository(VoucherPlan, session)
        self.series = GenericRepository(VoucherSeries, session)
        self.batches = GenericRepository(VoucherBatch, session)
        self.vouchers = GenericRepository(Voucher, session)

    # -- plans -----------------------------------------------------------------

    async def create_plan(self, **fields: object) -> VoucherPlan:
        return await self.plans.create(fields)

    async def get_plan(self, plan_id: uuid.UUID) -> VoucherPlan | None:
        return await self.plans.get_by_id(plan_id)

    async def update_plan(
        self, plan: VoucherPlan, data: dict[str, object]
    ) -> VoucherPlan:
        return await self.plans.update(plan, data)

    async def list_plans(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[VoucherPlan], PaginationMeta]:
        return await self.plans.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    # -- series ------------------------------------------------------------------

    async def create_series(self, **fields: object) -> VoucherSeries:
        return await self.series.create(fields)

    async def get_series(self, series_id: uuid.UUID) -> VoucherSeries | None:
        return await self.series.get_by_id(series_id)

    async def update_series(
        self, series: VoucherSeries, data: dict[str, object]
    ) -> VoucherSeries:
        return await self.series.update(series, data)

    async def list_series(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[VoucherSeries], PaginationMeta]:
        return await self.series.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    # -- batches -------------------------------------------------------------

    async def create_batch(self, **fields: object) -> VoucherBatch:
        return await self.batches.create(fields)

    async def get_batch(self, batch_id: uuid.UUID) -> VoucherBatch | None:
        return await self.batches.get_by_id(batch_id)

    async def update_batch(
        self, batch: VoucherBatch, data: dict[str, object]
    ) -> VoucherBatch:
        return await self.batches.update(batch, data)

    async def list_batches(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[VoucherBatch], PaginationMeta]:
        return await self.batches.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    # -- vouchers --------------------------------------------------------------

    async def bulk_create_vouchers(
        self, items: Sequence[dict[str, object]]
    ) -> list[Voucher]:
        return await self.vouchers.bulk_create(items)

    async def get_voucher_by_code(self, code: str) -> Voucher | None:
        results = await self.vouchers.get_all(filters={"code": code}, limit=1)
        return results[0] if results else None

    async def find_existing_codes(self, codes: Sequence[str]) -> list[str]:
        if not codes:
            return []
        results = await self.vouchers.get_all(
            filters={"code": list(codes)}, include_deleted=True
        )
        return [row.code for row in results]

    async def update_voucher(
        self, voucher: Voucher, data: dict[str, object]
    ) -> Voucher:
        return await self.vouchers.update(voucher, data)

    async def list_vouchers_for_batch(
        self,
        batch_id: uuid.UUID,
        *,
        page: int,
        page_size: int,
    ) -> tuple[list[Voucher], PaginationMeta]:
        return await self.vouchers.paginate(
            page=page,
            page_size=page_size,
            filters={"batch_id": batch_id},
            sort_by="created_at",
            sort_order=SortOrder.ASC,
        )

    async def list_all_vouchers_for_batch(self, batch_id: uuid.UUID) -> list[Voucher]:
        return await self.vouchers.get_all(
            filters={"batch_id": batch_id},
            sort_by="created_at",
            sort_order=SortOrder.ASC,
        )

    async def get_batch_status_counts(self, batch_id: uuid.UUID) -> dict[str, int]:
        """A single grouped-count query -- the one aggregate
        ``GenericRepository`` has no shape for (its own ``count`` only
        supports a single equality-filtered total)."""
        statement = (
            select(Voucher.status, func.count())
            .where(Voucher.batch_id == batch_id, Voucher.is_deleted.is_(False))
            .group_by(Voucher.status)
        )
        result = await self.session.execute(statement)
        return {status_value: count for status_value, count in result.all()}

    async def bulk_revoke_vouchers_for_batch(self, batch_id: uuid.UUID) -> int:
        """Flips every non-terminal voucher in ``batch_id`` to ``REVOKED`` in
        one statement -- used by ``VoucherService.revoke_batch``'s cascade.
        Deliberately a single ``UPDATE ... WHERE`` rather than an ORM
        per-row loop: a batch may hold up to
        ``app.database.constants.MAX_BULK_CREATE_SIZE`` vouchers, and
        looping ``GenericRepository.update`` that many times would be up to
        1,000 round trips for what is semantically one operation."""
        terminal = {
            VoucherStatus.EXHAUSTED.value,
            VoucherStatus.EXPIRED.value,
            VoucherStatus.REVOKED.value,
        }
        statement = (
            update(Voucher)
            .where(Voucher.batch_id == batch_id, Voucher.status.notin_(terminal))
            .values(status=VoucherStatus.REVOKED.value)
        )
        result = await self.session.execute(statement)
        await self.session.flush()
        return int(result.rowcount or 0)

    # -- redemption analytics (Phase 1 BhaiFi-parity) -----------------------------
    # ``Voucher`` itself carries no ``organization_id``/``location_id`` of its
    # own (only ``VoucherBatch`` does -- see models.py) -- every query below
    # joins through ``VoucherBatch`` for tenant scoping, real server-side SQL
    # rather than a Python-side scan, mirroring ``get_batch_status_counts``'s
    # identical "hand-written statement for what GenericRepository can't
    # express" precedent. Composed by
    # ``app.domains.analytics.voucher_analytics`` via
    # ``VoucherRepositoryProtocol`` directly (not through ``VoucherService``):
    # these are pure, read-only aggregate counts with no business rule to
    # apply first, unlike every other analytics-composed domain (which reads
    # through that domain's own service to get its authorization/business
    # logic for free).

    def _tenant_scoped_conditions(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
    ) -> list[object]:
        conditions: list[object] = [VoucherBatch.organization_id == organization_id]
        if location_id is not None:
            conditions.append(VoucherBatch.location_id == location_id)
        return conditions

    async def count_vouchers_issued(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> int:
        statement = (
            select(func.count())
            .select_from(Voucher)
            .join(VoucherBatch, Voucher.batch_id == VoucherBatch.id)
            .where(
                *self._tenant_scoped_conditions(
                    organization_id=organization_id, location_id=location_id
                ),
                Voucher.created_at >= start,
                Voucher.created_at < end,
                Voucher.is_deleted.is_(False),
            )
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def count_vouchers_redeemed(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> int:
        statement = (
            select(func.count())
            .select_from(Voucher)
            .join(VoucherBatch, Voucher.batch_id == VoucherBatch.id)
            .where(
                *self._tenant_scoped_conditions(
                    organization_id=organization_id, location_id=location_id
                ),
                Voucher.redeemed_at.isnot(None),
                Voucher.redeemed_at >= start,
                Voucher.redeemed_at < end,
                Voucher.is_deleted.is_(False),
            )
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def get_redemption_counts_by_plan(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[uuid.UUID | None, int]]:
        statement = (
            select(Voucher.plan_id, func.count())
            .select_from(Voucher)
            .join(VoucherBatch, Voucher.batch_id == VoucherBatch.id)
            .where(
                *self._tenant_scoped_conditions(
                    organization_id=organization_id, location_id=location_id
                ),
                Voucher.redeemed_at.isnot(None),
                Voucher.redeemed_at >= start,
                Voucher.redeemed_at < end,
                Voucher.is_deleted.is_(False),
            )
            .group_by(Voucher.plan_id)
        )
        result = await self.session.execute(statement)
        return [(plan_id, count) for plan_id, count in result.all()]


__all__ = ["VoucherRepositoryProtocol", "VoucherRepository"]
