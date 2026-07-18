"""Data access layer for the Voucher domain.

Mirrors ``app.domains.otp.repository``'s shape: a ``Protocol`` describing
the operations the service layer needs (``VoucherRepositoryProtocol``), and
a concrete, ``GenericRepository``-backed implementation
(``VoucherRepository``) wrapping *two* ``GenericRepository`` instances (one
per table -- ``VoucherBatch``, ``Voucher``), plus a handful of hand-written
statements for the few queries ``GenericRepository``'s equality/IN-filter
support genuinely can't express: a grouped per-status count (used by
``VoucherService.get_batch_stats``) and a bulk status update scoped to a
batch (used by ``VoucherService.revoke_batch``'s cascade).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Protocol

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .constants import VoucherStatus
from .models import Voucher, VoucherBatch


class VoucherRepositoryProtocol(Protocol):
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


class VoucherRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``VoucherRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.batches = GenericRepository(VoucherBatch, session)
        self.vouchers = GenericRepository(Voucher, session)

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


__all__ = ["VoucherRepositoryProtocol", "VoucherRepository"]
