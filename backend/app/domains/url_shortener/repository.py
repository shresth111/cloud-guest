"""Data access layer for the URL Shortener domain.

Mirrors ``app.domains.otp.repository``'s/``app.domains.voucher.repository``'s
shape: a ``Protocol`` describing the operations the service layer needs
(``ShortLinkRepositoryProtocol``), and a concrete, ``GenericRepository``-
backed implementation (``ShortLinkRepository``) for this module's one
table, plus one hand-written statement for the operation
``GenericRepository``'s read-modify-write ``update()`` genuinely cannot do
safely: an atomic click-count increment (see ``record_click``'s own
docstring).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import ShortLink


class ShortLinkRepositoryProtocol(Protocol):
    async def create(self, **fields: object) -> ShortLink: ...

    async def get_by_id(self, short_link_id: uuid.UUID) -> ShortLink | None: ...

    async def get_by_code(self, code: str) -> ShortLink | None: ...

    async def find_existing_codes(self, codes: Sequence[str]) -> list[str]: ...

    async def update(
        self, short_link: ShortLink, data: dict[str, object]
    ) -> ShortLink: ...

    async def list_short_links(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[ShortLink], PaginationMeta]: ...

    async def record_click(self, code: str, *, now: datetime) -> ShortLink | None: ...


class ShortLinkRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``ShortLinkRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.short_links = GenericRepository(ShortLink, session)

    async def create(self, **fields: object) -> ShortLink:
        return await self.short_links.create(fields)

    async def get_by_id(self, short_link_id: uuid.UUID) -> ShortLink | None:
        return await self.short_links.get_by_id(short_link_id)

    async def get_by_code(self, code: str) -> ShortLink | None:
        results = await self.short_links.get_all(filters={"code": code}, limit=1)
        return results[0] if results else None

    async def find_existing_codes(self, codes: Sequence[str]) -> list[str]:
        if not codes:
            return []
        results = await self.short_links.get_all(
            filters={"code": list(codes)}, include_deleted=True
        )
        return [row.code for row in results]

    async def update(self, short_link: ShortLink, data: dict[str, object]) -> ShortLink:
        """A full (non-partial) ``GenericRepository.update`` -- ``data`` is
        expected to already be exactly the caller-provided fields (e.g.
        ``ShortLinkUpdateRequest.model_dump(exclude_unset=True)`` at the
        router layer), so an explicit ``null`` the caller sent (e.g.
        clearing ``expires_at``) must still be applied, unlike
        ``partial_update``, which silently skips any ``None`` value -- the
        same ``exclude_unset``-at-the-router, full-``update``-at-the-
        repository pattern ``app.domains.location.service.LocationService
        .update_location`` already establishes."""
        return await self.short_links.update(short_link, data)

    async def list_short_links(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[ShortLink], PaginationMeta]:
        return await self.short_links.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def record_click(self, code: str, *, now: datetime) -> ShortLink | None:
        """Atomically increments ``click_count``/sets ``last_clicked_at`` in
        a single ``UPDATE ... WHERE ... RETURNING`` statement -- deliberately
        **not** a read-then-write (``get_by_code`` followed by
        ``GenericRepository.update``'s read-modify-write ``instance.click_count
        = instance.click_count + 1``), which would lose an increment under
        two concurrent redirects racing to read the same pre-update value
        (a real lost-update bug under real click traffic, e.g. a popular
        link shared during a live event). The ``WHERE`` clause folds the
        existence/active/not-expired check into the same atomic statement
        that performs the increment, mirroring
        ``app.domains.voucher.repository.VoucherRepository
        .bulk_revoke_vouchers_for_batch``'s identical "hand-written
        statement for what GenericRepository's ORM-level update can't
        express atomically" precedent. Returns ``None`` (no row matched --
        not found, inactive, or expired) or the fresh, fully up-to-date row
        on success."""
        statement = (
            update(ShortLink)
            .where(
                ShortLink.code == code,
                ShortLink.is_deleted.is_(False),
                ShortLink.is_active.is_(True),
                or_(ShortLink.expires_at.is_(None), ShortLink.expires_at > now),
            )
            .values(click_count=ShortLink.click_count + 1, last_clicked_at=now)
            .returning(ShortLink.id)
        )
        result = await self.session.execute(statement)
        row_id = result.scalar_one_or_none()
        await self.session.flush()
        if row_id is None:
            return None
        refreshed = await self.session.execute(
            select(ShortLink).where(ShortLink.id == row_id)
        )
        return refreshed.scalar_one()


__all__ = ["ShortLinkRepositoryProtocol", "ShortLinkRepository"]
