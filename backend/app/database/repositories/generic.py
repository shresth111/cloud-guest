import uuid
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any, Generic, TypeVar

from sqlalchemy import Select, func, inspect, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.base import BaseModel
from app.database.constants import DEFAULT_SORT_FIELD, MAX_BULK_CREATE_SIZE, SortOrder
from app.database.exceptions import (
    ConflictError,
    DatabaseError,
    DuplicateRecordError,
    RecordNotFoundError,
)
from app.database.utils.filters import apply_filters
from app.database.utils.pagination import PageParams, PaginationMeta, paginate
from app.database.utils.sorting import apply_sorting

ModelT = TypeVar("ModelT", bound=BaseModel)


class GenericRepository(Generic[ModelT]):
    def __init__(self, model: type[ModelT], session: AsyncSession) -> None:
        self.model = model
        self.session = session

    async def create(self, data: Mapping[str, Any]) -> ModelT:
        instance = self.model(**dict(data))
        self.session.add(instance)
        await self._flush_or_raise()
        await self.session.refresh(instance)
        return instance

    async def bulk_create(self, items: Sequence[Mapping[str, Any]]) -> list[ModelT]:
        if len(items) > MAX_BULK_CREATE_SIZE:
            raise ConflictError(
                f"Bulk create cannot exceed {MAX_BULK_CREATE_SIZE} records"
            )
        instances = [self.model(**dict(item)) for item in items]
        self.session.add_all(instances)
        await self._flush_or_raise()
        for instance in instances:
            await self.session.refresh(instance)
        return instances

    async def update(self, instance: ModelT, data: Mapping[str, Any]) -> ModelT:
        self._assign(instance, data, partial=False)
        await self._flush_or_raise()
        await self.session.refresh(instance)
        return instance

    async def partial_update(self, instance: ModelT, data: Mapping[str, Any]) -> ModelT:
        self._assign(instance, data, partial=True)
        await self._flush_or_raise()
        await self.session.refresh(instance)
        return instance

    async def delete(self, instance: ModelT) -> None:
        await self.session.delete(instance)
        await self._flush_or_raise()

    async def soft_delete(self, instance: ModelT) -> ModelT:
        instance.mark_deleted()
        await self._flush_or_raise()
        await self.session.refresh(instance)
        return instance

    async def restore(self, instance: ModelT) -> ModelT:
        instance.restore_deleted()
        await self._flush_or_raise()
        await self.session.refresh(instance)
        return instance

    async def get_by_id(
        self,
        record_id: uuid.UUID,
        *,
        include_deleted: bool = False,
    ) -> ModelT | None:
        statement = self._base_select(include_deleted=include_deleted).where(
            self.model.id == record_id
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def get_required(
        self,
        record_id: uuid.UUID,
        *,
        include_deleted: bool = False,
    ) -> ModelT:
        instance = await self.get_by_id(record_id, include_deleted=include_deleted)
        if instance is None:
            raise RecordNotFoundError(self.model.__name__, record_id)
        return instance

    async def get_all(
        self,
        *,
        filters: Mapping[str, Any] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
        include_deleted: bool = False,
        limit: int | None = None,
    ) -> list[ModelT]:
        statement = self._filtered_statement(
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
            include_deleted=include_deleted,
        )
        if limit is not None:
            statement = statement.limit(limit)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def paginate(
        self,
        *,
        page: int,
        page_size: int,
        filters: Mapping[str, Any] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
        include_deleted: bool = False,
    ) -> tuple[list[ModelT], PaginationMeta]:
        params = PageParams(page=page, page_size=page_size)
        count_statement = self._count_statement(
            filters=filters,
            include_deleted=include_deleted,
        )
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        statement = self._filtered_statement(
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
            include_deleted=include_deleted,
        )
        result = await self.session.execute(paginate(statement, params))
        rows = list(result.scalars().all())
        return rows, PaginationMeta.from_total(params, total_items)

    async def search(
        self,
        *,
        query: str,
        fields: Sequence[str],
        filters: Mapping[str, Any] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
        include_deleted: bool = False,
        limit: int | None = None,
    ) -> list[ModelT]:
        statement = self._filtered_statement(
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
            include_deleted=include_deleted,
        )
        expressions = []
        for field in fields:
            if not hasattr(self.model, field):
                raise ConflictError(f"Search field is not available: {field}")
            expressions.append(getattr(self.model, field).ilike(f"%{query}%"))
        if expressions:
            statement = statement.where(or_(*expressions))
        if limit is not None:
            statement = statement.limit(limit)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def exists(
        self,
        *,
        filters: Mapping[str, Any],
        include_deleted: bool = False,
    ) -> bool:
        statement = self._base_select(include_deleted=include_deleted).limit(1)
        statement = apply_filters(statement, self.model, filters)
        result = await self.session.execute(statement)
        return result.scalar_one_or_none() is not None

    async def count(
        self,
        *,
        filters: Mapping[str, Any] | None = None,
        include_deleted: bool = False,
    ) -> int:
        result = await self.session.execute(
            self._count_statement(filters=filters, include_deleted=include_deleted)
        )
        return int(result.scalar_one())

    async def commit(self) -> None:
        try:
            await self.session.commit()
        except SQLAlchemyError as exc:
            await self.session.rollback()
            raise DatabaseError(str(exc)) from exc

    async def rollback(self) -> None:
        await self.session.rollback()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator["GenericRepository[ModelT]"]:
        transaction = (
            self.session.begin_nested()
            if self.session.in_transaction()
            else self.session.begin()
        )
        async with transaction:
            yield self

    async def _flush_or_raise(self) -> None:
        try:
            await self.session.flush()
        except IntegrityError as exc:
            await self.session.rollback()
            raise DuplicateRecordError(
                self.model.__name__, "unique constraint"
            ) from exc
        except SQLAlchemyError as exc:
            await self.session.rollback()
            raise DatabaseError(str(exc)) from exc

    def _base_select(self, *, include_deleted: bool) -> Select[tuple[ModelT]]:
        statement = select(self.model)
        if not include_deleted:
            statement = statement.where(self.model.is_deleted.is_(False))
        return statement

    def _filtered_statement(
        self,
        *,
        filters: Mapping[str, Any] | None,
        sort_by: str,
        sort_order: SortOrder,
        include_deleted: bool,
    ) -> Select[tuple[ModelT]]:
        statement = self._base_select(include_deleted=include_deleted)
        statement = apply_filters(statement, self.model, filters)
        return apply_sorting(statement, self.model, sort_by, sort_order)

    def _count_statement(
        self,
        *,
        filters: Mapping[str, Any] | None,
        include_deleted: bool,
    ) -> Select[tuple[int]]:
        statement = select(func.count()).select_from(self.model)
        if not include_deleted:
            statement = statement.where(self.model.is_deleted.is_(False))
        return apply_filters(statement, self.model, filters)

    def _assign(
        self,
        instance: ModelT,
        data: Mapping[str, Any],
        *,
        partial: bool,
    ) -> None:
        columns = {column.key for column in inspect(self.model).mapper.column_attrs}
        protected = {
            "id",
            "created_at",
            "created_by",
            "deleted_at",
            "is_deleted",
            "version",
        }
        for key, value in data.items():
            if partial and value is None:
                continue
            if key in columns and key not in protected:
                setattr(instance, key, value)
        instance.version += 1
