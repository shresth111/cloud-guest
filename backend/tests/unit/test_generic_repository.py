import asyncio
from unittest.mock import AsyncMock, MagicMock

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel
from app.database.constants import SortOrder
from app.database.repositories import GenericRepository


class RepositoryWidget(BaseModel):
    __tablename__ = "repository_widgets"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)


def test_repository_create_adds_model_and_flushes() -> None:
    session = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    repository = GenericRepository(RepositoryWidget, session)

    async def run() -> RepositoryWidget:
        return await repository.create({"name": "Lobby", "status": "active"})

    instance = asyncio.run(run())

    session.add.assert_called_once()
    session.flush.assert_awaited_once()
    session.refresh.assert_awaited_once_with(instance)
    assert instance.name == "Lobby"
    assert instance.status == "active"


def test_partial_update_skips_none_and_increments_version() -> None:
    session = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    repository = GenericRepository(RepositoryWidget, session)
    instance = RepositoryWidget(name="Lobby", status="active")
    instance.version = 1

    async def run() -> RepositoryWidget:
        return await repository.partial_update(
            instance,
            {"name": None, "status": "disabled"},
        )

    updated = asyncio.run(run())

    assert updated.name == "Lobby"
    assert updated.status == "disabled"
    assert updated.version == 2
    session.flush.assert_awaited_once()


def test_repository_get_all_builds_excluding_deleted_by_default() -> None:
    session = MagicMock()
    repository = GenericRepository(RepositoryWidget, session)

    statement = repository._filtered_statement(
        filters={"status": "active"},
        sort_by="created_at",
        sort_order=SortOrder.DESC,
        include_deleted=False,
    )
    compiled = str(statement.compile(compile_kwargs={"literal_binds": True}))

    assert "is_deleted IS false" in compiled
    assert "status = 'active'" in compiled
    assert "ORDER BY" in compiled


def test_repository_soft_delete_uses_model_method() -> None:
    session = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    repository = GenericRepository(RepositoryWidget, session)
    instance = RepositoryWidget(name="Lobby", status="active")

    async def run() -> RepositoryWidget:
        return await repository.soft_delete(instance)

    deleted = asyncio.run(run())

    assert deleted.is_deleted is True
    assert deleted.deleted_at is not None
    session.flush.assert_awaited_once()
