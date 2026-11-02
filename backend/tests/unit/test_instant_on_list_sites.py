"""The Master site list must not show a site whose fleet router was deleted."""

from __future__ import annotations

from typing import Any

import pytest

from app.domains.network_integration.instant_on_repository import InstantOnRepository


class _Result:
    def scalars(self) -> _Result:
        return self

    def all(self) -> list[Any]:
        return []


class _Session:
    def __init__(self) -> None:
        self.statement: Any = None

    async def execute(self, statement: Any) -> _Result:
        self.statement = statement
        return _Result()


@pytest.mark.asyncio
async def test_list_sites_excludes_rows_of_deleted_routers() -> None:
    session = _Session()
    await InstantOnRepository(session).list_sites(limit=10)  # type: ignore[arg-type]
    sql = " ".join(str(session.statement).split())
    assert "JOIN routers ON routers.id = instant_on_sites.router_id" in sql
    assert "routers.is_deleted IS false" in sql
    assert "instant_on_sites.is_deleted IS false" in sql
