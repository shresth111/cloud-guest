from types import SimpleNamespace

from sqlalchemy import String, select
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel
from app.database.constants import MAX_PAGE_SIZE, SortOrder
from app.database.exceptions import InvalidFilterError, InvalidSortError
from app.database.utils import (
    PageParams,
    PaginationMeta,
    apply_filters,
    apply_sorting,
    generate_uuid,
    paginate,
)
from app.database.utils import pagination as pagination_module


class DatabaseUtilityWidget(BaseModel):
    __tablename__ = "database_utility_widgets"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)


def test_generate_uuid_returns_unique_uuid_values() -> None:
    first = generate_uuid()
    second = generate_uuid()

    assert first != second
    assert first.version == 4


def test_page_params_normalizes_bounds() -> None:
    params = PageParams(page=-5, page_size=MAX_PAGE_SIZE + 500)

    assert params.page == 1
    assert params.page_size == MAX_PAGE_SIZE
    assert params.offset == 0


def test_page_params_uses_settings_default_page_size_when_unspecified(
    monkeypatch,
) -> None:
    """Enterprise SaaS Phase G: page_size is no longer a hardcoded literal
    frozen at import time -- an unspecified page_size resolves from
    ``Settings.pagination_default_page_size`` at construction time."""
    fake_settings = SimpleNamespace(
        pagination_default_page_size=7, pagination_max_page_size=50
    )
    monkeypatch.setattr(pagination_module, "get_settings", lambda: fake_settings)

    params = PageParams(page=1)

    assert params.page_size == 7


def test_page_params_clamps_to_settings_max_page_size(monkeypatch) -> None:
    fake_settings = SimpleNamespace(
        pagination_default_page_size=25, pagination_max_page_size=50
    )
    monkeypatch.setattr(pagination_module, "get_settings", lambda: fake_settings)

    params = PageParams(page=1, page_size=9999)

    assert params.page_size == 50


def test_pagination_meta_from_total() -> None:
    params = PageParams(page=2, page_size=25)

    meta = PaginationMeta.from_total(params, total_items=51)

    assert meta.total_pages == 3
    assert meta.has_next is True
    assert meta.has_previous is True


def test_paginate_applies_limit_and_offset() -> None:
    statement = paginate(
        select(DatabaseUtilityWidget), PageParams(page=3, page_size=10)
    )

    assert statement._limit_clause.value == 10
    assert statement._offset_clause.value == 20


def test_apply_filters_rejects_unknown_fields() -> None:
    statement = select(DatabaseUtilityWidget)

    try:
        apply_filters(statement, DatabaseUtilityWidget, {"unknown": "value"})
    except InvalidFilterError as exc:
        assert "unknown" in str(exc)
    else:
        raise AssertionError("InvalidFilterError was not raised")


def test_apply_sorting_rejects_unknown_fields() -> None:
    statement = select(DatabaseUtilityWidget)

    try:
        apply_sorting(statement, DatabaseUtilityWidget, "unknown", SortOrder.ASC)
    except InvalidSortError as exc:
        assert "unknown" in str(exc)
    else:
        raise AssertionError("InvalidSortError was not raised")

