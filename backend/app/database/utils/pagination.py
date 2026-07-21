from dataclasses import dataclass
from math import ceil

from sqlalchemy import Select

from app.core.config import get_settings
from app.database.constants import DEFAULT_PAGE


@dataclass(frozen=True, slots=True)
class PageParams:
    page: int = DEFAULT_PAGE
    # None -- not a hardcoded literal -- so a caller who doesn't specify
    # page_size gets Settings.pagination_default_page_size (Enterprise
    # SaaS Phase G), not a value frozen at class-definition time. The
    # class-level DEFAULT_PAGE_SIZE import above is gone on purpose: it
    # would be evaluated once, at import time, before Settings could ever
    # override it.
    page_size: int | None = None

    def __post_init__(self) -> None:
        settings = get_settings()
        resolved_size = (
            self.page_size
            if self.page_size is not None
            else settings.pagination_default_page_size
        )
        normalized_page = max(self.page, DEFAULT_PAGE)
        normalized_size = min(
            max(resolved_size, 1), settings.pagination_max_page_size
        )
        object.__setattr__(self, "page", normalized_page)
        object.__setattr__(self, "page_size", normalized_size)

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


@dataclass(frozen=True, slots=True)
class PaginationMeta:
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool

    @classmethod
    def from_total(cls, params: PageParams, total_items: int) -> "PaginationMeta":
        total_pages = ceil(total_items / params.page_size) if total_items else 0
        return cls(
            page=params.page,
            page_size=params.page_size,
            total_items=total_items,
            total_pages=total_pages,
            has_next=params.page < total_pages,
            has_previous=params.page > 1 and total_pages > 0,
        )


def paginate(statement: Select, params: PageParams) -> Select:
    return statement.limit(params.page_size).offset(params.offset)

