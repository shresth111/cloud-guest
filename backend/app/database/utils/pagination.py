from dataclasses import dataclass
from math import ceil

from sqlalchemy import Select

from app.database.constants import DEFAULT_PAGE, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE


@dataclass(frozen=True, slots=True)
class PageParams:
    page: int = DEFAULT_PAGE
    page_size: int = DEFAULT_PAGE_SIZE

    def __post_init__(self) -> None:
        normalized_page = max(self.page, DEFAULT_PAGE)
        normalized_size = min(max(self.page_size, 1), MAX_PAGE_SIZE)
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

