from enum import StrEnum

DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
DEFAULT_PAGE = 1
DEFAULT_LIMIT = 100
MAX_BULK_CREATE_SIZE = 1_000
DEFAULT_SORT_FIELD = "created_at"


class SortOrder(StrEnum):
    ASC = "asc"
    DESC = "desc"

