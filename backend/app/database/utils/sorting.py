from sqlalchemy import Select, asc, desc
from sqlalchemy.orm import DeclarativeBase

from app.database.constants import SortOrder
from app.database.exceptions import InvalidSortError


def apply_sorting(
    statement: Select,
    model: type[DeclarativeBase],
    sort_by: str,
    sort_order: SortOrder = SortOrder.DESC,
) -> Select:
    if not hasattr(model, sort_by):
        raise InvalidSortError(sort_by)

    column = getattr(model, sort_by)
    sort_expression = asc(column) if sort_order == SortOrder.ASC else desc(column)
    return statement.order_by(sort_expression)

