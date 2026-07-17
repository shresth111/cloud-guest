from collections.abc import Mapping
from typing import Any

from sqlalchemy import Select
from sqlalchemy.orm import DeclarativeBase

from app.database.exceptions import InvalidFilterError


def apply_filters(
    statement: Select,
    model: type[DeclarativeBase],
    filters: Mapping[str, Any] | None,
) -> Select:
    if not filters:
        return statement

    for field, value in filters.items():
        if value is None:
            continue
        if not hasattr(model, field):
            raise InvalidFilterError(field)
        column = getattr(model, field)
        if isinstance(value, list | tuple | set):
            statement = statement.where(column.in_(value))
        else:
            statement = statement.where(column == value)
    return statement

