from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, or_
from sqlalchemy.orm import DeclarativeBase

from app.database.exceptions import InvalidFilterError


@dataclass(frozen=True, slots=True)
class AnyOfOrNull:
    """Filter value meaning ``column IN (values) OR column IS NULL``.

    For tables where a NULL column means "applies everywhere" (an
    organization-wide rule has ``location_id IS NULL``): a caller confined to
    some locations must still see the rows that apply at them. An empty
    ``values`` matches only the NULL rows.
    """

    values: tuple[Any, ...]


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
        if isinstance(value, AnyOfOrNull):
            statement = statement.where(
                or_(column.in_(list(value.values)), column.is_(None))
            )
        elif isinstance(value, list | tuple | set):
            statement = statement.where(column.in_(value))
        else:
            statement = statement.where(column == value)
    return statement
