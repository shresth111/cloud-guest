"""Real, collision-safe, concurrency-safe ``Location.location_code``
generation (Smart Location Provisioning) -- ``"LOC-2026-000001"``.

Mirrors ``app.domains.billing.number_generator`` exactly -- the same
``models.LocationCodeCounter`` unique-``counter_key`` table, the same single
atomic Postgres ``INSERT ... ON CONFLICT (counter_key) DO UPDATE SET
last_value = last_value + 1 ... RETURNING last_value`` statement (via
SQLAlchemy's ``postgresql.insert(...).on_conflict_do_update(...)``), and the
same reasoning for why this is genuinely (not just apparently) safe under
concurrency:

1. No read-then-write round trip from application code -- the increment is
   computed by Postgres itself, evaluating the ``SET`` clause against the
   row's value at the instant the statement executes.
2. Postgres serializes concurrent UPSERTs targeting the same ``counter_key``
   row (a real row-level lock for the duration of the ``DO UPDATE``), so two
   concurrent callers can never observe the same "before" value or compute
   the same "next" value.

This is deliberately the *same* mechanism ``app.domains.billing
.number_generator`` established, not a new one -- see that module's own
docstring for the full write-up this one intentionally does not repeat, and
``docs/location/FLOW.md``'s "location_code generation" section for the
cross-reference. ``counter_key`` includes the calendar year
(``"location:<year>"``) so the sequence resets to 1 at the start of each new
year, the same convention ``InvoiceNumberCounter`` uses.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

_LOCATION_CODE_PREFIX = "LOC"
_SEQUENCE_DIGITS = 6


class LocationCodeCounterRepositoryProtocol(Protocol):
    """The single method this module needs -- satisfied by
    ``repository.LocationCodeCounterRepository`` (a real, atomic Postgres
    UPSERT) for production use, and by a small in-memory fake in this
    domain's own tests."""

    async def increment_and_get_next(self, counter_key: str) -> int: ...


def _counter_key(year: int) -> str:
    return f"location:{year}"


def _format_code(year: int, sequence: int) -> str:
    return f"{_LOCATION_CODE_PREFIX}-{year}-{sequence:0{_SEQUENCE_DIGITS}d}"


async def generate_location_code(
    repository: LocationCodeCounterRepositoryProtocol, *, at: datetime
) -> str:
    """``"LOC-2026-000001"``-shaped, real, collision-safe -- see module
    docstring for the exact concurrency mechanism."""
    year = at.year
    sequence = await repository.increment_and_get_next(_counter_key(year))
    return _format_code(year, sequence)


__all__ = [
    "LocationCodeCounterRepositoryProtocol",
    "generate_location_code",
]
