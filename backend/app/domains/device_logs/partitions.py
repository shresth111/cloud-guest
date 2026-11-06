"""Monthly partitions of ``device_log_events``: create ahead, drop old.

``device_log_events`` is ``PARTITION BY RANGE (received_at)`` (migration
0167), one partition per calendar month in UTC named
``device_log_events_pYYYYMM``, plus ``device_log_events_default`` -- a
catch-all that exists only so ingest never fails because beat fell behind.

The nightly task (``tasks.run_partition_maintenance``) does two things:

1. **Create ahead.** Every month from the current one to
   ``device_logs_partitions_ahead`` months ahead gets its partition. If the
   DEFAULT partition already holds rows for that month (beat was down), the
   rows are moved into a fresh table and that table is attached -- a plain
   ``CREATE ... PARTITION OF`` would fail on them.
2. **Drop old.** A month partition whose whole range ends on or before
   ``first day of this month - device_logs_retention_months`` is dropped,
   after deleting the ``guest_device_events`` derived from it (no FK since
   0167, so nothing cascades). Old rows that ended up in DEFAULT are deleted
   by the same cutoff.

Only names this module generates are ever dropped: a table attached under
any other name is reported and left alone.

The planning (which months to create and drop) is pure and unit-tested; the
SQL runs in one transaction under an advisory lock, so two overlapping runs
cannot both create the same partition.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .constants import DEFAULT_PARTITION, PARTITION_PREFIX

logger = logging.getLogger(__name__)

PARENT = "device_log_events"
_NAME = re.compile(rf"^{re.escape(PARTITION_PREFIX)}(\d{{4}})(\d{{2}})$")
#: Arbitrary, fixed: "device_log_events partition maintenance".
_ADVISORY_LOCK_KEY = 815_150_167


def month_start(value: date | datetime) -> date:
    return date(value.year, value.month, 1)


def add_months(value: date, months: int) -> date:
    index = value.year * 12 + (value.month - 1) + months
    return date(index // 12, index % 12 + 1, 1)


def partition_name(month: date) -> str:
    return f"{PARTITION_PREFIX}{month.year:04d}{month.month:02d}"


def month_of(name: str) -> date | None:
    match = _NAME.match(name)
    if match is None:
        return None
    year, month = int(match.group(1)), int(match.group(2))
    if not 1 <= month <= 12:
        return None
    return date(year, month, 1)


@dataclass(frozen=True)
class PartitionPlan:
    create: tuple[date, ...]
    drop: tuple[date, ...]
    #: Rows older than this are past retention (also in DEFAULT).
    cutoff: date
    #: Attached partitions whose names this module did not generate.
    unknown: tuple[str, ...]


def plan_partitions(
    existing: list[str],
    *,
    now: datetime,
    retention_months: int,
    ahead: int,
) -> PartitionPlan:
    """Which months to create and which to drop. ``existing`` is every
    partition currently attached (DEFAULT included or not)."""
    if retention_months < 1:
        raise ValueError("retention_months must be >= 1")
    current = month_start(now.astimezone(UTC))
    have: set[date] = set()
    unknown: list[str] = []
    for name in existing:
        if name == DEFAULT_PARTITION:
            continue
        month = month_of(name)
        if month is None:
            unknown.append(name)
        else:
            have.add(month)
    wanted = [add_months(current, i) for i in range(0, ahead + 1)]
    cutoff = add_months(current, -retention_months)
    # A month is past retention when its range [month, month+1) ends on or
    # before the cutoff.
    drop = sorted(m for m in have if add_months(m, 1) <= cutoff)
    return PartitionPlan(
        create=tuple(m for m in wanted if m not in have),
        drop=tuple(drop),
        cutoff=cutoff,
        unknown=tuple(sorted(unknown)),
    )


def _dt(month: date) -> datetime:
    """A month boundary as a bound parameter (UTC midnight)."""
    return datetime(month.year, month.month, 1, tzinfo=UTC)


def _ts(month: date) -> str:
    """A UTC timestamptz literal for a month boundary (built from a date we
    generated, never from input)."""
    return f"{month.isoformat()} 00:00:00+00"


async def attached_partitions(session: AsyncSession) -> list[str]:
    rows = await session.execute(
        text(
            "SELECT c.relname FROM pg_inherits i "
            "JOIN pg_class c ON c.oid = i.inhrelid "
            "JOIN pg_class p ON p.oid = i.inhparent "
            "WHERE p.relname = :parent"
        ),
        {"parent": PARENT},
    )
    return [str(r[0]) for r in rows.all()]


async def _default_exists(session: AsyncSession) -> bool:
    found = await session.execute(
        text("SELECT to_regclass(:name) IS NOT NULL"), {"name": DEFAULT_PARTITION}
    )
    return bool(found.scalar_one())


async def _create_month(
    session: AsyncSession, month: date, *, has_default: bool
) -> int:
    """Create (or build-and-attach) one month's partition. Returns how many
    rows were moved out of DEFAULT."""
    name = partition_name(month)
    lo, hi = _ts(month), _ts(add_months(month, 1))
    bounds = {"lo": _dt(month), "hi": _dt(add_months(month, 1))}
    moved = 0
    if has_default:
        stray = await session.execute(
            text(
                f"SELECT count(*) FROM {DEFAULT_PARTITION} "  # noqa: S608 -- generated names
                "WHERE received_at >= :lo "
                "AND received_at < :hi"
            ),
            bounds,
        )
        moved = int(stray.scalar_one())
    if moved == 0:
        await session.execute(
            text(
                f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF {PARENT} "
                f"FOR VALUES FROM ('{lo}') TO ('{hi}')"
            )
        )
        return 0
    # DEFAULT holds rows for this month: move them, then attach. Ids are
    # copied as-is (a LIKE copy has no identity), so keyset cursors and
    # guest_device_events.device_log_event_id stay valid.
    await session.execute(
        text(
            f"CREATE TABLE {name} (LIKE {PARENT} INCLUDING DEFAULTS "
            "INCLUDING CONSTRAINTS)"
        )
    )
    await session.execute(
        text(
            f"WITH moved AS (DELETE FROM {DEFAULT_PARTITION} "  # noqa: S608
            "WHERE received_at >= :lo "
            "AND received_at < :hi RETURNING *) "
            f"INSERT INTO {name} SELECT * FROM moved"
        ),
        bounds,
    )
    await session.execute(
        text(
            f"ALTER TABLE {PARENT} ATTACH PARTITION {name} "
            f"FOR VALUES FROM ('{lo}') TO ('{hi}')"
        )
    )
    return moved


async def _drop_month(session: AsyncSession, month: date) -> int:
    derived = await session.execute(
        text(
            "DELETE FROM guest_device_events "
            "WHERE occurred_at >= :lo "
            "AND occurred_at < :hi"
        ),
        {"lo": _dt(month), "hi": _dt(add_months(month, 1))},
    )
    await session.execute(text(f"DROP TABLE IF EXISTS {partition_name(month)}"))
    return int(derived.rowcount or 0)


async def maintain_partitions(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    retention_months: int,
    ahead: int,
) -> dict[str, Any]:
    """One maintenance pass. The caller commits. Skips (``locked: True``)
    when another pass holds the advisory lock."""
    moment = now or datetime.now(UTC)
    got = await session.execute(
        text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": _ADVISORY_LOCK_KEY}
    )
    if not got.scalar_one():
        return {"locked": True}
    # Never wait behind a long reader holding the parent: fail this run and
    # let tomorrow's retry (or the next manual run) do it.
    await session.execute(text("SET LOCAL lock_timeout = '10s'"))

    plan = plan_partitions(
        await attached_partitions(session),
        now=moment,
        retention_months=retention_months,
        ahead=ahead,
    )
    has_default = await _default_exists(session)
    moved = 0
    for month in plan.create:
        moved += await _create_month(session, month, has_default=has_default)
    derived_deleted = 0
    for month in plan.drop:
        derived_deleted += await _drop_month(session, month)
    default_pruned = 0
    if has_default:
        cutoff = _dt(plan.cutoff)
        derived = await session.execute(
            text(
                "DELETE FROM guest_device_events g USING "
                f"{DEFAULT_PARTITION} d WHERE g.device_log_event_id = d.id "  # noqa: S608
                "AND d.received_at < :cutoff"
            ),
            {"cutoff": cutoff},
        )
        derived_deleted += int(derived.rowcount or 0)
        pruned = await session.execute(
            text(
                f"DELETE FROM {DEFAULT_PARTITION} "  # noqa: S608
                "WHERE received_at < :cutoff"
            ),
            {"cutoff": cutoff},
        )
        default_pruned = int(pruned.rowcount or 0)
    if plan.unknown:
        logger.warning(
            "device_logs_partition_unknown_names",
            extra={"partition_names": list(plan.unknown)},
        )
    return {
        "locked": False,
        "created": [partition_name(m) for m in plan.create],
        "dropped": [partition_name(m) for m in plan.drop],
        "moved_from_default": moved,
        "default_rows_pruned": default_pruned,
        "derived_rows_deleted": derived_deleted,
        "cutoff": plan.cutoff.isoformat(),
        "unknown": list(plan.unknown),
    }
