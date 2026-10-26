"""SMS delivery log: forward-only DLR application, the DLR poller, the
day-wise report and retention.

## Forward-only

A delivery report only ever moves a row out of ``sent``:

    sent -> delivered | undelivered

and the move is one conditional ``UPDATE ... WHERE status = 'sent'``, so it
is atomic and idempotent. A duplicate report, a second report after a final
one, or a stale "pending" arriving after "delivered" all match zero rows and
change nothing. ``failed`` (the provider refused the send) is never touched by
a DLR -- it has no message id to be reported on.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from collections.abc import Callable, Iterable
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import and_, case, delete, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger

from .constants import (
    DLR_POLL_BATCH_SIZE,
    DLR_POLL_INTERVAL_SECONDS,
    DLR_POLL_MAX_ATTEMPTS,
    DLR_POLL_MIN_AGE_SECONDS,
    DLR_POLL_WINDOW_HOURS,
    PING4SMS_DLR_URL,
    RETENTION_DELETE_BATCH,
    DlrSource,
    ProviderSource,
    SmsDeliveryStatus,
)
from .dlr import parse_poll_answer, scrub
from .models import SmsDeliveryLog

logger = get_logger(__name__)

_SENT = SmsDeliveryStatus.SENT.value


# ---------------------------------------------------------------------------
# DLR application
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class DlrOutcome:
    matched: bool
    applied: bool
    status: str | None


async def apply_dlr(
    session: AsyncSession,
    *,
    provider: str,
    provider_message_id: str,
    status: SmsDeliveryStatus | None,
    source: DlrSource,
    raw: str | None,
    now: datetime | None = None,
) -> DlrOutcome:
    """Apply one delivery report to the Wyfy-sent row it names.

    ``status`` is the already-classified final status, or ``None`` when the
    report did not name one (the raw answer is still kept on the row). Only
    rows sent through Wyfy's own provider account are matched -- a venue's own
    account has a separate message-id space. The caller commits.
    """
    now = now or datetime.now(UTC)
    raw_kept = scrub(raw, limit=120)
    match = and_(
        SmsDeliveryLog.provider == provider,
        SmsDeliveryLog.provider_message_id == provider_message_id,
        SmsDeliveryLog.provider_source == ProviderSource.WYFY.value,
    )
    if status is not None:
        result = await session.execute(
            update(SmsDeliveryLog)
            .where(match, SmsDeliveryLog.status == _SENT)
            .values(
                status=status.value,
                status_updated_at=now,
                dlr_received_at=now,
                dlr_source=source.value,
                dlr_raw=raw_kept,
            )
            .returning(SmsDeliveryLog.id)
        )
        if result.first() is not None:
            return DlrOutcome(matched=True, applied=True, status=status.value)
    else:
        # Not a final status: keep the provider's words on a still-open row,
        # nothing else.
        result = await session.execute(
            update(SmsDeliveryLog)
            .where(match, SmsDeliveryLog.status == _SENT)
            .values(dlr_raw=raw_kept)
            .returning(SmsDeliveryLog.id)
        )
        if result.first() is not None:
            return DlrOutcome(matched=True, applied=False, status=_SENT)
    current = (
        await session.execute(select(SmsDeliveryLog.status).where(match).limit(1))
    ).scalar_one_or_none()
    return DlrOutcome(matched=current is not None, applied=False, status=current)


# ---------------------------------------------------------------------------
# DLR poller (Ping4SMS)
# ---------------------------------------------------------------------------


def silence_url_logging() -> None:
    """httpx logs every request's full URL at INFO, and the Ping4SMS DLR
    query carries the API key. Raise its loggers to WARNING in the process
    that polls (cloud-guest PR #330 does this platform-wide; this keeps the
    poller safe whether or not that has merged)."""
    for name in ("httpx", "httpcore"):
        named = logging.getLogger(name)
        if named.getEffectiveLevel() < logging.WARNING:
            named.setLevel(logging.WARNING)


async def _fetch_ping4sms_dlr(api_key: str, message_id: str) -> str:
    import httpx

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            PING4SMS_DLR_URL, params={"key": api_key, "messageid": message_id}
        )
        response.raise_for_status()
        return response.text


async def poll_ping4sms_dlrs(
    session: AsyncSession,
    *,
    api_key: str,
    fetch: Callable[[str, str], Any] | None = None,
    now: datetime | None = None,
    batch_size: int = DLR_POLL_BATCH_SIZE,
) -> dict[str, int]:
    """Ask Ping4SMS for the delivery status of recent Wyfy-sent rows still at
    ``sent``. A row changes only on a recognised final status (see
    ``dlr.parse_poll_answer``); every answer is kept, scrubbed, in
    ``dlr_raw``. Commits per row so a slow provider never holds a lock."""
    fetch = fetch or _fetch_ping4sms_dlr
    now = now or datetime.now(UTC)
    rows = (
        await session.execute(
            select(SmsDeliveryLog.id, SmsDeliveryLog.provider_message_id)
            .where(
                SmsDeliveryLog.status == _SENT,
                SmsDeliveryLog.provider == "ping4sms",
                SmsDeliveryLog.provider_source == ProviderSource.WYFY.value,
                SmsDeliveryLog.provider_message_id.is_not(None),
                SmsDeliveryLog.created_at
                >= now - timedelta(hours=DLR_POLL_WINDOW_HOURS),
                SmsDeliveryLog.created_at
                <= now - timedelta(seconds=DLR_POLL_MIN_AGE_SECONDS),
                SmsDeliveryLog.dlr_poll_count < DLR_POLL_MAX_ATTEMPTS,
                or_(
                    SmsDeliveryLog.last_dlr_poll_at.is_(None),
                    SmsDeliveryLog.last_dlr_poll_at
                    <= now - timedelta(seconds=DLR_POLL_INTERVAL_SECONDS),
                ),
            )
            .order_by(SmsDeliveryLog.created_at)
            .limit(batch_size)
        )
    ).all()
    summary = {
        "polled": 0,
        "delivered": 0,
        "undelivered": 0,
        "unchanged": 0,
        "errors": 0,
    }
    for row_id, message_id in rows:
        summary["polled"] += 1
        await session.execute(
            update(SmsDeliveryLog)
            .where(SmsDeliveryLog.id == row_id)
            .values(
                dlr_poll_count=SmsDeliveryLog.dlr_poll_count + 1,
                last_dlr_poll_at=now,
            )
        )
        try:
            body = await fetch(api_key, message_id)
        except Exception as exc:  # noqa: BLE001 -- one bad answer must not stop the sweep
            summary["errors"] += 1
            logger.warning(
                "sms_dlr_poll_failed",
                extra={"sms_log_id": str(row_id), "error_type": type(exc).__name__},
            )
            await session.commit()
            continue
        outcome = await apply_dlr(
            session,
            provider="ping4sms",
            provider_message_id=message_id,
            status=parse_poll_answer(body),
            source=DlrSource.POLL,
            raw=body,
            now=now,
        )
        await session.commit()
        if outcome.applied and outcome.status:
            summary[outcome.status] += 1
        else:
            summary["unchanged"] += 1
    return summary


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class ReportScope:
    """Already-authorized scope. ``location_filter`` is what
    ``confine_location_filter`` returned: ``None`` (whole org), one id, or a
    list of ids (possibly empty, which matches nothing)."""

    organization_id: uuid.UUID
    location_filter: uuid.UUID | list[uuid.UUID] | None


_COUNT_KEYS = (
    "attempted",
    "sent",
    "failed",
    "delivered",
    "undelivered",
    "awaiting_dlr",
)


def _empty_counts() -> dict[str, int]:
    return dict.fromkeys(_COUNT_KEYS, 0)


def build_report_query(
    scope: ReportScope,
    *,
    start: date,
    end: date,
    tz: str,
    purpose: str | None = None,
):
    """``SELECT day, location_id, purpose, counts...`` for one organization.

    The organization filter is unconditional -- there is no "all
    organizations" form of this query. Days are bucketed in ``tz`` (the
    venue's clock, not UTC). ``start``/``end`` are inclusive local dates.
    """
    zone = ZoneInfo(tz)
    start_utc = datetime.combine(start, datetime.min.time(), tzinfo=zone)
    end_utc = datetime.combine(
        end + timedelta(days=1), datetime.min.time(), tzinfo=zone
    )
    day = func.date(func.timezone(tz, SmsDeliveryLog.created_at)).label("day")
    status = SmsDeliveryLog.status

    def _count(condition) -> Any:  # noqa: ANN001
        return func.sum(case((condition, 1), else_=0))

    query = (
        select(
            day,
            SmsDeliveryLog.location_id,
            SmsDeliveryLog.purpose,
            func.count().label("attempted"),
            _count(status != SmsDeliveryStatus.FAILED.value).label("sent"),
            _count(status == SmsDeliveryStatus.FAILED.value).label("failed"),
            _count(status == SmsDeliveryStatus.DELIVERED.value).label("delivered"),
            _count(status == SmsDeliveryStatus.UNDELIVERED.value).label("undelivered"),
            _count(status == _SENT).label("awaiting_dlr"),
            _count(SmsDeliveryLog.dlr_received_at.is_not(None)).label("dlr_received"),
        )
        .where(
            SmsDeliveryLog.organization_id == scope.organization_id,
            SmsDeliveryLog.created_at >= start_utc,
            SmsDeliveryLog.created_at < end_utc,
        )
        # Positional: the day expression carries a bound ``tz`` parameter, and
        # Postgres does not treat ``$1`` in SELECT and ``$9`` in GROUP BY as
        # the same expression.
        .group_by(text("1"), text("2"), text("3"))
    )
    if isinstance(scope.location_filter, list):
        query = query.where(SmsDeliveryLog.location_id.in_(scope.location_filter))
    elif scope.location_filter is not None:
        query = query.where(SmsDeliveryLog.location_id == scope.location_filter)
    if purpose is not None:
        query = query.where(SmsDeliveryLog.purpose == purpose)
    return query


def fold_report_rows(rows: Iterable[Any], *, start: date, end: date) -> dict[str, Any]:
    """Fold grouped rows into the report payload: one entry per calendar day
    in range (zero-filled -- an empty day is a real zero, not missing data),
    plus totals by location and by purpose."""
    days: dict[date, dict[str, int]] = {}
    cursor = start
    while cursor <= end:
        days[cursor] = _empty_counts()
        cursor += timedelta(days=1)
    by_location: dict[str | None, dict[str, int]] = {}
    by_purpose: dict[str, dict[str, int]] = {}
    totals = _empty_counts()
    dlr_received = 0
    for row in rows:
        mapping = row._mapping if hasattr(row, "_mapping") else row
        day_value = mapping["day"]
        if isinstance(day_value, datetime):
            day_value = day_value.date()
        elif isinstance(day_value, str):
            day_value = date.fromisoformat(day_value)
        location_key = (
            str(mapping["location_id"]) if mapping["location_id"] is not None else None
        )
        buckets = [
            days.setdefault(day_value, _empty_counts()),
            by_location.setdefault(location_key, _empty_counts()),
            by_purpose.setdefault(str(mapping["purpose"]), _empty_counts()),
            totals,
        ]
        for key in _COUNT_KEYS:
            value = int(mapping[key] or 0)
            for bucket in buckets:
                bucket[key] += value
        dlr_received += int(mapping.get("dlr_received", 0) or 0)
    return {
        "days": [
            {"date": d.isoformat(), **counts} for d, counts in sorted(days.items())
        ],
        "by_location": [
            {"location_id": loc, **counts} for loc, counts in by_location.items()
        ],
        "by_purpose": [{"purpose": p, **counts} for p, counts in by_purpose.items()],
        "totals": totals,
        "dlr_received": dlr_received,
    }


async def build_report(
    session: AsyncSession,
    scope: ReportScope,
    *,
    start: date,
    end: date,
    tz: str,
    purpose: str | None = None,
) -> dict[str, Any]:
    if isinstance(scope.location_filter, list) and not scope.location_filter:
        return fold_report_rows([], start=start, end=end)
    rows = (
        await session.execute(
            build_report_query(scope, start=start, end=end, tz=tz, purpose=purpose)
        )
    ).all()
    return fold_report_rows(rows, start=start, end=end)


def delivery_reports_state(settings: Any) -> dict[str, Any]:
    """Whether any real DLR mechanism is switched on, and what is missing
    when not. Reported as-is to the UI; it never claims more than config."""
    provider = (getattr(settings, "sms_delivery_provider", "") or "").lower()
    poll = bool(
        provider == "ping4sms"
        and getattr(settings, "sms_dlr_poll_enabled", False)
        and getattr(settings, "ping4sms_api_key", "")
    )
    webhook = bool(getattr(settings, "sms_dlr_webhook_token", ""))
    mechanisms = [m for m, on in (("poll", poll), ("webhook", webhook)) if on]
    return {"enabled": bool(mechanisms), "mechanisms": mechanisms, "provider": provider}


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


async def prune_logs(
    session: AsyncSession, *, retention_days: int, now: datetime | None = None
) -> int:
    """Delete rows older than ``retention_days`` in batches (short locks on a
    box that also serves the API, same as the platform retention job)."""
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=retention_days)
    total = 0
    while True:
        ids = (
            (
                await session.execute(
                    select(SmsDeliveryLog.id)
                    .where(SmsDeliveryLog.created_at < cutoff)
                    .limit(RETENTION_DELETE_BATCH)
                )
            )
            .scalars()
            .all()
        )
        if not ids:
            break
        await session.execute(delete(SmsDeliveryLog).where(SmsDeliveryLog.id.in_(ids)))
        await session.commit()
        total += len(ids)
        if len(ids) < RETENTION_DELETE_BATCH:
            break
    return total


__all__ = [
    "DlrOutcome",
    "ReportScope",
    "apply_dlr",
    "build_report",
    "build_report_query",
    "delivery_reports_state",
    "fold_report_rows",
    "poll_ping4sms_dlrs",
    "prune_logs",
    "silence_url_logging",
]
