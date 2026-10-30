"""Record "portal opened" for the login funnel -- without ever costing a
guest anything.

## Where the signal comes from

The portal runtime's first call on every page load is
``GET /captive-portal/resolve`` (cloudguest-foundation
``PortalRuntimeContext.tsx``). The dashboard's Portal Preview calls the same
endpoint, so the runtime marks a real guest load with
``record_impression=true`` (sent once per mounted runtime, not on react-query
refetches) and the endpoint schedules :func:`schedule_portal_impression`.
A request without the marker records nothing.

## Never on the guest's critical path

* The write runs in a detached ``asyncio`` task on its own session from
  ``SessionLocal``; the resolve response does not wait for it, and the
  resolve endpoint's cached path keeps its zero-database cost.
* At most ``MAX_IN_FLIGHT`` writes run at once per process. Past that an
  impression is **dropped** (counted in a debug log), not queued: under a
  burst the funnel undercounts slightly rather than the portal holding
  connections from the pool every guest login needs.
* Each write is bounded by ``WRITE_TIMEOUT_SECONDS`` and a matching
  ``statement_timeout``; every failure is caught and logged at WARNING.
  Nothing here can raise into the request.

## One statement, tenant-checked in SQL

``INSERT ... SELECT FROM locations``: the row is written only if the location
exists, is not deleted and belongs to the organization the resolve resolved
to; ``router_id`` is kept only if that router is at that location, else NULL.
The dedupe check (same device, same venue, within ``DEDUPE_WINDOW``) is a
``NOT EXISTS`` in the same statement, so a reload storm costs one indexed
probe per load and writes one row. Two loads racing inside the same
millisecond can both land; that is accepted.

## No personal data

The MAC is reduced to :func:`portal_device_key` -- HMAC-SHA256 keyed with the
application secret and salted with the organization id -- before it leaves
this module. No IP, user agent or phone is ever stored. A load with no
parseable MAC is recorded without a device key and is not deduplicated.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, delete, exists, literal, select, text
from sqlalchemy import insert as sa_insert

from app.core.config import get_settings
from app.core.logging import get_logger
from app.domains.guest.validators import canonical_mac_key
from app.domains.location.models import Location
from app.domains.router.models import Router

from .models import PortalImpression

logger = get_logger(__name__)

#: One device reloading the portal inside this window is one impression.
DEDUPE_WINDOW = timedelta(minutes=10)
#: Concurrent impression writes per API process; beyond this they are dropped.
MAX_IN_FLIGHT = 4
WRITE_TIMEOUT_SECONDS = 3.0
#: Matches the venue-insight endpoints' longest window (92 days).
PORTAL_IMPRESSION_RETENTION_DAYS = 92
RETENTION_DELETE_BATCH_SIZE = 5_000
RETENTION_MAX_BATCHES_PER_RUN = 200

_DEVICE_KEY_DOMAIN = b"wyfy.portal-impression.v1"

_in_flight: set[asyncio.Task[Any]] = set()


def portal_device_key(organization_id: uuid.UUID, device_mac: str | None) -> str | None:
    """Keyed, per-organization hash of a device MAC, or ``None`` when the
    value is not a six-octet MAC. Separator- and case-insensitive."""
    canonical = canonical_mac_key(device_mac)
    if canonical is None:
        return None
    secret = get_settings().jwt_secret_key.encode("utf-8")
    message = b"|".join(
        (_DEVICE_KEY_DOMAIN, str(organization_id).encode(), canonical.encode())
    )
    return hmac.new(secret, message, hashlib.sha256).hexdigest()[:32]


def build_impression_insert(
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    router_id: uuid.UUID | None,
    device_key: str | None,
    occurred_at: datetime,
):
    """The single ``INSERT ... SELECT`` described in the module docstring."""
    router_subquery = (
        select(Router.id)
        .where(
            Router.id == router_id,
            Router.location_id == Location.id,
            Router.organization_id == Location.organization_id,
            Router.is_deleted.is_(False),
        )
        .scalar_subquery()
        if router_id is not None
        else literal(None)
    )
    conditions = [
        Location.id == location_id,
        Location.organization_id == organization_id,
        Location.is_deleted.is_(False),
    ]
    if device_key is not None:
        conditions.append(
            ~exists(
                select(PortalImpression.id).where(
                    PortalImpression.location_id == location_id,
                    PortalImpression.client_mac_hash == device_key,
                    PortalImpression.occurred_at > occurred_at - DEDUPE_WINDOW,
                )
            )
        )
    source = select(
        literal(uuid.uuid4()),
        Location.organization_id,
        Location.id,
        router_subquery,
        literal(occurred_at),
        literal(device_key),
    ).where(and_(*conditions))
    return sa_insert(PortalImpression).from_select(
        [
            "id",
            "organization_id",
            "location_id",
            "router_id",
            "occurred_at",
            "client_mac_hash",
        ],
        source,
    )


def _default_session_factory():
    from app.database.session import SessionLocal

    return SessionLocal()


async def record_portal_impression(
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    router_id: uuid.UUID | None,
    device_mac: str | None,
    occurred_at: datetime | None = None,
    session_factory: Callable[[], Any] = _default_session_factory,
) -> bool:
    """Write one impression. Returns whether a row was written (``False``
    for a dedupe hit, a location outside the organization, or any error).
    Never raises."""
    moment = occurred_at or datetime.now(UTC)
    try:
        device_key = portal_device_key(organization_id, device_mac)
        statement = build_impression_insert(
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
            device_key=device_key,
            occurred_at=moment,
        )

        async def _write() -> bool:
            async with session_factory() as session:
                ms = int(WRITE_TIMEOUT_SECONDS * 1000)
                await session.execute(text(f"SET LOCAL statement_timeout = {ms}"))
                result = await session.execute(statement)
                await session.commit()
                return bool(result.rowcount)

        return await asyncio.wait_for(_write(), timeout=WRITE_TIMEOUT_SECONDS + 1)
    except Exception as exc:  # noqa: BLE001 -- see module docstring
        logger.warning(
            "portal_impression_write_failed",
            extra={
                "organization_id": str(organization_id),
                "location_id": str(location_id),
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
        return False


def schedule_portal_impression(**kwargs: Any) -> bool:
    """Fire-and-forget :func:`record_portal_impression`. Returns whether it
    was scheduled; ``False`` when ``MAX_IN_FLIGHT`` writes are already
    running or there is no running loop. Never raises."""
    try:
        if len(_in_flight) >= MAX_IN_FLIGHT:
            logger.debug(
                "portal_impression_dropped_backpressure",
                extra={"in_flight": len(_in_flight)},
            )
            return False
        task = asyncio.get_running_loop().create_task(
            record_portal_impression(**kwargs)
        )
        _in_flight.add(task)
        task.add_done_callback(_in_flight.discard)
        return True
    except Exception as exc:  # noqa: BLE001 -- see module docstring
        logger.warning("portal_impression_schedule_failed", extra={"error": str(exc)})
        return False


async def drain_pending_impressions() -> None:
    """Await every scheduled write. For tests and graceful shutdown only."""
    while _in_flight:
        await asyncio.gather(*list(_in_flight), return_exceptions=True)


async def purge_expired_impressions(
    session,
    *,
    now: datetime | None = None,
    retention_days: int = PORTAL_IMPRESSION_RETENTION_DAYS,
    batch_size: int = RETENTION_DELETE_BATCH_SIZE,
    max_batches: int = RETENTION_MAX_BATCHES_PER_RUN,
) -> dict[str, object]:
    """Hard-delete impressions older than ``retention_days`` in bounded
    batches, committing after each so no long lock is held on a table every
    portal load inserts into."""
    cutoff = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    deleted = 0
    batches = 0
    hit_batch_cap = False
    while True:
        if batches >= max_batches:
            hit_batch_cap = True
            break
        doomed = (
            select(PortalImpression.id)
            .where(PortalImpression.occurred_at < cutoff)
            .limit(batch_size)
        )
        result = await session.execute(
            delete(PortalImpression).where(PortalImpression.id.in_(doomed))
        )
        await session.commit()
        batches += 1
        count = int(result.rowcount or 0)
        deleted += count
        if count < batch_size:
            break
    return {
        "deleted": deleted,
        "batches": batches,
        "cutoff": cutoff.isoformat(),
        "hit_batch_cap": hit_batch_cap,
    }


__all__ = [
    "DEDUPE_WINDOW",
    "MAX_IN_FLIGHT",
    "PORTAL_IMPRESSION_RETENTION_DAYS",
    "build_impression_insert",
    "drain_pending_impressions",
    "portal_device_key",
    "purge_expired_impressions",
    "record_portal_impression",
    "schedule_portal_impression",
]
