"""BE-HARDEN: incremental coupon -> subscriber sync.

Before: every GET of the subscriber list, the 360 directory, the invoice
list, packages, speed groups and the coupon export ran a full sync. It loaded
every redeemed voucher ever and every subscriber of the ISP, once a minute per
worker process, and two concurrent runs raced each other into the unique
index.

Now:

* It runs in the background, from the 120 s ISP pass, the daily billing job
  and the explicit "sync now" route (``POST /isp/subscribers/sync``). It never
  runs inside a GET.
* It is incremental. ``isp_coupon_sync_state`` keeps a per-ISP watermark: the
  ``(redeemed_at, voucher id)`` of the last redemption it applied. Each run
  re-reads from ``watermark - OVERLAP``, so a redemption that committed late
  with an older timestamp is still picked up. Re-applying a redemption is a
  no-op: the subscriber's ``last_voucher_id`` check and the invoice
  ``source_key`` see to that. It pages with a keyset on
  ``(redeemed_at, id)``.
* It is single-flight per ISP: ``pg_try_advisory_xact_lock``. A second
  caller returns at once instead of racing.
* The expiry flip is one set-based UPDATE, not a Python loop over every
  subscriber.

Reads stay correct while the sync lags. ``subscriber_views`` and the
``status`` list filter treat an ``active`` row whose ``valid_until`` has
passed as ``expired``. A coupon redeemed in the last two minutes shows up
at the next pass, or at once after "sync now".
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    select,
    text,
    tuple_,
    update,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = [
    "COUPON_SYNC_TABLES",
    "IspCouponSyncState",
    "sync_coupon_subscribers",
]

#: re-read window behind the watermark (late commits with older timestamps)
OVERLAP = timedelta(minutes=10)
PAGE = 1000


class IspCouponSyncState(BaseModel):
    __tablename__ = "isp_coupon_sync_state"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    watermark_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    watermark_voucher_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_applied: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    __table_args__ = (
        Index(
            "uq_isp_coupon_sync_state_isp",
            "isp_organization_id",
            unique=True,
        ),
    )


COUPON_SYNC_TABLES = ("isp_coupon_sync_state",)


async def _state(session: Any, isp_org_id: uuid.UUID) -> IspCouponSyncState:
    row = (
        await session.execute(
            select(IspCouponSyncState).where(
                IspCouponSyncState.isp_organization_id == isp_org_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = IspCouponSyncState(isp_organization_id=isp_org_id, last_applied=0)
        session.add(row)
        await session.flush()
    return row


async def _page(
    session: Any,
    isp_org_id: uuid.UUID,
    since: datetime | None,
    cursor: tuple[datetime, uuid.UUID] | None,
) -> list:
    from app.domains.voucher.models import Voucher

    from .plans_models import IspCouponBatch, IspCouponBatchPart

    q = (
        select(Voucher, IspCouponBatch)
        .join(
            IspCouponBatchPart, IspCouponBatchPart.voucher_batch_id == Voucher.batch_id
        )
        .join(IspCouponBatch, IspCouponBatch.id == IspCouponBatchPart.coupon_batch_id)
        .where(
            IspCouponBatch.isp_organization_id == isp_org_id,
            Voucher.redeemed_at.is_not(None),
            Voucher.redeemed_identifier.is_not(None),
            Voucher.organization_id == IspCouponBatch.customer_organization_id,
        )
    )
    if since is not None:
        q = q.where(Voucher.redeemed_at > since)
    if cursor is not None:
        q = q.where(tuple_(Voucher.redeemed_at, Voucher.id) > tuple_(*cursor))
    q = q.order_by(Voucher.redeemed_at, Voucher.id).limit(PAGE)
    return list((await session.execute(q)).all())


async def expire_lapsed(session: Any, isp_org_id: uuid.UUID, now: datetime) -> int:
    from .plans_models import IspSubscriber

    res = await session.execute(
        update(IspSubscriber)
        .where(
            IspSubscriber.isp_organization_id == isp_org_id,
            IspSubscriber.is_deleted.is_(False),
            IspSubscriber.status == "active",
            IspSubscriber.valid_until.is_not(None),
            IspSubscriber.valid_until < now,
        )
        .values(status="expired")
        .execution_options(synchronize_session=False)
    )
    return int(res.rowcount or 0)


async def sync_coupon_subscribers(plans: Any, isp: Any) -> int:
    """Apply every redemption past the watermark; return how many subscribers
    were created or topped up. Runs in the caller's transaction."""
    from .zones_scope import unscoped

    session = plans.session
    got = (
        await session.execute(
            text("SELECT pg_try_advisory_xact_lock(hashtext(:k))"),
            {"k": f"isp_coupon_sync:{isp.isp_org_id}"},
        )
    ).scalar_one()
    if not got:
        return 0  # another run for this ISP is in flight
    now = plans._clock()
    with unscoped(session):
        state = await _state(session, isp.isp_org_id)
        since = state.watermark_at - OVERLAP if state.watermark_at else None
        cursor: tuple[datetime, uuid.UUID] | None = None
        changed = 0
        while True:
            rows = await _page(session, isp.isp_org_id, since, cursor)
            if not rows:
                break
            changed += await plans._apply_coupon_rows(isp, rows)
            last = rows[-1][0]
            cursor = (last.redeemed_at, last.id)
            if len(rows) < PAGE:
                break
        if cursor is not None and (
            state.watermark_at is None or cursor[0] >= state.watermark_at
        ):
            state.watermark_at, state.watermark_voucher_id = cursor
        state.last_run_at = datetime.now(UTC)
        state.last_applied = changed
        await expire_lapsed(session, isp.isp_org_id, now)
        await session.flush()
    return changed
