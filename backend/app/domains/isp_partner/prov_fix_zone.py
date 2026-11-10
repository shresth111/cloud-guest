"""PROV-FIX items 9 and 10: two gaps RAKESH-FS documented as known limits
(RAKESH_REQUIREMENTS_GAP.md "Known limits").

**9. Report rows keyed by customer only.** A franchisee is confined to its
zones' customers, and ``isp_subscribers`` / ``isp_invoices`` carry a zone
criterion (``zones_scope`` / ``workflow_franchisee``). The report sources that
hang off a subscriber did not: payments, PPPoE sessions, collection events,
subscriber timeline events, queued renewals and enforcement events were
narrowed by customer only. On a customer shared by two zones (one site, two
franchisees) a franchisee therefore counted the other zone's rows. For a
franchisee request only, every ORM select of those tables now also requires
the row's subscriber to be one the franchisee can see (the same
``_subscriber_criteria`` the subscriber list uses). A row without a
subscriber keeps today's customer narrowing (it belongs to no zone).

**10. Coupon batches carry no zone.** A new batch records the zone it was
created in (``isp_coupon_batch_zones``, a side table, so the batch table and
every existing read of it are untouched). A franchisee then sees a batch with
a recorded zone only when that zone is one of its own; a batch with no row
(every batch made before this, and batches an owner makes without a zone
filter) stays visible exactly as today.

Both are inert unless ``ISP_WORKFLOW_ENABLED`` and ``ISP_ZONES_ENABLED``: the
listener acts only on a session carrying a franchisee scope, and the zone is
recorded only while franchisee logins are on.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Index, and_, event, exists, or_, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, Session, mapped_column, with_loader_criteria
from sqlalchemy.schema import ForeignKey

from app.database.base import BaseModel

_FRANCHISEE_KEY = "isp_franchisee_scope"  # workflow_franchisee._INFO_KEY


class IspCouponBatchZone(BaseModel):
    """The zone a coupon batch was created in (item 10). One row per batch,
    only for batches created while franchisee logins are on and a zone was
    known."""

    __tablename__ = "isp_coupon_batch_zones"

    coupon_batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_coupon_batches.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    zone_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("isp_zones.id"), nullable=False
    )

    __table_args__ = (
        Index("ix_isp_coupon_batch_zones_isp_zone", "isp_organization_id", "zone_id"),
    )


def _subscriber_keyed_models() -> list[Any]:
    from .billing_models import IspPayment
    from .collections_models import IspCollectionEvent
    from .enforcement_models import IspEnforcementEvent
    from .pppoe_models import IspPppoeSession
    from .queued_renewal_models import IspQueuedRenewal
    from .subscriber360_models import IspSubscriberEvent

    return [
        IspPayment,
        IspPppoeSession,
        IspCollectionEvent,
        IspSubscriberEvent,
        IspQueuedRenewal,
        IspEnforcementEvent,
    ]


@event.listens_for(Session, "do_orm_execute")
def _franchisee_report_criteria(state: Any) -> None:
    if state.session.info.get(_FRANCHISEE_KEY) is None:
        return
    if not state.is_select or state.is_column_load or state.is_relationship_load:
        return
    from .plans_models import IspCouponBatch, IspSubscriber
    from .zones_scope import NO_MATCH, _subscriber_criteria, current_scope

    zone_scope = current_scope(state.session)
    franchisee = state.session.info[_FRANCHISEE_KEY]
    zone_ids = franchisee.zone_ids or frozenset({NO_MATCH})
    opts = []
    if zone_scope is not None:
        visible = select(IspSubscriber.id).where(_subscriber_criteria(zone_scope))
        for model in _subscriber_keyed_models():
            opts.append(
                with_loader_criteria(
                    model,
                    or_(
                        model.subscriber_id.is_(None),
                        model.subscriber_id.in_(visible),
                    ),
                    include_aliases=True,
                )
            )
    zone_row = IspCouponBatchZone
    opts.append(
        with_loader_criteria(
            IspCouponBatch,
            or_(
                ~exists().where(
                    and_(
                        zone_row.coupon_batch_id == IspCouponBatch.id,
                        zone_row.is_deleted.is_(False),
                    )
                ),
                exists().where(
                    and_(
                        zone_row.coupon_batch_id == IspCouponBatch.id,
                        zone_row.is_deleted.is_(False),
                        zone_row.zone_id.in_(zone_ids),
                    )
                ),
            ),
            include_aliases=True,
        )
    )
    state.statement = state.statement.options(*opts)


async def record_coupon_batch_zone(session: Any, isp: Any, batch: Any) -> None:
    """Item 10: remember the zone ``batch`` was made in. The customer's own
    profile zone when it is inside the caller's zone view, else the zone the
    caller is working in (franchisee: its zone; owner: ``scope_zone_id``).
    No zone known -> no row (visible to every franchisee, as before)."""
    from .models import IspCustomerProfile
    from .workflow_config import franchisee_logins_on
    from .zones_scope import NO_MATCH, current_scope

    if not franchisee_logins_on() or batch is None:
        return
    scope = current_scope(session)
    if scope is None:
        return
    profile_zone = (
        await session.execute(
            select(IspCustomerProfile.zone_id).where(
                IspCustomerProfile.isp_organization_id == isp.isp_org_id,
                IspCustomerProfile.customer_organization_id
                == batch.customer_organization_id,
            )
        )
    ).scalar_one_or_none()
    if profile_zone is not None and profile_zone in scope.zone_ids:
        zone_id = profile_zone
    else:
        zone_id = scope.zone_id
    if zone_id is None or zone_id == NO_MATCH:
        return
    session.add(
        IspCouponBatchZone(
            coupon_batch_id=batch.id,
            isp_organization_id=isp.isp_org_id,
            zone_id=zone_id,
        )
    )
    await session.flush()


__all__ = ["IspCouponBatchZone", "record_coupon_batch_zone"]
