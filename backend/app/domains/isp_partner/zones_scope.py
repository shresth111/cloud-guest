"""ZONE-1: the zone tree and the "Switch zone" scope.

**Tree.** ``isp_zone_nodes`` holds ``parent_zone_id`` for a zone. A zone with
no row, a NULL parent, or a parent that is deleted / belongs to another ISP is
a top-level zone, so nothing ever disappears from the tree.

**Scope.** ``scope_zone_id=<zone_id>`` on any ``/isp`` request is applied once,
in ``RequireIspPartner`` (``apply_zone_scope``), never per handler. It only
ever NARROWS what the caller can already see:

* ``confined_customer_ids`` becomes ``existing confinement ∩ zone customers``,
  where zone customers are the ISP's customers whose profile zone is in the
  subtree, plus customers holding a subscriber whose own zone is in the
  subtree. Every handler already honours confinement (``child_ids()`` /
  ``IspScope``), so customers, locations, routers, IP pools, CPEs and
  customer-keyed reports follow without being edited. An empty result is a
  set holding only the nil UUID, which matches nothing (never "all").
* ORM selects of ``isp_subscribers`` and ``isp_invoices`` in that request get
  an extra criterion (``with_loader_criteria`` via a ``do_orm_execute``
  listener keyed on ``session.info``): the row's own ``zone_id`` is in the
  subtree, or it has none and its customer's profile zone is in the subtree.

The scope lives on the request's DB session (``session.info``), so it ends with
the request and never touches Celery work or another request. Raw SQL is not
rewritten; it sees the customer narrowing only.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy import and_, event, func, or_, select, text
from sqlalchemy.orm import Session, with_loader_criteria

from .exceptions import IspZoneNotFoundError
from .zones_config import get_zones_settings

SCOPE_PARAM = "scope_zone_id"
_INFO_KEY = "isp_zone_scope"
#: Matches no organization: an empty zone narrows to nothing, never to "all".
NO_MATCH = uuid.UUID(int=0)


@dataclass(frozen=True)
class ZoneScope:
    zone_id: uuid.UUID
    zone_ids: frozenset[uuid.UUID]
    #: customers whose own profile zone is in the subtree (the fallback for
    #: subscribers / invoices without a zone of their own)
    profile_customer_ids: frozenset[uuid.UUID]


# --------------------------------------------------------------------------
# tree reads
# --------------------------------------------------------------------------


async def zone_rows(session: Any, isp_org_id: uuid.UUID) -> list[tuple[Any, Any]]:
    """Every live zone of the ISP with its parent id (or None)."""
    from .billing_models import IspZone
    from .zones_models import IspZoneNode

    rows = (
        await session.execute(
            select(IspZone, IspZoneNode.parent_zone_id)
            .outerjoin(
                IspZoneNode,
                and_(
                    IspZoneNode.zone_id == IspZone.id,
                    IspZoneNode.is_deleted.is_(False),
                ),
            )
            .where(
                IspZone.isp_organization_id == isp_org_id,
                IspZone.is_deleted.is_(False),
            )
            .order_by(func.lower(IspZone.name))
        )
    ).all()
    return [(z, p) for z, p in rows]


def parent_map(rows: list[tuple[Any, Any]]) -> dict[uuid.UUID, uuid.UUID | None]:
    """zone id -> effective parent (None when the stored parent is gone)."""
    ids = {z.id for z, _ in rows}
    return {z.id: (p if p in ids and p != z.id else None) for z, p in rows}


def descendants(
    parents: dict[uuid.UUID, uuid.UUID | None], root: uuid.UUID
) -> set[uuid.UUID]:
    """``root`` and everything under it. Cycle-safe (a stored cycle can only
    come from hand-edited data; the API refuses to create one)."""
    kids: dict[uuid.UUID, list[uuid.UUID]] = {}
    for zid, p in parents.items():
        if p is not None:
            kids.setdefault(p, []).append(zid)
    out: set[uuid.UUID] = set()
    stack = [root]
    while stack:
        z = stack.pop()
        if z in out:
            continue
        out.add(z)
        stack.extend(kids.get(z, []))
    return out


def ancestry(
    parents: dict[uuid.UUID, uuid.UUID | None], zid: uuid.UUID
) -> list[uuid.UUID]:
    """Root-first path ending at ``zid``. Cycle-safe."""
    path: list[uuid.UUID] = []
    seen: set[uuid.UUID] = set()
    cur: uuid.UUID | None = zid
    while cur is not None and cur not in seen:
        seen.add(cur)
        path.append(cur)
        cur = parents.get(cur)
    return list(reversed(path))


async def subtree_ids(
    session: Any, isp_org_id: uuid.UUID, zone_id: uuid.UUID
) -> set[uuid.UUID]:
    rows = await zone_rows(session, isp_org_id)
    parents = parent_map(rows)
    if zone_id not in parents:
        raise IspZoneNotFoundError()
    return descendants(parents, zone_id)


# --------------------------------------------------------------------------
# the scope
# --------------------------------------------------------------------------


async def build_scope(
    session: Any, isp_org_id: uuid.UUID, zone_id: uuid.UUID
) -> tuple[ZoneScope, frozenset[uuid.UUID]]:
    """(scope, zone customer ids). Raises 404 for a zone that is not this ISP's."""
    from .models import IspCustomerProfile
    from .plans_models import IspSubscriber

    zone_ids = frozenset(await subtree_ids(session, isp_org_id, zone_id))
    profile_customers = frozenset(
        (
            await session.execute(
                select(IspCustomerProfile.customer_organization_id).where(
                    IspCustomerProfile.isp_organization_id == isp_org_id,
                    IspCustomerProfile.zone_id.in_(zone_ids),
                )
            )
        ).scalars()
    )
    subscriber_customers = frozenset(
        (
            await session.execute(
                select(IspSubscriber.customer_organization_id)
                .where(
                    IspSubscriber.isp_organization_id == isp_org_id,
                    IspSubscriber.zone_id.in_(zone_ids),
                    IspSubscriber.is_deleted.is_(False),
                )
                .distinct()
            )
        ).scalars()
    )
    scope = ZoneScope(
        zone_id=zone_id, zone_ids=zone_ids, profile_customer_ids=profile_customers
    )
    return scope, profile_customers | subscriber_customers


def narrow(
    confined: frozenset[uuid.UUID] | None, zone_customers: frozenset[uuid.UUID]
) -> frozenset[uuid.UUID]:
    """Intersection, never a widening. Empty -> {NO_MATCH}."""
    out = zone_customers if confined is None else (confined & zone_customers)
    return out or frozenset({NO_MATCH})


async def apply_zone_scope(ctx: Any, request: Any) -> Any:
    """Called at the end of ``RequireIspPartner``. Returns ``ctx`` unchanged
    unless the flag is on and ``scope_zone_id`` is present."""
    if request is None or not get_zones_settings().zones_enabled:
        return ctx
    raw = request.query_params.get(SCOPE_PARAM)
    if not raw:
        return ctx
    try:
        zone_id = uuid.UUID(raw)
    except ValueError as exc:
        raise IspZoneNotFoundError() from exc
    session = getattr(ctx.repository, "session", None)
    if session is None:
        return ctx
    scope, zone_customers = await build_scope(session, ctx.isp_org_id, zone_id)
    session.info[_INFO_KEY] = scope
    return replace(
        ctx,
        confined_customer_ids=narrow(ctx.confined_customer_ids, zone_customers),
        _child_ids=None,
    )


def current_scope(session: Any) -> ZoneScope | None:
    info = getattr(session, "info", None)
    return info.get(_INFO_KEY) if info is not None else None


def clear_scope(session: Any) -> None:
    info = getattr(session, "info", None)
    if info is not None:
        info.pop(_INFO_KEY, None)


@contextmanager
def unscoped(session: Any) -> Iterator[None]:
    """BE-REVIEW R3: run a block without the request's zone filter.

    The ``do_orm_execute`` criteria narrow every ORM select of
    ``isp_subscribers`` / ``isp_invoices`` in a zone-scoped request. That is
    right for what the caller is SHOWN, and wrong for internal bookkeeping
    that must see the whole ISP: the coupon subscriber sync (it would miss a
    subscriber outside the zone, try to create it again and hit the unique
    index), invoice idempotency lookups and duplicate-identifier checks. The
    customer confinement on ``IspContext`` is untouched, so this never widens
    what a confined user can reach."""
    info = getattr(session, "info", None)
    saved = info.pop(_INFO_KEY, None) if info is not None else None
    try:
        yield
    finally:
        if saved is not None:
            info[_INFO_KEY] = saved


def _subscriber_criteria(scope: ZoneScope) -> Any:
    from .plans_models import IspSubscriber

    return or_(
        IspSubscriber.zone_id.in_(scope.zone_ids),
        and_(
            IspSubscriber.zone_id.is_(None),
            IspSubscriber.customer_organization_id.in_(
                scope.profile_customer_ids or {NO_MATCH}
            ),
        ),
    )


def _invoice_criteria(scope: ZoneScope) -> Any:
    from .billing_models import IspInvoice

    return or_(
        IspInvoice.zone_id.in_(scope.zone_ids),
        and_(
            IspInvoice.zone_id.is_(None),
            IspInvoice.customer_organization_id.in_(
                scope.profile_customer_ids or {NO_MATCH}
            ),
        ),
    )


def subscriber_zone_clause(session: Any, subscriber_col: Any) -> Any:
    """P3-SWEEP: the ZONE-1 subscriber rule for a table keyed by subscriber
    (collections, incidents, referrals, queued renewals, static IPs, revenue).

    ``None`` when the request has no zone scope (nothing to add). Otherwise a
    criterion "the row's subscriber is in the zone": the subscriber's own
    ``zone_id`` is in the subtree, or it has none and its customer's profile
    zone is. It is ANDed onto a query that is already confined by customer,
    so it can only narrow. A NULL subscriber column never matches it; callers
    with customer-level rows (no subscriber) decide for themselves."""
    scope = current_scope(session)
    if scope is None:
        return None
    from .plans_models import IspSubscriber

    return subscriber_col.in_(
        select(IspSubscriber.id).where(_subscriber_criteria(scope))
    )


def party_zone_clause(session: Any, subscriber_col: Any, customer_col: Any) -> Any:
    """P3-SWEEP: the ZONE-1 rule for a row that names a subscriber OR only a
    customer (collection promises, static-IP leases). A subscriber row uses
    ``subscriber_zone_clause``; a customer-level row (no subscriber) falls
    back to its customer's profile zone, exactly like a subscriber without a
    zone. ``None`` when there is no zone scope. Only narrows."""
    scope = current_scope(session)
    if scope is None:
        return None
    return or_(
        and_(
            subscriber_col.is_not(None),
            subscriber_zone_clause(session, subscriber_col),
        ),
        and_(
            subscriber_col.is_(None),
            customer_col.in_(scope.profile_customer_ids or {NO_MATCH}),
        ),
    )


async def zone_visible_subscribers(session: Any, ids: Any) -> set[uuid.UUID] | None:
    """P3-SWEEP: which of ``ids`` pass the ZONE-1 subscriber rule in this
    request. ``None`` = no zone scope (every id passes). For services that
    build their rows in Python after a customer-level query."""
    scope = current_scope(session)
    if scope is None:
        return None
    wanted = {i for i in ids if i is not None}
    if not wanted:
        return set()
    from .plans_models import IspSubscriber

    return set(
        (
            await session.execute(
                select(IspSubscriber.id).where(
                    IspSubscriber.id.in_(wanted), _subscriber_criteria(scope)
                )
            )
        ).scalars()
    )


@event.listens_for(Session, "do_orm_execute")
def _zone_criteria(state: Any) -> None:
    scope = state.session.info.get(_INFO_KEY)
    if scope is None:
        return
    if not state.is_select or state.is_column_load or state.is_relationship_load:
        return
    from .billing_models import IspInvoice
    from .plans_models import IspSubscriber

    state.statement = state.statement.options(
        with_loader_criteria(
            IspSubscriber, _subscriber_criteria(scope), include_aliases=True
        ),
        with_loader_criteria(
            IspInvoice, _invoice_criteria(scope), include_aliases=True
        ),
    )


async def lock_tree(session: Any, isp_org_id: uuid.UUID) -> None:
    """Serialise tree moves per ISP, so two concurrent moves cannot build a
    cycle between them."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
        {"k": f"isp_zone_tree:{isp_org_id}"},
    )


__all__ = [
    "NO_MATCH",
    "SCOPE_PARAM",
    "ZoneScope",
    "ancestry",
    "apply_zone_scope",
    "build_scope",
    "clear_scope",
    "current_scope",
    "descendants",
    "lock_tree",
    "narrow",
    "parent_map",
    "party_zone_clause",
    "subscriber_zone_clause",
    "subtree_ids",
    "unscoped",
    "zone_visible_subscribers",
    "zone_rows",
]
