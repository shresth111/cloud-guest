"""The SQL-side twin of :mod:`app.domains.router.vendor_capabilities`.

## Why a second module

``vendor_capabilities`` answers the vendor question about a *row you are
already holding*. That is the right shape for a service layer, and it is
the wrong shape for a sweep: by the time a fleet-wide sweep holds the row
it has already loaded a controller it had no business loading, and the
next line usually dispatches a Celery task or a device call for it. The
question has to be asked in the ``WHERE`` clause.

Kept apart from ``vendor_capabilities`` deliberately. That module is
imported by ``readiness`` and ``monitoring`` and is pure predicates over
strings -- no models, no SQLAlchemy, nothing that can fail to import while
the ORM layer is mid-edit. This one necessarily imports the ``Router``
model, so it is only ever imported by repositories, which already have it.

## Why the two must not drift, and what stops them

Both are derived from the *same* constant,
:data:`~app.domains.router.vendor_capabilities.CONTROLLER_MANAGED_VENDORS`.
Neither restates the vendor list. ``tests/unit/test_router_read_vendor_
coverage.py`` runs the SQL criterion against a real (SQLite, in-memory)
table of every vendor string the platform knows and asserts the rows it
keeps are exactly the rows :func:`is_agent_managed` returns ``True`` for --
so a vendor added to the set is gated on both sides or on neither, never
on one.

## The NULL branch is not defensive padding

``routers.vendor`` is ``NOT NULL`` with a ``"mikrotik"`` default, so in a
healthy database no row has a NULL here. The branch exists because SQL
three-valued logic would make a NULL row vanish from the *agent-managed*
side of an ``x NOT IN (...)`` test -- silently excluding a real MikroTik
from the sweep that keeps it healthy. ``vendor_of`` makes exactly the same
choice in Python (a missing vendor reads as the column default), and the
two are asserted to agree.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import or_
from sqlalchemy.sql.elements import ColumnElement

from .models import Router
from .vendor_capabilities import CONTROLLER_MANAGED_VENDORS

__all__ = [
    "agent_managed_only",
    "agent_managed_vendor_criterion",
]


def agent_managed_vendor_criterion(
    column: ColumnElement[Any] | None = None,
) -> ColumnElement[bool]:
    """A ``WHERE`` fragment matching only agent-managed fleet rows.

    ``column`` defaults to ``Router.vendor`` and exists so the criterion can
    be pointed at any vendor-bearing column -- which is what lets the
    coverage test execute it against real rows on a database that cannot
    hold a ``Router`` (the ``routers`` table uses PostgreSQL-native
    ``UUID``/``JSONB`` columns, and this suite has no PostgreSQL). A test
    that could only compile the clause to a string would be checking the
    string, not the filtering.
    """
    vendor = Router.vendor if column is None else column
    # `sorted` rather than the frozenset's own iteration order: the compiled
    # bind parameters then have a stable order, which keeps a statement's
    # cache key and any test that inspects them from depending on the hash
    # seed.
    return or_(vendor.is_(None), vendor.not_in(sorted(CONTROLLER_MANAGED_VENDORS)))


def agent_managed_only(statement):
    """Narrow a statement that reads ``routers`` to agent-managed rows.

    The one call every fleet sweep in this codebase should make, and the
    symbol ``tests/unit/test_router_read_vendor_coverage.py`` looks for
    when it decides whether a router-reading call site has answered the
    vendor question or merely not been asked it yet.

    Use it wherever the rows are about to be *acted on* -- dispatched a
    task, polled, pushed configuration, judged by an alert rule. Do not use
    it on a read whose job is to show an operator their whole inventory: a
    controller that is missing from the fleet list is a different lie from
    a controller reported as a broken MikroTik, and this filter cannot tell
    the two apart. That decision belongs at the call site, which is why the
    coverage test makes each one write it down.
    """
    return statement.where(agent_managed_vendor_criterion())
