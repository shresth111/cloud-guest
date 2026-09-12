"""Data access for the Dashboard domain: one question about a tenant's fleet.

This domain composes other services and owns no tables, which is why it had
no repository until now. It gains one because of a question no other service
answers in the shape the dashboard needs it:

    Does this organization have any device this platform's own agent runs on?

## Why the dashboard has to ask at all

``service._get_widgets`` hands the console a fixed list of widget
descriptors, two of which -- ``routers-online`` and ``router-health`` -- are
*agent-shaped*: they describe heartbeat liveness and RouterOS health, facts
that only exist for a device running this platform's agent.

A TP-Link Omada controller is a ``Router`` row (see
``app.domains.network_integration.models.NetworkIntegration.router_id`` for
why it must be), but it runs no agent, has no WireGuard peer and speaks no
RouterOS API. It is created ``pending_provisioning`` with NULL API
credentials and nothing ever transitions it to ``ONLINE``. So at a venue
whose only equipment is a controller, those two tiles do not report "no
data" -- they report a perfectly healthy venue as a fleet that is offline
and unhealthy, which is the exact failure mode
``app.domains.router.vendor_capabilities`` exists to prevent. The dashboard
was one of the surfaces that never asked.

## Why two methods rather than one

They are deliberately separate because they are opposite claims about the
same table, and ``tests/unit/test_router_read_vendor_coverage.py`` classifies
a *function*, not a statement. A single method holding both queries would
register as narrowed and would then have to be filed under
``AGENT_MANAGED_ONLY`` -- an entry asserting that every row it reads is
agent-managed, while half of them deliberately are not. Splitting them keeps
each classification honest:

* :meth:`count_agent_managed_routers` narrows through
  ``fleet_scope.agent_managed_only`` -- AGENT_MANAGED_ONLY.
* :meth:`count_routers` counts every fleet row the tenant owns --
  VENDOR_NEUTRAL, for the same reason ``UsageRepository.count_routers`` and
  both ``count_routers_by_status`` methods are: a controller the operator
  registered is a device the tenant has, and a total that quietly omits it
  is the worse lie.

## Why counts and not rows

The only consumer needs a yes/no about the *composition* of a fleet, and a
``COUNT(*)`` answers it without loading a single row into the dashboard's
memory or its response. Nothing here returns a router, a vendor string, or
any other controller detail to a caller -- which also keeps this read clear
of the organization-scoped leakage question being handled elsewhere.
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.router.fleet_scope import agent_managed_only
from app.domains.router.models import Router

__all__ = [
    "DashboardFleetRepository",
    "DashboardFleetRepositoryProtocol",
]


class DashboardFleetRepositoryProtocol(Protocol):
    async def count_agent_managed_routers(self, organization_id: uuid.UUID) -> int: ...

    async def count_routers(self, organization_id: uuid.UUID) -> int: ...


class DashboardFleetRepository:
    """Concrete, SQLAlchemy-backed implementation."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def count_agent_managed_routers(self, organization_id: uuid.UUID) -> int:
        """How many of this organization's fleet rows run this platform's
        agent -- i.e. how many the agent-shaped health tiles can speak for.

        Narrowed in SQL rather than filtered after loading, which is the
        posture ``fleet_scope.agent_managed_only`` documents: a row a caller
        never loads is a row it cannot judge by mistake.
        """
        statement = agent_managed_only(
            select(func.count())
            .select_from(Router)
            .where(
                Router.organization_id == organization_id,
                Router.is_deleted.is_(False),
            )
        )
        return int((await self.session.execute(statement)).scalar_one())

    async def count_routers(self, organization_id: uuid.UUID) -> int:
        """Every fleet row this organization owns, controllers included.

        Vendor-neutral on purpose. The caller needs to tell "this tenant has
        a fleet, and none of it is agent-managed" from "this tenant has no
        fleet at all", and only a total that counts the controller can make
        that distinction. A brand-new customer with nothing registered yet
        must keep the default dashboard, not inherit an Omada venue's.
        """
        statement = (
            select(func.count())
            .select_from(Router)
            .where(
                Router.organization_id == organization_id,
                Router.is_deleted.is_(False),
            )
        )
        return int((await self.session.execute(statement)).scalar_one())
