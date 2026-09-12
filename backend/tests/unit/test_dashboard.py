"""Unit tests for the dashboard composition layer
(``app.domains.dashboard.service``).

This domain had no test file at all, which is most of why the bug below
survived: ``GET /dashboard`` reported **0 routers** for every account since it
shipped.

``_get_overview`` read ``dash.total_routers_online + dash.total_routers_offline``
behind a ``hasattr(dash, "total_routers_online")`` guard. Neither attribute has
ever existed on ``SuperAdminDashboardResponse`` -- the real fields are
``total_routers`` / ``routers_online`` / ``routers_offline`` -- so the guard was
permanently ``False`` and the ``else 0`` branch was the only one that ever ran,
with the correct value sitting one attribute away. Both reads were also wrapped
in a bare ``except Exception: -> 0``, so a genuine failure was indistinguishable
from "you have nothing".

A second bug lived in the same function and is pinned here too: all three of
these counts ignored the request's organization outright. ``organization_id``
was accepted by the route, threaded through two call layers, and then dropped
-- the org count came from an ``OrganizationService`` call made with no scope,
and the location/router counts came from ``get_super_admin_dashboard``, which
takes no organization argument at all. So a platform admin who *had* selected a
venue, and whose every other tile honoured it, still read platform-wide totals
here. A count blended across fourteen tenants renders exactly like a correct
one, which is why it went unnoticed.

Plain-``assert``/native-``async def`` style, in-memory fakes, no live
Postgres -- same convention as the rest of this suite.
"""

from __future__ import annotations

import uuid

import pytest

from app.domains.analytics.dashboard_service import OverviewCounts
from app.domains.dashboard.service import AGENT_SHAPED_WIDGET_IDS, DashboardService


class _FakeAnalyticsDashboard:
    """Mirrors the *real* ``AnalyticsDashboardService.get_overview_counts``.

    A fake that invents ``total_routers_online`` would reproduce the original
    bug rather than catch it, so these are exactly the attributes
    ``analytics.dashboard_service.OverviewCounts`` declares.

    ``per_organization`` is what the second bug needs: the counts this returns
    when the request names a venue, as distinct from the platform-wide ones. A
    fake that returned the same numbers either way could not tell a scoped
    dashboard from an unscoped one.
    """

    def __init__(
        self,
        *,
        total_organizations: int = 0,
        total_locations: int = 0,
        total_routers: int = 0,
        per_organization: OverviewCounts | None = None,
        raises: Exception | None = None,
    ) -> None:
        self._platform = OverviewCounts(
            total_organizations=total_organizations,
            total_locations=total_locations,
            total_routers=total_routers,
        )
        self._per_organization = per_organization
        self._raises = raises
        self.seen_organization_ids: list[uuid.UUID | None] = []

    async def get_overview_counts(self, user_id, *, organization_id):
        self.seen_organization_ids.append(organization_id)
        if self._raises is not None:
            raise self._raises
        if organization_id is not None and self._per_organization is not None:
            return self._per_organization
        return self._platform


def _service(analytics: _FakeAnalyticsDashboard) -> DashboardService:
    return DashboardService(
        analytics_dashboard=analytics,
        platform_dashboard=None,
        billing_dashboard=None,
        rbac_service=None,
        organization_service=None,
    )


class TestOverviewCounts:
    async def test_total_routers_is_the_real_count_not_zero(self) -> None:
        """The shipped bug, pinned. 12 routers must read as 12."""
        service = _service(_FakeAnalyticsDashboard(total_routers=12))

        overview = await service._get_overview(uuid.uuid4())

        assert overview.total_routers == 12

    async def test_total_locations_is_carried_through(self) -> None:
        service = _service(_FakeAnalyticsDashboard(total_locations=4))

        overview = await service._get_overview(uuid.uuid4())

        assert overview.total_locations == 4

    async def test_total_organizations_is_carried_through(self) -> None:
        service = _service(_FakeAnalyticsDashboard(total_organizations=7))

        overview = await service._get_overview(uuid.uuid4())

        assert overview.total_organizations == 7

    async def test_a_genuinely_empty_platform_still_reads_zero(self) -> None:
        """Zero must remain reachable -- the fix must not turn "no routers"
        into something else."""
        service = _service(_FakeAnalyticsDashboard(total_routers=0))

        overview = await service._get_overview(uuid.uuid4())

        assert overview.total_routers == 0


class TestOverviewFailuresAreVisible:
    async def test_analytics_failure_propagates_rather_than_reporting_zero(
        self,
    ) -> None:
        """A broken query used to render as "0 routers, 0 locations", which an
        operator cannot tell from an empty platform."""
        service = _service(
            _FakeAnalyticsDashboard(raises=RuntimeError("analytics unavailable"))
        )

        with pytest.raises(RuntimeError):
            await service._get_overview(uuid.uuid4())

    async def test_a_scoped_failure_propagates_too(self) -> None:
        service = _service(
            _FakeAnalyticsDashboard(raises=RuntimeError("scoped read failed"))
        )

        with pytest.raises(RuntimeError):
            await service._get_overview(uuid.uuid4(), uuid.uuid4())


class TestOverviewHonoursTheSelectedOrganization:
    """The second bug. These three tiles used to be platform-wide even for a
    caller who had selected a venue -- see this module's own docstring."""

    async def test_a_selected_organization_reaches_the_counts(self) -> None:
        analytics = _FakeAnalyticsDashboard(
            total_organizations=14, total_locations=51, total_routers=120
        )
        service = _service(analytics)
        organization_id = uuid.uuid4()

        await service._get_overview(uuid.uuid4(), organization_id)

        assert analytics.seen_organization_ids == [organization_id], (
            "the organization was accepted by the route, threaded through two "
            "call layers, and then dropped on the floor"
        )

    async def test_the_venues_own_numbers_are_reported_not_the_platforms(
        self,
    ) -> None:
        analytics = _FakeAnalyticsDashboard(
            total_organizations=14,
            total_locations=51,
            total_routers=120,
            per_organization=OverviewCounts(
                total_organizations=1, total_locations=2, total_routers=3
            ),
        )
        service = _service(analytics)

        overview = await service._get_overview(uuid.uuid4(), uuid.uuid4())

        assert (
            overview.total_organizations,
            overview.total_locations,
            overview.total_routers,
        ) == (1, 2, 3)

    async def test_the_estate_view_still_answers_platform_wide(self) -> None:
        """Scoping must not remove the operator's cross-tenant overview -- a
        caller who asked for every organization arrives here with ``None``."""
        analytics = _FakeAnalyticsDashboard(
            total_organizations=14,
            total_locations=51,
            total_routers=120,
            per_organization=OverviewCounts(
                total_organizations=1, total_locations=2, total_routers=3
            ),
        )
        service = _service(analytics)

        overview = await service._get_overview(uuid.uuid4(), None)

        assert overview.total_organizations == 14
        assert analytics.seen_organization_ids == [None]


# ===========================================================================
# Agent-shaped widgets on a fleet that runs no agent
# ===========================================================================
#
# `_get_widgets` hands the console a fixed list of descriptors. Two of them
# -- `routers-online` and `router-health` -- describe heartbeat liveness and
# RouterOS health, which only exist for a device running this platform's
# agent. A TP-Link Omada controller is a `Router` row that runs no agent, is
# created `pending_provisioning` with NULL credentials, and never becomes
# ONLINE. So at a controller-only venue those two tiles do not read "no
# data": they read a healthy venue as an offline, unhealthy fleet.
#
# The rule is narrow on purpose, and most of what is pinned below is the
# cases that must NOT change -- because the cost of widening the predicate
# is paid by MikroTik venues, which are every venue in production today.


class _FakeFleetRepository:
    """Counts only, mirroring `DashboardFleetRepository`'s real signature.

    `raises` exists because "the count query broke" and "this tenant has no
    agent-managed devices" must not produce the same dashboard.
    """

    def __init__(
        self,
        *,
        agent_managed: int = 0,
        total: int = 0,
        raises: Exception | None = None,
    ) -> None:
        self._agent_managed = agent_managed
        self._total = total
        self._raises = raises
        self.seen_organization_ids: list[uuid.UUID] = []

    async def count_agent_managed_routers(self, organization_id: uuid.UUID) -> int:
        self.seen_organization_ids.append(organization_id)
        if self._raises is not None:
            raise self._raises
        return self._agent_managed

    async def count_routers(self, organization_id: uuid.UUID) -> int:
        if self._raises is not None:
            raise self._raises
        return self._total


def _widget_service(fleet: _FakeFleetRepository | None) -> DashboardService:
    return DashboardService(
        analytics_dashboard=_FakeAnalyticsDashboard(),
        platform_dashboard=None,
        billing_dashboard=None,
        rbac_service=None,
        organization_service=None,
        fleet_repository=fleet,
    )


async def _widget_ids(
    fleet: _FakeFleetRepository | None, organization_id: uuid.UUID | None
) -> list[str]:
    widgets = await _widget_service(fleet)._get_widgets(uuid.uuid4(), organization_id)
    return [w.id for w in widgets]


# The full list as it stood before this behaviour existed. Spelled out
# rather than derived, so a future edit to `_get_widgets` has to come
# through this constant and be looked at.
_ALL_WIDGET_IDS = [
    "kpi-overview",
    "active-guests",
    "routers-online",
    "revenue-mrr",
    "alerts",
    "guest-trend",
    "router-health",
    "recent-activity",
]


class TestAMikrotikVenueIsUntouched:
    """The hard constraint. Every one of these must return the list
    unchanged, in the same order, including the two agent-shaped tiles."""

    async def test_a_fleet_of_mikrotiks_keeps_every_widget(self) -> None:
        fleet = _FakeFleetRepository(agent_managed=3, total=3)
        assert await _widget_ids(fleet, uuid.uuid4()) == _ALL_WIDGET_IDS

    async def test_a_mixed_venue_keeps_every_widget(self) -> None:
        """One MikroTik alongside a controller. Agent-shaped health is
        meaningful the moment a single agent-managed device exists, and a
        mixed site is exactly where an operator needs it."""
        fleet = _FakeFleetRepository(agent_managed=1, total=2)
        assert await _widget_ids(fleet, uuid.uuid4()) == _ALL_WIDGET_IDS

    async def test_a_brand_new_customer_with_no_fleet_keeps_every_widget(
        self,
    ) -> None:
        """An empty fleet is a customer mid-onboarding, not an Omada venue.
        Their dashboard must look like every other new customer's -- this is
        the case a naive `agent_managed == 0` check would break for
        MikroTik."""
        fleet = _FakeFleetRepository(agent_managed=0, total=0)
        assert await _widget_ids(fleet, uuid.uuid4()) == _ALL_WIDGET_IDS

    async def test_the_platform_estate_view_keeps_every_widget(self) -> None:
        """No organization selected. A per-tenant fact must never remove a
        tile from the platform's own dashboard."""
        fleet = _FakeFleetRepository(agent_managed=0, total=1)
        assert await _widget_ids(fleet, None) == _ALL_WIDGET_IDS

    async def test_the_estate_view_does_not_even_ask(self) -> None:
        fleet = _FakeFleetRepository(agent_managed=0, total=1)
        await _widget_ids(fleet, None)
        assert fleet.seen_organization_ids == []

    async def test_no_fleet_repository_wired_keeps_every_widget(self) -> None:
        """ "Cannot tell" must read as "behave exactly as before", never as
        "hide the tiles"."""
        assert await _widget_ids(None, uuid.uuid4()) == _ALL_WIDGET_IDS

    async def test_a_broken_count_query_keeps_every_widget(self) -> None:
        """A dashboard that drops tiles because a query failed would turn a
        transient database fault into a silent, apparently-deliberate UI
        change."""
        fleet = _FakeFleetRepository(raises=RuntimeError("connection reset"))
        assert await _widget_ids(fleet, uuid.uuid4()) == _ALL_WIDGET_IDS


class TestAControllerOnlyVenueLosesTheAgentShapedTiles:
    async def test_routers_online_and_router_health_are_withheld(self) -> None:
        fleet = _FakeFleetRepository(agent_managed=0, total=1)
        assert await _widget_ids(fleet, uuid.uuid4()) == [
            "kpi-overview",
            "active-guests",
            "revenue-mrr",
            "alerts",
            "guest-trend",
            "recent-activity",
        ]

    async def test_every_other_widget_survives_in_order(self) -> None:
        """Withholding two tiles is the whole change -- this is not a
        redesign of the widget list."""
        fleet = _FakeFleetRepository(agent_managed=0, total=2)
        kept = await _widget_ids(fleet, uuid.uuid4())
        assert kept == [w for w in _ALL_WIDGET_IDS if w not in AGENT_SHAPED_WIDGET_IDS]

    async def test_the_tiles_are_dropped_not_merely_marked_invisible(self) -> None:
        """`WidgetConfig.visible` has never been set by anything, so no
        consumer is known to honour it. A tile that renders anyway would go
        on making the false claim this branch exists to stop."""
        fleet = _FakeFleetRepository(agent_managed=0, total=1)
        widgets = await _widget_service(fleet)._get_widgets(uuid.uuid4(), uuid.uuid4())
        assert not [w for w in widgets if w.id in AGENT_SHAPED_WIDGET_IDS]

    async def test_the_question_is_asked_about_the_selected_organization(
        self,
    ) -> None:
        organization_id = uuid.uuid4()
        fleet = _FakeFleetRepository(agent_managed=0, total=1)
        await _widget_ids(fleet, organization_id)
        assert fleet.seen_organization_ids == [organization_id]


class TestTheAgentShapedSetIsWhatItClaims:
    def test_it_names_exactly_the_two_agent_shaped_widgets(self) -> None:
        """Pinned so that adding a third agent-shaped tile to
        `_get_widgets` without adding it here is a visible omission."""
        assert {"router-health", "routers-online"} == AGENT_SHAPED_WIDGET_IDS

    def test_every_named_widget_actually_exists_in_the_list(self) -> None:
        assert set(_ALL_WIDGET_IDS) >= AGENT_SHAPED_WIDGET_IDS
