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
from app.domains.dashboard.service import DashboardService


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
