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

Plain-``assert``/native-``async def`` style, in-memory fakes, no live
Postgres -- same convention as the rest of this suite.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.dashboard.service import DashboardService


class _FakeAnalyticsDashboard:
    """Mirrors the *real* ``SuperAdminDashboardResponse`` field names.

    A fake that invents ``total_routers_online`` would reproduce the original
    bug rather than catch it, so these are exactly the attributes
    ``analytics.dashboard_schemas`` declares.
    """

    def __init__(
        self,
        *,
        total_locations: int = 0,
        total_routers: int = 0,
        routers_online: int = 0,
        routers_offline: int = 0,
        raises: Exception | None = None,
    ) -> None:
        self._response = SimpleNamespace(
            total_locations=total_locations,
            total_routers=total_routers,
            routers_online=routers_online,
            routers_offline=routers_offline,
        )
        self._raises = raises

    async def get_super_admin_dashboard(self, user_id):
        if self._raises is not None:
            raise self._raises
        return self._response


class _FakeOrganizationService:
    def __init__(self, total_items: int = 0, raises: Exception | None = None) -> None:
        self._total_items = total_items
        self._raises = raises

    async def list_organizations(self, *, requesting_user_id, page, page_size):
        if self._raises is not None:
            raise self._raises
        return [], SimpleNamespace(total_items=self._total_items)


def _service(
    analytics: _FakeAnalyticsDashboard,
    organizations: _FakeOrganizationService | None = None,
) -> DashboardService:
    return DashboardService(
        analytics_dashboard=analytics,
        platform_dashboard=None,
        billing_dashboard=None,
        rbac_service=None,
        organization_service=organizations or _FakeOrganizationService(),
    )


class TestOverviewCounts:
    async def test_total_routers_is_the_real_count_not_zero(self) -> None:
        """The shipped bug, pinned. 12 routers must read as 12."""
        service = _service(
            _FakeAnalyticsDashboard(
                total_routers=12, routers_online=9, routers_offline=3
            )
        )

        overview = await service._get_overview(uuid.uuid4())

        assert overview.total_routers == 12

    async def test_total_locations_is_carried_through(self) -> None:
        service = _service(_FakeAnalyticsDashboard(total_locations=4))

        overview = await service._get_overview(uuid.uuid4())

        assert overview.total_locations == 4

    async def test_total_organizations_comes_from_the_organization_service(
        self,
    ) -> None:
        service = _service(
            _FakeAnalyticsDashboard(), _FakeOrganizationService(total_items=7)
        )

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

    async def test_organization_failure_propagates(self) -> None:
        service = _service(
            _FakeAnalyticsDashboard(),
            _FakeOrganizationService(raises=RuntimeError("org listing failed")),
        )

        with pytest.raises(RuntimeError):
            await service._get_overview(uuid.uuid4())
