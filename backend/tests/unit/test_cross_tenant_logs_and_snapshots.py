"""Cross-tenant reads on ``GET /notifications/logs`` and the analytics
snapshot endpoints.

* ``GET /notifications/logs`` declared no organization dependency and its
  repository had no organization filter: any caller holding
  ``notifications.read`` on their own org (seeded down to LOCATION scope) got
  every tenant's delivery log -- including platform-wide channels' rows,
  which describe alerts about every tenant.
* ``GET /analytics/snapshots`` is already scoped: ``CurrentOrganization``
  only yields ``None`` for a GLOBAL-role caller who explicitly asked for all
  organizations. Pinned here so it stays that way.
* ``POST /analytics/snapshots/trigger`` took ``organization_id`` from the
  BODY with no comparison to the caller's scope: an org caller holding
  ``reports.manage`` could run another tenant's aggregation and read back its
  snapshots in the response.
"""

from __future__ import annotations

import inspect
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.analytics import router as analytics_router
from app.domains.analytics.schemas import TriggerAggregationRequest
from app.domains.monitoring import router as monitoring_router
from app.domains.monitoring.exceptions import UnscopedOrganizationListError
from app.domains.monitoring.repository import MonitoringRepository
from app.domains.organization.exceptions import CrossOrganizationAccessError
from app.domains.rbac.dependencies import CurrentOrganization


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(request_id="t"))


def _declares_current_organization(handler) -> bool:
    return any(
        getattr(p.default, "dependency", None) is CurrentOrganization
        for p in inspect.signature(handler).parameters.values()
    )


def _empty_page():
    return [], PaginationMeta.from_total(PageParams(page=1, page_size=25), 0)


# ---------------------------------------------------------------------------
# GET /notifications/logs
# ---------------------------------------------------------------------------


class RecordingNotificationService:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def list_logs(self, **kwargs):
        self.calls.append(kwargs)
        return _empty_page()


class TestNotificationLogsRoute:
    def test_handler_declares_current_organization(self) -> None:
        assert _declares_current_organization(monitoring_router.list_notification_logs)

    async def test_org_caller_is_scoped_to_their_org(self) -> None:
        org = uuid.uuid4()
        service = RecordingNotificationService()
        await monitoring_router.list_notification_logs(
            request=_request(),
            organization_id=org,
            channel_id=None,
            alert_id=None,
            log_status=None,
            page=1,
            page_size=25,
            service=service,
        )
        assert service.calls[0]["organization_id"] == org
        assert service.calls[0]["include_all_organizations"] is False

    async def test_master_all_organizations_is_explicit(self) -> None:
        """``None`` reaches here only for a GLOBAL-role caller who sent
        ``X-Organization-Scope: all`` (see ``CurrentOrganizationScope``)."""
        service = RecordingNotificationService()
        await monitoring_router.list_notification_logs(
            request=_request(),
            organization_id=None,
            channel_id=None,
            alert_id=None,
            log_status=None,
            page=1,
            page_size=25,
            service=service,
        )
        assert service.calls[0]["organization_id"] is None
        assert service.calls[0]["include_all_organizations"] is True


class CapturingSession:
    def __init__(self) -> None:
        self.statements: list = []

    async def execute(self, statement):
        self.statements.append(statement)
        return SimpleNamespace(
            scalar_one=lambda: 0,
            scalars=lambda: SimpleNamespace(all=lambda: []),
        )


def _sql(statement) -> str:
    return str(
        statement.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


class TestNotificationLogsRepository:
    async def test_org_filter_joins_the_channel_owner(self) -> None:
        org = uuid.uuid4()
        session = CapturingSession()
        repo = MonitoringRepository(session)
        await repo.list_notification_logs(organization_id=org)
        assert session.statements, "no query issued"
        for statement in session.statements:
            sql = _sql(statement)
            assert "notification_channels.organization_id" in sql
            assert org.hex in sql.replace("-", "")

    async def test_unscoped_without_opt_in_is_refused(self) -> None:
        repo = MonitoringRepository(CapturingSession())
        with pytest.raises(UnscopedOrganizationListError):
            await repo.list_notification_logs(organization_id=None)

    async def test_explicit_all_organizations_has_no_org_filter(self) -> None:
        session = CapturingSession()
        repo = MonitoringRepository(session)
        await repo.list_notification_logs(
            organization_id=None, include_all_organizations=True
        )
        for statement in session.statements:
            assert "notification_channels.organization_id" not in _sql(statement)


# ---------------------------------------------------------------------------
# /analytics/snapshots
# ---------------------------------------------------------------------------


class RecordingAnalyticsService:
    def __init__(self) -> None:
        self.list_calls: list[dict] = []
        self.trigger_calls: list[uuid.UUID] = []

    async def list_snapshots(self, **kwargs):
        self.list_calls.append(kwargs)
        return _empty_page()

    async def trigger_aggregation(self, organization_id, *, target_date_iso=None):
        self.trigger_calls.append(organization_id)
        return []


class TestSnapshotListIsScoped:
    def test_handler_declares_current_organization(self) -> None:
        assert _declares_current_organization(analytics_router.list_snapshots)

    async def test_org_is_forwarded_and_location_is_anded_with_it(self) -> None:
        org, foreign_location = uuid.uuid4(), uuid.uuid4()
        service = RecordingAnalyticsService()
        await analytics_router.list_snapshots(
            request=_request(),
            organization_id=org,
            location_id=foreign_location,
            snapshot_type=None,
            start_date=None,
            end_date=None,
            page=1,
            page_size=25,
            service=service,
        )
        assert service.list_calls[0]["organization_id"] == org
        # The repository ANDs both filters, so a foreign location id under
        # the caller's own org matches nothing.
        src = inspect.getsource(
            __import__(
                "app.domains.analytics.repository", fromlist=["x"]
            ).AnalyticsRepository.list_snapshots
        )
        assert "AnalyticsSnapshot.organization_id == organization_id" in src
        assert "AnalyticsSnapshot.location_id == location_id" in src


class TestSnapshotTriggerIsScoped:
    def test_handler_declares_current_organization(self) -> None:
        assert _declares_current_organization(
            analytics_router.trigger_snapshot_aggregation
        )

    async def test_org_caller_cannot_trigger_another_org(self) -> None:
        service = RecordingAnalyticsService()
        with pytest.raises(CrossOrganizationAccessError):
            await analytics_router.trigger_snapshot_aggregation(
                request=_request(),
                payload=TriggerAggregationRequest(organization_id=uuid.uuid4()),
                requesting_organization_id=uuid.uuid4(),
                organization_service=SimpleNamespace(
                    get_organization=_org_with_parent(None)
                ),
                service=service,
            )
        assert service.trigger_calls == []

    async def test_org_caller_may_trigger_own_org(self) -> None:
        org = uuid.uuid4()
        service = RecordingAnalyticsService()
        await analytics_router.trigger_snapshot_aggregation(
            request=_request(),
            payload=TriggerAggregationRequest(organization_id=org),
            requesting_organization_id=org,
            organization_service=SimpleNamespace(
                get_organization=_org_with_parent(None)
            ),
            service=service,
        )
        assert service.trigger_calls == [org]

    async def test_master_all_organizations_may_trigger_any(self) -> None:
        target = uuid.uuid4()
        service = RecordingAnalyticsService()
        await analytics_router.trigger_snapshot_aggregation(
            request=_request(),
            payload=TriggerAggregationRequest(organization_id=target),
            requesting_organization_id=None,
            organization_service=SimpleNamespace(
                get_organization=_org_with_parent(None)
            ),
            service=service,
        )
        assert service.trigger_calls == [target]


def _org_with_parent(parent_id):
    async def get_organization(organization_id, **_):
        return SimpleNamespace(id=organization_id, parent_organization_id=parent_id)

    return get_organization
