"""The Master console's two set-based reads.

Both replace a per-row loop that production measured as the bulk of a page
load (2026-10-10, 17-19 organizations, a database whose every statement
runs in well under a millisecond -- so the cost was never the SQL, it was
how many times the API was asked):

* ``GET /dashboard/super-admin/organizations`` replaces one
  ``GET /dashboard/organization`` per row of the platform organization
  table: 12 requests / 312 statements / 407 ms became one request and three
  statements, whatever the row count.
* ``GET /plans`` loaded each plan's features with its own query: 41 of that
  request's 44 statements.

What has to hold is (a) the numbers do not change -- every figure of the
new endpoint equals the same-named field of ``get_organization_dashboard``
-- and (b) the statement count no longer grows with the row count. The
service half runs against fakes like the rest of this suite; the SQL half
cannot be faked (``DISTINCT ON``, ``GROUP BY``) and runs against a real
Postgres, gated on ``CLOUDGUEST_TEST_POSTGRES_URL`` exactly as
``test_analytics_snapshot_upsert.py`` is.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest
from sqlalchemy import Column, MetaData, Table, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.domains.analytics.constants import AnalyticsSnapshotType
from app.domains.analytics.dashboard_scope import DashboardScopeResolver
from app.domains.analytics.dashboard_service import DashboardService
from app.domains.analytics.exceptions import DashboardScopeForbiddenError
from app.domains.analytics.models import AnalyticsSnapshot
from app.domains.analytics.repository import AnalyticsRepository
from app.domains.billing import router as billing_router
from app.domains.billing.models import Plan, PlanFeature
from app.domains.billing.repository import PlanRepository
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.enums import ScopeType

from .test_analytics_dashboards import (
    _FakeAssignment,
    _FakeDashboardRepository,
    _FakeGuestAnalyticsService,
    _FakeGuestSummary,
    _FakeLocationLookup,
    _FakeOrganization,
    _FakeOrganizationLookup,
    _FakeRedis,
    _FakeRoleResolver,
    _make_snapshot,
    _permission_key_and_scope_for_route,
)

ORG_SUMMARY = AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value


# ============================================================================
# Service: GET /dashboard/super-admin/organizations
# ============================================================================


class _CountingRepository(_FakeDashboardRepository):
    """The dashboard fake plus the three set-based reads, answered from the
    very same data the single-organization reads use -- so a disagreement
    between the two paths below is a disagreement in the service's own
    arithmetic, not in two hand-written fixtures."""

    def __init__(self, *, children: dict[uuid.UUID, list[uuid.UUID]], **overrides):
        super().__init__(**overrides)
        self._children = children
        self.calls: list[str] = []

    async def get_latest_snapshots_for_organizations(
        self, organization_ids, *, snapshot_type
    ):
        self.calls.append("get_latest_snapshots_for_organizations")
        found = {}
        for organization_id in organization_ids:
            snapshot = await super().get_latest_snapshot(
                organization_id=organization_id,
                location_id=None,
                snapshot_type=snapshot_type,
            )
            if snapshot is not None:
                found[organization_id] = snapshot
        return found

    async def count_active_locations_by_organization(self, organization_ids):
        self.calls.append("count_active_locations_by_organization")
        return {
            organization_id: len(self.active_location_ids_by_org[organization_id])
            for organization_id in organization_ids
            if self.active_location_ids_by_org.get(organization_id)
        }

    async def list_child_organization_ids(self, parent_organization_ids):
        self.calls.append("list_child_organization_ids")
        return {
            parent: list(self._children[parent])
            for parent in parent_organization_ids
            if parent in self._children
        }

    async def get_latest_snapshot(self, **kwargs):
        self.calls.append("get_latest_snapshot")
        return await super().get_latest_snapshot(**kwargs)

    async def list_active_location_ids_for_organization(self, organization_id):
        self.calls.append("list_active_location_ids_for_organization")
        return await super().list_active_location_ids_for_organization(organization_id)


class _ListingOrganizationLookup(_FakeOrganizationLookup):
    def __init__(self, organizations, children, listed):
        super().__init__(organizations, children)
        self._listed = listed
        self.list_calls: list[dict] = []

    async def list_organizations(self, *, requesting_organization_id, page, page_size):
        self.list_calls.append(
            {
                "requesting_organization_id": requesting_organization_id,
                "page": page,
                "page_size": page_size,
            }
        )
        return self._listed[:page_size], SimpleNamespace(total_items=len(self._listed))


def _metrics(guests: int, routers: int) -> dict[str, int]:
    return {
        "guest_count_unique": guests,
        "session_count_total": guests * 2,
        "session_count_active": 1,
        "router_count_online": routers,
        "router_count_total": routers,
        "total_bandwidth_bytes": 1000,
    }


def _platform(standard_count: int = 2, *, scope_type: str = ScopeType.GLOBAL.value):
    """An MSP with one child, ``standard_count`` ordinary organizations and
    one organization that has no snapshot and no location at all."""
    msp, child, empty = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    standards = [uuid.uuid4() for _ in range(standard_count)]

    snapshots = {
        (msp, None, ORG_SUMMARY): [
            _make_snapshot(organization_id=msp, metrics=_metrics(10, 4))
        ],
        (child, None, ORG_SUMMARY): [
            _make_snapshot(organization_id=child, metrics=_metrics(5, 2))
        ],
    }
    locations = {msp: [uuid.uuid4()], child: [uuid.uuid4(), uuid.uuid4()]}
    for index, org_id in enumerate(standards):
        snapshots[(org_id, None, ORG_SUMMARY)] = [
            _make_snapshot(organization_id=org_id, metrics=_metrics(index + 1, 1))
        ]
        locations[org_id] = [uuid.uuid4() for _ in range(index + 1)]

    organizations = {
        msp: _FakeOrganization(id=msp, org_type="msp", name="MSP"),
        child: _FakeOrganization(id=child, name="Child"),
        empty: _FakeOrganization(id=empty, name="Empty"),
        **{
            org_id: _FakeOrganization(id=org_id, name=f"Standard {index}")
            for index, org_id in enumerate(standards)
        },
    }
    listed = [organizations[i] for i in (msp, child, *standards, empty)]

    repository = _CountingRepository(
        children={msp: [child]},
        snapshots_by_key=snapshots,
        active_location_ids_by_org=locations,
    )
    lookup = _ListingOrganizationLookup(
        organizations, {msp: [organizations[child]]}, listed
    )
    service = DashboardService(
        repository,
        _FakeGuestAnalyticsService(
            _FakeGuestSummary(
                visitors=0,
                unique_guests=0,
                returning_guests=0,
                average_session_duration_seconds=0.0,
                total_bandwidth_bytes=0,
            )
        ),
        DashboardScopeResolver(
            _FakeRoleResolver(
                [_FakeAssignment(scope_type=scope_type, organization_id=msp)]
                if scope_type != ScopeType.GLOBAL.value
                else [_FakeAssignment(scope_type=scope_type)]
            ),
            lookup,
            _FakeLocationLookup({}),
        ),
        lookup,
        _FakeLocationLookup({}),
        _FakeRedis(),
    )
    return SimpleNamespace(
        service=service,
        repository=repository,
        lookup=lookup,
        listed=listed,
        msp=msp,
        child=child,
        empty=empty,
    )


async def test_every_row_equals_the_organization_dashboard_it_replaces():
    """The whole point: the table must show the numbers it showed when each
    row came from its own ``GET /dashboard/organization``."""
    fx = _platform()

    result = await fx.service.get_platform_organization_summaries(
        uuid.uuid4(), limit=100
    )

    assert [item.organization_id for item in result.items] == [
        org.id for org in fx.listed
    ]
    assert result.total_organizations == len(fx.listed)
    for item in result.items:
        dashboard = await fx.service.get_organization_dashboard(
            uuid.uuid4(), item.organization_id
        )
        assert item.guest_count_unique == dashboard.guest_count_unique
        assert item.router_count == dashboard.router_count
        assert item.location_count == dashboard.location_count


async def test_msp_row_rolls_its_children_in_and_an_empty_org_is_all_zero():
    fx = _platform()

    result = await fx.service.get_platform_organization_summaries(
        uuid.uuid4(), limit=100
    )
    rows = {item.organization_id: item for item in result.items}

    assert rows[fx.msp].guest_count_unique == 15  # 10 own + 5 child
    assert rows[fx.msp].router_count == 6  # 4 own + 2 child
    assert rows[fx.msp].location_count == 3  # 1 own + 2 child
    assert rows[fx.child].guest_count_unique == 5  # the child's own row is its own
    assert (
        rows[fx.empty].guest_count_unique,
        rows[fx.empty].router_count,
        rows[fx.empty].location_count,
    ) == (0, 0, 0)


@pytest.mark.parametrize("standard_count", [1, 12, 60])
async def test_repository_reads_do_not_grow_with_the_number_of_rows(standard_count):
    """Three set-based reads for 4 rows, for 15 and for 63 -- and never the
    per-organization ones, which are what made this a fan-out."""
    fx = _platform(standard_count)

    result = await fx.service.get_platform_organization_summaries(
        uuid.uuid4(), limit=100
    )

    assert len(result.items) == standard_count + 3
    assert sorted(fx.repository.calls) == [
        "count_active_locations_by_organization",
        "get_latest_snapshots_for_organizations",
        "list_child_organization_ids",
    ]
    assert len(fx.lookup.list_calls) == 1


async def test_limit_is_the_page_size_and_the_listing_is_platform_wide():
    fx = _platform(standard_count=10)

    result = await fx.service.get_platform_organization_summaries(uuid.uuid4(), limit=5)

    assert len(result.items) == 5
    assert result.total_organizations == len(fx.listed)
    assert fx.lookup.list_calls == [
        {"requesting_organization_id": None, "page": 1, "page_size": 5}
    ]


async def test_an_organization_scoped_caller_is_refused_before_anything_is_read():
    fx = _platform(scope_type=ScopeType.ORGANIZATION.value)

    with pytest.raises(DashboardScopeForbiddenError):
        await fx.service.get_platform_organization_summaries(uuid.uuid4(), limit=12)

    assert fx.repository.calls == []
    assert fx.lookup.list_calls == []


def test_route_is_registered_and_pinned_to_global_scope():
    """The response spans tenants, so GLOBAL must be stated on the route --
    an inferred scope lets the caller choose their own check level."""
    from app.main import create_app

    routes = {getattr(route, "path", None): route for route in create_app().routes}
    route = routes["/api/v1/dashboard/super-admin/organizations"]

    assert _permission_key_and_scope_for_route(route) == ("analytics.read", "global")
    assert route.methods == {"GET"}


# ============================================================================
# Handler: GET /plans
# ============================================================================


def _plan(sort_order: int) -> Plan:
    now = datetime.now(UTC)
    return Plan(
        id=uuid.uuid4(),
        created_at=now,
        updated_at=now,
        deleted_at=None,
        is_deleted=False,
        created_by=None,
        updated_by=None,
        version=1,
        name=f"Plan {sort_order}",
        slug=f"plan-{sort_order}",
        plan_type="starter",
        description=None,
        billing_cycle="monthly",
        base_price=Decimal("100.00"),
        currency="INR",
        is_active=True,
        is_public=True,
        sort_order=sort_order,
    )


def _feature(plan_id: uuid.UUID, key: str) -> PlanFeature:
    now = datetime.now(UTC)
    return PlanFeature(
        id=uuid.uuid4(),
        created_at=now,
        updated_at=now,
        deleted_at=None,
        is_deleted=False,
        created_by=None,
        updated_by=None,
        version=1,
        plan_id=plan_id,
        feature_key=key,
        feature_type="boolean",
        limit_value=None,
        is_enabled=True,
        tier_value=None,
    )


class _FakePlanService:
    def __init__(self, plans: list[Plan], features: dict[uuid.UUID, list[PlanFeature]]):
        self._plans = plans
        self._features = features
        self.calls: list[str] = []

    async def list_plans(self, **kwargs):
        self.calls.append("list_plans")
        return self._plans, SimpleNamespace(
            page=1,
            page_size=len(self._plans) or 1,
            total_items=len(self._plans),
            total_pages=1,
            has_next=False,
            has_previous=False,
        )

    async def list_features(self, plan_id):
        self.calls.append("list_features")
        return self._features.get(plan_id, [])

    async def list_features_for_plans(self, plan_ids):
        self.calls.append("list_features_for_plans")
        return {plan_id: self._features.get(plan_id, []) for plan_id in plan_ids}


class _FakeAccessValidator:
    async def has_permission(self, *args, **kwargs):
        return True


@pytest.mark.parametrize("plan_count", [1, 9, 41])
async def test_list_plans_loads_features_once_for_the_whole_page(
    monkeypatch, plan_count
):
    plans = [_plan(index) for index in range(plan_count)]
    # The last plan deliberately has no features at all.
    features = {
        plan.id: [_feature(plan.id, "captive_portal"), _feature(plan.id, "vouchers")]
        for plan in plans[:-1]
    }
    service = _FakePlanService(plans, features)
    captured = {}

    def _capture(**kwargs):
        captured.update(kwargs)
        return kwargs

    monkeypatch.setattr(billing_router, "build_response", _capture)

    await billing_router.list_plans(
        request=SimpleNamespace(state=SimpleNamespace(request_id="t")),
        include_private=True,
        is_active=True,
        plan_type=None,
        page=1,
        page_size=100,
        user=SimpleNamespace(id=str(uuid.uuid4())),
        access_validator=_FakeAccessValidator(),
        service=service,
    )

    assert service.calls == ["list_plans", "list_features_for_plans"]
    items = captured["data"]["items"]
    assert [item["id"] for item in items] == [str(plan.id) for plan in plans]
    expected = [
        ["captive_portal", "vouchers"] if plan.id in features else [] for plan in plans
    ]
    assert [[f["feature_key"] for f in item["features"]] for item in items] == expected


# ============================================================================
# SQL: the set-based reads against a real Postgres
# ============================================================================

_PG_URL = os.environ.get("CLOUDGUEST_TEST_POSTGRES_URL")
requires_postgres = pytest.mark.skipif(
    not _PG_URL, reason="CLOUDGUEST_TEST_POSTGRES_URL not set"
)


@pytest.fixture
async def session():
    schema = f"master_bulk_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(_PG_URL, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        _PG_URL, connect_args={"server_settings": {"search_path": schema}}
    )
    # `users` is only ever a foreign-key target here.
    stubs = MetaData()
    Table("users", stubs, Column("id", PG_UUID(as_uuid=True), primary_key=True))
    try:
        async with engine.begin() as conn:
            await conn.run_sync(stubs.create_all)
            for model in (Organization, Location, AnalyticsSnapshot, Plan, PlanFeature):
                await conn.run_sync(model.__table__.create)
        async with AsyncSession(engine, expire_on_commit=False) as db:
            yield db
    finally:
        await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def _org(db, name, *, parent=None, org_type="standard", deleted=False):
    org = Organization(
        name=name,
        slug=f"{name}-{uuid.uuid4().hex[:6]}",
        org_type=org_type,
        status="active",
        parent_organization_id=parent,
        contact_email="a@example.com",
        is_deleted=deleted,
    )
    db.add(org)
    await db.flush()
    return org.id


async def _location(db, org_id, *, status="active", deleted=False):
    db.add(
        Location(
            organization_id=org_id,
            name="L",
            slug=uuid.uuid4().hex,
            status=status,
            address_line1="1 Test Street",
            city="Test",
            state_province="TS",
            postal_code="000000",
            country="IN",
            is_deleted=deleted,
        )
    )
    await db.flush()


async def _snapshot(db, org_id, *, days_ago, guests, location_id=None, kind=None):
    repository = AnalyticsRepository(db)
    start = datetime(2026, 10, 1, tzinfo=UTC) - timedelta(days=days_ago)
    await repository.upsert_snapshot(
        organization_id=org_id,
        location_id=location_id,
        snapshot_type=kind or ORG_SUMMARY,
        period_start=start,
        period_end=start + timedelta(days=1),
        granularity="daily",
        metrics={"guest_count_unique": guests},
        computed_at=start,
        computation_duration_ms=1.0,
    )


@requires_postgres
async def test_sql_latest_snapshots_match_the_single_organization_read(session):
    repository = AnalyticsRepository(session)
    a = await _org(session, "a")
    b = await _org(session, "b")
    c = await _org(session, "c")
    for days_ago, guests in ((3, 1), (0, 9), (1, 5)):  # newest is NOT inserted last
        await _snapshot(session, a, days_ago=days_ago, guests=guests)
    await _snapshot(session, b, days_ago=2, guests=7)
    # Neither of these may be picked for `b`: wrong type, and location-level.
    await _snapshot(
        session,
        b,
        days_ago=0,
        guests=999,
        kind=AnalyticsSnapshotType.PLATFORM_DAILY_SUMMARY.value,
    )
    await session.commit()

    bulk = await repository.get_latest_snapshots_for_organizations(
        [a, b, c], snapshot_type=ORG_SUMMARY
    )

    assert set(bulk) == {a, b}  # c has no snapshot and is simply absent
    for org_id in (a, b, c):
        single = await repository.get_latest_snapshot(
            organization_id=org_id, location_id=None, snapshot_type=ORG_SUMMARY
        )
        assert (bulk[org_id].id if org_id in bulk else None) == (
            single.id if single else None
        )
    assert bulk[a].metrics == {"guest_count_unique": 9}
    assert (
        await repository.get_latest_snapshots_for_organizations(
            [], snapshot_type=ORG_SUMMARY
        )
        == {}
    )


@requires_postgres
async def test_sql_location_counts_match_the_single_organization_read(session):
    repository = AnalyticsRepository(session)
    a = await _org(session, "a")
    b = await _org(session, "b")
    c = await _org(session, "c")
    for _ in range(3):
        await _location(session, a)
    await _location(session, a, deleted=True)
    await _location(session, a, status="inactive")
    await _location(session, b)
    await session.commit()

    bulk = await repository.count_active_locations_by_organization([a, b, c])

    assert bulk == {a: 3, b: 1}
    for org_id in (a, b, c):
        single = await repository.list_active_location_ids_for_organization(org_id)
        assert bulk.get(org_id, 0) == len(single)
    assert await repository.count_active_locations_by_organization([]) == {}


@requires_postgres
async def test_sql_children_are_grouped_by_parent_and_skip_deleted(session):
    repository = AnalyticsRepository(session)
    msp = await _org(session, "msp", org_type="msp")
    other = await _org(session, "other", org_type="msp")
    kids = {await _org(session, f"kid{i}", parent=msp) for i in range(2)}
    await _org(session, "gone", parent=msp, deleted=True)
    await session.commit()

    children = await repository.list_child_organization_ids([msp, other])

    assert set(children) == {msp}
    assert set(children[msp]) == kids
    assert await repository.list_child_organization_ids([]) == {}


@requires_postgres
async def test_sql_plan_features_match_the_single_plan_read(session):
    repository = PlanRepository(session)
    plans = []
    for index in range(3):
        plan = await repository.create_plan(
            name=f"P{index}",
            slug=f"p{index}",
            plan_type="starter",
            billing_cycle="monthly",
            base_price=Decimal("1.00"),
            currency="INR",
            is_active=True,
            is_public=True,
            sort_order=index,
        )
        plans.append(plan)
    for key in ("vouchers", "captive_portal", "analytics"):  # not in key order
        for plan in plans[:2]:
            await repository.create_plan_feature(
                plan_id=plan.id,
                feature_key=key,
                feature_type="boolean",
                is_enabled=True,
            )
    await session.commit()
    ids = [plan.id for plan in plans]

    bulk = await repository.list_plan_features_for_plans(ids)

    assert list(bulk) == ids
    assert bulk[ids[2]] == []
    for plan_id in ids:
        single = await repository.list_plan_features(plan_id)
        assert [f.id for f in bulk[plan_id]] == [f.id for f in single]
    assert [f.feature_key for f in bulk[ids[0]]] == [
        "analytics",
        "captive_portal",
        "vouchers",
    ]
    assert await repository.list_plan_features_for_plans([]) == {}
