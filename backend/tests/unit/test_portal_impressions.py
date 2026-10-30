"""The login funnel's "portal opened" stage: ``portal_impressions``.

What must hold, in order of how badly it would hurt to lose it:

1. Recording can never fail or slow the guest's ``/captive-portal/resolve``
   -- an exception anywhere in the write is swallowed, the write is
   detached from the request, and a burst is dropped rather than queued.
2. Only a real guest load is recorded (the dashboard's Portal Preview hits
   the same endpoint without the marker).
3. No personal data: no MAC/IP/UA/phone column; the device key is a keyed,
   per-organization hash.
4. One device's reloads collapse (``NOT EXISTS`` inside the same INSERT),
   and the INSERT re-checks the tenant boundary in SQL.
5. Retention deletes in bounded batches.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.domains.analytics import portal_impressions as pi
from app.domains.analytics.models import PortalImpression

ORG = uuid.UUID("00000000-0000-0000-0000-00000000000a")
OTHER_ORG = uuid.UUID("00000000-0000-0000-0000-00000000000b")
LOC = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
ROUTER = uuid.UUID("00000000-0000-0000-0000-0000000000f1")
MAC = "AA:BB:CC:DD:EE:01"


def _sql(statement) -> str:
    return str(
        statement.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": False}
        )
    )


class TestNoPersonalData:
    def test_columns_are_exactly_these(self) -> None:
        assert set(PortalImpression.__table__.c.keys()) == {
            "id",
            "organization_id",
            "location_id",
            "router_id",
            "occurred_at",
            "client_mac_hash",
        }

    def test_device_key_is_keyed_hash_not_the_mac(self) -> None:
        key = pi.portal_device_key(ORG, MAC)
        assert key is not None and len(key) == 32
        assert "AABBCCDDEE01" not in key.upper()
        # Separator/case-insensitive: the same device, however spelled.
        assert pi.portal_device_key(ORG, "aa-bb-cc-dd-ee-01") == key
        assert pi.portal_device_key(ORG, "aabbccddee01") == key
        # Salted per organization: not joinable across tenants.
        assert pi.portal_device_key(OTHER_ORG, MAC) != key

    @pytest.mark.parametrize("raw", [None, "", "not-a-mac", "AA:BB:CC"])
    def test_unparseable_mac_has_no_key(self, raw) -> None:
        assert pi.portal_device_key(ORG, raw) is None


class TestInsertStatement:
    def _stmt(self, *, device_key, router_id=ROUTER):
        return pi.build_impression_insert(
            organization_id=ORG,
            location_id=LOC,
            router_id=router_id,
            device_key=device_key,
            occurred_at=datetime(2026, 10, 30, 12, tzinfo=UTC),
        )

    def test_insert_select_checks_location_belongs_to_org(self) -> None:
        sql = _sql(self._stmt(device_key="k"))
        assert sql.startswith("INSERT INTO portal_impressions")
        assert "FROM locations" in sql
        assert "locations.organization_id = " in sql
        assert "locations.is_deleted IS false" in sql

    def test_router_kept_only_if_at_that_location(self) -> None:
        sql = _sql(self._stmt(device_key="k"))
        assert "routers.location_id = locations.id" in sql
        assert "routers.organization_id = locations.organization_id" in sql

    def test_dedupe_probe_only_with_a_device_key(self) -> None:
        assert "NOT (EXISTS" in _sql(self._stmt(device_key="k"))
        assert "EXISTS" not in _sql(self._stmt(device_key=None, router_id=None))

    def test_dedupe_window(self) -> None:
        assert timedelta(minutes=10) == pi.DEDUPE_WINDOW


class _ExplodingSession:
    async def __aenter__(self):
        raise RuntimeError("database is down")

    async def __aexit__(self, *exc):
        return False


class _RecordingSession:
    def __init__(self, rowcount: int = 1) -> None:
        self.statements: list = []
        self.committed = False
        self.rowcount = rowcount

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, statement):
        self.statements.append(statement)
        return SimpleNamespace(rowcount=self.rowcount)

    async def commit(self):
        self.committed = True


class TestRecordNeverRaises:
    async def test_database_error_is_swallowed(self, caplog) -> None:
        ok = await pi.record_portal_impression(
            organization_id=ORG,
            location_id=LOC,
            router_id=None,
            device_mac=MAC,
            session_factory=_ExplodingSession,
        )
        assert ok is False

    async def test_success_sets_statement_timeout_and_commits(self) -> None:
        session = _RecordingSession(rowcount=1)
        ok = await pi.record_portal_impression(
            organization_id=ORG,
            location_id=LOC,
            router_id=ROUTER,
            device_mac=MAC,
            session_factory=lambda: session,
        )
        assert ok is True
        assert session.committed
        assert "statement_timeout" in str(session.statements[0])
        assert "INSERT INTO portal_impressions" in _sql(session.statements[1])

    async def test_dedupe_hit_reports_false(self) -> None:
        ok = await pi.record_portal_impression(
            organization_id=ORG,
            location_id=LOC,
            router_id=None,
            device_mac=MAC,
            session_factory=lambda: _RecordingSession(rowcount=0),
        )
        assert ok is False


class TestSchedule:
    async def test_runs_detached_and_drains(self, monkeypatch) -> None:
        calls: list[dict] = []

        async def fake_record(**kwargs):
            await asyncio.sleep(0)
            calls.append(kwargs)
            return True

        monkeypatch.setattr(pi, "record_portal_impression", fake_record)
        assert pi.schedule_portal_impression(organization_id=ORG) is True
        assert calls == []  # not awaited by the caller
        await pi.drain_pending_impressions()
        assert calls == [{"organization_id": ORG}]

    async def test_burst_beyond_cap_is_dropped_not_queued(self, monkeypatch) -> None:
        gate = asyncio.Event()

        async def slow_record(**kwargs):
            await gate.wait()
            return True

        monkeypatch.setattr(pi, "record_portal_impression", slow_record)
        scheduled = [pi.schedule_portal_impression() for _ in range(pi.MAX_IN_FLIGHT)]
        assert all(scheduled)
        assert pi.schedule_portal_impression() is False
        gate.set()
        await pi.drain_pending_impressions()
        assert pi.schedule_portal_impression() is True
        await pi.drain_pending_impressions()

    def test_no_running_loop_is_false_not_raise(self) -> None:
        assert pi.schedule_portal_impression(organization_id=ORG) is False


class TestResolveRoute:
    """The guest-facing endpoint: records only on the marker, with the
    resolved organization, and never lets the recorder break the response."""

    async def _call(self, monkeypatch, *, record_impression, recorder):
        from app.domains.captive_portal import router as router_module
        from tests.unit.test_captive_portal import (
            _apply_column_defaults,
            _create_config,
            _resolve_request,
            make_service,
        )

        fx = make_service()
        location = fx.location_lookup.add(organization_id=fx.organization.id)
        await _create_config(fx, name="Org default", is_default=True)
        for config in fx.repository.configs.values():
            _apply_column_defaults(config)
        monkeypatch.setattr(router_module, "schedule_portal_impression", recorder)
        response = await router_module.resolve_captive_portal_config(
            _resolve_request(),
            organization_id=None,
            location_id=location.id,
            record_impression=record_impression,
            router_id=ROUTER,
            device_mac=MAC,
            service=fx.service,
        )
        return fx, location, response

    async def test_marker_schedules_one_impression(self, monkeypatch) -> None:
        calls: list[dict] = []
        fx, location, response = await self._call(
            monkeypatch,
            record_impression=True,
            recorder=lambda **kw: calls.append(kw) or True,
        )
        assert response["success"] is True
        assert calls == [
            {
                "organization_id": fx.organization.id,
                "location_id": location.id,
                "router_id": ROUTER,
                "device_mac": MAC,
            }
        ]

    async def test_preview_without_marker_records_nothing(self, monkeypatch) -> None:
        calls: list[dict] = []
        _, _, response = await self._call(
            monkeypatch,
            record_impression=False,
            recorder=lambda **kw: calls.append(kw),
        )
        assert response["success"] is True
        assert calls == []

    async def test_real_recorder_failure_does_not_break_resolve(
        self, monkeypatch
    ) -> None:
        # The real scheduler, with a write that blows up inside the task.
        monkeypatch.setattr(pi, "_default_session_factory", _ExplodingSession)
        _, _, response = await self._call(
            monkeypatch,
            record_impression=True,
            recorder=pi.schedule_portal_impression,
        )
        assert response["success"] is True
        await pi.drain_pending_impressions()


class _PurgeSession:
    def __init__(self, counts: list[int]) -> None:
        self.counts = counts
        self.commits = 0

    async def execute(self, statement):
        assert "DELETE FROM portal_impressions" in _sql(statement)
        return SimpleNamespace(rowcount=self.counts.pop(0))

    async def commit(self):
        self.commits += 1


class TestRetention:
    async def test_batches_until_drained_and_commits_each(self) -> None:
        session = _PurgeSession([5, 5, 2])
        now = datetime(2026, 10, 30, tzinfo=UTC)
        summary = await pi.purge_expired_impressions(session, now=now, batch_size=5)
        assert summary["deleted"] == 12
        assert summary["batches"] == 3
        assert session.commits == 3
        assert summary["cutoff"] == (now - timedelta(days=92)).isoformat()
        assert summary["hit_batch_cap"] is False

    async def test_batch_cap(self) -> None:
        session = _PurgeSession([5, 5, 5])
        summary = await pi.purge_expired_impressions(
            session, batch_size=5, max_batches=2
        )
        assert summary["hit_batch_cap"] is True
        assert summary["deleted"] == 10

    def test_beat_schedules_the_sweep_daily(self) -> None:
        from app.core.celery_app import celery_app
        from app.domains.analytics.constants import (
            TASK_RUN_PORTAL_IMPRESSION_RETENTION_SWEEP,
        )

        entries = [
            e
            for e in celery_app.conf.beat_schedule.values()
            if e["task"] == TASK_RUN_PORTAL_IMPRESSION_RETENTION_SWEEP
        ]
        assert len(entries) == 1
        assert entries[0]["schedule"] == 86_400.0

    def test_retention_matches_longest_insight_window(self) -> None:
        from app.domains.analytics.venue_insights import MAX_WINDOW_DAYS

        assert pi.PORTAL_IMPRESSION_RETENTION_DAYS == MAX_WINDOW_DAYS


# ============================================================================
# The real INSERT ... SELECT, when a scratch Postgres is available
# (``CLOUDGUEST_TEST_POSTGRES_URL``; same convention as test_venue_insights).
# ============================================================================

_PG_URL = __import__("os").environ.get("CLOUDGUEST_TEST_POSTGRES_URL")


@pytest.fixture
async def pg_factory():
    if not _PG_URL:
        pytest.skip("CLOUDGUEST_TEST_POSTGRES_URL not set")
    from sqlalchemy import Column, MetaData, Table, text
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

    from app.domains.location.models import Location
    from app.domains.organization.models import Organization
    from app.domains.router.models import Router

    schema = f"portal_impr_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(_PG_URL)
    async with admin.begin() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        _PG_URL, connect_args={"server_settings": {"search_path": schema}}
    )
    metadata = MetaData()
    for model in (Organization, Location, Router):
        Table(
            model.__tablename__,
            metadata,
            *[
                Column(
                    c.name,
                    c.type,
                    nullable=not c.primary_key,
                    primary_key=c.primary_key,
                )
                for c in model.__table__.columns
            ],
        )
    PortalImpression.__table__.to_metadata(metadata)
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        for org in (ORG, OTHER_ORG):
            await conn.execute(
                text(
                    "INSERT INTO organizations (id, name, slug, status, "
                    "is_deleted) VALUES (:id, 'o', :slug, 'active', false)"
                ),
                {"id": org, "slug": org.hex},
            )
        await conn.execute(
            text(
                "INSERT INTO locations (id, organization_id, name, slug, status, "
                "is_deleted) VALUES (:id, :org, 'l', 'l', 'active', false)"
            ),
            {"id": LOC, "org": ORG},
        )
        await conn.execute(
            text(
                "INSERT INTO routers (id, organization_id, location_id, name, "
                "serial_number, is_deleted) VALUES (:id, :org, :loc, 'r', 's', false)"
            ),
            {"id": ROUTER, "org": ORG, "loc": LOC},
        )
    try:
        yield engine, (lambda: AsyncSession(engine))
    finally:
        await engine.dispose()
        async with admin.begin() as conn:
            await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def _rows(engine):
    from sqlalchemy import select

    async with engine.connect() as conn:
        return (
            await conn.execute(
                select(
                    PortalImpression.organization_id,
                    PortalImpression.router_id,
                    PortalImpression.client_mac_hash,
                ).order_by(PortalImpression.occurred_at)
            )
        ).all()


class TestRealInsert:
    async def test_dedupe_tenant_check_and_router_scoping(self, pg_factory) -> None:
        engine, factory = pg_factory
        t0 = datetime(2026, 10, 30, 12, tzinfo=UTC)

        async def rec(**kw):
            return await pi.record_portal_impression(session_factory=factory, **kw)

        base = {"organization_id": ORG, "location_id": LOC}
        assert await rec(**base, router_id=ROUTER, device_mac=MAC, occurred_at=t0)
        # Same device reloading inside ten minutes: collapsed.
        assert not await rec(
            **base,
            router_id=ROUTER,
            device_mac=MAC,
            occurred_at=t0 + timedelta(minutes=3),
        )
        # ...but counted again after the window.
        assert await rec(
            **base,
            router_id=ROUTER,
            device_mac=MAC,
            occurred_at=t0 + timedelta(minutes=11),
        )
        # No MAC: always recorded, no key.
        assert await rec(**base, router_id=None, device_mac=None, occurred_at=t0)
        # A router that is not at this location is dropped to NULL.
        assert await rec(
            **base,
            router_id=uuid.uuid4(),
            device_mac="AA:BB:CC:DD:EE:02",
            occurred_at=t0,
        )
        # Location claimed for another organization: nothing written.
        assert not await rec(
            organization_id=OTHER_ORG,
            location_id=LOC,
            router_id=None,
            device_mac=None,
            occurred_at=t0,
        )
        rows = await _rows(engine)
        assert len(rows) == 4
        assert {r.organization_id for r in rows} == {ORG}
        assert sorted(str(r.router_id) for r in rows) == sorted(
            [str(ROUTER), str(ROUTER), "None", "None"]
        )
        assert sum(1 for r in rows if r.client_mac_hash is None) == 1

    async def test_purge_on_real_table(self, pg_factory) -> None:
        engine, factory = pg_factory
        now = datetime(2026, 10, 30, tzinfo=UTC)
        for days in (1, 91, 93, 200):
            await pi.record_portal_impression(
                organization_id=ORG,
                location_id=LOC,
                router_id=None,
                device_mac=None,
                occurred_at=now - timedelta(days=days),
                session_factory=factory,
            )
        async with factory() as session:
            summary = await pi.purge_expired_impressions(session, now=now, batch_size=1)
        assert summary["deleted"] == 2
        assert len(await _rows(engine)) == 2
