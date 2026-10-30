"""``GET /analytics/venue-insights/*`` -- customer-dashboard business insights.

Layers:

1. Pure helpers (window, timezone, percent).
2. Service behaviour against ``_ReferenceRepository`` -- a direct Python
   statement of the documented semantics -- and, when
   ``CLOUDGUEST_TEST_POSTGRES_URL`` points at a scratch Postgres database,
   against the real ``VenueInsightsRepository`` SQL too (this repo has no
   database-backed CI, so in CI only the reference half runs).
3. Route contract: permission key + explicit scope, RequireOrganization,
   cross-tenant 404, sibling-site 403, 422s.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.common.exceptions import register_exception_handlers
from app.domains.analytics.venue_insights import (
    MAX_WINDOW_DAYS,
    NO_ROUTER_MESSAGE,
    OMADA_LEGACY_MESSAGE,
    OTP_AUTH_METHODS,
    GuestMixRow,
    InternetConfirmedRow,
    InvalidInsightWindowError,
    LocationActivityRow,
    LocationContext,
    LoginMethodRow,
    OtpFunnelRow,
    PortalImpressionRow,
    RouterCoverageRow,
    RouterLivenessRow,
    VenueInsightsRepository,
    VenueInsightsService,
    percent,
    resolve_timezone,
    resolve_window,
    router_confirmation_gap,
)
from app.domains.analytics.venue_insights_router import (
    get_venue_insights_service,
)
from app.domains.analytics.venue_insights_router import (
    router as venue_router,
)
from app.domains.location.exceptions import LocationNotFoundError
from app.domains.rbac.dependencies import (
    CurrentLocation,
    CurrentOrganization,
    RequireOrganization,
)
from app.domains.rbac.enums import ScopeType

ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
LOC_A = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
LOC_A2 = uuid.UUID("00000000-0000-0000-0000-0000000000a2")
ORG_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
LOC_B = uuid.UUID("00000000-0000-0000-0000-0000000000b1")
IST = "Asia/Kolkata"


def _utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


WIN_START = _utc(2026, 10, 1)
WIN_END = _utc(2026, 10, 29)


# ============================================================================
# 1. Pure helpers
# ============================================================================


class TestHelpers:
    def test_default_window_is_trailing_28_days(self) -> None:
        now = _utc(2026, 10, 30, 12)
        start, end = resolve_window(None, None, now=now)
        assert (start, end) == (now - timedelta(days=28), now)

    def test_naive_datetimes_are_utc(self) -> None:
        start, end = resolve_window(datetime(2026, 10, 1), datetime(2026, 10, 2))
        assert start == _utc(2026, 10, 1) and end == _utc(2026, 10, 2)

    @pytest.mark.parametrize(
        ("start", "end"),
        [
            (_utc(2026, 10, 2), _utc(2026, 10, 1)),
            (_utc(2026, 10, 1), _utc(2026, 10, 1)),
            (_utc(2026, 1, 1), _utc(2026, 1, 1) + timedelta(days=MAX_WINDOW_DAYS + 1)),
        ],
    )
    def test_bad_windows_raise(self, start, end) -> None:
        with pytest.raises(InvalidInsightWindowError):
            resolve_window(start, end)

    def test_timezone_prefers_location_then_org_then_utc(self) -> None:
        assert resolve_timezone(IST, "Europe/London") == IST
        assert resolve_timezone("UTC", IST) == IST
        assert resolve_timezone("Not/AZone", IST) == IST
        assert resolve_timezone("UTC", "UTC") == "UTC"
        assert resolve_timezone(None, "garbage") == "UTC"

    def test_percent(self) -> None:
        assert percent(1, 3) == 33.3
        assert percent(0, 0) is None


# ============================================================================
# 2. Behaviour
# ============================================================================


class _ReferenceRepository:
    """In-memory statement of the documented semantics."""

    def __init__(self) -> None:
        self.locations: dict[uuid.UUID, dict] = {}
        self.sessions: list[dict] = []
        self.otps: list[dict] = []
        self.logins: list[dict] = []
        self.routers: list[dict] = []
        self.impressions: list[dict] = []
        self.integrations: list[dict] = []
        self.calls: list[uuid.UUID] = []

    # --- seeding --------------------------------------------------------
    async def add_location(self, location_id, org, name="Site", tz=IST, org_tz="UTC"):
        self.locations[location_id] = {
            "organization_id": org,
            "name": name,
            "tz": tz,
            "org_tz": org_tz,
            "is_deleted": False,
        }

    async def add_session(self, **row) -> None:
        self.sessions.append({"is_deleted": False, **row})

    async def add_otp(self, **row) -> None:
        self.otps.append({"is_deleted": False, "purpose": "guest_login", **row})

    async def add_login(self, **row) -> None:
        self.logins.append({"is_deleted": False, **row})

    async def add_router(self, **row) -> None:
        self.routers.append({"is_deleted": False, **row})

    async def add_impression(self, **row) -> None:
        self.impressions.append(row)

    async def add_integration(self, **row) -> None:
        self.integrations.append({"is_deleted": False, **row})

    # --- protocol -------------------------------------------------------
    def _scoped_sessions(self, org, loc, start, end):
        return [
            s
            for s in self.sessions
            if s["organization_id"] == org
            and s["location_id"] == loc
            and not s["is_deleted"]
            and start <= s["started_at"] < end
        ]

    async def get_location_context(self, *, organization_id, location_id):
        self.calls.append(organization_id)
        loc = self.locations.get(location_id)
        if loc is None or loc["organization_id"] != organization_id:
            return None
        return LocationContext(
            location_id=location_id, timezone=resolve_timezone(loc["tz"], loc["org_tz"])
        )

    async def get_peak_hour_cells(
        self, *, organization_id, location_id, timezone, start, end
    ):
        tz = ZoneInfo(timezone)
        cells: dict[tuple[int, int], list] = {}
        for s in self._scoped_sessions(organization_id, location_id, start, end):
            local = s["started_at"].astimezone(tz)
            cell = cells.setdefault((local.isoweekday(), local.hour), [0, set()])
            cell[0] += 1
            cell[1].add(s["guest_id"])
        return [(d, h, n, len(g)) for (d, h), (n, g) in cells.items()]

    async def get_guest_mix(
        self, *, organization_id, location_id, timezone, start, end
    ):
        tz = ZoneInfo(timezone)
        rows = self._scoped_sessions(organization_id, location_id, start, end)
        days: dict[uuid.UUID, set[date]] = {}
        for s in rows:
            days.setdefault(s["guest_id"], set()).add(
                s["started_at"].astimezone(tz).date()
            )
        at_location = [
            s
            for s in self.sessions
            if s["organization_id"] == organization_id
            and s["location_id"] == location_id
            and not s["is_deleted"]
        ]
        before = {s["guest_id"] for s in at_location if s["started_at"] < start}
        return GuestMixRow(
            unique_guests=len(days),
            returning_guests=len(set(days) & before),
            multi_visit_guests=sum(1 for d in days.values() if len(d) >= 2),
            sessions=len(rows),
            history_starts_at=min((s["started_at"] for s in at_location), default=None),
        )

    async def get_otp_funnel(self, *, organization_id, location_id, start, end):
        otps = [
            o
            for o in self.otps
            if o["location_id"] == location_id
            and o["organization_id"] in (organization_id, None)
            and o["purpose"] == "guest_login"
            and not o["is_deleted"]
            and start <= o["created_at"] < end
        ]
        signed = {
            row["identifier"]
            for row in self.logins
            if row["organization_id"] == organization_id
            and row["location_id"] == location_id
            and not row["is_deleted"]
            and row["success"]
            and row["auth_method"] in OTP_AUTH_METHODS
            and start <= row["attempted_at"] < end
        }
        return OtpFunnelRow(
            codes_sent=len(otps),
            requested_identifiers=len({o["identifier"] for o in otps}),
            verified_identifiers=len(
                {o["identifier"] for o in otps if o["verified_at"] is not None}
            ),
            signed_in_identifiers=len(signed),
        )

    async def get_login_methods(self, *, organization_id, location_id, start, end):
        grouped: dict[str, list] = {}
        for row in self.logins:
            if not (
                row["organization_id"] == organization_id
                and row["location_id"] == location_id
                and not row["is_deleted"]
                and start <= row["attempted_at"] < end
            ):
                continue
            g = grouped.setdefault(row["auth_method"], [0, 0, set()])
            if row["success"]:
                g[0] += 1
                g[2].add(row["identifier"])
            else:
                g[1] += 1
        return [
            LoginMethodRow(auth_method=m, successful=ok, failed=bad, guests=len(ids))
            for m, (ok, bad, ids) in grouped.items()
        ]

    async def get_portal_impressions(self, *, organization_id, location_id, start, end):
        scoped = [
            i
            for i in self.impressions
            if i["organization_id"] == organization_id
            and i["location_id"] == location_id
        ]
        window = [i for i in scoped if start <= i["occurred_at"] < end]
        return PortalImpressionRow(
            impressions=len(window),
            devices=len({i["client_mac_hash"] for i in window if i["client_mac_hash"]}),
            tracked_since=min((i["occurred_at"] for i in scoped), default=None),
        )

    async def get_internet_confirmed(self, *, organization_id, location_id, start, end):
        scoped = [
            s
            for s in self.sessions
            if s["organization_id"] == organization_id
            and s["location_id"] == location_id
            and not s["is_deleted"]
            and s.get("internet_confirmed_at") is not None
        ]
        window = [s for s in scoped if start <= s["internet_confirmed_at"] < end]
        return InternetConfirmedRow(
            guests=len({s["guest_id"] for s in window}),
            otp_guests=len(
                {
                    s["guest_id"]
                    for s in window
                    if s.get("auth_method", "otp_sms") in OTP_AUTH_METHODS
                }
            ),
            sessions=len(window),
            tracked_since=min(
                (s["internet_confirmed_at"] for s in scoped), default=None
            ),
        )

    async def get_router_coverage(self, *, organization_id, location_id):
        out = []
        for r in self.routers:
            if not (
                r["organization_id"] == organization_id
                and r["location_id"] == location_id
                and not r["is_deleted"]
                and r["status"] != "decommissioned"
            ):
                continue
            integ = next(
                (
                    i
                    for i in self.integrations
                    if i["router_id"] == r["id"]
                    and i["organization_id"] == organization_id
                    and not i["is_deleted"]
                ),
                None,
            )
            out.append(
                RouterCoverageRow(
                    vendor=r.get("vendor", "mikrotik"),
                    integration_auth_mode=integ and integ["auth_mode"],
                    integration_portal_mode=integ and integ["portal_mode"],
                )
            )
        return out

    async def get_location_activity(self, *, organization_id, start, end):
        out = []
        for loc_id, loc in self.locations.items():
            if loc["organization_id"] != organization_id or loc["is_deleted"]:
                continue
            rows = self._scoped_sessions(organization_id, loc_id, start, end)
            out.append(
                LocationActivityRow(
                    location_id=loc_id,
                    location_name=loc["name"],
                    guests=len({s["guest_id"] for s in rows}),
                    sessions=len(rows),
                )
            )
        return out

    async def get_router_liveness(self, *, organization_id):
        return [
            RouterLivenessRow(
                location_id=r["location_id"],
                status=r["status"],
                last_seen_at=r["last_seen_at"],
            )
            for r in self.routers
            if r["organization_id"] == organization_id
            and not r["is_deleted"]
            and r["status"] != "decommissioned"
        ]


_PG_URL = os.environ.get("CLOUDGUEST_TEST_POSTGRES_URL")


class _PostgresHarness:
    """Real ``VenueInsightsRepository`` over a throwaway schema holding copies
    of the six tables it reads, without foreign keys."""

    def __init__(self, session) -> None:
        self.session = session
        self.repository = VenueInsightsRepository(session)

    async def _insert(self, model, **row) -> None:
        from sqlalchemy import insert

        now = datetime.now(UTC)
        values = {
            "id": uuid.uuid4(),
            "created_at": now,
            "updated_at": now,
            "is_deleted": False,
            "version": 1,
            **row,
        }
        await self.session.execute(insert(model.__table__).values(**values))
        await self.session.flush()

    async def add_location(self, location_id, org, name="Site", tz=IST, org_tz="UTC"):
        from sqlalchemy import select

        from app.domains.location.models import Location
        from app.domains.organization.models import Organization

        exists = await self.session.execute(
            select(Organization.id).where(Organization.id == org)
        )
        if exists.first() is None:
            await self._insert(
                Organization,
                id=org,
                name=f"Org {org}",
                slug=f"org-{org.hex[:8]}",
                status="active",
                timezone=org_tz,
            )
        await self._insert(
            Location,
            id=location_id,
            organization_id=org,
            name=name,
            slug=f"loc-{location_id.hex[:8]}",
            status="active",
            timezone=tz,
        )

    async def add_session(self, **row) -> None:
        from app.domains.guest.models import GuestSession

        await self._insert(
            GuestSession,
            **{
                "router_id": uuid.uuid4(),
                "auth_method": "otp_sms",
                "status": "disconnected",
                "last_activity_at": row["started_at"],
                "bytes_uploaded": 0,
                "bytes_downloaded": 0,
                **row,
            },
        )

    async def add_otp(self, **row) -> None:
        from app.domains.otp.models import OtpRequest

        await self._insert(
            OtpRequest,
            channel="sms",
            purpose="guest_login",
            code_hash="x",
            expires_at=row["created_at"] + timedelta(minutes=5),
            attempt_count=0,
            max_attempts=5,
            is_consumed=row.get("verified_at") is not None,
            **row,
        )

    async def add_login(self, **row) -> None:
        from app.domains.guest.models import GuestLoginHistory

        await self._insert(GuestLoginHistory, **row)

    async def add_router(self, **row) -> None:
        from app.domains.router.models import Router

        await self._insert(
            Router,
            name="r",
            serial_number=uuid.uuid4().hex,
            **row,
        )

    async def add_impression(self, **row) -> None:
        from sqlalchemy import insert

        from app.domains.analytics.models import PortalImpression

        await self.session.execute(
            insert(PortalImpression.__table__).values(id=uuid.uuid4(), **row)
        )
        await self.session.flush()

    async def add_integration(self, **row) -> None:
        from app.domains.network_integration.models import NetworkIntegration

        await self._insert(
            NetworkIntegration,
            provider="omada",
            name="omada",
            base_url="https://c",
            **row,
        )


@pytest.fixture(params=["reference", "postgres"])
async def harness(request):
    if request.param == "reference":
        repo = _ReferenceRepository()
        yield repo, repo
        return
    if not _PG_URL:
        pytest.skip("CLOUDGUEST_TEST_POSTGRES_URL not set")
    from sqlalchemy import Column, MetaData, Table, text
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

    from app.domains.analytics.models import PortalImpression
    from app.domains.guest.models import GuestLoginHistory, GuestSession
    from app.domains.location.models import Location
    from app.domains.network_integration.models import NetworkIntegration
    from app.domains.organization.models import Organization
    from app.domains.otp.models import OtpRequest
    from app.domains.router.models import Router

    schema = f"venue_insights_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(_PG_URL)
    async with admin.begin() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        _PG_URL, connect_args={"server_settings": {"search_path": schema}}
    )
    metadata = MetaData()
    for model in (
        GuestSession,
        GuestLoginHistory,
        OtpRequest,
        Location,
        Organization,
        Router,
        PortalImpression,
        NetworkIntegration,
    ):
        Table(
            model.__tablename__,
            metadata,
            *[
                # nullable everywhere except the PK: the harness only fills
                # the columns these queries read.
                Column(
                    c.name,
                    c.type,
                    nullable=c.primary_key is False,
                    primary_key=c.primary_key,
                )
                for c in model.__table__.columns
            ],
        )
    try:
        async with engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        async with AsyncSession(engine) as session:
            h = _PostgresHarness(session)
            yield h, h.repository
    finally:
        await engine.dispose()
        async with admin.begin() as conn:
            await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


def _s(started_at, *, guest_id, org=ORG_A, loc=LOC_A, is_deleted=False) -> dict:
    return {
        "organization_id": org,
        "location_id": loc,
        "guest_id": guest_id,
        "started_at": started_at,
        "is_deleted": is_deleted,
    }


G1, G2, G3, G4 = (uuid.UUID(int=i) for i in range(1, 5))


class TestPeakHours:
    async def test_buckets_in_venue_timezone(self, harness) -> None:
        h, repo = harness
        await h.add_location(LOC_A, ORG_A)
        # Thu 1 Oct 2026, 13:00Z == 18:30 IST -> Thursday (4), hour 18.
        await h.add_session(**_s(_utc(2026, 10, 1, 13, 0), guest_id=G1))
        await h.add_session(**_s(_utc(2026, 10, 1, 13, 20), guest_id=G1))
        await h.add_session(**_s(_utc(2026, 10, 1, 13, 25), guest_id=G2))
        # 20:00Z Thu == 01:30 IST Fri -> Friday (5), hour 1.
        await h.add_session(**_s(_utc(2026, 10, 1, 20, 0), guest_id=G3))
        # Outside window / other org / deleted: ignored.
        await h.add_session(**_s(_utc(2026, 9, 30, 13, 0), guest_id=G4))
        await h.add_session(
            **_s(_utc(2026, 10, 1, 13, 0), guest_id=G4, is_deleted=True)
        )
        result = await VenueInsightsService(repo).get_peak_hours(
            organization_id=ORG_A, location_id=LOC_A, start=WIN_START, end=WIN_END
        )
        assert result.timezone == IST
        assert [(c.weekday, c.hour, c.sessions, c.guests) for c in result.cells] == [
            (4, 18, 3, 2),
            (5, 1, 1, 1),
        ]
        assert result.total_sessions == 4

    async def test_empty_location_has_no_cells(self, harness) -> None:
        h, repo = harness
        await h.add_location(LOC_A, ORG_A)
        result = await VenueInsightsService(repo).get_peak_hours(
            organization_id=ORG_A, location_id=LOC_A, start=WIN_START, end=WIN_END
        )
        assert result.cells == [] and result.total_sessions == 0

    async def test_other_orgs_location_is_404(self, harness) -> None:
        h, repo = harness
        await h.add_location(LOC_B, ORG_B)
        await h.add_session(**_s(_utc(2026, 10, 2), guest_id=G1, org=ORG_B, loc=LOC_B))
        with pytest.raises(LocationNotFoundError):
            await VenueInsightsService(repo).get_peak_hours(
                organization_id=ORG_A, location_id=LOC_B, start=WIN_START, end=WIN_END
            )


class TestGuestMix:
    async def test_new_vs_returning_is_relative_to_this_location(self, harness) -> None:
        h, repo = harness
        await h.add_location(LOC_A, ORG_A)
        await h.add_location(LOC_A2, ORG_A)
        # G1 visited LOC_A before the window -> returning.
        await h.add_session(**_s(_utc(2026, 9, 15), guest_id=G1))
        await h.add_session(**_s(_utc(2026, 10, 3, 6), guest_id=G1))
        # G2 visited only a sibling site before -> new here.
        await h.add_session(**_s(_utc(2026, 9, 15), guest_id=G2, loc=LOC_A2))
        await h.add_session(**_s(_utc(2026, 10, 3, 6), guest_id=G2))
        # G3 is new and comes on two separate local days -> multi-visit.
        await h.add_session(**_s(_utc(2026, 10, 4, 6), guest_id=G3))
        await h.add_session(**_s(_utc(2026, 10, 4, 7), guest_id=G3))
        await h.add_session(**_s(_utc(2026, 10, 9, 6), guest_id=G3))
        # Two sessions either side of IST midnight on the same UTC day are
        # two local days: 4 Oct 18:00Z = 23:30 IST, 4 Oct 18:45Z = 00:15 IST.
        await h.add_session(**_s(_utc(2026, 10, 4, 18, 0), guest_id=G4))
        await h.add_session(**_s(_utc(2026, 10, 4, 18, 45), guest_id=G4))
        result = await VenueInsightsService(repo).get_guest_mix(
            organization_id=ORG_A, location_id=LOC_A, start=WIN_START, end=WIN_END
        )
        assert (result.unique_guests, result.new_guests, result.returning_guests) == (
            4,
            3,
            1,
        )
        assert result.sessions == 7
        assert result.multi_visit_guests == 2
        assert result.repeat_visit_rate_percent == 50.0
        assert result.has_prior_history is True
        assert result.history_starts_at == _utc(2026, 9, 15).isoformat()

    async def test_no_history_before_window_is_flagged(self, harness) -> None:
        h, repo = harness
        await h.add_location(LOC_A, ORG_A)
        await h.add_session(**_s(_utc(2026, 10, 3), guest_id=G1))
        result = await VenueInsightsService(repo).get_guest_mix(
            organization_id=ORG_A, location_id=LOC_A, start=WIN_START, end=WIN_END
        )
        assert result.has_prior_history is False
        assert (result.new_guests, result.returning_guests) == (1, 0)

    async def test_empty(self, harness) -> None:
        h, repo = harness
        await h.add_location(LOC_A, ORG_A)
        result = await VenueInsightsService(repo).get_guest_mix(
            organization_id=ORG_A, location_id=LOC_A, start=WIN_START, end=WIN_END
        )
        assert result.unique_guests == 0
        assert result.repeat_visit_rate_percent is None
        assert result.history_starts_at is None


class TestLoginFunnel:
    async def test_stages_and_methods(self, harness) -> None:
        h, repo = harness
        await h.add_location(LOC_A, ORG_A)
        t = _utc(2026, 10, 5, 10)
        # +91A: two codes (resend), verified, signed in.
        await h.add_otp(
            identifier="+91A",
            organization_id=ORG_A,
            location_id=LOC_A,
            created_at=t,
            verified_at=None,
        )
        await h.add_otp(
            identifier="+91A",
            organization_id=None,
            location_id=LOC_A,
            created_at=t + timedelta(minutes=1),
            verified_at=t + timedelta(minutes=2),
        )
        # +91B: verified, never signed in (the gap that matters).
        await h.add_otp(
            identifier="+91B",
            organization_id=ORG_A,
            location_id=LOC_A,
            created_at=t,
            verified_at=t + timedelta(minutes=1),
        )
        # +91C: requested only.
        await h.add_otp(
            identifier="+91C",
            organization_id=ORG_A,
            location_id=LOC_A,
            created_at=t,
            verified_at=None,
        )
        # Another org's row naming this location id is excluded.
        await h.add_otp(
            identifier="+91X",
            organization_id=ORG_B,
            location_id=LOC_A,
            created_at=t,
            verified_at=t,
        )
        await h.add_login(
            identifier="+91A",
            organization_id=ORG_A,
            location_id=LOC_A,
            auth_method="otp_sms",
            success=True,
            attempted_at=t + timedelta(minutes=2),
        )
        await h.add_login(
            identifier="+91C",
            organization_id=ORG_A,
            location_id=LOC_A,
            auth_method="otp_sms",
            success=False,
            attempted_at=t,
            failure_reason="OtpInvalidCodeError",
        )
        await h.add_login(
            identifier="V1",
            organization_id=ORG_A,
            location_id=LOC_A,
            auth_method="voucher",
            success=True,
            attempted_at=t,
        )
        await h.add_login(
            identifier="V1",
            organization_id=ORG_A,
            location_id=LOC_A,
            auth_method="voucher",
            success=True,
            attempted_at=t + timedelta(hours=1),
        )
        result = await VenueInsightsService(repo).get_login_funnel(
            organization_id=ORG_A, location_id=LOC_A, start=WIN_START, end=WIN_END
        )
        assert result.otp_codes_sent == 4
        assert result.otp_requested_guests == 3
        assert result.otp_verified_guests == 2
        assert result.otp_signed_in_guests == 1
        # No router, no impressions: portal opened is tracked but empty,
        # internet confirmed says why it cannot be reported.
        assert result.portal_opened.available is True
        assert result.portal_opened.count == 0
        assert result.portal_opened.tracked_since is None
        assert result.internet_confirmed.available is False
        assert result.internet_confirmed.message == NO_ROUTER_MESSAGE
        assert [
            (m.auth_method, m.successful_logins, m.failed_logins, m.guests)
            for m in result.methods
        ] == [("voucher", 2, 0, 1), ("otp_sms", 1, 1, 1)]


class TestFunnelStages:
    """ "Portal opened" and "internet confirmed": counts, tracked_since, and
    the per-venue unavailable reason."""

    async def _venue(self, h, *, vendor="mikrotik"):
        await h.add_location(LOC_A, ORG_A)
        router_id = uuid.uuid4()
        await h.add_router(
            id=router_id,
            organization_id=ORG_A,
            location_id=LOC_A,
            status="online",
            last_seen_at=_utc(2026, 10, 28),
            vendor=vendor,
        )
        return router_id

    async def _funnel(self, repo, org=ORG_A, loc=LOC_A):
        return await VenueInsightsService(repo).get_login_funnel(
            organization_id=org, location_id=loc, start=WIN_START, end=WIN_END
        )

    async def test_portal_opened_counts_window_and_tracked_since(self, harness):
        h, repo = harness
        await self._venue(h)
        await h.add_location(LOC_B, ORG_B)
        first = _utc(2026, 9, 20)  # before the window: tracked_since only
        await h.add_impression(
            organization_id=ORG_A,
            location_id=LOC_A,
            router_id=None,
            occurred_at=first,
            client_mac_hash="d1",
        )
        for when, key in (
            (_utc(2026, 10, 2), "d1"),
            (_utc(2026, 10, 3), "d1"),
            (_utc(2026, 10, 3), "d2"),
            (_utc(2026, 10, 4), None),
        ):
            await h.add_impression(
                organization_id=ORG_A,
                location_id=LOC_A,
                router_id=None,
                occurred_at=when,
                client_mac_hash=key,
            )
        # Another tenant's impression is never counted.
        await h.add_impression(
            organization_id=ORG_B,
            location_id=LOC_B,
            router_id=None,
            occurred_at=_utc(2026, 10, 2),
            client_mac_hash="x",
        )
        result = await self._funnel(repo)
        stage = result.portal_opened
        assert stage.available is True
        assert (stage.count, stage.devices) == (4, 2)
        assert stage.tracked_since == first.isoformat()

    async def test_internet_confirmed_counts_and_otp_split(self, harness):
        h, repo = harness
        await self._venue(h)
        t = _utc(2026, 10, 5, 10)
        await h.add_session(
            **_s(t, guest_id=G1), internet_confirmed_at=t, auth_method="otp_sms"
        )
        await h.add_session(
            **_s(t + timedelta(hours=1), guest_id=G1),
            internet_confirmed_at=t + timedelta(hours=1),
            auth_method="otp_sms",
        )
        await h.add_session(
            **_s(t, guest_id=G2), internet_confirmed_at=t, auth_method="voucher"
        )
        # Signed in but never confirmed: not counted.
        await h.add_session(**_s(t, guest_id=G3), auth_method="otp_sms")
        result = await self._funnel(repo)
        stage = result.internet_confirmed
        assert stage.available is True
        assert (stage.count, stage.otp_guests, stage.sessions) == (2, 1, 3)
        assert stage.tracked_since == t.isoformat()
        assert stage.note is None

    async def test_omada_legacy_only_venue_is_unavailable_with_reason(self, harness):
        h, repo = harness
        router_id = await self._venue(h, vendor="tplink_omada")
        await h.add_integration(
            organization_id=ORG_A,
            router_id=router_id,
            auth_mode="legacy",
            portal_mode="external_portal",
        )
        result = await self._funnel(repo)
        assert result.internet_confirmed.available is False
        assert result.internet_confirmed.message == OMADA_LEGACY_MESSAGE

    async def test_mixed_venue_is_available_with_partial_note(self, harness):
        h, repo = harness
        omada = await self._venue(h, vendor="tplink_omada")
        await h.add_integration(
            organization_id=ORG_A,
            router_id=omada,
            auth_mode="legacy",
            portal_mode="external_portal",
        )
        await h.add_router(
            id=uuid.uuid4(),
            organization_id=ORG_A,
            location_id=LOC_A,
            status="online",
            last_seen_at=_utc(2026, 10, 28),
            vendor="mikrotik",
        )
        result = await self._funnel(repo)
        assert result.internet_confirmed.available is True
        assert result.internet_confirmed.note.startswith("1 of 2 routers")


class TestRouterConfirmationGap:
    @pytest.mark.parametrize(
        ("vendor", "auth", "mode", "has_signal"),
        [
            ("mikrotik", None, None, True),
            ("aruba_instant_on", None, None, True),
            ("tplink_omada", "openapi", "external_portal", True),
            ("tplink_omada", "legacy", "radius", True),
            ("tplink_omada", "legacy", "external_portal", False),
            ("tplink_omada", None, None, False),
        ],
    )
    def test_rule(self, vendor, auth, mode, has_signal) -> None:
        assert (router_confirmation_gap(vendor, auth, mode) is None) is has_signal


class TestLocationComparison:
    async def test_rows_per_location_with_liveness(self, harness) -> None:
        h, repo = harness
        now = datetime.now(UTC)
        await h.add_location(LOC_A, ORG_A, name="Andheri")
        await h.add_location(LOC_A2, ORG_A, name="Bandra")
        await h.add_location(LOC_B, ORG_B, name="Other tenant")
        await h.add_session(**_s(_utc(2026, 10, 2), guest_id=G1))
        await h.add_session(**_s(_utc(2026, 10, 3), guest_id=G1))
        await h.add_session(**_s(_utc(2026, 10, 3), guest_id=G2))
        await h.add_session(**_s(_utc(2026, 10, 2), guest_id=G3, org=ORG_B, loc=LOC_B))
        await h.add_router(
            organization_id=ORG_A,
            location_id=LOC_A,
            status="online",
            last_seen_at=now - timedelta(minutes=1),
        )
        await h.add_router(
            organization_id=ORG_A,
            location_id=LOC_A,
            status="online",
            last_seen_at=now - timedelta(days=2),
        )
        await h.add_router(
            organization_id=ORG_A,
            location_id=LOC_A2,
            status="decommissioned",
            last_seen_at=now,
        )
        result = await VenueInsightsService(repo).get_location_comparison(
            organization_id=ORG_A, start=WIN_START, end=WIN_END, now=now
        )
        rows = [
            (r.location_name, r.guests, r.sessions, r.routers_total, r.routers_online)
            for r in result.locations
        ]
        assert rows == [("Andheri", 2, 3, 2, 1), ("Bandra", 0, 0, 0, 0)]
        assert result.locations[1].last_router_seen_at is None


# ============================================================================
# 3. Route contract
# ============================================================================

BASE = "/api/v1/analytics/venue-insights"


def _route(app, path: str, method: str = "GET"):
    return next(
        r
        for r in app.routes
        if getattr(r, "path", None) == path and method in getattr(r, "methods", set())
    )


def _dependency_calls(dependant) -> set:
    calls = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        calls |= _dependency_calls(d)
    return calls


def _permission_deps(route) -> list[tuple[object, str, object]]:
    """``(dependency, permission_key, scope)`` for every RequirePermission."""
    found = []
    for dep in _dependency_calls(route.dependant):
        cells = [c.cell_contents for c in (getattr(dep, "__closure__", None) or ())]
        keys = [c for c in cells if isinstance(c, str) and "." in c]
        if keys:
            scope = next((c for c in cells if isinstance(c, ScopeType)), None)
            found.append((dep, keys[0], scope))
    return found


@pytest.mark.parametrize(
    ("suffix", "scope"),
    [
        ("/peak-hours", ScopeType.LOCATION),
        ("/guest-mix", ScopeType.LOCATION),
        ("/login-funnel", ScopeType.LOCATION),
        ("/locations", ScopeType.ORGANIZATION),
    ],
)
def test_routes_mounted_with_explicit_scope_and_required_org(suffix, scope) -> None:
    from app.main import create_app

    route = _route(create_app(), BASE + suffix)
    perms = _permission_deps(route)
    assert [(key, s) for _, key, s in perms] == [("analytics.read", scope)]
    calls = _dependency_calls(route.dependant)
    assert RequireOrganization in calls
    if scope is ScopeType.LOCATION:
        assert CurrentLocation in calls


def _app(repo, *, organization_id=ORG_A, scope_location_id=None) -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(venue_router, prefix="/api/v1")
    for path in ("/peak-hours", "/guest-mix", "/login-funnel", "/locations"):
        for dep, _, _ in _permission_deps(_route(app, BASE + path)):
            app.dependency_overrides[dep] = lambda: None
    app.dependency_overrides[RequireOrganization] = lambda: organization_id
    app.dependency_overrides[CurrentLocation] = lambda: scope_location_id
    app.dependency_overrides[get_venue_insights_service] = lambda: VenueInsightsService(
        repo
    )
    return app


async def _get(app: FastAPI, path: str, **params):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(BASE + path, params=params)


_WINDOW = {"start_date": "2026-10-01T00:00:00Z", "end_date": "2026-10-29T00:00:00Z"}


class TestHttp:
    @pytest.mark.parametrize("path", ["/peak-hours", "/guest-mix", "/login-funnel"])
    async def test_other_orgs_location_is_404_and_reads_nothing(self, path) -> None:
        repo = _ReferenceRepository()
        await repo.add_location(LOC_B, ORG_B)
        await repo.add_session(
            **_s(_utc(2026, 10, 2), guest_id=G1, org=ORG_B, loc=LOC_B)
        )
        response = await _get(
            _app(repo, organization_id=ORG_A),
            path,
            location_id=str(LOC_B),
            **_WINDOW,
        )
        assert response.status_code == 404, response.text
        assert response.json()["data"] == {}
        assert repo.calls == [ORG_A]

    @pytest.mark.parametrize("path", ["/peak-hours", "/guest-mix", "/login-funnel"])
    async def test_sibling_site_outside_location_grant_is_403(self, path) -> None:
        repo = _ReferenceRepository()
        await repo.add_location(LOC_A, ORG_A)
        await repo.add_location(LOC_A2, ORG_A)
        response = await _get(
            _app(repo, scope_location_id=LOC_A),
            path,
            location_id=str(LOC_A2),
            **_WINDOW,
        )
        assert response.status_code == 403, response.text
        assert repo.calls == []

    async def test_location_comparison_never_includes_other_tenants(self) -> None:
        repo = _ReferenceRepository()
        await repo.add_location(LOC_A, ORG_A, name="Mine")
        await repo.add_location(LOC_B, ORG_B, name="Theirs")
        response = await _get(_app(repo), "/locations", **_WINDOW)
        assert response.status_code == 200, response.text
        names = [r["location_name"] for r in response.json()["data"]["locations"]]
        assert names == ["Mine"]

    @pytest.mark.parametrize(
        "params",
        [
            {"location_id": "not-a-uuid"},
            {},
            {
                "location_id": str(LOC_A),
                "start_date": "2026-10-29T00:00:00Z",
                "end_date": "2026-10-01T00:00:00Z",
            },
            {
                "location_id": str(LOC_A),
                "start_date": "2026-01-01T00:00:00Z",
                "end_date": "2026-12-01T00:00:00Z",
            },
        ],
    )
    async def test_bad_params_are_422(self, params) -> None:
        repo = _ReferenceRepository()
        await repo.add_location(LOC_A, ORG_A)
        response = await _get(_app(repo), "/peak-hours", **params)
        assert response.status_code == 422, response.text

    async def test_response_envelope(self) -> None:
        repo = _ReferenceRepository()
        await repo.add_location(LOC_A, ORG_A)
        await repo.add_session(**_s(_utc(2026, 10, 1, 13, 0), guest_id=G1))
        response = await _get(
            _app(repo), "/peak-hours", location_id=str(LOC_A), **_WINDOW
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["success"] is True
        assert body["data"]["timezone"] == IST
        assert body["data"]["cells"] == [
            {"weekday": 4, "hour": 18, "sessions": 1, "guests": 1}
        ]


async def test_login_funnel_wire_shape_is_discriminated_on_available() -> None:
    repo = _ReferenceRepository()
    await repo.add_location(LOC_A, ORG_A)
    response = await _get(
        _app(repo), "/login-funnel", location_id=str(LOC_A), **_WINDOW
    )
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["portal_opened"] == {
        "available": True,
        "count": 0,
        "devices": 0,
        "tracked_since": None,
    }
    assert data["internet_confirmed"] == {
        "available": False,
        "message": NO_ROUTER_MESSAGE,
    }


def test_current_organization_is_not_used() -> None:
    """``CurrentOrganization`` resolves to None ("every tenant") for a global
    caller; the handlers must take the org from ``RequireOrganization``."""
    from app.main import create_app

    app = create_app()
    for suffix in ("/peak-hours", "/guest-mix", "/login-funnel", "/locations"):
        top_level = {d.call for d in _route(app, BASE + suffix).dependant.dependencies}
        assert RequireOrganization in top_level
        assert CurrentOrganization not in top_level
