"""JAZE-3 (ADDENDUM_05 J4/J5/J6/J12/J17/J18): compliance logic + guards."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import compliance_logic as logic
from app.domains.isp_partner.compliance_kyc import (
    fy_of,
    render_caf_pdf,
    sniff_type,
    validate_document,
)
from app.domains.isp_partner.compliance_reports import CATALOGUE, catalogue
from app.domains.isp_partner.compliance_router import agr_csv, report_csv, trai_csv
from app.domains.isp_partner.compliance_service import (
    SESSION_DUMP_COLUMNS,
    session_dump_row,
)
from app.domains.isp_partner.compliance_tasks import due, previous_period
from app.domains.isp_partner.exceptions import IspBadRequestError

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


# -- J4 ----------------------------------------------------------------------


class TestSubscriberState:
    def _s(self, status="active", valid=None, overlay=None):
        return logic.subscriber_state(
            status=status, valid_until=valid, now=NOW, overlay=overlay
        )

    def test_open_ended_active(self) -> None:
        assert self._s() == "active"

    def test_lapsed_is_expired_then_churned(self) -> None:
        assert self._s(valid=NOW - timedelta(days=3)) == "expired"
        assert self._s(valid=NOW - timedelta(days=61)) == "churned"
        assert self._s(status="expired", valid=None) == "expired"

    def test_disabled_is_blocked(self) -> None:
        assert self._s(status="disabled") == "blocked"

    def test_overlay_wins(self) -> None:
        assert self._s(overlay="frozen", valid=NOW - timedelta(days=99)) == "frozen"
        assert self._s(overlay="suspended") == "suspended"
        assert self._s(overlay="nonsense") == "active"

    def test_counts_add_up_and_side_counters(self) -> None:
        a, b, c, d = (uuid.uuid4() for _ in range(4))
        rows = [
            {
                "id": a,
                "status": "active",
                "valid_until": NOW + timedelta(days=2),
                "created_at": NOW - timedelta(days=1),
            },
            {
                "id": b,
                "status": "active",
                "valid_until": NOW + timedelta(days=30),
                "created_at": NOW - timedelta(days=40),
            },
            {
                "id": c,
                "status": "disabled",
                "valid_until": None,
                "created_at": NOW - timedelta(days=40),
            },
            {
                "id": d,
                "status": "active",
                "valid_until": NOW - timedelta(days=90),
                "created_at": NOW - timedelta(days=200),
            },
        ]
        out = logic.count_states(
            rows,
            now=NOW,
            online_ids={a, c},
            renewal_ids=set(),
            churn_after=timedelta(days=60),
        )
        assert out["total"] == 4
        states = ("active", "expired", "suspended", "frozen", "blocked", "churned")
        assert sum(out[k] for k in states) == 4
        assert (out["active"], out["blocked"], out["churned"]) == (2, 1, 1)
        assert out["expiring_7d"] == 1
        assert out["new_7d"] == 1
        assert out["online"] == 2


class TestNatFeed:
    def _f(self, **kw):
        base = dict(
            last_nat_at=None,
            export_configured=True,
            router_online=True,
            now=NOW,
            stale_after=timedelta(minutes=60),
        )
        return logic.nat_feed_state(**{**base, **kw})

    def test_states(self) -> None:
        assert self._f(last_nat_at=NOW - timedelta(minutes=5)) == logic.FEED_OK
        assert self._f(last_nat_at=NOW - timedelta(hours=3)) == logic.FEED_STALE
        assert self._f() == logic.FEED_NEVER
        assert self._f(export_configured=False) == logic.FEED_NOT_CONFIGURED
        assert self._f(router_online=False) == logic.FEED_ROUTER_OFFLINE

    def test_fresh_data_beats_an_offline_flag(self) -> None:
        assert (
            self._f(router_online=False, last_nat_at=NOW - timedelta(minutes=1))
            == logic.FEED_OK
        )

    def test_offline_router_does_not_raise_the_banner(self) -> None:
        assert logic.FEED_ROUTER_OFFLINE not in logic.FEED_ALERTING
        assert logic.FEED_NEVER in logic.FEED_ALERTING


# -- J5 ----------------------------------------------------------------------


def _rec(**kw):
    base = {
        "ts": (NOW - timedelta(seconds=10)).isoformat(),
        "ts_end": (NOW + timedelta(seconds=30)).isoformat(),
        "organization_id": "o1",
        "user_known": True,
        "user_id": "9876543210",
        "mac": "AA:BB:CC:DD:EE:FF",
        "src_ip": "192.168.88.45",
        "src_port": 50681,
        "nat_ip": "203.0.113.80",
        "nat_port": 50681,
        "protocol": 6,
        "dst_ip": "198.51.100.7",
        "dst_port": 443,
    }
    return {**base, **kw}


Q = logic.LookupQuery(
    public_ip="203.0.113.80", public_port=50681, at=NOW, tolerance=timedelta(seconds=60)
)


class TestCgnat:
    def test_match_on_address_port_and_overlap(self) -> None:
        assert logic.record_covers(_rec(), Q)

    def test_other_port_or_ip_does_not_match(self) -> None:
        assert not logic.record_covers(_rec(nat_port=1), Q)
        assert not logic.record_covers(_rec(nat_ip="203.0.113.81"), Q)

    def test_outside_window_does_not_match(self) -> None:
        old = (NOW - timedelta(hours=1)).isoformat()
        assert not logic.record_covers(_rec(ts=old, ts_end=old), Q)

    def test_a_long_connection_spanning_the_instant_matches(self) -> None:
        r = _rec(
            ts=(NOW - timedelta(hours=2)).isoformat(),
            ts_end=(NOW + timedelta(hours=1)).isoformat(),
        )
        assert logic.record_covers(r, Q)

    def test_portless_query_matches_any_port(self) -> None:
        q = logic.LookupQuery(
            public_ip=Q.public_ip, public_port=None, at=NOW, tolerance=Q.tolerance
        )
        assert logic.record_covers(_rec(nat_port=9), q)

    def test_protocol_and_destination_filters(self) -> None:
        q = logic.LookupQuery(
            public_ip=Q.public_ip,
            public_port=None,
            at=NOW,
            tolerance=Q.tolerance,
            protocol=17,
        )
        assert not logic.record_covers(_rec(), q)
        q2 = logic.LookupQuery(
            public_ip=Q.public_ip,
            public_port=None,
            at=NOW,
            tolerance=Q.tolerance,
            dst_port=80,
        )
        assert not logic.record_covers(_rec(), q2)

    def test_verdicts_never_guess(self) -> None:
        assert logic.verdict([], had_nat_data=False) == logic.VERDICT_NO_DATA
        assert logic.verdict([], had_nat_data=True) == logic.VERDICT_NONE
        assert (
            logic.verdict([_rec(), _rec()], had_nat_data=True) == logic.VERDICT_UNIQUE
        )
        two = [
            _rec(),
            _rec(user_id="9000000000", mac="11:22:33:44:55:66", src_ip="192.168.88.46"),
        ]
        assert logic.verdict(two, had_nat_data=True) == logic.VERDICT_MULTIPLE
        unknown = [_rec(user_known=False, user_id="unknown")]
        assert logic.verdict(unknown, had_nat_data=True) == logic.VERDICT_UNIQUE
        unknowns = [_rec(user_known=False), _rec(user_known=False, mac="x", src_ip="y")]
        assert logic.verdict(unknowns, had_nat_data=True) == logic.VERDICT_MULTIPLE

    def test_normalize_ip(self) -> None:
        assert logic.normalize_ip(" 203.0.113.80 ") == "203.0.113.80"
        with pytest.raises(ValueError):
            logic.normalize_ip("not-an-ip")


# -- J6 ----------------------------------------------------------------------

#: A Verhoeff-valid 12-digit number made up for the test (not a real person's).
VALID_AADHAAR = "234123412346"


class TestIdNumbers:
    def test_test_number_is_verhoeff_valid(self) -> None:
        assert logic.verhoeff_ok(VALID_AADHAAR)
        assert not logic.verhoeff_ok("234123412345")

    def test_aadhaar_keeps_only_last_four(self) -> None:
        stored, last4 = logic.mask_id_number("aadhaar", "2341 2341 2346")
        assert stored == "XXXX XXXX 2346" and last4 == "2346"
        assert VALID_AADHAAR not in stored

    def test_aadhaar_masked_inputs(self) -> None:
        assert logic.mask_id_number("aadhaar", "2346") == ("XXXX XXXX 2346", "2346")
        assert logic.mask_id_number("aadhaar", "XXXXXXXX2346")[1] == "2346"

    def test_bad_aadhaar_refused(self) -> None:
        for bad in ("234123412345", "12345", "134123412346"):
            with pytest.raises(logic.IdNumberError):
                logic.mask_id_number("aadhaar", bad)

    def test_pan_format(self) -> None:
        assert logic.mask_id_number("pan", "abcde1234f") == ("ABCDE1234F", "234F")
        with pytest.raises(logic.IdNumberError):
            logic.mask_id_number("pan", "ABC123")

    def test_display_masks_non_aadhaar_unless_unmasked(self) -> None:
        assert logic.display_id_number("ABCDE1234F", unmasked=False) == "XXXXXX234F"
        assert logic.display_id_number("ABCDE1234F", unmasked=True) == "ABCDE1234F"
        assert (
            logic.display_id_number("XXXX XXXX 2346", unmasked=True) == "XXXX XXXX 2346"
        )

    async def test_upsert_never_stores_a_full_aadhaar(self) -> None:
        from app.domains.isp_partner.compliance_kyc import upsert_kyc

        class Db:
            added: list = []

            async def execute(self, *_a, **_k):
                return SimpleNamespace(scalar_one_or_none=lambda: None)

            def add(self, row):
                self.added.append(row)

            async def flush(self):
                pass

        db = Db()
        kyc = await upsert_kyc(
            db,
            isp_org_id=uuid.uuid4(),
            subscriber_id=uuid.uuid4(),
            body={
                "id_proof_type": "aadhaar",
                "id_number": VALID_AADHAAR,
                "full_name": " Test Person ",
                "installation_pincode": "324007",
            },
            actor=None,
        )
        assert kyc.id_number_masked == "XXXX XXXX 2346"
        assert kyc.full_name == "Test Person"
        assert VALID_AADHAAR not in repr(vars(kyc))

    async def test_number_without_type_refused(self) -> None:
        from app.domains.isp_partner.compliance_kyc import upsert_kyc

        class Db:
            async def execute(self, *_a, **_k):
                return SimpleNamespace(scalar_one_or_none=lambda: None)

            def add(self, row):
                pass

            async def flush(self):
                pass

        with pytest.raises(IspBadRequestError):
            await upsert_kyc(
                Db(),
                isp_org_id=uuid.uuid4(),
                subscriber_id=uuid.uuid4(),
                body={"id_number": VALID_AADHAAR},
                actor=None,
            )


class TestDocuments:
    def test_sniff(self) -> None:
        assert sniff_type(b"\xff\xd8\xff\xe0rest") == "image/jpeg"
        assert sniff_type(b"\x89PNG\r\n\x1a\nrest") == "image/png"
        assert sniff_type(b"%PDF-1.7") == "application/pdf"
        assert sniff_type(b"<html>") is None

    def test_validate(self) -> None:
        assert validate_document("id_proof", b"%PDF-1.4 x") == "application/pdf"
        for kind, content in (
            ("photo", b"%PDF-1.4"),
            ("bogus", b"%PDF-1.4"),
            ("id_proof", b""),
            ("id_proof", b"GIF89a"),
            ("id_proof", b"%PDF" + b"0" * (logic.MAX_DOCUMENT_BYTES + 1)),
        ):
            with pytest.raises(IspBadRequestError):
                validate_document(kind, content)


def test_fy_of() -> None:
    assert fy_of(date(2026, 3, 31)) == "25-26"
    assert fy_of(date(2026, 4, 1)) == "26-27"


def test_caf_pdf_renders_and_masks() -> None:
    pdf = render_caf_pdf(
        isp={
            "legal_name": "Test ISP & Co",
            "licence_number": "TEST-UL-1",
            "registered_address": "Line 1",
            "gstin": None,
        },
        subscriber={"username": "u1", "circuit_id": 7, "name": "A <B>", "phone": None},
        kyc={
            "caf_number": "CAF/26-27/1",
            "id_proof_type": "aadhaar",
            "id_number": "XXXX XXXX 2346",
            "applicant_type": "individual",
        },
        photo=b"not an image",
    )
    assert pdf.startswith(b"%PDF") and len(pdf) > 1500


# -- J12 ---------------------------------------------------------------------


def test_session_dump_row_has_every_column_and_prefers_kyc() -> None:
    sess = SimpleNamespace(
        started_at=NOW,
        ended_at=NOW + timedelta(minutes=5),
        auth_method="otp",
        ip_address="192.168.88.45",
        status="disconnected",
        bytes_uploaded=10,
        bytes_downloaded=20,
        user_agent="Mozilla/5.0 (Linux; Android 14) Chrome/120 Mobile Safari/537",
    )
    guest = SimpleNamespace(identifier="9876543210", email=None, display_name="G")
    sub = SimpleNamespace(
        first_name="Sub",
        last_name="Name",
        display_name=None,
        phone=None,
        email="s@example.com",
        address="billing addr",
        circuit_id=42,
    )
    kyc = SimpleNamespace(
        full_name="KYC Name",
        installation_address="install addr",
        gender="female",
        caf_number="CAF/26-27/3",
    )
    row = session_dump_row(
        sess,
        guest,
        mac="AA:BB:CC:DD:EE:FF",
        router_name="hEX",
        location_name="L",
        customer_name="C",
        subscriber=sub,
        kyc=kyc,
        zone_name="Z",
    )
    assert set(row) == set(SESSION_DUMP_COLUMNS)
    assert row["Name"] == "KYC Name" and row["Address"] == "install addr"
    assert row["Phone"] == "9876543210"
    assert row["Duration (s)"] == 300
    assert (row["Device Type"], row["Browser"]) == ("Mobile", "Chrome")
    assert row["Subscriber ID"] == 42


# -- J17 ---------------------------------------------------------------------


class TestTrai:
    def test_tiers(self) -> None:
        assert logic.speed_tier(1500) == "< 2 Mbps"
        assert logic.speed_tier(2000) == "2 - 10 Mbps"
        assert logic.speed_tier(50_000) == "50 - 100 Mbps"
        assert logic.speed_tier(100_000) == "> 100 Mbps"
        assert logic.speed_tier(None) == logic.TIER_UNKNOWN

    def test_month_bounds_is_ist(self) -> None:
        start, end = logic.month_bounds("2026-12")
        assert start.isoformat() == "2026-12-01T00:00:00+05:30"
        assert end.isoformat() == "2027-01-01T00:00:00+05:30"
        with pytest.raises(ValueError):
            logic.month_bounds("2026-13")

    def test_trai_csv_reports(self) -> None:
        data = {
            "period": "2026-10",
            "timezone": "Asia/Kolkata",
            "subscriptions_by_speed": [{"tier": "< 2 Mbps", "subscribers": 3}],
            "subscriptions_total": 3,
            "gigabit_threshold_mbps": 1000,
            "gigabit_subscribers": [
                {
                    "circuit_id": 1,
                    "username": "=cmd",
                    "customer_name": "C",
                    "download_mbps": 1000.0,
                }
            ],
            "public_wifi_hotspots": {
                "venues": 1,
                "nas_routers": 1,
                "access_points": None,
                "access_points_note": "n",
                "registered_users": 2,
                "users_active_in_period": 1,
                "sessions_in_period": 4,
                "download_bytes": 5,
                "upload_bytes": 6,
            },
            "data_usage": {
                "download_bytes": 5,
                "upload_bytes": 6,
                "download_tb": 0.0,
                "upload_tb": 0.0,
                "source": "s",
            },
        }
        assert b"Total,3" in trai_csv(data, "subscriptions")
        gig = trai_csv(data, "gigabit")
        assert b",'=cmd," in gig  # formula injection neutralised
        assert b"access_points," in trai_csv(data, "hotspots")
        assert b"download_tb" in trai_csv(data, "data_usage")


def test_agr_split_excludes_gst_and_nets_credit_notes() -> None:
    out = logic.agr_split(
        [
            {"sac_code": "998422", "taxable_paise": 100_000, "sign": 1},
            {"sac_code": "998422", "taxable_paise": 20_000, "sign": -1},
            {"sac_code": "995461", "taxable_paise": 50_000, "sign": 1},
        ]
    )
    assert out == {
        "telecom_taxable_paise": 80_000,
        "other_taxable_paise": 50_000,
        "gross_taxable_paise": 130_000,
    }
    csv_bytes = agr_csv(
        {
            "since": "2026-04-01",
            "until": "2026-10-31",
            **out,
            "gst_collected_paise": 0,
            "by_sac": [{"sac_code": "998422", "taxable_paise": 80_000}],
            "notes": ["n"],
        }
    )
    assert b"800.00" in csv_bytes


def test_schedule_period_and_due() -> None:
    assert previous_period(date(2026, 1, 5)) == "2025-12"
    s = SimpleNamespace(
        enabled=True,
        recipients=["a@example.com"],
        day_of_month=3,
        last_period_sent=None,
    )
    assert not due(s, date(2026, 11, 2))
    assert due(s, date(2026, 11, 3))
    s.last_period_sent = "2026-10"
    assert not due(s, date(2026, 11, 20))


# -- J18 ---------------------------------------------------------------------


def test_catalogue_marks_other_lanes_pending() -> None:
    items = {i["key"]: i for i in catalogue()}
    assert set(items) == set(CATALOGUE)
    assert items["invoices_per_day"]["available"]
    assert not items["security_deposits"]["available"]
    assert "JAZE-4" in items["security_deposits"]["pending"]
    pending = report_csv(
        {
            "title": "T",
            "since": "a",
            "until": "b",
            "available": False,
            "pending": "Data source pending (JAZE-1)",
        }
    )
    assert b"pending" in pending and b"0" not in pending.split(b"\n", 1)[1]


async def test_pending_report_runs_no_query() -> None:
    from app.domains.isp_partner.compliance_reports import IspComplianceReports

    class NoDb:
        async def execute(self, *_a, **_k):
            raise AssertionError("must not query")

    isp = SimpleNamespace(child_ids=None)
    out = await IspComplianceReports(NoDb()).run(
        isp,
        "moved_subscribers",
        since=NOW - timedelta(days=1),
        until=NOW,
        unmasked=False,
    )
    assert out["available"] is False and out["rows"] == []


async def test_reports_with_no_customers_never_query() -> None:
    from app.domains.isp_partner.compliance_reports import IspComplianceReports

    class NoDb:
        async def execute(self, *_a, **_k):
            raise AssertionError("must not query")

    async def none():
        return []

    isp = SimpleNamespace(child_ids=none)
    for key, (_t, _c, owner) in CATALOGUE.items():
        if owner is None:
            out = await IspComplianceReports(NoDb()).run(
                isp, key, since=NOW - timedelta(days=1), until=NOW, unmasked=False
            )
            assert out["rows"] == [] and out["columns"]


# -- guards ------------------------------------------------------------------

from tests.unit.test_isp_partner_hard_rules import (  # noqa: E402,F401
    AUDITS,
    _h,
    client,
)

PATHS = [
    ("GET", "/api/v1/isp/compliance/counters"),
    ("GET", "/api/v1/isp/compliance/nat-feed"),
    ("GET", "/api/v1/isp/compliance/reports"),
    ("GET", "/api/v1/isp/compliance/settings"),
    ("GET", "/api/v1/isp/compliance/trai-pmr?period=2026-10"),
    (
        "GET",
        "/api/v1/isp/compliance/cgnat-lookup?public_ip=203.0.113.80&at=2026-10-24T20:15:30",
    ),
    ("GET", f"/api/v1/isp/compliance/subscribers/{uuid.uuid4()}/kyc"),
]


@pytest.mark.parametrize(("method", "path"), PATHS)
def test_flag_off_is_a_plain_404(method, path) -> None:
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app(), raise_server_exceptions=False) as c:
        r = c.request(method, path, headers=_h())
    assert r.status_code == 404


@pytest.mark.parametrize(("method", "path"), PATHS)
def test_non_isp_org_is_refused(client, method, path) -> None:  # noqa: F811
    from tests.unit.isp_partner_fixtures import CUST_A1

    r = client.c.request(method, path, headers=_h(org=CUST_A1))
    assert r.status_code in (401, 403, 404), r.text
    assert client.db.writes == []


def test_location_header_refused(client) -> None:  # noqa: F811
    r = client.c.get(
        "/api/v1/isp/compliance/counters",
        headers=_h(**{"X-Location-Id": str(uuid.uuid4())}),
    )
    assert r.status_code == 400
