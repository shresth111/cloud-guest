"""J16 Apps (ADDENDUM_05, JAZE-5): helpdesk, field tasks, announcements,
discount codes, inventory, leads.

Pure rules are tested directly. Isolation is tested through the service
entry points with the shared fakes: another ISP's customer/subscriber is a
404, and an empty customer list is "nothing", never "everything" (no query
runs). The route table rules (guard stack, no scope-alias names) are walked
by ``test_isp_partner_guards`` for every isp_partner route, including these.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import apps_common as common
from app.domains.isp_partner.apps_announcements import whatsapp_link
from app.domains.isp_partner.apps_discounts import quote_discount
from app.domains.isp_partner.apps_helpdesk import (
    HelpdeskService,
    apply_status,
    check_transition,
    sla_state,
    summarise,
    tat_minutes,
)
from app.domains.isp_partner.apps_inventory import (
    check_unit_transition,
    normalise_mac,
    parse_import,
)
from app.domains.isp_partner.apps_leads import check_lead_status
from app.domains.isp_partner.apps_tasks import FieldTaskService, check_task_transition
from app.domains.isp_partner.exceptions import IspCustomerNotFoundError
from app.domains.isp_partner.rbac_roles import ROLES_BY_SLUG, all_permission_keys
from tests.unit.isp_partner_fixtures import (
    CUST_A1,
    CUST_B1,
    ISP_A,
    ISP_B,
    context,
    estate,
)

T0 = datetime(2026, 11, 1, 6, 0, tzinfo=UTC)


def _ticket(**kw):
    base = {
        "status": "open",
        "opened_at": T0,
        "due_at": T0 + timedelta(minutes=240),
        "resolved_at": None,
        "closed_at": None,
        "first_response_at": None,
        "rfo_reason": None,
        "type_id": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


# -- helpdesk rules ------------------------------------------------------------
def test_sla_state_and_tat() -> None:
    t = _ticket()
    assert sla_state(t, T0 + timedelta(minutes=10)) == "within"
    assert sla_state(t, T0 + timedelta(minutes=241)) == "breached"
    assert tat_minutes(t) is None
    t.resolved_at = T0 + timedelta(minutes=90)
    assert tat_minutes(t) == 90
    assert sla_state(t, T0 + timedelta(days=9)) == "within"  # judged at resolve
    t.resolved_at = T0 + timedelta(minutes=300)
    assert sla_state(t) == "breached"
    assert sla_state(_ticket(due_at=None)) == "no_sla"


def test_transitions_and_reopen_clear_resolution() -> None:
    t = _ticket()
    apply_status(t, "in_progress", now=T0 + timedelta(minutes=5))
    assert t.first_response_at == T0 + timedelta(minutes=5)
    apply_status(t, "resolved", now=T0 + timedelta(minutes=60))
    assert t.resolved_at and t.closed_at is None
    apply_status(t, "closed", now=T0 + timedelta(minutes=70))
    # closing keeps the original resolve time, so TAT is not stretched
    assert t.resolved_at == T0 + timedelta(minutes=60)
    apply_status(t, "open", now=T0 + timedelta(minutes=80))
    assert t.resolved_at is None and t.closed_at is None
    with pytest.raises(common.IspAppsInvalidError):
        check_transition("closed", "resolved")


def test_summary_counts_rfo_tat_and_breaches() -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    rows = [
        _ticket(
            type_id=a, rfo_reason="fiber_cut", resolved_at=T0 + timedelta(minutes=60)
        ),
        _ticket(
            type_id=a, rfo_reason="fiber_cut", resolved_at=T0 + timedelta(minutes=300)
        ),
        _ticket(type_id=b, rfo_reason="cpe_fault", resolved_at=None),
    ]
    out = summarise(
        rows, {a: "No connection", b: "Slow speed"}, now=T0 + timedelta(hours=10)
    )
    assert out["by_rfo"]["fiber_cut"] == 2 and out["by_rfo"]["cpe_fault"] == 1
    assert out["by_rfo"]["upstream"] == 0
    assert out["overall"] == {
        "count": 3,
        "resolved": 2,
        "avg_tat_minutes": 180.0,
        "breached": 2,
    }
    first = out["by_type"][0]
    assert first["type_name"] == "No connection" and first["count"] == 2


# -- discount maths ------------------------------------------------------------
def _code(**kw):
    base = {
        "id": uuid.uuid4(),
        "code": "NEW10",
        "kind": "percent",
        "value": 1000,
        "active": True,
        "is_deleted": False,
        "valid_from": None,
        "valid_until": None,
        "max_uses": None,
        "used_count": 0,
        "min_amount_paise": None,
        "max_discount_paise": None,
        "package_ids": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_percent_discount_rounds_half_up_and_caps() -> None:
    assert quote_discount(_code(), gross_paise=59_905).amount_paise == 5_991  # 5990.5
    assert (
        quote_discount(_code(max_discount_paise=2_000), gross_paise=59_905).amount_paise
        == 2_000
    )
    assert (
        quote_discount(
            _code(kind="flat", value=90_000), gross_paise=50_000
        ).amount_paise
        == 50_000
    )


@pytest.mark.parametrize(
    ("kw", "gross"),
    [
        ({"active": False}, 10_000),
        ({"valid_until": T0 - timedelta(days=1)}, 10_000),
        ({"valid_from": datetime.now(UTC) + timedelta(days=1)}, 10_000),
        ({"max_uses": 3, "used_count": 3}, 10_000),
        ({"min_amount_paise": 50_000}, 10_000),
        ({"package_ids": [str(uuid.uuid4())]}, 10_000),
    ],
)
def test_discount_rules_refuse(kw, gross) -> None:
    with pytest.raises(common.IspDiscountInvalidError):
        quote_discount(_code(**kw), gross_paise=gross)


def test_discount_package_allow_list_accepts_listed_package() -> None:
    pkg = uuid.uuid4()
    q = quote_discount(
        _code(package_ids=[str(pkg)]), gross_paise=10_000, package_id=pkg
    )
    assert q.amount_paise == 1_000


# -- inventory -------------------------------------------------------------------
def test_csv_import_parses_and_reports_bad_rows() -> None:
    text = (
        "serial,sku,mac,note\n"
        "SN1,ONT-DB,aa-bb-cc-dd-ee-ff,\n"
        "SN1,ONT-DB,,dup\n"
        ",ONT-DB,,\n"
        "SN2,ONT-DB,zz,\n"
        "SN3,RTR,,ok\n"
        ",,,\n"
    )
    rows, errors = parse_import(text)
    assert [r["serial"] for r in rows] == ["SN1", "SN3"]
    assert rows[0]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert sorted(e["line"] for e in errors) == [3, 4, 5]
    with pytest.raises(common.IspAppsInvalidError):
        parse_import("serial,name\nX,Y\n")


def test_unit_and_task_and_lead_transitions() -> None:
    check_unit_transition("in_stock", "assigned")
    with pytest.raises(common.IspAppsInvalidError):
        check_unit_transition("retired", "in_stock")
    with pytest.raises(common.IspAppsInvalidError):
        check_unit_transition("assigned", "in_stock")  # must be returned first
    check_task_transition("unclaimed", "assigned")
    with pytest.raises(common.IspAppsInvalidError):
        check_task_transition("completed", "assigned")
    with pytest.raises(common.IspAppsInvalidError):
        check_lead_status("new", "converted", dropped_reason=None)
    with pytest.raises(common.IspAppsInvalidError):
        check_lead_status("new", "dropped", dropped_reason=None)
    check_lead_status("new", "dropped", dropped_reason="out of area")
    assert normalise_mac(None) is None


def test_whatsapp_link_adds_country_code() -> None:
    assert whatsapp_link("98765 43210", "hi").startswith(
        "https://wa.me/919876543210?text=hi"
    )
    assert whatsapp_link("12", "hi") is None
    assert whatsapp_link(None, "hi") is None


# -- isolation -------------------------------------------------------------------
class _NoQueryDb:
    async def execute(self, *_a, **_k):  # pragma: no cover - must not run
        raise AssertionError("an empty customer list must not run a query")

    async def get(self, *_a, **_k):  # pragma: no cover
        raise AssertionError("no lookup expected")


async def test_ticket_list_with_no_customers_is_empty_without_a_query() -> None:
    isp = context(estate(), confined=set())
    items, total = await HelpdeskService(_NoQueryDb()).list_tickets(isp)
    assert (items, total) == ([], 0)
    stats = await HelpdeskService(_NoQueryDb()).stats(
        isp, isp_customer_id=None, since=None, until=None
    )
    assert stats["overall"]["count"] == 0


async def test_ticket_for_another_isps_customer_is_404() -> None:
    isp = context(estate())
    with pytest.raises(IspCustomerNotFoundError):
        await HelpdeskService(_NoQueryDb()).create_ticket(
            isp, {"isp_customer_id": CUST_B1, "subject": "x"}
        )
    with pytest.raises(IspCustomerNotFoundError):
        await HelpdeskService(_NoQueryDb()).list_tickets(isp, isp_customer_id=CUST_B1)


async def test_confined_task_list_with_no_customers_is_empty() -> None:
    isp = context(estate(), confined=set())
    assert await FieldTaskService(_NoQueryDb()).list(isp) == ([], 0)


class _SubDb:
    def __init__(self, sub):
        self.sub = sub

    async def get(self, _model, _id):
        return self.sub


def _sub(isp_org, customer):
    return SimpleNamespace(
        id=uuid.uuid4(),
        is_deleted=False,
        isp_organization_id=isp_org,
        customer_organization_id=customer,
    )


async def test_subscriber_of_another_isp_or_customer_is_404() -> None:
    isp = context(estate())
    with pytest.raises(common.IspAppsNotFoundError):
        await common.resolve_subscriber(isp, _SubDb(_sub(ISP_B, CUST_B1)), uuid.uuid4())
    with pytest.raises(common.IspAppsNotFoundError):
        await common.resolve_subscriber(
            isp, _SubDb(_sub(ISP_A, CUST_A1)), uuid.uuid4(), customer_id=uuid.uuid4()
        )
    ok = _sub(ISP_A, CUST_A1)
    assert await common.resolve_subscriber(isp, _SubDb(ok), ok.id) is ok


async def test_assignee_must_be_isp_staff_covering_the_customer() -> None:
    staff = uuid.uuid4()

    async def roles(_isp, user_id=None):
        return (
            [(None, SimpleNamespace(slug="isp-technician"))] if user_id == staff else []
        )

    async def scope(_isp, _user):
        return [CUST_A1]

    isp = context(estate())
    isp.repository.isp_role_assignments = roles  # type: ignore[method-assign]
    isp.repository.confined_customer_ids = scope  # type: ignore[method-assign]
    await common.assert_assignee(isp, staff, customer_id=CUST_A1)
    with pytest.raises(common.IspAppsInvalidError):
        await common.assert_assignee(isp, staff, customer_id=uuid.uuid4())
    with pytest.raises(common.IspAppsInvalidError):
        await common.assert_assignee(isp, staff, customer_id=None)
    with pytest.raises(common.IspAppsInvalidError):
        await common.assert_assignee(isp, uuid.uuid4(), customer_id=CUST_A1)


# -- RBAC + flag -----------------------------------------------------------------
def test_apps_keys_are_seeded_and_granted() -> None:
    keys = set(all_permission_keys())
    assert {
        "isp_apps.read",
        "isp_apps.create",
        "isp_apps.update",
        "isp_apps.manage",
        "isp_apps.export",
    } <= keys
    assert "isp_apps.manage" in ROLES_BY_SLUG["isp-owner"].permission_keys
    assert "isp_apps.manage" not in ROLES_BY_SLUG["isp-technician"].permission_keys
    assert "isp_apps.update" in ROLES_BY_SLUG["isp-technician"].permission_keys
    viewer = {
        k
        for k in ROLES_BY_SLUG["isp-viewer"].permission_keys
        if k.startswith("isp_apps.")
    }
    assert viewer == {"isp_apps.read", "isp_apps.export"}
    assert "isp_apps.export" not in ROLES_BY_SLUG["isp-technician"].permission_keys
    for slug in ("isp-owner", "isp-admin", "isp-noc", "isp-billing"):
        assert "isp_apps.export" in ROLES_BY_SLUG[slug].permission_keys


async def test_apps_flag_defaults_off() -> None:
    common.get_isp_apps_settings.cache_clear()
    assert common.get_isp_apps_settings().enabled is False
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        await common.RequireIspAppsEnabled()
    assert exc.value.status_code == 404


# -- exports + the JAZE-4 discount hook contract ---------------------------------
def test_csv_export_guards_formulas_and_formats_times() -> None:
    from app.domains.isp_partner.apps_export import TICKET_COLUMNS, render_csv

    row = {
        "number": "T-000001",
        "opened_at": T0,
        "subject": "=HYPERLINK(1)",
        "customer_name": "-neg",
        "tat_minutes": 42,
        "assignee_name": None,
    }
    lines = render_csv(TICKET_COLUMNS, [row]).decode().splitlines()
    assert lines[0].startswith("Number,Opened,Customer,Subscriber,Type,Subject")
    assert "'=HYPERLINK(1)" in lines[1]
    assert "'-neg" in lines[1]
    assert T0.isoformat() in lines[1]
    assert ",42," in lines[1]


def test_export_routes_sit_before_the_id_routes() -> None:
    """``/tickets/export.csv`` must not be swallowed by ``/tickets/{ticket_id}``."""
    from app.domains.isp_partner.apps_common import APPS_EXPORT
    from app.domains.isp_partner.apps_router import apps_router

    paths = [r.path for r in apps_router.routes]
    for export, item in (
        ("/apps/tickets/export.csv", "/apps/tickets/{ticket_id}"),
        ("/apps/tasks/export.csv", "/apps/tasks/{task_id}"),
        ("/apps/leads/export.csv", "/apps/leads/{lead_id}"),
        ("/apps/inventory/units/export.csv", "/apps/inventory/units/{unit_id}"),
    ):
        assert paths.index(export) < paths.index(item), export
    assert APPS_EXPORT == "isp_apps.export"


def test_record_redemption_matches_the_lane_contract() -> None:
    """LANE_NOTES [JAZE-5] promised JAZE-4
    ``record_redemption(session, quote, *, invoice_id, subscriber_id=None,
    customer_org_id)``: those keywords alone must bind."""
    import inspect

    from app.domains.isp_partner.apps_discounts import (
        DiscountQuote,
        evaluate_discount,
        record_redemption,
    )

    sig = inspect.signature(record_redemption)
    sig.bind(
        object(),
        DiscountQuote(uuid.uuid4(), "X", 1, "x"),
        invoice_id=uuid.uuid4(),
        customer_org_id=uuid.uuid4(),
    )
    ev = inspect.signature(evaluate_discount)
    ev.bind(object(), uuid.uuid4(), "CODE", gross_paise=100, package_id=None, at=None)
