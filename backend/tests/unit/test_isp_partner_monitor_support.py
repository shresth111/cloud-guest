"""Batch B5 (ADDENDUM_04): alerts, ISP -> Wyfy support tickets, staff activity.

Pinned here (the generic guard / gate / seam tests already walk the routes and
the twin rows):

1. only the fixed alert routes are twinned; no row calls an alert-RULE handler
   (the by-id rule routes carry the open path-id defect);
2. the ISP alert feed and staff activity never widen to "every org": an ISP
   with no customers gets an empty page WITHOUT a query being run;
3. a support ticket is filed under the ISP org, and a customer reference is
   resolved through IspScope (another ISP's customer is a 404);
4. the new routes are mounted with the ISP guard stack and B5 keys.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import monitor_support as b5
from app.domains.isp_partner.exceptions import IspCustomerNotFoundError
from app.domains.isp_partner.twins_all import ALL_TWINS
from app.domains.monitoring import router as monitoring_routes
from tests.unit.isp_partner_fixtures import CUST_A1, CUST_B1, ISP_A, context, estate


def _request():
    return SimpleNamespace(headers={}, state=SimpleNamespace(request_id="t"))


def test_only_fixed_alert_routes_are_twinned() -> None:
    rule_handlers = {
        monitoring_routes.create_alert_rule,
        monitoring_routes.list_alert_rules,
        monitoring_routes.get_alert_rule,
        monitoring_routes.update_alert_rule,
        monitoring_routes.delete_alert_rule,
        monitoring_routes.evaluate_alert_rules,
    }
    for spec in ALL_TWINS:
        assert spec.handler not in rule_handlers, spec.path
    handlers = {s.handler for s in b5.MONITOR_TWINS}
    assert handlers == {
        monitoring_routes.list_alerts,
        monitoring_routes.get_alert,
        monitoring_routes.acknowledge_alert,
        monitoring_routes.resolve_alert,
    }
    assert all(any(s is t for t in ALL_TWINS) for s in b5.MONITOR_TWINS)


class _NoQueryDb:
    async def execute(self, *_a, **_k):  # pragma: no cover - must not run
        raise AssertionError("an empty customer list must not run a query")


async def test_alert_feed_with_no_customers_is_empty_not_everything() -> None:
    repo = estate()
    isp = context(repo, confined=set())  # confined to nothing
    out = await b5.list_isp_alerts(
        _request(),
        isp_customer_id=None,
        alert_status=None,
        page=1,
        page_size=25,
        isp=isp,
        db=_NoQueryDb(),
    )
    assert out["data"]["items"] == [] and out["data"]["total_items"] == 0


async def test_alert_feed_refuses_another_isps_customer() -> None:
    isp = context(estate())
    with pytest.raises(IspCustomerNotFoundError):
        await b5.list_isp_alerts(
            _request(),
            isp_customer_id=CUST_B1,
            alert_status=None,
            page=1,
            page_size=25,
            isp=isp,
            db=_NoQueryDb(),
        )


async def test_staff_activity_unknown_staff_member_is_empty() -> None:
    repo = estate()
    isp = context(repo)

    async def no_staff(*_a, **_k):
        return []

    isp.repository.isp_role_assignments = no_staff  # type: ignore[method-assign]
    out = await b5.list_staff_activity(
        _request(),
        isp_user_id=uuid.uuid4(),
        isp_customer_id=None,
        action=None,
        since=None,
        until=None,
        page=1,
        page_size=50,
        isp=isp,
        db=_NoQueryDb(),
    )
    assert out["data"]["items"] == []


async def test_staff_activity_refuses_another_isps_customer() -> None:
    repo = estate()
    isp = context(repo)

    async def no_staff(*_a, **_k):
        return []

    isp.repository.isp_role_assignments = no_staff  # type: ignore[method-assign]
    with pytest.raises(IspCustomerNotFoundError):
        await b5.list_staff_activity(
            _request(),
            isp_user_id=None,
            isp_customer_id=CUST_B1,
            action=None,
            since=None,
            until=None,
            page=1,
            page_size=50,
            isp=isp,
            db=_NoQueryDb(),
        )


async def test_ticket_is_filed_under_the_isp_org(monkeypatch) -> None:
    seen: dict = {}

    async def fake_create(request, **kwargs):
        seen.update(kwargs)
        return {"ok": True}

    monkeypatch.setattr(b5.ticket_routes, "create_ticket", fake_create)
    isp = context(estate())
    await b5.create_isp_ticket(
        _request(),
        payload=b5.IspTicketCreateRequest(
            subject="Router offline",
            description="Customer router is not reachable",
            isp_customer_id=CUST_A1,
        ),
        isp=isp,
        user=SimpleNamespace(id=str(uuid.uuid4())),
        service=None,
    )
    assert seen["requesting_organization_id"] == ISP_A
    assert seen["payload"].location_id is None
    assert str(CUST_A1) in seen["payload"].description


async def test_ticket_about_another_isps_customer_is_refused(monkeypatch) -> None:
    async def fake_create(request, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("must not file")

    monkeypatch.setattr(b5.ticket_routes, "create_ticket", fake_create)
    with pytest.raises(IspCustomerNotFoundError):
        await b5.create_isp_ticket(
            _request(),
            payload=b5.IspTicketCreateRequest(
                subject="x" * 3, description="about B1", isp_customer_id=CUST_B1
            ),
            isp=context(estate()),
            user=SimpleNamespace(id=str(uuid.uuid4())),
            service=None,
        )


_EXPECTED = {
    ("GET", "/api/v1/isp/venue/alert-rules"): "isp_monitor.read",
    ("GET", "/api/v1/isp/alerts"): "isp_monitor.read",
    ("GET", "/api/v1/isp/support-tickets"): "isp_support.read",
    ("POST", "/api/v1/isp/support-tickets"): "isp_support.create",
    ("GET", "/api/v1/isp/support-tickets/{ticket_id}"): "isp_support.read",
    ("GET", "/api/v1/isp/support-tickets/{ticket_id}/replies"): "isp_support.read",
    ("POST", "/api/v1/isp/support-tickets/{ticket_id}/replies"): "isp_support.create",
    ("GET", "/api/v1/isp/staff-activity"): "isp_partner.assign",
}


def test_b5_routes_are_mounted_with_their_keys() -> None:
    from app.main import create_app

    found: dict = {}
    for r in create_app().routes:
        for m in getattr(r, "methods", None) or ():
            if (m, getattr(r, "path", "")) in _EXPECTED:
                keys = [
                    c.cell_contents
                    for d in r.dependant.dependencies
                    for c in (getattr(d.call, "__closure__", None) or ())
                    if isinstance(c.cell_contents, str) and "." in c.cell_contents
                ]
                found[(m, r.path)] = keys
    assert set(found) == set(_EXPECTED)
    for route, key in _EXPECTED.items():
        assert key in found[route], (route, found[route])
