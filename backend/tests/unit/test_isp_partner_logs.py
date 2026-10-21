"""BE-7: NetLogs / IPDR / auth logs across an ISP's customers."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.dialects import postgresql

from app.domains.device_logs import repository as dl_repo
from app.domains.device_logs.repository import CustomerFilters
from app.domains.ipdr.service import IpdrFilters
from app.domains.isp_partner import logs_router
from app.domains.isp_partner.logs_repository import (
    IspConditionsDriftError,
    IspLogsRepository,
    isp_conditions,
)
from tests.unit.isp_partner_fixtures import CUST_A1, CUST_A2, CUST_B1, ISP_A, context, estate
from tests.unit.test_isp_partner_hard_rules import AUDITS, _app, _h, client  # noqa: F401

T1 = datetime(2026, 10, 21, 0, 0, tzinfo=UTC)
T2 = T1 + timedelta(hours=24)


def _filters(**kw) -> CustomerFilters:
    return CustomerFilters(organization_id=CUST_A1, since=T1, until=T2, **kw)


def _sql(conditions) -> str:
    from sqlalchemy import and_

    return str(
        and_(*conditions).compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


class TestIspConditions:
    def test_only_the_organization_predicate_is_replaced(self) -> None:
        original = dl_repo.customer_conditions(_filters(text="dhcp"))
        ours = isp_conditions(_filters(text="dhcp"), [CUST_A1, CUST_A2])
        assert len(ours) == len(original)
        sql = _sql(ours)
        assert "device_log_events.organization_id IN (" in sql
        assert str(CUST_A1) in sql and str(CUST_A2) in sql
        assert str(CUST_B1) not in sql
        # NULL-organization rows can never match; the window is mandatory
        assert "device_log_events.organization_id IS NOT NULL" in sql
        assert "device_log_events.received_at >=" in sql
        assert "device_log_events.received_at <=" in sql
        assert "attribution !=" in sql
        # every other predicate is the very same SQL as the customer page's
        assert _sql(ours[1:]) == _sql(original[1:])

    def test_drift_in_customer_conditions_fails_loudly(self, monkeypatch) -> None:
        from app.domains.device_logs.models import DeviceLogEvent

        monkeypatch.setattr(
            "app.domains.isp_partner.logs_repository.customer_conditions",
            lambda f: [DeviceLogEvent.received_at >= f.since],
        )
        with pytest.raises(IspConditionsDriftError):
            isp_conditions(_filters(), [CUST_A1])

    def test_an_empty_customer_list_never_becomes_all(self) -> None:
        with pytest.raises(ValueError):
            isp_conditions(_filters(), [])

    async def test_repository_with_no_customers_returns_nothing_without_a_query(self) -> None:
        class NoSession:
            async def execute(self, *a, **k):
                raise AssertionError("must not query")

        repo = IspLogsRepository(NoSession(), [])
        assert await repo.list_events(_filters(), limit=10) == []
        assert await repo.summary_buckets(_filters(), tz="Asia/Kolkata") == []
        assert await repo.top_routers(_filters(), limit=10) == []
        assert await repo.by_customer(_filters()) == []


class TestScopeHelper:
    async def test_confined_caller_without_a_customer_gets_only_theirs(self) -> None:
        isp = context(estate(), role="isp-noc", confined={CUST_A2})
        customer, location, router, org_ids = await logs_router._scope(isp, None, None, None)
        assert (customer, location, router) == (None, None, None)
        assert org_ids == [CUST_A2]

    async def test_naming_a_customer_outside_confinement_is_404(self) -> None:
        from app.domains.isp_partner.exceptions import IspCustomerNotFoundError

        isp = context(estate(), role="isp-noc", confined={CUST_A2})
        with pytest.raises(IspCustomerNotFoundError):
            await logs_router._scope(isp, CUST_A1, None, None)


class FakeIpdr:
    def __init__(self) -> None:
        self.built: list[uuid.UUID] = []

    async def build_filters(self, *, organization_id, **kw):
        self.built.append(organization_id)
        return IpdrFilters(
            organization_id=organization_id,
            since=T1,
            until=T2,
            location_id=kw.get("location_id"),
            router_id=kw.get("router_id"),
            phone=None,
            user_id=None,
            mac=None,
            ip=None,
            dst_ip=None,
            guests_only=False,
            cursor=None,
        )

    async def list_page(self, filters, *, limit=None):
        return {"since": T1, "until": T2, "items": [], "next_cursor": None, "coverage": []}


@pytest.fixture
def ipdr(client, monkeypatch):  # noqa: F811
    from app.domains.ipdr.dependencies import get_ipdr_service

    fake = FakeIpdr()
    _app().dependency_overrides[get_ipdr_service] = lambda: fake
    streamed: list = []

    async def _stream(targets, *, provenance, max_rows=0):
        streamed.extend(name for name, _ in targets)
        yield "customer\n"
        for name, _ in targets:
            yield f"{name}\n"

    monkeypatch.setattr(logs_router, "_stream_ipdr", _stream)
    fake.streamed = streamed
    return fake


def test_ipdr_list_without_a_customer_is_422(client, ipdr) -> None:  # noqa: F811
    r = client.c.get("/api/v1/isp/logs/ipdr/connections", headers=_h())
    assert r.status_code == 422
    assert r.json()["data"]["code"] == "ISP_CUSTOMER_REQUIRED"
    assert ipdr.built == []


def test_ipdr_list_for_a_customer_audits_with_console_isp(client, ipdr) -> None:  # noqa: F811
    r = client.c.get(
        f"/api/v1/isp/logs/ipdr/connections?isp_customer_id={CUST_A1}", headers=_h()
    )
    assert r.status_code == 200, r.text
    assert ipdr.built == [CUST_A1]
    (row,) = [a for a in AUDITS if a["action"] == "ipdr_listed"]
    assert row["event_metadata"]["console"] == "isp"
    assert row["organization_id"] == CUST_A1


def test_ipdr_list_of_another_isps_customer_is_404(client, ipdr) -> None:  # noqa: F811
    r = client.c.get(
        f"/api/v1/isp/logs/ipdr/connections?isp_customer_id={CUST_B1}", headers=_h()
    )
    assert r.status_code == 404
    assert ipdr.built == []


def test_ipdr_export_all_customers_is_one_csv_one_audit_row_each(client, ipdr) -> None:  # noqa: F811
    r = client.c.get("/api/v1/isp/logs/ipdr/export.csv", headers=_h())
    assert r.status_code == 200, r.text
    assert r.headers["content-disposition"].startswith('attachment; filename="isp-ipdr-all-')
    names = [client.repo.orgs[c].name for c in (CUST_A1, CUST_A2)]
    assert ipdr.streamed == sorted(names)
    rows = [a for a in AUDITS if a["action"] == "ipdr_exported"]
    assert {a["organization_id"] for a in rows} == {CUST_A1, CUST_A2}
    assert all(a["event_metadata"]["console"] == "isp" for a in rows)
    assert all(a["event_metadata"]["all_customers"] is True for a in rows)
    assert ISP_A not in ipdr.built and CUST_B1 not in ipdr.built
