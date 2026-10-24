"""QA-027: the customer Guests tab (``GET /isp/customers/{id}/guests``) follows
the same F2 rule as the venue Guests twin: masked unless Master enabled
unmasking for this ISP and the caller is its owner/admin (decided by
``parity_settings.pii_unmasked_for``), and every unmasked view is audited."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import parity_settings
from app.domains.isp_partner import router as isp_router
from app.domains.isp_partner.scoping import IspScope


@pytest.fixture
def harness(monkeypatch):
    customer = SimpleNamespace(id=uuid.uuid4())
    guests = [
        (
            SimpleNamespace(
                id=uuid.uuid4(),
                identifier="+919999900000",
                email=None,
                display_name="Guest One",
                first_seen_at=datetime(2026, 10, 23, tzinfo=UTC),
                last_seen_at=datetime(2026, 10, 24, tzinfo=UTC),
                location_id=uuid.uuid4(),
            ),
            2,
        ),
        (
            SimpleNamespace(
                id=uuid.uuid4(),
                identifier="qa-guest-62f3@example.com",
                email="qa-guest-62f3@example.com",
                display_name=None,
                first_seen_at=None,
                last_seen_at=None,
                location_id=None,
            ),
            1,
        ),
    ]
    state = SimpleNamespace(unmasked=False, audits=[], rows=guests, customer=customer)

    async def assert_customer(isp, cid):
        return customer

    async def unmasked_for(db, isp):
        return state.unmasked

    async def record(db, isp, *, what, customer_org_id, location_id=None):
        state.audits.append((what, customer_org_id, location_id))

    class Repo:
        session = object()

        async def list_guests(self, cid, *, location_id, search, page, page_size):
            return state.rows, len(state.rows)

    monkeypatch.setattr(IspScope, "assert_customer", assert_customer)
    monkeypatch.setattr(parity_settings, "pii_unmasked_for", unmasked_for)
    monkeypatch.setattr(parity_settings, "record_unmasked_view", record)
    state.isp = SimpleNamespace(repository=Repo())
    return state


async def _call(h):
    body = await isp_router.list_guests(
        SimpleNamespace(headers={}, state=SimpleNamespace(request_id="t")),
        h.customer.id,
        isp_location_id=None,
        search=None,
        page=1,
        page_size=50,
        isp=h.isp,
    )
    return body["data"]["items"]


async def test_masked_by_default_and_not_audited(harness) -> None:
    items = await _call(harness)
    assert items[0]["phone_masked"] != "+919999900000"
    assert items[1]["email_masked"] != "qa-guest-62f3@example.com"
    assert all(i["masked"] for i in items)
    assert harness.audits == []


async def test_unmasked_for_owner_admin_when_master_enabled_and_audited(
    harness,
) -> None:
    harness.unmasked = True
    items = await _call(harness)
    assert items[0]["phone_masked"] == "+919999900000"
    assert items[1]["email_masked"] == "qa-guest-62f3@example.com"
    assert not any(i["masked"] for i in items)
    assert harness.audits == [
        ("GET /customers/{isp_customer_id}/guests", harness.customer.id, None)
    ]


async def test_unmasked_but_empty_list_is_not_audited(harness) -> None:
    harness.unmasked = True
    harness.rows = []
    assert await _call(harness) == []
    assert harness.audits == []


async def test_policy_decides_by_role(monkeypatch) -> None:
    """noc/technician/viewer never get raw identifiers, even when Master
    enabled unmasking (``pii_unmasked_for`` is the single decision point)."""

    async def setting(db, isp_org_id):
        return {"pii_unmask_enabled": True}

    monkeypatch.setattr(parity_settings, "get_parity_setting", setting)
    for role, expected in (
        ("isp-owner", True),
        ("isp-admin", True),
        ("isp-noc", False),
        ("isp-technician", False),
        ("isp-viewer", False),
        ("isp-billing", False),
    ):
        isp = SimpleNamespace(role_slug=role, isp_org_id=uuid.uuid4())
        assert await parity_settings.pii_unmasked_for(None, isp) is expected
