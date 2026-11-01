"""QA-021: ``GET /isp/public/portal-support`` -- the ISP's support contact for
the guest portal footer. It is public and read-only, returns only the two
contact fields, gives 404 for anything that is not an active ISP's customer
location, is rate limited per IP, and is flag-gated."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.domains.isp_partner import portal_support_router as psr

PATH = "/api/v1/isp/public/portal-support"


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class FakeSession:
    def __init__(self, state):
        self.state = state

    async def get(self, model, ident):
        return self.state.locations.get(ident)

    async def execute(self, stmt):
        from app.domains.isp_partner.models import IspCustomerProfile, IspPartnerProfile

        entity = stmt.column_descriptions[0]["entity"]
        params = stmt.compile().params
        if entity is IspCustomerProfile:
            org = next(
                v for k, v in params.items() if k.startswith("customer_organization_id")
            )
            return _Result(self.state.customers.get(org))
        if entity is IspPartnerProfile:
            org = next(v for k, v in params.items() if k.startswith("organization_id"))
            return _Result(self.state.isps.get(org))
        raise AssertionError(f"unexpected read: {entity}")


class FakeRedis:
    def __init__(self):
        self.counts: dict[str, int] = {}

    async def incr(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def expire(self, key, window):
        return True

    async def ttl(self, key):
        return 42


def _state():
    isp_org, cust_org, other_org = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    loc, other_loc, gone_loc = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    return SimpleNamespace(
        loc=loc,
        other_loc=other_loc,
        gone_loc=gone_loc,
        isp_org=isp_org,
        locations={
            loc: SimpleNamespace(organization_id=cust_org, is_deleted=False),
            other_loc: SimpleNamespace(organization_id=other_org, is_deleted=False),
            gone_loc: SimpleNamespace(organization_id=cust_org, is_deleted=True),
        },
        customers={
            cust_org: SimpleNamespace(isp_organization_id=isp_org, is_deleted=False)
        },
        isps={
            isp_org: SimpleNamespace(
                status="active",
                support_phone="+911234567890",
                support_email="help@isp.example",
                gstin="09ABCDE1234F1Z5",
                notes="internal",
            )
        },
    )


# -- the lookup ---------------------------------------------------------------


async def test_isp_customer_location_returns_only_the_contact_fields() -> None:
    st = _state()
    got = await psr.support_contact_for_location(FakeSession(st), st.loc)
    assert got == {
        "support_phone": "+911234567890",
        "support_email": "help@isp.example",
    }


@pytest.mark.parametrize(
    "case", ["unknown", "deleted", "non_isp", "suspended", "no_contact"]
)
async def test_everything_else_is_none(case) -> None:
    st = _state()
    loc = st.loc
    if case == "unknown":
        loc = uuid.uuid4()
    elif case == "deleted":
        loc = st.gone_loc
    elif case == "non_isp":
        loc = st.other_loc
    elif case == "suspended":
        st.isps[st.isp_org].status = "suspended"
    elif case == "no_contact":
        st.isps[st.isp_org].support_phone = None
        st.isps[st.isp_org].support_email = None
    assert await psr.support_contact_for_location(FakeSession(st), loc) is None


# -- the route ------------------------------------------------------------------


@pytest.fixture
def client(monkeypatch):
    from functools import lru_cache

    from app.database.redis import get_redis_client
    from app.database.session import get_db_session
    from app.domains.isp_partner import config as isp_config

    state = SimpleNamespace(flag=True, data=_state(), redis=FakeRedis())
    monkeypatch.setattr(
        isp_config,
        "get_isp_partner_settings",
        lambda: isp_config.IspPartnerSettings(enabled=state.flag),
    )

    @lru_cache(maxsize=1)
    def app():
        from app.main import create_app

        return create_app()

    async def _db():
        yield FakeSession(state.data)

    async def _redis():
        return state.redis

    application = app()
    application.dependency_overrides[get_db_session] = _db
    application.dependency_overrides[get_redis_client] = _redis
    state.client = TestClient(application, raise_server_exceptions=False)
    yield state
    application.dependency_overrides.clear()


def test_route_200_body_is_exactly_the_contact(client) -> None:
    r = client.client.get(PATH, params={"location": str(client.data.loc)})
    assert r.status_code == 200
    assert r.json()["data"] == {
        "support_phone": "+911234567890",
        "support_email": "help@isp.example",
    }
    assert "max-age" in r.headers.get("cache-control", "")


def test_route_404_for_a_non_isp_location(client) -> None:
    r = client.client.get(PATH, params={"location": str(client.data.other_loc)})
    assert r.status_code == 404
    assert r.json()["data"] == {"code": "ISP_PORTAL_SUPPORT_NOT_FOUND"}


def test_route_needs_no_session(client) -> None:
    """No Authorization header, no X-Organization-Id: still answers."""
    r = client.client.get(PATH, params={"location": str(client.data.loc)})
    assert r.status_code == 200


def test_route_is_rate_limited_per_ip(client) -> None:
    cap, _ = psr.IP_LIMIT
    codes = [
        client.client.get(PATH, params={"location": str(client.data.loc)}).status_code
        for _ in range(cap + 1)
    ]
    assert codes[:cap] == [200] * cap
    assert codes[cap] == 429


def test_route_429_carries_retry_after(client) -> None:
    cap, _ = psr.IP_LIMIT
    for _ in range(cap):
        client.client.get(PATH, params={"location": str(client.data.loc)})
    r = client.client.get(PATH, params={"location": str(client.data.loc)})
    assert r.status_code == 429 and r.headers["Retry-After"] == "42"


def test_route_is_flag_gated(client) -> None:
    client.flag = False
    r = client.client.get(PATH, params={"location": str(client.data.loc)})
    assert r.status_code == 404


def test_route_rejects_writes(client) -> None:
    r = client.client.post(PATH, params={"location": str(client.data.loc)})
    assert r.status_code == 405
