"""BE-T: the founder's negative tests. Each gets 403/422 (404 where noted)
and asserts nothing was written.

The permission decisions here are the REAL RBAC engine
(``AccessValidator`` -> ``PermissionResolver`` -> ``ScopeResolver``) over an
in-memory role store holding exactly the seeded ``isp-*`` role data, and the
real ``RequireIspPartner``. Only persistence is faked.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from functools import lru_cache
from types import SimpleNamespace

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.domains.auth.models import AuthUser
from app.domains.isp_partner import config as isp_config
from app.domains.isp_partner.dependencies import get_isp_repository
from app.domains.isp_partner.providers import get_isp_partner_service
from app.domains.isp_partner.rbac_roles import ROLES_BY_SLUG
from app.domains.isp_partner.users_router import get_isp_users_service
from app.domains.isp_partner.users_service import IspUsersService
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import (
    CurrentOrganizationScope,
    CurrentUser,
    get_access_validator,
    get_rbac_repository,
)
from app.domains.rbac.organization_scope import OrganizationScope
from app.database.session import get_db_session
from tests.unit.isp_partner_fixtures import (
    CFG_B1,
    CPE_B,
    CUST_A1,
    CUST_B1,
    ISP_A,
    LOC_B1,
    RTR_B1,
    USER_A,
)
from tests.unit.test_isp_partner_service import Recorder, _repo, _service

ISP_USER = USER_A
SUPER_ADMIN = uuid.UUID("00000000-0000-0000-0000-0000000005a5")
ORG_OWNER = uuid.UUID("00000000-0000-0000-0000-0000000000c0")


class RoleStore:
    """Just enough of RBACRepository for RoleResolver + PermissionResolver."""

    def __init__(self) -> None:
        self.assignments: dict[uuid.UUID, list] = {}
        self.role_keys: dict[uuid.UUID, set[str]] = {}

    def grant(self, user, slug, keys, *, scope="organization", org=None, role_scope=None):
        role = SimpleNamespace(
            id=uuid.uuid4(),
            slug=slug,
            organization_id=None,
            scope_type=role_scope or scope,
            is_active=True,
            is_deleted=False,
        )
        self.role_keys[role.id] = set(keys)
        self.assignments.setdefault(user, []).append(
            SimpleNamespace(
                role=role,
                role_id=role.id,
                scope_type=scope,
                organization_id=org,
                location_id=None,
                router_id=None,
                msp_id=None,
            )
        )

    async def get_active_user_roles(self, user_id, *, now=None):
        return self.assignments.get(user_id, [])

    async def get_role_permissions(self, role_id):
        return [
            SimpleNamespace(
                permission=SimpleNamespace(key=k, is_active=True, is_deleted=False),
                permission_id=uuid.uuid4(),
            )
            for k in self.role_keys.get(role_id, set())
        ]

    async def get_parent_chain(self, role_id, *, max_depth):
        return []

    async def get_active_overrides_for_user(self, user_id, *, now=None):
        return []

    async def create_audit_log_entry(self, **fields):
        WRITES.append(("audit", fields.get("action")))


WRITES: list = []
STORE = RoleStore()
STORE.grant(ISP_USER, "isp-owner", ROLES_BY_SLUG["isp-owner"].permission_keys, org=ISP_A)
STORE.grant(
    SUPER_ADMIN,
    "super-admin",
    ["organizations.create", "organizations.read", "users.create", "roles.assign"],
    scope="global",
)
STORE.grant(
    ORG_OWNER,
    "organization-owner",
    ["organizations.read", "users.create", "users.update", "locations.create"],
    org=CUST_A1,
)


@asynccontextmanager
async def _denial_sink():
    yield STORE


class FakeDb:
    def __init__(self) -> None:
        self.writes: list = []

    async def get(self, model, ident):
        return None

    def add(self, row):
        self.writes.append(row)

    async def flush(self):
        self.writes.append("flush")

    async def commit(self):
        return None

    async def rollback(self):
        return None

    async def execute(self, *a, **k):
        raise AssertionError("no query expected on a refused request")


@lru_cache(maxsize=1)
def _app():
    from app.main import create_app

    return create_app()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(
        isp_config, "get_isp_partner_settings", lambda: isp_config.IspPartnerSettings(enabled=True)
    )
    from app.domains.tr069 import config as tr_config

    monkeypatch.setattr(
        tr_config, "get_tr069_settings", lambda: tr_config.Tr069Settings(enabled=True)
    )
    app = _app()
    db = FakeDb()
    repo = _repo()
    rec = Recorder(repo)
    state = SimpleNamespace(user=ISP_USER, db=db, repo=repo, rec=rec)

    async def _db():
        yield db

    def _scope(request: Request):
        raw = request.headers.get("X-Organization-Id")
        return OrganizationScope.for_organization(uuid.UUID(raw))

    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(state.user), email="u@example.com"
    )
    app.dependency_overrides[get_db_session] = _db
    app.dependency_overrides[get_rbac_repository] = lambda: STORE
    app.dependency_overrides[get_access_validator] = lambda: AccessValidator(
        STORE, cache=None, denial_audit_repository=_denial_sink
    )
    app.dependency_overrides[CurrentOrganizationScope] = _scope
    app.dependency_overrides[get_isp_repository] = lambda: repo
    app.dependency_overrides[get_isp_partner_service] = lambda: _service(repo, rec)
    users = SimpleNamespace(calls=[])

    class FakeUserService:
        notification_service = None

        async def create_user(self, **kw):
            users.calls.append(kw)
            raise AssertionError("must not be reached")

    app.dependency_overrides[get_isp_users_service] = lambda: IspUsersService(
        repository=repo,
        user_service=FakeUserService(),
        identity_repository=None,
        rbac_repository=STORE,
        permission_cache=None,
        audit=STORE,
    )
    state.users = users
    WRITES.clear()
    with TestClient(app, raise_server_exceptions=False) as c:
        state.c = c
        yield state
    app.dependency_overrides.clear()


def _h(org=ISP_A, **extra):
    return {"X-Organization-Id": str(org), **extra}


def _nothing_written(state) -> None:
    assert state.db.writes == []
    assert not [n for n, _ in state.rec.calls if n != "audit"]
    assert [w for w in WRITES if w[1] != "permission_denied"] == []


BODY = {"name": "Cafe X", "contact_email": "amit@example.com"}


def test_1_customer_with_msp_org_type_is_422(client) -> None:
    r = client.c.post("/api/v1/isp/customers", json=dict(BODY, org_type="msp"), headers=_h())
    assert r.status_code == 422
    _nothing_written(client)


def test_2_grandchild_attempt_is_422_and_no_nested_route(client) -> None:
    r = client.c.post(
        "/api/v1/isp/customers",
        json=dict(BODY, parent_organization_id=str(CUST_A1)),
        headers=_h(),
    )
    assert r.status_code == 422
    r = client.c.post(f"/api/v1/isp/customers/{CUST_A1}/customers", json=BODY, headers=_h())
    assert r.status_code in (404, 405)
    _nothing_written(client)


@pytest.mark.parametrize(
    ("method", "path", "body", "org"),
    [
        # 4: existing POST /organizations, header = the ISP, parent = a customer
        ("POST", "/api/v1/organizations", {"name": "x", "slug": "x-1", "contact_email": "a@example.com", "parent_organization_id": str(CUST_A1)}, ISP_A),
        # 5: existing user creation / invite with the customer as header org
        ("POST", "/api/v1/users", {"first_name": "a", "last_name": "b", "email": "a@example.com", "username": "ab", "temporary_password": "Xy7!aaaaaaaa"}, CUST_A1),
        ("POST", "/api/v1/users/invite", {"first_name": "a", "last_name": "b", "email": "a@example.com"}, CUST_A1),
        # 6: existing membership invite on a customer
        ("POST", f"/api/v1/organizations/{CUST_A1}/members", {"user_id": str(uuid.uuid4())}, ISP_A),
        # 7: existing role assignment on the customer org
        ("POST", f"/api/v1/users/{uuid.uuid4()}/roles", {"role_id": str(uuid.uuid4()), "scope_type": "organization", "organization_id": str(CUST_A1)}, CUST_A1),
        # 11: existing smart provisioning
        ("POST", "/api/v1/customers/onboard", {}, ISP_A),
        ("POST", "/api/v1/locations/provision", {}, ISP_A),
    ],
    ids=["4-orgs", "5-users", "5-invite", "6-members", "7-roles", "11-onboard", "11-provision"],
)
def test_isp_user_is_refused_by_existing_endpoints(client, method, path, body, org) -> None:
    r = client.c.request(method, path, json=body, headers=_h(org))
    assert r.status_code == 403, r.text
    # refused by the permission engine itself, not by something incidental
    assert r.json()["data"].get("error_code") == "permission_denied", r.text
    _nothing_written(client)


def test_8_customer_role_slugs_are_isp_role_invalid(client) -> None:
    for role in ("organization-owner", "organization-admin", "msp-owner"):
        r = client.c.post(
            "/api/v1/isp/users",
            json={"first_name": "a", "last_name": "b", "email": "a@example.com", "role": role},
            headers=_h(),
        )
        assert r.status_code == 422
        assert r.json()["data"]["code"] == "ISP_ROLE_INVALID"
    assert client.users.calls == []


def test_9_user_body_naming_an_organization_is_422(client) -> None:
    for field in ("organization_id", "organization", "customer_organization_id"):
        r = client.c.post(
            "/api/v1/isp/users",
            json={
                "first_name": "a", "last_name": "b", "email": "a@example.com",
                "role": "isp-viewer", field: str(CUST_A1),
            },
            headers=_h(),
        )
        assert r.status_code == 422
    assert client.users.calls == []


@pytest.mark.parametrize("who", [ISP_USER, ORG_OWNER])
def test_10_create_isp_partner_is_refused(client, who) -> None:
    """On this branch the Master router is FULLSTACK's stub with no routes
    yet, so the path is a 404; the GLOBAL pin itself is FS-1's test. Either
    way an ISP user / org owner never gets a 2xx."""
    client.user = who
    r = client.c.post(
        "/api/v1/platform/isp-partners", json={"name": "x"}, headers=_h(ISP_A)
    )
    assert r.status_code in (403, 404)
    _nothing_written(client)


def test_12_customer_org_owner_on_isp_me_is_403(client) -> None:
    client.user = ORG_OWNER
    r = client.c.get("/api/v1/isp/me", headers=_h(CUST_A1))
    assert r.status_code == 403


def test_13_super_admin_on_isp_overview_is_403(client) -> None:
    client.user = SUPER_ADMIN
    r = client.c.get("/api/v1/isp/overview", headers=_h(ISP_A))
    assert r.status_code == 403
    _nothing_written(client)


@pytest.mark.parametrize(
    "path",
    [
        f"/api/v1/isp/customers/{CUST_B1}",
        f"/api/v1/isp/locations/{LOC_B1}",
        f"/api/v1/isp/routers/{RTR_B1}",
        f"/api/v1/isp/captive-portal-configs/{CFG_B1}",
        f"/api/v1/isp/routers/{RTR_B1}/as-router-device",
        f"/api/v1/isp/tr069/devices/{CPE_B}",
    ],
)
def test_14_isp_a_reading_isp_b_by_id_is_404(client, monkeypatch, path) -> None:
    from app.domains.tr069 import router as tr_router
    from app.domains.tr069.service import Tr069Service

    _app().dependency_overrides[tr_router.get_tr069_service] = lambda: Tr069Service(
        session=None, nbi=None, audit=None
    )
    r = client.c.get(path, headers=_h())
    assert r.status_code == 404, r.text
    assert r.json()["data"]["code"].endswith("NOT_FOUND")


def test_15_location_header_on_isp_is_400(client) -> None:
    for header in ("X-Location-Id", "X-Router-Id"):
        r = client.c.get(
            "/api/v1/isp/customers", headers=_h(**{header: str(uuid.uuid4())})
        )
        assert r.status_code == 400
        assert r.json()["data"]["code"] == "ISP_SCOPE_HEADERS_NOT_ALLOWED"


def test_isp_owner_happy_path_reaches_the_service(client) -> None:
    """Control: the same harness lets the ISP owner through, so the refusals
    above are decisions, not a broken harness."""
    r = client.c.post("/api/v1/isp/customers", json=BODY, headers=_h())
    assert r.status_code == 201, r.text
    assert r.json()["data"]["status"] == "active"
