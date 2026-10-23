"""ISP partner self-service forgot password (isp_partner.password_reset_router).

Pins: one response for every outcome, only ISP-role accounts get a link, the
link points at the partner host, the token goes into the SAME Redis key the
unchanged ``POST /auth/reset-password`` consumes, and both rate limits hold.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.auth.service import _RESET_TOKEN_KEY, _hash_token
from app.domains.isp_partner import password_reset_router as m
from app.domains.isp_partner.config import get_isp_partner_settings


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, Any] = {}
        self.ttls: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self.store[key] = int(self.store.get(key, 0)) + 1
        return self.store[key]

    async def expire(self, key: str, seconds: int) -> None:
        self.ttls[key] = seconds

    async def ttl(self, key: str) -> int:
        return self.ttls.get(key, -1)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value
        if ex:
            self.ttls[key] = ex


@dataclass
class FakeNotifier:
    sent: list[dict] = field(default_factory=list)

    async def enqueue(self, **kw: Any) -> None:
        self.sent.append(kw)


def _user(email="owner@isp.test", **kw):
    base = dict(
        id=uuid.uuid4(),
        email=email,
        first_name="Asha",
        is_active=True,
        status="active",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _assign(slug, *, role_scope="organization", scope="organization", role_org=None):
    return SimpleNamespace(
        role=SimpleNamespace(
            slug=slug, scope_type=role_scope, organization_id=role_org
        ),
        assignment=SimpleNamespace(scope_type=scope),
    )


class FakeRepo:
    def __init__(self, users):
        self.users = {u.email: u for u in users}

    async def get_user_by_email(self, email):
        return self.users.get(email.lower())


def _flow(users, assignments_by_user):
    from app.domains.auth.service import AuthService

    redis = FakeRedis()
    notifier = FakeNotifier()
    auth = AuthService(FakeRepo(users), redis, notification_service=notifier)

    class Resolver:
        def __init__(self, _repo):
            pass

        async def get_active_assignments(self, user_id):
            return assignments_by_user.get(user_id, [])

    flow = m.IspPasswordReset(
        auth_service=auth, rbac_repository=None, redis=redis, role_resolver_cls=Resolver
    )
    return flow, redis, notifier


@pytest.fixture(autouse=True)
def _partner_url(monkeypatch):
    monkeypatch.setenv(
        "ISP_PARTNER_LOGIN_URL", "https://network-staging.wyfyguest.com/"
    )
    get_isp_partner_settings.cache_clear()
    yield
    get_isp_partner_settings.cache_clear()


async def test_isp_owner_gets_partner_link_with_a_token_reset_password_accepts():
    u = _user()
    flow, redis, notifier = _flow([u], {u.id: [_assign("isp-owner")]})
    await flow.request("  Owner@ISP.test ")
    assert len(notifier.sent) == 1
    mail = notifier.sent[0]
    assert mail["recipient"] == u.email
    assert mail["organization_id"] is None
    prefix = "https://network-staging.wyfyguest.com/partner/reset-password?token="
    assert prefix in mail["body"]
    token = mail["body"].split(prefix, 1)[1].split('"', 1)[0].split("<", 1)[0]
    # The exact key the unchanged AuthService.reset_password peeks/consumes.
    key = _RESET_TOKEN_KEY.format(token=_hash_token(token))
    assert redis.store[key] == str(u.id)
    assert redis.ttls[key] == 3600
    assert "wyfyguest.com/reset-password" not in mail["body"].replace(
        "/partner/reset-password", ""
    )


@pytest.mark.parametrize(
    "assignments,user_kw",
    [
        ([], {}),  # no roles
        ([_assign("organization-owner")], {}),  # customer account
        ([_assign("super-admin", role_scope="global", scope="global")], {}),
        # an ISP role AND a GLOBAL role: platform staff, not a partner reset
        ([_assign("isp-owner"), _assign("x", role_scope="global", scope="global")], {}),
        ([_assign("isp-owner", role_org=uuid.uuid4())], {}),  # org-custom role
        ([_assign("isp-admin")], {"is_active": False}),
        ([_assign("isp-admin")], {"status": "suspended"}),
    ],
)
async def test_non_isp_or_inactive_accounts_get_nothing(assignments, user_kw):
    u = _user(**user_kw)
    flow, redis, notifier = _flow([u], {u.id: assignments})
    await flow.request(u.email)
    assert notifier.sent == []
    assert not any(k.startswith("auth:password_reset:") for k in redis.store)


async def test_unknown_email_sends_nothing():
    flow, _, notifier = _flow([], {})
    await flow.request("nobody@isp.test")
    assert notifier.sent == []


async def test_per_email_cap_silently_stops_sending():
    u = _user()
    flow, _, notifier = _flow([u], {u.id: [_assign("isp-viewer")]})
    for _ in range(m.EMAIL_LIMIT[0] + 3):
        await flow.request(u.email)
    assert len(notifier.sent) == m.EMAIL_LIMIT[0]


async def test_ip_limit_trips_after_cap_with_retry_after():
    flow, _, _ = _flow([], {})
    for _ in range(m.IP_LIMIT[0]):
        assert (await flow.ip_allowed("203.0.113.9"))[0] is True
    allowed, retry = await flow.ip_allowed("203.0.113.9")
    assert allowed is False and retry == m.IP_LIMIT[1]
    assert (await flow.ip_allowed("203.0.113.10"))[0] is True


async def test_backend_failure_is_swallowed_so_the_reply_cannot_differ():
    u = _user()
    flow, _, notifier = _flow([u], {u.id: [_assign("isp-owner")]})

    async def boom(**_kw):
        raise RuntimeError("smtp down")

    notifier.enqueue = boom  # type: ignore[method-assign]
    await flow.request(u.email)  # must not raise


def _client(monkeypatch, flow_factory):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.database.redis import get_redis_client
    from app.domains.auth.dependencies import get_auth_service
    from app.domains.isp_partner.router import isp_partner_router
    from app.domains.rbac.dependencies import get_rbac_repository

    monkeypatch.setenv("ISP_PARTNER_ENABLED", "true")
    get_isp_partner_settings.cache_clear()
    flow, redis, notifier = flow_factory()
    app = FastAPI()
    app.include_router(isp_partner_router, prefix="/api/v1")
    app.dependency_overrides[get_auth_service] = lambda: flow.auth_service
    app.dependency_overrides[get_rbac_repository] = lambda: None
    app.dependency_overrides[get_redis_client] = lambda: redis
    monkeypatch.setattr(m, "RoleResolver", flow.role_resolver_cls)
    return TestClient(app), notifier


def test_http_reply_is_identical_for_isp_customer_and_unknown(monkeypatch):
    isp = _user("isp@ispco.example.com")
    cust = _user("cust@venueco.example.com")
    users_assign = {
        isp.id: [_assign("isp-owner")],
        cust.id: [_assign("organization-owner")],
    }

    def factory():
        return _flow([isp, cust], users_assign)

    client, notifier = _client(monkeypatch, factory)
    replies = []
    emails = (
        "isp@ispco.example.com",
        "cust@venueco.example.com",
        "ghost@nowhere.example.com",
    )
    for email in emails:
        r = client.post("/api/v1/isp/auth/forgot-password", json={"email": email})
        body = r.json()
        body.pop("request_id", None)
        replies.append((r.status_code, body))
    assert replies[0] == replies[1] == replies[2]
    assert replies[0][0] == 200
    assert [s["recipient"] for s in notifier.sent] == ["isp@ispco.example.com"]


def test_http_404_while_flag_off(monkeypatch):
    client, _ = _client(monkeypatch, lambda: _flow([], {}))
    monkeypatch.setenv("ISP_PARTNER_ENABLED", "false")
    get_isp_partner_settings.cache_clear()
    r = client.post("/api/v1/isp/auth/forgot-password", json={"email": "a@b.test"})
    assert r.status_code == 404
