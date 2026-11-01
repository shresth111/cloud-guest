"""BE-9: ISP staff user rules (API_CONTRACT §1.3, §4.11)."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.auth.password import PasswordManager
from app.domains.isp_partner.exceptions import (
    IspConfinementNotAllowedError,
    IspCustomerNotFoundError,
    IspLastOwnerError,
    IspRoleEscalationError,
    IspRoleInvalidError,
    IspUserNotFoundError,
)
from app.domains.isp_partner.users_service import IspUsersService, temporary_password
from tests.unit.isp_partner_fixtures import (
    CUST_A1,
    CUST_B1,
    ISP_A,
    NOW,
    FakeIspRepository,
    context,
    estate,
)

ROLE_IDS = {
    slug: uuid.uuid4()
    for slug in ("isp-owner", "isp-admin", "isp-noc", "isp-technician", "isp-viewer")
}


def _user(uid, *, active=True):
    return SimpleNamespace(
        id=uid,
        first_name="A",
        last_name="B",
        email=f"{uid.hex[:6]}@example.com",
        phone=None,
        username=f"{uid.hex[:6]}@example.com",
        is_active=active,
        is_deleted=False,
        last_login_at=None,
        created_at=NOW,
    )


class Repo(FakeIspRepository):
    def __init__(self):
        base = estate()
        super().__init__(**{k: getattr(base, k) for k in base.__dataclass_fields__})
        self.users: dict = {}
        self.roles: dict = {}
        self.replaced: list = []

    async def get_user(self, uid):
        return self.users.get(uid)

    async def isp_role_assignments(self, isp_org_id, *, user_id=None):
        if user_id not in self.roles:
            return []
        slug = self.roles[user_id]
        return [
            (
                SimpleNamespace(id=uuid.uuid4(), user_id=user_id),
                SimpleNamespace(slug=slug),
            )
        ]

    async def count_active_owners(self, isp_org_id):
        return sum(
            1
            for u, s in self.roles.items()
            if s == "isp-owner" and self.users[u].is_active
        )

    async def scopes_for_users(self, isp, ids):
        return {}

    async def replace_scopes(self, isp, uid, ids, *, actor_user_id):
        self.replaced.append((uid, ids))


class Rbac:
    def __init__(self):
        self.created: list = []
        self.deactivated: list = []

    async def get_role_by_slug(self, slug, org):
        return (
            SimpleNamespace(id=ROLE_IDS[slug], slug=slug, organization_id=None)
            if slug in ROLE_IDS
            else None
        )

    async def create_user_role(self, **kw):
        self.created.append(kw)

    async def deactivate_user_role(self, assignment):
        self.deactivated.append(assignment)

    async def create_audit_log_entry(self, **kw):
        return None


class Users:
    notification_service = None

    def __init__(self, repo):
        self.repo = repo
        self.calls: list = []

    async def create_user(self, **kw):
        self.calls.append(("create", kw))
        u = _user(uuid.uuid4())
        self.repo.users[u.id] = u
        return u

    async def deactivate_user(self, **kw):
        self.calls.append(("deactivate", kw))
        u = self.repo.users[kw["user_id"]]
        u.is_active = False
        return u

    async def reactivate_user(self, **kw):
        u = self.repo.users[kw["user_id"]]
        u.is_active = True
        return u

    async def force_logout_user(self, **kw):
        self.calls.append(("force_logout", kw))
        return self.repo.users[kw["user_id"]]


class Identity:
    def __init__(self):
        self.updates: list = []

    async def update_user(self, user, **fields):
        self.updates.append(fields)
        for k, v in fields.items():
            setattr(user, k, v)
        return user


class Cache:
    def __init__(self):
        self.invalidated: list = []

    async def invalidate(self, uid):
        self.invalidated.append(uid)


def _svc():
    repo = Repo()
    rbac = Rbac()
    users = Users(repo)
    identity = Identity()
    cache = Cache()
    svc = IspUsersService(
        repository=repo,
        user_service=users,
        identity_repository=identity,
        rbac_repository=rbac,
        permission_cache=cache,
        audit=rbac,
    )
    return SimpleNamespace(
        svc=svc, repo=repo, rbac=rbac, users=users, identity=identity, cache=cache
    )


def _body(role, **kw):
    return {
        "first_name": "A",
        "last_name": "B",
        "email": "a@example.com",
        "role": role,
        "send_welcome_email": False,
        **kw,
    }


def _with(t, slug):
    u = _user(uuid.uuid4())
    t.repo.users[u.id] = u
    t.repo.roles[u.id] = slug
    return u


async def test_create_puts_user_in_isp_org_with_isp_role_only() -> None:
    t = _svc()
    out = await t.svc.create_user(
        context(t.repo), _body("isp-technician", customer_ids=[CUST_A1])
    )
    ((_, kw),) = t.users.calls
    assert kw["organization_id"] == ISP_A and kw["requesting_organization_id"] == ISP_A
    assert kw["initial_role_id"] is None  # never RBACService.assign_role_to_user
    (grant,) = t.rbac.created
    assert grant["role_id"] == ROLE_IDS["isp-technician"]
    assert grant["organization_id"] == ISP_A and grant["scope_type"] == "organization"
    assert t.identity.updates[0] == {"must_change_password": True}
    assert t.cache.invalidated
    assert out["temporary_password"] and out["user"]["role"] == "isp-technician"
    PasswordManager.validate_strength(out["temporary_password"])
    assert t.repo.replaced == [(uuid.UUID(out["user"]["id"]), [CUST_A1])]


@pytest.mark.parametrize(
    "role", ["organization-owner", "organization-admin", "msp-owner", "super-admin"]
)
async def test_non_isp_roles_are_invalid(role) -> None:
    t = _svc()
    with pytest.raises(IspRoleInvalidError):
        await t.svc.create_user(context(t.repo), _body(role))
    assert t.users.calls == [] and t.rbac.created == []


async def test_only_owner_grants_owner_or_admin() -> None:
    t = _svc()
    for role in ("isp-owner", "isp-admin"):
        with pytest.raises(IspRoleEscalationError) as err:
            await t.svc.create_user(context(t.repo, role="isp-admin"), _body(role))
        assert err.value.status_code == 403
    await t.svc.create_user(context(t.repo, role="isp-owner"), _body("isp-admin"))


async def test_owners_and_admins_cannot_be_confined_and_ids_are_scoped() -> None:
    t = _svc()
    with pytest.raises(IspConfinementNotAllowedError):
        await t.svc.create_user(
            context(t.repo), _body("isp-admin", customer_ids=[CUST_A1])
        )
    with pytest.raises(IspCustomerNotFoundError):
        await t.svc.create_user(
            context(t.repo), _body("isp-noc", customer_ids=[CUST_B1])
        )
    assert t.users.calls == []


async def test_admin_cannot_touch_an_owner() -> None:
    t = _svc()
    owner = _with(t, "isp-owner")
    _with(t, "isp-owner")
    admin_ctx = context(t.repo, role="isp-admin")
    for call in (
        t.svc.set_enabled(admin_ctx, owner.id, False),
        t.svc.reset_password(admin_ctx, owner.id),
        t.svc.update_user(admin_ctx, owner.id, {"first_name": "X"}),
        t.svc.force_logout(admin_ctx, owner.id),
    ):
        with pytest.raises(IspRoleEscalationError):
            await call


async def test_last_owner_cannot_be_disabled_or_demoted() -> None:
    t = _svc()
    owner = _with(t, "isp-owner")
    with pytest.raises(IspLastOwnerError) as err:
        await t.svc.set_enabled(context(t.repo), owner.id, False)
    assert err.value.status_code == 409
    with pytest.raises(IspLastOwnerError):
        await t.svc.update_user(context(t.repo), owner.id, {"role": "isp-admin"})
    second = _with(t, "isp-owner")
    await t.svc.set_enabled(context(t.repo), owner.id, False)
    assert (
        "deactivate",
        {
            "actor_user_id": context(t.repo).user_id,
            "user_id": owner.id,
            "requesting_organization_id": ISP_A,
        },
    ) in t.users.calls
    assert second


async def test_role_change_deactivates_old_row_and_grants_new() -> None:
    t = _svc()
    tech = _with(t, "isp-technician")
    out = await t.svc.update_user(context(t.repo), tech.id, {"role": "isp-viewer"})
    assert len(t.rbac.deactivated) == 1
    assert t.rbac.created[-1]["role_id"] == ROLE_IDS["isp-viewer"]
    assert out["role"] == "isp-viewer"


async def test_reset_sets_must_change_and_ends_sessions() -> None:
    t = _svc()
    noc = _with(t, "isp-noc")
    out = await t.svc.reset_password(context(t.repo), noc.id)
    assert t.identity.updates[-1]["must_change_password"] is True
    assert PasswordManager.verify(
        out["temporary_password"], t.identity.updates[-1]["password_hash"]
    )
    assert t.users.calls[-1][0] == "force_logout"


async def test_disable_blocks_login() -> None:
    """deactivate_user sets is_active=False, which get_current_user and login
    already refuse; this service must route disable through it."""
    t = _svc()
    noc = _with(t, "isp-noc")
    out = await t.svc.set_enabled(context(t.repo), noc.id, False)
    assert out["status"] == "disabled" and t.repo.users[noc.id].is_active is False


async def test_user_without_an_isp_role_on_this_isp_is_404() -> None:
    t = _svc()
    stranger = _user(uuid.uuid4())
    t.repo.users[stranger.id] = stranger
    with pytest.raises(IspUserNotFoundError):
        await t.svc.get_user(context(t.repo), stranger.id)


def test_temporary_password_meets_policy() -> None:
    for _ in range(50):
        PasswordManager.validate_strength(temporary_password())


async def test_role_rows_must_resolve_to_isp_slugs() -> None:
    with pytest.raises(IspRoleInvalidError):
        await IspUsersService._assert_isp_role(
            SimpleNamespace(slug="organization-owner", organization_id=None)
        )
    with pytest.raises(IspRoleInvalidError):
        await IspUsersService._assert_isp_role(
            SimpleNamespace(slug="isp-owner", organization_id=uuid.uuid4())
        )
