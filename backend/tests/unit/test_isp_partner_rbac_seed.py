"""BE-2: the ISP seeder adds rows and touches nothing else.

Runs the REAL ``rbac.seed.seed_rbac`` and the ISP seeder against one
in-memory repository and compares snapshots of every pre-existing role's
grants before and after.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import seed as isp_seed
from app.domains.isp_partner.rbac_roles import ROLES, all_permission_keys
from app.domains.rbac import seed as rbac_seed

EXPECTED = {
    "isp-owner": {
        "isp_partner.read",
        "isp_partner.create",
        "isp_partner.update",
        "isp_partner.manage",
        "isp_partner.execute",
        "isp_partner.export",
        "isp_partner.assign",
        "isp_logs.read",
        "isp_logs.export",
        "isp_ipdr.read",
        "isp_ipdr.export",
        "tr069.read",
        "tr069.execute",
        "tr069.manage",
    },
    "isp-noc": {
        "isp_partner.read",
        "isp_partner.export",
        "isp_logs.read",
        "isp_logs.export",
        "tr069.read",
        "tr069.execute",
    },
    "isp-technician": {
        "isp_partner.read",
        "isp_partner.create",
        "isp_partner.update",
        "isp_partner.execute",
        "isp_logs.read",
        "tr069.read",
        "tr069.execute",
        "tr069.manage",
    },
    "isp-viewer": {"isp_partner.read", "isp_partner.export", "tr069.read"},
}
# Phase 1b additions (ADDENDUM_01 §B.3, ADDENDUM_03 §11)
_BILLING = {
    f"isp_billing.{a}" for a in "read create update execute export manage".split()
}
_INVOICES = {f"isp_invoices.{a}" for a in "read create execute export manage".split()}
EXPECTED["isp-owner"] |= _BILLING | _INVOICES | {"isp_zones.read", "isp_zones.manage"}
EXPECTED["isp-noc"] |= {"isp_invoices.read", "isp_zones.read"}
EXPECTED["isp-technician"] |= {"isp_zones.read"}
EXPECTED["isp-viewer"] |= {
    "isp_billing.read",
    "isp_invoices.read",
    "isp_invoices.export",
    "isp_zones.read",
}
EXPECTED["isp-billing"] = (
    {"isp_partner.read", "isp_zones.read"}
    | (_BILLING - {"isp_billing.manage"})
    | _INVOICES
)
# Phase 2a additions (ADDENDUM_02 §7)
_PLANS = {f"isp_plans.{a}" for a in "read create update delete".split()}
_COUPONS = {f"isp_coupons.{a}" for a in "read create export update".split()}
EXPECTED["isp-owner"] |= (
    _PLANS | _COUPONS | {"isp_subscribers.read", "isp_subscribers.update"}
)
EXPECTED["isp-billing"] |= {
    "isp_plans.read",
    "isp_subscribers.read",
    "isp_subscribers.update",
} | _COUPONS
EXPECTED["isp-technician"] |= {
    "isp_plans.read",
    "isp_coupons.read",
    "isp_coupons.export",
    "isp_subscribers.read",
}
for _slug in ("isp-noc", "isp-viewer"):
    EXPECTED[_slug] |= {"isp_plans.read", "isp_coupons.read", "isp_subscribers.read"}
# Phase 2c additions: the venue twins (the customer dashboard's own feature
# set, ISP-gated). One group today; each further customer domain gets its own.
_NETWORK_FULL = {
    f"isp_network.{a}" for a in "read create update delete execute".split()
}
_NETWORK_CONFIGURE = {
    "isp_network.read",
    "isp_network.create",
    "isp_network.update",
    "isp_network.execute",
}
EXPECTED["isp-owner"] |= _NETWORK_FULL
EXPECTED["isp-noc"] |= {"isp_network.read", "isp_network.execute"}
EXPECTED["isp-technician"] |= _NETWORK_CONFIGURE
EXPECTED["isp-viewer"] |= {"isp_network.read"}
# ... and the Access & Policy surface (policies, allow-list, trusted devices,
# open hours).
_ACCESS_FULL = {f"isp_access.{a}" for a in "read create update delete execute".split()}
EXPECTED["isp-owner"] |= _ACCESS_FULL
EXPECTED["isp-noc"] |= {"isp_access.read"}
EXPECTED["isp-technician"] |= {
    "isp_access.read",
    "isp_access.create",
    "isp_access.update",
}
EXPECTED["isp-viewer"] |= {"isp_access.read"}
# ADDENDUM_04 §4: engage / security / ops / monitor / support.
EXPECTED["isp-owner"] |= (
    {f"isp_engage.{a}" for a in "read create update delete manage".split()}
    | {f"isp_security.{a}" for a in "read create update delete execute".split()}
    | {"isp_ops.execute", "isp_monitor.read", "isp_monitor.update"}
    | {"isp_support.read", "isp_support.create"}
)
EXPECTED["isp-noc"] |= {
    "isp_engage.read",
    "isp_security.read",
    "isp_ops.execute",
    "isp_monitor.read",
    "isp_monitor.update",
    "isp_support.read",
    "isp_support.create",
}
EXPECTED["isp-technician"] |= {
    "isp_engage.read",
    "isp_security.read",
    "isp_security.create",
    "isp_security.update",
    "isp_security.execute",
    "isp_ops.execute",
    "isp_monitor.read",
    "isp_monitor.update",
    "isp_support.read",
    "isp_support.create",
}
EXPECTED["isp-viewer"] |= {
    "isp_engage.read",
    "isp_security.read",
    "isp_monitor.read",
    "isp_support.read",
}
EXPECTED["isp-billing"] |= {
    "isp_engage.read",
    "isp_monitor.read",
    "isp_support.read",
    "isp_support.create",
}
EXPECTED["isp-admin"] = EXPECTED["isp-owner"]


class InMemoryRBAC:
    def __init__(self) -> None:
        self.groups: dict[str, SimpleNamespace] = {}
        self.permissions: dict[str, SimpleNamespace] = {}
        self.permission_scopes: dict[uuid.UUID, set[str]] = {}
        self.roles: dict[str, SimpleNamespace] = {}
        self.role_scopes: dict[uuid.UUID, set[str]] = {}
        self.role_permissions: dict[uuid.UUID, set[uuid.UUID]] = {}
        self.writes: list[tuple] = []

    async def get_permission_group_by_key(self, key):
        return self.groups.get(key)

    async def create_permission_group(self, **f):
        row = SimpleNamespace(id=uuid.uuid4(), **f)
        self.groups[f["key"]] = row
        self.writes.append(("group", f["key"]))
        return row

    async def get_permission_by_key(self, key):
        return self.permissions.get(key)

    async def create_permission(self, **f):
        row = SimpleNamespace(id=uuid.uuid4(), is_active=True, is_deleted=False, **f)
        self.permissions[f["key"]] = row
        self.writes.append(("permission", f["key"]))
        return row

    async def get_permission_scope_types(self, permission_id):
        return list(self.permission_scopes.get(permission_id, set()))

    async def add_permission_scope(self, permission_id, scope_type):
        self.permission_scopes.setdefault(permission_id, set()).add(scope_type.value)
        self.writes.append(("permission_scope", permission_id, scope_type.value))

    async def get_role_by_slug(self, slug, organization_id):
        return self.roles.get(slug)

    async def create_role(self, **f):
        row = SimpleNamespace(id=uuid.uuid4(), **f)
        self.roles[f["slug"]] = row
        self.writes.append(("role", f["slug"]))
        return row

    async def get_role_scope_types(self, role_id):
        return list(self.role_scopes.get(role_id, set()))

    async def add_role_scope(self, role_id, scope_type, *, is_default=False):
        self.role_scopes.setdefault(role_id, set()).add(scope_type.value)
        self.writes.append(("role_scope", role_id))

    async def get_role_permissions(self, role_id):
        return [
            SimpleNamespace(permission_id=p)
            for p in self.role_permissions.get(role_id, set())
        ]

    async def add_role_permission(self, role_id, permission_id, *, granted_by):
        self.role_permissions.setdefault(role_id, set()).add(permission_id)
        self.writes.append(("role_permission", role_id, permission_id))

    async def remove_role_permission(self, role_id, permission_id):
        self.role_permissions.get(role_id, set()).discard(permission_id)
        self.writes.append(("revoke", role_id, permission_id))
        return True

    # -- snapshots
    def grants(self, slugs=None) -> dict[str, set[str]]:
        by_id = {p.id: k for k, p in self.permissions.items()}
        return {
            slug: {by_id[p] for p in self.role_permissions.get(role.id, set())}
            for slug, role in self.roles.items()
            if slugs is None or slug in slugs
        }


@pytest.fixture
def repo(monkeypatch) -> InMemoryRBAC:
    shared = InMemoryRBAC()
    monkeypatch.setattr(rbac_seed, "RBACRepository", lambda session: shared)
    return shared


async def _existing_platform(repo: InMemoryRBAC) -> dict[str, set[str]]:
    await rbac_seed.seed_rbac(None)  # type: ignore[arg-type]
    return {k: set(v) for k, v in repo.grants().items()}


async def test_seeding_never_changes_a_pre_existing_role(repo) -> None:
    before = await _existing_platform(repo)
    assert "organization-owner" in before and "super-admin" in before
    await isp_seed.seed_isp_partner_rbac(repo)
    after = repo.grants(slugs=set(before))
    assert after == before
    # and no pre-existing role holds any ISP key
    ours = set(all_permission_keys())
    assert all(not (keys & ours) for keys in after.values())


async def test_roles_get_exactly_the_contract_keys(repo) -> None:
    await _existing_platform(repo)
    summary = await isp_seed.seed_isp_partner_rbac(repo)
    assert summary.permission_groups_created == 17  # +5 ADDENDUM_04 §4
    assert summary.permissions_created == 62  # +15 ADDENDUM_04 §4
    assert summary.roles_created == 6
    grants = repo.grants(slugs=set(EXPECTED))
    assert grants == EXPECTED
    for key in all_permission_keys():
        assert repo.permission_scopes[repo.permissions[key].id] == {"organization"}
    for role in ROLES:
        row = repo.roles[role.slug]
        assert row.is_system_role and row.organization_id is None
        assert row.scope_type == "organization"


async def test_running_twice_changes_nothing(repo) -> None:
    await _existing_platform(repo)
    await isp_seed.seed_isp_partner_rbac(repo)
    writes = len(repo.writes)
    summary = await isp_seed.seed_isp_partner_rbac(repo)
    assert len(repo.writes) == writes
    assert vars(summary) == vars(isp_seed.IspSeedSummary())


async def test_existing_rbac_seed_afterwards_leaves_isp_rows_alone(repo) -> None:
    await _existing_platform(repo)
    await isp_seed.seed_isp_partner_rbac(repo)
    isp_before = repo.grants(slugs=set(EXPECTED))
    everything_before = repo.grants()
    writes = len(repo.writes)
    await rbac_seed.seed_rbac(None)  # type: ignore[arg-type]
    assert repo.grants(slugs=set(EXPECTED)) == isp_before
    assert repo.grants() == everything_before
    assert len(repo.writes) == writes


async def test_a_non_system_role_squatting_a_slug_is_refused(repo) -> None:
    repo.roles["isp-owner"] = SimpleNamespace(
        id=uuid.uuid4(), slug="isp-owner", is_system_role=False
    )
    with pytest.raises(isp_seed.IspSeedConflictError):
        await isp_seed.seed_isp_partner_rbac(repo)
