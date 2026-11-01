"""J22 fiber plant registry (ADDENDUM_05 §7, JAZE-6 part B).

Pure rules directly; isolation through the service with a fake session (no
SQL runs for these paths). The route table (guard stack, flag-off 404, no
scope-alias names) is walked for every isp_partner route by
``test_isp_partner_guards``, fiber included.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import fiber_service as fs
from app.domains.isp_partner.fiber_models import IspFiberNode

ISP, OTHER_ISP = uuid.uuid4(), uuid.uuid4()
CUST_A, CUST_B = uuid.uuid4(), uuid.uuid4()


def _node(**kw):
    base = {
        "id": uuid.uuid4(),
        "isp_organization_id": ISP,
        "customer_organization_id": None,
        "kind": "splitter",
        "name": "SPL-1",
        "code": None,
        "latitude": None,
        "longitude": None,
        "address": None,
        "parent_id": None,
        "parent_port": None,
        "port_count": 8,
        "spec": None,
        "status": "active",
        "notes": None,
        "is_deleted": False,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def _isp(confined=None):
    async def children():
        return [c for c in (CUST_A, CUST_B) if confined is None or c in confined]

    return SimpleNamespace(
        isp_org_id=ISP,
        user_id=uuid.uuid4(),
        role_slug="isp-technician",
        confined_customer_ids=confined,
        child_ids=children,
    )


class _GetOnly:
    """session.get() from a dict; any query is a test failure."""

    def __init__(self, *rows):
        self.rows = {r.id: r for r in rows}

    async def get(self, _model, key):
        return self.rows.get(key)

    async def execute(self, *_a, **_k):  # pragma: no cover - must not run
        raise AssertionError("no query expected")


# -- pure rules ------------------------------------------------------------------
def test_maps_url() -> None:
    assert fs.maps_url(None, 77.1) is None
    assert fs.maps_url(28.5355, 77.391) == (
        "https://www.google.com/maps/search/?api=1&query=28.535500,77.391000"
    )


def test_parent_port_must_exist_on_the_parent() -> None:
    fs.check_parent_port(_node(port_count=8), None)
    fs.check_parent_port(_node(port_count=8), 8)
    with pytest.raises(fs.IspFiberInvalidError):
        fs.check_parent_port(_node(port_count=8), 9)
    with pytest.raises(fs.IspFiberInvalidError):
        fs.check_parent_port(_node(port_count=None), 1)


def test_node_view_carries_the_maps_link() -> None:
    v = fs.node_view(
        _node(latitude=1.0, longitude=2.0, customer_organization_id=CUST_A)
    )
    assert v["maps_url"].endswith("query=1.000000,2.000000")
    assert v["isp_customer_id"] == CUST_A


def test_kinds_match_the_model_check_constraint() -> None:
    ck = next(
        c
        for c in IspFiberNode.__table__.constraints
        if getattr(c, "name", "") == "ck_isp_fiber_nodes_kind"
    )
    for kind in fs.FIBER_KINDS:
        assert f"'{kind}'" in str(ck.sqltext)


# -- isolation ---------------------------------------------------------------------
async def test_another_isps_node_is_404() -> None:
    n = _node(isp_organization_id=OTHER_ISP)
    with pytest.raises(fs.IspFiberNotFoundError):
        await fs.IspFiberService(_GetOnly(n))._node(_isp(), n.id)


async def test_deleted_node_is_404() -> None:
    n = _node(is_deleted=True)
    with pytest.raises(fs.IspFiberNotFoundError):
        await fs.IspFiberService(_GetOnly(n))._node(_isp(), n.id)


async def test_confined_staff_see_shared_and_own_plant_only() -> None:
    shared, mine, theirs = (
        _node(),
        _node(customer_organization_id=CUST_A),
        _node(customer_organization_id=CUST_B),
    )
    svc = fs.IspFiberService(_GetOnly(shared, mine, theirs))
    isp = _isp(confined=frozenset({CUST_A}))
    assert (await svc._node(isp, shared.id)) is shared
    assert (await svc._node(isp, mine.id, write=True)) is mine
    with pytest.raises(fs.IspFiberNotFoundError):
        await svc._node(isp, theirs.id)
    with pytest.raises(fs.IspFiberInvalidError):
        await svc._node(isp, shared.id, write=True)


async def test_confined_staff_must_name_a_customer() -> None:
    with pytest.raises(fs.IspFiberInvalidError):
        await fs.IspFiberService(_GetOnly())._check_customer(
            _isp(confined=frozenset({CUST_A})), None
        )
    await fs.IspFiberService(_GetOnly())._check_customer(_isp(), None)


async def test_nothing_hangs_below_an_ont() -> None:
    ont = _node(kind="ont", port_count=None)
    child = _node(id=None, kind="other")
    with pytest.raises(fs.IspFiberInvalidError):
        await fs.IspFiberService(_GetOnly(ont))._set_parent(_isp(), child, ont.id, None)


async def test_ont_with_ports_is_refused_before_any_query() -> None:
    with pytest.raises(fs.IspFiberInvalidError):
        await fs.IspFiberService(_GetOnly()).create(
            _isp(), {"kind": "ont", "name": "ONT", "port_count": 4}
        )


async def test_port_without_parent_is_refused() -> None:
    with pytest.raises(fs.IspFiberInvalidError):
        await fs.IspFiberService(_GetOnly())._set_parent(_isp(), _node(), None, 3)


# -- flag + route table ---------------------------------------------------------------
async def test_fiber_flag_defaults_off() -> None:
    from fastapi import HTTPException

    fs.get_isp_fiber_settings.cache_clear()
    assert fs.get_isp_fiber_settings().enabled is False
    with pytest.raises(HTTPException) as exc:
        await fs.RequireIspFiberEnabled()
    assert exc.value.status_code == 404


def test_fiber_routes_use_existing_keys_only() -> None:
    from app.domains.isp_partner.fiber_router import fiber_router
    from app.domains.isp_partner.rbac_roles import all_permission_keys

    keys = set(all_permission_keys())
    seen = set()
    for r in fiber_router.routes:
        for d in r.dependencies:
            call = d.dependency
            if getattr(call, "__qualname__", "").startswith("RequirePermission"):
                for cell in call.__closure__ or ():
                    v = cell.cell_contents
                    if isinstance(v, str) and "." in v:
                        seen.add(v)
    assert seen and seen <= keys
    assert seen == {"isp_partner.read", "isp_partner.update", "isp_partner.manage"}
