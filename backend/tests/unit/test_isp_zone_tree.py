"""ZONE-1 pure logic: tree walks, the narrowing rule, the no-op paths of
``apply_zone_scope``, the ORM criteria, and the route guards. The database
behaviour is in ``test_isp_zone_tree_postgres.py``."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.isp_partner import zones_scope as zs

A, B, C, D, E = (uuid.UUID(int=i) for i in range(1, 6))


def test_descendants_and_ancestry() -> None:
    parents = {A: None, B: A, C: B, D: A, E: None}
    assert zs.descendants(parents, A) == {A, B, C, D}
    assert zs.descendants(parents, C) == {C}
    assert zs.ancestry(parents, C) == [A, B, C]
    assert zs.ancestry(parents, E) == [E]


def test_walks_survive_a_stored_cycle() -> None:
    parents = {A: B, B: A}
    assert zs.descendants(parents, A) == {A, B}
    assert set(zs.ancestry(parents, A)) == {A, B}


def test_parent_map_drops_missing_and_self_parents() -> None:
    rows = [
        (SimpleNamespace(id=A), None),
        (SimpleNamespace(id=B), A),
        (SimpleNamespace(id=C), uuid.uuid4()),  # parent deleted / other ISP
        (SimpleNamespace(id=D), D),  # hand-edited self parent
    ]
    assert zs.parent_map(rows) == {A: None, B: A, C: None, D: None}


def test_narrow_never_widens() -> None:
    zone = frozenset({A, B})
    assert zs.narrow(None, zone) == zone  # unconfined: the zone's customers
    assert zs.narrow(frozenset({A, C}), zone) == frozenset({A})
    # empty intersection matches nothing -- it must not fall back to "all"
    assert zs.narrow(frozenset({C}), zone) == frozenset({zs.NO_MATCH})
    assert zs.narrow(None, frozenset()) == frozenset({zs.NO_MATCH})


@dataclass
class _Ctx:
    isp_org_id: uuid.UUID
    confined_customer_ids: frozenset[uuid.UUID] | None
    repository: Any
    _child_ids: Any = field(default=None)


class _Req:
    def __init__(self, params: dict[str, str]) -> None:
        self.query_params = params


@pytest.fixture
def zones_on(monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    from app.domains.isp_partner import zones_config

    monkeypatch.setenv("ISP_ZONES_ENABLED", "true")
    zones_config.get_zones_settings.cache_clear()
    yield
    monkeypatch.delenv("ISP_ZONES_ENABLED", raising=False)
    zones_config.get_zones_settings.cache_clear()


async def test_apply_is_a_noop_when_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.domains.isp_partner import zones_config

    monkeypatch.delenv("ISP_ZONES_ENABLED", raising=False)
    zones_config.get_zones_settings.cache_clear()
    ctx = _Ctx(A, None, SimpleNamespace(session=None))
    assert await zs.apply_zone_scope(ctx, _Req({"scope_zone_id": str(B)})) is ctx


async def test_apply_is_a_noop_without_param(zones_on) -> None:  # noqa: ANN001
    ctx = _Ctx(A, None, SimpleNamespace(session=None))
    assert await zs.apply_zone_scope(ctx, _Req({})) is ctx
    assert await zs.apply_zone_scope(ctx, None) is ctx  # direct (test) calls


async def test_garbage_zone_is_404(zones_on) -> None:  # noqa: ANN001
    from app.domains.isp_partner.exceptions import IspZoneNotFoundError

    ctx = _Ctx(A, None, SimpleNamespace(session=object()))
    with pytest.raises(IspZoneNotFoundError):
        await zs.apply_zone_scope(ctx, _Req({"scope_zone_id": "../x"}))


async def test_apply_narrows_and_tags_the_session(
    zones_on, monkeypatch: pytest.MonkeyPatch
) -> None:  # noqa: ANN001
    session = SimpleNamespace(info={})
    scope = zs.ZoneScope(
        zone_id=B, zone_ids=frozenset({B}), profile_customer_ids=frozenset()
    )

    async def fake_build(_s, _isp, zone_id):  # noqa: ANN001, ANN202
        assert zone_id == B
        return scope, frozenset({C, D})

    monkeypatch.setattr(zs, "build_scope", fake_build)
    ctx = _Ctx(A, frozenset({D, E}), SimpleNamespace(session=session), ["stale"])
    out = await zs.apply_zone_scope(ctx, _Req({"scope_zone_id": str(B)}))
    assert out.confined_customer_ids == frozenset({D})
    assert out._child_ids is None  # recomputed from the narrowed set
    assert zs.current_scope(session) is scope
    zs.clear_scope(session)
    assert zs.current_scope(session) is None


def test_criteria_cover_own_zone_and_customer_fallback() -> None:
    from sqlalchemy.dialects import postgresql

    scope = zs.ZoneScope(
        zone_id=A, zone_ids=frozenset({A, B}), profile_customer_ids=frozenset({C})
    )
    for crit in (zs._subscriber_criteria(scope), zs._invoice_criteria(scope)):
        sql = str(crit.compile(dialect=postgresql.dialect()))
        assert "zone_id IN" in sql and "zone_id IS NULL" in sql
        assert "customer_organization_id IN" in sql
    # no profile customers: the fallback matches nothing, not everything
    empty = zs.ZoneScope(
        zone_id=A, zone_ids=frozenset({A}), profile_customer_ids=frozenset()
    )
    sql = str(
        zs._subscriber_criteria(empty).compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    assert str(zs.NO_MATCH) in sql


def test_zone_routes_are_guarded_and_flag_gated() -> None:
    from app.domains.isp_partner.zones_config import RequireZonesEnabled
    from app.domains.isp_partner.zones_router import zones_router

    paths = set()
    for r in zones_router.routes:
        deps = {d.call for d in r.dependant.dependencies}
        names = {getattr(d, "__name__", type(d).__name__) for d in deps}
        assert RequireZonesEnabled in deps, r.path
        assert "RequireIspPartner" in names, r.path
        assert "RejectLocationRouterHeaders" in names, r.path
        paths.add((r.path, tuple(sorted(r.methods))))
    assert paths == {
        ("/zones/tree", ("GET",)),
        ("/zones/tree", ("POST",)),
        ("/zones/{zone_id}/parent", ("PUT",)),
        ("/zones/{zone_id}/tree", ("DELETE",)),
        ("/zones/{zone_id}/subtree", ("GET",)),
        ("/zones/totals", ("GET",)),
    }


def test_routes_are_mounted_before_billing() -> None:
    from app.main import create_app

    paths = [getattr(r, "path", "") for r in create_app().routes]
    assert "/api/v1/isp/zones/tree" in paths
    assert paths.index("/api/v1/isp/zones/tree") < paths.index("/api/v1/isp/zones")
