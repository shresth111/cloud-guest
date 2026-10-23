"""ADDENDUM_04 §1: every ISP twin carries its original route's business gates.

A twin calls the ORIGINAL handler as a function, so the original route's
``RequireFeature(<key>)`` and the ``_PAID_WRITES`` include
(``RequireActiveLicenseForWrites``) never run. ``twin_gates`` re-applies them
against the CUSTOMER org. This file pins three things:

1. **Parity (structural).** For every row in ``VENUE_TWINS`` and every hand
   twin in ``router.py``, find the original route in the real app by its
   endpoint function, walk its dependency tree, and assert the twin declares
   the same feature keys and the same licence-on-writes gate. A
   ``RequireFeature`` added upstream later, or a router newly put on
   ``_PAID_WRITES``, turns this red until the twin row declares it.
2. **Inventory completeness.** Every ``router.py`` function that calls into
   another domain's router module is in ``HAND_TWIN_GATES`` -- a new hand twin
   cannot skip the declaration.
3. **Enforcement (behaviour).** ``build_twin`` and the hand twins refuse with
   the original 402s, evaluated on the CUSTOMER org (never the ISP header org),
   before the handler runs.

And it proves the checker bites: a row with a gate removed, and a synthetic
row over a feature-gated original with no feature declared, are both reported.
"""

from __future__ import annotations

import ast
import inspect
import uuid
from dataclasses import replace
from functools import lru_cache
from importlib import import_module
from pathlib import Path

import pytest
from starlette.requests import Request

from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.exceptions import (
    FeatureNotEntitledError,
    LicenseNotActiveError,
)
from app.domains.isp_partner import router as isp_router_module
from app.domains.isp_partner.twin_gates import (
    GATE_KWARG,
    HAND_TWIN_GATES,
    enforce_customer_gates,
    is_write,
)
from app.domains.isp_partner.twin_headers import HEADER_LOCATION
from app.domains.isp_partner.twins import TwinSpec, build_twin
from app.domains.isp_partner.twins_venue import VENUE_TWINS
from tests.unit.isp_partner_fixtures import CUST_A1, ISP_A, LOC_A1, context, estate
from tests.unit.isp_partner_gate_fakes import FakeChecker, FakeSnapshot

# ---------------------------------------------------------------------------
# Introspecting the ORIGINAL route
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _app():
    from app.main import create_app

    return create_app()


def _walk(dependant):
    for dep in dependant.dependencies:
        yield dep
        yield from _walk(dep)


def _closure(call) -> list:
    return [c.cell_contents for c in (getattr(call, "__closure__", None) or ())]


def original_routes(handler) -> list:
    """Every mounted route whose endpoint IS this handler function."""
    return [
        r
        for r in _app().routes
        if getattr(r, "endpoint", None) is handler and getattr(r, "methods", None)
    ]


def route_gates(route) -> tuple[frozenset[PlanFeatureKey], bool]:
    """(feature keys, licence-on-writes) declared anywhere in the route's tree."""
    features: set[PlanFeatureKey] = set()
    paid_writes = False
    for dep in _walk(route.dependant):
        qual = getattr(dep.call, "__qualname__", "")
        if qual.startswith("RequireFeature."):
            features |= {v for v in _closure(dep.call) if isinstance(v, PlanFeatureKey)}
        elif qual.startswith("RequireActiveLicenseForWrites."):
            paid_writes = True
    return frozenset(features), paid_writes


def expected_gates(handler, method: str) -> tuple[frozenset[PlanFeatureKey], bool]:
    """What a twin of ``handler`` called with ``method`` must declare."""
    routes = original_routes(handler)
    assert routes, (
        f"{handler.__module__}.{handler.__name__} is not mounted anywhere; a "
        "twin of an unmounted handler has no gates to compare against"
    )
    features: set[PlanFeatureKey] = set()
    paid = False
    for route in routes:
        f, p = route_gates(route)
        features |= f
        paid = paid or p
    return frozenset(features), (paid and is_write(method))


def gate_mismatches(spec: TwinSpec) -> list[str]:
    """Empty when the row declares exactly its original route's gates."""
    want_features, want_paid = expected_gates(spec.handler, spec.method)
    problems = []
    have_features = frozenset(spec.requires_features)
    if have_features != want_features:
        problems.append(
            f"{spec.method} {spec.path}: requires_features "
            f"{sorted(k.value for k in have_features)} != original "
            f"{sorted(k.value for k in want_features)}"
        )
    if spec.effective_paid_write != want_paid:
        problems.append(
            f"{spec.method} {spec.path}: paid_write "
            f"{spec.effective_paid_write} != original {want_paid}"
        )
    return problems


def _ids() -> list[str]:
    return [f"{s.method} {s.path}" for s in VENUE_TWINS]


# ---------------------------------------------------------------------------
# 1. Parity: every table row
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
def test_venue_twin_declares_its_original_routes_gates(spec: TwinSpec) -> None:
    assert gate_mismatches(spec) == []


def test_gated_rows_exist() -> None:
    """Sanity: the walk actually finds _PAID_WRITES on the network originals.

    If ``route_gates`` silently found nothing (a renamed dependency, say),
    every row would "match" with no gates and the parity test above would be
    vacuous.
    """
    paid = [s for s in VENUE_TWINS if expected_gates(s.handler, s.method)[1]]
    assert len(paid) >= 20, f"only {len(paid)} paid-write originals found"


# ---------------------------------------------------------------------------
# 2. Parity + completeness: hand twins in router.py
# ---------------------------------------------------------------------------


def _resolve_original(dotted: str):
    module, func = dotted.split(":")
    return getattr(import_module(module), func)


def _route_method(endpoint) -> str:
    for r in _app().routes:
        if getattr(r, "endpoint", None) is endpoint:
            return sorted(r.methods)[0]
    raise AssertionError(f"{endpoint.__name__} is not mounted")


@pytest.mark.parametrize("name", sorted(HAND_TWIN_GATES))
def test_hand_twin_declares_its_original_routes_gates(name: str) -> None:
    decl = HAND_TWIN_GATES[name]
    endpoint = getattr(isp_router_module, name)
    method = _route_method(endpoint)
    want_features, want_paid = expected_gates(_resolve_original(decl.original), method)
    assert frozenset(decl.features) == want_features, name
    assert (decl.paid_write and is_write(method)) == want_paid, name
    if want_paid or want_features:
        src = inspect.getsource(endpoint)
        calls = f'_hand_gate(\n        "{name}"' in src or f'_hand_gate("{name}"' in src
        assert calls, f"{name} declares a gate but never calls _hand_gate"


def _router_modules_imported_as_aliases() -> set[str]:
    """Local aliases of other domains' router modules (``portal_routes`` ...)."""
    tree = ast.parse(Path(isp_router_module.__file__).read_text())
    aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name == "router" and alias.asname:
                    aliases.add(alias.asname)
    return aliases


def test_every_hand_twin_is_in_the_gate_inventory() -> None:
    aliases = _router_modules_imported_as_aliases()
    assert {"portal_routes", "router_routes"} <= aliases
    tree = ast.parse(Path(isp_router_module.__file__).read_text())
    callers = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in aliases
                and not node.func.attr.startswith("_")  # serializers, not handlers
                and not node.func.attr.startswith("get_")  # DI providers
            ):
                callers.add(fn.name)
    missing = callers - set(HAND_TWIN_GATES)
    assert not missing, f"hand twins without a gate declaration: {sorted(missing)}"


# ---------------------------------------------------------------------------
# 3. The checker bites
# ---------------------------------------------------------------------------


def _first_paid_write_row() -> TwinSpec:
    return next(s for s in VENUE_TWINS if s.effective_paid_write)


def test_checker_reports_a_dropped_licence_gate() -> None:
    row = _first_paid_write_row()
    broken = replace(row, paid_write=False)
    problems = gate_mismatches(broken)
    assert problems and "paid_write" in problems[0]


def test_checker_reports_a_missing_feature_gate() -> None:
    """A twin of a RequireFeature(GUEST_MARKETING) original with no feature."""
    from app.domains.marketing import router as marketing_routes

    gated = [
        r
        for r in _app().routes
        if getattr(r, "endpoint", None) is not None
        and r.endpoint.__module__ == marketing_routes.__name__
        and route_gates(r)[0]
    ]
    assert gated, "no feature-gated marketing route found; the walk is broken"
    route = gated[0]
    method = sorted(route.methods)[0]
    synthetic = TwinSpec(
        method=method,
        path="/venue/_probe",
        permission_key="isp_engage.read",
        handler=route.endpoint,
        target="header_location",
    )
    problems = gate_mismatches(synthetic)
    assert any("requires_features" in p for p in problems)
    fixed = replace(synthetic, requires_features=tuple(route_gates(route)[0]))
    assert not any("requires_features" in p for p in gate_mismatches(fixed))


def test_checker_reports_an_extra_gate_too() -> None:
    """Over-gating is also drift: an ungated GET original with a feature."""
    row = next(s for s in VENUE_TWINS if s.method == "GET")
    assert gate_mismatches(
        replace(row, requires_features=(PlanFeatureKey.WHITE_LABEL,))
    )


# ---------------------------------------------------------------------------
# 4. Enforcement against the CUSTOMER org
# ---------------------------------------------------------------------------


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, request, **kwargs):
        self.calls.append(kwargs)
        return {"ok": True}


def _request() -> Request:
    headers = {"X-Organization-Id": str(ISP_A), HEADER_LOCATION: str(LOC_A1)}
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "POST", "headers": raw, "path": "/"})


def _probe(method: str, **overrides) -> tuple[TwinSpec, _Recorder]:
    rec = _Recorder()
    spec = TwinSpec(
        method=method,
        path="/venue/_probe",
        permission_key="isp_network.update",
        handler=rec,
        target="header_location",
        inject={"requesting_organization_id": ("org",)},
        **overrides,
    )
    return spec, rec


async def _call(spec: TwinSpec, checker) -> None:
    twin = build_twin(spec)
    kwargs = {"request": _request(), "isp": context(estate())}
    if spec.gated:
        kwargs[GATE_KWARG] = checker
    await twin(**kwargs)


async def test_lapsed_customer_write_is_refused_before_the_handler() -> None:
    spec, rec = _probe("POST")
    checker = FakeChecker(
        snapshots={
            CUST_A1: FakeSnapshot(license_status="expired"),
            # The ISP's own licence is fine: checking it would wrongly pass.
            ISP_A: FakeSnapshot(),
        }
    )
    with pytest.raises(LicenseNotActiveError):
        await _call(spec, checker)
    assert rec.calls == []
    assert checker.seen == [CUST_A1], "the gate must check the CUSTOMER org"


async def test_lapsed_customer_read_is_allowed() -> None:
    spec, rec = _probe("GET")
    checker = FakeChecker(snapshots={CUST_A1: FakeSnapshot(license_status="expired")})
    await _call(spec, checker)
    assert rec.calls and rec.calls[0]["requesting_organization_id"] == CUST_A1
    assert checker.seen == []


async def test_customer_without_any_licence_cannot_write() -> None:
    spec, rec = _probe("PUT")
    with pytest.raises(LicenseNotActiveError):
        await _call(spec, FakeChecker())
    assert rec.calls == []


async def test_missing_feature_is_refused_even_on_a_read() -> None:
    spec, rec = _probe("GET", requires_features=(PlanFeatureKey.GUEST_MARKETING,))
    checker = FakeChecker(
        snapshots={
            CUST_A1: FakeSnapshot(),
            ISP_A: FakeSnapshot(enabled_features=frozenset({"guest_marketing"})),
        }
    )
    with pytest.raises(FeatureNotEntitledError):
        await _call(spec, checker)
    assert rec.calls == []


async def test_entitled_customer_reaches_the_handler() -> None:
    spec, rec = _probe("POST", requires_features=(PlanFeatureKey.GUEST_MARKETING,))
    checker = FakeChecker(
        snapshots={
            CUST_A1: FakeSnapshot(enabled_features=frozenset({"guest_marketing"}))
        }
    )
    await _call(spec, checker)
    assert rec.calls


async def test_explicitly_ungated_write_skips_the_licence() -> None:
    spec, rec = _probe("POST", paid_write=False)
    assert not spec.gated
    await _call(spec, None)
    assert rec.calls


async def test_a_gated_twin_without_a_checker_fails_closed() -> None:
    with pytest.raises(RuntimeError):
        await enforce_customer_gates(
            None, uuid.uuid4(), method="POST", paid_write=True
        )


def test_a_gated_twin_with_no_customer_target_is_rejected_at_build() -> None:
    spec, _ = _probe("POST")
    with pytest.raises(ValueError):
        build_twin(replace(spec, target="none"))


def test_gated_twin_signature_requests_the_checker() -> None:
    spec, _ = _probe("POST")
    assert GATE_KWARG in inspect.signature(build_twin(spec)).parameters
    ungated, _ = _probe("GET")
    assert GATE_KWARG not in inspect.signature(build_twin(ungated)).parameters
