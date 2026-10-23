"""Phase 2c venue twins: the table must actually fit the handlers it calls.

The guard test (``test_isp_partner_guards.py``) proves the *metadata*: four
guards in order, one ORGANIZATION-pinned permission, no scope-alias parameter.
It cannot see whether a row's ``inject``/``deps``/``extras`` names exist on the
original handler. A typo there is invisible to the guard test, invisible to a
type checker (everything is ``dict[str, Any]``), and fails only at request time
in production with a ``TypeError``.

So this file pins the seam. For every row in ``VENUE_TWINS`` it asserts:

1. every name the row will pass to the handler is a real parameter of that
   handler -- which is what catches ``actor`` vs ``user``, ``pool_id`` vs
   ``isp_pool_id``, a renamed schema field, or a handler that grew/lost an
   argument since the row was written;
2. every parameter the handler REQUIRES is supplied by the row -- so a new
   required argument on the original makes the row fail here rather than 500;
3. the row exposes no parameter named like an RBAC scope alias;
4. resolution works: a row whose target is ``header_location`` turns the
   location header into that location's CUSTOMER organization id, and refuses
   another ISP's location.

It deliberately does not require a live service: it substitutes a recording
handler, so the test stays a pure unit test and the assertion is about the
seam, not about any one domain's business logic.
"""

from __future__ import annotations

import inspect
import uuid
from dataclasses import replace

import pytest
from starlette.requests import Request

from app.domains.isp_partner.twin_gates import GATE_KWARG
from app.domains.isp_partner.twin_headers import HEADER_CUSTOMER, HEADER_LOCATION
from app.domains.isp_partner.twins import Param, TwinSpec, build_twin
from app.domains.isp_partner.twins_all import ALL_TWINS as VENUE_TWINS
from tests.unit.isp_partner_fixtures import (
    CFG_A1,
    CUST_A1,
    ISP_A,
    LOC_A1,
    LOC_B1,
    RTR_A1,
    context,
    estate,
)

FORBIDDEN_PARAM_NAMES = {"organization_id", "customer_id", "location_id", "router_id"}


def _request(**headers: str) -> Request:
    raw = [
        (k.lower().encode(), v.encode())
        for k, v in {
            "X-Organization-Id": str(ISP_A),
            HEADER_CUSTOMER: str(CUST_A1),
            **headers,
        }.items()
    ]
    return Request({"type": "http", "method": "GET", "headers": raw, "path": "/"})


def _supplied(spec: TwinSpec) -> set[str]:
    """Every name the row will hand the handler.

    A parameter the row consumes through ``inject: {..., ("param", name)}``
    reaches the handler under the INJECT key, not under its own exposed name --
    ``isp_user_id`` on the wire becomes ``user_id`` in the call. So the exposed
    name is only "supplied" when nothing renames it.
    """
    renamed = {src[1] for src in spec.inject.values() if src[0] == "param"}
    names = {"request"}
    names |= set(spec.inject)
    names |= set(spec.deps)
    names |= {p.forward or p.name for p in spec.params if p.name not in renamed}
    names |= {e.forward for e in spec.extras}
    return names


def _ids() -> list[str]:
    return [f"{s.method} {s.path}" for s in VENUE_TWINS]


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
def test_row_only_passes_names_the_handler_accepts(spec: TwinSpec) -> None:
    accepted = set(inspect.signature(spec.handler).parameters)
    unknown = {n for n in _supplied(spec) if n not in accepted}
    assert not unknown, (
        f"{spec.name} passes {sorted(unknown)} to "
        f"{spec.handler.__module__}.{spec.handler.__name__}, which does not accept "
        f"them. Accepted: {sorted(accepted)}"
    )


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
def test_row_supplies_every_required_handler_parameter(spec: TwinSpec) -> None:
    supplied = _supplied(spec)
    missing = [
        name
        for name, param in inspect.signature(spec.handler).parameters.items()
        if param.default is inspect.Parameter.empty
        and param.kind
        in (inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        and name not in supplied
    ]
    assert not missing, (
        f"{spec.name} leaves required parameter(s) {missing} unsupplied for "
        f"{spec.handler.__module__}.{spec.handler.__name__}"
    )


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
def test_row_exposes_no_scope_alias_parameter_name(spec: TwinSpec) -> None:
    exposed = {p.name for p in spec.params} | {e.name for e in spec.extras}
    assert not (exposed & FORBIDDEN_PARAM_NAMES), (
        f"{spec.name} exposes {sorted(exposed & FORBIDDEN_PARAM_NAMES)}; those names "
        "are RBAC scope aliases and would move the permission check onto a customer org"
    )


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
def test_every_extra_is_reachable_and_isp_prefixed(spec: TwinSpec) -> None:
    for extra in spec.extras:
        assert extra.name.startswith("isp_"), extra.name
        assert extra.forward in inspect.signature(spec.handler).parameters, (
            f"{spec.name}: extra forwards {extra.forward!r}, not a handler parameter"
        )
    assert all(isinstance(p, Param) for p in spec.params)


# --------------------------------------------------------------------------
# resolution: the seam between the header, IspScope and the handler
# --------------------------------------------------------------------------


class Recorder:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, request, **kwargs):
        self.calls.append(kwargs)
        return {"ok": True}


def _recording(spec: TwinSpec) -> tuple[TwinSpec, Recorder]:
    rec = Recorder()
    return replace(spec, handler=rec), rec


def _kwargs(spec: TwinSpec) -> dict:
    """The non-dependency values the twin's own signature will receive."""
    out: dict = {"request": None, "isp": None}
    if spec.gated:
        # A permissive checker so these seam tests reach the handler; the
        # gates themselves are pinned by test_isp_partner_twin_gates.py.
        from tests.unit.isp_partner_gate_fakes import entitled_everything

        out[GATE_KWARG] = entitled_everything()
    for param in spec.params:
        if param.name == spec.resolve_param:
            # The row resolves through this id: a real fixture row of CUST_A1.
            out[param.name] = _RESOLVABLE[spec.target]
        elif param.required:
            out[param.name] = _sample(param)
        elif param.source == "query":
            out[param.name] = param.default
        else:  # an optional body part, e.g. an UploadFile with a File() default
            out[param.name] = object()
    for extra in spec.extras:
        # A real fixture row, not a random id: resolution runs before the
        # handler, so a made-up id would 404 and never reach the recorder.
        out[extra.name] = _KNOWN[extra.target] if extra.required else None
    return out


#: A resolvable id per path-resolved target, all CUST_A1's.
_RESOLVABLE = {
    "customer": CUST_A1,
    "portal_config": CFG_A1,
    "location": LOC_A1,
    "router": RTR_A1,
}

#: Real rows from ``estate()``, all belonging to ISP A's customer CUST_A1.
_KNOWN = {"router": RTR_A1, "location": LOC_A1, "customer": CUST_A1}


def _sample(param: Param):
    if param.annotation is uuid.UUID:
        return uuid.uuid4()
    if param.annotation is int:
        return param.default if param.default is not inspect.Parameter.empty else 1
    # a body model: an unvalidated instance, so the twin's body-id checks
    # (twin_body.py) have real attributes to read. A policy assignment needs a
    # scope an ISP may use.
    construct = getattr(param.annotation, "model_construct", None)
    if construct is None:
        return object()
    if "scope_type" in param.annotation.model_fields:
        return construct(scope_type="organization")
    return construct()


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
async def test_header_location_rows_resolve_to_the_customers_org(
    spec: TwinSpec,
) -> None:
    """The row must hand the handler the LOCATION'S customer, never the ISP."""
    if spec.target != "header_location":
        pytest.skip("not a venue-location row")
    twin_spec, rec = _recording(spec)
    twin = build_twin(twin_spec)
    repo = estate()
    isp = context(repo)
    kwargs = _kwargs(twin_spec)
    kwargs["request"] = _request(**{HEADER_LOCATION: str(LOC_A1)})
    kwargs["isp"] = isp
    for dep in twin_spec.deps:
        kwargs[dep] = None

    await twin(**kwargs)

    assert rec.calls, "the handler was never called"
    call = rec.calls[0]
    # The handler's own name for the org differs across domains
    # (``requesting_organization_id`` in most, plain ``organization_id`` on the
    # captive-portal resolve), so read it off the row's own declaration rather
    # than assuming a name.
    org_keys = [k for k, src in twin_spec.inject.items() if src[0] == "org"]
    assert org_keys, f"{twin_spec.name} scopes the handler to no organization"
    for key in org_keys:
        assert call[key] == CUST_A1, (
            "a venue twin must scope the original handler to the CUSTOMER org "
            f"({CUST_A1}), got {call.get(key)}"
        )
        assert call[key] != ISP_A, "scoped to the ISP org"
    for key in [k for k, src in twin_spec.inject.items() if src[0] == "location"]:
        assert call[key] == LOC_A1


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
async def test_header_location_refuses_another_isps_location(spec: TwinSpec) -> None:
    """ISP A naming ISP B's location is a 404, and the handler never runs."""
    if spec.target != "header_location":
        pytest.skip("not a venue-location row")
    from app.domains.isp_partner.exceptions import IspLocationNotFoundError

    twin_spec, rec = _recording(spec)
    twin = build_twin(twin_spec)
    repo = estate()
    kwargs = _kwargs(twin_spec)
    kwargs["request"] = _request(**{HEADER_LOCATION: str(LOC_B1)})
    kwargs["isp"] = context(repo, isp=ISP_A)
    for dep in twin_spec.deps:
        kwargs[dep] = None

    with pytest.raises(IspLocationNotFoundError):
        await twin(**kwargs)
    assert rec.calls == [], "the handler ran for another ISP's location"


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
async def test_a_missing_location_header_is_refused(spec: TwinSpec) -> None:
    if spec.target != "header_location":
        pytest.skip("not a venue-location row")
    twin_spec, rec = _recording(spec)
    twin = build_twin(twin_spec)
    kwargs = _kwargs(twin_spec)
    kwargs["request"] = _request()
    kwargs["isp"] = context(estate())
    for dep in twin_spec.deps:
        kwargs[dep] = None

    with pytest.raises(Exception) as excinfo:
        await twin(**kwargs)
    assert getattr(excinfo.value, "code", None) == "ISP_BAD_REQUEST"
    assert rec.calls == []


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
async def test_a_router_extra_from_another_customer_is_refused(spec: TwinSpec) -> None:
    """A router id belonging to a different customer of the same ISP is a 404."""
    if not spec.extras:
        pytest.skip("no extra ids")
    from app.domains.isp_partner.exceptions import IspRouterNotFoundError
    from tests.unit.isp_partner_fixtures import RTR_B1

    router_extra = next((e for e in spec.extras if e.target == "router"), None)
    if router_extra is None:
        pytest.skip("no router extra")

    twin_spec, rec = _recording(spec)
    twin = build_twin(twin_spec)
    repo = estate()
    kwargs = _kwargs(twin_spec)
    kwargs["request"] = _request(**{HEADER_LOCATION: str(LOC_A1)})
    kwargs["isp"] = context(repo)
    kwargs[router_extra.name] = RTR_B1  # ISP B's router, not A's
    for dep in twin_spec.deps:
        kwargs[dep] = None

    with pytest.raises(IspRouterNotFoundError):
        await twin(**kwargs)
    assert rec.calls == [], "the handler ran for a router outside the customer"


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
async def test_every_declared_parameter_reaches_the_handler(spec: TwinSpec) -> None:
    """A param the twin parses but never forwards is a silent 500.

    The original handlers declare query parameters with FastAPI defaults
    (`page: int = Query(default=1)`). Those defaults are `Query` OBJECTS until
    FastAPI resolves them through its own signature -- which never happens for a
    twin, because the twin calls the handler directly. So a dropped parameter
    reaches the service as a `Query` and dies in `PageParams` with
    `TypeError: '>' not supported between instances of 'int' and 'Query'`.

    This was found on the test box, not here: the earlier tests only required
    that the handler's REQUIRED parameters were supplied, and `page` has a
    default, so nothing noticed it was missing.
    """
    twin_spec, rec = _recording(spec)
    twin = build_twin(twin_spec)
    kwargs = _kwargs(twin_spec)
    kwargs["request"] = _request(**{HEADER_LOCATION: str(LOC_A1)})
    kwargs["isp"] = context(estate())
    for dep in twin_spec.deps:
        kwargs[dep] = None

    await twin(**kwargs)

    assert rec.calls, "the handler was never called"
    got = rec.calls[0]
    renamed = {src[1] for src in twin_spec.inject.values() if src[0] == "param"}
    for param in twin_spec.params:
        if param.name in renamed:
            continue
        assert (param.forward or param.name) in got, (
            f"{spec.name} declares {param.name!r} but never forwards it, so the "
            f"handler would fall back to its own Query default"
        )


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
def test_row_supplies_every_handler_parameter_not_just_the_required_ones(
    spec: TwinSpec,
) -> None:
    """An OPTIONAL handler parameter the row never supplies is a 500, not a no-op.

    The handlers declare optional filters as `param: X | None = Query(default=None)`.
    FastAPI turns those into real values only through its own signature, which a
    twin never goes through -- it calls the handler directly, so the default that
    arrives is the raw `Query` OBJECT. That object then reaches the repository as
    a bind parameter:

        asyncpg DataError: invalid input for query argument $2: Query(None)

    Found on the test box: `GET /isp/venue/vlans` supplied neither `router_id`
    (it had no router extra) nor the guest allow-list's `identifier`/`rule_type`.
    The "required parameters" test above cannot see this, because all three have
    defaults.
    """
    supplied = _supplied(spec)
    missing = [
        name
        for name, param in inspect.signature(spec.handler).parameters.items()
        if param.kind
        in (inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        and name not in supplied
    ]
    assert not missing, (
        f"{spec.name} never supplies {missing} to "
        f"{spec.handler.__module__}.{spec.handler.__name__}; those handler defaults "
        "are Query objects when called directly, and leak into the DB layer"
    )


@pytest.mark.parametrize("spec", VENUE_TWINS, ids=_ids())
async def test_a_router_extra_from_another_location_is_refused(spec: TwinSpec) -> None:
    """Same customer, DIFFERENT location: the ISP manages each location's
    routers separately, so that router is out of scope for this workspace."""
    from types import SimpleNamespace

    from app.domains.isp_partner.exceptions import IspRouterNotFoundError

    router_extra = next((e for e in spec.extras if e.target == "router"), None)
    if router_extra is None:
        pytest.skip("no router extra")

    twin_spec, rec = _recording(spec)
    twin = build_twin(twin_spec)
    repo = estate()
    # A second location of the SAME customer, with its own router.
    other_loc = uuid.UUID("00000000-0000-0000-0000-00000000a102")
    other_rtr = uuid.UUID("00000000-0000-0000-0000-0000a1020001")
    repo.locations[other_loc] = SimpleNamespace(
        id=other_loc, organization_id=CUST_A1, name="Loc A1b", is_deleted=False
    )
    repo.routers[other_rtr] = SimpleNamespace(
        id=other_rtr,
        organization_id=CUST_A1,
        location_id=other_loc,
        name="hEX 2",
        is_deleted=False,
    )

    kwargs = _kwargs(twin_spec)
    kwargs["request"] = _request(**{HEADER_LOCATION: str(LOC_A1)})
    kwargs["isp"] = context(repo)
    kwargs[router_extra.name] = other_rtr
    for dep in twin_spec.deps:
        kwargs[dep] = None

    with pytest.raises(IspRouterNotFoundError):
        await twin(**kwargs)
    assert rec.calls == [], "the handler ran for a router in another location"
