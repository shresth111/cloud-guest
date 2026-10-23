"""The declarative ISP twin layer.

WHY THIS EXISTS
---------------
An ISP user holds ``isp_*`` keys on the ISP organization, never the customer's
own keys: ``dhcp.read``, ``firewall.read``, ``captive_portal.read`` and so on
belong to roles on the *customer* org, which an ISP user deliberately does not
hold. So an ``/isp`` route cannot simply forward to a customer endpoint -- its
own ``RequirePermission`` would 403 before the service is reached.

The pattern that resolves this is the **twin**: an ``/isp`` route that runs
``isp_guards(<isp key>)``, resolves the target row through
:class:`~app.domains.isp_partner.scoping.IspScope`, and then calls the ORIGINAL
customer-facing handler **function directly** with
``requesting_organization_id=<the customer org>``. The original's route-level
dependency does not re-run (we never went through its route), while its service
layer keeps every tenant check it already had. That is why a twin's response
body is the original's byte for byte, and why ``test_isp_partner_twins.py``
asserts exactly that.

Eleven twins were hand-written that way (``router.py`` §4.6 and §4.7). Each one
is a near-copy of its neighbours: same guard decorator, same
``IspScope.assert_*``, same call, differing only in the handler, the resolved
target and which parameters are forwarded. Hand-writing them does not scale to
the full customer surface, and the copies drift.

This module replaces the copies with a table. One row per endpoint: the method,
the ``/isp`` path, the permission key, the original handler, how to resolve the
target, and how each of the handler's parameters is supplied. ``build_twin``
turns a row into a real route function.

FASTAPI AND GENERATED SIGNATURES
--------------------------------
FastAPI derives dependency injection, path/query/body parsing and the OpenAPI
schema from ``inspect.signature(func)``. A closure over a table row has the
wrong signature -- everything would arrive as ``*args``/``**kwargs`` and no
parameter would be documented or validated. So ``build_twin`` assembles an
explicit ``inspect.Signature`` from the spec and assigns it to the generated
function's ``__signature__``. FastAPI then sees exactly the parameters the row
declares: path params, query params, one optional body model, and the
``Depends(...)`` providers -- and nothing else.

Everything the function actually needs beyond that (the ``Request``, the
``IspContext``, the resolved target) is injected through the same signature, so
the body stays a few lines.

INVARIANTS (checked by ``tests/unit/test_isp_partner_guards.py``)
-----------------------------------------------------------------
- the route is mounted with ``dependencies=isp_guards(<key>)``, which is the
  four guards in contract order, with the permission pinned to ORGANIZATION;
- no exposed parameter is named ``organization_id`` / ``customer_id`` /
  ``location_id`` / ``router_id`` -- those are RBAC scope aliases. The twin's
  own ids are ``isp_*``, and the *customer's* ids only ever reach the original
  handler as forwarded arguments, never as request parameters;
- (ADDENDUM_04 §1, ``test_isp_partner_twin_gates.py``) each row declares the
  same ``RequireFeature`` keys and ``_PAID_WRITES`` licence gate as its
  original route, and ``build_twin`` evaluates them against the CUSTOMER org;
- the endpoint function's ``__module__`` is this module, so the guard test's
  discovery (which keys off the module, not the path) sees it.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request

from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import (
    IspCustomerNotFoundError,
    IspLocationNotFoundError,
    IspRouterNotFoundError,
)
from .scoping import IspScope
from .twin_body import BodyId, apply_body_ids
from .twin_gates import (
    GATE_KWARG,
    enforce_customer_gates,
    get_twin_entitlement_checker,
    is_write,
)
from .twin_headers import HEADER_CUSTOMER, HEADER_LOCATION
from .twin_privacy import force_masking, redact

__all__ = [
    "Extra",
    "Param",
    "Target",
    "TwinSpec",
    "build_twin",
    "mount_twins",
]

#: How a twin resolves the row the caller named.
#:
#: - ``customer``/``location``/``router``/``portal_config``: the id arrives as
#:   the path parameter named in ``resolve_param`` and is checked through the
#:   matching ``IspScope.assert_*``.
#: - ``header_location``/``header_customer``: the id arrives in the
#:   ``X-Isp-Location-Id`` / ``X-Isp-Customer-Id`` header instead. The venue
#:   workspace pages send it for every call, which is what lets one generic
#:   twin serve a whole feature's endpoint set without a path id in each.
#: - ``none``: nothing to resolve (the original handler needs no org).
Target = Literal[
    "customer",
    "location",
    "router",
    "portal_config",
    "header_location",
    "header_customer",
    "none",
]

ParamSource = Literal["path", "query", "body"]


@dataclass(frozen=True)
class Param:
    """One parameter the twin exposes to the client.

    ``forward`` is the name the ORIGINAL handler uses for it, when that
    differs from the exposed name (``isp_location_id`` on the wire, ``id`` in
    the handler, say). ``None`` means "same name".
    """

    name: str
    source: ParamSource
    annotation: Any
    default: Any = inspect.Parameter.empty
    forward: str | None = None

    @property
    def required(self) -> bool:
        return self.default is inspect.Parameter.empty


@dataclass(frozen=True)
class Extra:
    """A second id a twin accepts, resolved alongside the primary target.

    Needed wherever a customer endpoint is scoped by a router rather than (or
    as well as) a location: ``GET /dhcp-pools?router_id=...``,
    ``GET /dhcp-pools/routers/{router_id}/leases``. The exposed name is always
    the ``isp_``-prefixed one -- ``router_id`` is a scope alias and
    ``test_isp_partner_guards.py`` rejects it as a parameter name -- and
    ``forward`` is the name the original handler uses.

    A path extra needs no client-side help: the template's parameter NAME never
    appears on the wire, so the frontend shim only rewrites the prefix. A query
    extra does: the customer page sends ``router_id=...``, so the shim renames
    that key to ``isp_router_id`` on venue requests.
    """

    name: str
    source: ParamSource
    target: Target
    forward: str
    annotation: Any = uuid.UUID
    required: bool = False
    #: Attribute of the resolved row to forward. ``id`` for every twin today;
    #: ``location_id`` would be the other candidate if a handler ever needs it.
    attr: str = "id"


@dataclass(frozen=True)
class TwinSpec:
    """One row of the twin table.

    ``handler`` is the original customer-facing function. ``deps`` maps the
    handler's dependency keyword to the provider that supplies it, e.g.
    ``{"service": get_dhcp_service}`` -- the twin builds its own ``Depends``
    because the original's route dependencies never run.

    ``inject`` maps the handler's other keywords to the request-derived values
    the twin computes:

    - ``("target", attr)``   -- an attribute of the row ``IspScope`` resolved;
    - ``("org",)``           -- the target customer's organization id, i.e. the
      ``requesting_organization_id`` every twin must pass;
    - ``("location",)``      -- the resolved location id;
    - ``("router",)``        -- the resolved router id;
    - ``("user",)``          -- the authenticated ``AuthUser``;
    - ``("param", name)``    -- a value from one of the twin's own ``params``.
    """

    method: str
    path: str
    permission_key: str
    handler: Callable[..., Any]
    target: Target = "none"
    resolve_param: str | None = None
    params: tuple[Param, ...] = ()
    extras: tuple[Extra, ...] = ()
    deps: dict[str, Callable[..., Any]] = field(default_factory=dict)
    inject: dict[str, tuple[str, ...]] = field(default_factory=dict)
    status_code: int | None = None
    #: ADDENDUM_04 §1. Every ``RequireFeature(<key>)`` the ORIGINAL route
    #: carries, evaluated against the resolved CUSTOMER org (402
    #: ``feature_not_entitled``). ``test_isp_partner_twin_gates.py`` asserts
    #: this equals the original route's set.
    requires_features: tuple[Any, ...] = ()
    #: ``RequireActiveLicenseForWrites`` (the ``_PAID_WRITES`` include) against
    #: the CUSTOMER org. ``None`` = the default: on for every state-changing
    #: method (fail closed); set ``False`` explicitly only where the original
    #: router is deliberately ungated (e.g. ``voucher_router``).
    paid_write: bool | None = None
    #: Tenant ids inside the request body, each checked or overwritten
    #: against the resolved target (see ``twin_body``).
    body_ids: tuple[BodyId, ...] = ()
    #: F2 (masked by default, see ``twin_privacy``): response keys the
    #: original returns as a plain, unmasked ``str`` identifier.
    redact_fields: tuple[str, ...] = ()

    @property
    def effective_paid_write(self) -> bool:
        """Whether the lapsed-licence write check applies to this row."""
        if not is_write(self.method):
            return False
        return True if self.paid_write is None else self.paid_write

    @property
    def gated(self) -> bool:
        return bool(self.requires_features) or self.effective_paid_write

    @property
    def name(self) -> str:
        return f"{self.method.lower()}_{self.path.strip('/').replace('/', '_')}"


def _scope_header(request: Request, header: str) -> uuid.UUID:
    raw = request.headers.get(header)
    if not raw:
        from .exceptions import IspBadRequestError

        raise IspBadRequestError(f"{header} is required")
    try:
        return uuid.UUID(raw)
    except ValueError:
        from .exceptions import IspBadRequestError

        raise IspBadRequestError(f"{header} is not a valid id") from None


async def _assert_row(isp: IspContext, target: Target, value: uuid.UUID):
    """Resolve one id through the shared ``IspScope`` (404 on any miss)."""
    if target == "router":
        return await IspScope.assert_router(isp, value)
    if target == "location":
        return await IspScope.assert_location(isp, value)
    if target == "customer":
        return await IspScope.assert_customer(isp, value)
    if target == "portal_config":
        return await IspScope.assert_portal_config(isp, value)
    raise AssertionError(f"{target!r} is not a resolvable row")


def _not_found_for(target: Target) -> Exception:
    """The 404 the matching ``IspScope`` assert would have raised."""
    if target == "router":
        return IspRouterNotFoundError()
    if target == "location":
        return IspLocationNotFoundError()
    return IspCustomerNotFoundError()


async def _resolve(
    spec: TwinSpec, isp: IspContext, request: Request, args: dict[str, Any]
):
    """Resolve the row the caller named, via the shared ``IspScope``.

    Returns ``(target, org_id, location_id, router_id)``.
    """
    if spec.target == "none":
        return None, None, None, None

    if spec.target == "header_customer":
        customer = await IspScope.assert_customer(
            isp, _scope_header(request, HEADER_CUSTOMER)
        )
        return customer, customer.id, None, None

    if spec.target == "header_location":
        location = await IspScope.assert_location(
            isp, _scope_header(request, HEADER_LOCATION)
        )
        return location, location.organization_id, location.id, None

    assert spec.resolve_param, "a resolving twin needs resolve_param"
    raw = args[spec.resolve_param]

    if spec.target == "customer":
        customer = await IspScope.assert_customer(isp, raw)
        return customer, customer.id, None, None
    if spec.target == "location":
        location = await IspScope.assert_location(isp, raw)
        return location, location.organization_id, location.id, None
    if spec.target == "router":
        router = await IspScope.assert_router(isp, raw)
        return router, router.organization_id, router.location_id, router.id
    if spec.target == "portal_config":
        config = await IspScope.assert_portal_config(isp, raw)
        return config, config.organization_id, None, None

    raise AssertionError(f"unknown twin target {spec.target!r}")


def _value(
    spec: TwinSpec,
    resolved: tuple[Any, Any, Any, Any],
    args: dict[str, Any],
    user: Any,
) -> dict[str, Any]:
    """Turn ``inject`` into the handler's keyword arguments."""
    target, org_id, location_id, router_id = resolved
    out: dict[str, Any] = {}
    for kwarg, source in spec.inject.items():
        kind = source[0]
        if kind == "target":
            out[kwarg] = getattr(target, source[1])
        elif kind == "org":
            out[kwarg] = org_id
        elif kind == "location":
            out[kwarg] = location_id
        elif kind == "router":
            out[kwarg] = router_id
        elif kind == "user":
            out[kwarg] = user
        elif kind == "const":
            out[kwarg] = source[1]
        elif kind == "param":
            out[kwarg] = args[source[1]]
        else:  # pragma: no cover - a typo in the table, caught by tests
            raise AssertionError(f"unknown twin inject {kind!r}")
    return out


def build_twin(spec: TwinSpec) -> Callable[..., Any]:
    """Build the real route function for one table row."""
    needs_user = any(source[0] == "user" for source in spec.inject.values())
    if spec.gated and spec.target == "none":
        # A gate needs a customer org to check; a target-less row has none.
        raise ValueError(f"{spec.name}: a gated twin must resolve a customer")

    async def twin(**kwargs: Any) -> Any:
        request: Request = kwargs["request"]
        isp: IspContext = kwargs["isp"]
        args = {p.name: kwargs[p.name] for p in spec.params}
        resolved = await _resolve(spec, isp, request, args)
        if spec.body_ids:
            await apply_body_ids(spec.body_ids, args, isp, resolved[1], resolved[2])
        if spec.gated:
            # ADDENDUM_04 §1: the original route's feature/licence gates, run
            # against the CUSTOMER org (resolved[1]), never the ISP's header org.
            await enforce_customer_gates(
                kwargs.get(GATE_KWARG),
                resolved[1],
                method=spec.method,
                paid_write=spec.effective_paid_write,
                features=spec.requires_features,
            )
        kwargs_for_handler = _value(spec, resolved, args, kwargs.get("_actor"))
        # Every DECLARED parameter reaches the handler, under the name the
        # handler uses -- unless an ``inject`` entry already renamed it (a param
        # consumed as ``("param", name)`` arrives under the inject key instead).
        #
        # This is not a convenience. The original handlers declare their query
        # parameters with FastAPI defaults (`page: int = Query(default=1)`), and
        # those defaults are `Query` OBJECTS until FastAPI resolves them through
        # its own signature -- which never happens for a twin, because the twin
        # calls the handler directly. A parameter the twin parsed but did not
        # forward therefore falls back to a raw `Query` instance inside the
        # service, which is a 500 (`TypeError: '>' not supported between
        # instances of 'int' and 'Query'` inside PageParams), not a sensible
        # error -- found on the test box, not by the contract test.
        renamed = {src[1] for src in spec.inject.values() if src[0] == "param"}
        for param in spec.params:
            if param.name in renamed:
                continue
            kwargs_for_handler[param.forward or param.name] = args[param.name]
        # Extra ids: resolved through the same IspScope and pinned to the same
        # customer AND the same location as the primary target. An ISP manages
        # each location's routers separately, so a router belonging to another
        # location of the same customer is out of scope for this workspace and
        # is refused here, before the handler runs.
        for extra in spec.extras:
            value = kwargs.get(extra.name)
            if value is None:
                if extra.required:  # pragma: no cover - FastAPI enforces it
                    raise AssertionError(f"{extra.name} is required")
                kwargs_for_handler[extra.forward] = None
                continue
            row = await _assert_row(isp, extra.target, value)
            if (
                resolved[1] is not None
                and getattr(row, "organization_id", None) != resolved[1]
            ):
                raise _not_found_for(extra.target)
            row_location = getattr(row, "location_id", None)
            if (
                resolved[2] is not None
                and row_location is not None
                and row_location != resolved[2]
            ):
                raise _not_found_for(extra.target)
            kwargs_for_handler[extra.forward] = getattr(row, extra.attr)
        # Dependency providers the original route declared.
        for kwarg in spec.deps:
            kwargs_for_handler[kwarg] = kwargs[kwarg]
        force_masking()
        result = await spec.handler(request, **kwargs_for_handler)
        return redact(result, spec.redact_fields)

    # -- the signature FastAPI actually reads -------------------------------
    parameters: list[inspect.Parameter] = [
        inspect.Parameter(
            "request", inspect.Parameter.KEYWORD_ONLY, annotation=Request
        ),
        inspect.Parameter(
            "isp",
            inspect.Parameter.KEYWORD_ONLY,
            annotation=IspContext,
            default=Depends(RequireIspPartner),
        ),
    ]
    for param in spec.params:
        parameters.append(
            inspect.Parameter(
                param.name,
                inspect.Parameter.KEYWORD_ONLY,
                annotation=param.annotation,
                default=param.default,
            )
        )
    for extra in spec.extras:
        if extra.source == "path":
            parameters.append(
                inspect.Parameter(
                    extra.name,
                    inspect.Parameter.KEYWORD_ONLY,
                    annotation=extra.annotation,
                )
            )
        else:
            parameters.append(
                inspect.Parameter(
                    extra.name,
                    inspect.Parameter.KEYWORD_ONLY,
                    annotation=extra.annotation | None,
                    default=None,
                )
            )
    for kwarg, provider in spec.deps.items():
        parameters.append(
            inspect.Parameter(
                kwarg,
                inspect.Parameter.KEYWORD_ONLY,
                annotation=inspect.Parameter.empty,
                default=Depends(provider),
            )
        )
    if spec.gated:
        parameters.append(
            inspect.Parameter(
                GATE_KWARG,
                inspect.Parameter.KEYWORD_ONLY,
                annotation=inspect.Parameter.empty,
                default=Depends(get_twin_entitlement_checker),
            )
        )
    if needs_user:
        from app.domains.rbac.dependencies import CurrentUser

        parameters.append(
            inspect.Parameter(
                "_actor",
                inspect.Parameter.KEYWORD_ONLY,
                annotation=inspect.Parameter.empty,
                default=Depends(CurrentUser),
            )
        )

    twin.__signature__ = inspect.Signature(parameters)  # type: ignore[attr-defined]
    twin.__name__ = spec.name
    twin.__qualname__ = spec.name
    return twin


def mount_twins(router: APIRouter, specs: tuple[TwinSpec, ...]) -> None:
    """Register every row on ``router`` with the four-guard stack."""
    for spec in specs:
        route_kwargs: dict[str, Any] = {
            "dependencies": isp_guards(spec.permission_key),
            "name": spec.name,
        }
        if spec.status_code is not None:
            route_kwargs["status_code"] = spec.status_code
        router.add_api_route(
            spec.path,
            build_twin(spec),
            methods=[spec.method],
            **route_kwargs,
        )
