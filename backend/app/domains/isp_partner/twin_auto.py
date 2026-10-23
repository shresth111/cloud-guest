"""Derive a twin row from the original handler's own signature.

A hand-written row restates what the handler already declares: which
``Depends`` providers it takes, which query parameters, which body. That
restatement is where the integ bugs came from (a parameter not forwarded, a
``Query`` object reaching the service). ``auto_twin`` reads the signature
instead:

=================================  ==========================================
handler parameter                  becomes
=================================  ==========================================
``request``                        (always passed)
``requesting_organization_id`` /   ``inject ("org",)`` -- the RESOLVED customer
``Depends(RequireOrganization)``
``Depends(CurrentLocation)``       ``inject ("location",)``
``Depends(CurrentUser)``           ``inject ("user",)``
any other ``Depends(provider)``    ``deps`` (the twin builds the same provider)
``location_id`` query              ``inject ("location",)`` -- FORCED to the
                                   workspace location, never a request param
``organization_id`` query          ``inject ("org",)``
``router_id`` query                ``Extra isp_router_id`` (IspScope, pinned to
                                   the customer and location)
a ``{name}`` in the path           ``Param(path)``
other query params                 ``Param(query)`` with the ORIGINAL
                                   ``Query(...)`` as default, so FastAPI keeps
                                   its constraints and alias
a pydantic model                   ``Param(body)``
``UploadFile``                     ``Param(body)`` with the original ``File()``
=================================  ==========================================

Anything it cannot classify raises at import time, so a handler that grows a
new kind of parameter fails loudly rather than producing a wrong row. The row
then goes through exactly the same tests as a hand-written one (guards, gate
parity, body ids, seam).
"""

from __future__ import annotations

import inspect
import re
import typing
from typing import Any

from fastapi import UploadFile
from fastapi.params import Depends as DependsParam
from fastapi.params import File as FileParam
from fastapi.params import Query as QueryParam
from pydantic import BaseModel

from .twin_body import BodyId
from .twins import Extra, Param, Target, TwinSpec

__all__ = ["auto_twin"]

_SCOPE_ALIASES = {"organization_id", "customer_id", "location_id", "router_id"}


def _dep_name(dep: Any) -> str:
    call = getattr(dep, "dependency", None)
    return getattr(call, "__name__", "") if call else ""


def _hints(handler) -> dict[str, Any]:
    try:
        return typing.get_type_hints(handler)
    except Exception:  # pragma: no cover - unresolved forward refs
        return {}


def auto_twin(
    method: str,
    path: str,
    handler,
    permission_key: str,
    *,
    target: Target = "header_location",
    resolve_param: str | None = None,
    body_ids: tuple[BodyId, ...] = (),
    redact_fields: tuple[str, ...] = (),
    requires_features: tuple[Any, ...] = (),
    paid_write: bool | None = None,
    status_code: int | None = None,
    rename_path: dict[str, str] | None = None,
    deps_override: dict[str, Any] | None = None,
) -> TwinSpec:
    """One row for ``handler`` at ``/isp`` + ``path`` (``/venue/...``).

    ``rename_path`` maps a handler path param that is a scope alias (say
    ``location_id``) to the exposed ``isp_*`` name used in ``path``.
    ``deps_override`` swaps one of the handler's own providers for an ISP-side
    one (named, so a typo fails at import).
    """
    rename_path = rename_path or {}
    exposed_path_names = set(re.findall(r"{(\w+)}", path))
    hints = _hints(handler)
    params: list[Param] = []
    extras: list[Extra] = []
    deps: dict[str, Any] = {}
    inject: dict[str, tuple[str, ...]] = {}
    for name, p in inspect.signature(handler).parameters.items():
        if name == "request":
            continue
        ann = hints.get(name, p.annotation)
        default = p.default
        if isinstance(default, DependsParam):
            dep = _dep_name(default)
            if dep in ("CurrentOrganization", "RequireOrganization") or (
                name == "requesting_organization_id"
            ):
                inject[name] = ("org",)
            elif dep in ("CurrentLocation", "RequireLocation"):
                inject[name] = ("location",)
            elif dep in ("get_current_user", "CurrentUser"):
                inject[name] = ("user",)
            else:
                deps[name] = default.dependency
            continue
        exposed = next((k for k, v in rename_path.items() if v == name), name)
        if exposed in exposed_path_names:
            params.append(
                Param(exposed, "path", ann, forward=None if exposed == name else name)
            )
            continue
        if isinstance(default, FileParam) or ann is UploadFile:
            params.append(Param(name, "body", UploadFile, default))
            continue
        if isinstance(default, QueryParam) or (
            default is not inspect.Parameter.empty and not _is_model(ann)
        ):
            if name == "location_id":
                inject[name] = ("location",)
            elif name == "organization_id":
                inject[name] = ("org",)
            elif name == "router_id":
                extras.append(Extra("isp_router_id", "query", "router", "router_id"))
            elif name in _SCOPE_ALIASES:  # pragma: no cover - customer_id query
                raise ValueError(f"{handler.__name__}: unhandled scope alias {name}")
            else:
                alias = getattr(default, "alias", None)
                if alias:
                    params.append(Param(alias, "query", ann, default, forward=name))
                else:
                    params.append(Param(name, "query", ann, default))
            continue
        if _is_model(ann):
            params.append(Param(name, "body", ann, default))
            continue
        raise ValueError(
            f"{handler.__module__}.{handler.__name__}: cannot classify "
            f"parameter {name!r} ({ann!r})"
        )
    for name, provider in (deps_override or {}).items():
        if name not in deps:
            raise ValueError(f"{handler.__name__}: no dependency {name!r} to override")
        deps[name] = provider
    return TwinSpec(
        method=method,
        path=path,
        permission_key=permission_key,
        handler=handler,
        target=target,
        resolve_param=resolve_param,
        params=tuple(params),
        extras=tuple(extras),
        deps=deps,
        inject=inject,
        status_code=status_code,
        body_ids=body_ids,
        redact_fields=redact_fields,
        requires_features=requires_features,
        paid_write=paid_write,
    )


def _is_model(ann: Any) -> bool:
    return isinstance(ann, type) and issubclass(ann, BaseModel)
