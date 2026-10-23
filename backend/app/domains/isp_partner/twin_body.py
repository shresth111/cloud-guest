"""Tenant ids inside a twin's REQUEST BODY (the body-id defect class).

A twin resolves the customer and location from the ``X-Isp-*`` headers and
pins path/query extras through ``IspScope``. A request body can still name
ids of its own -- ``router_id`` on ``POST /vlans``, ``organization_id`` on
``POST /guest-access/rules``, ``scope_id``/``target_id`` on a policy
assignment -- and the original handler trusts whatever arrives, relying on its
service's org check. That org check is not enough here:

- it does not know about the ISP workspace's LOCATION, so a router at another
  location of the same customer would be accepted while the screen names this
  one;
- a ``scope_type="global"`` policy assignment is not an org-scoped thing at
  all.

So every id-shaped field of every twin body is declared here, one
``BodyId`` per field, and ``tests/unit/test_isp_partner_twin_body_ids.py``
fails if a body model gains an id-shaped field no row declares.

Modes
-----
``router``           resolve through ``IspScope.assert_router`` and require the
                     same customer AND location as the header target (404).
``force_org``        overwrite with the resolved customer org, whatever was sent.
``force_location``   overwrite with the header location, whatever was sent.
``policy_scope``     the ``scope_type``/``scope_id`` pair of a policy
                     assignment: ``organization`` -> forced to the customer,
                     ``location`` -> must be the header location, ``router`` ->
                     pinned like ``router``; anything else (``global``, ``msp``)
                     is refused (422).
``policy_target``    the ``target_type``/``target_id`` pair: ``none``,
                     ``members`` and ``guest`` pass (a guest id is checked by
                     the service against the customer org); ``user``/``role``
                     are refused -- an ISP customer has no users or roles.
``opaque``           not a tenant id (a VLAN tag number, say). Declared so the
                     coverage test knows it was looked at.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal

from .exceptions import (
    IspBadRequestError,
    IspLocationNotFoundError,
    IspRouterNotFoundError,
)
from .scoping import IspScope

__all__ = ["BodyId", "BodyIdMode", "apply_body_ids", "is_id_shaped"]

BodyIdMode = Literal[
    "router",
    "force_org",
    "force_location",
    "policy_scope",
    "policy_target",
    "opaque",
]


@dataclass(frozen=True)
class BodyId:
    field: str
    mode: BodyIdMode
    #: Name of the body parameter this applies to (``payload`` everywhere today).
    param: str = "payload"


def is_id_shaped(name: str) -> bool:
    return name.endswith(("_id", "_ids"))


def _uuid(value: Any) -> uuid.UUID | None:
    if value is None or value == "":
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise IspBadRequestError("an id in the request body is not valid") from None


async def _pinned_router(isp, raw: Any, org_id, location_id) -> uuid.UUID | None:
    value = _uuid(raw)
    if value is None:
        return None
    router = await IspScope.assert_router(isp, value)
    if org_id is not None and router.organization_id != org_id:
        raise IspRouterNotFoundError()
    if location_id is not None and router.location_id not in (None, location_id):
        raise IspRouterNotFoundError()
    return router.id


def _with(payload: Any, field: str, value: Any) -> Any:
    original = getattr(payload, field, None)
    if isinstance(original, str) and value is not None:
        value = str(value)
    return payload.model_copy(update={field: value})


async def apply_body_ids(
    body_ids: tuple[BodyId, ...],
    kwargs: dict[str, Any],
    isp,
    org_id: uuid.UUID | None,
    location_id: uuid.UUID | None,
) -> None:
    """Check or overwrite every declared body id, in place in ``kwargs``."""
    for spec in body_ids:
        payload = kwargs.get(spec.param)
        if payload is None or spec.mode == "opaque":
            continue
        raw = getattr(payload, spec.field, None)
        if spec.mode == "router":
            pinned = await _pinned_router(isp, raw, org_id, location_id)
            if pinned is not None:
                payload = _with(payload, spec.field, pinned)
        elif spec.mode == "force_org":
            payload = _with(payload, spec.field, org_id)
        elif spec.mode == "force_location":
            payload = _with(payload, spec.field, location_id)
        elif spec.mode == "policy_scope":
            kind = str(getattr(payload, "scope_type", "")).lower()
            if kind == "organization":
                payload = _with(payload, spec.field, org_id)
            elif kind == "location":
                if _uuid(raw) != location_id:
                    raise IspLocationNotFoundError()
            elif kind == "router":
                pinned = await _pinned_router(isp, raw, org_id, location_id)
                if pinned is None:
                    raise IspBadRequestError("scope_id is required for a router")
            else:
                raise IspBadRequestError(
                    "an ISP can assign a policy to this customer, this location "
                    "or one of its routers only"
                )
        elif spec.mode == "policy_target":
            kind = str(getattr(payload, "target_type", "none")).lower()
            if kind in ("user", "role"):
                raise IspBadRequestError(
                    "an ISP customer has no users or roles to target"
                )
        else:  # pragma: no cover - a typo in the table, caught by tests
            raise AssertionError(f"unknown body id mode {spec.mode!r}")
        kwargs[spec.param] = payload
