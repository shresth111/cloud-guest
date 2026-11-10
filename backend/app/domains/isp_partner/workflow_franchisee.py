"""RAKESH-FS: franchisee logins (founder 2026-11-10, replaces D6 "zones bina
login").

A franchisee is an ordinary ISP staff user of the same ``/partner`` console
with the role ``isp-franchisee`` and one or more rows in
``isp_franchisee_zones``. Everything it can reach is cut down to the ZONE-1
subtrees of those zones, in the backend, once per request
(``apply_franchisee_scope``, called from ``RequireIspPartner``):

* **customers** (and so locations, routers, CPEs, coupon batches, every
  customer-keyed report) = ``confined_customer_ids`` narrowed to the zone
  customers (ZONE-1 ``build_scope`` rule: profile zone in the subtree, or a
  subscriber of theirs is). Never ``None`` (= all): no zones -> nothing.
* **subscribers / invoices**: the ZONE-1 ORM criteria for the union subtree
  (``zones_scope._zone_criteria``), so another zone's subscriber on a shared
  customer is a 404 like any other row it cannot see.
* **zones**: ORM selects of ``isp_zones`` only return its own subtree, so the
  tree, names and totals of other zones are invisible.
* **packages**: when its zones have an ``isp_zone_packages`` allowlist, ORM
  selects of ``isp_packages`` return only those (a disallowed package is a
  404 at onboarding / renew / coupon create).
* **path / query ids**: any id in the URL that is a zone of this ISP outside
  the subtree -> 404 before the handler runs (covers raw-SQL handlers).
* **writes**: a ``before_flush`` guard refuses a subscriber / invoice /
  customer profile that would land in a zone outside the subtree.

``scope_zone_id`` still works inside the subtree (narrows further); a zone
outside it is a 404. The role holds no ``isp_partner.create/manage/assign``,
so it cannot add customers, users (franchisees), ISPs or dashboards.

While ``ISP_WORKFLOW_ENABLED`` or ``ISP_ZONES_ENABLED`` is off a franchisee
gets ``ISP_ROLE_REQUIRED`` (never an unconfined view) and the role cannot be
granted.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy import event, select
from sqlalchemy.orm import Session, with_loader_criteria

from .exceptions import IspBadRequestError, IspRoleRequiredError, IspZoneNotFoundError
from .workflow_config import franchisee_logins_on

FRANCHISEE_SLUG = "isp-franchisee"
_INFO_KEY = "isp_franchisee_scope"


@dataclass(frozen=True)
class FranchiseeScope:
    zone_ids: frozenset[uuid.UUID]
    #: customers whose profile zone is in the subtree
    profile_customer_ids: frozenset[uuid.UUID]
    #: None = every package
    package_ids: frozenset[uuid.UUID] | None


def franchisee_role_definition() -> Any:
    """Appended to ``rbac_roles.ROLES`` (seeded by ``isp_partner.seed``)."""
    from .rbac_roles import IspRoleDefinition, _keys

    return IspRoleDefinition(
        slug=FRANCHISEE_SLUG,
        name="ISP Franchisee",
        description=(
            "Runs the zones the ISP assigns: their routers, subscribers, "
            "renewals and coupons. Cannot add sites, users or other franchisees."
        ),
        permission_keys=_keys(
            isp_partner="read update execute",
            isp_zones="read",
            isp_plans="read",
            isp_coupons="read create export",
            isp_subscribers="read update disconnect kyc",
            isp_billing="read create execute",
            isp_invoices="read create",
            isp_monitor="read",
            isp_support="read create",
            isp_apps="read create update",
            isp_collections="read collect",
            isp_incidents="read",
            isp_referrals="read create",
        ),
    )


def check_role_allowed(slug: str) -> None:
    """``users_service._check_role``: the role cannot be granted while off."""
    if slug == FRANCHISEE_SLUG and not franchisee_logins_on():
        raise IspBadRequestError("Franchisee logins are not switched on")


def current_franchisee_scope(session: Any) -> FranchiseeScope | None:
    info = getattr(session, "info", None)
    return info.get(_INFO_KEY) if info is not None else None


async def franchisee_root_zones(
    session: Any, isp_org_id: uuid.UUID, user_id: uuid.UUID
) -> list[uuid.UUID]:
    from .workflow_models import IspFranchiseeZone

    return list(
        (
            await session.execute(
                select(IspFranchiseeZone.zone_id).where(
                    IspFranchiseeZone.isp_organization_id == isp_org_id,
                    IspFranchiseeZone.user_id == user_id,
                    IspFranchiseeZone.is_deleted.is_(False),
                )
            )
        ).scalars()
    )


async def build_franchisee_scope(
    session: Any, isp_org_id: uuid.UUID, roots: list[uuid.UUID]
) -> tuple[FranchiseeScope, frozenset[uuid.UUID]]:
    """(scope, zone customers) for the union of the roots' subtrees."""
    from .billing_models import IspZone
    from .models import IspCustomerProfile
    from .plans_models import IspSubscriber
    from .workflow_models import IspZonePackage
    from .zones_scope import descendants, parent_map, zone_rows

    parents = parent_map(await zone_rows(session, isp_org_id))
    zone_ids: set[uuid.UUID] = set()
    for r in roots:
        if r in parents:  # a deleted zone simply drops out
            zone_ids |= descendants(parents, r)
    if not zone_ids:
        return FranchiseeScope(frozenset(), frozenset(), None), frozenset()
    profile = frozenset(
        (
            await session.execute(
                select(IspCustomerProfile.customer_organization_id).where(
                    IspCustomerProfile.isp_organization_id == isp_org_id,
                    IspCustomerProfile.zone_id.in_(zone_ids),
                )
            )
        ).scalars()
    )
    via_subs = frozenset(
        (
            await session.execute(
                select(IspSubscriber.customer_organization_id)
                .where(
                    IspSubscriber.isp_organization_id == isp_org_id,
                    IspSubscriber.zone_id.in_(zone_ids),
                    IspSubscriber.is_deleted.is_(False),
                )
                .distinct()
            )
        ).scalars()
    )
    # package allowlist: rows on the assigned zones (or their subtree)
    pkgs = set(
        (
            await session.execute(
                select(IspZonePackage.package_id).where(
                    IspZonePackage.isp_organization_id == isp_org_id,
                    IspZonePackage.zone_id.in_(zone_ids),
                    IspZonePackage.is_deleted.is_(False),
                )
            )
        ).scalars()
    )
    _ = IspZone  # imported for the mapper registry
    return (
        FranchiseeScope(
            frozenset(zone_ids), profile, frozenset(pkgs) if pkgs else None
        ),
        profile | via_subs,
    )


def _ids_in_request(request: Any) -> set[uuid.UUID]:
    out: set[uuid.UUID] = set()
    values: list[Any] = list((getattr(request, "path_params", None) or {}).values())
    qp = getattr(request, "query_params", None)
    if qp is not None:
        values.extend(v for _, v in qp.multi_items())
    for v in values:
        try:
            out.add(uuid.UUID(str(v)))
        except (ValueError, TypeError):
            continue
    return out


async def _guard_request_zone_ids(
    session: Any, isp_org_id: uuid.UUID, allowed: frozenset[uuid.UUID], request: Any
) -> None:
    ids = _ids_in_request(request) - allowed
    if not ids:
        return
    from .billing_models import IspZone

    foreign = (
        await session.execute(
            select(IspZone.id).where(
                IspZone.id.in_(ids), IspZone.isp_organization_id == isp_org_id
            )
        )
    ).first()
    if foreign is not None:
        raise IspZoneNotFoundError()


async def apply_franchisee_scope(ctx: Any, request: Any) -> Any:
    """Identity for every role but ``isp-franchisee``."""
    if getattr(ctx, "role_slug", None) != FRANCHISEE_SLUG:
        return ctx
    if not franchisee_logins_on():
        raise IspRoleRequiredError()
    session = getattr(ctx.repository, "session", None)
    if session is None:  # pragma: no cover - every request has one
        raise IspRoleRequiredError()
    from .zones_scope import _INFO_KEY as ZONE_KEY
    from .zones_scope import NO_MATCH, ZoneScope, current_scope, narrow

    requested = current_scope(session)  # set by apply_zone_scope
    session.info.pop(ZONE_KEY, None)  # build over the whole ISP first
    roots = await franchisee_root_zones(session, ctx.isp_org_id, ctx.user_id)
    scope, customers = await build_franchisee_scope(session, ctx.isp_org_id, roots)
    await _guard_request_zone_ids(session, ctx.isp_org_id, scope.zone_ids, request)

    confined = narrow(ctx.confined_customer_ids, customers)
    if requested is not None:
        if not requested.zone_ids <= scope.zone_ids:
            raise IspZoneNotFoundError()
        zone_scope = requested  # ctx is already narrowed to it
    else:
        zone_scope = ZoneScope(
            zone_id=roots[0] if roots else NO_MATCH,
            zone_ids=scope.zone_ids or frozenset({NO_MATCH}),
            profile_customer_ids=scope.profile_customer_ids,
        )
    session.info[ZONE_KEY] = zone_scope
    session.info[_INFO_KEY] = scope
    return replace(ctx, confined_customer_ids=confined, _child_ids=None)


# --------------------------------------------------------------------------
# listeners (no-ops unless the request is a franchisee's)
# --------------------------------------------------------------------------


@event.listens_for(Session, "do_orm_execute")
def _franchisee_criteria(state: Any) -> None:
    scope: FranchiseeScope | None = state.session.info.get(_INFO_KEY)
    if scope is None:
        return
    if not state.is_select or state.is_column_load or state.is_relationship_load:
        return
    from .billing_models import IspZone
    from .plans_models import IspPackage
    from .zones_scope import NO_MATCH

    zone_ids = scope.zone_ids or frozenset({NO_MATCH})
    opts = [
        with_loader_criteria(IspZone, IspZone.id.in_(zone_ids), include_aliases=True)
    ]
    if scope.package_ids is not None:
        pkgs = scope.package_ids
        opts.append(
            with_loader_criteria(
                IspPackage, IspPackage.id.in_(pkgs), include_aliases=True
            )
        )
    state.statement = state.statement.options(*opts)


def check_write(scope: FranchiseeScope, obj: Any) -> None:
    """Raise when ``obj`` would land outside the franchisee's zones."""
    from .billing_models import IspInvoice
    from .models import IspCustomerProfile
    from .plans_models import IspSubscriber

    if isinstance(obj, IspSubscriber | IspInvoice):
        zid = obj.zone_id
        if zid is not None:
            if zid not in scope.zone_ids:
                raise IspZoneNotFoundError()
        elif obj.customer_organization_id not in scope.profile_customer_ids:
            # no zone of its own and its customer's profile zone is not ours:
            # it would be invisible to us and belong to someone else's zone
            raise IspZoneNotFoundError()
    elif isinstance(obj, IspCustomerProfile):
        if obj.zone_id is None or obj.zone_id not in scope.zone_ids:
            raise IspZoneNotFoundError()


@event.listens_for(Session, "before_flush")
def _franchisee_write_guard(session: Any, _ctx: Any, _instances: Any) -> None:
    scope: FranchiseeScope | None = session.info.get(_INFO_KEY)
    if scope is None:
        return
    from .billing_models import IspInvoice
    from .models import IspCustomerProfile
    from .plans_models import IspSubscriber

    watched = (IspSubscriber, IspInvoice, IspCustomerProfile)
    for obj in list(session.new) + list(session.dirty):
        if isinstance(obj, watched):
            if obj in session.dirty and not session.is_modified(obj):
                continue
            check_write(scope, obj)


__all__ = [
    "FRANCHISEE_SLUG",
    "FranchiseeScope",
    "apply_franchisee_scope",
    "build_franchisee_scope",
    "check_role_allowed",
    "check_write",
    "current_franchisee_scope",
    "franchisee_role_definition",
    "franchisee_root_zones",
]
