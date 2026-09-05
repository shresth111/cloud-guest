"""Every request parameter that names a tenant must be one the resolver knows.

Sibling of ``test_route_permission_coverage.py``, and built for the same
reason: that test walks the mounted app and fails when a route is not
authorized, and it is what caught ``/me/entitlements`` being added ungated.
This one walks the mounted app and fails when a route names an organization, a
location or a router under a spelling ``_current_scope_context`` does not
recognise.

## Why this test is the point

``_current_scope_context`` used to look for path parameters spelled exactly
``organization_id``/``location_id``/``router_id``. ``GET
/customers/{customer_id}/features`` names an organization -- the value goes
straight to ``LicenseService.get_entitlement_snapshot(organization_id)`` --
but it is not spelled that way, so the resolver saw nothing, the permission
check fell back to the caller's own ``X-Organization-Id``, and any tenant
holding ``billing.read`` could read another tenant's plan, limits and support
tier.

That was found by hand, twice, in two different domains. Finding it a third
time by hand is not a plan. A parameter the resolver does not recognise is a
parameter the permission check silently ignores, and "silently" is the whole
problem: there is no error, no log line, and the endpoint returns a perfectly
well-formed 200 containing someone else's data.

So the rule enforced here is deliberately blunt: **every** ``*_id`` parameter
on **every** mounted route must be classified, either as a scope dimension
(``SCOPE_PARAM_ALIASES``) or as explicitly not one
(``NOT_SCOPE_BEARING_ID_PARAMS``). A new parameter name fails this test until
somebody decides which it is. That is the point -- the failure is the
decision being forced, not a bug being reported.
"""

from __future__ import annotations

import re

import pytest

from app.domains.rbac.scope_params import (
    NOT_SCOPE_BEARING_ID_PARAMS,
    SCOPE_PARAM_ALIASES,
)

_ID_PARAM = re.compile(r"(_id$|^id$)")


def _routes():
    from app.main import create_app

    for route in create_app().routes:
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        yield route, dependant


def _id_params(dependant) -> set[str]:
    return {
        p.name
        for p in list(dependant.path_params) + list(dependant.query_params)
        if _ID_PARAM.search(p.name)
    }


def _dependency_calls(dependant) -> set:
    calls = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        calls |= _dependency_calls(d)
    return calls


# Routes that name a scope id and legitimately carry no permission dependency.
# Each is guest-facing by design: a guest has no dashboard login and no RBAC
# grants, so there is no permission to check. They are listed rather than
# skipped so that a *new* unauthenticated route naming a tenant has to be
# argued for here in writing.
_UNAUTHENTICATED_BY_DESIGN: dict[tuple[str, str], str] = {
    ("GET", "/api/v1/captive-portal/resolve"): (
        "Guest portal render. The guest has not logged in yet -- this is the "
        "screen that lets them."
    ),
    ("GET", "/api/v1/captive-portal/rfc8908"): (
        "RFC 8908 Captive Portal API, read by the device's own OS before any "
        "guest interaction."
    ),
    ("GET", "/api/v1/branding/{organization_id}/logo/public"): (
        "Public branding asset, fetched by the portal page itself."
    ),
    ("GET", "/api/v1/branding/{organization_id}/background-image/public"): (
        "Public branding asset, fetched by the portal page itself."
    ),
    ("GET", "/api/v1/guest/session/active"): (
        "Guest-facing: a connected guest reading their own session state."
    ),
    # -- authorized in the handler rather than by a dependency ---------------
    #
    # These three are checked, just not somewhere this test can see. Listed
    # with the line that does the checking, so the claim is falsifiable rather
    # than a promise.
    ("POST", "/api/v1/organizations/{organization_id}/members/{member_id}/accept"): (
        "Accepting an invitation. An invited-but-not-yet-active member holds "
        "no roles in the organization yet -- that is the point of membership "
        "being distinct from RBAC assignment -- so no `organizations.*` "
        "permission could exist to check. The only requirement is being the "
        "invited user, enforced in `OrganizationService.accept_invite`. See "
        "`organization/router.py`'s own module docstring."
    ),
    **{
        (method, "/api/v1/routers/{router_id}/webfig/{path:path}"): (
            "Reverse proxy to the router's own console. Authorized by a "
            "Redis-bound, router-scoped session token minted by "
            "`POST /routers/{router_id}/webfig-session` (which *is* permission "
            "gated); the handler rejects a token issued for a different router "
            "with a 401. A `RequirePermission` here would check the wrong "
            "thing -- the caller is the browser following the proxy, not the "
            "operator who opened the session."
        )
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE")
    },
    ("", "/api/v1/support-tickets/ws"): (
        "WebSocket. Starlette exposes no `methods`, and the permission check "
        "cannot be a dependency because a failed check must close the socket "
        "with a code rather than raise an HTTP error: it authenticates the "
        "token, then calls `access_validator.has_permission` against "
        "`ScopeContext.for_organization(organization_id)` and closes with "
        "4403 on denial (support_tickets/router.py:401-408)."
    ),
}


def test_every_id_parameter_is_classified() -> None:
    """The test that stops the next ``customer_id``.

    An unclassified ``*_id`` is not necessarily a bug -- most name a rule, a
    campaign, an invoice, entities whose tenancy the service layer resolves.
    But nobody can tell which from the name alone, and guessing wrong is
    exactly how a cross-tenant read shipped. So the classification is
    mandatory and this test is where it gets made.
    """
    unclassified: dict[str, list[str]] = {}
    for route, dependant in _routes():
        for name in _id_params(dependant):
            if name in SCOPE_PARAM_ALIASES or name in NOT_SCOPE_BEARING_ID_PARAMS:
                continue
            unclassified.setdefault(name, []).append(
                f"{sorted(getattr(route, 'methods', []))} {getattr(route, 'path', '')}"
            )

    assert not unclassified, (
        "These request parameters end in `_id` and are not classified:\n"
        + "\n".join(f"  {n}: {rs[0]}" for n, rs in sorted(unclassified.items()))
        + "\n\nDecide for each, in app/domains/rbac/scope_params.py:\n"
        "  * it names an organization, location or router -> add it to "
        "SCOPE_PARAM_ALIASES, so the permission check is evaluated against "
        "the entity being acted on rather than against a header the caller "
        "chose;\n"
        "  * it names anything else -> add it to NOT_SCOPE_BEARING_ID_PARAMS.\n"
        "Getting this wrong is not a visible failure: the endpoint returns a "
        "well-formed 200 containing another tenant's data."
    )


def test_the_alias_table_has_no_stale_entries() -> None:
    """A table that keeps names no route uses stops describing the app, and a
    stale entry is indistinguishable from a live one when you are reading it
    to decide whether a new parameter is covered."""
    live = set()
    for _route, dependant in _routes():
        live |= _id_params(dependant)

    stale = set(SCOPE_PARAM_ALIASES) - live
    assert not stale, (
        f"SCOPE_PARAM_ALIASES names parameters no mounted route has: {sorted(stale)}. "
        "Remove them, or the table stops describing the application."
    )


def test_no_name_is_classified_both_ways() -> None:
    overlap = set(SCOPE_PARAM_ALIASES) & NOT_SCOPE_BEARING_ID_PARAMS
    assert not overlap, f"classified as both scope and not-scope: {sorted(overlap)}"


def test_every_route_naming_a_tenant_is_authorized() -> None:
    """A route that names an organization, location or router must check a
    permission -- or say in writing why it does not."""
    offenders = []
    for route, dependant in _routes():
        names = _id_params(dependant)
        if not (names & set(SCOPE_PARAM_ALIASES)):
            continue
        methods = sorted(getattr(route, "methods", []))
        path = getattr(route, "path", "")
        allowlist_keys = [(m, path) for m in methods] or [("", path)]
        if any(key in _UNAUTHENTICATED_BY_DESIGN for key in allowlist_keys):
            continue
        qualnames = {
            getattr(f, "__qualname__", "") for f in _dependency_calls(dependant)
        }
        if not any(n.startswith("RequirePermission") for n in qualnames):
            offenders.append(f"{methods} {path}")

    assert not offenders, (
        "These routes name a tenant-bearing id but check no permission:\n"
        + "\n".join(f"  {o}" for o in sorted(offenders))
        + "\n\nAdd a RequirePermission dependency, or -- if it is genuinely "
        "guest-facing -- add it to _UNAUTHENTICATED_BY_DESIGN with the reason."
    )


def test_the_unauthenticated_allowlist_has_no_stale_entries() -> None:
    """An allowlist entry for a route that no longer exists is a permission
    exemption sitting in the codebase waiting for a path to be reused."""
    live = set()
    for route, _d in _routes():
        path = getattr(route, "path", "")
        methods = list(getattr(route, "methods", []) or [])
        live |= {(m, path) for m in methods} or {("", path)}
    stale = set(_UNAUTHENTICATED_BY_DESIGN) - live
    assert not stale, f"allowlisted routes that no longer exist: {sorted(stale)}"


@pytest.mark.parametrize("alias", sorted(SCOPE_PARAM_ALIASES))
def test_each_alias_is_resolved_by_the_real_resolver(alias: str) -> None:
    """The table and the resolver must not drift: an alias the resolver does
    not actually read is documentation, not enforcement."""
    import uuid

    from starlette.requests import Request

    from app.domains.rbac.dependencies import _named_scope_ids

    value = uuid.uuid4()
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "path_params": {alias: str(value)},
        }
    )

    resolved = _named_scope_ids(request)

    assert resolved.get(SCOPE_PARAM_ALIASES[alias]) == value
