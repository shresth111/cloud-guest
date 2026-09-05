"""Every domain whose rows carry a location must decide what that means.

The contract this enforces is the one that outlives the fix. The sweep test
(``test_scope_parameter_coverage``) catches routes that *name* a scope id in
their URL. This class is the opposite: routes that name a plain entity id --
``DELETE /firewall-rules/{rule_id}`` -- whose tenant and site are only knowable
once the row is loaded, which happens after ``RequirePermission`` has run. RBAC
cannot pin those from the outside, so the check lives in the service, and the
only thing that stops a service forgetting it is this file.

## Why it is derived from the models rather than from a list

A hand-maintained list of "domains to fix" describes the day it was written.
This starts from ``BaseModel.registry`` -- every mapped class carrying a
``location_id`` column -- so the set of domains that *could* have this defect
is computed from the code. A new domain with a location-bearing model appears
here automatically and fails until somebody classifies it.

Three buckets, and a domain must be in exactly one:

``LOCATION_SCOPED``
    Converted. Every route in the domain must resolve ``CallerLocationScope``,
    because ``caller_location_scope`` defaults to ``None`` (unconfined)
    throughout -- a route that forgets to pass it fails **open**. Fail-open is
    only acceptable when something makes forgetting visible, and this is that
    something.

``PENDING``
    Known to need the work. Each entry records **what was analysed and what
    is not yet settled**, not merely that the domain is on a list -- because
    a list of nine a future reader cannot distinguish from nine that were
    considered and dismissed is how this quietly becomes permanent. An entry
    saying "not yet analysed" is a fine entry; an entry saying nothing is not.

    This list is expected to shrink; nothing enforces that it does, because a
    ratchet on a count fails for the wrong reasons and gets deleted. What is
    enforced is that a domain cannot leave the list by being forgotten -- only
    by moving to another bucket.

    The bar for leaving is: name the entity the routes actually address by id,
    and say why that getter and not another. `voucher` is why. A mechanical
    pass matched its `get_series` and would have confined voucher *series*
    while leaving *batches* -- the entity every route addresses -- wide open,
    with the whole suite green and this contract marking the domain done. A
    hole behind a green tick is worse than an unconverted domain.

``EXEMPT``
    Genuinely does not need it, with the argument written down. An exemption
    without a reason is indistinguishable from an oversight six months later.
"""

from __future__ import annotations

import pytest

from app.domains.rbac.location_scope import CallerLocationScope

# ---------------------------------------------------------------------------
# The three buckets
# ---------------------------------------------------------------------------

LOCATION_SCOPED: dict[str, str] = {
    "guest_teams": (
        "One entity, `GuestTeam`, addressed by `{team_id}` on the detail, "
        "revoke and remove-member routes; `get_team` is the entity getter and "
        "`get_team_summary` composes it. Uses the anonymous-tolerant "
        "dependency because `POST /guest-teams/join` is guest-facing and "
        "shares the provider -- but `join_team` resolves by team *code* off "
        "the repository and never calls `get_team`, so the guest path does "
        "not touch the confined code at all."
    ),
    "support_tickets": (
        "One entity, `SupportTicket`, addressed by `{ticket_id}` on the four "
        "detail/reply routes; `get_ticket` is the only entity getter "
        "(`get_location` is the location lookup protocol). The location lives "
        "on `record.ticket`, not on the `TicketRecord` wrapper. Strict "
        "`CallerLocationScope` is safe here: the `/ws` route authorises "
        "in-handler and never resolves the ticket service."
    ),
    "monitored_hardware": (
        "The hardware inventory and up/down view for a site. Raises its own"
        "NotFound rather than a 403, preserving this domain's existing choice"
        "not to confirm a row exists."
    ),
    "queue_management": (
        "Bandwidth queues shape a site's guest traffic. Same NotFound-not-403"
        "convention as monitored_hardware."
    ),
    "vlan": (
        "VLANs are the guest/office separation itself; a confined account could"
        "reshape another site's segmentation."
    ),
    "connected_devices": (
        "Connected-device rows are the live view of who is on another site's network."
    ),
    "device_sync": (
        "Sync runs read another site's router."
    ),
    "dhcp": (
        "DHCP pools are per-router and per-site; a confined account could"
        "repoint another site's address range."
    ),
    "dns": (
        "DNS records are per-router; a confined account could redirect another"
        "site's name resolution."
    ),
    "hotspot": (
        "Hotspot profiles carry the walled garden a guest sees before login."
    ),
    "isp": (
        "ISP links carry failover configuration for a site's uplinks."
    ),
    "isp_routing": (
        "Routing rules decide which uplink a site's traffic takes."
    ),
    "mac_authorization": (
        "Whitelisted MACs skip the portal entirely at whichever site they name."
    ),
    "network_device": (
        "The device inventory for a site."
    ),
    "port_forwarding": (
        "Port-forward rules expose internal hosts; a confined account could"
        "open a port at another site."
    ),
    "qos": (
        "QoS rules shape another site's traffic, including voice priority."
    ),
    "content_filtering": (
        "Same getter shape as firewall. A site-A account could block or "
        "unblock domains for every other site in the organization."
    ),
    "firewall": (
        "Worked example and the shape the rest follow. `DELETE "
        "/firewall-rules/{rule_id}` let a site-A account delete site B's "
        "network security rules."
    ),
}

PENDING: dict[str, str] = {
    "captive_portal": (
        "NOT YET ANALYSED. `CaptivePortalConfig` is per-location, but the "
        "guest-facing resolve path must stay unconfined and the config is "
        "resolved by org+location rather than by its own id, so the getter "
        "choice is not obvious."
    ),
    "campaigns": (
        "PARTLY ANALYSED. `get_campaign` is the getter the admin routes "
        "address. Unsettled: the three `/portal/campaigns/*` guest routes "
        "reach the same service and must stay unconfined, so this needs "
        "`OptionalCallerLocationScope` plus a decision on serve/respond."
    ),
    "voucher": (
        "ANALYSED, NOT CONVERTED -- and the reason this bar exists. A "
        "mechanical pass matched `get_series` and would have confined voucher "
        "*series* while leaving *batches* open; `get_batch` is what the routes "
        "address. Also has unauthenticated redeem/validate. Convert against "
        "`get_batch`, and decide `get_series`/`get_plan` explicitly."
    ),
    "guest_access": (
        "NOT YET ANALYSED. Two entities -- `GuestAccessRule` and "
        "`DeviceAccessRule` -- so which getters the routes address needs "
        "checking before conversion, per the voucher lesson."
    ),
    "guest": (
        "DELIBERATELY LAST, not unanalysed. `Guest`, `GuestSession` and "
        "`GuestLoginHistory` are all per-location and the admin reads over "
        "them are the PII surface. Some methods must stay unconfined even for "
        "an authenticated caller, so this is the one domain that should not "
        "be batched with anything."
    ),
    "otp": (
        "NOT YET ANALYSED, and the domain where the suite carries the least "
        "information: production runs `LoggingSmsProvider`, so an SMS OTP "
        "request already produces a row and no message. A confinement mistake "
        "here would not fail, it would join an existing silence. Read the "
        "routes rather than trusting the tests."
    ),
    "monitoring": (
        "NOT YET ANALYSED. `Alert` and `PlatformEvent` both carry a location "
        "and two WebSockets reach the service unauthenticated by dependency."
    ),
}

EXEMPT: dict[str, str] = {
    "rbac": (
        "These rows *are* the scope machinery -- UserRole, PermissionOverride, "
        "LocationRole, AuditLogEntry. Confining them by a confinement derived "
        "from them would be circular, and an audit log that hides entries from "
        "the person reading it is worse than no audit log."
    ),
    "router": (
        "Every router route names `router_id` in its own URL, so the permission "
        "check is pinned to the target by `_current_scope_context` rather than "
        "in the service. This is the class the sweep branch closes structurally, "
        "not the class this file is about."
    ),
    "network_diagnostics": (
        "Closed separately on `fix/diagnostics-scope-and-abuse` (1527aec), "
        "which is where this defect was first found live."
    ),
    "provisioning_engine": (
        "Device-fleet orchestration. Its routes name `router_id`, and its jobs "
        "run as the platform with no caller to confine."
    ),
    "router_provisioning": (
        "As `provisioning_engine`: router-named routes and system-run tasks."
    ),
    "analytics": (
        "AnalyticsSnapshot is a precomputed aggregate, and every analytics read "
        "route already carries an explicit `scope=ScopeType.ORGANIZATION` plus "
        "`RequireOrganization`, which a narrower grant cannot satisfy."
    ),
}


def _domains_with_a_location_column() -> set[str]:
    """Every domain owning at least one mapped class with a ``location_id``."""
    import app.main  # noqa: F401  -- importing registers every model
    from app.database.base import BaseModel

    domains = set()
    for mapper in BaseModel.registry.mappers:
        if "location_id" not in {c.key for c in mapper.columns}:
            continue
        parts = mapper.class_.__module__.split(".")
        if len(parts) > 2 and parts[0] == "app" and parts[1] == "domains":
            domains.add(parts[2])
    return domains


def _routes_of_domain(domain: str):
    """Routes whose endpoint is defined in ``app.domains.<domain>``.

    Resolved by module rather than by URL prefix: a domain's paths are not
    always its name (`firewall` serves `/firewall-rules`, `guest` serves
    `/guests` and `/guest-sessions`), and a prefix guess that silently matches
    nothing would make this test pass by covering no routes at all.
    """
    from app.main import create_app

    prefix = f"app.domains.{domain}."
    for route in create_app().routes:
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None:
            continue
        if getattr(endpoint, "__module__", "").startswith(prefix):
            yield route


def _dependency_calls(dependant) -> set:
    calls = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        calls |= _dependency_calls(d)
    return calls


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


def test_every_location_bearing_domain_is_classified() -> None:
    """The test that stops domain 26 skipping this quietly."""
    classified = set(LOCATION_SCOPED) | set(PENDING) | set(EXEMPT)
    unclassified = _domains_with_a_location_column() - classified

    assert not unclassified, (
        "These domains own rows carrying a `location_id` and are in none of "
        f"LOCATION_SCOPED / PENDING / EXEMPT: {sorted(unclassified)}.\n\n"
        "A row with a location can be reached by a caller confined to a "
        "different one. Decide which it is, in this file:\n"
        "  * needs the service-layer check -> PENDING, then do the work;\n"
        "  * already has it -> LOCATION_SCOPED;\n"
        "  * genuinely does not need it -> EXEMPT, with the argument.\n"
        "The failure mode is silent: the endpoint returns a well-formed 200 "
        "for another site's data."
    )


def test_no_domain_is_in_two_buckets() -> None:
    pairs = [
        ("LOCATION_SCOPED", "PENDING", set(LOCATION_SCOPED) & set(PENDING)),
        ("LOCATION_SCOPED", "EXEMPT", set(LOCATION_SCOPED) & set(EXEMPT)),
        ("PENDING", "EXEMPT", set(PENDING) & set(EXEMPT)),
    ]
    for a, b, overlap in pairs:
        assert not overlap, f"in both {a} and {b}: {sorted(overlap)}"


def test_every_bucket_entry_names_a_real_domain() -> None:
    """A stale entry is an exemption sitting in the codebase waiting for a
    domain name to be reused."""
    live = _domains_with_a_location_column()
    stale = (set(LOCATION_SCOPED) | set(PENDING) | set(EXEMPT)) - live
    assert not stale, (
        f"classified domains that own no location-bearing model: {sorted(stale)}"
    )


def test_every_entry_carries_a_reason() -> None:
    for bucket_name, bucket in (
        ("LOCATION_SCOPED", LOCATION_SCOPED),
        ("PENDING", PENDING),
        ("EXEMPT", EXEMPT),
    ):
        for domain, reason in bucket.items():
            assert len(reason.strip()) > 20, (
                f"{bucket_name}[{domain!r}] needs a real reason, not {reason!r}"
            )


@pytest.mark.parametrize("domain", sorted(LOCATION_SCOPED))
def test_a_converted_domains_service_takes_the_confinement(domain: str) -> None:
    """The service must accept the confinement at construction.

    Constructor injection rather than a per-method argument, because a method
    that accepts a security control can forget to use it: a mutator that took
    `caller_location_scope` and did not pass it into the getter produced no
    error, no test failure and no enforcement. With it on the instance there is
    nothing per-method to forget.
    """
    import importlib
    import inspect

    module = importlib.import_module(f"app.domains.{domain}.service")
    services = [
        obj
        for _n, obj in vars(module).items()
        if inspect.isclass(obj)
        and obj.__module__ == module.__name__
        and _n.endswith("Service")
    ]
    assert services, f"no service class found in {domain}"

    accepting = [
        cls
        for cls in services
        if "caller_location_scope" in inspect.signature(cls.__init__).parameters
    ]
    assert accepting, (
        f"{domain}: no service takes `caller_location_scope` at construction, "
        f"so nothing can confine it: {[c.__name__ for c in services]}"
    )


@pytest.mark.parametrize("domain", sorted(LOCATION_SCOPED))
def test_a_converted_domains_provider_supplies_the_confinement(domain: str) -> None:
    """A constructor parameter nothing supplies is unconfined by default -- it
    fails **open**. The DI provider is the single place that must fill it, so
    this is where forgetting becomes visible."""
    import importlib
    import inspect

    from app.domains.rbac.location_scope import (
        CallerLocationScope,
        OptionalCallerLocationScope,
    )

    # Either is acceptable. A domain whose service also backs an
    # unauthenticated route must use the anonymous-tolerant variant, or
    # FastAPI would resolve `CurrentUser` before the handler runs and force
    # authentication on the guest portal. What is *not* acceptable is
    # neither, which leaves every caller silently unconfined.
    accepted = {CallerLocationScope, OptionalCallerLocationScope}

    deps = importlib.import_module(f"app.domains.{domain}.dependencies")
    providers = [
        fn
        for name, fn in vars(deps).items()
        if inspect.isfunction(fn)
        and name.startswith("get_")
        and name.endswith("_service")
    ]
    assert providers, f"no `get_*_service` provider found in {domain}"

    supplying = []
    for fn in providers:
        param = inspect.signature(fn).parameters.get("caller_location_scope")
        if param is not None and getattr(
            param.default, "dependency", None
        ) in accepted:
            supplying.append(fn.__name__)

    assert supplying, (
        f"{domain}: no service provider resolves a location-scope dependency, "
        f"so every caller is unconfined: {[f.__name__ for f in providers]}"
    )


# ---------------------------------------------------------------------------
# Anonymous-therefore-unconfined must never be the whole of a route's defence
# ---------------------------------------------------------------------------
#
# `OptionalCallerLocationScope` resolves to `None` -- unconfined -- when no
# credential is presented, because the services it feeds also back guest
# routes (`/otp/request`, `/vouchers/redeem`, `/captive-portal/resolve`).
#
# That is safe only in combination with authentication. On a route carrying
# `RequirePermission`, omitting the `Authorization` header dead-ends at 401
# long before any service is consulted. On a route relying on service-level
# confinement *alone*, an attacker would shed their confinement simply by not
# authenticating. The safety is a property of the pair, so it is asserted
# here rather than assumed.

# Guest-facing routes that legitimately reach a confinement-dependent service
# without authenticating. Each must be a route where being unconfined is
# correct because the caller is a guest acting on their own session, not a
# staff member reading a tenant's records.
_GUEST_FACING_UNCONFINED: dict[tuple[str, str], str] = {
    ("POST", "/api/v1/guest-teams/join"): (
        "A guest joining a team with a code they were given. They hold no "
        "roles, so there is no confinement to derive, and `join_team` "
        "resolves by team code off the repository rather than through the "
        "confined `get_team` -- so being unconfined here grants nothing."
    ),
}


def test_no_route_relies_on_confinement_without_authentication() -> None:
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.location_scope import (
        CallerLocationScope,
        OptionalCallerLocationScope,
    )
    from app.main import create_app

    confinement_deps = {CallerLocationScope, OptionalCallerLocationScope}
    offenders = []
    for route in create_app().routes:
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        resolved = _dependency_calls(dependant)
        if not (resolved & confinement_deps):
            continue

        names = {getattr(f, "__qualname__", "") for f in resolved}
        authenticated = CurrentUser in resolved or any(
            n.startswith("RequirePermission") for n in names
        )
        if authenticated:
            continue

        path = getattr(route, "path", "")
        methods = list(getattr(route, "methods", []) or [])
        keys = [(m, path) for m in methods] or [("", path)]
        if any(k in _GUEST_FACING_UNCONFINED for k in keys):
            continue
        offenders.append(f"{sorted(methods)} {path}")

    assert not offenders, (
        "These routes reach a location-confined service without requiring "
        "authentication, so omitting the Authorization header makes the "
        "caller unconfined:\n"
        + "\n".join(f"  {o}" for o in sorted(offenders))
        + "\n\nEither require authentication, or -- if the caller is genuinely "
        "a guest acting on their own session -- add it to "
        "_GUEST_FACING_UNCONFINED with the reason."
    )
