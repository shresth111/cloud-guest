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
    Known to need the work, with the reason it has not had it yet. This list is
    expected to shrink; nothing enforces that it does, because a ratchet on a
    count fails for the wrong reasons. What is enforced is that a domain cannot
    leave the list by being forgotten -- only by moving to another bucket.

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
    "firewall": (
        "Worked example and the shape the rest follow. `DELETE "
        "/firewall-rules/{rule_id}` let a site-A account delete site B's "
        "network security rules."
    ),
}

PENDING: dict[str, str] = {
    "content_filtering": "Same shape as firewall; next in the replication.",
    "dhcp": "Same shape as firewall.",
    "dns": "Same shape as firewall.",
    "port_forwarding": "Same shape as firewall.",
    "qos": "Same shape as firewall.",
    "vlan": "Same shape as firewall.",
    "hotspot": "Same shape as firewall.",
    "isp": "Same shape as firewall.",
    "isp_routing": "Same shape as firewall.",
    "mac_authorization": "Same shape as firewall.",
    "connected_devices": "Same shape as firewall.",
    "device_sync": "Same shape as firewall.",
    "monitored_hardware": "Same shape as firewall.",
    "network_device": "Same shape as firewall.",
    "queue_management": "Same shape as firewall.",
    "captive_portal": (
        "Portal configs are per-location. Needs care: the guest-facing "
        "resolve path must stay unconfined, since a guest has no grants."
    ),
    "campaigns": (
        "Campaigns are per-location. The guest-facing serve/respond routes "
        "must stay unconfined."
    ),
    "voucher": (
        "Batches are per-location. The unauthenticated redeem/validate routes "
        "must stay unconfined."
    ),
    "guest_access": "Access rules are per-location.",
    "guest_teams": "Teams are per-location; the guest join route stays open.",
    "guest": (
        "Guest, GuestSession and login history are per-location, and the admin "
        "reads over them are the PII surface. Larger than the others and worth "
        "doing deliberately rather than in a sweep."
    ),
    "otp": "OtpRequest carries a location; the admin read is `GET /otp/requests`.",
    "support_tickets": "Tickets carry a location.",
    "monitoring": (
        "Alert and PlatformEvent carry a location. Alert reads already scope by "
        "organization; the location half is missing."
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
def test_a_converted_domain_resolves_the_confinement_on_every_route(
    domain: str,
) -> None:
    """`caller_location_scope` defaults to `None` -- unconfined -- all the way
    down, so a route that forgets to resolve it fails **open**. That default is
    deliberate (it keeps system-internal composition working, where there is no
    caller to confine), which makes this test the thing that stops it being a
    hole.
    """
    routes = list(_routes_of_domain(domain))
    assert routes, f"no routes found for {domain!r} -- the module filter is wrong"

    missing = [
        f"{sorted(getattr(r, 'methods', []))} {getattr(r, 'path', '')}"
        for r in routes
        if CallerLocationScope not in _dependency_calls(r.dependant)
    ]

    assert not missing, (
        f"{domain}: these routes do not resolve CallerLocationScope, so the "
        f"service cannot confine them and they fail open:\n"
        + "\n".join(f"  {m}" for m in missing)
    )
