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

    Two things must be established before a domain leaves this bucket.

    **1. Which entity the routes actually address by id, and why that getter
    and not another.** `voucher` is why. A mechanical pass matched its
    `get_series` and would have confined voucher *series* while leaving
    *batches* -- the entity every route addresses -- wide open, with the whole
    suite green and this contract marking the domain done. A hole behind a
    green tick is worse than an unconverted domain. Where a domain has several
    entities, enforce all of them or say which are deliberately left alone:
    `guest_access` has two and enforces both.

    **2. What composes this service -- not only what routes it serves.** The
    hazard travels through composition. `queue_management` and
    `mac_authorization` have no guest-facing routes of their own; both are
    reached as hooks from `get_guest_service`. Converting them with the strict
    `CallerLocationScope` -- which depends on `CurrentUser` -- made FastAPI
    resolve `CurrentUser` before every route that reaches the guest service,
    and fifteen routes silently began requiring authentication: every guest
    login method, both router-agent endpoints, and `POST /radius/authorize`,
    which authenticates by NAS shared secret and is the path every guest's
    traffic authorises through. It would have 401'd, at every venue at once.
    Nothing in a per-domain reading of either service would have shown it.

    So: `grep` for the service class and its `get_*_service` provider across
    `app/domains/*/dependencies.py` before converting. If anything composes it
    into a guest-serving domain, it needs `OptionalCallerLocationScope`.

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
    "guest": (
        "The PII surface, done last and alone. THREE getters across TWO "
        "service classes: `_require_guest` (the chokepoint all nine "
        "guest-by-id operations funnel through -- block, unblock, reconnect, "
        "read), `get_session` (six `{session_id}` routes including terminate "
        "and disconnect), both on `GuestService`; and `get_nas_client` on "
        "`RadiusService`, a separate class with its own provider, which would "
        "have been a partial conversion if left out since `RadiusNasClient` "
        "carries a location too. Login is untouched: it goes through "
        "`get_or_create_guest`, never `_require_guest`. Anonymous-tolerant, "
        "necessarily -- this service backs every guest login route and is "
        "composed into eleven other domains."
    ),
    "network_integration": (
        "TWO location-bearing models, and the by-id surface is a single "
        "chokepoint. `NetworkIntegration` carries a nullable `location_id` "
        "and is reached by `{integration_id}` on fifteen routes; every one "
        "of them funnels through "
        "`NetworkIntegrationService._load_owned_integration`, which does the "
        "organization comparison AND `enforce_entity_location` in the same "
        "place, so a new endpoint cannot reach a row without both. "
        "`NetworkIntegrationAuthorization` also carries a `location_id` but "
        "has no by-id route at all -- it is written by the portal path and "
        "read only as a count, so there is no getter to confine. "
        "`find_integration_for_router` is the one read that does not go "
        "through `_load_owned_integration`, and it is not a route: it "
        "serves `readiness.NetworkIntegrationLookupProtocol`, keyed by "
        "ROUTER id, and that router has already been resolved org-scoped "
        "by the caller. Adding an organization parameter there that was "
        "compared against the caller's header rather than the router's "
        "owner would BE the path-id defect, not a guard against it. "
        "Anonymous-tolerant, necessarily: this service also backs the "
        "public `POST /network-integrations/portal/authorize`, and the "
        "strict dependency would drag `CurrentUser` in and 401 every guest "
        "joining WiFi. That route does not use the confinement at all -- it "
        "proves an ACTIVE GuestSession whose own organization AND location "
        "match the body, and resolves the integration from the session's "
        "venue rather than the caller's."
    ),
    "monitoring": (
        "Seven service classes; only one owns a location-bearing row reached "
        "by id. `Alert` via `AlertService.get_alert` -- whose docstring "
        "already argues the organization half of exactly this case -- so the "
        "location check sits beside it. `Incident` has no `location_id` "
        "column, so `IncidentService.get_incident` is deliberately left "
        "alone; `PlatformEvent` carries one but is not reached by id. "
        "Anonymous-tolerant: `MonitoringService` is composed into "
        "`get_guest_service` and the domain serves two WebSockets."
    ),
    "captive_portal": (
        "`CaptivePortalConfig` via `get_config`, the chokepoint every "
        "`{config_id}` route funnels through (`_enforce_tenant_scope` is the "
        "organization half of the same check). The guest-facing "
        "`resolve_portal_config` deliberately does NOT come through here -- "
        "it resolves by organization+location, so the portal render a guest "
        "sees is untouched. Anonymous-tolerant anyway: `/captive-portal/"
        "resolve` is unauthenticated and the service is "
        "composed into `get_guest_service`."
    ),
    "voucher": (
        "THREE entities addressed by id, and the answer the mechanical pass "
        "got wrong. `VoucherBatch` via `get_batch` (nine routes -- approve, "
        "revoke, export, email, stats, vouchers) and `VoucherSeries` via "
        "`get_series` both carry a location and are both enforced. "
        "`VoucherPlan` has no `location_id` column at all, so there is "
        "nothing to compare and `get_plan` is deliberately left alone. The "
        "transformer had matched `get_series` only, which would have left "
        "every batch route open. Anonymous-tolerant: `/vouchers/redeem` and "
        "`/validate` are unauthenticated, and the service is composed into "
        "`get_guest_service`."
    ),
    "campaigns": (
        "One getter covers the whole surface. `get_campaign` handles "
        "`{campaign_id}` directly, and the sub-entity routes -- "
        "`/questions/{question_id}` and `/assets/{asset_id}` -- fetch their "
        "row and then call `get_campaign` to authorise, so they inherit the "
        "check without touching them. That inheritance is only automatic "
        "because the confinement lives on the instance. Anonymous-tolerant: "
        "the three `/portal/campaigns/*` routes are guest-facing."
    ),
    "guest_access": (
        "TWO entities, both addressed by id and both enforced: "
        "`GuestAccessRule` via `get_guest_rule` (`/rules/{rule_id}`) and "
        "`DeviceAccessRule` via `get_device_rule` "
        "(`/device-rules/{rule_id}`). Confining one and not the other would "
        "have been the `voucher` mistake. Uses the anonymous-tolerant "
        "dependency because this service is composed into `get_guest_service` "
        "as `access_control_hook`, so the strict one would have 401'd guest "
        "login -- the composition hazard, not a route in this domain."
    ),
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
    "device_sync": ("Sync runs read another site's router."),
    "dhcp": (
        "DHCP pools are per-router and per-site; a confined account could"
        "repoint another site's address range."
    ),
    "dns": (
        "DNS records are per-router; a confined account could redirect another"
        "site's name resolution."
    ),
    "hotspot": ("Hotspot profiles carry the walled garden a guest sees before login."),
    "isp": ("ISP links carry failover configuration for a site's uplinks."),
    "isp_routing": ("Routing rules decide which uplink a site's traffic takes."),
    "mac_authorization": (
        "Whitelisted MACs skip the portal entirely at whichever site they name."
    ),
    "network_device": ("The device inventory for a site."),
    "port_forwarding": (
        "Port-forward rules expose internal hosts; a confined account could"
        "open a port at another site."
    ),
    "qos": ("QoS rules shape another site's traffic, including voice priority."),
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

PENDING: dict[str, str] = {}

EXEMPT: dict[str, str] = {
    "otp": (
        "Exempt from *this* class, not from scrutiny. `OtpRequest` carries a "
        "location, but the domain has **no by-id route at all** -- only "
        "`/request`, `/verify` and the admin list `/requests`. There is no "
        "'row reached by its own id' surface for a service-layer getter to "
        "confine. Its one location-bearing surface is "
        "`GET /otp/requests?location_id=`, a query *filter*, which belongs to "
        "the other class: a route naming a scope id whose permission check "
        "must be pinned to it. That is what `fix/scope-guard-sweep` closes by "
        "making `_current_scope_context` read query parameters. "
        "CAVEAT: until that branch lands, this filter IS reachable across "
        "sites -- exempt here means 'wrong tool', not 'no problem'. Read "
        "carefully rather than trusting the suite: production runs "
        "`LoggingSmsProvider`, so an SMS OTP request already produces a row "
        "and no message, and a break here would join an existing silence."
    ),
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
    assert (
        not stale
    ), f"classified domains that own no location-bearing model: {sorted(stale)}"


def test_every_entry_carries_a_reason() -> None:
    for bucket_name, bucket in (
        ("LOCATION_SCOPED", LOCATION_SCOPED),
        ("PENDING", PENDING),
        ("EXEMPT", EXEMPT),
    ):
        for domain, reason in bucket.items():
            assert (
                len(reason.strip()) > 20
            ), f"{bucket_name}[{domain!r}] needs a real reason, not {reason!r}"


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
        if param is not None and getattr(param.default, "dependency", None) in accepted:
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
    ("GET", "/api/v1/captive-portal/resolve"): (
        "The guest portal render. Pre-login by definition; the caller holds no "
        "roles, and `resolve_portal_config` resolves by organization+location "
        "rather than through the confined `get_config`."
    ),
    ("POST", "/api/v1/network-integrations/portal/authorize"): (
        "Captive-portal network enforcement for a guest who has just been "
        "issued a GuestSession by app.domains.guest. They hold no roles, so "
        "there is no confinement to derive, and the handler does not use "
        "one: it resolves the integration by (organization, location) taken "
        "from the SESSION -- not from the caller and not from the body -- "
        "via `find_enabled_integration_for_location`, never through the "
        "confined `_load_owned_integration`. Unconfined is correct here "
        "because the caller is a guest acting on their own session."
    ),
    ("POST", "/api/v1/vouchers/redeem"): (
        "A guest redeeming or checking a code handed to them at a front desk -- the "
        "whole point is that they have no account. They hold no roles, so there is no "
        "confinement to derive, and redemption resolves the voucher by its own code "
        "rather than through the confined `get_batch`."
    ),
    ("POST", "/api/v1/vouchers/validate"): (
        "A guest redeeming or checking a code handed to them at a front desk -- the "
        "whole point is that they have no account. They hold no roles, so there is no "
        "confinement to derive, and redemption resolves the voucher by its own code "
        "rather than through the confined `get_batch`."
    ),
    ("GET", "/api/v1/portal/campaigns/next"): (
        "A guest at the portal being shown a campaign, recording that it was shown, or "
        "answering its survey. They hold no roles, so there is no confinement to "
        "derive. The campaign they are served is already chosen by their own session's "
        "location (`get_next_campaign_for_session`), so being unconfined here does not "
        "widen what they can see."
    ),
    ("POST", "/api/v1/portal/campaigns/{campaign_id}/impression"): (
        "A guest at the portal being shown a campaign, recording that it was shown, or "
        "answering its survey. They hold no roles, so there is no confinement to "
        "derive. The campaign they are served is already chosen by their own session's "
        "location (`get_next_campaign_for_session`), so being unconfined here does not "
        "widen what they can see."
    ),
    ("POST", "/api/v1/portal/campaigns/{campaign_id}/respond"): (
        "A guest at the portal being shown a campaign, recording that it was shown, or "
        "answering its survey. They hold no roles, so there is no confinement to "
        "derive. The campaign they are served is already chosen by their own session's "
        "location (`get_next_campaign_for_session`), so being unconfined here does not "
        "widen what they can see."
    ),
    ("POST", "/api/v1/guest/login/otp"): (
        "A guest acting on their own session, before or during login. They hold no "
        "roles, so there is no confinement to derive; the anonymous-tolerant "
        "dependency resolves them to unconfined rather than 401ing them out of the "
        "portal."
    ),
    ("POST", "/api/v1/guest/login/voucher"): (
        "A guest acting on their own session, before or during login. They hold no "
        "roles, so there is no confinement to derive; the anonymous-tolerant "
        "dependency resolves them to unconfined rather than 401ing them out of the "
        "portal."
    ),
    ("POST", "/api/v1/guest/login/password"): (
        "A guest acting on their own session, before or during login. They hold no "
        "roles, so there is no confinement to derive; the anonymous-tolerant "
        "dependency resolves them to unconfined rather than 401ing them out of the "
        "portal."
    ),
    ("POST", "/api/v1/guest/login/pin"): (
        "A guest acting on their own session, before or during login. They hold no "
        "roles, so there is no confinement to derive; the anonymous-tolerant "
        "dependency resolves them to unconfined rather than 401ing them out of the "
        "portal."
    ),
    ("POST", "/api/v1/guest/consent"): (
        "A guest acting on their own session, before or during login. They hold no "
        "roles, so there is no confinement to derive; the anonymous-tolerant "
        "dependency resolves them to unconfined rather than 401ing them out of the "
        "portal."
    ),
    ("POST", "/api/v1/guest/profile"): (
        "A guest acting on their own session, before or during login. They hold no "
        "roles, so there is no confinement to derive; the anonymous-tolerant "
        "dependency resolves them to unconfined rather than 401ing them out of the "
        "portal."
    ),
    ("POST", "/api/v1/guest/review-link-opened"): (
        "A guest tapping the review card on their own connected session -- the same "
        "shape as `/guest/profile` above, and unauthenticated for the same reason: "
        "they hold no roles, so there is no confinement to derive, and the strict "
        "dependency would drag `CurrentUser` in and 401 them out of the portal. It "
        "records one bit against the session the caller already holds and reads "
        "nothing, so being unconfined here widens nothing: the worst a caller can do "
        "with a session id they do not own is mark someone else's review card as "
        "already tapped, which suppresses a nudge and grants no access."
    ),
    ("POST", "/api/v1/guest/set-password"): (
        "A guest acting on their own session, before or during login. They hold no "
        "roles, so there is no confinement to derive; the anonymous-tolerant "
        "dependency resolves them to unconfined rather than 401ing them out of the "
        "portal."
    ),
    ("POST", "/api/v1/guest/set-pin"): (
        "A guest acting on their own session, before or during login. They hold no "
        "roles, so there is no confinement to derive; the anonymous-tolerant "
        "dependency resolves them to unconfined rather than 401ing them out of the "
        "portal."
    ),
    ("GET", "/api/v1/guest/session/active"): (
        "A guest acting on their own session, before or during login. They hold no "
        "roles, so there is no confinement to derive; the anonymous-tolerant "
        "dependency resolves them to unconfined rather than 401ing them out of the "
        "portal."
    ),
    ("GET", "/api/v1/guest/session/last-ended"): (
        "The read-only twin of `/guest/session/active` above, asked by the portal "
        "only after that one answers 'no active session', and unauthenticated for "
        "the identical reason: a guest whose session has just ended holds no roles, "
        "so there is no confinement to derive, and the strict dependency would drag "
        "`CurrentUser` in and 401 them out of the portal at exactly the moment the "
        "screen exists to help them. Being unconfined widens nothing here, and this "
        "route is deliberately narrower than its twin rather than as wide: it "
        "returns a closed two-member enum plus the venue's own session-timeout "
        "setting -- no identifier, no ids, no timestamp, no `disconnect_reason` -- "
        "and returns null outright for any session an operator terminated, so it "
        "cannot be used to ask whether a MAC is blocked at a venue. The most a "
        "caller holding a MAC they do not own can learn is that some session on "
        "that device ended within LAST_ENDED_SESSION_WINDOW_MINUTES, which is "
        "strictly less than `/session/active` already discloses for a live one."
    ),
    ("POST", "/api/v1/guest/session/disconnect"): (
        "A guest acting on their own session, before or during login. They hold no "
        "roles, so there is no confinement to derive; the anonymous-tolerant "
        "dependency resolves them to unconfined rather than 401ing them out of the "
        "portal."
    ),
    ("POST", "/api/v1/radius/authorize"): (
        "Authenticated by the NAS shared secret (`CurrentNas`), not by a user session "
        "-- the router itself is the caller. It has no RBAC grants and therefore no "
        "location confinement, and it must never 401: this is the path every guest's "
        "traffic authorises through."
    ),
    ("POST", "/api/v1/radius/accounting"): (
        "Authenticated by the NAS shared secret (`CurrentNas`), not by a user session "
        "-- the router itself is the caller. It has no RBAC grants and therefore no "
        "location confinement, and it must never 401: this is the path every guest's "
        "traffic authorises through."
    ),
    ("GET", "/api/v1/agent/authorized-macs"): (
        "Authenticated by the router agent's own credential (`CurrentAgent`), not by a "
        "user session. Same reasoning as the RADIUS routes: a device is the caller, "
        "holds no grants, and must not be confined."
    ),
    ("POST", "/api/v1/agent/netwatch-event"): (
        "Authenticated by the router agent's own credential (`CurrentAgent`), not by a "
        "user session. Same reasoning as the RADIUS routes: a device is the caller, "
        "holds no grants, and must not be confined."
    ),
    ("POST", "/api/v1/otp/request"): (
        "A guest at a captive portal asking for a sign-in code, before they have any "
        "identity at all -- the very first call the portal makes. It reaches a "
        "confined service because it now composes `GuestService.check_portal_admission`"
        ", the per-property whitelist-only gate that must refuse a non-listed guest "
        "*before* the venue pays for an SMS. Being unconfined grants nothing: the "
        "admission check resolves the portal config by the organization/location the "
        "request itself names and reads only that property's own access rules, exactly "
        "as `POST /guest/login/otp` does one step later. Requiring a credential here "
        "would 401 every guest out of the portal."
    ),
    ("POST", "/api/v1/guest-teams/join"): (
        "A guest joining a team with a code they were given. They hold no "
        "roles, so there is no confinement to derive, and `join_team` "
        "resolves by team code off the repository rather than through the "
        "confined `get_team` -- so being unconfined here grants nothing."
    ),
    ("GET", "/api/v1/guest-teams/open"): (
        "The sign-in screen's optional 'which group do you belong to?' "
        "dropdown, fetched by an anonymous guest in the captive portal "
        "before they have signed in -- the same pre-identity moment as "
        "`POST /guest-teams/join` next to it. `list_open_teams` reads only "
        "the organization/location the request itself names and returns "
        "nothing but team names/codes that are already public join tokens; "
        "requiring a credential would 401 every guest out of the dropdown."
    ),
    ("GET", "/api/v1/captive-portal-configs/{config_id}/content-image/public"): (
        "The uploaded 'Before sign-in: show a picture' content image, "
        "rendered by the guest portal's own <img> before the guest has any "
        "identity -- the same class of exception as the branding public "
        "proxies (GET /branding/{organization_id}/logo/public). The config "
        "id in the path is the (unguessable) capability and the endpoint "
        "only ever streams one image's bytes; a credential requirement "
        "would break every portal that uses the feature."
    ),
}


def test_no_route_relies_on_confinement_without_authentication() -> None:
    """Also catches the inverse: a confinement dependency *adding* auth.

    The first version of this test asked "is `CurrentUser` anywhere in the
    route's dependency graph?" and answered yes for every route -- because
    `CallerLocationScope` depends on `CurrentUser` and had just been added to
    the graph. It reported zero offenders while fifteen routes were broken,
    including every guest login method and `POST /radius/authorize`.

    So the graph is walked twice: once for everything, and once **excluding
    the confinement dependencies' own subtrees**, which is the authentication
    a route has on its own account. A route with no independent authentication
    that reaches a confined service is either a guest route needing the
    anonymous-tolerant dependency, or a route that just had authentication
    silently added to it.
    """
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.location_scope import (
        CallerLocationScope,
        OptionalCallerLocationScope,
    )
    from app.main import create_app

    confinement = {CallerLocationScope, OptionalCallerLocationScope}

    def all_calls(dependant) -> set:
        found = {d.call for d in dependant.dependencies}
        for d in dependant.dependencies:
            found |= all_calls(d)
        return found

    def independent_calls(dependant) -> set:
        """Everything reachable *except* through a confinement dependency."""
        found = set()
        for d in dependant.dependencies:
            if d.call in confinement:
                continue
            found.add(d.call)
            found |= independent_calls(d)
        return found

    offenders = []
    for route in create_app().routes:
        dependant = getattr(route, "dependant", None)
        if dependant is None or not (all_calls(dependant) & confinement):
            continue

        own = independent_calls(dependant)
        names = {getattr(f, "__qualname__", "") for f in own}
        if CurrentUser in own or any(n.startswith("RequirePermission") for n in names):
            continue

        path = getattr(route, "path", "")
        methods = list(getattr(route, "methods", []) or [])
        keys = [(m, path) for m in methods] or [("", path)]
        if any(k in _GUEST_FACING_UNCONFINED for k in keys):
            continue
        offenders.append(f"{sorted(methods)} {path}")

    assert not offenders, (
        "These routes have no authentication of their own but reach a "
        "location-confined service:\n"
        + "\n".join(f"  {o}" for o in sorted(offenders))
        + "\n\nEither the domain needs OptionalCallerLocationScope (the strict "
        "one drags CurrentUser in and turns a guest route into a 401), or -- if "
        "being unconfined there is correct -- add it to "
        "_GUEST_FACING_UNCONFINED with the reason."
    )
