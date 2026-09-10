"""Every read of the ``routers`` table must have answered the vendor
question -- or say, in writing, why it did not have to.

## Why this file exists

Contract 11.5 named fifteen domains to audit, and
``test_vendor_gating_audit.py`` closed all fifteen. That work was correct
and it is not enough, because it is a description of one afternoon. The
hazard is not the surfaces that existed when a TP-Link Omada controller
first became a ``Router`` row; it is the next sweep, the next dashboard
tile, the next domain -- each of which will iterate ``routers``, treat
every row as a MikroTik running this platform's agent, and be *right*
about every row but one.

The failure mode is what makes a per-surface audit insufficient. Nothing
raises. A controller-managed row has NULL API credentials, ``snmp_enabled
= False`` and no agent, so the code does not crash on it: it reports. A
venue that is serving guests perfectly is described as a device that is
offline, unprovisioned, and failing its checklist -- and the operator sent
to fix it finds nothing wrong, because nothing is.

So the question moves from "did we remember at each site" to "can a site
exist that never asked". This file enumerates the sites from the code and
requires each one to be classified. A new one appears here automatically
and fails until somebody writes down which it is.

## Two buckets, and a site must be in exactly one

``AGENT_MANAGED_ONLY``
    The read is narrowed to agent-managed rows in the ``WHERE`` clause,
    through ``app.domains.router.fleet_scope.agent_managed_only``. Use it
    when the rows are about to be *acted on* -- dispatched a Celery task,
    polled, pushed configuration. A row a sweep never loads is a row it
    cannot act on by mistake, which is why this is preferred over
    filtering the result.

``VENDOR_NEUTRAL``
    The read deliberately returns every row, controller-managed included.
    The entry must say **why that is the honest answer here, and what
    protects the consumers that need the narrower set.** "It's only a
    count" is a reason; silence is not.

    This is the bucket that does the work. A filter is easy to add and
    easy to add wrongly: a controller *missing* from the fleet inventory
    an operator is looking at is a different lie from a controller
    reported as a broken MikroTik, and no query-level helper can tell the
    two apart. Forcing the argument to be written where the reviewer will
    see it is the point.

## What this guard does NOT do

It watches reads of the ``routers`` *table*. It cannot see a consumer that
takes an already-loaded roster and asks it an agent-shaped question --
``monitoring``'s alert evaluator was exactly that, and it is caught here
only because ``list_routers``'s entry below had to name it. Nor does it
reach the many domains that take a single ``router_id`` and dispatch on
vendor through an adapter registry; those fail closed with an explicit
error and are covered by ``test_vendor_gating_audit.py``.

Read the entries as a review, not as a checklist that has been ticked.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from sqlalchemy import Column, MetaData, String, Table, create_engine, insert, select
from wyfy_device_gateway.contract import DeviceVendor

from app.domains.router.fleet_scope import (
    agent_managed_only,
    agent_managed_vendor_criterion,
)
from app.domains.router.vendor_capabilities import (
    CONTROLLER_MANAGED_VENDORS,
    agent_managed_rows,
    is_agent_managed,
)

APP_ROOT = pathlib.Path("app")
ROUTER_MODEL_MODULE = "app.domains.router.models"

# The module that *defines* the gate necessarily names `Router.vendor`. It
# is the answer, not a call site, so it is skipped -- and the skip is one
# named path rather than a pattern, so nothing else can hide behind it.
THE_GATE_ITSELF = pathlib.Path("app/domains/router/fleet_scope.py")

# The symbol a site must call to count as narrowed in SQL.
NARROWING_HELPERS = frozenset({"agent_managed_only", "agent_managed_vendor_criterion"})


# ---------------------------------------------------------------------------
# The two buckets. Keys are "<module path>::<qualified function name>".
# ---------------------------------------------------------------------------

AGENT_MANAGED_ONLY: dict[str, str] = {
    "app/domains/connected_devices/repository.py::"
    "ConnectedDeviceRepository.list_routers_for_sync": (
        "Fleet-wide DHCP-lease discovery. Each row is dispatched to "
        "`sync_single_router_devices`, which opens a RouterOS session with "
        "the row's own stored credentials -- NULL by construction on a "
        "controller. Before this filter every tick produced one guaranteed "
        "failure per controller, absorbed by the sweep's per-router "
        "isolation into a `routers_failed` count and a warning log."
    ),
    "app/domains/connected_devices/repository.py::"
    "ConnectedDeviceRepository.list_routers_with_monitored_hardware": (
        "The monitored-hardware liveness sweep's fan-out list. Same "
        "device-I/O reason as `list_routers_for_sync`, and worse in one "
        "respect: the target list is built by joining on `location_id`, so "
        "a controller-managed row at a shared site would be handed another "
        "vendor's hardware to ping through a session it can never open."
    ),
    "app/domains/dhcp/repository.py::DhcpRepository.list_all_router_ids": (
        "The captive-portal DHCP-option convergence sweep. Every id goes "
        "straight to a RouterOS write. Note this method's docstring "
        "argues, correctly, against narrowing the set by `DhcpPool` -- a "
        "router this platform never configured must stay in it. 'Cannot "
        "run RouterOS at all' is the different question, and the one this "
        "filter answers."
    ),
}


# Six `monitoring` reads share one shape: the row-set is `provisioning_jobs`
# and `Router` appears only as the tenancy column that table has no column
# for. Written once and referenced, rather than six near-identical
# paragraphs a reader would skim past -- each entry still says what its own
# query is for.
_PROVISIONING_JOB_TENANCY_JOIN = (
    "Reads `provisioning_jobs`; `Router` is joined only when an "
    "`organization_id` is given, purely as the tenancy column that table "
    "lacks. No router row is selected, returned or judged, and a controller "
    "is never enqueued for provisioning so it contributes no job rows "
    "either way."
)


VENDOR_NEUTRAL: dict[str, str] = {
    # -- the router domain's own accessors ---------------------------------
    "app/domains/router/repository.py::RouterRepository.__init__": (
        "Constructs the `GenericRepository(Router, ...)` that backs "
        "`get_by_id`/`get_by_serial_number`/`get_by_mac_address` -- three "
        "single-row lookups by an identifier the caller already holds. A "
        "vendor filter here would make a controller unfindable by its own "
        "id, which would break the fleet detail page, the network "
        "integration's `router_id` join, and the onboarding path that "
        "creates the pair."
    ),
    "app/domains/router/repository.py::RouterRepository.list_routers": (
        "The Router Fleet inventory listing, per location, paginated. A "
        "controller MUST appear: the operator registered it, it is a fleet "
        "device (contract 11.3), and hiding it would make the Master "
        "console disagree with the database about what the customer owns. "
        "The console renders it with its own `ControllerManagedBadge` and "
        "a `controller` liveness bucket rather than a Degraded one -- see "
        "`src/lib/router-vendors.ts`, the console twin of "
        "`vendor_capabilities`."
    ),
    "app/domains/router/repository.py::stale_heartbeat_statement": (
        "Restricted to `status == ONLINE`, and a controller row is never "
        "ONLINE (`create_integration_with_fleet_device` writes "
        "`pending_provisioning` and no agent ever transitions it). So it "
        "is excluded already -- but by the row's *status*, not by its "
        "vendor, and a status is a value someone can change. Left "
        "unfiltered rather than double-gated because ONLINE is genuinely "
        "the predicate this sweep is about; if a controller ever becomes "
        "ONLINE that is a bug in the writer, and hiding it here would hide "
        "the bug too."
    ),
    "app/domains/router/repository.py::reachability_candidate_statement": (
        "Same shape as `stale_heartbeat_statement`, doubly so: it is "
        "restricted to ONLINE/OFFLINE *and* inner-joined to "
        "`router_agent_credentials`, and a controller has no agent "
        "credential at all. The join is the real gate and it is the "
        "honest one -- 'no agent has ever authenticated for this row' is "
        "exactly what makes the row unjudgeable here."
    ),
    # -- monitoring ---------------------------------------------------------
    "app/domains/monitoring/repository.py::MonitoringRepository.list_routers": (
        "One read, two questions. `AlertService.get_router_names_for_alerts` "
        "needs every row -- an alert that references a controller and "
        "cannot resolve its name renders a bare UUID on the customer's "
        "Alerts page, which is the defect that method was added to fix. "
        "The rule evaluator needs only agent-reported rows and narrows this "
        "result itself in `AlertService._agent_managed_routers`, which "
        "`TestAlertRulesNeverJudgeAController` below pins behaviourally. "
        "The ZTP dashboard narrows it a third way, through "
        "`supports_zero_touch_provisioning`."
    ),
    "app/domains/monitoring/repository.py::"
    "MonitoringRepository.list_rogue_dhcp_statuses_with_routers": (
        "Inner join to `router_rogue_dhcp_statuses`. Those rows are "
        "written only by `app.domains.dhcp.tasks`'s detector, which reads "
        "`/ip dhcp-server alert` over RouterOS -- a controller can never "
        "have one, so the join excludes it and absence stays absence. "
        "Gating the vendor as well would change nothing and would suggest "
        "the join was not already the answer."
    ),
    "app/domains/monitoring/repository.py::"
    "MonitoringRepository.count_routers_by_status": (
        "A GROUP BY over `routers.status` for the platform overview tile. "
        "A controller sits in `pending_provisioning` permanently, so it "
        "does inflate that bucket -- which is a *display* question the "
        "console already answers with its own fourth `controller` bucket, "
        "not something to fix by deleting the row from the total. A count "
        "that silently omits devices the customer owns is the worse lie."
    ),
    "app/domains/monitoring/repository.py::MonitoringRepository.list_router_events": (
        "Reads `router_events`; `Router` appears only in an optional join "
        "used to scope those events to an organization, because "
        "`RouterEvent` has no `organization_id` of its own. No router row "
        "is returned or judged."
    ),
    "app/domains/monitoring/repository.py::"
    "MonitoringRepository.get_average_provisioning_duration_seconds": (
        "Averages over `provisioning_jobs` durations."
        + _PROVISIONING_JOB_TENANCY_JOIN
    ),
    "app/domains/monitoring/repository.py::"
    "MonitoringRepository.compute_provisioning_job_outcome_counts": (
        "Counts terminal `provisioning_jobs` outcomes."
        + _PROVISIONING_JOB_TENANCY_JOIN
    ),
    "app/domains/monitoring/repository.py::"
    "MonitoringRepository.list_provisioning_failure_counts": (
        "Groups failed `provisioning_jobs` by error."
        + _PROVISIONING_JOB_TENANCY_JOIN
    ),
    "app/domains/monitoring/repository.py::"
    "MonitoringRepository.list_provisioning_failure_samples": (
        "Samples individual failed `provisioning_jobs`."
        + _PROVISIONING_JOB_TENANCY_JOIN
    ),
    "app/domains/monitoring/repository.py::MonitoringRepository.list_retry_jobs": (
        "Pages `provisioning_jobs` that have been retried."
        + _PROVISIONING_JOB_TENANCY_JOIN
    ),
    "app/domains/monitoring/repository.py::"
    "MonitoringRepository.compute_activation_duration_stats": (
        "Measures time-to-activation from `provisioning_jobs`."
        + _PROVISIONING_JOB_TENANCY_JOIN
    ),
    # -- provisioning_engine ------------------------------------------------
    "app/domains/provisioning_engine/repository.py::"
    "ProvisioningEngineRepository.list_routers_for_health_poll": (
        "Restricted to ONLINE/OFFLINE, which a controller row never "
        "reaches. Same argument as `stale_heartbeat_statement`: the status "
        "predicate is what this poll is genuinely about, and a controller "
        "that somehow became ONLINE is a writer bug that should surface "
        "rather than be filtered away here."
    ),
    "app/domains/provisioning_engine/repository.py::"
    "ProvisioningEngineRepository.list_routers_for_snmp_poll": (
        "Restricted to ONLINE/OFFLINE **and** `snmp_enabled IS TRUE`. "
        "`create_integration_with_fleet_device` writes `snmp_enabled = "
        "False` for a controller and nothing flips it, so this is gated "
        "twice over by columns whose values are the honest answer."
    ),
    # -- analytics ----------------------------------------------------------
    "app/domains/analytics/repository.py::"
    "AnalyticsRepository.count_routers_by_status": (
        "The platform-overview twin of monitoring's method of the same "
        "name; identical reasoning, and the two are documented as having "
        "to move together."
    ),
    "app/domains/analytics/repository.py::AnalyticsRepository.list_routers_for_scope": (
        "The seed row-set for the customer's Router Analytics page -- a "
        "device the customer owns belongs in their own analytics roster. "
        "Every per-router figure joined onto it comes from "
        "`guest_sessions`, which an Omada venue genuinely produces (that "
        "is the whole reason the fleet row exists), so the numbers are "
        "real rather than empty."
    ),
    "app/domains/analytics/repository.py::"
    "AnalyticsRepository.get_top_routers_by_bandwidth": (
        "Ranks by summed `guest_sessions` bytes and joins Router only for "
        "the display name. An Omada venue's sessions are real sessions and "
        "belong in the ranking."
    ),
    "app/domains/analytics/repository.py::"
    "AnalyticsRepository.list_all_routers_with_organization": (
        "The Operational Recommendations engine's seed set. Its two "
        "router rules read `status == OFFLINE` (a controller is "
        "`pending_provisioning`, so it never matches) and "
        "`router_health_snapshots` history (a controller has none, and "
        "the rule needs two samples). Both therefore produce no "
        "recommendation for a controller today. That is a consequence of "
        "the rules' own predicates rather than of a vendor check, so a "
        "third rule written against a NULL-ish signal would need to make "
        "its own decision -- which is what this entry exists to tell "
        "whoever writes it."
    ),
    # -- billing ------------------------------------------------------------
    "app/domains/billing/repository.py::UsageRepository.count_routers": (
        "Counts fleet devices against a plan's device allowance. A "
        "controller the operator registered is a device the tenant has, "
        "and quietly not counting it would let a tenant exceed a limit "
        "they are paying for by onboarding controllers. Whether a "
        "controller should cost the same as a router is a pricing "
        "decision, not a gating one, and does not belong in a WHERE "
        "clause."
    ),
    # -- wireguard ----------------------------------------------------------
    "app/domains/wireguard/repository.py::"
    "WireGuardRepository.list_all_peers_with_router_names": (
        "Reads `wireguard_peers`; Router appears only in an OUTER join "
        "supplying a display name. A controller can no longer have a peer "
        "at all -- `validate_router_eligible_for_wireguard` refuses one "
        "with `WireGuardVendorNotSupportedError` (see "
        "`test_vendor_gating_audit.py`) -- so filtering here would only "
        "hide a peer that should not exist and that nothing else would "
        "report."
    ),
    # -- connected_devices --------------------------------------------------
    "app/domains/connected_devices/repository.py::"
    "ConnectedDeviceRepository.list_monitored_macs_for_router": (
        "Router is joined to resolve one already-known `router_id` to its "
        "`location_id`; the query returns MAC addresses. Its caller "
        "reached it through `sync_router`, which the gated "
        "`list_routers_for_sync` no longer dispatches for a controller."
    ),
}


# ---------------------------------------------------------------------------
# Deriving the sites from the code
# ---------------------------------------------------------------------------


def _module_name(path: pathlib.Path) -> str:
    return ".".join(path.with_suffix("").parts)


def _resolved_import_module(path: pathlib.Path, node: ast.ImportFrom) -> str:
    """Absolute module name for an ``ImportFrom``, relative or not."""
    if not node.level:
        return node.module or ""
    package = _module_name(path).split(".")[:-1]
    if node.level > 1:
        package = package[: -(node.level - 1)]
    if node.module:
        package = package + [node.module]
    return ".".join(package)


def _binds_router_model(path: pathlib.Path, tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and _resolved_import_module(path, node) == ROUTER_MODEL_MODULE
        and any(a.name == "Router" and a.asname is None for a in node.names)
        for node in ast.walk(tree)
    )


def _enclosing_qualname(parents: dict, node: ast.AST) -> str:
    chain: list[str] = []
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(
            current, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
        ):
            chain.append(current.name)
    return ".".join(reversed(chain)) or "<module>"


def _reads_the_router_table(node: ast.AST) -> bool:
    """Does this node put the ``routers`` table into a query?

    Two shapes, both of which have to count. ``Router.<column>`` covers
    every hand-written statement -- a WHERE, a join condition, a selected
    column. ``select(Router)``/``GenericRepository(Router, ...)`` covers
    the ones that name the class and no column of it.
    """
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "Router"
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id
        in {"select", "GenericRepository", "delete", "update", "insert"}
    ):
        return any(
            isinstance(arg, ast.Name) and arg.id == "Router" for arg in node.args
        )
    return False


def _calls_a_narrowing_helper(parents: dict, tree: ast.Module) -> set[str]:
    """Qualified names of functions that call ``agent_managed_only``."""
    narrowed: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in NARROWING_HELPERS
        ):
            narrowed.add(_enclosing_qualname(parents, node))
    return narrowed


def _router_read_sites() -> dict[str, bool]:
    """``{"<path>::<qualname>": narrowed_in_sql}`` for the whole app."""
    sites: dict[str, bool] = {}
    for path in sorted(APP_ROOT.rglob("*.py")):
        if path == THE_GATE_ITSELF:
            continue
        source = path.read_text()
        if "Router" not in source:
            continue
        tree = ast.parse(source, filename=str(path))
        if not _binds_router_model(path, tree):
            continue
        parents: dict = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        narrowed_here = _calls_a_narrowing_helper(parents, tree)
        for node in ast.walk(tree):
            if not _reads_the_router_table(node):
                continue
            qualname = _enclosing_qualname(parents, node)
            key = f"{path}::{qualname}"
            sites[key] = sites.get(key, False) or qualname in narrowed_here
    return sites


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


def test_every_router_read_is_classified() -> None:
    """The test that stops call site 27 slipping through unasked."""
    classified = set(AGENT_MANAGED_ONLY) | set(VENDOR_NEUTRAL)
    unclassified = sorted(set(_router_read_sites()) - classified)

    assert not unclassified, (
        "These call sites read the `routers` table and are in neither "
        "AGENT_MANAGED_ONLY nor VENDOR_NEUTRAL:\n  "
        + "\n  ".join(unclassified)
        + "\n\nA TP-Link Omada controller is a `Router` row with NULL API "
        "credentials, no agent and no WireGuard peer (contract 11.3/11.5). "
        "Decide which this read is, in this file:\n"
        "  * it feeds device work / an agent-shaped judgement -> wrap the "
        "statement in `app.domains.router.fleet_scope.agent_managed_only` "
        "and add it to AGENT_MANAGED_ONLY;\n"
        "  * every row genuinely belongs in the answer -> VENDOR_NEUTRAL, "
        "with the argument written out.\n"
        "Nothing raises if you skip this. A working venue is simply "
        "reported as broken hardware."
    )


def test_no_site_is_in_both_buckets() -> None:
    overlap = sorted(set(AGENT_MANAGED_ONLY) & set(VENDOR_NEUTRAL))
    assert not overlap, f"classified twice: {overlap}"


def test_no_bucket_entry_is_stale() -> None:
    """An entry naming a call site that no longer exists is an exemption
    lying in wait for a function name to be reused."""
    live = set(_router_read_sites())
    stale = sorted((set(AGENT_MANAGED_ONLY) | set(VENDOR_NEUTRAL)) - live)
    assert not stale, f"classified sites that read no router rows: {stale}"


def test_every_entry_carries_a_real_reason() -> None:
    for bucket_name, bucket in (
        ("AGENT_MANAGED_ONLY", AGENT_MANAGED_ONLY),
        ("VENDOR_NEUTRAL", VENDOR_NEUTRAL),
    ):
        for site, reason in bucket.items():
            assert len(reason.strip()) >= 60, (
                f"{bucket_name}[{site!r}] needs an argument a reviewer can "
                f"disagree with, not {reason!r}"
            )


@pytest.mark.parametrize("site", sorted(AGENT_MANAGED_ONLY))
def test_an_agent_managed_only_site_actually_narrows_its_query(site: str) -> None:
    """The bucket is a claim about the SQL, so it is checked against the
    SQL. Without this, moving `agent_managed_only` off a statement would
    leave the classification behind, still asserting the filter is there."""
    narrowed = _router_read_sites()
    assert narrowed.get(site) is True, (
        f"{site} is listed as AGENT_MANAGED_ONLY but does not call "
        "`agent_managed_only`/`agent_managed_vendor_criterion`. Either "
        "restore the filter or move it to VENDOR_NEUTRAL and write down "
        "why every row belongs."
    )


@pytest.mark.parametrize("site", sorted(VENDOR_NEUTRAL))
def test_a_vendor_neutral_site_does_not_quietly_narrow(site: str) -> None:
    """The mirror image: a site whose entry argues that every row belongs,
    while the query drops some, is documentation that lies."""
    narrowed = _router_read_sites()
    assert narrowed.get(site) is False, (
        f"{site} narrows its query to agent-managed rows but is classified "
        "VENDOR_NEUTRAL, whose entry claims every row belongs in the "
        "answer. One of the two is wrong."
    )


# ---------------------------------------------------------------------------
# "Test the test": the derivation has to actually find things.
# ---------------------------------------------------------------------------


def test_the_derivation_finds_the_known_sites() -> None:
    """A scanner that silently matched nothing would make every assertion
    above pass while guarding not one line of code."""
    sites = _router_read_sites()
    assert len(sites) >= 20, f"suspiciously few router reads found: {sites}"
    assert (
        "app/domains/monitoring/repository.py::MonitoringRepository.list_routers"
        in sites
    )
    assert (
        "app/domains/connected_devices/repository.py::"
        "ConnectedDeviceRepository.list_routers_for_sync" in sites
    )


def test_the_only_skipped_module_is_the_gate_itself() -> None:
    """The scanner skips exactly one file. If that file ever stops
    defining the helper, the skip has become a hole."""
    assert THE_GATE_ITSELF.exists()
    source = THE_GATE_ITSELF.read_text()
    for helper in NARROWING_HELPERS:
        assert f"def {helper}(" in source
    assert not any(str(THE_GATE_ITSELF) in site for site in _router_read_sites())


def test_the_derivation_resolves_relative_imports() -> None:
    """`app/domains/router/repository.py` imports the model as
    `from .models import Router`. An earlier version of this scanner
    matched only the absolute path and therefore skipped the router
    domain's own four reads entirely -- the ones most worth watching."""
    sites = _router_read_sites()
    assert any(site.startswith("app/domains/router/repository.py::") for site in sites)


def test_the_derivation_reads_router_column_references_not_only_select() -> None:
    """`DhcpRepository.list_all_router_ids` selects `Router.id`, never
    `select(Router)`. A scanner watching only the latter would miss every
    column-level read."""
    assert (
        "app/domains/dhcp/repository.py::DhcpRepository.list_all_router_ids"
        in _router_read_sites()
    )


# ---------------------------------------------------------------------------
# The SQL gate and the Python predicate must agree, over real rows.
# ---------------------------------------------------------------------------

# Every vendor string the platform can put in `routers.vendor`, plus the
# two values that are not in the enum: the column default, and NULL.
_ALL_VENDOR_VALUES: tuple[str | None, ...] = tuple(
    dict.fromkeys([v.value for v in DeviceVendor] + ["mikrotik", None])
)


def _vendors_kept_by_the_sql_gate() -> set[str | None]:
    """Run the criterion over real rows on a real database.

    SQLite, in memory, through a two-column throwaway table -- the
    `routers` table itself uses PostgreSQL-native `UUID`/`JSONB` and this
    suite has no PostgreSQL. That is why
    `agent_managed_vendor_criterion` takes a column: the alternative is
    compiling the clause to a string and asserting on the string, which
    would test the spelling and not the filtering.
    """
    metadata = MetaData()
    probe = Table("vendor_probe", metadata, Column("vendor", String, nullable=True))
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            metadata.create_all(connection)
            connection.execute(
                insert(probe), [{"vendor": v} for v in _ALL_VENDOR_VALUES]
            )
            rows = connection.execute(
                select(probe.c.vendor).where(
                    agent_managed_vendor_criterion(probe.c.vendor)
                )
            ).scalars()
            return set(rows)
    finally:
        engine.dispose()


class TestTheSqlGateAndThePythonPredicateAgree:
    """Two gates derived from one constant, on opposite sides of the
    database. If they ever disagree, one of the two surfaces is reporting
    a different fleet from the other and nothing else would say so."""

    def test_the_sql_gate_keeps_exactly_what_is_agent_managed(self) -> None:
        kept = _vendors_kept_by_the_sql_gate()
        expected = {v for v in _ALL_VENDOR_VALUES if is_agent_managed(v)}
        assert kept == expected

    def test_a_null_vendor_survives_the_sql_gate(self) -> None:
        """`NULL NOT IN (...)` is NULL, not true, so a bare `not_in` would
        silently drop a row with no vendor -- excluding a real MikroTik
        from the sweep that keeps it healthy. `vendor_of` makes the same
        call in Python (no vendor reads as the column default)."""
        assert None in _vendors_kept_by_the_sql_gate()
        assert is_agent_managed(None) is True

    def test_the_sql_gate_drops_every_controller_managed_vendor(self) -> None:
        kept = _vendors_kept_by_the_sql_gate()
        assert CONTROLLER_MANAGED_VENDORS
        for vendor in CONTROLLER_MANAGED_VENDORS:
            assert vendor not in kept

    def test_the_sql_gate_excludes_exactly_the_shared_constant(self) -> None:
        """Neither gate restates the vendor list, so a vendor added to
        `CONTROLLER_MANAGED_VENDORS` is gated on both sides or on neither.

        Checked against the criterion's own bind parameters rather than by
        monkeypatching the constant: `fleet_scope` binds it with a
        `from ... import`, so a patched module attribute would not reach
        it and the test would prove only that patching does not work.
        """
        metadata = MetaData()
        probe = Table("vendor_probe", metadata, Column("vendor", String))
        compiled = agent_managed_vendor_criterion(probe.c.vendor).compile()
        excluded: set[str] = set()
        for value in compiled.params.values():
            if isinstance(value, str):
                excluded.add(value)
            elif isinstance(value, list | tuple):
                excluded.update(v for v in value if isinstance(v, str))
        assert excluded == set(CONTROLLER_MANAGED_VENDORS)


class TestEveryPreexistingVendorIsUnaffected:
    """The whole change has to be invisible to anyone not running an Omada
    controller. Asserted rather than assumed: `mikrotik` is every row in
    production today, and the four stub vendors are what a future one will
    arrive as."""

    @pytest.mark.parametrize(
        "vendor", sorted(v.value for v in DeviceVendor if v.value != "tplink_omada")
    )
    def test_the_sql_gate_keeps_it(self, vendor: str) -> None:
        assert vendor in _vendors_kept_by_the_sql_gate()

    @pytest.mark.parametrize(
        "vendor", sorted(v.value for v in DeviceVendor if v.value != "tplink_omada")
    )
    def test_the_row_filter_keeps_it(self, vendor: str) -> None:
        row = _FleetRow(vendor=vendor)
        assert agent_managed_rows([row]) == [row]

    def test_a_row_that_predates_the_vendor_column_is_kept(self) -> None:
        class _Bare:
            pass

        bare = _Bare()
        assert agent_managed_rows([bare]) == [bare]

    def test_agent_managed_only_adds_nothing_but_the_vendor_clause(self) -> None:
        """A statement that has been narrowed must be the same statement
        otherwise -- same columns, same froms, same existing predicates."""
        from app.domains.router.models import Router as RouterModel

        base = select(RouterModel.id).where(RouterModel.is_deleted.is_(False))
        narrowed = agent_managed_only(base)
        assert [c.name for c in narrowed.selected_columns] == [
            c.name for c in base.selected_columns
        ]
        assert str(base.whereclause) in str(narrowed.whereclause)


class _FleetRow:
    def __init__(self, vendor: str | None = "mikrotik") -> None:
        self.vendor = vendor


class TestTheRowFilterAndTheSqlGateAgreeToo:
    def test_a_controller_row_is_dropped(self) -> None:
        assert agent_managed_rows([_FleetRow(vendor="tplink_omada")]) == []

    def test_order_and_identity_are_preserved_for_the_rest(self) -> None:
        keep_a, drop, keep_b = (
            _FleetRow("mikrotik"),
            _FleetRow("tplink_omada"),
            _FleetRow("ruckus"),
        )
        assert agent_managed_rows([keep_a, drop, keep_b]) == [keep_a, keep_b]
