"""Tests for the Security domain.

Three things are under test here, and the first is the most important:

1. **This domain is read-only, and stays that way.** Not by convention -- by
   assertion. ``app.domains.security.router`` is included in the v1 router
   *without* the licence gate that every writing router carries, and that is
   only safe while it has no write endpoint. The guard below is what turns
   "someone adds a POST here" into a failing test naming the licence decision,
   instead of a shipped write that skips ``RequireActiveLicenseForWrites``.
2. **The score says what it measures.** Every factor is asserted to be
   itemised, capped, and derived from the state handed in -- so a change in the
   numbers is traceable to a change in the inputs.
3. **A capability cannot be advertised without a mechanism.** The brief's rule
   is that a feature must not appear supported merely because a dashboard can
   display it, so ``AVAILABLE`` is asserted to always name where it is enforced
   and the known exclusions are asserted to stay excluded.

No database and no device is touched: the service takes a repository, and the
tests hand it a fake. The repository itself is a thin layer of aggregate SQL and
is exercised by the integration sweep, not here.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from app.domains.rbac.enums import PermissionAction, PermissionModule, ScopeType
from app.domains.rbac.seed import (
    MODULE_ACTIONS,
    MODULE_DISPLAY_NAMES,
    MODULE_NARROWEST_SCOPE,
    SYSTEM_ROLES,
    permission_key,
)
from app.domains.security.constants import (
    MIN_ROUTERS_FOR_SCORE,
    SCORE_FACTOR_WEIGHTS,
    SECURITY_FEATURES,
    SECURITY_SCORE_MAX,
    ScoreFactorKey,
    SecurityAvailability,
    score_band_for,
)
from app.domains.security.repository import (
    BlockCounts,
    DeviceRuleCounts,
    FleetCounts,
    RogueDhcpCounts,
    RuleCounts,
    VpnPeerCounts,
)
from app.domains.security.router import router as security_router
from app.domains.security.service import SecurityOverviewService, _rate_penalty

_SECURITY = PermissionModule.SECURITY


def _code_without_docstrings(source: str) -> str:
    """``source`` re-printed with every docstring stripped.

    ``ast.unparse`` drops comments on its own; this removes docstrings too,
    which is what makes a source scan about what the code *does* rather than
    about what its prose mentions.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(
            node,
            ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
        ):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def _fleet(
    total: int, reporting: int, *, stale: int = 0, unhealthy: int = 0
) -> FleetCounts:
    """Shorthand for the fleet shape, which several tests vary one field of."""
    return FleetCounts(
        total=total, reporting=reporting, stale=stale, unhealthy=unhealthy
    )


class _FakeRepository:
    """In-memory stand-in for the aggregate reads.

    Defaults describe a small, clean, single-gateway venue, so a test only has
    to override the one dimension it is about.
    """

    def __init__(
        self,
        *,
        fleet: FleetCounts | None = None,
        blocks: BlockCounts | None = None,
        vpn: VpnPeerCounts | None = None,
        rules: RuleCounts | None = None,
        devices: DeviceRuleCounts | None = None,
        rogue: RogueDhcpCounts | None = None,
        open_alerts: int = 0,
    ) -> None:
        self._fleet = fleet or FleetCounts(
            total=1, reporting=1, stale=0, unhealthy=0
        )
        self._blocks = blocks or BlockCounts(
            domains_enabled=0,
            addresses_enabled=0,
            enabled_not_applied=0,
            failed=0,
        )
        self._vpn = vpn or VpnPeerCounts(total=1, active=1)
        self._rules = rules or RuleCounts(total=0, enabled=0)
        self._devices = devices or DeviceRuleCounts(
            active_blocks=0, active_allowlists=0
        )
        self._rogue = rogue or RogueDhcpCounts(
            guarded=1, unguarded=0, unknown=0
        )
        self._open_alerts = open_alerts

    async def fleet_counts(self, *, organization_id, stale_after_minutes):
        return self._fleet

    async def vpn_peer_counts(self, *, organization_id):
        return self._vpn

    async def block_counts(self, *, organization_id):
        return self._blocks

    async def firewall_rule_counts(self, *, organization_id):
        return self._rules

    async def device_rule_counts(self, *, organization_id):
        return self._devices

    async def rogue_dhcp_counts(self, *, organization_id):
        return self._rogue

    async def open_alert_count(self, *, organization_id):
        return self._open_alerts


# ============================================================================
# 1. Read-only, by assertion
# ============================================================================


class TestTheDomainIsReadOnly:
    """The property that lets this router be included without the licence gate."""

    def test_the_router_exposes_no_write_route(self) -> None:
        """Adding a POST/PUT/PATCH/DELETE here is not a small change.

        ``app/api/v1/router.py`` includes this router without
        ``_PAID_WRITES``, which is correct only while every route is a read.
        A write added without moving the ``include_router`` call would skip
        ``RequireActiveLicenseForWrites`` entirely -- an ungated write on a
        paid product, arrived at silently. Failing here is the notification.
        """
        offenders = {
            route.path: sorted(route.methods)
            for route in security_router.routes
            if set(getattr(route, "methods", set())) - {"GET", "HEAD"}
        }
        assert not offenders, (
            "the Security router must stay read-only -- if a write route is "
            "genuinely intended, move the include_router call in "
            "app/api/v1/router.py onto _PAID_WRITES and update this test: "
            f"{offenders}"
        )

    def test_every_route_requires_the_security_read_permission(self) -> None:
        """A route here that checks no permission would be an unauthenticated
        read of a venue's exposure."""
        route_paths = [route.path for route in security_router.routes]
        assert route_paths, "expected the security router to expose routes"
        for route in security_router.routes:
            names = {
                getattr(dep.call, "__qualname__", "")
                for dep in route.dependant.dependencies
            }
            assert any(name.startswith("RequirePermission") for name in names), (
                route.path
            )

    def test_the_package_contains_no_write_or_device_io(self) -> None:
        """A source-level guard, because a future method could write through
        the repository without adding a route of its own.

        Compares against the parsed code with docstrings removed, deliberately
        not the raw file. Raw text is unusable here for a mundane reason: this
        package's own docstrings *name* the things they refuse to use --
        ``constants.py`` points at ``content_filtering.device_adapters`` as the
        incident it learned from, and a raw scan reads that cross-reference as
        a call. Stripping prose first keeps the assertion about behaviour.

        Same posture as ``test_router_read_vendor_coverage.py``, which scans
        call sites for a symbol rather than trusting the reader to remember.
        """
        forbidden = (
            "session.add(",
            "session.commit(",
            "session.flush(",
            "wyfy_device_gateway",
            "device_adapters",
            "get_adapter(",
        )
        package = pathlib.Path(__file__).parents[2] / "app" / "domains" / "security"
        assert package.is_dir(), package
        checked = 0
        for source_file in sorted(package.glob("*.py")):
            code = _code_without_docstrings(
                source_file.read_text(encoding="utf-8")
            )
            checked += 1
            for token in forbidden:
                assert token not in code, f"{source_file.name} contains {token!r}"
        assert checked, "expected to scan the security package's own modules"


# ============================================================================
# 2. The seed
# ============================================================================


class TestSecurityIsSeeded:
    def test_the_module_is_mapped_in_all_three_tables(self) -> None:
        assert _SECURITY in MODULE_ACTIONS
        assert _SECURITY in MODULE_DISPLAY_NAMES
        assert _SECURITY in MODULE_NARROWEST_SCOPE

    def test_read_is_the_only_seeded_action(self) -> None:
        """Anything else would be a permission key no route checks.

        This file's own NETWORK_INTEGRATIONS entry calls that out as "dead
        permission data that reads like a capability". The write actions must
        land with the endpoints that check them.
        """
        assert MODULE_ACTIONS[_SECURITY] == (PermissionAction.READ,)
        assert permission_key(_SECURITY, PermissionAction.READ) == "security.read"

    def test_the_narrowest_scope_is_location(self) -> None:
        """A venue's posture is a venue-level question. ROUTER would mean an
        owner cannot see their own venue unless scoped to one gateway."""
        assert MODULE_NARROWEST_SCOPE[_SECURITY] is ScopeType.LOCATION

    def test_the_security_administrator_role_exists_and_holds_it(self) -> None:
        by_slug = {role.slug: role for role in SYSTEM_ROLES}
        assert "security-administrator" in by_slug
        role = by_slug["security-administrator"]
        assert role.scope_type is ScopeType.LOCATION
        assert _SECURITY in role.grants()

    def test_the_network_roles_hold_it(self) -> None:
        """Both default to GrantLevel.NONE, so without an explicit entry they
        would hold nothing -- which is not a safe default for the roles whose
        job this is."""
        by_slug = {role.slug: role for role in SYSTEM_ROLES}
        for slug in ("network-administrator", "network-engineer"):
            assert _SECURITY in by_slug[slug].grants(), slug

    def test_roles_without_a_stake_do_not_hold_it(self) -> None:
        """Every one of these defaults to NONE, so none should inherit. The
        guard exists because the opposite is silent: ``grants()`` applies a
        role's ``default_level`` to *every* module, so a role whose default is
        FULL would pick this module up without anyone deciding it should."""
        by_slug = {role.slug: role for role in SYSTEM_ROLES}
        for slug in (
            "billing-manager",
            "office-admin",
            "location-manager",
            "reception-staff",
            "helpdesk",
            "guest-operator",
        ):
            assert _SECURITY not in by_slug[slug].grants(), slug

    def test_the_security_administrator_does_not_hold_audit_logs(self) -> None:
        """A LOCATION-scoped role cannot hold an ORGANIZATION-scoped module.

        Seeding would raise ``InvalidScopeAssignmentError``, so this is a
        would-not-boot bug rather than a permissions nicety -- worth pinning,
        because AUDIT_LOGS is exactly what a security role looks like it
        should have.
        """
        by_slug = {role.slug: role for role in SYSTEM_ROLES}
        grants = by_slug["security-administrator"].grants()
        assert PermissionModule.AUDIT_LOGS not in grants


# ============================================================================
# 3. The score model
# ============================================================================


class TestScoreMaths:
    def test_bands_partition_zero_to_full(self) -> None:
        assert score_band_for(SECURITY_SCORE_MAX).value == "excellent"
        assert score_band_for(90).value == "excellent"
        assert score_band_for(89).value == "good"
        assert score_band_for(75).value == "good"
        assert score_band_for(74).value == "fair"
        assert score_band_for(50).value == "fair"
        assert score_band_for(49).value == "poor"
        assert score_band_for(0).value == "poor"

    def test_a_rate_factor_is_capped(self) -> None:
        per, cap = SCORE_FACTOR_WEIGHTS[ScoreFactorKey.FLEET_REPORTING]
        assert per > cap, "this test assumes the cap binds before the raw rate"
        # Every gateway stale would be a 60-point rate against a 40-point cap.
        assert _rate_penalty(
            ScoreFactorKey.FLEET_REPORTING, affected=10, denominator=10
        ) == cap

    def test_a_rate_factor_with_no_denominator_scores_nothing(self) -> None:
        """"Zero blocks configured" is a posture gap, not a push failure, and
        a rate with no denominator has nothing to be a rate of."""
        assert _rate_penalty(
            ScoreFactorKey.BLOCK_PUSH_INTEGRITY, affected=0, denominator=0
        ) == 0

    def test_a_count_factor_scales_per_occurrence(self) -> None:
        per, cap = SCORE_FACTOR_WEIGHTS[ScoreFactorKey.ALERT_PRESSURE]
        assert _rate_penalty(
            ScoreFactorKey.ALERT_PRESSURE, affected=1, denominator=0
        ) == per
        assert _rate_penalty(
            ScoreFactorKey.ALERT_PRESSURE, affected=99, denominator=0
        ) == cap


class TestScoreIsProduced:
    async def test_a_clean_venue_scores_full_marks(self) -> None:
        service = SecurityOverviewService(_FakeRepository())
        score = await service.build_score(requesting_organization_id=None)
        assert score.available is True
        assert score.score == SECURITY_SCORE_MAX
        assert score.band is not None

    async def test_no_managed_gateway_is_unavailable_not_perfect(self) -> None:
        """The failure this guards: an unmonitored venue rendering as a
        hardened one, because every counter is zero by absence."""
        service = SecurityOverviewService(
            _FakeRepository(fleet=_fleet(0, 0))
        )
        score = await service.build_score(requesting_organization_id=None)
        assert score.available is False
        assert score.score is None
        assert score.band is None
        assert score.unavailable_reason
        assert score.factors == []

    async def test_the_penalties_add_up_to_the_score(self) -> None:
        """The number must be explainable by its own itemisation."""
        service = SecurityOverviewService(
            _FakeRepository(
                fleet=FleetCounts(total=4, reporting=2, stale=2, unhealthy=1),
                blocks=BlockCounts(
                    domains_enabled=3,
                    addresses_enabled=1,
                    enabled_not_applied=2,
                    failed=1,
                ),
                vpn=VpnPeerCounts(total=4, active=3),
                rogue=RogueDhcpCounts(guarded=2, unguarded=1, unknown=1),
                open_alerts=3,
            )
        )
        score = await service.build_score(requesting_organization_id=None)
        assert score.available is True
        assert score.score is not None
        assert score.score == SECURITY_SCORE_MAX - sum(
            factor.penalty for factor in score.factors
        )

    async def test_every_factor_reports_its_own_ceiling(self) -> None:
        service = SecurityOverviewService(_FakeRepository())
        score = await service.build_score(requesting_organization_id=None)
        keys = {factor.key for factor in score.factors}
        assert keys == {key.value for key in ScoreFactorKey}
        for factor in score.factors:
            assert factor.penalty <= factor.max_penalty
            assert factor.detail
            assert factor.available is True


# ============================================================================
# 4. The capability matrix
# ============================================================================


class TestCapabilityMatrix:
    def test_an_available_feature_always_names_its_mechanism(self) -> None:
        """The brief's rule, enforced: nothing is "available" without saying
        what enforces it. "Supported" with no mechanism is the claim this
        matrix exists to make impossible."""
        for feature in SECURITY_FEATURES:
            if feature.availability is SecurityAvailability.AVAILABLE:
                assert feature.enforcement, feature.key
            else:
                assert feature.enforcement is None, feature.key
            assert feature.detail, feature.key

    def test_the_known_exclusions_stay_excluded(self) -> None:
        """Pinned so that "we'll just show a toggle for now" fails the build
        rather than shipping a control that writes a row and blocks nothing."""
        req = SecurityAvailability.REQUIRES_ADDITIONAL_TECHNOLOGY
        unsupported = SecurityAvailability.NOT_SUPPORTED
        expected = {
            "web_category_filtering": req,
            "application_control": req,
            "threat_intelligence": req,
            "geo_blocking": req,
            "per_application_traffic": unsupported,
            "ids_ips": unsupported,
            "url_path_filtering": unsupported,
        }
        by_key = {feature.key: feature for feature in SECURITY_FEATURES}
        for key, availability in expected.items():
            assert key in by_key, key
            assert by_key[key].availability is availability, key

    def test_feature_keys_are_unique(self) -> None:
        keys = [feature.key for feature in SECURITY_FEATURES]
        assert len(keys) == len(set(keys))

    def test_the_capabilities_endpoint_serves_the_matrix(self) -> None:
        payload = SecurityOverviewService(_FakeRepository()).capabilities()
        assert {feature.key for feature in payload.features} == {
            feature.key for feature in SECURITY_FEATURES
        }


# ============================================================================
# 5. Counters report unknown as unknown
# ============================================================================


class TestCounters:
    async def test_the_threat_counters_are_unavailable_rather_than_zero(self) -> None:
        """This platform has no event capture. A zero would read as "we looked
        and found nothing", which is false, so the honest answer is an
        explicit gap naming the missing pipeline."""
        overview = await SecurityOverviewService(_FakeRepository()).build_overview(
            requesting_organization_id=None
        )
        by_key = {counter.key: counter for counter in overview.counters}
        for key in ("threats_detected", "threats_blocked"):
            counter = by_key[key]
            assert counter.available is False
            assert counter.count is None
            assert counter.unavailable_reason

    async def test_blocks_report_whether_they_reached_a_gateway(self) -> None:
        overview = await SecurityOverviewService(
            _FakeRepository(
                blocks=BlockCounts(
                    domains_enabled=5,
                    addresses_enabled=0,
                    enabled_not_applied=2,
                    failed=1,
                )
            )
        ).build_overview(requesting_organization_id=None)
        by_key = {counter.key: counter for counter in overview.counters}
        assert by_key["blocked_domains"].count == 5
        assert by_key["blocks_not_applied"].count == 2
        assert by_key["blocks_not_applied"].source == (
            "content_filter_rules.device_push_status"
        )

    async def test_an_empty_venue_says_so_without_inventing_numbers(self) -> None:
        overview = await SecurityOverviewService(
            _FakeRepository(fleet=_fleet(0, 0))
        ).build_overview(requesting_organization_id=None)
        assert overview.fleet.no_managed_gateway is True
        assert overview.fleet.routers_total == 0
        assert overview.score.available is False

    async def test_the_small_venue_shape_is_reported_faithfully(self) -> None:
        overview = await SecurityOverviewService(
            _FakeRepository(
                fleet=_fleet(3, 2, stale=1),
                vpn=VpnPeerCounts(total=3, active=2),
            )
        ).build_overview(requesting_organization_id=None)
        assert overview.fleet.routers_reporting == 2
        assert overview.fleet.routers_stale == 1
        assert overview.fleet.vpn_peers_active == 2
        assert overview.fleet.vpn_peers_total == 3
        assert overview.fleet.no_managed_gateway is False

    async def test_a_single_gateway_is_enough_to_score(self) -> None:
        assert MIN_ROUTERS_FOR_SCORE == 1
        overview = await SecurityOverviewService(
            _FakeRepository(fleet=_fleet(1, 1))
        ).build_overview(requesting_organization_id=None)
        assert overview.score.available is True


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
