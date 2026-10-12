"""Traffic flow, customer side: a venue owner reads their own venue and
nothing else.

* **Scoping** -- own venue, another organization's venue, a venue that does
  not exist, a venue outside a location-confined caller's grants, a path id
  that disagrees with the header.
* **Entitlement** -- the ``traffic_flow`` add-on is off by default and 402s.
* **What is in the response** -- three collection states, no router or
  collector internals, devices as an address and a session reference only,
  destinations withheld when too few devices are online, and never a device
  beside a destination.
* **Permission** -- read-only, ``venue_traffic.read`` pinned at LOCATION,
  held by the organization owner only among customer roles.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.billing.constants import (
    ADDON_FEATURE_KEYS,
    BOOLEAN_FEATURE_KEYS,
    FEATURE_REQUIRES,
    PlanFeatureKey,
)
from app.domains.billing.exceptions import FeatureNotEntitledError
from app.domains.location.exceptions import (
    CrossOrganizationLocationAccessError,
    LocationNotFoundError,
)
from app.domains.rbac.dependencies import (
    CurrentLocation,
    CurrentOrganization,
    RequireOrganization,
)
from app.domains.rbac.enums import PermissionModule, ScopeType
from app.domains.rbac.location_scope import CallerLocationScope
from app.domains.rbac.seed import (
    MODULE_ACTIONS,
    MODULE_NARROWEST_SCOPE,
    SYSTEM_ROLES,
)
from app.domains.traffic_flow import customer_router
from app.domains.traffic_flow.constants import (
    CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS,
    CustomerCollection,
    FlowState,
)
from app.domains.traffic_flow.service import (
    FleetRouter,
    RouterActivity,
    SummaryScope,
    TrafficFlowCrossLocationError,
    TrafficFlowCustomerService,
    TrafficFlowError,
    TrafficFlowLocationNotFoundError,
    customer_collection,
)
from app.domains.traffic_flow.summary import ServiceStepRow, step_start_of

NOW = datetime(2026, 10, 12, 14, 10, tzinfo=UTC)
ORG_A = uuid.UUID("aaaaaaaa-0000-4000-8000-00000000000a")
ORG_B = uuid.UUID("bbbbbbbb-0000-4000-8000-00000000000b")
VENUE_A = uuid.UUID("a1a1a1a1-0000-4000-8000-000000000001")
VENUE_A2 = uuid.UUID("a2a2a2a2-0000-4000-8000-000000000002")
VENUE_B = uuid.UUID("b1b1b1b1-0000-4000-8000-000000000001")
ROUTER_A = uuid.UUID("8a199617-0000-4000-8000-000000000031")
ROUTER_B = uuid.UUID("8b199617-0000-4000-8000-000000000032")
EXPORTER = "10.20.0.31"
DEVICE = "192.168.88.24"
REMOTE = "142.250.193.14"


@pytest.fixture(autouse=True)
def _info_logging(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO", logger="app.domains.traffic_flow")


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


class Locations:
    """Stands in for ``LocationService.get_location``: the real one raises
    for a missing venue and for another organization's."""

    def __init__(self, *, trusting: bool = False) -> None:
        self.owner = {VENUE_A: ORG_A, VENUE_A2: ORG_A, VENUE_B: ORG_B}
        self.trusting = trusting
        self.asked: list[tuple[uuid.UUID, uuid.UUID | None]] = []

    async def get_location(self, location_id, *, requesting_organization_id=None):  # noqa: ANN001
        self.asked.append((location_id, requesting_organization_id))
        if location_id not in self.owner:
            raise LocationNotFoundError(location_id)
        organization_id = self.owner[location_id]
        if not self.trusting and organization_id != requesting_organization_id:
            raise CrossOrganizationLocationAccessError()
        return SimpleNamespace(id=location_id, organization_id=organization_id)


def _window(
    minutes_ago: int,
    *,
    location_id: uuid.UUID = VENUE_A,
    router_id: uuid.UUID = ROUTER_A,
    devices: int = 6,
    up: int = 100,
    down: int = 900,
) -> Any:
    return SimpleNamespace(
        router_id=router_id,
        location_id=location_id,
        exporter_address=EXPORTER,
        window_start=NOW - timedelta(minutes=minutes_ago),
        window_seconds=300,
        bytes_up=up,
        bytes_down=down,
        bytes_internal=0,
        bytes_unclassified=0,
        flows_total=3,
        services_measured=True,
        talker_count=devices,
        destination_count=1,
        top_talkers=[
            {
                "ip": DEVICE,
                "bytes_up": up,
                "bytes_down": down,
                "flows": 3,
                "match": "session",
                "guest_session_id": "5e55105e-0000-4000-8000-000000000001",
            }
        ],
        top_destinations=[
            {
                "ip": REMOTE,
                "bytes": up + down,
                "bytes_up": up,
                "bytes_down": down,
                "flows": 3,
            }
        ],
    )


class Repo:
    """Holds windows for several venues and honours the scope it is given,
    so a wrong scope shows up as another venue's numbers."""

    def __init__(self) -> None:
        self.windows: list[Any] = []
        self.routers: list[FleetRouter] = []
        self.scopes: list[SummaryScope] = []
        self.fleet_asked: list[uuid.UUID | None] = []

    def _in(self, scope: SummaryScope) -> list[Any]:
        return [
            w
            for w in self.windows
            if (scope.location_id is None or w.location_id == scope.location_id)
            and (scope.router_id is None or w.router_id == scope.router_id)
        ]

    async def data_bounds(self, scope):  # noqa: ANN001
        self.scopes.append(scope)
        starts = [w.window_start for w in self._in(scope)]
        return (min(starts), max(starts)) if starts else (None, None)

    async def windows_in_range(self, scope, *, since, until):  # noqa: ANN001
        self.scopes.append(scope)
        return [w for w in self._in(scope) if since <= w.window_start < until]

    async def service_steps(self, scope, *, since, until, step_seconds):  # noqa: ANN001
        self.scopes.append(scope)
        return [
            ServiceStepRow(
                step_start=step_start_of(w.window_start, step_seconds),
                protocol=6,
                remote_port=443,
                bytes_up=w.bytes_up,
                bytes_down=w.bytes_down,
                flows=3,
            )
            for w in self._in(scope)
            if since <= w.window_start < until
        ]

    async def fleet_routers(self, router_id=None, *, location_id=None):  # noqa: ANN001
        self.fleet_asked.append(location_id)
        return [r for r in self.routers if r.location_id == location_id]

    async def router_activity(self, recent_since):  # noqa: ANN001
        out: dict[uuid.UUID, RouterActivity] = {}
        for w in self.windows:
            current = out.get(w.router_id)
            if current is None or w.window_start > current.newest_window_start:
                out[w.router_id] = RouterActivity(w.window_start, 300, 1, 0)
        return out


def _router(
    router_id: uuid.UUID,
    location_id: uuid.UUID,
    vendor: str = "mikrotik",
    on: bool = True,
) -> FleetRouter:
    return FleetRouter(
        router_id=router_id,
        router_name="Router",
        vendor=vendor,
        organization_id=None,
        organization_name=None,
        location_id=location_id,
        location_name="Venue",
        export=SimpleNamespace(
            enabled=on,
            configured_at=NOW,
            last_verified_at=NOW,
            last_verdict_ok=True,
            last_verdict_detail="verified",
        ),
    )


def _service(
    repo: Repo | None = None,
    *,
    locations: Locations | None = None,
    confined_to: frozenset[uuid.UUID] | None = None,
    enabled: bool = True,
) -> TrafficFlowCustomerService:
    return TrafficFlowCustomerService(
        repo or Repo(),  # type: ignore[arg-type]
        locations or Locations(),
        SimpleNamespace(  # type: ignore[arg-type]
            traffic_flow_enabled=enabled,
            traffic_flow_agent_url="",
            traffic_flow_agent_secret="",
        ),
        caller_location_scope=confined_to,
        now=lambda: NOW,
    )


async def _summary(service: TrafficFlowCustomerService, venue: uuid.UUID, **kw: Any):
    args: dict[str, Any] = {"organization_id": ORG_A, "since": None, "until": None}
    args.update(kw)
    return await service.summary(venue, **args)


def _two_venues() -> Repo:
    repo = Repo()
    repo.windows = [
        _window(10, location_id=VENUE_A, router_id=ROUTER_A, up=100, down=900),
        _window(10, location_id=VENUE_B, router_id=ROUTER_B, up=7_000, down=70_000),
    ]
    repo.routers = [_router(ROUTER_A, VENUE_A), _router(ROUTER_B, VENUE_B)]
    return repo


# ---------------------------------------------------------------------------
# scoping
# ---------------------------------------------------------------------------


class TestScoping:
    async def test_own_venue_returns_only_that_venues_traffic(self) -> None:
        repo = _two_venues()
        data = await _summary(_service(repo), VENUE_A)
        assert data["measured"] is True and data["location_id"] == str(VENUE_A)
        assert (data["totals"]["bytes_up"], data["totals"]["bytes_down"]) == (100, 900)
        # Every read was filtered on the venue, and on nothing wider.
        assert repo.scopes and all(s.location_id == VENUE_A for s in repo.scopes)
        assert repo.fleet_asked == [VENUE_A]

    async def test_another_organizations_venue_is_a_404_and_nothing_is_read(
        self,
    ) -> None:
        repo = _two_venues()
        service = _service(repo)
        with pytest.raises(TrafficFlowLocationNotFoundError) as exc:
            await _summary(service, VENUE_B)
        assert exc.value.status_code == 404
        with pytest.raises(TrafficFlowLocationNotFoundError):
            await service.status(VENUE_B, organization_id=ORG_A)
        assert repo.scopes == [] and repo.fleet_asked == []

    async def test_a_missing_venue_gets_the_same_answer_as_a_foreign_one(
        self,
    ) -> None:
        missing = uuid.uuid4()
        with pytest.raises(TrafficFlowLocationNotFoundError) as unknown:
            await _summary(_service(), missing)
        with pytest.raises(TrafficFlowLocationNotFoundError) as foreign:
            await _summary(_service(), VENUE_B)
        # No oracle for "that venue exists, it just is not yours".
        assert unknown.value.status_code == foreign.value.status_code == 404
        assert unknown.value.data == foreign.value.data

    async def test_the_boundary_does_not_rest_on_the_lookup_alone(self) -> None:
        """A lookup that returned another organization's venue without
        complaint must still not get its traffic read."""
        repo = _two_venues()
        service = _service(repo, locations=Locations(trusting=True))
        with pytest.raises(TrafficFlowLocationNotFoundError):
            await _summary(service, VENUE_B)
        assert repo.scopes == []

    async def test_the_organization_asked_about_is_the_callers(self) -> None:
        locations = Locations()
        await _summary(_service(_two_venues(), locations=locations), VENUE_A)
        assert locations.asked == [(VENUE_A, ORG_A)]

    async def test_a_caller_confined_to_one_venue_cannot_read_a_sibling(
        self,
    ) -> None:
        repo = _two_venues()
        service = _service(repo, confined_to=frozenset({VENUE_A}))
        assert (await _summary(service, VENUE_A))["measured"] is True
        with pytest.raises(TrafficFlowCrossLocationError) as exc:
            await _summary(service, VENUE_A2)  # same organization, other venue
        assert exc.value.status_code == 403
        with pytest.raises(TrafficFlowCrossLocationError):
            await service.status(VENUE_A2, organization_id=ORG_A)

    async def test_a_router_filter_cannot_reach_outside_the_venue(self) -> None:
        repo = _two_venues()
        data = await _summary(_service(repo), VENUE_A, router_id=ROUTER_B)
        # The other venue's router narrows *within* this venue: nothing.
        assert data["measured"] is False and data["totals"] is None
        assert all(s.location_id == VENUE_A for s in repo.scopes)

    def test_header_naming_another_venue_is_refused(self) -> None:
        """RequirePermission checks the header's venue when one is sent. A
        different venue in the path was therefore never checked."""
        customer_router._same_venue(VENUE_A, None)  # noqa: SLF001
        customer_router._same_venue(VENUE_A, VENUE_A)  # noqa: SLF001
        with pytest.raises(TrafficFlowCrossLocationError):
            customer_router._same_venue(VENUE_A, VENUE_A2)  # noqa: SLF001

    async def test_range_rules_are_the_master_ones(self) -> None:
        with pytest.raises(TrafficFlowError) as exc:
            await _summary(
                _service(_two_venues()),
                VENUE_A,
                since=NOW - timedelta(days=8),
                until=NOW,
            )
        assert exc.value.code == "TRAFFIC_FLOW_WINDOW_TOO_LARGE"


# ---------------------------------------------------------------------------
# a venue with no data, and the three states
# ---------------------------------------------------------------------------


class TestCollectionState:
    @pytest.mark.parametrize(
        ("states", "want"),
        [
            ([FlowState.RECEIVING], CustomerCollection.COLLECTING),
            ([FlowState.SILENT, FlowState.RECEIVING], CustomerCollection.COLLECTING),
            (
                [FlowState.UNSUPPORTED_VENDOR, FlowState.RECEIVING],
                CustomerCollection.COLLECTING,
            ),
            ([FlowState.AWAITING_FIRST_DATA], CustomerCollection.NOT_COLLECTING_YET),
            ([FlowState.NOT_CONFIGURED], CustomerCollection.NOT_COLLECTING_YET),
            ([FlowState.SILENT], CustomerCollection.NOT_COLLECTING_YET),
            ([FlowState.FEATURE_OFF], CustomerCollection.NOT_COLLECTING_YET),
            ([FlowState.UNSUPPORTED_VENDOR], CustomerCollection.NOT_AVAILABLE),
            ([], CustomerCollection.NOT_AVAILABLE),
        ],
    )
    def test_router_states_fold_into_three(self, states, want) -> None:  # noqa: ANN001
        assert customer_collection(s.value for s in states) == want

    async def test_venue_with_no_data_is_not_measured_not_zero(self) -> None:
        repo = Repo()
        repo.routers = [_router(ROUTER_A, VENUE_A)]
        service = _service(repo)
        data = await _summary(service, VENUE_A)
        assert data["measured"] is False and data["totals"] is None
        assert data["collection"] == "not_collecting_yet"
        assert data["latest_data"] is None and data["data_oldest"] is None
        assert data["timeline"]["steps"] == [] and data["devices"]["items"] == []
        assert data["destinations"] == {
            "min_devices": CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS,
            "windows_withheld": 0,
            "items": [],
            "other_bytes_at_most": 0,
        }
        status = await service.status(VENUE_A, organization_id=ORG_A)
        assert status == {
            "location_id": str(VENUE_A),
            "collection": "not_collecting_yet",
            "latest_data": None,
            "data_starts": None,
            "window_seconds": 300,
            "retention_days": 7,
        }

    async def test_venue_on_other_equipment_is_not_available(self) -> None:
        repo = Repo()
        repo.routers = [_router(ROUTER_A, VENUE_A, vendor="omada", on=False)]
        status = await _service(repo).status(VENUE_A, organization_id=ORG_A)
        assert status["collection"] == "not_available"
        repo.routers = []
        status = await _service(repo).status(VENUE_A, organization_id=ORG_A)
        assert status["collection"] == "not_available"

    async def test_collecting_reports_freshness_as_the_end_of_the_window(self) -> None:
        status = await _service(_two_venues()).status(VENUE_A, organization_id=ORG_A)
        assert status["collection"] == "collecting"
        assert status["latest_data"] == (NOW - timedelta(minutes=5)).isoformat()
        assert status["data_starts"] == (NOW - timedelta(minutes=10)).isoformat()

    async def test_data_stopped_keeps_its_last_time(self) -> None:
        repo = Repo()
        repo.windows = [_window(180)]
        repo.routers = [_router(ROUTER_A, VENUE_A)]
        status = await _service(repo).status(VENUE_A, organization_id=ORG_A)
        assert status["collection"] == "not_collecting_yet"
        assert status["latest_data"] == (NOW - timedelta(minutes=175)).isoformat()

    async def test_platform_flag_off_shows_nothing_as_collecting(self) -> None:
        data = await _summary(_service(_two_venues(), enabled=False), VENUE_A)
        assert data["measured"] is False and data["collection"] == "not_collecting_yet"


# ---------------------------------------------------------------------------
# what a customer response contains
# ---------------------------------------------------------------------------

_FORBIDDEN_WORDS = (
    "tunnel",
    "wireguard",
    "exporter",
    "collector",
    "netflow",
    "ipfix",
    "verdict",
    "configured",
    "feature_enabled",
    "agent",
)


class TestResponseContent:
    async def test_a_device_is_an_address_and_a_session_reference_only(self) -> None:
        data = await _summary(_service(_two_venues()), VENUE_A)
        (device,) = data["devices"]["items"]
        assert set(device) == {
            "router_id",
            "ip",
            "bytes_up",
            "bytes_down",
            "bytes",
            "flows",
            "share_at_least",
            "match",
            "guest_session_id",
        }
        assert device["ip"] == DEVICE and device["match"] == "session"

    async def test_no_field_pairs_a_device_with_a_destination(self) -> None:
        data = await _summary(_service(_two_venues()), VENUE_A)
        (destination,) = data["destinations"]["items"]
        assert destination["ip"] == REMOTE
        assert REMOTE not in json.dumps(data["devices"])
        assert DEVICE not in json.dumps(data["destinations"])
        # ...and neither address is anywhere in the service figures.
        services = json.dumps([data["services"], data["timeline"], data["protocols"]])
        assert DEVICE not in services and REMOTE not in services
        # Each address appears in exactly one place in the whole response.
        text = json.dumps(data)
        assert text.count(DEVICE) == 1 and text.count(REMOTE) == 1

    @pytest.mark.parametrize("call", ["summary", "status"])
    async def test_no_router_or_collector_internals(self, call: str) -> None:
        service = _service(_two_venues())
        if call == "summary":
            data = await _summary(service, VENUE_A)
        else:
            data = await service.status(VENUE_A, organization_id=ORG_A)
        text = json.dumps(data).lower()
        assert EXPORTER not in text
        for word in _FORBIDDEN_WORDS:
            assert word not in text, word

    async def test_the_same_figures_as_the_master_view(self) -> None:
        data = await _summary(_service(_two_venues()), VENUE_A)
        assert data["services"]["items"][0]["port"] == 443
        assert data["services"]["exact"] is True
        assert [p["protocol_name"] for p in data["protocols"]] == [
            "tcp",
            "udp",
            "icmp",
            "other",
        ]
        assert data["timeline"]["series"][0]["key"] == "6/443"
        assert data["list_accuracy"]["lower_bound"] is True
        assert data["latest_data"] == (NOW - timedelta(minutes=5)).isoformat()

    async def test_destinations_are_withheld_when_few_devices_are_online(self) -> None:
        repo = Repo()
        repo.routers = [_router(ROUTER_A, VENUE_A)]
        repo.windows = [
            _window(15, devices=CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS - 1),
            _window(10, devices=1),
        ]
        data = await _summary(_service(repo), VENUE_A)
        destinations = data["destinations"]
        assert destinations["items"] == []
        assert destinations["windows_withheld"] == data["windows"] == 2
        assert destinations["min_devices"] == CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS
        # Nothing that holds no address is affected.
        assert data["totals"]["bytes_down"] == 1800
        assert data["services"]["items"] and data["devices"]["items"]

    async def test_only_the_busy_windows_feed_the_destination_list(self) -> None:
        repo = Repo()
        repo.routers = [_router(ROUTER_A, VENUE_A)]
        repo.windows = [
            _window(15, devices=CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS, up=0, down=500),
            _window(10, devices=2, up=0, down=300),
        ]
        data = await _summary(_service(repo), VENUE_A)
        (destination,) = data["destinations"]["items"]
        assert destination["bytes"] == 500  # the quiet window's 300 is not in it
        assert data["destinations"]["windows_withheld"] == 1


# ---------------------------------------------------------------------------
# entitlement
# ---------------------------------------------------------------------------


def _closure(call: Any) -> list[Any]:
    return [c.cell_contents for c in (getattr(call, "__closure__", None) or ())]


def _feature_guard() -> Any:
    (guard,) = [
        g.dependency
        for g in customer_router._GUARDS  # noqa: SLF001
        if PlanFeatureKey.TRAFFIC_FLOW in _closure(g.dependency)
    ]
    return guard


def _snapshot(*features: str) -> Any:
    return SimpleNamespace(
        enabled_features=frozenset(features),
        limits={"max_locations": Decimal(1)},
        has_feature=lambda key: key.value in features,
    )


class _Checker:
    def __init__(self, *features: str) -> None:
        self.features = features

    async def get_snapshot(self, organization_id: uuid.UUID) -> Any:
        return _snapshot(*self.features)


class TestEntitlement:
    async def test_add_on_off_is_a_402_naming_the_feature(self) -> None:
        with pytest.raises(FeatureNotEntitledError) as exc:
            await _feature_guard()(organization_id=ORG_A, checker=_Checker("reports"))
        assert exc.value.status_code == 402
        assert exc.value.data == {
            "error_code": "feature_not_entitled",
            "feature_key": "traffic_flow",
        }

    async def test_add_on_on_passes(self) -> None:
        guard = _feature_guard()
        assert (
            await guard(organization_id=ORG_A, checker=_Checker("traffic_flow"))
            == ORG_A
        )

    def test_it_is_an_add_on_the_master_console_can_switch(self) -> None:
        key = PlanFeatureKey.TRAFFIC_FLOW
        assert key.value == "traffic_flow"
        assert key in ADDON_FEATURE_KEYS and key in BOOLEAN_FEATURE_KEYS
        assert key not in FEATURE_REQUIRES and key not in FEATURE_REQUIRES.values()

    async def test_it_is_off_by_default_and_named_for_the_panel(self) -> None:
        from app.domains.feature_entitlement.service import (
            FEATURE_META,
            FeatureEntitlementService,
        )

        listing = await FeatureEntitlementService(None, None).list_features()  # type: ignore[arg-type]
        (feature,) = [f for f in listing.features if f.key == "traffic_flow"]
        assert feature.default_enabled is False and feature.type == "boolean"
        assert FEATURE_META[PlanFeatureKey.TRAFFIC_FLOW][0] == "Traffic Lens"


# ---------------------------------------------------------------------------
# routes and permission
# ---------------------------------------------------------------------------


def _dependency_calls(dependant: Any) -> set[Any]:
    calls = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        calls |= _dependency_calls(d)
    return calls


class TestRoutes:
    def _routes(self) -> list[Any]:
        return list(customer_router.traffic_flow_customer_router.routes)

    def test_read_only_and_only_these_two(self) -> None:
        assert sorted((sorted(r.methods), r.path) for r in self._routes()) == [
            (["GET"], "/traffic-flow/locations/{location_id}/status"),
            (["GET"], "/traffic-flow/locations/{location_id}/summary"),
        ]

    def test_every_route_carries_all_three_guards(self) -> None:
        for route in self._routes():
            guards = [d.dependency for d in route.dependencies]
            assert guards[0] is RequireOrganization, route.path
            assert PlanFeatureKey.TRAFFIC_FLOW in _closure(guards[1]), route.path
            permission = _closure(guards[2])
            assert "venue_traffic.read" in permission, route.path
            assert ScopeType.LOCATION in permission, route.path
            assert len(guards) == 3

    def test_every_route_resolves_organization_location_and_confinement(self) -> None:
        for route in self._routes():
            calls = _dependency_calls(route.dependant)
            assert RequireOrganization in calls, route.path
            assert CurrentOrganization in calls, route.path
            assert CurrentLocation in calls, route.path
            assert CallerLocationScope in calls, route.path

    def test_no_route_takes_an_organization_from_the_request(self) -> None:
        for route in self._routes():
            names = {p.name for p in route.dependant.path_params}
            names |= {p.name for p in route.dependant.query_params}
            assert "organization_id" not in names, route.path
            assert route.dependant.body_params == []

    def test_mounted_outside_the_platform_prefix(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {r.path for r in api_v1_router.routes}
        assert "/traffic-flow/locations/{location_id}/summary" in paths
        assert "/traffic-flow/locations/{location_id}/status" in paths

    def test_master_routes_are_untouched_by_the_add_on(self) -> None:
        from app.domains.traffic_flow.router import traffic_flow_platform_router

        for route in traffic_flow_platform_router.routes:
            for dependency in route.dependencies:
                assert PlanFeatureKey.TRAFFIC_FLOW not in _closure(
                    dependency.dependency
                )


class TestPermissionSeed:
    def test_module_is_read_only_and_location_scoped(self) -> None:
        actions = MODULE_ACTIONS[PermissionModule.VENUE_TRAFFIC]
        assert [a.value for a in actions] == ["read"]
        assert (
            MODULE_NARROWEST_SCOPE[PermissionModule.VENUE_TRAFFIC] == ScopeType.LOCATION
        )

    def test_only_the_owner_holds_it_among_customer_roles(self) -> None:
        holders = {
            role.slug
            for role in SYSTEM_ROLES
            if role.grants().get(PermissionModule.VENUE_TRAFFIC)
        }
        assert holders == {"super-admin", "platform-admin", "organization-owner"}

    def test_holding_it_does_not_give_the_master_permission(self) -> None:
        owner = next(r for r in SYSTEM_ROLES if r.slug == "organization-owner")
        assert not owner.grants().get(PermissionModule.TRAFFIC_FLOWS)
        assert [a.value for a in owner.grants()[PermissionModule.VENUE_TRAFFIC]] == [
            "read"
        ]
