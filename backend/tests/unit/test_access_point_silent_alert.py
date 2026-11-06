"""P2-P: the "access point silent" alert for Aruba Instant On venues.

Same conventions as ``test_monitoring_network_controller_alerts.py``: the
shared in-memory ``FakeRepository`` from ``test_monitoring_alerts.py``,
extended here with the four P2-P reads, and the real repository's SQL
checked by compiling what it builds.

Owner rule: Aruba only. MikroTik and Omada alert behaviour must stay exactly
as it is -- the "unchanged" section pins that.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.dialects import postgresql

from app.domains.monitoring import access_point_silence as aps
from app.domains.monitoring.constants import (
    ACCESS_POINT_SILENT_STATE,
    ALERT_TARGET_ACCESS_POINT_SILENT,
    ALERT_TARGET_NETWORK_CONTROLLER,
    ALERT_TARGET_ROUTER_REACHABILITY,
    AlertStatus,
    AlertTriggerType,
)
from app.domains.monitoring.default_alerting import DEFAULT_ALERT_RULES
from app.domains.monitoring.exceptions import InvalidAlertRuleConfigError
from app.domains.monitoring.repository import (
    IDLE_SWEEP_DISCONNECT_REASON,
    MonitoringRepository,
    UnclosedGuestActivity,
    VenueOpenHours,
)
from app.domains.monitoring.service import AlertService
from app.domains.monitoring.validators import validate_alert_rule_condition_config
from app.domains.network_integration.constants import IntegrationStatus
from tests.unit.test_monitoring_alerts import (
    FakeRepository,
    FakeRouter,
    _alert_rule_fields,
    _ensure_defaults,
)
from tests.unit.test_monitoring_network_controller_alerts import FakeIntegration

ARUBA = "aruba_instant_on"
FORBIDDEN_WORDS = ("offline", " down", "isp", "outage")


def _now() -> datetime:
    return datetime.now(UTC)


def _ago(minutes: float) -> datetime:
    return _now() - timedelta(minutes=minutes)


@dataclass
class FakeAccessPoint:
    """Duck-typed ``ArubaAccessPoint`` -- only what the evaluator reads."""

    organization_id: uuid.UUID
    router_id: uuid.UUID
    mac: str
    name: str | None = None
    status: str = "approved"
    last_seen_at: datetime | None = None
    id: uuid.UUID = field(default_factory=uuid.uuid4)


@dataclass
class ApFakeRepository(FakeRepository):
    """``FakeRepository`` plus the four P2-P reads, keyed by router id. A
    router id absent from a map means "no rows" -- exactly what the real
    grouped queries return."""

    radius: dict[uuid.UUID, datetime] = field(default_factory=dict)
    guests: dict[uuid.UUID, UnclosedGuestActivity] = field(default_factory=dict)
    access_points: list[FakeAccessPoint] = field(default_factory=list)
    hours: dict[uuid.UUID, VenueOpenHours] = field(default_factory=dict)
    asked_router_ids: list[uuid.UUID] = field(default_factory=list)

    async def radius_activity_for_routers(self, router_ids):
        self.asked_router_ids.extend(router_ids)
        return {rid: self.radius[rid] for rid in router_ids if rid in self.radius}

    async def unclosed_guest_activity_for_routers(self, router_ids, *, since):
        self.asked_router_ids.extend(router_ids)
        return {
            rid: self.guests[rid]
            for rid in router_ids
            if rid in self.guests and self.guests[rid].last_activity_at >= since
        }

    async def list_aruba_access_points(self, *, organization_id, router_ids):
        return [
            ap
            for ap in self.access_points
            if ap.organization_id == organization_id and ap.router_id in router_ids
        ]

    async def open_hours_for_locations(self, *, organization_id, location_ids):
        return {lid: self.hours[lid] for lid in location_ids if lid in self.hours}


def _router(
    org_id: uuid.UUID, *, vendor: str = ARUBA, name: str = "Cafe"
) -> FakeRouter:
    return FakeRouter(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        name=name,
        health_status=None,
        vendor=vendor,
    )


def _guests(router: FakeRouter, *, count: int, last: datetime) -> UnclosedGuestActivity:
    return UnclosedGuestActivity(
        router_id=router.id, sessions=count, last_activity_at=last
    )


async def _harness(
    org_id: uuid.UUID, **config: object
) -> tuple[ApFakeRepository, AlertService]:
    repo = ApFakeRepository()
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=ALERT_TARGET_ACCESS_POINT_SILENT,
            condition_config={"expected_status": ACCESS_POINT_SILENT_STATE, **config},
            organization_id=org_id,
        )
    )
    return repo, AlertService(repo)


def _open(repo: FakeRepository):
    return [a for a in repo.alerts.values() if a.status != AlertStatus.RESOLVED.value]


def _assert_honest(message: str) -> None:
    lowered = message.lower()
    for word in FORBIDDEN_WORDS:
        assert word not in lowered, (word, message)


# ============================================================================
# Validator
# ============================================================================


@pytest.mark.parametrize(
    "config",
    [
        {"expected_status": "silent"},
        {
            "expected_status": "silent",
            "silence_minutes": 45,
            "use_open_hours": True,
            "open_hours_silence_minutes": 90,
            "per_access_point": True,
            "access_point_silence_minutes": 60,
        },
    ],
)
def test_valid_configs_are_accepted(config: dict) -> None:
    validate_alert_rule_condition_config(
        AlertTriggerType.HEALTH_STATUS_CHANGE, ALERT_TARGET_ACCESS_POINT_SILENT, config
    )


@pytest.mark.parametrize(
    "config",
    [
        {"expected_status": "down"},
        {"expected_status": "silent", "silence_minutes": 5},
        {"expected_status": "silent", "silence_minutes": 99999},
        {"expected_status": "silent", "silence_minutes": True},
        {"expected_status": "silent", "silence_minutes": "30"},
        {"expected_status": "silent", "open_hours_silence_minutes": 10},
        {"expected_status": "silent", "access_point_silence_minutes": 10},
        {"expected_status": "silent", "use_open_hours": "yes"},
        {"expected_status": "silent", "per_access_point": 1},
    ],
)
def test_invalid_configs_are_refused(config: dict) -> None:
    with pytest.raises(InvalidAlertRuleConfigError):
        validate_alert_rule_condition_config(
            AlertTriggerType.HEALTH_STATUS_CHANGE,
            ALERT_TARGET_ACCESS_POINT_SILENT,
            config,
        )


def test_defaults_are_conservative() -> None:
    config = aps.AccessPointSilentConfig.from_condition_config(
        {"expected_status": "silent"}
    )
    assert config.silence == timedelta(minutes=30)
    assert config.use_open_hours is False
    assert config.per_access_point is False
    assert config.access_point_silence == timedelta(minutes=120)


def test_idle_sweep_reason_matches_the_guest_domain() -> None:
    from app.domains.guest.service import SESSION_TIMEOUT_DISCONNECT_REASON

    assert IDLE_SWEEP_DISCONNECT_REASON == SESSION_TIMEOUT_DISCONNECT_REASON


# ============================================================================
# Venue level: guests connected, then silence
# ============================================================================


async def test_an_idle_venue_with_no_guests_never_pages() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org)
    router = _router(org)
    repo.routers.append(router)
    repo.radius[router.id] = _ago(10 * 60)  # quiet all night

    result = await service.evaluate_alert_rules()

    assert result.triggered == [] and result.skipped_rules == 0


async def test_silence_while_guests_were_connected_alerts_once() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org)
    router = _router(org, name="Blue Cafe")
    repo.routers.append(router)
    repo.radius[router.id] = _ago(40)
    repo.guests[router.id] = _guests(router, count=3, last=_ago(42))

    result = await service.evaluate_alert_rules()

    (alert,) = result.triggered
    assert alert.organization_id == org
    assert alert.router_id == router.id
    assert alert.location_id == router.location_id
    assert alert.subject_id is None
    assert alert.message.startswith("Blue Cafe:")
    assert "3 guests were still connected" in alert.message
    assert "40 minutes" in alert.message
    assert "Instant On app" in alert.message
    _assert_honest(alert.message)

    again = await service.evaluate_alert_rules()
    assert again.triggered == []
    assert len(_open(repo)) == 1


async def test_inside_the_silence_window_nothing_fires() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org)
    router = _router(org)
    repo.routers.append(router)
    repo.radius[router.id] = _ago(20)  # under the 30-minute default
    repo.guests[router.id] = _guests(router, count=2, last=_ago(21))

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_the_window_is_configurable() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org, silence_minutes=60)
    router = _router(org)
    repo.routers.append(router)
    repo.radius[router.id] = _ago(40)
    repo.guests[router.id] = _guests(router, count=1, last=_ago(41))

    assert (await service.evaluate_alert_rules()).triggered == []
    repo.radius[router.id] = _ago(61)
    repo.guests[router.id] = _guests(router, count=1, last=_ago(62))
    (alert,) = (await service.evaluate_alert_rules()).triggered
    assert "1 guest was still connected" in alert.message


async def test_guests_who_went_quiet_long_before_the_venue_do_not_count() -> None:
    """A guest whose last report was hours before the venue's last packet was
    not on when the venue went quiet; their stale row is not evidence."""
    org = uuid.uuid4()
    repo, service = await _harness(org)
    router = _router(org)
    repo.routers.append(router)
    repo.radius[router.id] = _ago(45)
    repo.guests[router.id] = _guests(router, count=1, last=_ago(45 + 60))

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_a_venue_never_heard_from_is_not_a_finding() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org)
    router = _router(org)
    repo.routers.append(router)
    repo.guests[router.id] = _guests(router, count=1, last=_ago(60))

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_resolves_only_when_the_venue_is_heard_again() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org)
    router = _router(org, name="Blue Cafe")
    repo.routers.append(router)
    repo.radius[router.id] = _ago(40)
    repo.guests[router.id] = _guests(router, count=2, last=_ago(41))
    (alert,) = (await service.evaluate_alert_rules()).triggered

    # The guest evidence ages out (idle sweep, lookback): still silent, so
    # the alert must stay open.
    repo.guests.clear()
    assert (await service.evaluate_alert_rules()).resolved == []
    assert alert.status != AlertStatus.RESOLVED.value

    repo.radius[router.id] = _ago(1)
    (resolved,) = (await service.evaluate_alert_rules()).resolved
    assert resolved.id == alert.id
    assert resolved.message == (
        "Blue Cafe: your Aruba Instant On access points are reporting guest "
        "activity again."
    )


async def test_an_alert_for_a_venue_that_is_gone_is_closed_and_says_why() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org)
    router = _router(org)
    repo.routers.append(router)
    repo.radius[router.id] = _ago(40)
    repo.guests[router.id] = _guests(router, count=2, last=_ago(41))
    await service.evaluate_alert_rules()

    repo.routers.clear()
    (resolved,) = (await service.evaluate_alert_rules()).resolved
    assert resolved.message == aps.VENUE_GONE_MESSAGE


# ============================================================================
# Venue level: open hours (opt-in)
# ============================================================================

_ALL_DAY = {
    day: {"open": True, "start": "00:00", "end": "23:59"}
    for day in (
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    )
}


def test_opened_at_is_todays_start_in_the_venues_zone() -> None:
    now = datetime(2026, 10, 5, 8, 0, tzinfo=UTC)  # Monday 13:30 in Kolkata
    schedule = {"monday": {"open": True, "start": "09:00", "end": "22:00"}}
    opened = aps.opened_at(
        enabled=True, timezone="Asia/Kolkata", schedule=schedule, now=now
    )
    assert opened is not None
    assert opened.astimezone(UTC) == datetime(2026, 10, 5, 3, 30, tzinfo=UTC)
    # Closed now, or hours switched off: no expectation of guests.
    late = datetime(2026, 10, 5, 18, 0, tzinfo=UTC)  # 23:30 Kolkata
    assert (
        aps.opened_at(
            enabled=True, timezone="Asia/Kolkata", schedule=schedule, now=late
        )
        is None
    )
    assert (
        aps.opened_at(
            enabled=False, timezone="Asia/Kolkata", schedule=schedule, now=now
        )
        is None
    )


async def test_open_hours_are_ignored_unless_the_owner_opts_in() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org)
    router = _router(org)
    repo.routers.append(router)
    repo.radius[router.id] = _ago(5 * 60)
    repo.hours[router.location_id] = VenueOpenHours(True, "UTC", _ALL_DAY)

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_open_and_silent_past_the_window_alerts_when_opted_in() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org, use_open_hours=True)
    router = _router(org, name="Blue Cafe")
    repo.routers.append(router)
    repo.radius[router.id] = _ago(5 * 60)
    # Open since a fixed point far enough back; built so it is open "now".
    start = _now() - timedelta(hours=3)
    if start.date() != _now().date():
        pytest.skip("window straddles midnight UTC")
    schedule = {
        day: {"open": True, "start": start.strftime("%H:%M"), "end": "23:59"}
        for day in _ALL_DAY
    }
    repo.hours[router.location_id] = VenueOpenHours(True, "UTC", schedule)

    (alert,) = (await service.evaluate_alert_rules()).triggered
    assert "during your open hours" in alert.message
    assert "can simply mean no guests have connected" in alert.message
    _assert_honest(alert.message)


def test_opening_time_does_not_count_last_nights_quiet() -> None:
    config = aps.AccessPointSilentConfig.from_condition_config(
        {"expected_status": "silent", "use_open_hours": True}
    )
    now = _now()
    assert (
        aps.venue_silence_reason(
            now=now,
            last_radius_at=now - timedelta(hours=10),
            unclosed_guest_last_activity_at=None,
            open_since=now - timedelta(minutes=20),
            config=config,
        )
        is None
    )
    assert (
        aps.venue_silence_reason(
            now=now,
            last_radius_at=now - timedelta(hours=10),
            unclosed_guest_last_activity_at=None,
            open_since=now - timedelta(minutes=121),
            config=config,
        )
        == aps.REASON_OPEN_HOURS
    )


async def test_closed_venue_with_hours_on_does_not_page() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org, use_open_hours=True)
    router = _router(org)
    repo.routers.append(router)
    repo.radius[router.id] = _ago(5 * 60)
    repo.hours[router.location_id] = VenueOpenHours(True, "UTC", {})  # no open day

    assert (await service.evaluate_alert_rules()).triggered == []


# ============================================================================
# Per access point (opt-in)
# ============================================================================


def _aps(org: uuid.UUID, router: FakeRouter, *last_seen: datetime | None):
    return [
        FakeAccessPoint(
            organization_id=org,
            router_id=router.id,
            mac=f"AA:BB:CC:DD:EE:0{i}",
            name=f"AP {i}",
            last_seen_at=seen,
        )
        for i, seen in enumerate(last_seen, start=1)
    ]


async def test_per_ap_is_off_by_default() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org)
    router = _router(org)
    repo.routers.append(router)
    repo.radius[router.id] = _ago(1)
    repo.access_points = _aps(org, router, _ago(1), _ago(3 * 60))

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_a_stale_ap_beside_an_active_sibling_alerts() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org, per_access_point=True)
    router = _router(org, name="Blue Cafe")
    repo.routers.append(router)
    repo.radius[router.id] = _ago(1)
    active, stale = _aps(org, router, _ago(2), _ago(3 * 60))
    repo.access_points = [active, stale]

    (alert,) = (await service.evaluate_alert_rules()).triggered
    assert alert.subject_id == stale.id
    assert alert.router_id == router.id
    assert alert.message.startswith(
        "Access point AP 2 (AA:BB:CC:DD:EE:02) at Blue Cafe: no guest activity "
        "for 3 hours, while other access points there are serving guests."
    )
    _assert_honest(alert.message)

    stale.last_seen_at = _ago(1)
    (resolved,) = (await service.evaluate_alert_rules()).resolved
    assert resolved.id == alert.id
    assert "reporting guest activity again" in resolved.message


@pytest.mark.parametrize(
    "siblings_seen, stale_seen",
    [
        ((180,), 200),  # sibling quiet too: a quiet venue, not a dead AP
        ((2,), 60),  # under the 120-minute per-AP window
        ((2,), None),  # never seen: approved but not installed yet
        ((2,), 3 * 24 * 60),  # silent for days: a known state, not news
        ((), 200),  # a single-AP venue has no sibling to compare against
    ],
)
async def test_per_ap_does_not_fire(siblings_seen, stale_seen) -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org, per_access_point=True)
    router = _router(org)
    repo.routers.append(router)
    repo.radius[router.id] = _ago(1)
    seen = [_ago(m) for m in siblings_seen]
    repo.access_points = _aps(
        org, router, *seen, None if stale_seen is None else _ago(stale_seen)
    )

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_pending_and_rejected_aps_are_not_judged() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org, per_access_point=True)
    router = _router(org)
    repo.routers.append(router)
    active, stale = _aps(org, router, _ago(2), _ago(3 * 60))
    stale.status = "pending"
    repo.access_points = [active, stale]

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_an_unapproved_ap_closes_its_alert_and_says_why() -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org, per_access_point=True)
    router = _router(org)
    repo.routers.append(router)
    repo.radius[router.id] = _ago(1)
    active, stale = _aps(org, router, _ago(2), _ago(3 * 60))
    repo.access_points = [active, stale]
    await service.evaluate_alert_rules()

    stale.status = "rejected"
    (resolved,) = (await service.evaluate_alert_rules()).resolved
    assert resolved.message == (
        "Access point AP 2 (AA:BB:CC:DD:EE:02) was removed or is no longer "
        "approved for this venue, so this alert was closed."
    )


# ============================================================================
# Organization scoping
# ============================================================================


async def test_another_organizations_venue_is_not_this_rules_business() -> None:
    mine, theirs = uuid.uuid4(), uuid.uuid4()
    repo, service = await _harness(mine, per_access_point=True)
    other = _router(theirs)
    repo.routers.append(other)
    repo.radius[other.id] = _ago(40)
    repo.guests[other.id] = _guests(other, count=2, last=_ago(41))
    repo.access_points = _aps(theirs, other, _ago(2), _ago(3 * 60))

    result = await service.evaluate_alert_rules()

    assert result.triggered == []
    assert other.id not in repo.asked_router_ids


async def test_an_organization_less_rule_evaluates_nothing() -> None:
    repo = ApFakeRepository()
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=ALERT_TARGET_ACCESS_POINT_SILENT,
            condition_config={"expected_status": ACCESS_POINT_SILENT_STATE},
            organization_id=None,
        )
    )
    router = _router(uuid.uuid4())
    repo.routers.append(router)
    repo.radius[router.id] = _ago(40)
    repo.guests[router.id] = _guests(router, count=2, last=_ago(41))

    result = await AlertService(repo).evaluate_alert_rules()

    assert result.triggered == [] and result.skipped_rules == 0
    assert repo.asked_router_ids == []


async def _create(service: AlertService, org_id: uuid.UUID | None):
    return await service.create_alert_rule(
        name="Access point silent",
        description=None,
        organization_id=org_id,
        trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
        target_component=ALERT_TARGET_ACCESS_POINT_SILENT,
        condition_config={"expected_status": ACCESS_POINT_SILENT_STATE},
        severity="warning",
    )


async def test_create_requires_one_organization_with_an_aruba_venue() -> None:
    repo = ApFakeRepository()
    service = AlertService(repo)
    with pytest.raises(InvalidAlertRuleConfigError):
        await _create(service, None)

    mikrotik_only = uuid.uuid4()
    repo.routers.append(_router(mikrotik_only, vendor="mikrotik"))
    repo.routers.append(_router(mikrotik_only, vendor="tplink_omada"))
    with pytest.raises(InvalidAlertRuleConfigError):
        await _create(service, mikrotik_only)

    aruba_org = uuid.uuid4()
    repo.routers.append(_router(aruba_org))
    rule = await _create(service, aruba_org)
    assert rule.organization_id == aruba_org


# ============================================================================
# MikroTik / Omada unchanged (owner rule)
# ============================================================================


def test_not_a_default_rule_so_never_backfilled() -> None:
    assert ALERT_TARGET_ACCESS_POINT_SILENT not in {
        rule["target_component"] for rule in DEFAULT_ALERT_RULES
    }


async def test_ensure_default_alerting_does_not_create_it() -> None:
    repo = ApFakeRepository()
    org = uuid.uuid4()
    repo.routers.append(_router(org))  # even an Aruba org
    await _ensure_defaults(repo, org, "owner@venue.example")
    assert ALERT_TARGET_ACCESS_POINT_SILENT not in {
        rule.target_component for rule in repo.alert_rules.values()
    }


@pytest.mark.parametrize("rule", DEFAULT_ALERT_RULES, ids=lambda r: r["name"])
def test_every_existing_default_still_validates(rule) -> None:
    validate_alert_rule_condition_config(
        rule["trigger_type"], rule["target_component"], rule["condition_config"]
    )


@pytest.mark.parametrize("vendor", ["mikrotik", "tplink_omada"])
async def test_never_reads_or_alerts_on_mikrotik_or_omada_rows(vendor) -> None:
    org = uuid.uuid4()
    repo, service = await _harness(org, per_access_point=True, use_open_hours=True)
    aruba = _router(org)
    repo.routers.append(aruba)
    router = _router(org, vendor=vendor)
    repo.routers.append(router)
    # Data that WOULD fire if this row were judged.
    repo.radius[router.id] = _ago(40)
    repo.guests[router.id] = _guests(router, count=5, last=_ago(41))
    repo.hours[router.location_id] = VenueOpenHours(True, "UTC", _ALL_DAY)

    result = await service.evaluate_alert_rules()

    assert result.triggered == []
    assert router.id not in repo.asked_router_ids


async def _non_aruba_outcome(with_ap_rule: bool) -> list[tuple]:
    org = uuid.uuid4()
    repo = ApFakeRepository()
    await _ensure_defaults(repo, org, "owner@venue.example")
    if with_ap_rule:
        await repo.create_alert_rule(
            **_alert_rule_fields(
                trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
                target_component=ALERT_TARGET_ACCESS_POINT_SILENT,
                condition_config={
                    "expected_status": ACCESS_POINT_SILENT_STATE,
                    "per_access_point": True,
                    "use_open_hours": True,
                },
                organization_id=org,
            )
        )
    mikrotik = _router(org, vendor="mikrotik", name="Hall Router")
    mikrotik.reachability_state = "unreachable"
    aruba = _router(org, name="Garden AP")
    repo.routers.extend([mikrotik, aruba])
    repo.radius[aruba.id] = _ago(40)
    repo.guests[aruba.id] = _guests(aruba, count=1, last=_ago(41))
    omada = FakeIntegration(organization_id=org, name="Lobby Omada")
    omada.failing(IntegrationStatus.CONNECTION_FAILED, 5)
    repo.network_integrations.append(omada)

    result = await AlertService(repo).evaluate_alert_rules()
    assert result.skipped_rules == 0
    targets = {r.id: r.target_component for r in repo.alert_rules.values()}
    return sorted(
        (targets[a.rule_id], str(a.router_id == mikrotik.id), a.message)
        for a in result.triggered
        if targets[a.rule_id] != ALERT_TARGET_ACCESS_POINT_SILENT
    )


async def test_mikrotik_and_omada_alerts_are_identical_with_the_rule_on() -> None:
    without = await _non_aruba_outcome(with_ap_rule=False)
    with_rule = await _non_aruba_outcome(with_ap_rule=True)
    assert without == with_rule
    fired = {target for target, _, _ in without}
    assert ALERT_TARGET_ROUTER_REACHABILITY in fired
    assert ALERT_TARGET_NETWORK_CONTROLLER in fired


# ============================================================================
# The real repository's SQL
# ============================================================================


class _CapturingSession:
    def __init__(self) -> None:
        self.statements: list[object] = []

    async def execute(self, statement: object) -> object:
        self.statements.append(statement)

        class _Result:
            def all(self) -> list[object]:
                return []

            def scalars(self):
                return self

        return _Result()


def _sql(statement: object) -> str:
    return str(statement.compile(dialect=postgresql.dialect()))


async def test_repository_reads_are_scoped_and_grouped() -> None:
    session = _CapturingSession()
    repo = MonitoringRepository(session)  # type: ignore[arg-type]
    org, router_id, location_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    assert await repo.radius_activity_for_routers([router_id]) == {}
    assert (
        await repo.unclosed_guest_activity_for_routers([router_id], since=_now()) == {}
    )
    assert (
        await repo.list_aruba_access_points(organization_id=org, router_ids=[router_id])
        == []
    )
    assert (
        await repo.open_hours_for_locations(
            organization_id=org, location_ids=[location_id]
        )
        == {}
    )
    radius, guests, access_points, hours = (_sql(s) for s in session.statements)

    assert "GROUP BY radius_nas_clients.router_id" in radius
    assert "greatest(max(radius_nas_clients.last_request_at)" in radius
    assert "GROUP BY guest_sessions.router_id" in guests
    assert "guest_sessions.last_activity_at >=" in guests
    assert "guest_sessions.disconnect_reason =" in guests
    assert "aruba_access_points.organization_id =" in access_points
    assert "aruba_access_points.is_deleted IS false" in access_points
    assert "captive_portal_configs.organization_id =" in hours
    assert "routers" not in " ".join((radius, guests, access_points, hours)).replace(
        "router_id", ""
    )


async def test_empty_inputs_issue_no_queries() -> None:
    session = _CapturingSession()
    repo = MonitoringRepository(session)  # type: ignore[arg-type]
    org = uuid.uuid4()
    assert await repo.radius_activity_for_routers([]) == {}
    assert await repo.unclosed_guest_activity_for_routers([], since=_now()) == {}
    assert await repo.list_aruba_access_points(organization_id=org, router_ids=[]) == []
    assert (
        await repo.open_hours_for_locations(organization_id=org, location_ids=[]) == {}
    )
    assert session.statements == []


def test_format_quiet_for() -> None:
    assert aps.format_quiet_for(timedelta(minutes=45)) == "45 minutes"
    assert aps.format_quiet_for(timedelta(minutes=60)) == "1 hour"
    assert aps.format_quiet_for(timedelta(minutes=130)) == "2 hours 10 minutes"
    assert aps.format_quiet_for(timedelta(seconds=10)) == "1 minute"
