"""INCIDENTS-1 pure helpers and the route surface (no database)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.domains.isp_partner import incidents_service as S


def test_default_grace_hours_rounds_up_and_caps() -> None:
    t0 = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
    assert S.default_grace_hours(t0, None) == 1
    assert S.default_grace_hours(t0, t0 + timedelta(minutes=10)) == 1
    assert S.default_grace_hours(t0, t0 + timedelta(hours=2, minutes=1)) == 3
    assert S.default_grace_hours(t0, t0 + timedelta(days=30)) == 168


def test_message_texts_name_the_area_and_time() -> None:
    out = S.outage_text("NetA", "Ravi", "Zone North", "01 Nov 2026, 14:05")
    assert "Zone North" in out and "14:05" in out and out.endswith("NetA")
    back = S.restored_text("NetA", "Ravi", "Zone North", "01 Nov 2026, 16:40")
    assert "back" in back and "16:40" in back


def test_csv_cells_cannot_start_a_formula() -> None:
    assert S._csv_safe("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert S._csv_safe("+91 98") == "'+91 98"
    assert S._csv_safe("Ravi") == "Ravi" and S._csv_safe(None) == ""


def test_grants() -> None:
    from app.domains.isp_partner.rbac_roles import ROLES

    def holders(key: str) -> set[str]:
        return {r.slug for r in ROLES if key in r.permission_keys}

    assert holders("isp_incidents.execute") == {"isp-owner", "isp-admin", "isp-noc"}
    assert "isp-technician" in holders("isp_incidents.manage")
    assert "isp-technician" not in holders("isp_incidents.export")


def test_routes_are_flagged_and_outage_triggers_are_wired() -> None:
    from app.domains.isp_partner.automation import OPT_IN_TRIGGERS, TRIGGERS
    from app.domains.isp_partner.comms_logic import EVENTS
    from app.domains.isp_partner.incidents_config import RequireIncidentsEnabled
    from app.domains.isp_partner.incidents_router import incidents_router

    for r in incidents_router.routes:
        assert r.dependencies[0].dependency is RequireIncidentsEnabled, r.path
    paths = [r.path for r in incidents_router.routes]
    # literal paths before /{incident_id}
    assert paths.index("/incidents/health") < paths.index("/incidents/{incident_id}")
    assert paths.index("/incidents/preview") < paths.index("/incidents/{incident_id}")
    for t in ("outage", "restored"):
        assert t in TRIGGERS and t in OPT_IN_TRIGGERS
        assert EVENTS[t]["trigger"] == t and len(EVENTS[t]["vars"]) == 3
