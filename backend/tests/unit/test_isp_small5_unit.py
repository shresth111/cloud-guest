"""SMALL-5: auto-incident settings view, routes' guard shape, RFO label."""

from __future__ import annotations

from types import SimpleNamespace

from app.domains.isp_partner import incident_auto as auto


def test_settings_view_defaults_off() -> None:
    assert auto.settings_view(None) == {
        "enabled": False,
        "down_minutes": 10,
        "up_minutes": 15,
    }
    row = SimpleNamespace(enabled=True, down_minutes=3, up_minutes=4)
    assert auto.settings_view(row) == {
        "enabled": True,
        "down_minutes": 3,
        "up_minutes": 4,
    }


def test_routes_flag_gated_and_own_prefix() -> None:
    from app.domains.isp_partner.incident_auto_router import incident_auto_router
    from app.domains.isp_partner.incidents_config import RequireIncidentsEnabled

    for r in incident_auto_router.routes:
        assert r.path.startswith("/incident-auto/"), r.path
        assert RequireIncidentsEnabled in [d.dependency for d in r.dependencies]


def test_auto_rfo_has_a_label_but_is_not_offered() -> None:
    from app.domains.isp_partner.incidents_service import RFO_LABEL, RFO_REASONS

    assert RFO_LABEL[auto.AUTO_RFO] == "Power/link restored – auto"
    assert auto.AUTO_RFO not in RFO_REASONS
