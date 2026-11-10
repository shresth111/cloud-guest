"""IPLOGS-SELFSERVE unit tests: the paste script and the status rules.

The Postgres scenario (cross-ISP isolation, enable/disable, arrivals) is
``test_isp_iplogs_postgres.py``.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.device_logs.constants import ROUTEROS_ACTION_NAME, ROUTEROS_TOPICS
from app.domains.isp_partner import iplogs_status as st
from app.domains.isp_partner.iplogs_script import (
    IpLogsTargets,
    deferred,
    render_disable_script,
    render_enable_script,
    safe_identity,
)

RID = uuid.UUID("12345678-9abc-4def-8123-456789abcdef")


def _t(**kw: object) -> IpLogsTargets:
    base: dict[str, object] = {
        "router_id": RID,
        "router_name": "Hotel Blue Main",
        "source_address": "10.66.0.13",
        "syslog_host": "10.66.0.1",
        "syslog_port": 5514,
        "flow_host": "10.66.0.1",
        "flow_port": 2055,
    }
    base.update(kw)
    return IpLogsTargets(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# script
# --------------------------------------------------------------------------


def test_safe_identity() -> None:
    assert safe_identity("Hotel Blue Main", RID) == "Hotel-Blue-Main"
    assert safe_identity("  ", RID) == "wyfy-12345678"
    assert safe_identity(None, RID) == "wyfy-12345678"
    assert safe_identity('a:b/c"d$e', RID) == "a-b-c-d-e"
    assert len(safe_identity("x" * 80, RID)) == 32


def test_deferred_escapes_and_refuses_help_char() -> None:
    assert deferred('/a b="c" d=$x') == '[[:parse "/a b=\\"c\\" d=\\$x"]]'
    with pytest.raises(ValueError):
        deferred("/ip address print where address?")


def test_targets_are_validated() -> None:
    with pytest.raises(ValueError):
        _t(source_address="10.66.0.13; /system reset")
    with pytest.raises(ValueError):
        _t(flow_port=70000)


def test_enable_script_both_syslog_dialects_are_parse_deferred() -> None:
    lines = render_enable_script(_t())
    text = "\n".join(lines)
    # Both dialects present, each ONLY inside a run-time [[:parse "..."]].
    for prop in ("bsd-syslog=yes", "remote-log-format=syslog"):
        assert prop in text
        for line in lines:
            if prop in line:
                literal = re.sub(r'\[\[:parse "(?:[^"\\]|\\.)*"\]\]', "", line)
                assert prop not in literal, line
    assert "syslog-time-format=bsd-syslog" in text
    assert "remote=10.66.0.1 remote-port=5514 src-address=10.66.0.13" in text
    rules = [ln for ln in lines if ln.startswith("/system logging add ")]
    assert len(rules) == len(ROUTEROS_TOPICS)
    assert all(f"action={ROUTEROS_ACTION_NAME}" in r for r in rules)
    assert all("prefix=wyfy-12345678" in r for r in rules)


def test_enable_script_traffic_flow_with_nat_events_v7_guarded() -> None:
    lines = render_enable_script(_t())
    flow = [ln for ln in lines if "traffic-flow" in ln and not ln.startswith("#")]
    assert flow
    for line in flow:
        # every version-dependent traffic-flow property stays inside :parse
        literal = re.sub(r'\[\[:parse "(?:[^"\\]|\\.)*"\]\]', "", line)
        for prop in ("src-address=", "nat-events=", "nat-src-address="):
            assert prop not in literal, line
    text = "\n".join(lines)
    assert "nat-events=yes" in text
    assert "nat-dst-address=yes" in text
    assert "nat-src-port=yes" in text
    assert (
        "dst-address=10.66.0.1 port=2055 version=ipfix src-address=10.66.0.13" in text
    )
    assert "active-flow-timeout=1m" in text
    assert "SKIPPED connection logs: RouterOS 7 is needed" in text
    # the NAT events line warns instead of stopping the paste
    nat_line = next(ln for ln in lines if "nat-events=yes" in ln)
    assert "on-error=" in nat_line and "WARNING" in nat_line


def test_enable_script_identity_clock_and_readback() -> None:
    text = "\n".join(render_enable_script(_t()))
    assert '/system identity set name="Hotel-Blue-Main"' in text
    assert "time-zone-name=Asia/Kolkata" in text
    assert "servers=216.239.35.0,162.159.200.1" in text
    assert "primary-ntp=216.239.35.0" in text
    assert ':log info "wyfy: IP logs set up"' in text


def test_scripts_are_console_safe_and_use_partner_wording() -> None:
    for lines in (render_enable_script(_t()), render_disable_script(_t())):
        for line in lines:
            assert "?" not in line
            assert "\n" not in line
            # each line is its own program: no cross-line :local use
            assert ":local" not in line
            low = line.lower()
            assert "wireguard" not in low and "tunnel" not in low
            assert "{{" not in line and "}}" not in line
            assert line.count("{") == line.count("}"), line
            assert line.count("[") == line.count("]"), line


def test_disable_script_touches_only_our_rows() -> None:
    text = "\n".join(render_disable_script(_t()))
    assert f"remove [find action={ROUTEROS_ACTION_NAME}]" in text
    assert "target remove [find where dst-address=10.66.0.1 and port=2055]" in text
    assert "/ip traffic-flow set enabled=no" in text
    assert "remove [find]" not in text


# --------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------

NOW = datetime(2026, 11, 10, 8, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("collector", "set_up", "last", "want"),
    [
        (False, True, NOW, st.COLLECTOR_OFF),
        (True, False, NOW - timedelta(minutes=5), st.RECEIVING),
        (True, True, NOW - timedelta(hours=3), st.SILENT),
        (True, True, None, st.AWAITING_FIRST),
        (True, False, None, st.NOT_SET_UP),
    ],
)
def test_pipe_state(collector: bool, set_up: bool, last, want: str) -> None:  # noqa: ANN001
    assert (
        st.pipe_state(
            collector_on=collector,
            set_up=set_up,
            last_at=last,
            now=NOW,
            stale_after=timedelta(minutes=60),
        )
        == want
    )


def test_overall_state() -> None:
    rx = {"syslog": st.RECEIVING, "flows": st.COLLECTOR_OFF, "nat": st.COLLECTOR_OFF}
    idle = {"syslog": st.NOT_SET_UP, "flows": st.NOT_SET_UP, "nat": st.NOT_SET_UP}
    wait = {"syslog": st.AWAITING_FIRST, "flows": st.COLLECTOR_OFF, "nat": "x"}
    silent = {"syslog": st.SILENT, "flows": st.NOT_SET_UP, "nat": st.NOT_SET_UP}
    f = st.overall_state
    assert f(blocker=None, router_online=False, pipes=rx) == st.LOGS_ARRIVING
    assert f(blocker="not_mikrotik", router_online=True, pipes=rx) == st.NOT_SUPPORTED
    assert f(blocker="needs_link", router_online=True, pipes=idle) == st.NEEDS_LINK
    assert f(blocker=None, router_online=False, pipes=wait) == st.OFFLINE
    assert f(blocker=None, router_online=True, pipes=silent) == st.OVERALL_SILENT
    assert f(blocker=None, router_online=True, pipes=wait) == st.WAITING
    assert f(blocker=None, router_online=True, pipes=idle) == st.OVERALL_NOT_SET_UP
    assert set(st.OVERALL_LABEL) >= {
        st.LOGS_ARRIVING,
        st.WAITING,
        st.OVERALL_NOT_SET_UP,
        st.OFFLINE,
        st.OVERALL_SILENT,
        st.NEEDS_LINK,
        st.NOT_SUPPORTED,
    }


@pytest.mark.parametrize(
    ("ip", "want"),
    [
        ("192.168.1.10", True),
        ("100.70.1.2", True),
        ("10.0.0.1/32", True),
        ("49.36.10.5", False),
        (None, False),
        ("not-an-ip", False),
    ],
)
def test_is_non_public(ip, want: bool) -> None:  # noqa: ANN001
    assert st.is_non_public(ip) is want


def _warn(**kw: object) -> list[str]:
    base: dict[str, object] = {
        "routeros_version": "7.20.1",
        "public_ip": "49.36.10.5",
        "translated_ips": [],
        "clock_offset_seconds": 3.0,
        "tag_mismatch_lines": 0,
        "untagged_lines": 0,
        "flows_receiving": False,
        "nat_events_seen": False,
        "collector_flows_on": True,
    }
    base.update(kw)
    return [w["code"] for w in st.warnings_for(**base)]  # type: ignore[arg-type]


def test_warnings() -> None:
    assert _warn() == []
    assert _warn(routeros_version="6.49.10") == ["routeros_6"]
    assert _warn(translated_ips=["192.168.0.5", "49.36.10.5"]) == ["double_nat"]
    assert _warn(public_ip="192.168.0.5") == ["double_nat"]
    assert _warn(clock_offset_seconds=-900) == ["clock_off"]
    assert _warn(tag_mismatch_lines=3) == ["tag_mismatch"]
    assert _warn(untagged_lines=2) == ["untagged"]
    assert _warn(collector_flows_on=False) == ["flows_not_collected"]
    assert _warn(flows_receiving=True) == ["no_nat_events"]
    assert _warn(flows_receiving=True, nat_events_seen=True) == []
    msgs = st.warnings_for(
        routeros_version="6.48",
        public_ip="10.1.1.1",
        translated_ips=[],
        clock_offset_seconds=600,
        tag_mismatch_lines=1,
        untagged_lines=1,
        flows_receiving=False,
        nat_events_seen=False,
        collector_flows_on=False,
    )
    for m in msgs:
        low = m["message"].lower()
        assert "wireguard" not in low and "tunnel" not in low


# --------------------------------------------------------------------------
# routes: flag, guards, parameter names
# --------------------------------------------------------------------------


def _iplogs_routes() -> list:
    from app.domains.isp_partner.iplogs_router import iplogs_router

    return list(iplogs_router.routes)


def test_routes_are_flag_gated_and_guarded() -> None:
    from app.domains.isp_partner.iplogs_router import RequireIpLogsEnabled

    routes = _iplogs_routes()
    assert {(next(iter(r.methods)), r.path) for r in routes} == {
        ("GET", "/routers/{isp_router_id}/ip-logs"),
        ("GET", "/routers/{isp_router_id}/ip-logs/script"),
        ("POST", "/routers/{isp_router_id}/ip-logs/enable"),
        ("POST", "/routers/{isp_router_id}/ip-logs/disable"),
        ("GET", "/ip-logs/routers"),
    }
    for r in routes:
        deps = [d.dependency for d in r.dependencies]
        assert deps[0] is RequireIpLogsEnabled, r.path
        assert len(deps) > 1, r.path  # isp_guards follow
        names = set(r.param_convertors) | {
            p.name for p in r.dependant.query_params + r.dependant.path_params
        }
        assert not names & {
            "organization_id",
            "customer_id",
            "location_id",
            "router_id",
        }, r.path


async def test_flag_off_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.domains.isp_partner import iplogs_router as mod

    monkeypatch.delenv("ISP_IPLOGS_SELFSERVE_ENABLED", raising=False)
    mod.get_iplogs_settings.cache_clear()
    with pytest.raises(mod.IspIpLogsDisabledError):
        await mod.RequireIpLogsEnabled()
    monkeypatch.setenv("ISP_IPLOGS_SELFSERVE_ENABLED", "true")
    mod.get_iplogs_settings.cache_clear()
    await mod.RequireIpLogsEnabled()
    mod.get_iplogs_settings.cache_clear()
