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
    render_setup_lines,
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
        ("GET", "/ip-logs/features"),
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


# -- [POSTFIX-1] D12: a stopped pipe is never hidden behind a green card -------


def test_d12_partial_when_a_set_up_pipe_stopped() -> None:
    f = st.overall_state
    qa = {"syslog": st.RECEIVING, "flows": st.SILENT, "nat": st.SILENT}
    assert f(blocker=None, router_online=True, pipes=qa) == st.PARTIAL
    assert st.lagging_pipes(qa) == ["flows", "nat"]
    assert st.state_label(st.PARTIAL, qa) == (
        "Some logs are not arriving: Connection logs stopped, NAT translations stopped"
    )
    fresh = {
        "syslog": st.RECEIVING,
        "flows": st.AWAITING_FIRST,
        "nat": st.AWAITING_FIRST,
    }
    assert f(blocker=None, router_online=True, pipes=fresh) == st.PARTIAL
    assert "Connection logs not arriving yet" in st.state_label(st.PARTIAL, fresh)
    flows_only = {"syslog": st.SILENT, "flows": st.RECEIVING, "nat": st.RECEIVING}
    assert st.state_label(st.PARTIAL, flows_only).endswith(": System logs stopped")


@pytest.mark.parametrize(
    "pipes",
    [
        {"syslog": st.RECEIVING, "flows": st.RECEIVING, "nat": st.RECEIVING},
        # not set up / not collected on this server are not "lagging": they
        # have their own state and warning
        {"syslog": st.RECEIVING, "flows": st.COLLECTOR_OFF, "nat": st.COLLECTOR_OFF},
        {"syslog": st.RECEIVING, "flows": st.NOT_SET_UP, "nat": st.NOT_SET_UP},
    ],
)
def test_d12_all_set_up_pipes_arriving_stays_green(pipes) -> None:  # noqa: ANN001
    assert (
        st.overall_state(blocker=None, router_online=True, pipes=pipes)
        == st.LOGS_ARRIVING
    )
    assert st.state_label(st.LOGS_ARRIVING, pipes) == "Logs arriving"
    assert st.lagging_pipes(pipes) == []


# -- DEFAULT-LOGS: the IP-logs lines folded into the partner setup script -----


def _do_bodies(line: str) -> list[list[str]]:
    """Statements of every ``:do {}`` / ``do={}`` / ``on-error={}`` /
    ``else={}`` body OUTSIDE strings: the same rule as the console's
    ``validateSetupScriptChunks`` (one statement per body)."""
    opens, in_str, i = [], False, 0
    while i < len(line):
        ch = line[i]
        if in_str:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{" and re.search(
            r"(?::do|\bdo=|on-error=|else=)\s*$", line[max(0, i - 12) : i]
        ):
            opens.append(i)
        i += 1
    out = []
    for o in opens:
        depth, close, st = 0, -1, False
        j = o
        while j < len(line):
            ch = line[j]
            if st:
                if ch == "\\":
                    j += 1
                elif ch == '"':
                    st = False
            elif ch == '"':
                st = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    close = j
                    break
            j += 1
        body = line[o + 1 : close]
        parts, cur, d, bs, k = [], "", 0, False, 0
        while k < len(body):
            ch = body[k]
            if bs:
                cur += ch
                if ch == "\\":
                    k += 1
                    cur += body[k] if k < len(body) else ""
                elif ch == '"':
                    bs = False
            elif ch == '"':
                bs = True
                cur += ch
            else:
                if ch in "{[(":
                    d += 1
                elif ch in "}])":
                    d -= 1
                if d == 0 and ch == ";":
                    parts.append(cur)
                    cur = ""
                    k += 1
                    continue
                cur += ch
            k += 1
        parts.append(cur)
        out.append([p.strip() for p in parts if p.strip()])
    return out


def test_setup_lines_one_statement_per_body_and_under_paste_cap() -> None:
    lines = render_setup_lines(_t())
    assert all(len(line) <= 3300 for line in lines)
    assert all("\n" not in line for line in lines)
    for line in lines:
        for stmts in _do_bodies(line):
            assert len(stmts) <= 1, (line, stmts)
    # the guard itself fires on the card script's two-statement bodies
    card = render_enable_script(_t())
    assert any(len(b) > 1 for line in card for b in _do_bodies(line))


def test_setup_lines_same_values_and_deferral_as_card_script() -> None:
    t = _t()
    lines = render_setup_lines(t)
    text = "\n".join(lines)
    card = "\n".join(render_enable_script(t))
    # both syslog dialects deferred, 7.18+ first, same action text as the card
    modern = re.search(
        r'\[\[:parse "(/system logging action add [^"]*remote-log-format[^"]*)"\]\]',
        text,
    )
    legacy = re.search(
        r'\[\[:parse "(/system logging action add [^"]*bsd-syslog=yes[^"]*)"\]\]', text
    )
    assert (
        modern and legacy and text.index(modern.group(0)) < text.index(legacy.group(0))
    )
    assert modern.group(1) in card and legacy.group(1) in card
    assert "src-address=10.66.0.13" in modern.group(1)
    assert (
        ':do { [[:parse "/system logging action set [find name='
        f'{ROUTEROS_ACTION_NAME}] add-topics-string=yes"]] }} on-error={{}}'
    ) in text
    for topic in ROUTEROS_TOPICS:
        assert f"topics={topic} prefix=wyfy-{RID.hex[:8]}" in text
    # traffic flow + NAT events: v7 only, deferred, the card's values
    assert "nat-events=yes" in text and "version=ipfix" in text
    assert text.count('[:pick [/system resource get version] 0 2] = "7."') >= 5
    # inside the setup script: no clock (setup has its own), never :error
    assert "time-zone-name" not in text and "ntp client" not in text
    assert ":error" not in text
    assert lines[-1] == ':log info "wyfy: IP logs set up"'
    # identity fix kept (location names with spaces break the tag)
    assert 'name="Hotel-Blue-Main"' in text
    assert "wireguard" not in text.lower() and "tunnel" not in text.lower()


def test_add_router_choice_is_a_noop_unless_sent_and_flag_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    from app.domains.isp_partner import iplogs_router as mod
    from app.domains.isp_partner.iplogs_default import record_add_router_choice
    from app.domains.isp_partner.schemas import IspRouterCreateRequest

    body = IspRouterCreateRequest(
        name="R", serial_number="S", mac_address="02:00:00:00:00:01", model="hEX"
    )
    assert body.ip_logs is None
    assert "ip_logs" not in body.model_dump(exclude={"ip_logs"})

    class _Db:
        def __getattr__(self, name: str):  # noqa: ANN204
            raise AssertionError(f"db touched: {name}")

    data = {"id": str(RID), "name": "R"}
    assert asyncio.run(record_add_router_choice(_Db(), object(), data, None)) is data
    monkeypatch.delenv("ISP_IPLOGS_SELFSERVE_ENABLED", raising=False)
    mod.get_iplogs_settings.cache_clear()
    assert asyncio.run(record_add_router_choice(_Db(), object(), data, True)) is data
    mod.get_iplogs_settings.cache_clear()
