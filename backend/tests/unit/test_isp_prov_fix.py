"""PROV-FIX (QA_IPLOGS_SELFSERVE.md D1, D4, D6, D7, D8): unit tests.

Postgres scenario (cross-ISP 404s on the new routes) lives in
``test_isp_prov_fix_postgres.py``.
"""

from __future__ import annotations

import re
import uuid
from types import SimpleNamespace

import pytest

from app.domains.device_logs.routeros import (
    desired_config,
    render_action_add,
    render_script,
)
from app.domains.device_logs.service import is_agent_fetch_noise
from app.domains.isp_partner import prov_fix_router as mod
from app.domains.isp_partner.constants import IspRole
from app.domains.isp_partner.iplogs_script import IpLogsTargets, render_enable_script
from app.domains.wireguard.exceptions import HubCannotLearnPlatformKeyError

ROUTER_ID = uuid.UUID("8a199617-0000-4000-8000-000000000001")


def _cfg():  # noqa: ANN202
    return desired_config(
        router_id=ROUTER_ID,
        tunnel_ip="10.20.0.31",
        remote_host="10.20.0.1",
        remote_port=5140,
    )


# -- D8: Master device-logs line ------------------------------------------

#: What the renderer produced before PROV-FIX (origin/integ/isp-test ff0f58ec),
#: captured from that exact code. A 7.18+ router must still get it byte for
#: byte.
ORIGINAL_ACTION_LINE = (
    ":local m false; :do { /system logging action get [find name=remote] "
    "remote-log-format; :set m true } on-error={}; :if ($m) do={ /system logging "
    "action add name=wyfysyslog target=remote remote=10.20.0.1 remote-port=5140 "
    "src-address=10.20.0.31 syslog-facility=local5 syslog-severity=auto "
    "remote-log-format=syslog syslog-time-format=bsd-syslog } else={ /system "
    "logging action add name=wyfysyslog target=remote remote=10.20.0.1 "
    "remote-port=5140 src-address=10.20.0.31 bsd-syslog=yes "
    "syslog-facility=local5 syslog-severity=auto }"
)


@pytest.mark.parametrize("version", ["7.18", "7.18.2", "7.25.1 (stable)", "8.0"])
def test_d8_modern_router_gets_the_original_line_byte_for_byte(version: str) -> None:
    assert render_action_add(_cfg(), routeros_version=version) == ORIGINAL_ACTION_LINE
    assert render_script(_cfg(), routeros_version=version)[2] == ORIGINAL_ACTION_LINE


@pytest.mark.parametrize("version", [None, "", "7.16.2", "7.17.9", "6.49.17", "junk"])
def test_d8_older_or_unknown_router_gets_parse_deferred_adds(version) -> None:  # noqa: ANN001
    line = render_action_add(_cfg(), routeros_version=version)
    assert line != ORIGINAL_ACTION_LINE
    # Neither dialect's property name is visible to the line parser any more:
    # both sit inside a [[:parse "..."]] string.
    outside = re.sub(r'\[\[:parse "[^"]*"\]\]', "", line)
    assert "remote-log-format=" not in outside
    assert "bsd-syslog=yes" not in outside
    assert line.count('[[:parse "/system logging action add ') == 2
    # The add is not swallowed: only the probe sits in on-error.
    for handler in re.findall(r"on-error=\{([^}]*)\}", line):
        assert "add" not in handler
    assert line.count("{") == line.count("}")
    assert line.count("[") == line.count("]")
    assert '\\"' not in line  # no value needs quoting today


def test_d8_same_values_in_both_shapes() -> None:
    plain = render_action_add(_cfg(), routeros_version="7.18")
    deferred = render_action_add(_cfg(), routeros_version="7.16.2")
    strip = re.sub(r'\[\[:parse "([^"]*)"\]\]', r"\1", deferred)
    assert strip == plain


# -- D6: topics on in the ISP IP-logs script ------------------------------


def _targets() -> IpLogsTargets:
    return IpLogsTargets(
        router_id=ROUTER_ID,
        router_name="Cafe Router",
        source_address="10.66.0.98",
        syslog_host="10.66.0.1",
        syslog_port=5514,
        flow_host="10.66.0.1",
        flow_port=2055,
    )


def test_d6_topics_switched_on_inside_parse_and_on_error() -> None:
    lines = render_enable_script(_targets())
    hits = [ln for ln in lines if "add-topics-string" in ln]
    assert hits == [
        ':do { [[:parse "/system logging action set [find name=wyfysyslog] '
        'add-topics-string=yes"]] } on-error={}'
    ]
    # after the action add, before the rules
    idx = lines.index(hits[0])
    assert "remote logging refused" in lines[idx - 1]
    assert lines[idx + 1].startswith("/system logging add ")


# -- D7: collector drops only the schedulers' fetch-success line ----------

HOSTS = frozenset({"network-staging.wyfyguest.com"})


def _p(message: str, topics: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(message=message, topics=topics)


@pytest.mark.parametrize(
    ("message", "topics"),
    [
        ("Download from network-staging.wyfyguest.com FINISHED", None),
        ("Download from network-staging.wyfyguest.com FINISHED", "fetch,info"),
        ("Download from NETWORK-STAGING.wyfyguest.com FINISHED ", "info,fetch"),
    ],
)
def test_d7_drops_the_exact_heartbeat_shape(message: str, topics) -> None:  # noqa: ANN001
    assert is_agent_fetch_noise(_p(message, topics), HOSTS)


@pytest.mark.parametrize(
    ("message", "topics"),
    [
        # another host: an ISP / subscriber-relevant fetch, kept
        ("Download from api.ipify.org FINISHED", None),
        ("Download from example.com FINISHED", "fetch,info"),
        # failures and uploads of the platform host, kept
        ("Download from network-staging.wyfyguest.com FAILED", None),
        ("Upload to network-staging.wyfyguest.com FINISHED", None),
        # more text on the line, kept
        ("Download from network-staging.wyfyguest.com FINISHED x", None),
        ("fetch: Download from network-staging.wyfyguest.com FINISHED", None),
        # other topics on the line, kept
        ("Download from network-staging.wyfyguest.com FINISHED", "fetch,error"),
        ("Download from network-staging.wyfyguest.com FINISHED", "script,info"),
        # not a fetch line at all
        ("dhcp1 assigned 192.168.88.254 to 02:9A:00:00:00:01", "dhcp,info"),
    ],
)
def test_d7_keeps_every_other_line(message: str, topics) -> None:  # noqa: ANN001
    assert not is_agent_fetch_noise(_p(message, topics), HOSTS)


def test_d7_off_by_default_drops_nothing() -> None:
    from app.core.config import Settings

    assert Settings().device_logs_drop_agent_fetch_hosts == []
    assert not is_agent_fetch_noise(
        _p("Download from network-staging.wyfyguest.com FINISHED"), frozenset()
    )


async def test_d7_ingest_counts_and_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import UTC, datetime

    from app.domains.device_logs.service import DeviceLogsService, IngestEvent

    inserted: list[list[dict]] = []

    class Repo:
        async def owners_by_tunnel_ip(self, ips):  # noqa: ANN001, ANN202
            return {}

        async def insert_events(self, rows):  # noqa: ANN001, ANN202
            inserted.append(rows)
            return list(range(len(rows)))

        async def insert_guest_events(self, rows):  # noqa: ANN001, ANN202
            return 0

    settings = SimpleNamespace(
        device_logs_drop_agent_fetch_hosts=["network-staging.wyfyguest.com"],
        device_logs_enabled=True,
    )
    svc = DeviceLogsService(Repo(), settings)  # type: ignore[arg-type]
    now = datetime.now(UTC)
    base = "<190>Nov 10 13:55:31 Cafe wyfy-990b6cd2 "
    events = [
        IngestEvent(
            raw=base + "Download from network-staging.wyfyguest.com FINISHED",
            source_ip="10.66.0.98",
            received_at=now,
        ),
        IngestEvent(
            raw=base + "Download from example.com FINISHED",
            source_ip="10.66.0.98",
            received_at=now,
        ),
    ]
    result = await svc.ingest(events)
    assert result["accepted"] == 1
    assert result["dropped_agent_fetch"] == 1
    assert [r["message"] for r in inserted[0]] == ["Download from example.com FINISHED"]


# -- route table: flag-gated, guarded, no scope-alias path names ----------


def test_routes_are_flag_gated_and_guarded() -> None:
    routes = list(mod.prov_fix_router.routes)
    assert {(next(iter(r.methods)), r.path) for r in routes} == {
        ("GET", "/setup-fixes"),
        ("POST", "/routers/{isp_router_id}/setup/check-in"),
        ("GET", "/routers/{isp_router_id}/monitoring"),
        ("POST", "/routers/{isp_router_id}/monitoring/enable"),
        ("POST", "/routers/{isp_router_id}/monitoring/disable"),
    }
    for r in routes:
        deps = [d.dependency for d in r.dependencies]
        assert deps[0] is mod.RequireProvFixEnabled, r.path
        assert len(deps) > 1, r.path
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
    monkeypatch.delenv("ISP_PROV_FIX_ENABLED", raising=False)
    mod.get_prov_fix_settings.cache_clear()
    with pytest.raises(mod.IspProvFixDisabledError) as exc:
        await mod.RequireProvFixEnabled()
    assert exc.value.status_code == 404
    monkeypatch.setenv("ISP_PROV_FIX_ENABLED", "true")
    mod.get_prov_fix_settings.cache_clear()
    await mod.RequireProvFixEnabled()
    mod.get_prov_fix_settings.cache_clear()


def test_partner_copy_never_names_the_tunnel() -> None:
    for name in dir(mod):
        obj = getattr(mod, name)
        msg = getattr(obj, "default_message", None)
        if isinstance(obj, type) and isinstance(msg, str):
            low = msg.lower()
            assert "wireguard" not in low and "tunnel" not in low, name
            assert "/routers/" not in msg and "verb" not in low, name


# -- D1: check-in twin ------------------------------------------------------


class _Peer:
    def __init__(self, revoked: bool = False) -> None:
        self._revoked = revoked

    def is_revoked(self) -> bool:
        return self._revoked


def _isp(role: str = IspRole.OWNER) -> SimpleNamespace:
    return SimpleNamespace(
        role_slug=role, user_id=uuid.uuid4(), isp_org_id=uuid.uuid4()
    )


class _Audit:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def create_audit_log_entry(self, **kw):  # noqa: ANN003, ANN202
        self.rows.append(kw)


def _wire(monkeypatch, *, token_router, peer, check_in_raises=None):  # noqa: ANN001, ANN202
    target = SimpleNamespace(
        id=ROUTER_ID, organization_id=uuid.uuid4(), location_id=uuid.uuid4()
    )
    calls: list[str] = []

    async def assert_router(isp, rid):  # noqa: ANN001, ANN202
        assert rid == ROUTER_ID
        return target

    monkeypatch.setattr(mod.IspScope, "assert_router", staticmethod(assert_router))

    async def allocate(request, **kw):  # noqa: ANN001, ANN003, ANN202
        calls.append("allocate")
        assert kw["rotate"] is False and kw["force"] is False
        assert kw["router_id"] == ROUTER_ID
        return {"data": {"peer_private_key": "PRIV", "tunnel_ip_address": "10.66.0.9"}}

    async def check_in(payload, **kw):  # noqa: ANN001, ANN003, ANN202
        calls.append("check_in")
        if check_in_raises:
            raise check_in_raises
        return SimpleNamespace(model_dump=lambda mode: {"router_id": str(ROUTER_ID)})

    monkeypatch.setattr(
        mod.wireguard_routes, "allocate_external_wireguard_peer", allocate
    )
    monkeypatch.setattr(mod.router_routes, "provisioning_check_in", check_in)

    class TokRepo:
        async def get_provisioning_token_by_hash(self, h):  # noqa: ANN001, ANN202
            if token_router is None:
                return None
            return SimpleNamespace(router_id=token_router)

    class WgRepo:
        async def get_peer_by_router_id(self, rid):  # noqa: ANN001, ANN202
            return peer

    router_service = SimpleNamespace(repository=TokRepo())
    wg = SimpleNamespace(repository=WgRepo())
    return calls, router_service, wg


def _req() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(request_id="t"), headers={})


def _settings(can_register: bool = False) -> SimpleNamespace:
    return SimpleNamespace(hub_wg_agent_supports_key_registration=can_register)


async def _call(router_service, wg, *, settings=None, role=IspRole.OWNER):  # noqa: ANN001, ANN202
    audit = _Audit()
    out = await mod.setup_check_in(
        _req(),
        ROUTER_ID,
        mod.IspSetupCheckInRequest(token="tok"),
        isp=_isp(role),
        router_service=router_service,
        agent_service=SimpleNamespace(),
        wireguard_service=wg,
        audit=audit,
        settings=settings or _settings(),
    )
    return out, audit


async def test_d1_fresh_router_allocates_through_the_hub_first(monkeypatch) -> None:  # noqa: ANN001
    calls, rs, wg = _wire(monkeypatch, token_router=ROUTER_ID, peer=None)
    out, audit = await _call(rs, wg)
    assert calls == ["allocate", "check_in"]
    assert out["data"]["management_connection"]["peer_private_key"] == "PRIV"
    assert audit.rows[0]["action"] == "isp_router_setup_check_in"
    assert audit.rows[0]["event_metadata"]["allocated_management_connection"]


async def test_d1_revoked_peer_also_allocates(monkeypatch) -> None:  # noqa: ANN001
    calls, rs, wg = _wire(monkeypatch, token_router=ROUTER_ID, peer=_Peer(True))
    await _call(rs, wg)
    assert calls == ["allocate", "check_in"]


async def test_d1_existing_peer_is_left_alone(monkeypatch) -> None:  # noqa: ANN001
    calls, rs, wg = _wire(monkeypatch, token_router=ROUTER_ID, peer=_Peer())
    out, _ = await _call(rs, wg)
    assert calls == ["check_in"]
    assert out["data"]["management_connection"] is None


async def test_d1_hub_that_can_register_keys_needs_no_fallback(monkeypatch) -> None:  # noqa: ANN001
    calls, rs, wg = _wire(monkeypatch, token_router=ROUTER_ID, peer=None)
    await _call(rs, wg, settings=_settings(can_register=True))
    assert calls == ["check_in"]


async def test_d1_foreign_token_allocates_nothing(monkeypatch) -> None:  # noqa: ANN001
    calls, rs, wg = _wire(monkeypatch, token_router=uuid.uuid4(), peer=None)
    with pytest.raises(mod.IspSetupTokenMismatchError):
        await _call(rs, wg)
    assert calls == []


async def test_d1_unknown_token_goes_to_the_original_error(monkeypatch) -> None:  # noqa: ANN001
    calls, rs, wg = _wire(monkeypatch, token_router=None, peer=None)
    await _call(rs, wg)
    assert calls == ["check_in"]  # the original handler answers "not found"


async def test_d1_engineering_refusal_becomes_partner_code(monkeypatch) -> None:  # noqa: ANN001
    calls, rs, wg = _wire(
        monkeypatch,
        token_router=ROUTER_ID,
        peer=_Peer(),
        check_in_raises=HubCannotLearnPlatformKeyError("Creating this tunnel"),
    )
    with pytest.raises(mod.IspManagementConnectionNotReadyError) as exc:
        await _call(rs, wg)
    assert exc.value.status_code == 409
    assert exc.value.data["code"] == "ISP_MANAGEMENT_CONNECTION_NOT_READY"
    assert "verb" not in exc.value.message and "tunnel" not in exc.value.message


async def test_d1_viewer_cannot_check_in(monkeypatch) -> None:  # noqa: ANN001
    calls, rs, wg = _wire(monkeypatch, token_router=ROUTER_ID, peer=None)
    from app.domains.isp_partner.exceptions import IspSetupNotAllowedError

    with pytest.raises(IspSetupNotAllowedError):
        await _call(rs, wg, role=IspRole.VIEWER)
    assert calls == []


# -- D4: monitoring ----------------------------------------------------------


def _router_row(**kw) -> SimpleNamespace:  # noqa: ANN003
    base = dict(
        id=ROUTER_ID,
        organization_id=uuid.uuid4(),
        location_id=uuid.uuid4(),
        snmp_enabled=False,
        snmp_community_encrypted=None,
        snmp_device_applied_at=None,
        snmp_last_success_at=None,
        snmp_last_poll_status=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


class _Snmp:
    def __init__(self, row, apply_exc=None, verified=True) -> None:  # noqa: ANN001
        self.row = row
        self.apply_exc = apply_exc
        self.verified = verified
        self.updates: list[dict] = []

    async def update_config(self, rid, *, actor_user_id, data):  # noqa: ANN001, ANN202
        self.updates.append(data)
        self.row.snmp_enabled = bool(data["enabled"])
        return self.row

    async def apply_to_device(self, rid, *, actor_user_id):  # noqa: ANN001, ANN202
        if self.apply_exc:
            raise self.apply_exc
        return SimpleNamespace(verified=self.verified)


def _scope(monkeypatch, row) -> None:  # noqa: ANN001
    async def assert_router(isp, rid):  # noqa: ANN001, ANN202
        return row

    monkeypatch.setattr(mod.IspScope, "assert_router", staticmethod(assert_router))


async def test_d4_owner_switches_on_with_its_own_community(monkeypatch) -> None:  # noqa: ANN001
    row = _router_row()
    _scope(monkeypatch, row)
    snmp = _Snmp(row)
    out = await mod._switch(_req(), ROUTER_ID, True, _isp(), snmp, _Audit())
    assert out["data"]["enabled"] is True
    sent = snmp.updates[0]
    assert sent["enabled"] is True and sent["version"] == "2c"
    assert re.fullmatch(r"wyfy[0-9a-f]{16}", sent["community"])


async def test_d4_existing_community_is_kept(monkeypatch) -> None:  # noqa: ANN001
    row = _router_row(snmp_community_encrypted="gAAAA")
    _scope(monkeypatch, row)
    snmp = _Snmp(row)
    await mod._switch(_req(), ROUTER_ID, True, _isp(IspRole.ADMIN), snmp, _Audit())
    assert snmp.updates == [{"enabled": True}]


@pytest.mark.parametrize(
    "role", [IspRole.NOC, IspRole.TECHNICIAN, IspRole.VIEWER, IspRole.BILLING]
)
async def test_d4_only_owner_and_admin(monkeypatch, role) -> None:  # noqa: ANN001
    row = _router_row()
    _scope(monkeypatch, row)
    with pytest.raises(mod.IspMonitoringNotAllowedError):
        await mod._switch(_req(), ROUTER_ID, True, _isp(role), _Snmp(row), _Audit())


async def test_d4_unreachable_router_refuses_on(monkeypatch) -> None:  # noqa: ANN001
    from app.domains.router.snmp import SnmpDeviceUnreachableError

    row = _router_row()
    _scope(monkeypatch, row)
    snmp = _Snmp(row, apply_exc=SnmpDeviceUnreachableError(ROUTER_ID, "timeout"))
    with pytest.raises(mod.IspMonitoringRouterUnreachableError):
        await mod._switch(_req(), ROUTER_ID, True, _isp(), snmp, _Audit())


async def test_d4_unverified_write_refuses_on(monkeypatch) -> None:  # noqa: ANN001
    row = _router_row()
    _scope(monkeypatch, row)
    with pytest.raises(mod.IspMonitoringRouterUnreachableError):
        await mod._switch(
            _req(), ROUTER_ID, True, _isp(), _Snmp(row, verified=False), _Audit()
        )


async def test_d4_off_works_even_when_router_is_unreachable(monkeypatch) -> None:  # noqa: ANN001
    from app.domains.router.snmp import SnmpDeviceUnreachableError

    row = _router_row(snmp_enabled=True, snmp_community_encrypted="gAAAA")
    _scope(monkeypatch, row)
    snmp = _Snmp(row, apply_exc=SnmpDeviceUnreachableError(ROUTER_ID, "timeout"))
    audit = _Audit()
    out = await mod._switch(_req(), ROUTER_ID, False, _isp(), snmp, audit)
    assert out["data"]["enabled"] is False
    assert audit.rows[0]["action"] == "isp_router_setup_monitoring_off"


async def test_d4_config_problem_is_partner_copy(monkeypatch) -> None:  # noqa: ANN001
    from app.domains.router.snmp import SnmpConfigInvalidError

    row = _router_row()
    _scope(monkeypatch, row)
    snmp = _Snmp(row, apply_exc=SnmpConfigInvalidError("POLLER_SOURCE empty"))
    with pytest.raises(mod.IspMonitoringUnavailableError) as exc:
        await mod._switch(_req(), ROUTER_ID, True, _isp(), snmp, _Audit())
    assert "POLLER" not in exc.value.message


def test_d4_netmon_hint_is_self_serve_only_when_flag_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.domains.isp_partner import netmon_router
    from app.domains.isp_partner.netmon import FORBIDDEN_HINT_WORDS

    low = netmon_router.SELF_SERVE_MONITORING_HINT.lower()
    assert not any(w in low for w in FORBIDDEN_HINT_WORDS)
    assert "support" not in low
    monkeypatch.delenv("ISP_PROV_FIX_ENABLED", raising=False)
    mod.get_prov_fix_settings.cache_clear()
    assert netmon_router._self_serve_monitoring() is False
    monkeypatch.setenv("ISP_PROV_FIX_ENABLED", "true")
    mod.get_prov_fix_settings.cache_clear()
    assert netmon_router._self_serve_monitoring() is True
    mod.get_prov_fix_settings.cache_clear()
