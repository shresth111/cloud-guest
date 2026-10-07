"""Device Logs (syslog): parser, RouterOS rendering + parity with the API
writer, ingest attribution, honest states, flag gating and route guards."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

from app.domains.device_logs import router as dl_router
from app.domains.device_logs.constants import (
    ROUTEROS_ACTION_NAME,
    ROUTEROS_TOPICS,
    Attribution,
    ReceivingState,
)
from app.domains.device_logs.exceptions import (
    DeviceLogsBadCursorError,
    DeviceLogsDeviceError,
    DeviceLogsDisabledError,
    DeviceLogsRouterBlockedError,
)
from app.domains.device_logs.parser import mask_personal_data, parse_line
from app.domains.device_logs.repository import PeerOwner
from app.domains.device_logs.routeros import (
    RemoteLoggingConfig,
    desired_config,
    hub_tunnel_address,
    modern_action_row,
    render_action_add,
    render_removal,
    render_script,
    router_tag,
)
from app.domains.device_logs.schemas import IngestEvent, IngestRequest
from app.domains.device_logs.service import (
    DeviceLogsService,
    DeviceWriteFailed,
    WriteVerdict,
    decode_cursor,
    encode_cursor,
    receiving_state,
)

NOW = datetime(2026, 10, 6, 9, 0, 0, tzinfo=UTC)  # 14:30 IST
ROUTER_ID = uuid.UUID("8a199617-0000-4000-8000-000000000001")
ORG_ID = uuid.uuid4()
LOC_ID = uuid.uuid4()


# -- parser -----------------------------------------------------------------


class TestParser:
    def test_routeros_bsd_line_with_identity_tag_and_topics(self) -> None:
        raw = (
            "<174>Oct  6 14:29:58 Hall-Router wyfy-8a199617 dhcp,info "
            "dhcp-guest assigned 10.5.50.12 for 3C:22:FB:11:22:33 Rahuls-iPhone"
        )
        p = parse_line(raw, received_at=NOW)
        assert (p.facility, p.severity) == (21, 6)  # local5, info
        assert p.hostname == "Hall-Router"
        assert p.tag == "8a199617"
        assert p.topics == "dhcp,info"
        assert p.message.startswith(
            "dhcp-guest assigned 10.5.50.12 for 3C:22:FB:11:22:33"
        )
        assert p.device_time == datetime(2026, 10, 6, 8, 59, 58, tzinfo=UTC)

    def test_line_without_hostname_and_with_colon_after_tag(self) -> None:
        p = parse_line(
            "<172>Oct  6 14:29:58 wyfy-8a199617: system,error,critical login failure "
            "for user admin from 1.2.3.4 via winbox",
            received_at=NOW,
        )
        assert p.hostname is None
        assert p.tag == "8a199617"
        assert p.topics == "system,error,critical"
        assert p.severity == 4

    def test_line_without_pri_keeps_severity_unknown_not_info(self) -> None:
        p = parse_line("something happened", received_at=NOW)
        assert p.severity is None and p.facility is None
        assert p.message == "something happened"

    def test_rfc5424_header(self) -> None:
        p = parse_line(
            "<165>1 2026-10-06T08:59:00Z host app - - - hello", received_at=NOW
        )
        assert p.device_time == datetime(2026, 10, 6, 8, 59, tzinfo=UTC)

    def test_year_rollover_picks_the_nearest_year(self) -> None:
        received = datetime(2027, 1, 1, 0, 0, 5, tzinfo=UTC)
        p = parse_line("<30>Jan  1 05:29:59 r msg", received_at=received)
        assert p.device_time is not None and p.device_time.year == 2026

    def test_wrong_router_clock_is_not_dressed_up_as_a_time(self) -> None:
        p = parse_line("<30>Jan  1 00:00:01 r msg", received_at=NOW)
        assert p.device_time is None  # RouterOS build-date clock

    def test_unparseable_line_is_kept_whole(self) -> None:
        p = parse_line("<999>garbage", received_at=NOW)
        assert "garbage" in p.message

    def test_hotspot_login_phone_is_masked_ip_and_mac_kept(self) -> None:
        p = parse_line(
            "<174>Oct  6 14:29:58 r hotspot,info,debug 9876598647 (10.5.50.12): "
            "logged in from 3C:22:FB:11:22:33",
            received_at=NOW,
        )
        assert "9876598647" not in p.message
        assert "XXXXX98647" in p.message
        assert "10.5.50.12" in p.message and "3C:22:FB:11:22:33" in p.message

    def test_masking_variants(self) -> None:
        out = mask_personal_data(
            "user +91 98765 98647 / 919876598647 / akhil@gmail.com bytes=12345678901"
        )
        assert "akhil@" not in out and "@gmail.com" in out
        assert "98765 98647" not in out and "919876598647" not in out
        assert "12345678901" in out  # a counter, not a phone number

    def test_message_capped(self) -> None:
        p = parse_line("<30>" + "x" * 5000, received_at=NOW)
        assert len(p.message) == 2000


# -- RouterOS rendering and parity with the API writer -----------------------


def _config() -> RemoteLoggingConfig:
    return desired_config(
        router_id=ROUTER_ID,
        tunnel_ip="10.20.0.31",
        remote_host="10.20.0.1",
        remote_port=5140,
    )


def _kv(line: str) -> dict[str, str]:
    return dict(re.findall(r"(\S+?)=(\S+)", line))


class TestRouterOs:
    def test_hub_tunnel_address_is_first_host(self) -> None:
        assert hub_tunnel_address("10.20.0.0/24") == "10.20.0.1"

    def test_tag_is_first_8_hex(self) -> None:
        assert router_tag(ROUTER_ID) == "8a199617"

    def test_rendered_add_lines_equal_the_writer_rows(self) -> None:
        """Parity by test: the paste script and the API writer can only
        differ if this fails."""
        cfg = _config()
        lines = render_script(cfg)
        action_lines = [ln for ln in lines if "/system logging action add " in ln]
        rule_lines = [ln for ln in lines if ln.startswith("/system logging add ")]
        assert len(action_lines) == 1
        modern_part, legacy_part = re.findall(
            r"/system logging action add ([^}]*) \}", action_lines[0]
        )
        assert _kv(legacy_part) == cfg.action_row()
        assert _kv(modern_part) == modern_action_row(cfg.action_row())
        assert [_kv(ln) for ln in rule_lines] == cfg.rule_rows()
        assert [r["topics"] for r in cfg.rule_rows()] == list(ROUTEROS_TOPICS)

    def test_script_removes_before_adding_and_is_balanced(self) -> None:
        lines = render_script(_config())
        assert lines[:2] == render_removal()
        text = "\n".join(lines)
        assert text.count("{") == text.count("}")
        assert text.count("[") == text.count("]")
        assert text.count('"') % 2 == 0
        assert "debug" not in text

    def test_add_lines_are_not_swallowed_by_on_error(self) -> None:
        for line in render_script(_config()):
            for handler in re.findall(r"on-error=\{([^}]*)\}", line):
                assert "add" not in handler
            if " add " in line and "on-error" in line:
                # Only the dialect probe may sit in a :do; the add is in :if.
                assert re.search(r":if \(\$m\) do=\{ /system logging action add ", line)

    def test_both_routeros_dialects_are_rendered(self) -> None:
        """Older RouterOS takes bsd-syslog=yes; newer RouterOS 7 rejects it
        ("unknown parameter bsd-syslog", prod 2026-10-07) and takes
        remote-log-format=syslog + syslog-time-format=bsd-syslog (bsd-syslog
        is not a value of remote-log-format on RouterOS 7.21.4)."""
        line = render_action_add(_config())
        assert "remote-log-format=syslog" in line
        assert "syslog-time-format=bsd-syslog" in line
        assert "bsd-syslog=yes" in line
        assert line.count("/system logging action add ") == 2

    def test_renderer_and_writer_agree_on_the_modern_dialect(self) -> None:
        from wyfy_device_gateway.mikrotik_remote_logging import adapt_action_for_device

        row = _config().action_row()
        assert adapt_action_for_device(row, modern=True) == modern_action_row(row)
        assert adapt_action_for_device(row, modern=False) == row

    def test_script_targets_the_tunnel(self) -> None:
        row = _config().action_row()
        assert row["remote"] == "10.20.0.1" and row["src-address"] == "10.20.0.31"
        assert row["remote-port"] == "5140" and row["name"] == ROUTEROS_ACTION_NAME

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"remote_host": "10.20.0.1; /system reset-configuration"},
            {"src_address": "hub.wyfyguest.com"},
            {"remote_port": 0},
            {"tag": "XYZ"},
        ],
    )
    def test_config_refuses_anything_that_is_not_an_ip_port_or_tag(
        self, kwargs
    ) -> None:
        base = {
            "remote_host": "10.20.0.1",
            "remote_port": 514,
            "src_address": "10.20.0.31",
            "tag": "8a199617",
        }
        with pytest.raises(ValueError):
            RemoteLoggingConfig(**{**base, **kwargs})


# -- service ---------------------------------------------------------------


class FakeRepo:
    def __init__(self) -> None:
        self.owners: dict[str, list[PeerOwner]] = {}
        self.inserted: list[dict[str, Any]] = []
        self.list_calls = 0
        self.context: Any = None
        self.config: Any = None
        self.last: dict[uuid.UUID, datetime] = {}
        self.saved: list[Any] = []
        self.guest_rows: list[dict[str, Any]] = []

    async def owners_by_tunnel_ip(self, ips):
        return {ip: self.owners[ip] for ip in ips if ip in self.owners}

    async def insert_events(self, rows):
        start = len(self.inserted)
        self.inserted.extend(rows)
        return list(range(start + 1, start + 1 + len(rows)))

    async def insert_guest_events(self, rows):
        self.guest_rows.extend(rows)
        return len(rows)

    async def list_events(self, filters, *, limit):
        self.list_calls += 1
        return []

    async def last_received_by_router(self, ids):
        return {i: self.last[i] for i in ids if i in self.last}

    async def count_unattributed_since(self, since):
        return 0

    async def get_router_context(self, router_id):
        return self.context

    async def get_config(self, router_id):
        return self.config

    async def save_config(self, row):
        self.config = row
        self.saved.append(row)
        return row

    async def list_configs(self):
        return []


class FakeWriter:
    def __init__(self, verdict=WriteVerdict(ok=True, detail="verified"), fail=False):
        self.verdict = verdict
        self.fail = fail
        self.applied: list[Any] = []
        self.removed = 0

    async def apply(self, creds, config):
        if self.fail:
            raise DeviceWriteFailed("timed out")
        self.applied.append((creds, config))
        return self.verdict

    async def remove(self, creds):
        self.removed += 1
        return WriteVerdict(ok=True, detail="removed")


def _settings(**over):
    base = {
        "device_logs_enabled": True,
        "device_logs_remote_host": "",
        "device_logs_remote_port": 514,
        "device_logs_ingest_secret": "s3cret",
    }
    return SimpleNamespace(**{**base, **over})


def _service(repo=None, writer=None, **settings) -> DeviceLogsService:
    return DeviceLogsService(
        repo or FakeRepo(), _settings(**settings), writer=writer, clock=lambda: NOW
    )


def _event(ip="10.20.0.31", raw="<174>Oct  6 14:29:58 r wyfy-8a199617 dhcp,info x"):
    return IngestEvent(received_at=NOW, source_ip=ip, raw=raw)


class TestIngest:
    @pytest.mark.asyncio
    async def test_attributed_by_tunnel_ip(self) -> None:
        repo = FakeRepo()
        repo.owners["10.20.0.31"] = [PeerOwner(ROUTER_ID, ORG_ID, LOC_ID)]
        result = await _service(repo).ingest([_event()])
        assert result == {
            "accepted": 1,
            "attributed": 1,
            "unattributed": 0,
            "tag_mismatch": 0,
        }
        row = repo.inserted[0]
        assert row["router_id"] == ROUTER_ID and row["organization_id"] == ORG_ID
        assert row["attribution"] == Attribution.TUNNEL_IP

    @pytest.mark.asyncio
    async def test_tag_naming_another_router_flags_mismatch_but_keeps_ip_owner(
        self,
    ) -> None:
        repo = FakeRepo()
        other = uuid.uuid4()
        repo.owners["10.20.0.31"] = [PeerOwner(other, ORG_ID, LOC_ID)]
        await _service(repo).ingest([_event()])
        assert repo.inserted[0]["attribution"] == Attribution.TAG_MISMATCH
        assert repo.inserted[0]["router_id"] == other

    @pytest.mark.asyncio
    async def test_unknown_ip_is_unattributed_even_with_a_valid_tag(self) -> None:
        repo = FakeRepo()
        await _service(repo).ingest([_event(ip="172.31.38.10")])
        row = repo.inserted[0]
        assert (
            row["router_id"] is None and row["attribution"] == Attribution.UNATTRIBUTED
        )
        assert row["claimed_tag"] == "8a199617"

    @pytest.mark.asyncio
    async def test_ambiguous_ip_across_hubs_is_unattributed(self) -> None:
        repo = FakeRepo()
        repo.owners["10.20.0.31"] = [
            PeerOwner(ROUTER_ID, ORG_ID, LOC_ID),
            PeerOwner(uuid.uuid4(), uuid.uuid4(), None),
        ]
        await _service(repo).ingest([_event()])
        assert repo.inserted[0]["router_id"] is None

    @pytest.mark.asyncio
    async def test_stored_message_is_masked(self) -> None:
        repo = FakeRepo()
        await _service(repo).ingest(
            [_event(raw="<174>Oct  6 14:29:58 r hotspot,info 9876598647 logged in")]
        )
        assert "9876598647" not in repo.inserted[0]["message"]

    def test_request_shape_is_strict(self) -> None:
        with pytest.raises(ValueError):
            IngestRequest.model_validate(
                {
                    "events": [
                        {
                            "received_at": NOW.isoformat(),
                            "source_ip": "1.1.1.1",
                            "raw": "x",
                            "host": "y",
                        }
                    ]
                }
            )
        with pytest.raises(ValueError):
            IngestRequest.model_validate(
                {
                    "events": [
                        {
                            "received_at": NOW.isoformat(),
                            "source_ip": "1.1.1.1",
                            "raw": "x",
                        }
                    ]
                    * 1001
                }
            )


class TestHonestStates:
    @pytest.mark.parametrize(
        ("enabled", "configured", "last", "expected"),
        [
            (False, True, NOW, ReceivingState.FEATURE_OFF),
            (True, False, None, ReceivingState.NOT_CONFIGURED),
            (True, True, None, ReceivingState.AWAITING_FIRST_MESSAGE),
            (True, True, NOW - timedelta(minutes=5), ReceivingState.RECEIVING),
            (True, True, NOW - timedelta(hours=3), ReceivingState.SILENT),
            (True, False, NOW - timedelta(minutes=1), ReceivingState.RECEIVING),
        ],
    )
    def test_receiving_state(self, enabled, configured, last, expected) -> None:
        assert (
            receiving_state(
                feature_enabled=enabled,
                configured=configured,
                last_received_at=last,
                now=NOW,
            )
            == expected
        )

    @pytest.mark.asyncio
    async def test_viewer_with_flag_off_says_so_and_does_not_query(self) -> None:
        repo = FakeRepo()
        page = await _service(repo, device_logs_enabled=False).list_events(
            since=None,
            until=None,
            organization_id=None,
            location_id=None,
            router_id=None,
            max_severity=None,
            text=None,
            unattributed_only=False,
            cursor=None,
            limit=None,
        )
        assert page["feature_enabled"] is False and page["items"] == []
        assert repo.list_calls == 0

    @pytest.mark.asyncio
    async def test_window_is_capped(self) -> None:
        page = await _service().list_events(
            since=NOW - timedelta(days=400),
            until=NOW,
            organization_id=None,
            location_id=None,
            router_id=None,
            max_severity=None,
            text=None,
            unattributed_only=False,
            cursor=None,
            limit=None,
        )
        assert page["until"] - page["since"] == timedelta(days=31)

    def test_cursor_round_trip_and_garbage(self) -> None:
        assert decode_cursor(encode_cursor(NOW, 42)) == (NOW, 42)
        with pytest.raises(DeviceLogsBadCursorError):
            decode_cursor("!!!not-base64")


def _router(vendor="mikrotik", creds=True):
    return SimpleNamespace(
        id=ROUTER_ID,
        name="Lab hEX",
        organization_id=ORG_ID,
        location_id=LOC_ID,
        vendor=vendor,
        management_ip_address="10.20.0.31",
        public_ip_address=None,
        api_username="wyfy" if creds else None,
        api_credentials_encrypted="enc" if creds else None,
    )


def _ctx(router, peer=True):
    p = SimpleNamespace(tunnel_ip_address="10.20.0.31") if peer else None
    s = SimpleNamespace(tunnel_network_cidr="10.20.0.0/24") if peer else None
    return (router, p, s, "Lab", "Wyfy QA")


@pytest.fixture
def no_decrypt(monkeypatch):
    monkeypatch.setattr(
        "app.domains.device_logs.service.decrypt_secret", lambda _c: "pw"
    )


class TestApplyRemove:
    @pytest.mark.asyncio
    async def test_flag_off_refuses_before_touching_anything(self) -> None:
        writer = FakeWriter()
        with pytest.raises(DeviceLogsDisabledError):
            await _service(writer=writer, device_logs_enabled=False).apply(
                ROUTER_ID, actor_user_id=uuid.uuid4()
            )
        assert writer.applied == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("router", "peer", "blocker"),
        [
            (_router(vendor="omada"), True, "NOT_MIKROTIK"),
            (_router(vendor="aruba_instant_on"), True, "NOT_MIKROTIK"),
            (_router(), False, "NO_TUNNEL"),
            (_router(creds=False), True, "NO_API_CREDENTIALS"),
        ],
    )
    async def test_blocked_routers_are_refused(
        self, router, peer, blocker, no_decrypt
    ) -> None:
        repo = FakeRepo()
        repo.context = _ctx(router, peer)
        writer = FakeWriter()
        with pytest.raises(DeviceLogsRouterBlockedError) as err:
            await _service(repo, writer).apply(ROUTER_ID, actor_user_id=uuid.uuid4())
        assert err.value.data["blocker"] == blocker
        assert writer.applied == []

    @pytest.mark.asyncio
    async def test_apply_writes_derived_hub_address_and_records_read_back(
        self, no_decrypt
    ) -> None:
        repo = FakeRepo()
        repo.context = _ctx(_router())
        writer = FakeWriter(
            verdict=WriteVerdict(ok=False, detail="missing rules: info")
        )
        detail = await _service(repo, writer).apply(
            ROUTER_ID, actor_user_id=uuid.uuid4()
        )
        creds, cfg = writer.applied[0]
        assert cfg.remote_host == "10.20.0.1" and cfg.src_address == "10.20.0.31"
        assert creds.host == "10.20.0.31" and creds.password == "pw"
        assert repo.config.verified_ok is False
        assert repo.config.verify_detail == "missing rules: info"
        assert detail["status"]["verified_ok"] is False
        assert detail["state"] == ReceivingState.AWAITING_FIRST_MESSAGE

    @pytest.mark.asyncio
    async def test_remote_host_override_and_port(self, no_decrypt) -> None:
        repo = FakeRepo()
        repo.context = _ctx(_router())
        writer = FakeWriter()
        await _service(
            repo,
            writer,
            device_logs_remote_host="10.20.0.254",
            device_logs_remote_port=5140,
        ).apply(ROUTER_ID, actor_user_id=uuid.uuid4())
        cfg = writer.applied[0][1]
        assert (cfg.remote_host, cfg.remote_port) == ("10.20.0.254", 5140)

    @pytest.mark.asyncio
    async def test_device_failure_is_a_502_and_records_nothing(
        self, no_decrypt
    ) -> None:
        repo = FakeRepo()
        repo.context = _ctx(_router())
        with pytest.raises(DeviceLogsDeviceError):
            await _service(repo, FakeWriter(fail=True)).apply(
                ROUTER_ID, actor_user_id=uuid.uuid4()
            )
        assert repo.saved == []

    @pytest.mark.asyncio
    async def test_detail_without_credentials_still_offers_the_script(self) -> None:
        repo = FakeRepo()
        repo.context = _ctx(_router(creds=False))
        detail = await _service(repo).router_detail(ROUTER_ID)
        assert detail["blocker"] == "NO_API_CREDENTIALS"
        assert detail["script"] and any("wyfysyslog" in ln for ln in detail["script"])
        assert detail["state"] == ReceivingState.NOT_CONFIGURED

    @pytest.mark.asyncio
    async def test_detail_for_aruba_offers_no_script(self) -> None:
        repo = FakeRepo()
        repo.context = _ctx(_router(vendor="aruba_instant_on", creds=False))
        detail = await _service(repo).router_detail(ROUTER_ID)
        assert detail["blocker"] == "NOT_MIKROTIK" and detail["script"] is None
        assert "cannot send syslog" in detail["blocker_detail"]


# -- routes ----------------------------------------------------------------


class TestIngestGuard:
    def _patch(self, monkeypatch, **over):
        monkeypatch.setattr(dl_router, "get_settings", lambda: _settings(**over))

    def test_flag_off_is_404(self, monkeypatch) -> None:
        self._patch(monkeypatch, device_logs_enabled=False)
        with pytest.raises(HTTPException) as err:
            dl_router.require_ingest_secret("s3cret")
        assert err.value.status_code == 404

    @pytest.mark.parametrize("sent", [None, "", "wrong"])
    def test_wrong_secret_is_401(self, monkeypatch, sent) -> None:
        self._patch(monkeypatch)
        with pytest.raises(HTTPException) as err:
            dl_router.require_ingest_secret(sent)
        assert err.value.status_code == 401

    def test_empty_configured_secret_refuses_even_an_empty_header(
        self, monkeypatch
    ) -> None:
        self._patch(monkeypatch, device_logs_ingest_secret="")
        with pytest.raises(HTTPException):
            dl_router.require_ingest_secret("")

    def test_right_secret_passes(self, monkeypatch) -> None:
        self._patch(monkeypatch)
        assert dl_router.require_ingest_secret("s3cret") is None


def _closure(call) -> set[str]:
    return {str(cell.cell_contents) for cell in (call.__closure__ or ())}


class TestPlatformRoutesArePinnedGlobal:
    def test_every_platform_route_requires_device_logs_at_global(self) -> None:
        routes = dl_router.device_logs_platform_router.routes
        assert len(routes) == 5
        for route in routes:
            deps = [d.dependency for d in route.dependencies]
            assert len(deps) == 1, route.path
            closure = _closure(deps[0])
            assert "global" in closure, route.path
            wanted = (
                "device_logs.manage"
                if route.path.endswith(("/apply", "/remove"))
                else "device_logs.read"
            )
            assert wanted in closure, route.path

    def test_ingest_route_has_the_secret_guard(self) -> None:
        (route,) = dl_router.device_logs_ingest_router.routes
        assert [d.dependency for d in route.dependencies] == [
            dl_router.require_ingest_secret
        ]


class TestRbacSeed:
    def test_only_global_roles_hold_device_logs(self) -> None:
        from app.domains.rbac.enums import PermissionModule, ScopeType
        from app.domains.rbac.seed import SYSTEM_ROLES

        holders = {
            r.slug: r.grants().get(PermissionModule.DEVICE_LOGS, ())
            for r in SYSTEM_ROLES
            if PermissionModule.DEVICE_LOGS in r.grants()
        }
        for r in SYSTEM_ROLES:
            if r.slug in holders:
                assert r.scope_type == ScopeType.GLOBAL, r.slug
        assert "super-admin" in holders and "organization-owner" not in holders
        support = {a.value for a in holders.get("platform-support", ())}
        assert support == {"read"}
