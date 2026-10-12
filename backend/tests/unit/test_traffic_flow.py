"""NetFlow/IPFIX MVP (``app.domains.traffic_flow``).

Pins, in order:

* **Ingest** -- local/remote split by which side is private (not by flow
  direction), internal and unclassified bytes counted not dropped, top-N
  with the remainder kept, attribution never guesses.
* **Privacy shape** -- a stored window holds no talker x destination pair.
* **Parity** -- the generator's lines parse back to exactly the writer's
  desired rows; the block is structurally balanced; the target add is
  guarded; v6 gets a comment, not a guess.
* **Gates** -- flag, allowlist, vendor, tunnel, on both config paths.
* **Overview states** -- disabled / not_allowlisted / collector_unreachable
  / no_windows / stale / ok, never an unexplained empty table.
* **Device service** -- dry run writes nothing, refusals surface their code,
  a real apply audits and reports read-back.
* **Pull sweep** -- failure is recorded, cursor advances, re-pull is a no-op.
* **Authorization** -- every route pinned GLOBAL on ``traffic_flows.*``; the
  module is GLOBAL-only and held by Super Admin / Platform Admin only.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.config import Settings
from app.domains.network_config.renderers import render_network_config
from app.domains.rbac.enums import PermissionModule, ScopeType
from app.domains.rbac.seed import MODULE_NARROWEST_SCOPE, SYSTEM_ROLES
from app.domains.traffic_flow.constants import (
    TRAFFIC_FLOW_SECTION_HEADER,
    TRAFFIC_FLOW_TARGET_MARKER,
    RouterFlowState,
    TalkerMatch,
)
from app.domains.traffic_flow.ingest import (
    attribute_talkers,
    is_local_address,
    reduce_window,
    top_destinations,
    top_talkers,
)
from app.domains.traffic_flow.routeros import (
    TrafficFlowTarget,
    desired_config,
    render_traffic_flow_lines,
    traffic_flow_lines_for_router,
)
from app.domains.traffic_flow.service import (
    ExporterRouter,
    TrafficFlowDeviceService,
    TrafficFlowError,
    TrafficFlowIngestService,
    TrafficFlowOverviewService,
)
from app.domains.traffic_flow.tasks import pull_once

ROUTER_ID = uuid.UUID("8a199617-0000-4000-8000-000000000031")
OTHER_ROUTER = uuid.UUID("11111111-0000-4000-8000-000000000001")
NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
TARGET = TrafficFlowTarget(
    collector_address="10.20.0.1", collector_port=2055, source_address="10.20.0.31"
)


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "traffic_flow_enabled": True,
        "traffic_flow_router_ids": str(ROUTER_ID),
        "traffic_flow_agent_url": "http://172.31.40.230:9094",
        "traffic_flow_agent_secret": "s3cret",
    }
    base.update(overrides)
    return Settings(**base)


def _row(
    src: str, dst: str, nbytes: int, *, exporter: str = "10.20.0.31", flows: int = 1
):
    return {
        "peer_ip_src": exporter,
        "ip_src": src,
        "ip_dst": dst,
        "bytes": nbytes,
        "packets": 1,
        "flows": flows,
    }


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------


class TestIngest:
    def test_local_side_decides_talker_regardless_of_direction(self) -> None:
        windows = reduce_window(
            [
                _row("192.168.95.10", "142.250.1.1", 100),  # upload
                _row("142.250.1.1", "192.168.95.10", 900),  # download
            ]
        )
        w = windows["10.20.0.31"]
        assert w.talkers["192.168.95.10"].bytes_up == 100
        assert w.talkers["192.168.95.10"].bytes_down == 900
        assert w.destinations["142.250.1.1"] == [1000, 2]

    def test_internal_and_unclassified_are_counted_not_ranked(self) -> None:
        w = reduce_window(
            [
                _row("192.168.95.10", "192.168.95.1", 50),  # guest -> router DNS
                _row("10.20.0.31", "10.20.0.1", 70),  # export over the tunnel
                _row("8.8.8.8", "1.1.1.1", 5),  # should not happen behind NAT
            ]
        )["10.20.0.31"]
        assert w.bytes_internal == 120
        assert w.bytes_unclassified == 5
        assert w.bytes_total == 125
        assert w.destinations == {}

    def test_cgnat_counts_as_local(self) -> None:
        assert is_local_address("100.64.3.2") is True
        assert is_local_address("142.250.1.1") is False
        assert is_local_address("not-an-ip") is None

    def test_unparseable_row_is_rejected_and_counted(self) -> None:
        w = reduce_window([_row("garbage", "1.1.1.1", 10)])["10.20.0.31"]
        assert w.rows_rejected == 1 and w.bytes_total == 0

    def test_top_n_keeps_the_remainder(self) -> None:
        rows = [_row(f"192.168.95.{i}", "1.1.1.1", i * 10) for i in range(1, 15)]
        w = reduce_window(rows)["10.20.0.31"]
        entries, rest = top_talkers(w, {}, limit=10)
        assert len(entries) == 10
        assert entries[0]["ip"] == "192.168.95.14"
        assert rest == sum(i * 10 for i in range(1, 5))
        dests, dest_rest = top_destinations(w, limit=10)
        assert dests[0]["bytes"] == sum(i * 10 for i in range(1, 15)) and dest_rest == 0

    def test_attribution_never_guesses(self) -> None:
        a, b = uuid.uuid4(), uuid.uuid4()
        got = attribute_talkers(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            {"10.0.0.1": [a], "10.0.0.2": [a, b]},
        )
        assert got["10.0.0.1"] == (TalkerMatch.SESSION, a)
        assert got["10.0.0.2"] == (TalkerMatch.AMBIGUOUS, None)
        assert got["10.0.0.3"] == (TalkerMatch.NONE, None)

    def test_stored_window_never_pairs_a_talker_with_a_destination(self) -> None:
        w = reduce_window([_row("192.168.95.10", "142.250.1.1", 100)])["10.20.0.31"]
        talkers, _ = top_talkers(w, {})
        dests, _ = top_destinations(w)
        assert set(talkers[0]) == {
            "ip",
            "bytes_up",
            "bytes_down",
            "flows",
            "match",
            "guest_session_id",
        }
        assert set(dests[0]) == {"ip", "bytes", "flows"}


# ---------------------------------------------------------------------------
# parity between the generator and the device writer
# ---------------------------------------------------------------------------


def _kv(text: str) -> dict[str, str]:
    return dict(re.findall(r'([a-z0-9-]+)=("[^"]*"|\S+)', text))


class TestParity:
    def test_rendered_lines_equal_the_writer_desired_rows(self) -> None:
        config = desired_config(TARGET)
        lines = render_traffic_flow_lines(config, routeros_version="7.16.2 (stable)")
        assert lines[0] == TRAFFIC_FLOW_SECTION_HEADER
        settings_line = next(x for x in lines if x.startswith("/ip traffic-flow set "))
        ipfix_line = next(
            x for x in lines if x.startswith("/ip traffic-flow ipfix set ")
        )
        target_set = next(
            x for x in lines if x.startswith("/ip traffic-flow target set ")
        )
        assert _kv(settings_line.removeprefix("/ip traffic-flow set ")) == dict(
            config.settings
        )
        assert _kv(ipfix_line.removeprefix("/ip traffic-flow ipfix set ")) == dict(
            config.ipfix
        )
        target_fields = _kv(target_set.split("]", 1)[1])
        assert target_fields == dict(config.target or {})

    def test_target_add_is_guarded_and_duplicates_are_collapsed(self) -> None:
        lines = render_traffic_flow_lines(
            desired_config(TARGET), routeros_version="7.15"
        )
        add = next(x for x in lines if "target add" in x)
        assert add.startswith(":if ([:len [/ip traffic-flow target find where comment=")
        assert f'comment="{TRAFFIC_FLOW_TARGET_MARKER}"' in add
        assert any("target remove [:pick" in x for x in lines)
        # target in place before export is switched on (same order as the writer)
        assert lines.index(add) < next(
            i for i, x in enumerate(lines) if x.startswith("/ip traffic-flow set ")
        )

    def test_block_is_structurally_balanced(self) -> None:
        for line in render_traffic_flow_lines(
            desired_config(TARGET), routeros_version="7.15"
        ):
            assert line.count("{") == line.count("}"), line
            assert line.count("[") == line.count("]"), line
            assert line.count('"') % 2 == 0, line

    @pytest.mark.parametrize("version", ["6.49.10", None, "garbage"])
    def test_non_v7_gets_a_comment_not_a_guess(self, version: str | None) -> None:
        lines = render_traffic_flow_lines(
            desired_config(TARGET), routeros_version=version
        )
        assert all(x.startswith("#") for x in lines)
        assert "RouterOS 7 required" in lines[1]

    def test_render_network_config_carries_its_own_wrapped_block(self) -> None:
        lines = render_traffic_flow_lines(
            desired_config(TARGET), routeros_version="7.15"
        )
        script = render_network_config(
            dhcp_pools=[], vlans=[], port_forwarding_rules=[], traffic_flow_lines=lines
        )
        assert TRAFFIC_FLOW_SECTION_HEADER in script
        assert ":do { /ip traffic-flow set enabled=yes" in script
        assert (
            render_network_config(
                dhcp_pools=[],
                vlans=[],
                port_forwarding_rules=[],
                traffic_flow_lines=None,
            )
            == ""
        )


class TestGeneratorGate:
    peer = SimpleNamespace(tunnel_ip_address="10.20.0.31")
    server = SimpleNamespace(tunnel_network_cidr="10.20.0.0/24")

    def _lines(self, settings: Settings, **kw: Any) -> list[str] | None:
        args: dict[str, Any] = {
            "router_id": ROUTER_ID,
            "vendor": "mikrotik",
            "routeros_version": "7.15",
            "peer": self.peer,
            "server": self.server,
        }
        args["settings"] = kw.pop("settings_override", settings)
        args.update(kw)
        return traffic_flow_lines_for_router(**args)

    def test_on_when_every_gate_passes(self) -> None:
        lines = self._lines(_settings())
        assert lines and "dst-address=10.20.0.1" in "\n".join(lines)
        assert "src-address=10.20.0.31" in "\n".join(lines)

    @pytest.mark.parametrize(
        "kw",
        [
            {"settings": "flag_off"},
            {"router_id": OTHER_ROUTER},
            {"vendor": "omada"},
            {"peer": None},
        ],
    )
    def test_off_when_any_gate_fails(self, kw: dict[str, Any]) -> None:
        kw = dict(kw)
        if kw.pop("settings", None) == "flag_off":
            kw["settings_override"] = _settings(traffic_flow_enabled=False)
        assert self._lines(_settings(), **kw) is None

    def test_defaults_are_off(self) -> None:
        defaults = Settings()
        assert defaults.traffic_flow_enabled is False
        assert defaults.traffic_flow_router_id_set == frozenset()


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


class FakeRepo:
    def __init__(self) -> None:
        self.windows: list[Any] = []
        self.inserted: list[dict[str, Any]] = []
        self.keys: set[tuple[Any, ...]] = set()
        self.state = SimpleNamespace(
            last_window_start=None,
            last_pull_at=None,
            last_pull_ok=None,
            last_error=None,
            unknown_exporters=[],
        )
        self.exporters = {
            "10.20.0.31": ExporterRouter(
                router_id=ROUTER_ID, organization_id=None, location_id=None
            )
        }
        self.sessions: dict[str, list[uuid.UUID]] = {}
        self.peer: Any = SimpleNamespace(tunnel_ip_address="10.20.0.31", server_id=1)
        self.server: Any = SimpleNamespace(tunnel_network_cidr="10.20.0.0/24")
        self.pruned_before: datetime | None = None

    async def exporter_router_map(self):
        return self.exporters

    async def sessions_by_ip(self, router_id, ips, *, start, end):  # noqa: ANN001
        return {ip: self.sessions[ip] for ip in ips if ip in self.sessions}

    async def insert_window(self, values):  # noqa: ANN001
        key = (values["router_id"], values["source"], values["window_start"])
        if key in self.keys:
            return False
        self.keys.add(key)
        self.inserted.append(dict(values))
        self.windows.append(SimpleNamespace(**values))
        return True

    async def get_state(self):
        return self.state

    async def windows_since(self, since):  # noqa: ANN001
        return [w for w in self.windows if w.window_start >= since]

    async def router_labels(self, ids):  # noqa: ANN001
        return {
            i: {
                "router_name": "Lab hEX",
                "vendor": "mikrotik",
                "location_name": "Lab",
                "organization_name": "Wyfy",
            }
            for i in ids
        }

    async def peer_and_server(self, router_id):  # noqa: ANN001
        return self.peer, self.server

    async def delete_windows_before(self, cutoff, *, limit):  # noqa: ANN001
        self.pruned_before = cutoff
        return 0


# ---------------------------------------------------------------------------
# ingest service + overview
# ---------------------------------------------------------------------------


class TestIngestAndOverview:
    async def _ingest(self, repo: FakeRepo, start: datetime, rows: list[dict]) -> Any:
        return await TrafficFlowIngestService(repo).ingest_window(  # type: ignore[arg-type]
            window_start=start, window_seconds=300, rows=rows
        )

    async def test_ingest_attributes_and_is_idempotent(self) -> None:
        repo = FakeRepo()
        sid = uuid.uuid4()
        repo.sessions = {"192.168.95.10": [sid]}
        start = NOW - timedelta(minutes=10)
        rows = [
            _row("192.168.95.10", "142.250.1.1", 500),
            _row("10.9.9.9", "1.1.1.1", 1, exporter="10.20.0.99"),
        ]
        first = await self._ingest(repo, start, rows)
        assert first.written == 1 and first.unknown_exporters == ("10.20.0.99",)
        talker = repo.inserted[0]["top_talkers"][0]
        assert talker["match"] == "session" and talker["guest_session_id"] == str(sid)
        again = await self._ingest(repo, start, rows)
        assert again.written == 0 and again.duplicates == 1

    async def test_overview_ok_and_merged(self) -> None:
        repo = FakeRepo()
        for minutes in (10, 15):
            await self._ingest(
                repo,
                NOW - timedelta(minutes=minutes),
                [_row("192.168.95.10", "142.250.1.1", 100)],
            )
        repo.state.last_pull_ok = True
        data = await TrafficFlowOverviewService(
            repo, _settings(), now=lambda: NOW
        ).overview(minutes=60)  # type: ignore[arg-type]
        (router,) = data["routers"]
        assert router["state"] == RouterFlowState.OK.value
        assert router["windows"] == 2 and router["approximate"] is True
        assert router["talkers"][0]["bytes_up"] == 200
        assert router["destinations"][0] == {
            "ip": "142.250.1.1",
            "bytes": 200,
            "flows": 2,
        }

    @pytest.mark.parametrize(
        ("settings_kw", "pull_ok", "age_min", "want"),
        [
            ({"traffic_flow_enabled": False}, True, 5, RouterFlowState.DISABLED),
            ({"traffic_flow_router_ids": ""}, True, 5, RouterFlowState.NOT_ALLOWLISTED),
            ({}, False, 5, RouterFlowState.COLLECTOR_UNREACHABLE),
            ({}, True, None, RouterFlowState.NO_WINDOWS),
            ({}, True, 40, RouterFlowState.STALE),
        ],
    )
    async def test_overview_states(self, settings_kw, pull_ok, age_min, want) -> None:  # noqa: ANN001
        repo = FakeRepo()
        if age_min is not None:
            await self._ingest(
                repo,
                NOW - timedelta(minutes=age_min),
                [_row("192.168.95.10", "1.1.1.1", 1)],
            )
        repo.state.last_pull_ok = pull_ok
        data = await TrafficFlowOverviewService(
            repo,
            _settings(**settings_kw),
            now=lambda: NOW,  # type: ignore[arg-type]
        ).overview(minutes=60)
        states = {r["router_id"]: r["state"] for r in data["routers"]}
        assert states[str(ROUTER_ID)] == want.value


# ---------------------------------------------------------------------------
# pull sweep
# ---------------------------------------------------------------------------


class TestPull:
    async def _commit(self) -> None:
        return None

    async def test_failure_is_recorded_not_swallowed(self) -> None:
        repo = FakeRepo()

        async def boom(after: int):
            raise ConnectionError("agent down")

        result = await pull_once(
            repository=repo,
            settings=_settings(),  # type: ignore[arg-type]
            fetch_windows=boom,
            commit=self._commit,
            now=lambda: NOW,
        )
        assert result["ok"] is False
        assert (
            repo.state.last_pull_ok is False and "agent down" in repo.state.last_error
        )

    async def test_cursor_advances_and_repull_is_noop(self) -> None:
        repo = FakeRepo()
        start = int((NOW - timedelta(minutes=10)).timestamp())
        asked: list[int] = []

        async def fetch(after: int):
            asked.append(after)
            return {
                "windows": [
                    {
                        "window_start": start,
                        "window_seconds": 300,
                        "rows": [_row("192.168.95.10", "1.1.1.1", 9)],
                    }
                ]
            }

        first = await pull_once(
            repository=repo,
            settings=_settings(),  # type: ignore[arg-type]
            fetch_windows=fetch,
            commit=self._commit,
            now=lambda: NOW,
        )
        assert first["written"] == 1
        assert repo.state.last_window_start == datetime.fromtimestamp(start, tz=UTC)
        assert repo.pruned_before == NOW - timedelta(days=7)
        second = await pull_once(
            repository=repo,
            settings=_settings(),  # type: ignore[arg-type]
            fetch_windows=fetch,
            commit=self._commit,
            now=lambda: NOW,
        )
        assert asked[1] == start and second["windows"] == 0

    @pytest.mark.parametrize(
        ("kw", "skip"),
        [
            ({"traffic_flow_enabled": False}, "disabled"),
            ({"traffic_flow_agent_url": ""}, "agent_not_configured"),
        ],
    )
    async def test_gated_off_makes_no_call(self, kw, skip) -> None:  # noqa: ANN001
        async def never(after: int):
            raise AssertionError("must not be called")

        result = await pull_once(
            repository=FakeRepo(),
            settings=_settings(**kw),  # type: ignore[arg-type]
            fetch_windows=never,
            commit=self._commit,
        )
        assert result == {"skipped": skip}


# ---------------------------------------------------------------------------
# device service
# ---------------------------------------------------------------------------


class FakeAdapter:
    def __init__(self, *, refuse: bool = False) -> None:
        self.applied: list[Any] = []
        self.refuse = refuse
        self.state = SimpleNamespace(
            routeros_version="7.16.2",
            settings={"enabled": "no"},
            ipfix={},
            targets=(),
            foreign_targets=0,
        )

    async def read_traffic_flow(self, creds, *, marker):  # noqa: ANN001
        return self.state

    async def apply_traffic_flow(self, creds, config):  # noqa: ANN001
        from wyfy_device_gateway.mikrotik_traffic_flow import (
            TRAFFIC_FLOW_V7_REQUIRED,
            TrafficFlowRefusal,
        )

        if self.refuse:
            raise TrafficFlowRefusal(TRAFFIC_FLOW_V7_REQUIRED, "RouterOS 7 required")
        self.applied.append(config)
        return SimpleNamespace(
            writes=("add /ip/traffic-flow/target ...",),
            matches=True,
            mismatches=(),
            before=self.state,
            after=self.state,
        )


class FakeRouters:
    def __init__(self, **kw: Any) -> None:
        self.router = SimpleNamespace(
            id=ROUTER_ID,
            vendor="mikrotik",
            routeros_version="7.16.2",
            management_ip_address="10.20.0.31",
            public_ip_address=None,
            api_username="wyfy",
            organization_id=None,
        )
        for k, v in kw.items():
            setattr(self.router, k, v)

    async def get_router(self, router_id):  # noqa: ANN001
        return self.router

    def get_decrypted_api_secret(self, router):  # noqa: ANN001
        return "pw"


class FakeAudit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    async def create_audit_log_entry(self, **kw: Any) -> None:
        self.entries.append(kw)


def _device(
    settings: Settings | None = None,
    adapter: FakeAdapter | None = None,
    routers: FakeRouters | None = None,
    audit: FakeAudit | None = None,
):
    adapter = adapter or FakeAdapter()
    return TrafficFlowDeviceService(
        FakeRepo(),  # type: ignore[arg-type]
        routers or FakeRouters(),
        settings or _settings(),
        adapter_factory=lambda: adapter,
        credentials_factory=lambda router, secret: ("creds", secret),
        audit_writer=audit,
    ), adapter


class TestDeviceService:
    async def test_preview_renders_from_the_shared_source(self) -> None:
        service, _ = _device()
        data = await service.preview(ROUTER_ID)
        assert data["eligible"] is True and data["blockers"] == []
        assert data["lines"] == render_traffic_flow_lines(
            desired_config(TARGET), routeros_version="7.16.2"
        )

    async def test_dry_run_is_the_default_shape_and_writes_nothing(self) -> None:
        service, adapter = _device()
        data = await service.apply(
            ROUTER_ID, enabled=True, dry_run=True, actor_user_id=None
        )
        assert data["dry_run"] is True and adapter.applied == []
        assert any("add /ip/traffic-flow/target" in w for w in data["planned_writes"])

    @pytest.mark.parametrize(
        ("settings", "router_kw", "needle"),
        [
            ({"traffic_flow_enabled": False}, {}, "ENABLED is off"),
            ({"traffic_flow_router_ids": ""}, {}, "ROUTER_IDS"),
            ({}, {"vendor": "omada"}, "MikroTik only"),
            ({}, {"routeros_version": "6.49.10"}, "RouterOS 7 required"),
        ],
    )
    async def test_blocked_routers_are_refused_before_any_device_call(
        self,
        settings,
        router_kw,
        needle,  # noqa: ANN001
    ) -> None:
        service, adapter = _device(
            _settings(**settings), routers=FakeRouters(**router_kw)
        )
        with pytest.raises(TrafficFlowError) as exc:
            await service.apply(
                ROUTER_ID, enabled=True, dry_run=False, actor_user_id=None
            )
        assert needle in exc.value.message and adapter.applied == []

    async def test_disable_is_allowed_after_leaving_the_allowlist(self) -> None:
        service, adapter = _device(_settings(traffic_flow_router_ids=""))
        data = await service.apply(
            ROUTER_ID, enabled=False, dry_run=False, actor_user_id=None
        )
        assert data["matches"] is True
        assert adapter.applied[0].target is None

    async def test_device_refusal_surfaces_its_code(self) -> None:
        service, _ = _device(adapter=FakeAdapter(refuse=True))
        with pytest.raises(TrafficFlowError) as exc:
            await service.apply(
                ROUTER_ID, enabled=True, dry_run=False, actor_user_id=None
            )
        assert exc.value.code == "TRAFFIC_FLOW_V7_REQUIRED"

    async def test_real_apply_audits_and_reports_read_back(self) -> None:
        audit = FakeAudit()
        service, _ = _device(audit=audit)
        actor = uuid.uuid4()
        data = await service.apply(
            ROUTER_ID, enabled=True, dry_run=False, actor_user_id=actor
        )
        assert data["matches"] is True
        assert audit.entries[0]["action"] == "traffic_flow_applied"
        assert audit.entries[0]["actor_user_id"] == actor


# ---------------------------------------------------------------------------
# authorization
# ---------------------------------------------------------------------------


def _pins(router, path_suffix: str, method: str) -> dict:  # noqa: ANN001
    route = next(
        r for r in router.routes if r.path.endswith(path_suffix) and method in r.methods
    )
    closures = [
        {
            type(cell.cell_contents): cell.cell_contents
            for cell in (getattr(d.dependency, "__closure__", None) or ())
        }
        for d in route.dependencies
    ]
    pinned = [c for c in closures if ScopeType in c]
    assert pinned, closures
    return pinned[0]


class TestAuthorization:
    @pytest.mark.parametrize(
        ("suffix", "method", "perm"),
        [
            ("/overview", "GET", "traffic_flows.read"),
            ("/routers/{router_id}/config", "GET", "traffic_flows.read"),
            ("/routers/{router_id}/apply", "POST", "traffic_flows.update"),
        ],
    )
    def test_every_route_pinned_global(
        self, suffix: str, method: str, perm: str
    ) -> None:
        from app.domains.traffic_flow.router import traffic_flow_platform_router

        pin = _pins(traffic_flow_platform_router, suffix, method)
        assert pin[ScopeType] == ScopeType.GLOBAL and pin[str] == perm

    def test_routes_are_mounted_under_platform(self) -> None:
        from app.api.v1.router import api_v1_router

        paths = {r.path for r in api_v1_router.routes}
        assert "/platform/traffic-flow/overview" in paths
        assert not any(
            "traffic-flow" in p and not p.startswith("/platform/") for p in paths
        )

    def test_module_is_global_only(self) -> None:
        assert (
            MODULE_NARROWEST_SCOPE[PermissionModule.TRAFFIC_FLOWS] == ScopeType.GLOBAL
        )

    def test_only_super_admin_and_platform_admin_hold_it(self) -> None:
        holders = {
            role.slug
            for role in SYSTEM_ROLES
            if role.grants().get(PermissionModule.TRAFFIC_FLOWS)
        }
        assert holders == {"super-admin", "platform-admin"}
