"""Traffic flow: hub hostnames resolved by the sweep.

The hub's ``endpoint_host`` is a name in production, so the router's own
tunnel was not recognised as platform overhead until its address was put in
a setting by hand -- a value that goes stale, silently, the day the hub's
address changes.

Here: the sweep resolves names with a short TTL and stores the answer; every
reader takes it from the store. A failed lookup keeps the last good answer.
No test does a real lookup: the resolver is always a fake, and every host
and address is a reserved example value.
"""

from __future__ import annotations

import importlib.util
import pathlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.config import Settings
from app.domains.traffic_flow.models import TrafficFlowIngestState
from app.domains.traffic_flow.platform_overhead import (
    PLATFORM_HOST_TTL_SECONDS,
    host_resolutions,
    platform_endpoints_from,
    refresh_platform_hosts,
    refreshed_hosts,
)
from app.domains.traffic_flow.service import TrafficFlowStatusService
from app.domains.traffic_flow.tasks import pull_once

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
HOST = "hub.example.net"
OTHER_HOST = "hub2.example.net"
PORT = 51820
A1 = "192.0.2.10"
A2 = "192.0.2.11"
A6 = "2001:db8:aa::10"
LITERAL = "198.51.100.7"


@pytest.fixture(autouse=True)
def _info_logging(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO", logger="app.domains.traffic_flow")


class Resolver:
    """A fake DNS: ``answers[host]`` is a list of addresses or an exception
    to raise. Every call is recorded."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    async def __call__(self, host: str) -> list[str]:
        self.calls.append(host)
        answer = self.answers[host]
        if isinstance(answer, Exception):
            raise answer
        return list(answer)


def _endpoints(stored: Any, extra: tuple[str, ...] = ()) -> Any:
    return platform_endpoints_from([(HOST, PORT)], extra, stored)


class TestResolution:
    async def test_a_literal_address_is_never_looked_up(self) -> None:
        resolver = Resolver({})
        stored = await refreshed_hosts({}, [LITERAL, A6], now=NOW, resolver=resolver)
        assert stored == {} and resolver.calls == []
        platform = platform_endpoints_from([(LITERAL, PORT)], (), stored)
        assert platform.endpoints == frozenset({(LITERAL, PORT)})
        assert platform.hosts == () and platform.unresolved_hosts == ()

    async def test_a_hostname_resolving_to_one_address(self) -> None:
        resolver = Resolver({HOST: [A1]})
        stored = await refreshed_hosts({}, [HOST], now=NOW, resolver=resolver)
        assert stored == {
            HOST: {
                "addresses": [A1],
                "resolved_at": NOW.isoformat(),
                "attempted_at": NOW.isoformat(),
                "last_error": None,
            }
        }
        platform = _endpoints(stored)
        assert platform.endpoints == frozenset({(A1, PORT)})
        assert platform.unresolved_hosts == ()
        # Now the tunnel is recognised with nothing in the setting.
        assert platform.is_endpoint(A1, "udp", PORT)

    async def test_a_hostname_resolving_to_several_addresses_v4_and_v6(self) -> None:
        # Duplicates and other spellings, as a resolver may return them.
        resolver = Resolver({HOST: [A2, A1, A1, "2001:DB8:AA:0::10"]})
        stored = await refreshed_hosts({}, [HOST], now=NOW, resolver=resolver)
        assert stored[HOST]["addresses"] == sorted([A1, A2, A6])
        assert _endpoints(stored).endpoints == frozenset(
            {(A1, PORT), (A2, PORT), (A6, PORT)}
        )

    async def test_a_failed_lookup_keeps_the_last_good_answer(self) -> None:
        good = await refreshed_hosts(
            {}, [HOST], now=NOW, resolver=Resolver({HOST: [A1]})
        )
        later = NOW + timedelta(seconds=PLATFORM_HOST_TTL_SECONDS + 1)
        failing = Resolver({HOST: OSError("Name or service not known")})
        stored = await refreshed_hosts(good, [HOST], now=later, resolver=failing)
        assert failing.calls == [HOST]
        assert stored[HOST]["addresses"] == [A1]
        assert stored[HOST]["resolved_at"] == NOW.isoformat()  # when it was good
        assert stored[HOST]["attempted_at"] == later.isoformat()
        assert "Name or service not known" in stored[HOST]["last_error"]
        assert _endpoints(stored).endpoints == frozenset({(A1, PORT)})
        # ...for as long as it keeps failing.
        much_later = later + timedelta(days=3)
        stored = await refreshed_hosts(stored, [HOST], now=much_later, resolver=failing)
        assert stored[HOST]["addresses"] == [A1]

    @pytest.mark.parametrize(
        "answer", [TimeoutError(), [], ["not-an-address"], RuntimeError("boom")]
    )
    async def test_no_usable_answer_is_a_failure_not_an_empty_answer(
        self, answer: Any
    ) -> None:
        good = await refreshed_hosts(
            {}, [HOST], now=NOW, resolver=Resolver({HOST: [A1]})
        )
        later = NOW + timedelta(hours=1)
        stored = await refreshed_hosts(
            good, [HOST], now=later, resolver=Resolver({HOST: answer})
        )
        assert stored[HOST]["addresses"] == [A1]
        assert stored[HOST]["last_error"]

    async def test_a_new_answer_replaces_the_old_one_and_clears_the_error(self) -> None:
        stored = await refreshed_hosts(
            {}, [HOST], now=NOW, resolver=Resolver({HOST: [A1]})
        )
        later = NOW + timedelta(hours=1)
        stored = await refreshed_hosts(
            stored, [HOST], now=later, resolver=Resolver({HOST: OSError("x")})
        )
        moved = later + timedelta(hours=1)
        stored = await refreshed_hosts(
            stored, [HOST], now=moved, resolver=Resolver({HOST: [A2]})
        )
        # The hub moved: the old address is gone, with no setting to edit.
        assert stored[HOST] == {
            "addresses": [A2],
            "resolved_at": moved.isoformat(),
            "attempted_at": moved.isoformat(),
            "last_error": None,
        }

    async def test_a_hostname_that_never_resolved_is_named(self) -> None:
        stored = await refreshed_hosts(
            {}, [HOST], now=NOW, resolver=Resolver({HOST: OSError("nxdomain")})
        )
        assert stored[HOST]["addresses"] == [] and stored[HOST]["resolved_at"] is None
        platform = _endpoints(stored)
        assert not platform and platform.unresolved_hosts == (HOST,)
        (host,) = platform.hosts
        assert host.resolved_at is None and "nxdomain" in (host.last_error or "")


class TestTtl:
    async def test_no_lookup_inside_the_ttl(self) -> None:
        resolver = Resolver({HOST: [A1]})
        stored = await refreshed_hosts({}, [HOST], now=NOW, resolver=resolver)
        for seconds in (1, 300, PLATFORM_HOST_TTL_SECONDS - 1):
            again = await refreshed_hosts(
                stored, [HOST], now=NOW + timedelta(seconds=seconds), resolver=resolver
            )
            assert again == stored
        assert resolver.calls == [HOST]  # one lookup, however many sweeps

    async def test_a_lookup_once_the_ttl_has_passed(self) -> None:
        resolver = Resolver({HOST: [A1]})
        stored = await refreshed_hosts({}, [HOST], now=NOW, resolver=resolver)
        due = NOW + timedelta(seconds=PLATFORM_HOST_TTL_SECONDS)
        stored = await refreshed_hosts(stored, [HOST], now=due, resolver=resolver)
        assert resolver.calls == [HOST, HOST]
        assert stored[HOST]["resolved_at"] == due.isoformat()

    async def test_a_failing_host_is_not_hammered_either(self) -> None:
        resolver = Resolver({HOST: OSError("down")})
        stored = await refreshed_hosts({}, [HOST], now=NOW, resolver=resolver)
        await refreshed_hosts(
            stored, [HOST], now=NOW + timedelta(seconds=60), resolver=resolver
        )
        assert resolver.calls == [HOST]

    def test_the_ttl_is_minutes(self) -> None:
        assert 60 <= PLATFORM_HOST_TTL_SECONDS <= 1800

    async def test_a_host_no_longer_a_hub_is_dropped(self) -> None:
        resolver = Resolver({HOST: [A1], OTHER_HOST: [A2]})
        stored = await refreshed_hosts(
            {}, [HOST, OTHER_HOST], now=NOW, resolver=resolver
        )
        assert set(stored) == {HOST, OTHER_HOST}
        stored = await refreshed_hosts(stored, [OTHER_HOST], now=NOW, resolver=resolver)
        assert set(stored) == {OTHER_HOST}


class TestUnionWithTheSetting:
    async def test_setting_and_resolved_addresses_are_both_used(self) -> None:
        stored = await refreshed_hosts(
            {}, [HOST], now=NOW, resolver=Resolver({HOST: [A1]})
        )
        platform = _endpoints(stored, extra=(A2, "junk"))
        assert platform.endpoints == frozenset({(A1, PORT), (A2, PORT)})

    def test_the_setting_alone_still_works_before_the_first_lookup(self) -> None:
        platform = _endpoints({}, extra=(A2,))
        assert platform.endpoints == frozenset({(A2, PORT)})
        # ...and the name is still reported as never resolved.
        assert platform.unresolved_hosts == (HOST,)

    def test_the_setting_is_an_override_and_normally_empty(self) -> None:
        assert Settings().traffic_flow_platform_addresses == ""
        description = Settings.model_fields[
            "traffic_flow_platform_addresses"
        ].description
        assert "NORMALLY EMPTY" in description

    def test_malformed_stored_values_read_as_nothing(self) -> None:
        for stored in (None, [], "x", {HOST: "x"}, {HOST: {"addresses": ["junk"]}}):
            assert not _endpoints(stored).endpoints
        assert host_resolutions({HOST: {"addresses": [A1, "junk", A1]}})[
            HOST
        ].addresses == (A1,)


# ---------------------------------------------------------------------------
# the sweep, and no lookup anywhere else
# ---------------------------------------------------------------------------


class Repo:
    def __init__(self, hosts: list[str]) -> None:
        self.hosts = hosts
        self.state = SimpleNamespace(
            last_window_start=None,
            last_pull_at=None,
            last_pull_ok=None,
            last_error=None,
            unknown_exporters=[],
            platform_hosts={},
        )
        self.endpoint_reads = 0

    async def platform_server_hosts(self) -> list[str]:
        return list(self.hosts)

    async def get_state(self) -> Any:
        return self.state

    async def platform_endpoints(self, settings: Any) -> Any:
        self.endpoint_reads += 1
        return platform_endpoints_from(
            [(h, PORT) for h in self.hosts], (), self.state.platform_hosts
        )

    async def exporter_router_map(self) -> dict[str, Any]:
        return {}

    async def delete_windows_before(self, cutoff, *, limit):  # noqa: ANN001
        return 0

    async def delete_service_buckets_before(self, cutoff, *, limit):  # noqa: ANN001
        return 0

    async def delete_destination_buckets_before(self, cutoff, *, limit):  # noqa: ANN001
        return 0

    async def fleet_routers(self, router_id=None, *, location_id=None):  # noqa: ANN001
        return []

    async def router_activity(self, recent_since):  # noqa: ANN001
        return {}


_SETTINGS = SimpleNamespace(
    traffic_flow_enabled=True,
    traffic_flow_agent_url="http://hub.invalid:9094",
    traffic_flow_agent_secret="s3cret",
    traffic_flow_platform_addresses="",
)


async def _sweep(repo: Repo, resolver: Resolver, now: datetime) -> dict[str, Any]:
    commits: list[int] = []

    async def fetch(after: int) -> dict[str, Any]:
        return {"windows": []}

    async def commit() -> None:
        commits.append(1)

    result = await pull_once(
        repository=repo,  # type: ignore[arg-type]
        settings=_SETTINGS,  # type: ignore[arg-type]
        fetch_windows=fetch,
        commit=commit,
        now=lambda: now,
        resolver=resolver,
    )
    assert commits, "the sweep must commit what it resolved"
    return result


class TestSweep:
    async def test_the_sweep_resolves_and_stores(self) -> None:
        repo, resolver = Repo([HOST]), Resolver({HOST: [A1]})
        result = await _sweep(repo, resolver, NOW)
        assert result["ok"] is True
        assert repo.state.platform_hosts[HOST]["addresses"] == [A1]

    async def test_many_sweeps_inside_the_ttl_are_one_lookup(self) -> None:
        repo, resolver = Repo([HOST]), Resolver({HOST: [A1]})
        for minutes in (0, 5):
            await _sweep(repo, resolver, NOW + timedelta(minutes=minutes))
        assert resolver.calls == [HOST]
        await _sweep(repo, resolver, NOW + timedelta(minutes=10))
        assert resolver.calls == [HOST, HOST]

    async def test_a_dns_failure_does_not_stop_the_sweep(self) -> None:
        repo = Repo([HOST])
        await _sweep(repo, Resolver({HOST: [A1]}), NOW)
        result = await _sweep(
            repo, Resolver({HOST: OSError("servfail")}), NOW + timedelta(minutes=15)
        )
        assert result["ok"] is True
        assert repo.state.platform_hosts[HOST]["addresses"] == [A1]
        assert "servfail" in repo.state.platform_hosts[HOST]["last_error"]

    async def test_a_resolver_that_blows_up_changes_nothing(self) -> None:
        class Broken(Repo):
            async def platform_server_hosts(self) -> list[str]:
                raise RuntimeError("database gone")

        repo = Broken([HOST])
        changed = await refresh_platform_hosts(repo, now=NOW, resolver=Resolver({}))
        assert changed is False and repo.state.platform_hosts == {}

    async def test_unchanged_answers_do_not_rewrite_the_row(self) -> None:
        repo, resolver = Repo([HOST]), Resolver({HOST: [A1]})
        assert await refresh_platform_hosts(repo, now=NOW, resolver=resolver) is True
        held = repo.state.platform_hosts
        assert (
            await refresh_platform_hosts(
                repo, now=NOW + timedelta(seconds=30), resolver=resolver
            )
            is False
        )
        assert repo.state.platform_hosts is held

    async def test_a_repository_without_hubs_is_left_alone(self) -> None:
        assert (
            await refresh_platform_hosts(object(), now=NOW, resolver=Resolver({}))
            is False
        )

    def test_no_read_path_can_do_a_lookup(self) -> None:
        """The resolver is called from ``refreshed_hosts`` only, and that is
        reached from the sweep only. Nothing a request runs imports it."""
        domain = pathlib.Path("app/domains/traffic_flow")
        users = sorted(
            path.name
            for path in domain.glob("*.py")
            if "refresh_platform_hosts" in path.read_text()
            or "resolve_host" in path.read_text()
        )
        assert users == ["platform_overhead.py", "tasks.py"]
        loader = (domain / "platform_overhead.py").read_text()
        body = loader[loader.index("async def load_platform_endpoints") :]
        body = body[: body.index("async def platform_endpoints_of")]
        assert "getaddrinfo" not in body and "resolve" not in body.replace(
            "resolved", ""
        )


class TestStatus:
    async def _status(self, repo: Repo, now: datetime) -> dict[str, Any]:
        service = TrafficFlowStatusService(repo, _SETTINGS, now=lambda: now)  # type: ignore[arg-type]
        return (await service.status())["platform_overhead"]

    async def test_count_and_age_of_resolved_addresses(self) -> None:
        repo = Repo([HOST])
        await _sweep(repo, Resolver({HOST: [A1, A2]}), NOW)
        status = await self._status(repo, NOW + timedelta(minutes=7))
        assert status["endpoints_known"] == 2 and status["unresolved_hosts"] == []
        assert status["hosts"] == [
            {
                "host": HOST,
                "addresses": 2,
                "resolved_at": NOW.isoformat(),
                "age_seconds": 420,
                "last_attempt_at": NOW.isoformat(),
                "last_error": None,
                "never_resolved": False,
            }
        ]
        # A count, never the addresses themselves.
        assert A1 not in str(status) and A2 not in str(status)

    async def test_a_hostname_that_never_resolved_is_said_plainly(self) -> None:
        repo = Repo([HOST])
        await _sweep(repo, Resolver({HOST: OSError("nxdomain")}), NOW)
        status = await self._status(repo, NOW)
        assert status["endpoints_known"] == 0
        assert status["unresolved_hosts"] == [HOST]
        (host,) = status["hosts"]
        assert host["never_resolved"] is True and host["addresses"] == 0
        assert host["resolved_at"] is None and host["age_seconds"] is None
        assert "nxdomain" in host["last_error"]

    async def test_a_stale_answer_shows_its_age_and_the_error(self) -> None:
        repo = Repo([HOST])
        await _sweep(repo, Resolver({HOST: [A1]}), NOW)
        later = NOW + timedelta(hours=2)
        await _sweep(repo, Resolver({HOST: OSError("timeout")}), later)
        (host,) = (await self._status(repo, later))["hosts"]
        assert host["addresses"] == 1 and host["never_resolved"] is False
        assert host["age_seconds"] == 7200
        assert host["last_attempt_at"] == later.isoformat()
        assert "timeout" in host["last_error"]

    async def test_a_literal_hub_has_no_host_entry(self) -> None:
        status = await self._status(Repo([LITERAL]), NOW)
        assert status["endpoints_known"] == 1 and status["hosts"] == []


class TestMigration:
    FILE = pathlib.Path("alembic/versions/0165_traffic_flow_platform_hosts.py")

    def _run(self, fn: str) -> tuple[Any, list[str]]:
        spec = importlib.util.spec_from_file_location("m0165", self.FILE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        statements: list[str] = []

        class _Op:
            def execute(self, sql: Any) -> None:
                statements.append(" ".join(str(sql).split()))

            def __getattr__(self, name: str) -> Any:
                raise AssertionError(f"op.{name} is not guarded; use op.execute")

        module.op = _Op()
        getattr(module, fn)()
        return module, statements

    def test_it_is_the_single_head(self) -> None:
        module, _ = self._run("upgrade")
        assert module.down_revision == "0164_traffic_flow_window_overhead"
        versions = list(pathlib.Path("alembic/versions").glob("*.py"))
        assert [
            p.name
            for p in versions
            if f'down_revision = "{module.down_revision}"' in p.read_text()
        ] == [self.FILE.name]
        # One revision follows this one (the review-prompt session columns).
        # A second child would be a second head.
        assert [
            p.name
            for p in versions
            if f'down_revision = "{module.revision}"' in p.read_text()
        ] == ["0166_add_review_prompt_columns_to_guest_sessions.py"]
        # Recognised by name in the findings test, or the deploy check fails.
        findings = pathlib.Path("tests/unit/test_traffic_flow_findings.py").read_text()
        assert self.FILE.name in findings

    def test_one_guarded_column_with_a_default_for_the_existing_row(self) -> None:
        _, up = self._run("upgrade")
        assert up == [
            "ALTER TABLE traffic_flow_ingest_state ADD COLUMN IF NOT EXISTS "
            "platform_hosts JSONB NOT NULL DEFAULT '{}'::jsonb"
        ]
        _, down = self._run("downgrade")
        assert down == [
            "ALTER TABLE traffic_flow_ingest_state DROP COLUMN IF EXISTS platform_hosts"
        ]

    def test_the_model_declares_it(self) -> None:
        column = TrafficFlowIngestState.__table__.columns["platform_hosts"]
        assert column.nullable is False


def test_no_real_host_or_address_in_this_change() -> None:
    """Public repository: example names and documentation ranges only."""
    import re

    for path in (
        pathlib.Path("app/domains/traffic_flow/platform_overhead.py"),
        pathlib.Path("alembic/versions/0165_traffic_flow_platform_hosts.py"),
    ):
        text = path.read_text()
        assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text), path
        assert not re.search(r"\b[a-z0-9-]+\.(com|in|io|net)\b", text), path
