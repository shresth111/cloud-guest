"""Security activity: router rule counters -> hourly deltas -> plain
sentences, without ever writing to a router.

Pins:

1. Classification: each platform-owned row lands in the right protection;
   foreign, disabled, allow and counter-less rows are never counted.
2. The collector reads through ``ReadOnlyDeviceReader`` only, baselines the
   first read (delta 0), diffs later ones, and treats a counter that went
   down as a restart.
3. The view: absent protections stay absent (never a fake zero),
   Cloudflare degrades honestly, staff changes read as sentences.
4. Load and wiring: staggered leaves, device-I/O queue, hourly beat entry.
5. The Cloudflare analytics call sums only blocked decisions and reports a
   permission failure as an error, not as zero.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import SecretStr

from app.core.celery_app import DEVICE_IO_QUEUE_NAME, celery_app
from app.domains.dns_filtering.cloudflare_client import (
    CloudflareApiError,
    CloudflareGatewayClient,
)
from app.domains.rbac.enums import AuditAction
from app.domains.security_activity.classify import (
    Protection,
    classify_counter_rows,
    protection_sentence,
)
from app.domains.security_activity.constants import (
    TASK_COLLECT_SECURITY_COUNTERS_FOR_ROUTER,
    TASK_RUN_SECURITY_COUNTER_SWEEP,
)
from app.domains.security_activity.repository import (
    SECURITY_AUDIT_ACTIONS,
    CloudflareScope,
    CollectionTarget,
    PreviousSample,
    ProtectionTotals,
    RuleTotals,
    StaffChange,
)
from app.domains.security_activity.service import (
    SecurityActivityService,
    SecurityCounterCollector,
    hour_bucket,
)
from app.domains.security_activity.tasks import stagger_countdown

FW_RULE_ID = "3f1c2b9a-1111-4222-8333-444455556666"
CF_RULE_ID = "9a8b7c6d-1111-4222-8333-444455556666"


def _row(comment: str, packets: int = 10, **extra: object) -> dict[str, object]:
    return {
        "comment": comment,
        "packets": str(packets),
        "bytes": str(packets * 60),
        **extra,
    }


FILTER_ROWS = [
    _row("cloudguest-fw-flood-limit", 7, action="drop"),
    _row(
        f"cloudguest-fw:{FW_RULE_ID}",
        12,
        action="drop",
        **{"dst-address": "192.168.88.0/24"},
    ),
    _row(
        "cloudguest-fw:aaaaaaaa-1111-4222-8333-444455556666",
        3,
        action="reject",
        **{"dst-address": "8.8.8.8"},
    ),
    _row("cloudguest-fw:bbbbbbbb-1111-4222-8333-444455556666", 99, action="accept"),
    _row(
        f"WyfyGuest content filter {CF_RULE_ID} (https): Facebook",
        5,
        action="drop",
        **{"tls-host": "facebook.com"},
    ),
    _row(
        f"WyfyGuest content filter {CF_RULE_ID} (https subdomains): Facebook",
        6,
        action="drop",
    ),
    _row("Wyfy Guest content filtering: block listed addresses", 4, action="drop"),
    _row("cloudguest-dnsf-vpn-wireguard-auth", 2, action="drop"),
    _row("cloudguest-fw-block-wan-dns", 8, action="drop"),
    _row("cloudguest-fw-guest-isolation", 1, action="drop"),
    _row("cloudguest-fw-flood-limit-but-disabled", 50, action="drop"),
    _row("someone's own rule", 1000, action="drop"),
    _row("cloudguest-fw-band-begin", 0, action="passthrough"),
    {"comment": "cloudguest-block-dot-udp", "action": "drop"},  # no counters
    _row("cloudguest-fw-flood-limit", 999, action="drop", disabled="true"),
]
NAT_ROWS = [_row("cloudguest-dnsf-redirect-dns-udp", 20, action="redirect")]


class TestClassification:
    def test_each_owned_row_lands_in_its_protection(self) -> None:
        readings = classify_counter_rows(FILTER_ROWS, NAT_ROWS)
        by = {}
        for r in readings:
            by.setdefault(r.protection, []).append(r)
        assert [r.packets for r in by[Protection.FLOOD_LIMIT]] == [7]
        assert by[Protection.PRIVATE_NETWORK][0].ref_id == FW_RULE_ID
        assert [r.packets for r in by[Protection.ACCESS_RULE]] == [3]
        assert sorted(r.packets for r in by[Protection.WEBSITE_BLOCK]) == [5, 6]
        assert by[Protection.WEBSITE_BLOCK][0].label == "Facebook"
        assert by[Protection.WEBSITE_BLOCK][0].ref_id == CF_RULE_ID
        assert [r.packets for r in by[Protection.ADDRESS_BLOCK]] == [4]
        assert [r.packets for r in by[Protection.VPN_BLOCK]] == [2]
        assert [r.packets for r in by[Protection.DNS_BYPASS]] == [8]
        assert [r.packets for r in by[Protection.GUEST_ISOLATION]] == [1]
        assert [r.packets for r in by[Protection.DNS_REDIRECT]] == [20]

    def test_never_counts_what_is_not_ours_or_cannot_be_read(self) -> None:
        keys = {r.rule_key for r in classify_counter_rows(FILTER_ROWS, NAT_ROWS)}
        assert "someone's own rule" not in keys  # a venue's own rule
        assert "cloudguest-fw:bbbbbbbb-1111-4222-8333-444455556666" not in keys  # allow
        assert "cloudguest-block-dot-udp" not in keys  # no counters: not zero
        assert "cloudguest-fw-flood-limit-but-disabled" not in keys
        assert (
            sum(
                r.packets
                for r in classify_counter_rows(FILTER_ROWS)
                if r.rule_key == "cloudguest-fw-flood-limit"
            )
            == 7
        )  # the disabled duplicate is skipped

    def test_sentences(self) -> None:
        assert (
            protection_sentence(Protection.PRIVATE_NETWORK, 312)
            == "Stopped 312 attempts by guests to reach your private network."
        )
        assert protection_sentence(Protection.WEBSITE_BLOCK, 0).startswith("No one")
        assert "1,234" in protection_sentence(Protection.FLOOD_LIMIT, 1234)


# ============================================================================
# 2. Collector
# ============================================================================


class FakeCapture:
    def __init__(self, filter_rows, nat_rows, errors=None):
        self.sections = {"firewall_filter": filter_rows, "firewall_nat": nat_rows}
        self.errors = errors or {}


class FakeReader:
    """Exposes only what ReadOnlyDeviceReader exposes. Anything else the
    collector tried to call would raise AttributeError."""

    calls: list[list[str]] = []

    def __init__(self, creds, rows=None, exc=None):
        self.creds = creds
        self._rows = rows
        self._exc = exc

    async def read_all(self, sections):
        FakeReader.calls.append(list(sections))
        if self._exc:
            raise self._exc
        return FakeCapture(*self._rows)


class FakeRepo:
    def __init__(self, target, previous=None):
        self.target = target
        self.previous = previous or {}
        self.upserts: list[dict] = []

    async def get_collection_target(self, router_id):
        return self.target

    async def latest_samples(self, router_id):
        return self.previous

    async def upsert_sample(self, **fields):
        self.upserts.append(fields)

    async def rule_names(
        self, *, organization_id, firewall_rule_ids, content_filter_rule_ids
    ):
        return {FW_RULE_ID: "Keep guests off office LAN", CF_RULE_ID: "Facebook"}


def _target():
    return CollectionTarget(
        router_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        location_id=uuid.uuid4(),
        host="10.20.0.31",
        api_username="wyfy",
        api_credentials_encrypted="enc",
    )


NOW = datetime(2026, 10, 1, 10, 25, tzinfo=UTC)


def _collector(repo, rows=(FILTER_ROWS, NAT_ROWS), exc=None):
    return SecurityCounterCollector(
        repo,
        reader_factory=lambda creds: FakeReader(creds, rows=rows, exc=exc),
        decrypt=lambda _: "secret",
        clock=lambda: NOW,
    )


class TestCollector:
    async def test_first_read_is_a_baseline_not_a_burst(self) -> None:
        repo = FakeRepo(_target())
        FakeReader.calls = []
        summary = await _collector(repo).collect_for_router(repo.target.router_id)
        assert summary.status == "ok"
        assert summary.packets_added == 0
        assert summary.baselined == summary.rules_seen
        assert all(u["packets_delta"] == 0 for u in repo.upserts)
        assert all(u["bucket_start"] == hour_bucket(NOW) for u in repo.upserts)
        # One read, of exactly the two counter sections.
        assert FakeReader.calls == [["firewall_filter", "firewall_nat"]]

    async def test_later_reads_are_diffed_and_restarts_count_from_zero(self) -> None:
        then = NOW - timedelta(hours=1)
        repo = FakeRepo(
            _target(),
            previous={
                "cloudguest-fw-flood-limit": PreviousSample(5, 300, then),
                # counter went from 40 down to 12: the router restarted
                f"cloudguest-fw:{FW_RULE_ID}": PreviousSample(40, 2400, then),
            },
        )
        await _collector(repo).collect_for_router(repo.target.router_id)
        by_key = {u["rule_key"]: u for u in repo.upserts}
        assert by_key["cloudguest-fw-flood-limit"]["packets_delta"] == 2
        assert by_key[f"cloudguest-fw:{FW_RULE_ID}"]["packets_delta"] == 12
        assert (
            by_key[f"cloudguest-fw:{FW_RULE_ID}"]["label"]
            == "Keep guests off office LAN"
        )

    async def test_unreachable_router_is_a_gap(self) -> None:
        repo = FakeRepo(_target())
        summary = await _collector(repo, exc=OSError("timed out")).collect_for_router(
            repo.target.router_id
        )
        assert summary.status == "unreachable"
        assert repo.upserts == []

    async def test_no_credentials_is_skipped_without_a_connection(self) -> None:
        target = _target()
        repo = FakeRepo(
            CollectionTarget(
                router_id=target.router_id,
                organization_id=target.organization_id,
                location_id=None,
                host=None,
                api_username=None,
                api_credentials_encrypted=None,
            )
        )
        FakeReader.calls = []
        summary = await _collector(repo).collect_for_router(target.router_id)
        assert summary.status == "skipped"
        assert FakeReader.calls == []

    def test_the_default_reader_is_the_read_only_one(self) -> None:
        import inspect

        from wyfy_device_gateway.read_only_reader import ReadOnlyDeviceReader

        default = (
            inspect.signature(SecurityCounterCollector.__init__)
            .parameters["reader_factory"]
            .default
        )
        assert default is ReadOnlyDeviceReader

    def test_the_domain_never_imports_a_writing_adapter(self) -> None:
        import pathlib

        package = pathlib.Path(__file__).parents[2] / "app/domains/security_activity"
        for source in package.glob("*.py"):
            text = source.read_text()
            for forbidden in (
                "MikroTikAdapter",
                "device_adapters",
                "get_adapter(",
                "apply_flood_limit",
                "push_config",
            ):
                assert forbidden not in text, (source.name, forbidden)


# ============================================================================
# 3. The view
# ============================================================================


class ViewRepo:
    def __init__(self, *, totals=(), rules=(), cf_scope=None, changes=()):
        self._totals = list(totals)
        self._rules = list(rules)
        self._cf = cf_scope or CloudflareScope([], [], 0)
        self._changes = list(changes)
        self.seen_scope: list[tuple] = []

    async def protection_totals(self, *, organization_id, location, since):
        self.seen_scope.append((organization_id, location))
        return self._totals

    async def top_rules(self, *, organization_id, location, since, limit=30):
        return self._rules

    async def agent_managed_router_count(self, *, organization_id, location):
        return 2

    async def device_block_counts(self, *, organization_id, location, since):
        return 3, 1

    async def recent_staff_changes(self, *, organization_id, location, since, limit=20):
        return self._changes

    async def cloudflare_scope(self, *, organization_id, location):
        return self._cf


class TestView:
    async def test_counts_sentences_and_absent_protections(self) -> None:
        org = uuid.uuid4()
        repo = ViewRepo(
            totals=[ProtectionTotals("private_network", 312, 2, NOW)],
            rules=[RuleTotals("private_network", "Keep guests off office LAN", 312)],
            changes=[StaffChange(NOW, "firewall_flood_limit_changed", "x", "Asha Rao")],
        )
        view = await SecurityActivityService(repo, clock=lambda: NOW).build(
            organization_id=org, location=None, window="24h"
        )
        keys = [p["key"] for p in view["protections"]]
        assert keys == [
            "private_network",
            "device_block",
        ]  # website_block etc. absent, not 0
        private = view["protections"][0]
        assert private["sentence"] == (
            "Stopped 312 attempts by guests to reach your private network."
        )
        assert private["top_rules"] == [
            {"label": "Keep guests off office LAN", "count": 312}
        ]
        assert view["protections"][1]["count"] == 3
        assert view["staff_changes"][0]["summary"] == (
            "Asha Rao changed the connection flood limit."
        )
        assert repo.seen_scope == [(org, None)]

    async def test_cloudflare_shared_profile_is_unavailable_not_zero(self) -> None:
        async def counter(*_):  # pragma: no cover - must not be called
            raise AssertionError("queried a shared location")

        repo = ViewRepo(cf_scope=CloudflareScope([], ["loc-shared"], 1))
        view = await SecurityActivityService(
            repo, cloudflare_counter=counter, clock=lambda: NOW
        ).build(organization_id=uuid.uuid4(), location=None, window="7d")
        cf = view["protections"][-1]
        assert cf["key"] == "cloudflare_dns"
        assert cf["available"] is False and cf["count"] is None
        assert "shared" in cf["unavailable_reason"]

    async def test_cloudflare_permission_error_degrades(self) -> None:
        async def counter(*_):
            raise CloudflareApiError(
                "gateway_analytics", "not authorized for that account"
            )

        repo = ViewRepo(cf_scope=CloudflareScope(["loc-1"], [], 1))
        view = await SecurityActivityService(
            repo, cloudflare_counter=counter, clock=lambda: NOW
        ).build(organization_id=uuid.uuid4(), location=None, window="24h")
        cf = view["protections"][-1]
        assert cf["available"] is False
        assert "analytics" in cf["unavailable_reason"]

    async def test_cloudflare_counts_when_attributable(self) -> None:
        async def counter(locations, start, end):
            assert locations == ["loc-1"]
            return {"loc-1": 41, "loc-other": 999}

        repo = ViewRepo(cf_scope=CloudflareScope(["loc-1"], [], 1))
        view = await SecurityActivityService(
            repo, cloudflare_counter=counter, clock=lambda: NOW
        ).build(organization_id=uuid.uuid4(), location=None, window="24h")
        cf = view["protections"][-1]
        assert cf["count"] == 41 and cf["available"] is True

    async def test_no_category_filtering_means_no_cloudflare_entry(self) -> None:
        view = await SecurityActivityService(ViewRepo(), clock=lambda: NOW).build(
            organization_id=uuid.uuid4(), location=None, window="24h"
        )
        assert "cloudflare_dns" not in [p["key"] for p in view["protections"]]


def test_audit_actions_exist() -> None:
    values = {a.value for a in AuditAction}
    assert set(SECURITY_AUDIT_ACTIONS) <= values


# ============================================================================
# 4. Load and wiring
# ============================================================================


def test_leaves_are_staggered_and_wrap() -> None:
    delays = [stagger_countdown(i) for i in range(1000)]
    assert delays[:3] == [0, 3, 6]
    assert max(delays) < 1800
    assert len(set(delays[:600])) == 600  # no two of the first 600 at once


def test_leaf_runs_on_device_io_and_sweep_is_hourly() -> None:
    import app.domains.security_activity.tasks  # noqa: F401 -- registers tasks

    routes = celery_app.conf.task_routes
    assert routes[TASK_COLLECT_SECURITY_COUNTERS_FOR_ROUTER] == {
        "queue": DEVICE_IO_QUEUE_NAME
    }
    assert TASK_RUN_SECURITY_COUNTER_SWEEP not in routes
    entry = celery_app.conf.beat_schedule["security-counter-sweep"]
    assert entry["task"] == TASK_RUN_SECURITY_COUNTER_SWEEP
    assert entry["schedule"] == 3600.0


# ============================================================================
# 5. Cloudflare analytics
# ============================================================================


def _client(handler) -> CloudflareGatewayClient:
    return CloudflareGatewayClient(
        api_token=SecretStr("tok-123"),
        account_id="acc",
        transport=httpx.MockTransport(handler),
    )


async def test_cloudflare_sums_only_blocked_decisions() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        groups = [
            {"count": 10, "dimensions": {"locationId": "L1", "resolverDecision": 3}},
            {"count": 5, "dimensions": {"locationId": "L1", "resolverDecision": 9}},
            {"count": 500, "dimensions": {"locationId": "L1", "resolverDecision": 5}},
            {"count": 2, "dimensions": {"locationId": "L2", "resolverDecision": 2}},
        ]
        return httpx.Response(
            200,
            json={
                "data": {
                    "viewer": {
                        "accounts": [{"gatewayResolverQueriesAdaptiveGroups": groups}]
                    }
                }
            },
        )

    client = _client(handler)
    counts = await client.gateway_blocked_query_counts(
        location_ids=["L1", "L2"], start=NOW - timedelta(days=1), end=NOW
    )
    await client.aclose()
    assert counts == {"L1": 15, "L2": 2}
    assert seen["path"].endswith("/graphql")
    assert seen["body"]["variables"]["accountTag"] == "acc"


async def test_cloudflare_permission_error_is_an_error_and_redacted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"data": None, "errors": [{"message": "not authorized tok-123"}]}
        )

    client = _client(handler)
    with pytest.raises(CloudflareApiError) as caught:
        await client.gateway_blocked_query_counts(
            location_ids=["L1"], start=NOW - timedelta(days=1), end=NOW
        )
    await client.aclose()
    assert "tok-123" not in caught.value.message
