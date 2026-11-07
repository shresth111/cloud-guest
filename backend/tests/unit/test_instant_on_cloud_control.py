"""Aruba Instant On cloud control: block / unblock / disconnect / guest speed cap.

Every request goes to an ``httpx.MockTransport``. Body shapes are the ones
the portal bundle (3.4.2.0-26) sends and the live site returned on
2026-10-03 -- see ``wyfy-ops/aruba-ap21/INSTANT_ON_CLOUD_CONTROL.md``. No
real token, secret or customer MAC appears here.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core.config import Settings
from app.domains.guest.constants import GuestSessionStatus
from app.domains.network_integration import instant_on_control as control
from app.domains.network_integration.providers.aruba_instant_on_client import (
    InstantOnAuthConfig,
    InstantOnForbiddenError,
    InstantOnTokenManager,
    InstantOnTokenState,
)
from app.domains.network_integration.providers.aruba_instant_on_control import (
    BlockResult,
    InstantOnClientNotBlockableError,
    InstantOnControlClient,
    InstantOnWriteNotConfirmedError,
    normalize_instant_on_mac,
)
from tests.unit.test_instant_on_client import FakeCredentials, FakeLock, FakeStore

API = "https://portal.instant-on.hpe.com/api"
SSO = "https://sso.arubainstanton.com"
SITE = "3f6c2a10-7b1d-4c9e-9a55-0d2e8b7c4f11"
MAC = "02:11:22:33:44:55"
NET = "net-1"
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# A tiny fake Instant On site
# ---------------------------------------------------------------------------


class FakeSite:
    """Stateful: blockedClients and the guest network, as the API keeps them.
    ``ignore_writes`` makes every write answer 2xx and change nothing -- the
    Omada errorCode-0 failure mode."""

    def __init__(self) -> None:
        self.blocked: list[dict] = []
        self.clients: list[dict] = [
            {"kind": "clientSummary", "id": MAC, "macAddress": MAC, "isBlockable": True}
        ]
        self.network: dict = {
            "id": NET,
            "kind": "networkSummary",
            "networkName": "WYFY_ARUBA",
            "preSharedKey": "do-not-lose-me",
            "isGuestPortalEnabled": True,
            "qos": {
                "isBandwidthLimitEnabled": False,
                "isDownloadBandwidthLimitEnabled": False,
                "isUploadBandwidthLimitEnabled": False,
                "bandwidthLimitMode": "perClient",
                "perClientDownloadBandwidthLimitInMbps": 1000,
                "perClientUploadBandwidthLimitInMbps": 1000,
                "trafficPriority": "low",
            },
            "isBandwidthLimitEnabled": False,
        }
        self.ignore_writes = False
        self.write_status: int | None = None
        self.timeout_on_write = False
        self.requests: list[httpx.Request] = []
        # Network total rollback: the first PUT lands wrong, reads fail after it,
        # or the restoring PUT is refused.
        self.mangle_next_total = False
        self.fail_reads_after_write = False
        self.refuse_second_write = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.removeprefix(f"/api/sites/{SITE}/")
        if request.method != "GET":
            if self.timeout_on_write:
                self.timeout_on_write = False
                self._apply(request, path)
                raise httpx.ReadTimeout("lost", request=request)
            if self.write_status is not None:
                return httpx.Response(self.write_status, json={})
            if self.refuse_second_write and len(self.writes()) > 1:
                return httpx.Response(400, json={})
            if not self.ignore_writes:
                self._apply(request, path)
            if self.mangle_next_total:
                self.mangle_next_total = False
                self.network["qos"]["perNetworkDownstreamBandwidthLimitInMbps"] = 1
            return httpx.Response(200, json={})
        if path == "blockedClients":
            return httpx.Response(
                200, json={"kind": "resourceList", "elements": self.blocked}
            )
        if path == "clientSummary":
            return httpx.Response(200, json={"elements": self.clients, "metaData": {}})
        if path == "networksSummary":
            if self.fail_reads_after_write and self.writes():
                return httpx.Response(500, json={})
            return httpx.Response(200, json={"elements": [self.network]})
        return httpx.Response(404, json={})

    def _apply(self, request: httpx.Request, path: str) -> None:
        if request.method == "POST" and path == "blockedClients":
            body = json.loads(request.content)
            self.blocked.append({"id": f"b-{len(self.blocked)}", **body})
        elif request.method == "DELETE" and path.startswith("blockedClients/"):
            entry_id = path.split("/", 1)[1]
            self.blocked = [b for b in self.blocked if b["id"] != entry_id]
        elif request.method == "PUT" and path == f"networksSummary/{NET}":
            self.network = json.loads(request.content)

    def writes(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.method != "GET"]


def _client(site: FakeSite) -> InstantOnControlClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(site.handler))
    tokens = InstantOnTokenManager(
        http=http,
        store=FakeStore(
            InstantOnTokenState(
                access_token="access-1",
                access_expires_at=NOW + timedelta(seconds=1800),
                refresh_token="refresh-1",
                auth_state="ok",
            )
        ),
        lock=FakeLock(),
        credentials=FakeCredentials(),
        config=InstantOnAuthConfig(api_base_url=API, sso_base_url=SSO, client_id="c"),
        clock=lambda: NOW,
    )

    async def no_sleep(_: float) -> None:
        return None

    return InstantOnControlClient(
        http=http,
        tokens=tokens,
        api_base_url=API,
        api_version=28,
        sleep=no_sleep,
        clock=lambda: NOW,
    )


# ---------------------------------------------------------------------------
# MAC form
# ---------------------------------------------------------------------------


class TestMac:
    def test_portal_form_is_lower_case_colons(self) -> None:
        assert normalize_instant_on_mac("02-11-22-33-44-55") == MAC
        assert normalize_instant_on_mac("021122334455") == MAC
        assert normalize_instant_on_mac("02:11:22:33:44:55".upper()) == MAC

    def test_rejects_non_mac(self) -> None:
        with pytest.raises(ValueError):
            normalize_instant_on_mac("+919811122233")


# ---------------------------------------------------------------------------
# Block / unblock
# ---------------------------------------------------------------------------


class TestBlock:
    async def test_posts_the_portal_body_and_reads_back(self) -> None:
        site = FakeSite()
        result = await _client(site).block_client(SITE, "02-11-22-33-44-55")
        assert result.blocked and result.created
        (write,) = site.writes()
        assert write.method == "POST"
        assert write.url.path == f"/api/sites/{SITE}/blockedClients"
        assert json.loads(write.content) == {
            "kind": "blockedClients",
            "macAddress": MAC,
        }
        assert write.headers["x-ion-api-version"] == "28"
        # read-back after the write
        assert site.requests[-1].method == "GET"
        assert site.requests[-1].url.path.endswith("/blockedClients")

    async def test_already_blocked_is_not_posted_again(self) -> None:
        site = FakeSite()
        site.blocked.append({"id": "b-9", "macAddress": MAC})
        result = await _client(site).block_client(SITE, MAC)
        assert result == BlockResult(
            mac=MAC, blocked=True, created=False, entry_id="b-9"
        )
        assert site.writes() == []

    async def test_a_2xx_that_changed_nothing_is_not_success(self) -> None:
        site = FakeSite()
        site.ignore_writes = True
        with pytest.raises(InstantOnWriteNotConfirmedError):
            await _client(site).block_client(SITE, MAC)

    async def test_a_lost_answer_is_decided_by_the_read_back(self) -> None:
        site = FakeSite()
        site.timeout_on_write = True
        result = await _client(site).block_client(SITE, MAC)
        assert result.blocked
        assert len(site.writes()) == 1  # a POST is never retried

    async def test_not_blockable_is_refused_before_any_write(self) -> None:
        site = FakeSite()
        site.clients[0]["isBlockable"] = False
        with pytest.raises(InstantOnClientNotBlockableError):
            await _client(site).block_client(SITE, MAC)
        assert site.writes() == []

    async def test_viewer_role_403_says_so(self) -> None:
        site = FakeSite()
        site.write_status = 403
        with pytest.raises(InstantOnForbiddenError) as exc_info:
            await _client(site).block_client(SITE, MAC)
        assert exc_info.value.reason == "write_forbidden"


class TestUnblock:
    async def test_deletes_by_entry_id_and_reads_back(self) -> None:
        site = FakeSite()
        site.blocked.append({"id": "b-0", "macAddress": MAC})
        assert await _client(site).unblock_client(SITE, MAC) is True
        (write,) = site.writes()
        assert write.method == "DELETE"
        assert write.url.path == f"/api/sites/{SITE}/blockedClients/b-0"
        assert site.blocked == []

    async def test_nothing_to_unblock_writes_nothing(self) -> None:
        site = FakeSite()
        assert await _client(site).unblock_client(SITE, MAC) is True
        assert site.writes() == []

    async def test_still_listed_after_delete_is_not_success(self) -> None:
        site = FakeSite()
        site.blocked.append({"id": "b-0", "macAddress": MAC})
        site.ignore_writes = True
        with pytest.raises(InstantOnWriteNotConfirmedError):
            await _client(site).unblock_client(SITE, MAC)


# ---------------------------------------------------------------------------
# Guest network per-client speed cap
# ---------------------------------------------------------------------------


class TestGuestRateLimit:
    async def test_put_keeps_every_other_field_and_reads_back(self) -> None:
        site = FakeSite()
        after = await _client(site).set_guest_network_rate_limit(
            SITE, NET, download_mbps=5, upload_mbps=2
        )
        assert (after.enabled, after.download_mbps, after.upload_mbps) == (True, 5, 2)
        (write,) = site.writes()
        assert write.method == "PUT"
        assert write.url.path == f"/api/sites/{SITE}/networksSummary/{NET}"
        body = json.loads(write.content)
        # An omitted field is a reset field: the PSK and the unrelated QoS
        # setting must travel back unchanged.
        assert body["preSharedKey"] == "do-not-lose-me"
        assert body["qos"]["trafficPriority"] == "low"
        assert body["qos"]["bandwidthLimitMode"] == "perClient"
        assert body["qos"]["perClientDownloadBandwidthLimitInMbps"] == 5

    async def test_clear(self) -> None:
        site = FakeSite()
        client = _client(site)
        await client.set_guest_network_rate_limit(
            SITE, NET, download_mbps=5, upload_mbps=None
        )
        after = await client.set_guest_network_rate_limit(
            SITE, NET, download_mbps=None, upload_mbps=None
        )
        assert after.enabled is False

    async def test_not_kept_is_not_success(self) -> None:
        site = FakeSite()
        site.ignore_writes = True
        with pytest.raises(InstantOnWriteNotConfirmedError):
            await _client(site).set_guest_network_rate_limit(
                SITE, NET, download_mbps=5, upload_mbps=2
            )

    @pytest.mark.parametrize("value", [0, 1001, -1])
    async def test_out_of_range_is_refused_before_any_call(self, value: int) -> None:
        site = FakeSite()
        with pytest.raises(ValueError):
            await _client(site).set_guest_network_rate_limit(
                SITE, NET, download_mbps=value, upload_mbps=None
            )
        assert site.requests == []


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

ROUTER = uuid.uuid4()
ARN = "arn:aws:secretsmanager:ap-south-1:000000000000:secret:test"


def _settings(**overrides) -> Settings:  # noqa: ANN003
    base = {
        "instant_on_cloud_control_enabled": True,
        "instant_on_cloud_control_router_ids": str(ROUTER),
        "instant_on_control_secret_arn": ARN,
    }
    base.update(overrides)
    return Settings(**base)


class TestGates:
    def test_off_by_default(self) -> None:
        assert Settings().instant_on_cloud_control_enabled is False
        assert control.cloud_control_allowed(ROUTER, Settings()) is False

    def test_needs_all_three(self) -> None:
        assert control.cloud_control_allowed(ROUTER, _settings()) is True
        assert not control.cloud_control_allowed(
            ROUTER, _settings(instant_on_cloud_control_enabled=False)
        )
        assert not control.cloud_control_allowed(
            ROUTER, _settings(instant_on_cloud_control_router_ids="")
        )
        assert not control.cloud_control_allowed(
            ROUTER, _settings(instant_on_control_secret_arn="")
        )
        assert not control.cloud_control_allowed(uuid.uuid4(), _settings())

    def test_per_venue_account_override(self) -> None:
        other = "arn:aws:secretsmanager:ap-south-1:000000000000:secret:venue"
        settings = _settings(
            instant_on_control_secret_arns_by_router=f"{ROUTER}={other}"
        )
        assert settings.instant_on_control_secret_arn_for(ROUTER) == other
        assert settings.instant_on_control_secret_arn_for(uuid.uuid4()) == ARN

    def test_typos_stop_the_process(self) -> None:
        with pytest.raises(ValueError):
            _settings(instant_on_cloud_control_router_ids="not-a-uuid")
        with pytest.raises(ValueError):
            _settings(instant_on_control_secret_arns_by_router=f"{ROUTER}=nope")


# ---------------------------------------------------------------------------
# Disconnect = block + timed unblock; admin block is persistent
# ---------------------------------------------------------------------------


class FakeRedis:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self.data[key] = value
        return True

    async def get(self, key: str) -> str | None:
        return self.data.get(key)

    async def delete(self, key: str) -> int:
        return 1 if self.data.pop(key, None) is not None else 0


@pytest.fixture
def wired(monkeypatch):  # noqa: ANN001, ANN201
    site = FakeSite()
    redis = FakeRedis()
    scheduled: list[tuple] = []
    target = control.ControlTarget(
        router_id=ROUTER,
        organization_id=uuid.uuid4(),
        location_id=uuid.uuid4(),
        site_id=SITE,
        secret_arn=ARN,
    )

    async def resolve(session, **kwargs):  # noqa: ANN001, ANN003, ANN202
        return target if kwargs.get("organization_id") is not None else None

    async def with_client(t, settings, action):  # noqa: ANN001, ANN202
        return await action(_client(site))

    monkeypatch.setattr(control, "resolve_control_target", resolve)
    monkeypatch.setattr(control, "_with_client", with_client)
    monkeypatch.setattr(control, "_redis", lambda: redis)
    monkeypatch.setattr(
        control,
        "_schedule_release",
        lambda t, mac, token, countdown: scheduled.append((mac, token, countdown)),
    )
    return site, redis, scheduled, target


class TestDisconnect:
    async def test_blocks_then_schedules_the_timed_unblock(self, wired) -> None:  # noqa: ANN001
        site, redis, scheduled, target = wired
        ended = await control.end_nas_only_session(
            None,  # type: ignore[arg-type]
            router_id=ROUTER,
            organization_id=target.organization_id,
            client_mac="02-11-22-33-44-55",
            settings=_settings(),
        )
        assert ended is True
        assert [b["macAddress"] for b in site.blocked] == [MAC]
        ((mac, token, countdown),) = scheduled
        assert (mac, countdown) == (MAC, 30)
        assert redis.data[control.transient_marker_key(SITE, MAC)] == token

    async def test_the_timed_unblock_releases_its_own_block(self, wired) -> None:  # noqa: ANN001
        site, redis, scheduled, target = wired
        await control.end_nas_only_session(
            None,
            router_id=ROUTER,
            organization_id=target.organization_id,  # type: ignore[arg-type]
            client_mac=MAC,
            settings=_settings(),
        )
        ((mac, token, _),) = scheduled
        result = await control.release_transient_block(
            None,
            organization_id=target.organization_id,
            router_id=ROUTER,  # type: ignore[arg-type]
            mac=mac,
            token=token,
            settings=_settings(),
        )
        assert result == "released"
        assert site.blocked == []
        assert redis.data == {}

    async def test_an_admin_block_is_never_undone_by_a_pending_unblock(
        self, wired
    ) -> None:  # noqa: ANN001
        site, redis, scheduled, target = wired
        await control.end_nas_only_session(
            None,
            router_id=ROUTER,
            organization_id=target.organization_id,  # type: ignore[arg-type]
            client_mac=MAC,
            settings=_settings(),
        )
        outcome = await control.instant_on_block_device(
            None,
            location_id=target.location_id,  # type: ignore[arg-type]
            organization_id=target.organization_id,
            client_mac=MAC,
            settings=_settings(),
        )
        assert outcome.status == "enforced"
        ((mac, token, _),) = scheduled
        result = await control.release_transient_block(
            None,
            organization_id=target.organization_id,
            router_id=ROUTER,  # type: ignore[arg-type]
            mac=mac,
            token=token,
            settings=_settings(),
        )
        assert result == "superseded"
        assert [b["macAddress"] for b in site.blocked] == [MAC]

    async def test_disconnecting_an_already_blocked_device_schedules_nothing(
        self, wired
    ) -> None:  # noqa: ANN001
        site, redis, scheduled, target = wired
        site.blocked.append({"id": "b-9", "macAddress": MAC})
        assert await control.end_nas_only_session(
            None,
            router_id=ROUTER,
            organization_id=target.organization_id,  # type: ignore[arg-type]
            client_mac=MAC,
            settings=_settings(),
        )
        assert scheduled == []

    async def test_a_failed_write_is_could_not(self, wired) -> None:  # noqa: ANN001
        site, _, scheduled, target = wired
        site.ignore_writes = True
        assert not await control.end_nas_only_session(
            None,
            router_id=ROUTER,
            organization_id=target.organization_id,  # type: ignore[arg-type]
            client_mac=MAC,
            settings=_settings(),
        )
        assert scheduled == []

    async def test_no_tenant_resolves_nothing(self, wired) -> None:  # noqa: ANN001
        site, _, _, _ = wired
        assert not await control.end_nas_only_session(
            None,
            router_id=ROUTER,
            organization_id=None,  # type: ignore[arg-type]
            client_mac=MAC,
            settings=_settings(),
        )
        assert site.requests == []

    async def test_release_device_unblocks(self, wired) -> None:  # noqa: ANN001
        site, _, _, target = wired
        site.blocked.append({"id": "b-0", "macAddress": MAC})
        outcome = await control.instant_on_release_device(
            None,
            location_id=target.location_id,  # type: ignore[arg-type]
            organization_id=target.organization_id,
            client_mac=MAC,
            settings=_settings(),
        )
        assert outcome.status == "enforced"
        assert site.blocked == []


# ---------------------------------------------------------------------------
# LiveSessionTerminator: the NAS-only branch
# ---------------------------------------------------------------------------


def _terminator(end_nas_only):  # noqa: ANN001, ANN202
    from app.domains.guest_access.enforcement import LiveSessionTerminator
    from tests.unit.test_omada_client_management import (
        CLIENT_MAC,
        _DeviceLookup,
        _Router,
        _RouterLookup,
    )

    async def controller(**kwargs):  # noqa: ANN003, ANN202
        raise AssertionError("an Aruba session must not reach the Omada path")

    if end_nas_only is not None:
        controller.end_nas_only = end_nas_only  # type: ignore[attr-defined]
    return LiveSessionTerminator(
        router_lookup=_RouterLookup(
            _Router(
                vendor="aruba_instant_on", api_username=None, management_ip_address=None
            )
        ),
        device_lookup=_DeviceLookup(mac=CLIENT_MAC),
        controller_terminator=controller,
    )


class TestTerminatorNasOnlyBranch:
    async def _end(self, terminator):  # noqa: ANN001, ANN202
        from tests.unit.test_omada_client_management import GUEST_IDENTIFIER, _Session

        return await terminator.end_on_router(
            session=_Session(device_id=uuid.uuid4()),
            identifier=GUEST_IDENTIFIER,
            organization_id=uuid.uuid4(),
        )

    async def test_confirmed_cloud_disconnect_is_an_ended_session(self) -> None:
        calls: list[dict] = []

        async def end_nas_only(**kwargs):  # noqa: ANN003, ANN202
            calls.append(kwargs)
            return True

        outcome = await self._end(_terminator(end_nas_only))
        assert outcome.ended_cleanly is True
        assert outcome.removed == 1
        assert len(calls) == 1

    async def test_could_not_keeps_the_old_plain_sentence(self) -> None:
        from app.domains.guest_access.exceptions import (
            NasOnlyLiveSessionUnreachableError,
        )

        async def end_nas_only(**kwargs):  # noqa: ANN003, ANN202
            return False

        with pytest.raises(NasOnlyLiveSessionUnreachableError):
            await self._end(_terminator(end_nas_only))

    async def test_no_cloud_hook_keeps_the_old_behaviour(self) -> None:
        from app.domains.guest_access.exceptions import (
            NasOnlyLiveSessionUnreachableError,
        )

        with pytest.raises(NasOnlyLiveSessionUnreachableError):
            await self._end(_terminator(None))


# ---------------------------------------------------------------------------
# Data cap at an Aruba venue with cloud control
# ---------------------------------------------------------------------------


class _CloudHook:
    def __init__(self, *, works: bool) -> None:
        self.works = works
        self.calls = 0

    async def end_on_router(self, **kwargs):  # noqa: ANN003, ANN202
        from app.domains.guest_access.device_adapters import (
            SessionControlSnapshot,
            SessionEndOutcome,
        )
        from app.domains.guest_access.exceptions import (
            NasOnlyLiveSessionUnreachableError,
        )

        self.calls += 1
        if not self.works:
            raise NasOnlyLiveSessionUnreachableError(uuid.uuid4())
        return SessionEndOutcome(
            control=SessionControlSnapshot(
                hotspot_servers=1, coa_accept=False, coa_port=None
            ),
            matched=1,
            removed=1,
            still_active=0,
        )


class TestDataCapWithCloudControl:
    async def _over_cap(self, hook):  # noqa: ANN001, ANN202
        from app.domains.policy.constants import PolicyType
        from tests.unit.test_aruba_access_rules import (
            _fixture,
            _PolicyLookup,
            _sign_in,
        )
        from tests.unit.test_guest import BYTES_PER_MB

        fx = _fixture(
            policy_lookup=_PolicyLookup({PolicyType.FUP: {"daily_data_limit_mb": 10}})
        )
        fx.guest_service.session_end_hook = hook
        result = await _sign_in(fx)
        await fx.guest_service.record_usage(
            session_id=result.session.id,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=11 * BYTES_PER_MB,
        )
        return await fx.repository.get_session_by_id(result.session.id)

    async def test_confirmed_disconnect_ends_the_session(self) -> None:
        hook = _CloudHook(works=True)
        session = await self._over_cap(hook)
        assert hook.calls == 1
        assert session.status == GuestSessionStatus.EXPIRED.value
        assert session.disconnect_reason == "fup_data_quota_exceeded_daily"
        assert session.disconnect_enforced is True

    async def test_gate_closed_leaves_it_active_as_before(self) -> None:
        hook = _CloudHook(works=False)
        session = await self._over_cap(hook)
        assert hook.calls == 1
        assert session.status == GuestSessionStatus.ACTIVE.value
        assert session.ended_at is None


class TestListGuestNetworks:
    async def test_lists_each_guest_ssid_with_its_cap_and_writes_nothing(self) -> None:
        site = FakeSite()
        staff = {
            "id": "net-2",
            "networkName": "STAFF",
            "type": "employee",
            "isGuestPortalEnabled": False,
            "qos": {"isBandwidthLimitEnabled": False},
        }
        fast = json.loads(json.dumps(site.network))
        fast.update({"id": "net-3", "networkName": "GUEST_FAST", "type": "guest"})
        fast["qos"].update(
            {
                "isBandwidthLimitEnabled": True,
                "isDownloadBandwidthLimitEnabled": True,
                "perClientDownloadBandwidthLimitInMbps": 50,
            }
        )
        original = site.handler

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/networksSummary"):
                site.requests.append(request)
                return httpx.Response(
                    200, json={"elements": [site.network, staff, fast]}
                )
            return original(request)

        site.handler = handler  # type: ignore[method-assign]
        limits = await _client(site).list_guest_network_rate_limits(SITE)
        assert [(n.network_id, n.enabled, n.download_mbps) for n in limits] == [
            (NET, False, None),
            ("net-3", True, 50),
        ]
        assert site.writes() == []


class TestRedisClientPerEventLoop:
    """A shared client breaks across Celery's per-task ``asyncio.run()``."""

    def test_each_event_loop_gets_its_own_client(self):
        import asyncio

        async def two_reads():
            first, second = control._redis(), control._redis()
            assert first is second
            return first

        assert asyncio.run(two_reads()) is not asyncio.run(two_reads())

    def test_close_releases_the_clients_connections(self):
        import asyncio

        async def run():
            client = control._redis()
            await control._close_loop_redis()
            assert control._redis() is not client

        asyncio.run(run())

    def test_release_task_retries_on_redis_errors(self):
        from redis.exceptions import ConnectionError as RedisConnectionError

        from app.domains.network_integration.providers.aruba_instant_on_client import (
            InstantOnError,
        )

        retried = control.release_transient_block_task.autoretry_for
        assert issubclass(RedisConnectionError, retried)
        assert issubclass(InstantOnError, retried)


# ---------------------------------------------------------------------------
# The customer's speed write against what the network already holds
# ---------------------------------------------------------------------------


class TestVenueGuestSpeed:
    """A cap set in the Instant On app can be outside the presets, or in the
    portal's "Usage Controlled By: Network" mode."""

    @staticmethod
    def _wire(monkeypatch, site: FakeSite) -> None:  # noqa: ANN001
        from app.domains.network_integration import instant_on_control as control

        target = control.ControlTarget(
            router_id=ROUTER,
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            site_id=SITE,
            secret_arn=ARN,
        )

        async def resolve(*_: object, **__: object) -> object:
            return target

        async def with_client(_t: object, _s: object, action):  # noqa: ANN001, ANN202
            return await action(_client(site))

        monkeypatch.setattr(control, "resolve_control_target", resolve)
        monkeypatch.setattr(control, "_with_client", with_client)

    @staticmethod
    async def _set(down: int | None, up: int | None):  # noqa: ANN205
        from app.domains.network_integration.instant_on_control import (
            set_venue_guest_speed,
        )

        return await set_venue_guest_speed(
            None,  # type: ignore[arg-type]
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            network_id=NET,
            download_mbps=down,
            upload_mbps=up,
            settings=_settings(),
        )

    @staticmethod
    def _hold(site: FakeSite, down: int, up: int, mode: str = "perClient") -> None:
        site.network["qos"].update(
            isBandwidthLimitEnabled=True,
            bandwidthLimitMode=mode,
            isDownloadBandwidthLimitEnabled=True,
            isUploadBandwidthLimitEnabled=True,
            perClientDownloadBandwidthLimitInMbps=down,
            perClientUploadBandwidthLimitInMbps=up,
        )

    async def test_an_off_preset_cap_survives_changing_the_other_direction(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        site = FakeSite()
        self._hold(site, down=2, up=2)
        self._wire(monkeypatch, site)
        result = await self._set(2, 20)
        assert result.status == "applied"
        assert (result.applied.download_mbps, result.applied.upload_mbps) == (2, 20)

    async def test_a_new_off_preset_value_is_refused_before_any_write(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        site = FakeSite()
        self._hold(site, down=2, up=2)
        self._wire(monkeypatch, site)
        with pytest.raises(ValueError):
            await self._set(35, 2)
        assert site.writes() == []

    async def test_out_of_range_is_refused_before_any_instant_on_call(self) -> None:
        with pytest.raises(ValueError):
            await self._set(5000, None)

    async def test_a_network_wide_limit_is_reported_and_not_overwritten(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        site = FakeSite()
        self._hold(site, down=1000, up=1000, mode="perNetwork")
        site.network["qos"].update(
            perNetworkDownstreamBandwidthLimitInMbps=50,
            perNetworkUpstreamBandwidthLimitInMbps=20,
        )
        self._wire(monkeypatch, site)
        result = await self._set(10, 10)
        assert result.status == "failed"
        assert result.reason == "network_wide_limit_set"
        assert site.writes() == []
        held = result.networks[0]
        assert held.other_mode_limit is True and held.enabled is False
        assert (held.network_download_mbps, held.network_upload_mbps) == (50, 20)
        assert (held.download_mbps, held.upload_mbps) == (None, None)

    async def test_a_per_client_network_is_not_flagged(self, monkeypatch) -> None:  # noqa: ANN001
        site = FakeSite()
        self._wire(monkeypatch, site)
        result = await self._set(10, 10)
        assert result.status == "applied"
        assert result.applied.other_mode_limit is False

    def test_a_network_secret_never_reaches_the_response_shape(self) -> None:
        from app.domains.network_integration.instant_on_schemas import (
            InstantOnVenueGuestNetwork,
        )

        assert set(InstantOnVenueGuestNetwork.model_fields) == {
            "network_id",
            "network_name",
            "enabled",
            "download_mbps",
            "upload_mbps",
            "other_mode_limit",
            "network_download_mbps",
            "network_upload_mbps",
        }

    async def test_the_provider_write_refuses_a_network_wide_limit(self) -> None:
        """The chokepoint for all three writers: it forces perClient, which would
        silently replace the owner's network-wide limit."""
        from app.domains.network_integration.providers.aruba_instant_on_control import (
            InstantOnNetworkWideLimitError,
        )

        site = FakeSite()
        self._hold(site, down=1000, up=1000, mode="perNetwork")
        with pytest.raises(InstantOnNetworkWideLimitError) as refused:
            await _client(site).set_guest_network_rate_limit(
                SITE, NET, download_mbps=10, upload_mbps=10
            )
        assert refused.value.code == "network_wide_limit_set"
        assert site.writes() == []

    async def test_clearing_also_refuses_a_network_wide_limit(self) -> None:
        from app.domains.network_integration.providers.aruba_instant_on_control import (
            InstantOnNetworkWideLimitError,
        )

        site = FakeSite()
        self._hold(site, down=1000, up=1000, mode="perNetwork")
        with pytest.raises(InstantOnNetworkWideLimitError):
            await _client(site).set_guest_network_rate_limit(
                SITE, NET, download_mbps=None, upload_mbps=None
            )
        assert site.writes() == []

    @pytest.mark.parametrize("dry_run", [True, False])
    async def test_the_master_endpoint_reports_it_even_on_a_preview(
        self, monkeypatch, dry_run: bool
    ) -> None:  # noqa: ANN001
        from types import SimpleNamespace

        from app.domains.network_integration import instant_on_repository
        from app.domains.network_integration import instant_on_router as routes
        from app.domains.network_integration.instant_on_schemas import (
            InstantOnGuestRateLimitRequest,
        )

        site = FakeSite()
        self._hold(site, down=1000, up=1000, mode="perNetwork")

        async def get_site(_self: object, _router_id: object) -> object:
            return SimpleNamespace(organization_id=uuid.uuid4())

        async def resolve(*_: object, **__: object) -> object:
            return SimpleNamespace(site_id=SITE, secret_arn=ARN)

        monkeypatch.setattr(
            instant_on_repository.InstantOnRepository, "get_site_for_router", get_site
        )
        monkeypatch.setattr(control, "resolve_control_target", resolve)
        monkeypatch.setattr(
            control, "build_live_control_client", lambda *_a, **_k: _client(site)
        )
        response = await routes.set_instant_on_guest_rate_limit(
            ROUTER,
            InstantOnGuestRateLimitRequest(
                network_id=NET, download_mbps=10, upload_mbps=10, dry_run=dry_run
            ),
            SimpleNamespace(state=SimpleNamespace(request_id="r"), headers={}),
            user=SimpleNamespace(id=str(uuid.uuid4())),
            db=None,
        )
        assert response["data"]["status"] == "failed"
        assert response["data"]["reason"] == "network_wide_limit_set"
        assert site.writes() == []


# ============================================================================
# A deleted fleet router never resolves; end_nas_only_session never raises
# ============================================================================


class _CapturingSession:
    """Answers every query with the given rows and records the statement."""

    def __init__(self, rows: list) -> None:  # noqa: ANN001
        self.rows = rows
        self.statements: list = []

    async def execute(self, statement):  # noqa: ANN001, ANN201
        self.statements.append(statement)
        rows = self.rows

        class _Result:
            def scalars(self):  # noqa: ANN202
                class _S:
                    def all(self):  # noqa: ANN202
                        return rows

                    def first(self):  # noqa: ANN202
                        return rows[0] if rows else None

                return _S()

        return _Result()


def _sql(statement) -> str:  # noqa: ANN001
    return str(statement.compile(compile_kwargs={"literal_binds": True}))


class TestDeletedRouterNeverResolves:
    async def test_control_target_query_excludes_deleted_routers(self) -> None:
        """The SQL itself joins routers and requires is_deleted false, so a
        site row whose fleet router was deleted cannot come back."""
        db = _CapturingSession([])
        assert (
            await control.resolve_control_target(
                db,  # type: ignore[arg-type]
                organization_id=uuid.uuid4(),
                router_id=ROUTER,
                settings=_settings(),
            )
            is None
        )
        sql = _sql(db.statements[0])
        assert "JOIN routers ON routers.id = instant_on_sites.router_id" in sql
        assert "routers.is_deleted IS false" in sql
        assert "instant_on_sites.is_deleted IS false" in sql

    async def test_location_lookup_excludes_deleted_routers(self) -> None:
        from app.domains.network_integration.instant_on_repository import (
            InstantOnRepository,
        )

        db = _CapturingSession([])
        repo = InstantOnRepository(db)  # type: ignore[arg-type]
        assert (
            await repo.get_site_for_location(
                location_id=uuid.uuid4(), organization_id=uuid.uuid4()
            )
            is None
        )
        sql = _sql(db.statements[0])
        assert "JOIN routers ON routers.id = instant_on_sites.router_id" in sql
        assert "routers.is_deleted IS false" in sql


class TestEndNasOnlySessionNeverRaises:
    @pytest.mark.parametrize("error", [RuntimeError("db gone"), ConnectionError()])
    async def test_resolve_failure_is_could_not(self, monkeypatch, error) -> None:  # noqa: ANN001
        async def boom(session, **kwargs):  # noqa: ANN001, ANN003, ANN202
            raise error

        monkeypatch.setattr(control, "resolve_control_target", boom)
        assert (
            await control.end_nas_only_session(
                None,  # type: ignore[arg-type]
                router_id=ROUTER,
                organization_id=uuid.uuid4(),
                client_mac=MAC,
                settings=_settings(),
            )
            is False
        )

    async def test_redis_failure_after_resolve_is_could_not(
        self, wired, monkeypatch
    ) -> None:  # noqa: ANN001
        _, _, _, target = wired

        async def with_client(t, settings, action):  # noqa: ANN001, ANN202
            raise OSError("redis connection refused")

        monkeypatch.setattr(control, "_with_client", with_client)
        assert (
            await control.end_nas_only_session(
                None,  # type: ignore[arg-type]
                router_id=ROUTER,
                organization_id=target.organization_id,
                client_mac=MAC,
                settings=_settings(),
            )
            is False
        )
