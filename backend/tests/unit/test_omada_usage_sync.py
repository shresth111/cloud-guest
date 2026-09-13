"""Unit tests for the Omada guest data-usage back-fill sweep
(``app.domains.network_integration.usage_tasks``).

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` (see ``pyproject.toml``) runs the async tests
directly. Nothing here touches a database, a controller, or Celery: the
matching/delta core (``apply_controller_usage``) takes every collaborator as
an argument, and the orchestrator (``sync_omada_session_usage``) is exercised
against hand-rolled fakes, including a fake Redis for the per-session cursor.

What is pinned here is the contract that mattered:

* the per-session **cursor** model -- the delta is taken against the controller
  total this sweep last recorded for the session, not against ``session.bytes``.
  The first sight of a session baselines (accrues zero); only later growth
  counts. This is what stops a fresh session from inheriting the prior
  session's controller total and false-tripping a data cap on reconnect;
* a backwards counter (reset/roam) clamps the delta to zero and re-baselines;
* deterministic selection when one MAC has two ACTIVE sessions -- the newest
  (current connection) wins;
* MAC matching across the colon/dash/case spelling difference;
* failure isolation -- one venue's dead controller does not abort the sweep.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.domains.network_integration.exceptions import ProviderConnectionFailedError
from app.domains.network_integration.providers.base import ProviderClient
from app.domains.network_integration.usage_tasks import (
    _USAGE_CURSOR_KEY,
    _canonical_mac,
    apply_controller_usage,
    sync_omada_session_usage,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------


@dataclass
class FakeSession:
    id: uuid.UUID
    device_id: uuid.UUID | None
    bytes_uploaded: int
    bytes_downloaded: int
    started_at: datetime = _T0


@dataclass
class FakeDevice:
    id: uuid.UUID
    mac_address: str


class RecordingUsageRecorder:
    """Captures every ``record_usage`` call -- stands in for ``GuestService``
    without building its graph."""

    def __init__(self) -> None:
        self.calls: list[tuple[uuid.UUID, int, int]] = []

    async def record_usage(
        self,
        *,
        session_id: uuid.UUID,
        bytes_uploaded_delta: int,
        bytes_downloaded_delta: int,
    ) -> None:
        self.calls.append((session_id, bytes_uploaded_delta, bytes_downloaded_delta))


class FakeRedis:
    """In-memory stand-in for the async Redis client: ``get``/``set`` over a
    dict, persisting across sweeps in a test so the cursor behaves as it does
    in production."""

    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self._store: dict[str, str] = dict(initial or {})

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = value


def _seed_cursor(session_id: uuid.UUID, up: int, down: int) -> dict[str, str]:
    return {_USAGE_CURSOR_KEY.format(session_id=session_id): f"{up},{down}"}


class FakeNiRepository:
    def __init__(self, integrations: list[object]) -> None:
        self._integrations = integrations
        self.limit_seen: int | None = None

    async def list_omada_openapi_for_usage_sync(
        self, *, limit: int
    ) -> list[object]:
        self.limit_seen = limit
        return list(self._integrations)


class FakeNiService:
    """Just enough of ``NetworkIntegrationService`` for the orchestrator."""

    def __init__(
        self,
        *,
        integrations: list[object],
        clients_by_integration: dict[uuid.UUID, object],
    ) -> None:
        self.repository = FakeNiRepository(integrations)
        self._clients_by_integration = clients_by_integration
        self.list_clients_org_args: list[uuid.UUID | None] = []

    async def list_clients(
        self, integration_id: uuid.UUID, *, requesting_organization_id
    ) -> list[ProviderClient]:
        self.list_clients_org_args.append(requesting_organization_id)
        result = self._clients_by_integration[integration_id]
        if isinstance(result, Exception):
            raise result
        return result


class FakeGuestRepository:
    def __init__(
        self,
        *,
        sessions_by_router: dict[uuid.UUID, list[FakeSession]],
        devices: list[FakeDevice],
    ) -> None:
        self._sessions_by_router = sessions_by_router
        self._devices = devices
        self.device_org_args: list[uuid.UUID | None] = []

    async def list_active_sessions_for_router(
        self, router_id: uuid.UUID
    ) -> list[FakeSession]:
        return list(self._sessions_by_router.get(router_id, []))

    async def list_devices_for_session_ids(
        self, *, device_ids, organization_id
    ) -> list[FakeDevice]:
        self.device_org_args.append(organization_id)
        wanted = set(device_ids)
        return [d for d in self._devices if d.id in wanted]


def _client(mac: str, up: int | None, down: int | None) -> ProviderClient:
    return ProviderClient(mac=mac, traffic_up_bytes=up, traffic_down_bytes=down)


def _session(
    session_id: uuid.UUID,
    device_id: uuid.UUID | None,
    *,
    started_at: datetime = _T0,
) -> FakeSession:
    return FakeSession(
        id=session_id,
        device_id=device_id,
        bytes_uploaded=0,
        bytes_downloaded=0,
        started_at=started_at,
    )


# --------------------------------------------------------------------------
# _canonical_mac
# --------------------------------------------------------------------------


class TestCanonicalMac:
    def test_colon_dash_and_case_all_collapse_to_the_same_hex(self) -> None:
        assert (
            _canonical_mac("aa:bb:cc:dd:ee:ff")
            == _canonical_mac("AA-BB-CC-DD-EE-FF")
            == _canonical_mac("AABB.CCDD.EEFF")
            == "AABBCCDDEEFF"
        )

    def test_none_and_blank_are_none(self) -> None:
        assert _canonical_mac(None) is None
        assert _canonical_mac("   ") is None

    def test_wrong_length_or_non_hex_is_none(self) -> None:
        assert _canonical_mac("AA:BB:CC:DD:EE") is None  # five octets
        assert _canonical_mac("ZZ:BB:CC:DD:EE:FF") is None  # not hex


# --------------------------------------------------------------------------
# apply_controller_usage -- the delta/matching core
# --------------------------------------------------------------------------


class TestApplyControllerUsage:
    async def test_first_sight_baselines_and_accrues_nothing(self) -> None:
        """The decisive case. A session never seen before -- e.g. a fresh
        re-login row at bytes=0 -- must NOT have the controller's carried-over
        total dumped into it. It sets a baseline and accrues zero."""
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()
        session = _session(session_id, device_id)
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        # Controller already shows a big carried-over total; cursors is empty.
        updated, up, down, new_cursors = await apply_controller_usage(
            clients=[_client("aa-bb-cc-dd-ee-ff", up=5_000_000, down=9_000_000)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
            cursors={},
        )

        assert (updated, up, down) == (0, 0, 0)
        assert recorder.calls == []  # nothing accrued -> no false cap trip
        assert new_cursors == {session_id: (5_000_000, 9_000_000)}

    async def test_growth_after_baseline_accrues_only_the_delta(self) -> None:
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()
        session = _session(session_id, device_id)
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        # Cursor already at 1000/5000 (a prior sweep); controller now 1500/8000.
        _, up, down, new_cursors = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=1500, down=8000)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
            cursors={session_id: (1000, 5000)},
        )

        assert (up, down) == (500, 3000)
        assert recorder.calls == [(session_id, 500, 3000)]
        assert new_cursors == {session_id: (1500, 8000)}

    async def test_fresh_session_does_not_inherit_prior_sessions_total(
        self,
    ) -> None:
        """Two sequential sessions for the same device across a reconnect.
        The controller total keeps climbing across the boundary; the new
        session must accrue only what happens after its own first sight, not
        the old session's usage."""
        device_id = uuid.uuid4()
        s2_id = uuid.uuid4()
        s2 = _session(s2_id, device_id)  # the fresh re-login row, bytes=0
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        # First sweep of S2: controller total is the ~5GB carried over from S1.
        _, _, _, cursors_after = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=5_000_000, down=0)],
            active_sessions=[s2],
            devices_by_id={device_id: device},
            guest_service=recorder,
            cursors={},
        )
        assert recorder.calls == []  # no inheritance

        # Second sweep: guest has now actually used 1MB more on S2.
        _, up, _, _ = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=6_000_000, down=0)],
            active_sessions=[s2],
            devices_by_id={device_id: device},
            guest_service=recorder,
            cursors=cursors_after,
        )
        assert up == 1_000_000
        assert recorder.calls == [(s2_id, 1_000_000, 0)]

    async def test_two_active_sessions_one_mac_newest_session_wins(self) -> None:
        """A device that overran its timeout can hold a stale ACTIVE row and a
        fresh re-login row at once. The controller's live traffic belongs to
        the current connection -- the most recently started session."""
        device_id = uuid.uuid4()
        old_id = uuid.uuid4()
        new_id = uuid.uuid4()
        old = _session(old_id, device_id, started_at=_T0)
        new = _session(new_id, device_id, started_at=_T0 + timedelta(minutes=45))
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        # Both already baselined at 0; controller reports 500/500.
        _, up, down, _ = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=500, down=500)],
            # Deliberately list the stale one first to prove ordering does not
            # decide it.
            active_sessions=[old, new],
            devices_by_id={device_id: device},
            guest_service=recorder,
            cursors={old_id: (0, 0), new_id: (0, 0)},
        )

        assert (up, down) == (500, 500)
        assert recorder.calls == [(new_id, 500, 500)]  # newest, not stale

    async def test_repeated_total_is_an_idempotent_no_op(self) -> None:
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()
        session = _session(session_id, device_id)
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        updated, up, down, new_cursors = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=1500, down=8000)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
            cursors={session_id: (1500, 8000)},
        )

        assert (updated, up, down) == (0, 0, 0)
        assert recorder.calls == []
        assert new_cursors == {session_id: (1500, 8000)}

    async def test_counter_reset_clamps_to_zero_and_rebaselines(self) -> None:
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()
        session = _session(session_id, device_id)
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        # Controller counter restarted (reboot/roam) -> below the cursor.
        updated, up, down, new_cursors = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=10, down=10)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
            cursors={session_id: (9000, 9000)},
        )

        assert (updated, up, down) == (0, 0, 0)
        assert recorder.calls == []
        # Re-baselined at the lower value so the next growth is measured from
        # there rather than re-crediting the whole drop.
        assert new_cursors == {session_id: (10, 10)}

    async def test_missing_both_counters_is_skipped_without_a_cursor(
        self,
    ) -> None:
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()
        session = _session(session_id, device_id)
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        updated, _, _, new_cursors = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=None, down=None)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
            cursors={},
        )

        assert updated == 0
        assert recorder.calls == []
        assert new_cursors == {}  # nothing to baseline

    async def test_one_sided_counter_applies_only_that_direction(self) -> None:
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()
        session = _session(session_id, device_id)
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        _, up, down, _ = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=700, down=None)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
            cursors={session_id: (0, 0)},
        )

        assert (up, down) == (700, 0)
        assert recorder.calls == [(session_id, 700, 0)]

    async def test_unmatched_client_and_deviceless_session_are_ignored(
        self,
    ) -> None:
        device_id = uuid.uuid4()
        session = _session(uuid.uuid4(), device_id)
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        updated, _, _, new_cursors = await apply_controller_usage(
            clients=[_client("11:22:33:44:55:66", up=999, down=999)],
            active_sessions=[session, _session(uuid.uuid4(), None)],
            devices_by_id={device_id: device},
            guest_service=recorder,
            cursors={},
        )

        assert updated == 0
        assert recorder.calls == []
        assert new_cursors == {}


# --------------------------------------------------------------------------
# sync_omada_session_usage -- orchestration + failure isolation
# --------------------------------------------------------------------------


class TestSyncOmadaSessionUsage:
    async def test_first_sweep_baselines_then_second_accrues(self) -> None:
        """End-to-end through the orchestrator and a persisting fake Redis:
        the first sweep of a session accrues nothing (baseline), the second
        accrues the growth."""
        org_id = uuid.uuid4()
        router_id = uuid.uuid4()
        integration = SimpleNamespace(
            id=uuid.uuid4(), organization_id=org_id, router_id=router_id
        )
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()

        def _service(up: int, down: int) -> FakeNiService:
            return FakeNiService(
                integrations=[integration],
                clients_by_integration={
                    integration.id: [_client("AA-BB-CC-DD-EE-FF", up=up, down=down)]
                },
            )

        guest_repo = FakeGuestRepository(
            sessions_by_router={router_id: [_session(session_id, device_id)]},
            devices=[FakeDevice(id=device_id, mac_address="aa:bb:cc:dd:ee:ff")],
        )
        recorder = RecordingUsageRecorder()
        redis = FakeRedis()

        first = await sync_omada_session_usage(
            ni_service=_service(2000, 3000),
            guest_repository=guest_repo,
            guest_service=recorder,
            redis=redis,
            limit=50,
        )
        assert first.sessions_updated == 0  # baseline sweep
        assert recorder.calls == []

        second = await sync_omada_session_usage(
            ni_service=_service(2500, 5000),
            guest_repository=guest_repo,
            guest_service=recorder,
            redis=redis,
            limit=50,
        )
        assert second.sessions_updated == 1
        assert second.bytes_uploaded_applied == 500
        assert second.bytes_downloaded_applied == 2000
        assert recorder.calls == [(session_id, 500, 2000)]

    async def test_happy_path_applies_usage_for_an_already_seen_session(
        self,
    ) -> None:
        org_id = uuid.uuid4()
        router_id = uuid.uuid4()
        integration = SimpleNamespace(
            id=uuid.uuid4(), organization_id=org_id, router_id=router_id
        )
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()

        ni_service = FakeNiService(
            integrations=[integration],
            clients_by_integration={
                integration.id: [_client("AA-BB-CC-DD-EE-FF", up=2000, down=3000)]
            },
        )
        guest_repo = FakeGuestRepository(
            sessions_by_router={router_id: [_session(session_id, device_id)]},
            devices=[FakeDevice(id=device_id, mac_address="aa:bb:cc:dd:ee:ff")],
        )
        recorder = RecordingUsageRecorder()
        # Session already baselined at 0/0 by a prior sweep.
        redis = FakeRedis(_seed_cursor(session_id, 0, 0))

        summary = await sync_omada_session_usage(
            ni_service=ni_service,
            guest_repository=guest_repo,
            guest_service=recorder,
            redis=redis,
            limit=50,
        )

        assert summary.integrations_considered == 1
        assert summary.integrations_synced == 1
        assert summary.integrations_failed == 0
        assert summary.sessions_updated == 1
        assert summary.bytes_uploaded_applied == 2000
        assert summary.bytes_downloaded_applied == 3000
        assert recorder.calls == [(session_id, 2000, 3000)]
        assert ni_service.list_clients_org_args == [None]
        assert guest_repo.device_org_args == [org_id]
        assert ni_service.repository.limit_seen == 50

    async def test_provider_failure_on_one_venue_does_not_stop_the_sweep(
        self,
    ) -> None:
        org_id = uuid.uuid4()
        router_a = uuid.uuid4()
        router_b = uuid.uuid4()
        bad = SimpleNamespace(
            id=uuid.uuid4(), organization_id=org_id, router_id=router_a
        )
        good = SimpleNamespace(
            id=uuid.uuid4(), organization_id=org_id, router_id=router_b
        )
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()

        ni_service = FakeNiService(
            integrations=[bad, good],
            clients_by_integration={
                bad.id: ProviderConnectionFailedError("controller unreachable"),
                good.id: [_client("AA:BB:CC:DD:EE:FF", up=100, down=200)],
            },
        )
        guest_repo = FakeGuestRepository(
            sessions_by_router={router_b: [_session(session_id, device_id)]},
            devices=[FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")],
        )
        recorder = RecordingUsageRecorder()
        redis = FakeRedis(_seed_cursor(session_id, 0, 0))

        summary = await sync_omada_session_usage(
            ni_service=ni_service,
            guest_repository=guest_repo,
            guest_service=recorder,
            redis=redis,
            limit=50,
        )

        assert summary.integrations_considered == 2
        assert summary.integrations_failed == 1
        assert summary.integrations_synced == 1
        assert summary.sessions_updated == 1
        assert recorder.calls == [(session_id, 100, 200)]
