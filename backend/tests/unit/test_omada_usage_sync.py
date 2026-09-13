"""Unit tests for the Omada guest data-usage back-fill sweep
(``app.domains.network_integration.usage_tasks``).

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` (see ``pyproject.toml``) runs the async tests
directly. Nothing here touches a database, a controller, or Celery: the
matching/delta core (``apply_controller_usage``) takes every collaborator as
an argument, and the orchestrator (``sync_omada_session_usage``) is exercised
against hand-rolled fakes -- the same fake-driven discipline
``tests/unit/test_network_integration.py`` uses.

What is pinned here is the contract that mattered:

* the monotonic ``max(0, controller_total - session.bytes_*)`` clamp, mirrored
  verbatim from ``RadiusService.accounting_interim_update`` -- a repeated poll
  is a no-op, a counter reset never credits quota back;
* MAC matching across the colon/dash/case spelling difference between the
  controller and ``GuestDevice.mac_address``;
* failure isolation -- one venue's dead controller does not abort the sweep.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from types import SimpleNamespace

from app.domains.network_integration.exceptions import ProviderConnectionFailedError
from app.domains.network_integration.providers.base import ProviderClient
from app.domains.network_integration.usage_tasks import (
    _canonical_mac,
    apply_controller_usage,
    sync_omada_session_usage,
)

# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------


@dataclass
class FakeSession:
    id: uuid.UUID
    device_id: uuid.UUID | None
    bytes_uploaded: int
    bytes_downloaded: int


@dataclass
class FakeDevice:
    id: uuid.UUID
    mac_address: str


class RecordingUsageRecorder:
    """Captures every ``record_usage`` call -- stands in for ``GuestService``
    without building its graph. Does not itself mutate the session (the real
    method does; the sweep matches each session at most once per run, so a
    stale in-memory value never feeds a second delta in one run)."""

    def __init__(self) -> None:
        self.calls: list[tuple[uuid.UUID, int, int]] = []

    async def record_usage(
        self,
        *,
        session_id: uuid.UUID,
        bytes_uploaded_delta: int,
        bytes_downloaded_delta: int,
    ) -> None:
        self.calls.append(
            (session_id, bytes_uploaded_delta, bytes_downloaded_delta)
        )


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
    """Just enough of ``NetworkIntegrationService`` for the orchestrator:
    a ``.repository`` and ``list_clients``. ``clients_by_integration`` maps an
    integration id to either a list of ``ProviderClient`` or an exception to
    raise."""

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
    """Backs ``list_active_sessions_for_router`` and
    ``list_devices_for_session_ids`` off in-memory maps."""

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
    return ProviderClient(
        mac=mac, traffic_up_bytes=up, traffic_down_bytes=down
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
    async def test_matches_across_separator_and_case_and_applies_full_total(
        self,
    ) -> None:
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()
        session = FakeSession(
            id=session_id, device_id=device_id, bytes_uploaded=0, bytes_downloaded=0
        )
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        # Controller spells the MAC with dashes; device row uses colons.
        updated, up, down = await apply_controller_usage(
            clients=[_client("aa-bb-cc-dd-ee-ff", up=1000, down=5000)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
        )

        assert updated == 1
        assert (up, down) == (1000, 5000)
        assert recorder.calls == [(session_id, 1000, 5000)]

    async def test_delta_is_against_already_recorded_bytes(self) -> None:
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()
        session = FakeSession(
            id=session_id,
            device_id=device_id,
            bytes_uploaded=1000,
            bytes_downloaded=5000,
        )
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        # Controller now reports cumulative 1500/8000 -> deltas 500/3000.
        _, up, down = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=1500, down=8000)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
        )

        assert (up, down) == (500, 3000)
        assert recorder.calls == [(session_id, 500, 3000)]

    async def test_repeated_total_is_an_idempotent_no_op(self) -> None:
        device_id = uuid.uuid4()
        session = FakeSession(
            id=uuid.uuid4(),
            device_id=device_id,
            bytes_uploaded=1500,
            bytes_downloaded=8000,
        )
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        updated, up, down = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=1500, down=8000)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
        )

        assert (updated, up, down) == (0, 0, 0)
        assert recorder.calls == []

    async def test_counter_reset_clamps_to_zero_never_credits_back(self) -> None:
        device_id = uuid.uuid4()
        session = FakeSession(
            id=uuid.uuid4(),
            device_id=device_id,
            bytes_uploaded=9000,
            bytes_downloaded=9000,
        )
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        # Controller counter restarted (reboot) -> totals below recorded.
        updated, up, down = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=10, down=10)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
        )

        assert (updated, up, down) == (0, 0, 0)
        assert recorder.calls == []

    async def test_missing_both_counters_is_skipped(self) -> None:
        device_id = uuid.uuid4()
        session = FakeSession(
            id=uuid.uuid4(), device_id=device_id, bytes_uploaded=0, bytes_downloaded=0
        )
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        updated, _, _ = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=None, down=None)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
        )

        assert updated == 0
        assert recorder.calls == []

    async def test_one_sided_counter_applies_only_that_direction(self) -> None:
        device_id = uuid.uuid4()
        session_id = uuid.uuid4()
        session = FakeSession(
            id=session_id, device_id=device_id, bytes_uploaded=0, bytes_downloaded=0
        )
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        _, up, down = await apply_controller_usage(
            clients=[_client("AA:BB:CC:DD:EE:FF", up=700, down=None)],
            active_sessions=[session],
            devices_by_id={device_id: device},
            guest_service=recorder,
        )

        assert (up, down) == (700, 0)
        assert recorder.calls == [(session_id, 700, 0)]

    async def test_unmatched_client_and_deviceless_session_are_ignored(
        self,
    ) -> None:
        device_id = uuid.uuid4()
        session = FakeSession(
            id=uuid.uuid4(), device_id=device_id, bytes_uploaded=0, bytes_downloaded=0
        )
        device = FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")
        recorder = RecordingUsageRecorder()

        updated, _, _ = await apply_controller_usage(
            # A client for a device with no active session, plus a session
            # whose device row was not resolved.
            clients=[_client("11:22:33:44:55:66", up=999, down=999)],
            active_sessions=[
                session,
                FakeSession(
                    id=uuid.uuid4(),
                    device_id=None,
                    bytes_uploaded=0,
                    bytes_downloaded=0,
                ),
            ],
            devices_by_id={device_id: device},
            guest_service=recorder,
        )

        assert updated == 0
        assert recorder.calls == []


# --------------------------------------------------------------------------
# sync_omada_session_usage -- orchestration + failure isolation
# --------------------------------------------------------------------------


class TestSyncOmadaSessionUsage:
    async def test_happy_path_applies_usage_for_the_matched_session(self) -> None:
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
            sessions_by_router={
                router_id: [
                    FakeSession(
                        id=session_id,
                        device_id=device_id,
                        bytes_uploaded=0,
                        bytes_downloaded=0,
                    )
                ]
            },
            devices=[FakeDevice(id=device_id, mac_address="aa:bb:cc:dd:ee:ff")],
        )
        recorder = RecordingUsageRecorder()

        summary = await sync_omada_session_usage(
            ni_service=ni_service,
            guest_repository=guest_repo,
            guest_service=recorder,
            limit=50,
        )

        assert summary.integrations_considered == 1
        assert summary.integrations_synced == 1
        assert summary.integrations_failed == 0
        assert summary.sessions_updated == 1
        assert summary.bytes_uploaded_applied == 2000
        assert summary.bytes_downloaded_applied == 3000
        assert recorder.calls == [(session_id, 2000, 3000)]
        # Platform read: no requesting organization, and device resolution is
        # org-scoped to the integration's own org.
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
            sessions_by_router={
                router_b: [
                    FakeSession(
                        id=session_id,
                        device_id=device_id,
                        bytes_uploaded=0,
                        bytes_downloaded=0,
                    )
                ]
            },
            devices=[FakeDevice(id=device_id, mac_address="AA:BB:CC:DD:EE:FF")],
        )
        recorder = RecordingUsageRecorder()

        summary = await sync_omada_session_usage(
            ni_service=ni_service,
            guest_repository=guest_repo,
            guest_service=recorder,
            limit=50,
        )

        assert summary.integrations_considered == 2
        assert summary.integrations_failed == 1
        assert summary.integrations_synced == 1
        assert summary.sessions_updated == 1
        assert recorder.calls == [(session_id, 100, 200)]
