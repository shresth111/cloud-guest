"""``guest_sessions.internet_confirmed_at``: the login funnel's "internet
confirmed" stage.

The rule under test: set only from a reading the NAS or controller took,
first report wins, and never from "this platform asked the network to let
the guest through". Per source:

* RADIUS Accounting-Start / Interim-Update (``RadiusService``);
* the MikroTik gate push's own read-back (``hotspot_gate
  .internet_confirmation_source`` + ``tasks._record_gate_internet_confirmation``);
* the Omada Open-API usage sweep's ``authStatus`` read
  (``usage_tasks.controller_authorized_session_ids``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.domains.guest.constants import GuestAuthMethod, InternetConfirmationSource
from app.domains.guest.hotspot_gate import (
    HotspotGateResult,
    internet_confirmation_source,
)
from app.domains.guest.repository import GuestRepository
from app.domains.network_integration.providers.base import ProviderClient
from app.domains.network_integration.usage_tasks import (
    controller_authorized_session_ids,
    sync_omada_session_usage,
)

from .test_guest import make_fixture
from .test_omada_usage_sync import (
    FakeDevice,
    FakeGuestRepository,
    FakeNiService,
    FakeRedis,
    RecordingUsageRecorder,
    _session,
)

_NAS_IDENTIFIER = "nas-1"
_NAS_SECRET = "supersecret123"
_GUEST = "+15554445555"


# ============================================================================
# RADIUS accounting
# ============================================================================


def _install_first_write_wins(repository: Any) -> list[tuple]:
    """The in-memory guest repository has no ``mark_internet_confirmed``;
    give it one with the real method's contract (first write wins)."""
    calls: list[tuple] = []

    async def mark(session_id, *, at, source):
        calls.append((session_id, source))
        session = repository.sessions[session_id]
        if session.internet_confirmed_at is not None:
            return False
        session.internet_confirmed_at = at
        session.internet_confirmed_source = source
        return True

    repository.mark_internet_confirmed = mark
    return calls


async def _signed_in(fx: Any) -> Any:
    await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier=_NAS_IDENTIFIER,
        shared_secret=_NAS_SECRET,
    )
    await fx.guest_service.login_via_otp(
        identifier=_GUEST,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
    )
    return await fx.radius_service.authenticate_nas(
        nas_identifier=_NAS_IDENTIFIER, shared_secret=_NAS_SECRET
    )


def _only_session(fx: Any) -> Any:
    (session,) = fx.repository.sessions.values()
    return session


class TestRadiusAccounting:
    async def test_sign_in_alone_confirms_nothing(self) -> None:
        """The login (and the gate request it dispatches) is the platform
        *asking*; nothing the NAS said yet."""
        fx = make_fixture()
        calls = _install_first_write_wins(fx.repository)
        await _signed_in(fx)
        session = _only_session(fx)
        assert session.internet_confirmed_at is None
        assert calls == []

    async def test_accounting_start_confirms(self) -> None:
        fx = make_fixture()
        _install_first_write_wins(fx.repository)
        nas = await _signed_in(fx)
        await fx.radius_service.accounting_start(nas_client=nas, username=_GUEST)
        session = _only_session(fx)
        assert session.internet_confirmed_at is not None
        assert (
            session.internet_confirmed_source
            == InternetConfirmationSource.RADIUS_ACCOUNTING_START.value
        )

    async def test_first_report_wins_and_later_packets_do_not_write(self) -> None:
        fx = make_fixture()
        calls = _install_first_write_wins(fx.repository)
        nas = await _signed_in(fx)
        await fx.radius_service.accounting_start(nas_client=nas, username=_GUEST)
        first_at = _only_session(fx).internet_confirmed_at
        await fx.radius_service.accounting_start(nas_client=nas, username=_GUEST)
        await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=10,
            bytes_downloaded_total=20,
        )
        session = _only_session(fx)
        assert session.internet_confirmed_at == first_at
        assert (
            session.internet_confirmed_source
            == InternetConfirmationSource.RADIUS_ACCOUNTING_START.value
        )
        # Already set: no further write per packet.
        assert len(calls) == 1

    async def test_interim_confirms_when_start_was_missed(self) -> None:
        fx = make_fixture()
        _install_first_write_wins(fx.repository)
        nas = await _signed_in(fx)
        await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=0,
            bytes_downloaded_total=0,
        )
        assert (
            _only_session(fx).internet_confirmed_source
            == InternetConfirmationSource.RADIUS_ACCOUNTING_INTERIM.value
        )

    async def test_ended_session_is_not_confirmed_by_a_late_start(self) -> None:
        fx = make_fixture()
        calls = _install_first_write_wins(fx.repository)
        nas = await _signed_in(fx)
        session = _only_session(fx)
        session.status = "terminated"
        await fx.radius_service.accounting_start(nas_client=nas, username=_GUEST)
        assert session.internet_confirmed_at is None
        assert calls == []

    async def test_repository_without_the_method_changes_nothing(self) -> None:
        """Every other suite's fake: accounting still works."""
        fx = make_fixture()
        nas = await _signed_in(fx)
        result = await fx.radius_service.accounting_start(
            nas_client=nas, username=_GUEST
        )
        assert result.id == _only_session(fx).id


# ============================================================================
# GuestRepository.mark_internet_confirmed (the real SQL)
# ============================================================================


class _Nested:
    def __init__(self, owner) -> None:
        self.owner = owner

    async def __aenter__(self):
        self.owner.savepoints += 1
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeAsyncSession:
    def __init__(self, *, rowcount: int = 1, fail: bool = False) -> None:
        self.rowcount = rowcount
        self.fail = fail
        self.statements: list = []
        self.savepoints = 0

    def begin_nested(self):
        return _Nested(self)

    async def execute(self, statement):
        if self.fail:
            raise RuntimeError("column does not exist")
        self.statements.append(statement)
        return SimpleNamespace(rowcount=self.rowcount)


class TestRepositoryMark:
    async def test_conditional_update_inside_a_savepoint(self) -> None:
        db = _FakeAsyncSession(rowcount=1)
        ok = await GuestRepository(db).mark_internet_confirmed(
            uuid.uuid4(), at=datetime.now(UTC), source="radius_accounting_start"
        )
        assert ok is True
        assert db.savepoints == 1
        sql = str(db.statements[0].compile(dialect=postgresql.dialect()))
        assert sql.startswith("UPDATE guest_sessions SET internet_confirmed_at=")
        assert "guest_sessions.internet_confirmed_at IS NULL" in sql
        # ``version`` untouched, so a caller's loaded ORM row stays writable.
        assert "version=" not in sql

    async def test_already_set_reports_false(self) -> None:
        ok = await GuestRepository(
            _FakeAsyncSession(rowcount=0)
        ).mark_internet_confirmed(uuid.uuid4(), at=datetime.now(UTC), source="x")
        assert ok is False

    async def test_database_error_never_raises(self) -> None:
        ok = await GuestRepository(
            _FakeAsyncSession(fail=True)
        ).mark_internet_confirmed(uuid.uuid4(), at=datetime.now(UTC), source="x")
        assert ok is False


# ============================================================================
# MikroTik gate push read-back
# ============================================================================


class TestGatePushClassifier:
    @pytest.mark.parametrize(
        ("result", "expected"),
        [
            (
                HotspotGateResult("active_session"),
                InternetConfirmationSource.MIKROTIK_HOTSPOT_ACTIVE.value,
            ),
            (
                HotspotGateResult("created", wrote=True, host_state="bypassed"),
                InternetConfirmationSource.MIKROTIK_HOST_BYPASSED.value,
            ),
            (
                HotspotGateResult(
                    "already_bound", existing_bindings=("bypassed:cloudguest-authmac",)
                ),
                InternetConfirmationSource.MIKROTIK_BINDING_BYPASSED.value,
            ),
            (
                HotspotGateResult(
                    "raced", existing_bindings=("bypassed:cloudguest-authmac",)
                ),
                InternetConfirmationSource.MIKROTIK_BINDING_BYPASSED.value,
            ),
            # The write alone -- the platform asked -- is not confirmation.
            (HotspotGateResult("created", wrote=True, host_state="absent"), None),
            (HotspotGateResult("created", wrote=True, host_state="pending"), None),
            (HotspotGateResult("created", wrote=True, host_state=None), None),
            # A block wins over any bypass.
            (
                HotspotGateResult(
                    "already_bound",
                    existing_bindings=("bypassed:cloudguest-authmac", "blocked:op"),
                ),
                None,
            ),
            (HotspotGateResult("already_bound", existing_bindings=("regular:",)), None),
            (HotspotGateResult("no_reconciler"), None),
            (HotspotGateResult("no_hotspot"), None),
            (HotspotGateResult("held", hold_seconds=2.0), None),
            (HotspotGateResult("not_listed", retry=True), None),
            (HotspotGateResult("unsupported_vendor"), None),
        ],
    )
    def test_rule(self, result, expected) -> None:
        assert internet_confirmation_source(result) == expected


class _GateRepo:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple] = []

    async def mark_internet_confirmed(self, session_id, *, at, source):
        if self.fail:
            raise RuntimeError("boom")
        self.calls.append((session_id, source))
        return True


class _CommitCounter:
    def __init__(self) -> None:
        self.commits = 0

    async def commit(self):
        self.commits += 1


class TestGateTaskWrite:
    async def test_confirming_read_is_written_and_committed(self) -> None:
        from app.domains.guest.tasks import _record_gate_internet_confirmation

        repo, db, sid = _GateRepo(), _CommitCounter(), str(uuid.uuid4())
        await _record_gate_internet_confirmation(
            db, repo, session_id=sid, result=HotspotGateResult("active_session")
        )
        assert repo.calls == [
            (uuid.UUID(sid), InternetConfirmationSource.MIKROTIK_HOTSPOT_ACTIVE.value)
        ]
        assert db.commits == 1

    async def test_binding_write_alone_writes_nothing(self) -> None:
        from app.domains.guest.tasks import _record_gate_internet_confirmation

        repo, db = _GateRepo(), _CommitCounter()
        await _record_gate_internet_confirmation(
            db,
            repo,
            session_id=str(uuid.uuid4()),
            result=HotspotGateResult("created", wrote=True, host_state="absent"),
        )
        assert repo.calls == [] and db.commits == 0

    async def test_failure_never_raises(self) -> None:
        from app.domains.guest.tasks import _record_gate_internet_confirmation

        await _record_gate_internet_confirmation(
            _CommitCounter(),
            _GateRepo(fail=True),
            session_id=str(uuid.uuid4()),
            result=HotspotGateResult("active_session"),
        )


# ============================================================================
# Omada Open-API authStatus
# ============================================================================


def _client(mac: str, authorized: bool | None) -> ProviderClient:
    return ProviderClient(mac=mac, is_authorized=authorized)


class TestOmadaAuthorizedSessions:
    def _fixture(self):
        d1, d2, d3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        s1, s2, s3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        sessions = [_session(s1, d1), _session(s2, d2), _session(s3, d3)]
        devices = {
            d1: FakeDevice(id=d1, mac_address="aa:bb:cc:dd:ee:01"),
            d2: FakeDevice(id=d2, mac_address="aa:bb:cc:dd:ee:02"),
            d3: FakeDevice(id=d3, mac_address="aa:bb:cc:dd:ee:03"),
        }
        return sessions, devices, (s1, s2, s3)

    def test_only_authorized_true_counts(self) -> None:
        sessions, devices, (s1, _s2, _s3) = self._fixture()
        ids = controller_authorized_session_ids(
            clients=[
                _client("AA-BB-CC-DD-EE-01", True),
                _client("AA-BB-CC-DD-EE-02", False),  # pending / no auth
                _client("AA-BB-CC-DD-EE-03", None),  # controller did not say
                _client("AA-BB-CC-DD-EE-99", True),  # no session of ours
            ],
            active_sessions=sessions,
            devices_by_id=devices,
        )
        assert ids == [s1]

    def test_already_confirmed_is_skipped(self) -> None:
        sessions, devices, _ = self._fixture()
        sessions[0].internet_confirmed_at = datetime.now(UTC)
        assert (
            controller_authorized_session_ids(
                clients=[_client("AA-BB-CC-DD-EE-01", True)],
                active_sessions=sessions,
                devices_by_id=devices,
            )
            == []
        )

    async def test_sweep_marks_through_the_repository(self) -> None:
        router_id = uuid.uuid4()
        device_id, session_id = uuid.uuid4(), uuid.uuid4()
        integration = SimpleNamespace(
            id=uuid.uuid4(), organization_id=uuid.uuid4(), router_id=router_id
        )
        repo = FakeGuestRepository(
            sessions_by_router={router_id: [_session(session_id, device_id)]},
            devices=[FakeDevice(id=device_id, mac_address="aa:bb:cc:dd:ee:ff")],
        )
        marks: list[tuple] = []

        async def mark(sid, *, at, source):
            marks.append((sid, source))
            return True

        repo.mark_internet_confirmed = mark
        summary = await sync_omada_session_usage(
            ni_service=FakeNiService(
                integrations=[integration],
                clients_by_integration={
                    integration.id: [
                        ProviderClient(
                            mac="AA-BB-CC-DD-EE-FF",
                            is_authorized=True,
                            traffic_up_bytes=1,
                            traffic_down_bytes=1,
                        )
                    ]
                },
            ),
            guest_repository=repo,
            guest_service=RecordingUsageRecorder(),
            redis=FakeRedis(),
            limit=50,
        )
        assert marks == [
            (session_id, InternetConfirmationSource.OMADA_CLIENT_AUTHORIZED.value)
        ]
        assert summary.sessions_internet_confirmed == 1
