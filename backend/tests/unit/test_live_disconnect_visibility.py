"""A session end must take the guest off the WiFi, and a failure must be
visible: in the log, on the row, and in what the operator is told.

``issue_live_disconnect`` is the only enforcement mechanism behind every
session-ending path -- the inactivity sweep, pause, disconnect, terminate, and
both the data-cap and FUP-quota paths. It runs *after* the status transition
has already committed, and it never raises. Both of those are deliberate: an
unreachable router must not stop an operator ending a session in our own
records.

It used to send an RFC 5176 Disconnect-Request to the NAS over UDP, and that
never once worked in this deployment -- the app server has no route into the
hub's ``10.20.0.0/24`` tunnel subnet, so every packet left by the default
gateway and was dropped. Measured on production 2026-09-16,
``guest_sessions.disconnect_enforced`` stood at 584 NULL, 32 false and **zero
true**: the platform had never disconnected a single guest. It now asks the
router directly over the RouterOS API (port 8728), through the
``terminator`` passed in -- the same work ``guest_access``'s block
enforcement already does, and the only transport that answers from the app
server.

These tests pin the two things that matter about that call: it really happens,
and its outcome -- success, failure, or not-attempted -- is recorded honestly
rather than reported as an enforcement this platform did not perform.
"""

from __future__ import annotations

import logging
import uuid
from types import SimpleNamespace

import pytest

from app.domains.guest.service import issue_live_disconnect


class _Repo:
    """Minimal stand-in for ``GuestRepositoryProtocol``.

    Only the two methods ``issue_live_disconnect`` actually reaches are
    implemented, and ``update_session`` records what it was asked to write so
    a test can assert on the persisted outcome rather than on a mock call."""

    def __init__(self, *, guest=None, fail_update: bool = False):
        self._guest = guest
        self._fail_update = fail_update
        self.updates: list[dict] = []

    async def get_guest_by_id(self, guest_id):
        return self._guest

    async def update_session(self, session, data):
        if self._fail_update:
            raise RuntimeError("db is down")
        self.updates.append(dict(data))
        for key, value in data.items():
            setattr(session, key, value)
        return session


class _Terminator:
    """Stand-in for ``LiveSessionTerminator``.

    Records what it was asked to end. The real one *raises* when the router
    says the guest is still there; swallowing that is
    ``issue_live_disconnect``'s job, which is what makes it worth asserting
    both halves separately."""

    _DEFAULT = object()

    def __init__(self, *, fail: Exception | None = None, outcome=_DEFAULT):
        self._fail = fail
        #  Defaults to the real shape a confirmed removal has, so every test
        #  written before the outcome mattered keeps meaning what it meant.
        self._outcome = (
            SimpleNamespace(matched=1, removed=1, still_active=0)
            if outcome is self._DEFAULT
            else outcome
        )
        self.calls: list[dict] = []

    async def end_on_router(self, *, session, identifier, organization_id=None):
        self.calls.append(
            {
                "session_id": session.id,
                "identifier": identifier,
                "organization_id": organization_id,
            }
        )
        if self._fail is not None:
            raise self._fail
        return self._outcome


def _session():
    return SimpleNamespace(
        id=uuid.uuid4(),
        router_id=uuid.uuid4(),
        guest_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        ip_address="10.5.50.20",
        disconnect_enforced=None,
    )


# ---------------------------------------------------------------------------
# the device call actually happens
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_confirmed_disconnect_asks_the_router_and_records_true(caplog):
    """The whole point of the change: the router is asked, by the guest's own
    identifier, and the row says so."""
    session = _session()
    terminator = _Terminator()
    repo = _Repo(guest=SimpleNamespace(identifier="g@example.com"))

    with caplog.at_level(logging.INFO):
        assert (
            await issue_live_disconnect(repo, session=session, terminator=terminator)
            is True
        )

    assert terminator.calls == [
        {
            "session_id": session.id,
            "identifier": "g@example.com",
            "organization_id": session.organization_id,
        }
    ]
    assert session.disconnect_enforced is True
    assert repo.updates == [{"disconnect_enforced": True}]
    record = next(
        r for r in caplog.records if r.message == "guest_live_disconnect_enforced"
    )
    assert record.enforcement_delivered is True


# ---------------------------------------------------------------------------
# every way it can fail is recorded and warned about
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_router_that_refuses_is_recorded_and_warned(caplog):
    """``LiveSessionTerminator`` raises when the guest is still on the
    router's own active table. That is an attempt that failed, not an
    attempt that did not happen -- and the guest is still online either
    way, so the row must not read as enforced."""
    session = _session()
    terminator = _Terminator(fail=RuntimeError("still active on device"))
    repo = _Repo(guest=SimpleNamespace(identifier="g@example.com"))

    with caplog.at_level(logging.WARNING):
        assert (
            await issue_live_disconnect(repo, session=session, terminator=terminator)
            is False
        )

    assert session.disconnect_enforced is False
    assert repo.updates == [{"disconnect_enforced": False}]
    record = next(
        r for r in caplog.records if r.message == "guest_live_disconnect_failed"
    )
    assert record.levelno == logging.WARNING
    assert record.enforcement_delivered is False


@pytest.mark.asyncio
async def test_no_guest_row_is_recorded_and_warned(caplog):
    session = _session()
    terminator = _Terminator()
    repo = _Repo(guest=None)

    with caplog.at_level(logging.WARNING):
        assert (
            await issue_live_disconnect(repo, session=session, terminator=terminator)
            is None
        )

    #  Nothing to identify the guest by, so the router was never asked.
    assert terminator.calls == []
    assert session.disconnect_enforced is False


@pytest.mark.asyncio
async def test_no_terminator_wired_is_recorded_and_warned(caplog):
    """A deployment (or a test) with no hook wired has no way to reach a
    device at all. Distinct from a failure, and still recorded as
    not-enforced, because the guest is still online."""
    session = _session()
    repo = _Repo(guest=SimpleNamespace(identifier="g@example.com"))

    with caplog.at_level(logging.WARNING):
        assert await issue_live_disconnect(repo, session=session) is None

    assert session.disconnect_enforced is False
    assert any(
        r.message == "guest_live_disconnect_no_terminator" for r in caplog.records
    )


# ---------------------------------------------------------------------------
# a stop the router itself reported is not ours to make
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_nas_reported_stop_touches_no_device_and_writes_nothing():
    """``accounting_stop`` fires on every ordinary guest disconnect, and the
    router is the one telling us the session is over. Opening a connection
    to remove a row that is already gone, fleet-wide, per disconnect, is
    pure cost -- and the column means "did *we* enforce this", so it is left
    as NULL rather than claimed."""
    session = _session()
    terminator = _Terminator()
    repo = _Repo(guest=SimpleNamespace(identifier="g@example.com"))

    assert (
        await issue_live_disconnect(
            repo,
            session=session,
            terminator=terminator,
            already_ended_on_device=True,
        )
        is None
    )

    assert terminator.calls == []
    assert repo.updates == []
    assert session.disconnect_enforced is None


# ---------------------------------------------------------------------------
# recording must never become the thing that breaks a disconnect
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_failure_to_record_does_not_raise(caplog):
    """The whole contract of this function is that it cannot raise: the status
    transition has already committed by the time it runs. Adding a write must
    not quietly add a way for it to blow up an operator's terminate."""
    session = _session()
    repo = _Repo(guest=None, fail_update=True)
    with caplog.at_level(logging.WARNING):
        assert await issue_live_disconnect(repo, session=session) is None
    assert any(
        r.message == "guest_live_disconnect_record_failed" for r in caplog.records
    )


# ---------------------------------------------------------------------------
# what the operator is told
# ---------------------------------------------------------------------------


def test_operator_message_does_not_claim_a_disconnect_that_did_not_happen():
    """The specific lie this closes: "Guest session terminated" shown for a
    session whose device was never cut off."""
    from app.domains.guest.router import _session_end_message

    unenforced = SimpleNamespace(disconnect_enforced=False)
    message = _session_end_message(unenforced, action="terminated")
    assert "in records only" in message
    assert "may still be online" in message
    assert message != "Guest session terminated"


def test_operator_message_confirms_a_real_disconnect():
    from app.domains.guest.router import _session_end_message

    enforced = SimpleNamespace(disconnect_enforced=True)
    assert (
        _session_end_message(enforced, action="terminated")
        == "Guest session terminated and the device was disconnected"
    )


def test_operator_message_is_unchanged_when_nothing_was_attempted():
    """NULL is the ordinary case -- the NAS told us the session ended, so no
    call was owed. That must not read as a failure."""
    from app.domains.guest.router import _session_end_message

    untouched = SimpleNamespace(disconnect_enforced=None)
    assert (
        _session_end_message(untouched, action="disconnected")
        == "Guest session disconnected"
    )


# ---------------------------------------------------------------------------
# the speed limit comes off whether or not we ended the session
# ---------------------------------------------------------------------------


class _TerminatorWithRelease(_Terminator):
    """A terminator that also knows how to release the venue's speed limit,
    which is what the real one does at a controller-managed venue."""

    #  Forwards rather than re-declaring its base's keywords, so a release
    #  test can also pin an outcome as ``_Terminator`` grows knobs. Every
    #  test below drives the ``already_ended_on_device`` branch, where
    #  ``end_on_router`` is never reached at all -- the default outcome is
    #  simply never consulted.
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.released: list[dict] = []

    async def release_rate_limit(self, *, session, organization_id=None):
        self.released.append(
            {"session_id": session.id, "organization_id": organization_id}
        )


@pytest.mark.asyncio
async def test_a_nas_reported_stop_still_releases_the_speed_limit():
    """The defect, as a test.

    ``already_ended_on_device`` returns early -- correctly, there is no
    authorization left to remove -- and it used to take the rate-limit
    release with it. At a RADIUS-mode venue an Accounting-Stop is the
    *ordinary* ending, so the limit was set once and never removed, on a
    controller record keyed by MAC that outlives the session. The next
    device to hold that MAC inherited a cap nobody configured for it: the
    ``/queue simple`` accumulation defect, reborn on a different vendor.
    """
    session = _session()
    terminator = _TerminatorWithRelease()
    repo = _Repo(guest=SimpleNamespace(identifier="g@example.com"))

    await issue_live_disconnect(
        repo,
        session=session,
        terminator=terminator,
        already_ended_on_device=True,
    )

    # Still no device call and still no claim of enforcement...
    assert terminator.calls == []
    assert session.disconnect_enforced is None
    # ...but the limit is taken off.
    assert [r["session_id"] for r in terminator.released] == [session.id]
    assert terminator.released[0]["organization_id"] == session.organization_id


@pytest.mark.asyncio
async def test_a_release_that_fails_does_not_break_the_session_end(caplog):
    """Same contract as everything else on this path: the status transition
    has already committed, so a venue's controller must not be able to turn
    a completed disconnect into an exception."""
    session = _session()

    class _Boom(_TerminatorWithRelease):
        async def release_rate_limit(self, *, session, organization_id=None):
            raise RuntimeError("controller is unreachable")

    assert (
        await issue_live_disconnect(
            _Repo(guest=SimpleNamespace(identifier="g@example.com")),
            session=session,
            terminator=_Boom(),
            already_ended_on_device=True,
        )
        is None
    )
    assert any(
        r.message == "guest_live_rate_limit_release_failed" for r in caplog.records
    )


@pytest.mark.asyncio
async def test_a_terminator_without_a_release_is_not_a_failure():
    """A RouterOS-only wiring, or a test's own fake. There is no controller
    limit to release, and the absence must not log an enforcement failure or
    raise."""
    session = _session()
    assert (
        await issue_live_disconnect(
            _Repo(guest=SimpleNamespace(identifier="g@example.com")),
            session=session,
            terminator=_Terminator(),
            already_ended_on_device=True,
        )
        is None
    )


# ---------------------------------------------------------------------------
# a call that removed nothing is not an enforcement
# ---------------------------------------------------------------------------
#
# The adapter contract is explicit that ending sessions for a guest who has
# none "matches nothing, removes nothing, and raises nothing" -- that is what
# makes blocking idempotent. ``issue_live_disconnect`` used to infer
# enforcement from the absence of an exception, so every one of those wrote
# ``disconnect_enforced = true``: the platform claiming it took a guest off
# the WiFi by a call that took nobody off anything. The column means "did we",
# and the honest answer there is the same NULL an ``already_ended_on_device``
# stop already writes.


@pytest.mark.asyncio
async def test_a_device_call_that_removed_nothing_is_left_null(caplog):
    """The regression test. No exception, and no removal either."""
    session = _session()
    terminator = _Terminator(outcome=SimpleNamespace(matched=0, removed=0,
                                                     still_active=0))
    repo = _Repo(guest=SimpleNamespace(identifier="g@example.com"))

    with caplog.at_level(logging.WARNING):
        result = await issue_live_disconnect(
            repo, session=session, terminator=terminator
        )

    #  The call still happened -- this is not a short-circuit.
    assert len(terminator.calls) == 1
    assert result is None
    assert repo.updates == []
    assert session.disconnect_enforced is None
    record = next(
        r
        for r in caplog.records
        if r.message == "guest_live_disconnect_nothing_removed"
    )
    assert record.levelno == logging.WARNING
    assert record.enforcement_delivered is False


@pytest.mark.asyncio
async def test_removing_nothing_is_recorded_exactly_like_a_nas_reported_stop():
    """Both are "the device had no live session and we ended nothing". They
    must not be recorded two different ways -- the deliberate NULL of the
    ``already_ended_on_device`` branch is the precedent this follows."""
    nas_reported, removed_nothing = _session(), _session()
    repo = _Repo(guest=SimpleNamespace(identifier="g@example.com"))

    await issue_live_disconnect(
        repo,
        session=nas_reported,
        terminator=_Terminator(),
        already_ended_on_device=True,
    )
    await issue_live_disconnect(
        repo,
        session=removed_nothing,
        terminator=_Terminator(
            outcome=SimpleNamespace(matched=0, removed=0, still_active=0)
        ),
    )

    assert nas_reported.disconnect_enforced is None
    assert removed_nothing.disconnect_enforced is None
    assert repo.updates == []


@pytest.mark.asyncio
async def test_rows_removed_but_the_guest_still_on_the_device_is_not_enforcement():
    """``still_active`` beats ``removed``: rows can go and the guest remain,
    which is the entire reason ``SessionEndOutcome`` takes a second read of
    the active table after the removals."""
    session = _session()
    terminator = _Terminator(
        outcome=SimpleNamespace(matched=1, removed=1, still_active=1)
    )
    repo = _Repo(guest=SimpleNamespace(identifier="g@example.com"))

    assert (
        await issue_live_disconnect(repo, session=session, terminator=terminator)
        is None
    )
    assert session.disconnect_enforced is None


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [None, True, "ok", SimpleNamespace()])
async def test_a_terminator_that_reports_no_counters_is_not_believed(answer):
    """``LiveSessionTerminatorProtocol.end_on_router`` is typed ``-> object``.
    A hook that returns something without the counters has not shown us a
    removal, and this column may not be filled in from an absence of
    contradiction."""
    session = _session()
    terminator = _Terminator(outcome=answer)
    repo = _Repo(guest=SimpleNamespace(identifier="g@example.com"))

    assert (
        await issue_live_disconnect(repo, session=session, terminator=terminator)
        is None
    )
    assert session.disconnect_enforced is None


# ---------------------------------------------------------------------------
# ...proven against the real terminator, wired the way the app wires it
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_real_terminator_on_a_mikrotik_with_nobody_online_writes_null():
    """A ``SimpleNamespace`` can be made to say anything. This constructs the
    actual ``LiveSessionTerminator`` the sweeps build -- real
    ``SessionEndOutcome``, real MikroTik branch, real ``end_on_router`` --
    against an adapter returning precisely the idempotent no-op its own
    contract documents, and asserts the row is left NULL.

    It is also the MikroTik non-regression test for the rest of that path:
    the adapter is still asked, with the guest's identifier and the session's
    MAC, and ``ended_cleanly`` still keeps it from raising."""
    from app.domains.guest_access.device_adapters import (
        SessionControlSnapshot,
        SessionEndOutcome,
    )
    from app.domains.guest_access.enforcement import LiveSessionTerminator

    asked: list[dict] = []

    class _Adapter:
        vendor = "mikrotik"

        async def end_sessions(self, credentials, *, mac_address, username):
            asked.append({"mac_address": mac_address, "username": username})
            #  "a guest with no live session matches nothing, removes
            #  nothing, and raises nothing" -- BaseGuestAccessAdapter.
            return SessionEndOutcome(
                control=SessionControlSnapshot(
                    hotspot_servers=1, coa_accept=False, coa_port=None
                ),
                matched=0,
                removed=0,
                still_active=0,
            )

    class _RouterLookup:
        async def get_router(self, router_id, *, requesting_organization_id=None):
            return SimpleNamespace(
                id=router_id,
                vendor="mikrotik",
                management_ip_address="10.5.50.1",
                public_ip_address=None,
                api_username="admin",
            )

        def get_decrypted_api_secret(self, router):
            return "s3cret"

    class _DeviceLookup:
        async def get_device_by_id(self, device_id):
            return SimpleNamespace(mac_address="AA:BB:CC:DD:EE:FF")

    session = _session()
    session.device_id = uuid.uuid4()
    terminator = LiveSessionTerminator(
        router_lookup=_RouterLookup(),
        device_lookup=_DeviceLookup(),
        adapter_factory=lambda vendor: _Adapter(),
    )
    repo = _Repo(guest=SimpleNamespace(identifier="+919315074877"))

    result = await issue_live_disconnect(
        repo, session=session, terminator=terminator
    )

    assert asked == [
        {"mac_address": "AA:BB:CC:DD:EE:FF", "username": "+919315074877"}
    ]
    assert result is None
    assert repo.updates == []
    assert session.disconnect_enforced is None
