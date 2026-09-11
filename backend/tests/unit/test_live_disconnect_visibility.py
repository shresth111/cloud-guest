"""A failed live disconnect must be visible: in the log, on the row, and in
what the operator is told.

``issue_live_disconnect`` is the only enforcement mechanism behind every
session-ending path -- the inactivity sweep, pause, disconnect, terminate, and
both the data-cap and FUP-quota paths. It sends an RFC 5176 Disconnect-Request
*after* the status transition has already committed, and it never raises. Both
of those are deliberate: an unreachable NAS must not stop an operator ending a
session in our own records.

The cost was that a failed enforcement and a successful one were
indistinguishable. ``status`` said ``TERMINATED`` either way, the API said
"Guest session terminated" either way, and the only difference -- a timeout --
was logged at INFO with a docstring calling it "the expected outcome in this
sandbox".

Measured on production 2026-09-11, the unenforced outcome was the *only* one
occurring: the app server has no route to the WireGuard tunnel range
(``ip route show`` carries no ``10.20.0.0/24``, no WireGuard interface,
``ping 10.20.0.19`` 100% loss) while ``nas_client.ip_address`` is a tunnel
address. So every Disconnect-Request was dropped and every session-ending
action reported success for something that did not happen.

These tests do not fix that -- the transport has to change, or the tunnel has
to become routable. They pin the part that was fixed: it is no longer silent.
"""

from __future__ import annotations

import logging
import uuid
from types import SimpleNamespace

import pytest

from app.domains.guest.service import issue_live_disconnect


class _Repo:
    """Minimal stand-in for ``GuestRepositoryProtocol``.

    Only the four methods ``issue_live_disconnect`` actually reaches are
    implemented, and ``update_session`` records what it was asked to write so
    a test can assert on the persisted outcome rather than on a mock call."""

    def __init__(self, *, nas=None, guest=None, fail_update: bool = False):
        self._nas = nas
        self._guest = guest
        self._fail_update = fail_update
        self.updates: list[dict] = []

    async def get_nas_client_by_router(self, router_id):
        return self._nas

    async def get_guest_by_id(self, guest_id):
        return self._guest

    async def update_session(self, session, data):
        if self._fail_update:
            raise RuntimeError("db is down")
        self.updates.append(dict(data))
        for key, value in data.items():
            setattr(session, key, value)
        return session


def _session():
    return SimpleNamespace(
        id=uuid.uuid4(),
        router_id=uuid.uuid4(),
        guest_id=uuid.uuid4(),
        ip_address="10.5.50.20",
        disconnect_enforced=None,
    )


def _nas(ip: str | None = "10.20.0.19"):
    return SimpleNamespace(
        ip_address=ip,
        nas_identifier="cg-bfc7ed1c",
        shared_secret_encrypted=b"enc",
    )


# ---------------------------------------------------------------------------
# the three paths that used to return None in silence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_registered_nas_is_recorded_and_warned(caplog):
    """A session-ending path that cannot even find a NAS performed no
    enforcement whatsoever. This used to be a bare ``return None``."""
    session = _session()
    repo = _Repo(nas=None)
    with caplog.at_level(logging.WARNING):
        assert await issue_live_disconnect(repo, session=session) is None

    assert session.disconnect_enforced is False
    assert repo.updates == [{"disconnect_enforced": False}]
    assert any(r.message == "guest_live_disconnect_no_nas" for r in caplog.records)


@pytest.mark.asyncio
async def test_nas_without_an_address_is_recorded_and_warned(caplog):
    session = _session()
    repo = _Repo(nas=_nas(ip=None))
    with caplog.at_level(logging.WARNING):
        assert await issue_live_disconnect(repo, session=session) is None

    assert session.disconnect_enforced is False
    assert any(
        r.message == "guest_live_disconnect_nas_has_no_address"
        for r in caplog.records
    )


@pytest.mark.asyncio
async def test_no_response_is_a_warning_not_an_info(caplog, monkeypatch):
    """The production case, and the one that most needed the level change.

    A dropped Disconnect-Request is not informational -- it is the enforcement
    silently not happening. At INFO it sat below the threshold anyone reads."""
    session = _session()
    repo = _Repo(nas=_nas(), guest=SimpleNamespace(identifier="g@example.com"))
    monkeypatch.setattr(
        "app.domains.guest.service.decrypt_secret", lambda _: "secret"
    )
    monkeypatch.setattr(
        "app.domains.guest.service.send_packet", lambda *a, **k: None
    )

    with caplog.at_level(logging.INFO):
        assert await issue_live_disconnect(repo, session=session) is None

    record = next(
        r for r in caplog.records if r.message == "guest_live_disconnect_no_response"
    )
    assert record.levelno == logging.WARNING
    assert record.enforcement_delivered is False
    assert session.disconnect_enforced is False


@pytest.mark.asyncio
async def test_a_send_error_is_recorded_too(caplog, monkeypatch):
    session = _session()
    repo = _Repo(nas=_nas(), guest=SimpleNamespace(identifier="g@example.com"))
    monkeypatch.setattr(
        "app.domains.guest.service.decrypt_secret", lambda _: "secret"
    )

    def _boom(*a, **k):
        raise OSError("network unreachable")

    monkeypatch.setattr("app.domains.guest.service.send_packet", _boom)
    with caplog.at_level(logging.WARNING):
        assert await issue_live_disconnect(repo, session=session) is None
    assert session.disconnect_enforced is False


# ---------------------------------------------------------------------------
# the success path still means what it says
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_acknowledged_disconnect_records_true(monkeypatch):
    from app.domains.guest.radius_coa import RADIUS_CODE_DISCONNECT_ACK

    session = _session()
    repo = _Repo(nas=_nas(), guest=SimpleNamespace(identifier="g@example.com"))
    monkeypatch.setattr(
        "app.domains.guest.service.decrypt_secret", lambda _: "secret"
    )
    monkeypatch.setattr(
        "app.domains.guest.service.send_packet", lambda *a, **k: b"response"
    )
    monkeypatch.setattr(
        "app.domains.guest.service.parse_response_code",
        lambda _: RADIUS_CODE_DISCONNECT_ACK,
    )

    assert await issue_live_disconnect(repo, session=session) is True
    assert session.disconnect_enforced is True


@pytest.mark.asyncio
async def test_a_nak_is_a_real_answer_and_still_not_enforcement(monkeypatch):
    """A NAK means a real NAS replied and refused. The guest is still online,
    so ``disconnect_enforced`` tracks the ACK rather than merely whether a
    packet came back."""
    session = _session()
    repo = _Repo(nas=_nas(), guest=SimpleNamespace(identifier="g@example.com"))
    monkeypatch.setattr(
        "app.domains.guest.service.decrypt_secret", lambda _: "secret"
    )
    monkeypatch.setattr(
        "app.domains.guest.service.send_packet", lambda *a, **k: b"response"
    )
    monkeypatch.setattr(
        "app.domains.guest.service.parse_response_code", lambda _: 45
    )

    assert await issue_live_disconnect(repo, session=session) is False
    assert session.disconnect_enforced is False


# ---------------------------------------------------------------------------
# recording must never become the thing that breaks a disconnect
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_failure_to_record_does_not_raise(caplog):
    """The whole contract of this function is that it cannot raise: the status
    transition has already committed by the time it runs. Adding a write must
    not quietly add a way for it to blow up an operator's terminate."""
    session = _session()
    repo = _Repo(nas=None, fail_update=True)
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
    packet was owed. That must not read as a failure."""
    from app.domains.guest.router import _session_end_message

    untouched = SimpleNamespace(disconnect_enforced=None)
    assert (
        _session_end_message(untouched, action="disconnected")
        == "Guest session disconnected"
    )
