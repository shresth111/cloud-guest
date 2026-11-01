"""AUDIT-LOG IP capture: the listener is a no-op outside an ``/isp`` request,
the ContextVar is always reset at the end of a request (no leak into the
next request or a Celery task), and the IP is the app's trusted client
address (never a raw X-Forwarded-For header)."""

from __future__ import annotations

import contextvars
from types import SimpleNamespace

import pytest

from app.domains.isp_partner import audit_ip


class _Req:
    def __init__(self, host: str, headers: dict | None = None) -> None:
        self.client = SimpleNamespace(host=host, port=1)
        self.headers = headers or {}


@pytest.fixture
def flag_on(monkeypatch):  # noqa: ANN001, ANN201
    from app.domains.isp_partner import audit_log_config

    class _On:
        audit_log_enabled = True

    monkeypatch.setattr(audit_log_config, "get_audit_log_settings", lambda: _On())


def test_stamp_is_a_no_op_without_the_contextvar() -> None:
    meta = {"console": "customer", "x": 1}
    row = SimpleNamespace(event_metadata=meta)
    audit_ip.stamp_ip(row)
    assert row.event_metadata is meta and meta == {"console": "customer", "x": 1}
    empty = SimpleNamespace(event_metadata=None)
    audit_ip.stamp_ip(empty)
    assert empty.event_metadata is None


async def test_scope_sets_and_always_resets(flag_on) -> None:  # noqa: ANN001
    assert audit_ip.current_request_ip() is None
    gen = audit_ip.isp_request_ip_scope(_Req("203.0.113.7"))
    await gen.__anext__()
    assert audit_ip.current_request_ip() == "203.0.113.7"
    row = SimpleNamespace(event_metadata={"a": 1})
    audit_ip.stamp_ip(row)
    assert row.event_metadata == {"a": 1, "ip": "203.0.113.7"}
    own = SimpleNamespace(event_metadata={"ip": "writer-set"})
    audit_ip.stamp_ip(own)
    assert own.event_metadata == {"ip": "writer-set"}  # never overwritten
    with pytest.raises(StopAsyncIteration):
        await gen.__anext__()
    assert audit_ip.current_request_ip() is None
    # the next request starts clean, and an exception still resets it
    gen = audit_ip.isp_request_ip_scope(_Req("198.51.100.9"))
    await gen.__anext__()
    with pytest.raises(RuntimeError):
        await gen.athrow(RuntimeError("handler failed"))
    assert audit_ip.current_request_ip() is None
    # a Celery task runs in a fresh context: never sees an IP
    assert contextvars.Context().run(audit_ip.current_request_ip) is None


async def test_flag_off_sets_nothing() -> None:
    gen = audit_ip.isp_request_ip_scope(_Req("203.0.113.7"))
    await gen.__anext__()
    assert audit_ip.current_request_ip() is None
    with pytest.raises(StopAsyncIteration):
        await gen.__anext__()


def test_ip_is_the_trusted_client_address_not_a_raw_header() -> None:
    req = _Req("10.0.0.5", {"x-forwarded-for": "1.2.3.4", "x-real-ip": "5.6.7.8"})
    assert audit_ip.trusted_client_ip(req) == "10.0.0.5"
    assert audit_ip.trusted_client_ip(None) is None
    assert audit_ip.trusted_client_ip(SimpleNamespace(client=None, headers={})) is None


def test_listener_is_registered_once() -> None:
    from sqlalchemy import event

    from app.domains.rbac.models import AuditLogEntry

    audit_ip.register()
    audit_ip.register()
    assert event.contains(AuditLogEntry, "before_insert", audit_ip._before_insert)
