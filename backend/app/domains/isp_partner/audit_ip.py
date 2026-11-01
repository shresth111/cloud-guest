"""AUDIT-LOG: remember which IP an ``/isp`` request came from, on the audit
rows that request writes.

* The IP is the app's own trusted client address: ``auth.dependencies
  .get_device_info(request).ip_address`` (``request.client.host``). Uvicorn
  runs with proxy headers and ``--forwarded-allow-ips``
  (``scripts/run_api.sh``), so X-Forwarded-For is honoured only from the
  trusted nginx hop; no raw header is read here.
* ``isp_request_ip_scope`` is a yield dependency of ``RequireIspPartner``: it
  sets a ContextVar for the request and ALWAYS resets it when the request
  ends, so nothing leaks into the next request or a Celery task.
* The ``before_insert`` listener on ``audit_log_entries`` is a strict no-op
  unless that ContextVar is set (i.e. inside an ``/isp`` request with
  ``ISP_AUDIT_LOG_ENABLED`` on). It then adds one key, ``ip``, to the row's
  ``event_metadata`` when the writer did not put one there. No column, no
  other key, no other row is touched.
"""

from __future__ import annotations

import contextvars
from collections.abc import AsyncIterator
from typing import Any

from fastapi import Request
from sqlalchemy import event

_REQUEST_IP: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "isp_audit_request_ip", default=None
)


def current_request_ip() -> str | None:
    return _REQUEST_IP.get()


def trusted_client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    from app.domains.auth.dependencies import get_device_info

    ip = get_device_info(request).ip_address
    return None if not ip or ip == "unknown" else ip[:45]


async def isp_request_ip_scope(request: Request = None) -> AsyncIterator[None]:  # type: ignore[assignment]
    from .audit_log_config import get_audit_log_settings

    token = None
    if request is not None and get_audit_log_settings().audit_log_enabled:
        token = _REQUEST_IP.set(trusted_client_ip(request))
    try:
        yield
    finally:
        if token is not None:
            try:
                _REQUEST_IP.reset(token)
            except ValueError:  # exited in another context: clear it anyway
                _REQUEST_IP.set(None)


def stamp_ip(target: Any) -> None:
    """Add ``ip`` to a new audit row's metadata. No-op unless the ContextVar
    is set; never overwrites a writer's own ``ip``."""
    ip = _REQUEST_IP.get()
    if not ip:
        return
    meta = target.event_metadata
    if meta is None:
        target.event_metadata = {"ip": ip}
    elif isinstance(meta, dict) and "ip" not in meta:
        target.event_metadata = {**meta, "ip": ip}


def _before_insert(_mapper: Any, _connection: Any, target: Any) -> None:
    stamp_ip(target)


def register() -> None:
    from app.domains.rbac.models import AuditLogEntry

    if not event.contains(AuditLogEntry, "before_insert", _before_insert):
        event.listen(AuditLogEntry, "before_insert", _before_insert)


def unregister() -> None:
    """For the no-op test only."""
    from app.domains.rbac.models import AuditLogEntry

    if event.contains(AuditLogEntry, "before_insert", _before_insert):
        event.remove(AuditLogEntry, "before_insert", _before_insert)


register()

__all__ = [
    "current_request_ip",
    "isp_request_ip_scope",
    "register",
    "stamp_ip",
    "trusted_client_ip",
    "unregister",
]
