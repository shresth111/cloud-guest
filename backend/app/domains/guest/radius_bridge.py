"""The one implementation of "push this NAS client to the real FreeRADIUS
server", shared by the operator-facing registration endpoint and by
``app.domains.hub_reconciliation``.

Extracted from ``router.register_external_radius_nas``, where it had been
inline, for a reason the 2026-08-27 fault makes concrete rather than
stylistic. The ``client{}`` stanza the hub holds is keyed on the router's
WireGuard tunnel address (``radius_agent.add_client`` writes
``ipaddr = <tunnel_ip>/32``), and that address changes -- every hub
re-allocation moves it. Until now the push existed at exactly one call
site, the operator clicking "Generate", so a peer that moved by any other
route left the stanza behind, pointing at an address no device owned. The
symptom is total and silent: FreeRADIUS drops an Access-Request from an
address it has no client for without a reply, and nothing is logged
anywhere.

Making the push callable from the reconciliation pass is what lets the NAS
binding *follow* the peer instead of being a one-time derivation. Keeping
it in one place is what stops the retry/error-reporting behaviour below
from being reimplemented differently in the second caller.

``add_client`` is idempotent on ``nas_identifier`` -- it strips every
stanza with that shortname and writes exactly one -- so re-pushing is
always safe and always converges, whether or not a previous attempt got
part-way.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# RETRY A 5xx, ONCE-PLUS-TWO. Established 2026-08-27 after the failure
# which started all of this proved TRANSIENT, not structural: the same call
# succeeded unchanged when replayed later.
#
# The bridge is a `ThreadingHTTPServer` doing read-modify-write on
# `clients.conf` plus `systemctl restart freeradius`, and a separate 60s
# `wyfy-radius-sync.timer` on the same host runs `systemctl reload
# freeradius`. So there is a recurring window in which a perfectly valid
# request loses a race, systemd returns non-zero, `_validate_and_restart`
# restores the backup and raises, and the caller sees an opaque 500.
# `ops/hub-agents/radius_agent.py` now takes a process-local lock, closing
# the half this codebase owns; the sync timer is outside it.
#
# 5xx ONLY. A 4xx from this bridge is deterministic -- 401 is a secret
# mismatch, 400 a malformed payload -- and retrying it just triples the
# latency before reporting the same thing.
RETRY_DELAYS = (0.5, 2.0)


class RadiusBridgePushError(Exception):
    """The NAS client could not be written to the real RADIUS server.

    Carries the bridge's own explanation, which is frequently the only
    description of the failure that exists anywhere: the agent answers
    every fault as ``{"error": "<str(exception)>"}`` and its
    ``log_message`` writes access lines at DEBUG only, so a discarded
    response body used to leave nothing in either system. Losing that body
    once cost a multi-hour investigation.

    ``transport`` distinguishes "no request/response exchange completed"
    from "the bridge answered and refused" -- the first is worth retrying
    at a higher level, the second is not.
    """

    def __init__(self, detail: str, *, transport: bool, status_code: int | None):
        super().__init__(detail)
        self.detail = detail
        self.transport = transport
        self.status_code = status_code


def bridge_error_detail(resp: httpx.Response) -> str:
    """The hub agent's own explanation of a >=400, in a form safe to put in
    an API error detail. Truncated because ``_validate_and_restart`` embeds
    up to 2000 characters of ``freeradius -CX`` output in it."""
    try:
        body = resp.json()
    except ValueError:
        return (resp.text or "<empty response body>")[:600]
    if isinstance(body, dict) and "error" in body:
        return str(body["error"])[:600]
    return str(body)[:600]


async def push_nas_client(
    *, tunnel_ip: str, nas_identifier: str, secret: str
) -> None:
    """Writes (or rewrites) ``nas_identifier``'s ``client{}`` stanza on the
    real FreeRADIUS server, bound to ``tunnel_ip``.

    Returns only when the hub has confirmed the write with a 2xx. Raises
    ``RadiusBridgePushError`` otherwise -- there is no "probably worked"
    return value, because the entire class of bug this module keeps being
    bitten by is an operation reporting success having changed nothing.
    """
    settings = get_settings()
    resp: httpx.Response | None = None
    last_transport_error: httpx.HTTPError | None = None

    for attempt in range(len(RETRY_DELAYS) + 1):
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    settings.hub_radius_agent_url,
                    headers={
                        "X-Agent-Secret": settings.hub_radius_agent_secret,
                        "Content-Type": "application/json",
                    },
                    json={
                        "tunnel_ip": tunnel_ip,
                        "nas_identifier": nas_identifier,
                        "secret": secret,
                    },
                )
        except httpx.HTTPError as exc:
            # A transport failure is also worth one more try -- the restart
            # this races with drops connections as well as failing them.
            last_transport_error = exc
            resp = None
        else:
            last_transport_error = None
            if resp.status_code < 500:
                break
        if attempt < len(RETRY_DELAYS):
            logger.warning(
                "radius_bridge_retrying",
                extra={
                    "nas_identifier": nas_identifier,
                    "attempt": attempt + 1,
                    "status_code": None if resp is None else resp.status_code,
                    "detail": (
                        str(last_transport_error)
                        if last_transport_error is not None
                        else bridge_error_detail(resp)
                    ),
                },
            )
            await asyncio.sleep(RETRY_DELAYS[attempt])

    if last_transport_error is not None:
        raise RadiusBridgePushError(
            f"Could not reach the RADIUS server bridge after "
            f"{len(RETRY_DELAYS) + 1} attempts: {last_transport_error!s}",
            transport=True,
            status_code=None,
        ) from last_transport_error

    assert resp is not None  # noqa: S101 -- the only other path raises above
    if resp.status_code >= 400:
        raise RadiusBridgePushError(
            f"The RADIUS server bridge refused this registration "
            f"(HTTP {resp.status_code}): {bridge_error_detail(resp)}",
            transport=False,
            status_code=resp.status_code,
        )


__all__ = [
    "push_nas_client",
    "bridge_error_detail",
    "RadiusBridgePushError",
    "RETRY_DELAYS",
]
