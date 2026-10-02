"""One lock per router around every write to its ``/ip firewall filter``
``chain=forward``.

## Why

Three request paths write that chain over the RouterOS API:

* ``FirewallService.push_rules_to_router`` -- one read, then adds and
  removes positioned ``place-before=<band-end .id>``, then a verifying
  re-read, and on failure a restore of a snapshot taken at the first read.
* ``FirewallService.install_firewall_band`` -- two adds above the
  established accept, then a verifying re-read that removes them again if
  they did not land adjacent.
* ``ContentFilterService.push_rule_to_device`` -- its
  ``_ensure_content_filter_enforcement_rule`` places (and re-places) the
  shared content-filter drop *before the first accept* in ``forward``. Once
  a customer ``accept`` rule sits in the band, that is inside the band.

Each assumes the chain does not change between its read and its writes. Two
of them interleaved on one router can verify against, or restore over, the
other's half-finished writes: a firewall push that snapshots, then fails,
restores a snapshot that predates a concurrent push's adds. So they share
one lock, keyed on the router. A caller that finds it held gets a 409
(``FIREWALL_PUSH_IN_PROGRESS``) and can retry in a few seconds; nothing
queues.

## The mechanism is the codebase's existing one

``redis.set(key, value, nx=True, ex=ttl)``, released in ``finally`` -- the
same SETNX shape every sweep lock here uses (e.g.
``connected_devices.tasks``' liveness sweep lock,
``provisioning_engine.tasks``' health-poll sweep lock). One difference, and
it is deliberate: the value is a per-acquisition token and release deletes
the key only if it still holds that token. A sweep lock has one holder
fleet-wide; this one is taken by request handlers, so a push that outran the
TTL must not delete the lock a second push has since taken.

## TTL

``FIREWALL_PUSH_LOCK_TTL_SECONDS`` is 600. The gateway's RouterOS socket
timeout is 10 s per call and a timed-out call aborts the push, so a push
only runs long when every call is slow but under the timeout. A push of N
rules issues at most one read, N adds, N removes, one verifying read, and,
on failure, N adds and N removes more -- about 4N+2 calls. 600 s covers
that at the full 10 s per call for up to 14 rules, and at a (still very
slow) 1 s per call for ~145. The TTL only matters if the process dies
mid-push; every normal exit, success or exception, releases in ``finally``.

## When there is no Redis

``redis=None`` (a service constructed directly by a unit test, as
``NetworkDiagnosticsService`` allows) takes no lock. The FastAPI
dependencies always inject the real client. A Redis *error* while acquiring
propagates: pushing unserialised because Redis is down is not a fallback
this module takes.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "FIREWALL_PUSH_IN_PROGRESS",
    "FIREWALL_PUSH_LOCK_REDIS_KEY_TEMPLATE",
    "FIREWALL_PUSH_LOCK_TTL_SECONDS",
    "router_firewall_lock",
]

#: The error code a caller receives in ``data.code`` when the lock is held.
FIREWALL_PUSH_IN_PROGRESS = "FIREWALL_PUSH_IN_PROGRESS"

FIREWALL_PUSH_LOCK_REDIS_KEY_TEMPLATE = "firewall:router-push:lock:{router_id}"
FIREWALL_PUSH_LOCK_TTL_SECONDS = 600

#: Delete the key only if it still holds our token. Atomic on the server.
_RELEASE_IF_OURS = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)


@asynccontextmanager
async def router_firewall_lock(
    redis: Any | None,
    router_id: uuid.UUID,
    *,
    busy_error: Callable[[], Exception],
) -> AsyncIterator[None]:
    """Hold the router's forward-chain lock for the body, or raise
    ``busy_error()`` at once if another holder has it."""
    if redis is None:
        yield
        return
    key = FIREWALL_PUSH_LOCK_REDIS_KEY_TEMPLATE.format(router_id=router_id)
    token = uuid.uuid4().hex
    acquired = await redis.set(key, token, nx=True, ex=FIREWALL_PUSH_LOCK_TTL_SECONDS)
    if not acquired:
        logger.info("router_firewall_lock_busy", extra={"router_id": str(router_id)})
        raise busy_error()
    try:
        yield
    finally:
        try:
            await redis.eval(_RELEASE_IF_OURS, 1, key, token)
        except Exception:  # noqa: BLE001 -- never mask the body's outcome
            # The TTL frees it; a failed release must not turn a successful
            # push into an error, or replace the push's own exception.
            logger.warning(
                "router_firewall_lock_release_failed",
                extra={"router_id": str(router_id)},
                exc_info=True,
            )
