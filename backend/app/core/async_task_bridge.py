"""The standard sync-Celery-task -> async-work bridge every Beat-scheduled
task in this codebase uses (see ``app.core.celery_app``'s own module
docstring for the "async-in-a-sync-worker bridge" write-up this formalizes
into one shared, real helper instead of every task calling
``asyncio.run(...)`` directly).

## The bug this closes: a shared ``AsyncEngine`` pool outliving the loop
   that owns its connections

Every domain's Celery task module opens a fresh ``AsyncSession`` per task
run via ``app.database.session.SessionLocal()`` -- correct, deliberate
per-run *session* discipline. But every one of those sessions is bound to
the exact same process-wide ``app.database.session.engine``, whose
connection *pool* holds real, live ``asyncpg`` connections across calls,
not just across statements within one call. ``asyncpg`` connections are
bound to whichever ``asyncio`` event loop was running when they were
opened -- but a Celery worker task body is a plain, synchronous callable
that bridges to async work via ``asyncio.run(...)``, which creates a
**brand-new** event loop on *every single invocation*. A prefork worker
child process executes many different tasks over its lifetime (Celery
does not spawn a fresh OS process per task by default), so the exact same
``engine``/pool object -- and any connections still sitting in it -- is
reused across many, otherwise-unrelated ``asyncio.run()`` calls, each with
its own, different event loop.

Confirmed by direct reproduction against a real local Postgres: calling
``engine.connect()`` from a fresh ``asyncio.run()`` loop repeatedly,
*without* disposing the engine between calls, intermittently raises
exactly ``RuntimeError: Task <...> got Future <Future pending> attached to
a different loop`` (a stale pooled connection being handed back out) and
``RuntimeError: Event loop is closed`` (the pool later trying to
gracefully terminate that same stale connection, which requires
scheduling a coroutine on the event loop that created it -- a loop that
has since been closed and cannot schedule anything). This is the exact
error class this codebase's real, running celery-worker container hit
across *many* different Beat-scheduled tasks (drain_provision_queue,
run_isp_health_check_sweep, run_fup_time_accrual_sweep,
run_connected_device_sync_sweep, run_notification_dispatch_sweep, ...) --
not a defect isolated to any one domain's task, because the shared engine
is the actual source, not any one task's own code.

``Settings.pool_pre_ping`` does not save this: pre-ping catches DBAPI-level
disconnection errors on checkout and transparently reconnects, but a raw
``asyncio.RuntimeError`` from a cross-loop ``Future``/closed-loop access is
not a DBAPI error SQLAlchemy's pre-ping path catches -- it propagates
straight up and kills the task.

## The fix: dispose the pool from inside the loop that owns it, before
   that loop closes

``AsyncEngine.dispose()`` gracefully closes every connection currently in
the pool -- but only works correctly when awaited from within the same
event loop that opened those connections. Doing this as the very last
thing this invocation's async work does (in a ``finally``, still inside
the ``asyncio.run()``-managed loop) means: every connection this
invocation itself opened gets closed cleanly before its own loop goes
away, and the pool is left empty for the *next* invocation's own, different
loop to lazily open brand-new connections into -- never handing a
loop-A-bound connection to loop B. Confirmed by the same direct
reproduction above: identical repeated ``asyncio.run()`` calls, this time
disposing the engine in a ``finally`` before each call's loop closes,
complete cleanly every time.

Disposing a process-wide engine from inside one task is safe under
Celery's default ``prefork`` pool (this codebase's own deployment -- see
``docker-compose.yml``'s plain ``celery ... worker`` command, no
``--pool``/``--concurrency`` override): each worker child is a forked OS
process that runs one task at a time, so there is never a second task
concurrently mid-flight against the same ``engine`` object within one
process to disrupt.

## Why not a Celery signal handler instead

``task_postrun`` fires only *after* the task's own ``asyncio.run()`` call
has already returned -- meaning that call's event loop has already been
torn down by the time the signal handler runs. Disposing from there would
hit precisely the same "loop already closed" failure this module exists to
avoid; disposal must happen from *inside* the async function that owns the
loop, before it returns.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import TypeVar

from app.database.session import engine

T = TypeVar("T")


async def _run_and_dispose(coro: Awaitable[T]) -> T:
    try:
        return await coro
    finally:
        # Gracefully closes every pooled asyncpg connection this
        # invocation's own event loop opened, while that loop is still the
        # running one -- see module docstring for why this must happen
        # here, not in a task_postrun signal handler.
        await engine.dispose()


def run_celery_task(coro: Awaitable[T]) -> T:
    """The one, real replacement for calling ``asyncio.run(coro)`` directly
    from a Celery task's sync body. Every Beat-scheduled task in this
    codebase should call this instead -- see module docstring for exactly
    what it protects against and why."""
    return asyncio.run(_run_and_dispose(coro))


__all__ = ["run_celery_task"]
