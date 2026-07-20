"""Celery task definitions for the Guest domain (Guest Session Engine,
Phase 1).

Wraps ``service.enforce_session_timeouts`` -- a status-transition sweep that
already existed (as ``GuestService.enforce_timeouts``) and was already
tested, but was never actually invoked by anything before this module. See
``app.core.celery_app``'s module docstring for why: this codebase's
``GuestSession``/timeout detection was, until now, a callable mechanism
with no scheduler wired to call it periodically -- the exact same "real
logic, missing the cron" gap this file closes.

## The async bridge, concretely

Mirrors ``app.domains.analytics.tasks``'s identical bridge pattern:
``run_session_timeout_sweep`` is a plain, synchronous function (what
Celery's worker expects), which delegates immediately to a module-level
**async** function (``_run_session_timeout_sweep_async``) via
``asyncio.run(...)``. That async function opens a fresh ``AsyncSession``
(``app.database.session.SessionLocal``), builds a real ``GuestRepository``,
and calls the module-level ``enforce_session_timeouts`` function directly --
**not** a full ``GuestService`` (which would additionally require real
``OtpService``/``VoucherService``/``CaptivePortalService``/``RouterService``
instances this task never needs, since the sweep only ever reads/writes
``GuestSession`` rows through the repository). See ``service
.enforce_session_timeouts``'s own docstring for why that function was
pulled out to module scope specifically to make this possible.

Keeping the async bridge function at module scope (rather than inlining it
into the ``@celery_app.task`` body) is what keeps this file testable
without a running Celery worker or broker -- the same "monkeypatch the
bridge, call the plain task function directly" contract
``tests/unit/test_guest.py``'s task-bridge test uses, mirroring
``tests/unit/test_analytics.py``'s identical pattern for
``analytics.tasks``.
"""

from __future__ import annotations

import asyncio

from app.core.celery_app import celery_app
from app.core.logging import get_logger
from app.database.session import SessionLocal

from .constants import TASK_RUN_SESSION_TIMEOUT_SWEEP
from .repository import GuestRepository
from .service import enforce_session_timeouts

logger = get_logger(__name__)


async def _run_session_timeout_sweep_async() -> int:
    """The actual async work behind ``run_session_timeout_sweep`` -- a
    fresh session per task run (never a session shared across separate task
    invocations/worker ticks, mirroring ``analytics.tasks``'s identical
    per-run session discipline). Returns the number of sessions flipped to
    ``EXPIRED``."""
    async with SessionLocal() as session:
        try:
            repository = GuestRepository(session)
            expired = await enforce_session_timeouts(repository)
            await session.commit()
            return len(expired)
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_SESSION_TIMEOUT_SWEEP)
def run_session_timeout_sweep() -> dict[str, object]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- runs every
    ``constants.SESSION_TIMEOUT_SWEEP_INTERVAL_SECONDS``). Flips every
    ``ACTIVE`` ``GuestSession`` whose inactivity has exceeded its own
    ``session_timeout_minutes`` to ``EXPIRED``, exactly what
    ``GuestService.enforce_timeouts`` has always computed -- this task is
    what makes that computation actually run on a schedule instead of only
    ever being reachable by an explicit caller (e.g. a test, or a future
    manual admin trigger)."""
    expired_count = asyncio.run(_run_session_timeout_sweep_async())
    logger.info(
        "guest_task_run_session_timeout_sweep_completed",
        extra={"expired_count": expired_count},
    )
    return {"expired_count": expired_count}


__all__ = ["run_session_timeout_sweep"]
