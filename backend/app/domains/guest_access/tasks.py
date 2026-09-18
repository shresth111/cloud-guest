"""The half of a controller-side block that nobody clicks: letting it go.

## What this exists to prevent

A ``BLOCKLIST`` rule may carry an ``expires_at`` -- ``validators
.validate_rule_expiry`` allows one on every rule type and only *requires*
one for ``TEMPORARY`` -- and expiry on this platform is evaluated lazily, at
read time. ``check_access`` simply stops matching the row. Nothing fires, no
sweep runs, and nothing needs to: a rule that has lapsed stops refusing the
guest at their very next sign-in.

That is exactly right for a rule and exactly wrong for a controller block,
because a controller block is not a row in this database. It is durable state
on a customer's own hardware, keyed by MAC on the known-client record, and
**nothing on the controller ever removes it**. So a venue owner who blocks
somebody "until Sunday" and a venue owner who blocks them forever produce the
same permanent result on the device, and the difference is invisible from
both sides: the rule looks lapsed here, and the controller offers no readable
list of blocked clients through the connection this platform holds (measured
-- see ``network_integration.providers.omada.OmadaProvider
._BLOCKED_LIST_REASON`` and CAPABILITY-MATRIX §4.4).

The same reasoning covers the two operator paths that already release
inline. ``GuestAccessService.deactivate_guest_rule`` and ``delete_guest_rule``
both ask the controller before the rule stops applying -- but a controller
that was unreachable at that moment leaves the row uncleared on purpose, and
this sweep is the thing that comes back for it. Without it, "the controller
was down when I unblocked them" is a permanently blocked customer device.

## What it deliberately does not do

It does not decide who should be blocked, it never blocks anything, and it
reads no rule the operator has not already stopped applying. Its entire
input is ``guest_access_controller_blocks`` rows that are still open for a
rule that is expired, deactivated or deleted, and its entire output is an
unblock per row plus a ``cleared_at``.

It is not a substitute for the inline release either. Releasing at the moment
the operator asks is what makes an unblock feel like an unblock; this is the
retry behind it.

## Failure isolation, and why a failure is not an error here

One venue's unreachable controller must not stop the other venues' releases,
so every row is attempted independently and a failure is recorded on that row
and counted. The row stays open, so the next tick finds it again -- which is
the correct behaviour rather than a degraded one, because the controller's
own unblock is idempotent (measured: a second unblock returns ``errorCode 0``,
CAPABILITY-MATRIX §4.2).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.database.session import SessionLocal
from app.domains.guest.constants import GuestSessionStatus
from app.domains.guest.repository import GuestRepository
from app.domains.location.repository import (
    LocationCodeCounterRepository,
    LocationRepository,
)
from app.domains.location.service import LocationService
from app.domains.organization.repository import OrganizationRepository
from app.domains.organization.service import OrganizationService
from app.domains.rbac.repository import RBACRepository
from app.domains.router.repository import RouterRepository
from app.domains.router.service import RouterService

from .constants import (
    CONTROLLER_BLOCK_RELEASE_MAX_PER_RUN,
    TASK_RUN_CONTROLLER_BLOCK_RELEASE_SWEEP,
)
from .enforcement import BlocklistEnforcer
from .repository import GuestAccessRepository

logger = logging.getLogger(__name__)


def _build_router_service(session) -> RouterService:  # noqa: ANN001
    """The same graph ``router.dependencies.get_router_service`` wires in a
    request, assembled by hand because a Celery worker has no FastAPI
    dependency resolution -- identical to
    ``connected_devices.tasks._build_router_service`` and for the identical
    reason.

    This sweep never reaches it: releasing a block touches the controller
    hook and nothing else. It is built anyway, so the enforcer this task
    holds is the *same shape* as the one the request path holds. An enforcer
    assembled differently on the schedule than in the API is precisely how a
    capability comes to work when a human clicks it and do nothing when
    nobody does.
    """
    organization_service = OrganizationService(OrganizationRepository(session))
    location_service = LocationService(
        LocationRepository(session),
        organization_service,
        location_code_counter=LocationCodeCounterRepository(session),
    )
    return RouterService(
        RouterRepository(session),
        location_service,
        organization_service,
        audit_writer=RBACRepository(session),
    )


@dataclass(frozen=True, slots=True)
class ControllerBlockReleaseSummary:
    """Counted, never inferred.

    ``released`` is rows a controller confirmed it had cleared. ``failed``
    is rows it did not, which stay open and are retried next tick. The two
    never add up to more than ``considered``, and ``released`` is never
    incremented on a guess.
    """

    considered: int
    released: int
    failed: int


async def _run_controller_block_release_async() -> ControllerBlockReleaseSummary:
    async with SessionLocal() as session:
        try:
            from app.domains.network_integration.client_hooks import (  # noqa: PLC0415
                build_controller_device_blocker,
            )

            repository = GuestAccessRepository(session)
            # Built the way the request path builds it (see
            # ``dependencies.get_block_enforcer``), because a sweep holding
            # a differently-shaped enforcer is how a capability ends up
            # working in the API and doing nothing on the schedule.
            enforcer = BlocklistEnforcer(
                session_lookup=GuestRepository(session),
                router_lookup=_build_router_service(session),
                terminated_session_status=GuestSessionStatus.TERMINATED.value,
                controller_terminator=None,
                device_blocker=build_controller_device_blocker(session),
            )
            now = datetime.now(UTC)
            open_blocks = (
                await repository.list_open_controller_blocks_for_expired_rules(
                    now=now, limit=CONTROLLER_BLOCK_RELEASE_MAX_PER_RUN
                )
            )
            released = 0
            failed = 0
            for block, outcome in await enforcer.release_devices(open_blocks):
                await repository.update_controller_block(
                    block,  # type: ignore[arg-type]
                    {
                        "cleared_at": now if outcome.released else None,
                        "release_error": (
                            None if outcome.released else outcome.error_message
                        ),
                    },
                )
                if outcome.released:
                    released += 1
                else:
                    failed += 1
            await session.commit()
            return ControllerBlockReleaseSummary(
                considered=len(open_blocks), released=released, failed=failed
            )
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_CONTROLLER_BLOCK_RELEASE_SWEEP)
def run_controller_block_release_sweep() -> dict[str, int]:
    """Beat-scheduled periodic task -- see ``app.core.celery_app``'s
    ``beat_schedule``.

    Asks each venue's controller to release the device blocks this platform
    placed for rules that have since expired, been deactivated or been
    deleted, and clears the stored row once the controller confirms it."""
    summary = run_celery_task(_run_controller_block_release_async())
    result = {
        "considered": summary.considered,
        "released": summary.released,
        "failed": summary.failed,
    }
    logger.info("guest_access_controller_block_release_sweep_completed", extra=result)
    return result
