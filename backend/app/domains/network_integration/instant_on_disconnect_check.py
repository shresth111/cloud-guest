"""Evidence after an Instant On disconnect: what the AP's client list says.

A disconnect is a block, then a timed unblock. Whether the phone really left,
and whether it came back without signing in, was only ever knowable with the
phone in hand. So the worker reads ``clientSummary`` at a few points after the
block and logs one ``instant_on_disconnect_check`` per read.

It only reads, and it never affects the disconnect: the block and the release
do not depend on any of this. A failed read logs ``unknown``, never ``absent``.
Guest name, IP and full MAC are not logged.

Reads are bounded: four per disconnect, and a per-site hourly cap. The cap
applies to every session end rather than only an operator's, because telling
them apart would mean threading a flag through the shared session-end path, and
a sweep's end is just as useful as evidence.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import Settings, get_settings
from app.core.logging import get_logger

from . import instant_on_control as control
from .constants import TASK_INSTANT_ON_CHECK_DISCONNECTED_CLIENT

logger = get_logger(__name__)

__all__ = [
    "check_disconnected_client",
    "check_disconnected_client_task",
    "phase_plan",
    "schedule_disconnect_checks",
]

#: The fields this check reports. Names come from the portal's client model and
#: a live read; a row without one says so in ``missing_fields``.
_EXPECTED_FIELDS = (
    "status",
    "isBlocked",
    "wirelessNetworkId",
    "wirelessNetworkName",
    "connectionDurationInSeconds",
)


def phase_plan(hold_seconds: int) -> tuple[tuple[str, int], ...]:
    """Each phase and its delay in seconds after the block."""
    first = min(5, max(1, hold_seconds // 3))
    return (
        ("after_block", first),
        ("before_unblock", max(first + 1, hold_seconds - 5)),
        ("after_unblock_60s", hold_seconds + 60),
        ("after_unblock_5m", hold_seconds + 300),
    )


def _last4(mac: str) -> str:
    return mac.replace(":", "").replace("-", "")[-4:]


async def check_disconnected_client(
    session: AsyncSession | None,
    *,
    organization_id: uuid.UUID,
    router_id: uuid.UUID,
    mac: str,
    phase: str,
    seconds_since_block: int,
    settings: Settings | None = None,
) -> str:
    """One read and one log line. Returns the client state:
    ``present``, ``absent``, ``unknown``, or ``not_available``."""
    settings = settings or get_settings()
    target = await control.resolve_control_target(
        session, organization_id=organization_id, router_id=router_id, settings=settings
    )
    if target is None:
        return "not_available"
    extra: dict[str, Any] = {
        "router_id": str(router_id),
        "phase": phase,
        "seconds_since_block": seconds_since_block,
        "mac_last4": _last4(mac),
    }
    try:
        row = await control._with_client(
            target, settings, lambda client: client.get_client(target.site_id, mac)
        )
    except Exception as error:  # noqa: BLE001 -- evidence only; a failure is "unknown"
        logger.info(
            "instant_on_disconnect_check",
            extra={
                **extra,
                "client_state": "unknown",
                "error_code": getattr(error, "code", type(error).__name__),
            },
        )
        return "unknown"
    if row is None:
        logger.info(
            "instant_on_disconnect_check", extra={**extra, "client_state": "absent"}
        )
        return "absent"
    logger.info(
        "instant_on_disconnect_check",
        extra={
            **extra,
            "client_state": "present",
            "ap_status": row.get("status"),
            "ap_is_blocked": row.get("isBlocked"),
            "network_id": row.get("wirelessNetworkId"),
            "network_name": row.get("wirelessNetworkName"),
            "connection_seconds": row.get("connectionDurationInSeconds"),
            "missing_fields": [f for f in _EXPECTED_FIELDS if f not in row],
        },
    )
    return "present"


async def schedule_disconnect_checks(
    target: control.ControlTarget, mac: str, redis: Any, settings: Settings
) -> None:
    """Publish the first check, capped per site per hour. One publish with no
    broker retries, because this runs inside the disconnect's request."""
    if not settings.instant_on_disconnect_check_enabled:
        return
    key = f"instant_on:disconnect_check_count:{target.site_id}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 3600)
    if count > settings.instant_on_disconnect_check_max_per_hour:
        return
    hold = settings.instant_on_disconnect_hold_seconds
    check_disconnected_client_task.apply_async(
        kwargs={
            "organization_id": str(target.organization_id),
            "router_id": str(target.router_id),
            "mac": mac,
            "blocked_at": time.time(),
            "hold_seconds": hold,
            "index": 0,
        },
        countdown=phase_plan(hold)[0][1],
        retry=False,
    )


async def _check_async(
    *, organization_id: str, router_id: str, mac: str, phase: str, seconds: int
) -> str:
    from app.database.session import SessionLocal

    try:
        async with SessionLocal() as session:
            return await check_disconnected_client(
                session,
                organization_id=uuid.UUID(organization_id),
                router_id=uuid.UUID(router_id),
                mac=mac,
                phase=phase,
                seconds_since_block=seconds,
            )
    finally:
        await control._close_loop_redis()


@celery_app.task(name=TASK_INSTANT_ON_CHECK_DISCONNECTED_CLIENT)
def check_disconnected_client_task(
    *,
    organization_id: str,
    router_id: str,
    mac: str,
    blocked_at: float,
    hold_seconds: int,
    index: int,
) -> str:
    plan = phase_plan(hold_seconds)
    phase = plan[index][0]
    state = "unknown"
    try:
        state = run_celery_task(
            _check_async(
                organization_id=organization_id,
                router_id=router_id,
                mac=mac,
                phase=phase,
                seconds=round(time.time() - blocked_at),
            )
        )
    except Exception as error:  # noqa: BLE001 -- a crashed check must not end the chain
        logger.warning(
            "instant_on_disconnect_check_failed",
            extra={"phase": phase, "error_type": type(error).__name__},
        )
    if state != "not_available" and index + 1 < len(plan):
        check_disconnected_client_task.apply_async(
            kwargs={
                "organization_id": organization_id,
                "router_id": router_id,
                "mac": mac,
                "blocked_at": blocked_at,
                "hold_seconds": hold_seconds,
                "index": index + 1,
            },
            countdown=max(1, round(blocked_at + plan[index + 1][1] - time.time())),
            retry=False,
        )
    return state
