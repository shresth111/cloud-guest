"""DEFAULT-LOGS (2026-11-11, founder "Logging default ON kar do"): the ISP's
IP-logs choice for a router, recorded before the router can send anything.

The partner requirement: "Provide an enable/disable option during router
configuration. Logging enabled by default, with an option to control it."

Why a side table: ``POST /isp/routers/{isp_router_id}/ip-logs/enable`` writes
the two intent rows (``router_remote_logging``, ``router_traffic_flow_export``)
and both need the router's management-connection address, which does not
exist until the setup script is generated. So the Add router switch (and the
IP-logs switch on a router that has no management connection yet) records
the CHOICE here, one row per router:

* ``wanted = true``  -- IP logs are folded into the router's setup script on
  the next Generate, and Generate then writes the intent rows (the same
  enable the "Turn on" button calls).
* ``wanted = false`` -- the ISP switched them off; the setup script has no
  IP-logs lines.
* no row             -- a router added before this change. Nothing is
  switched on silently; the console shows a "Turn on IP logs" prompt.

Only written while ``ISP_IPLOGS_SELFSERVE_ENABLED`` is on. Partner routers
only: the Master console never reads or writes this table.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Boolean, ForeignKey, String, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = [
    "IspRouterIpLogsDefault",
    "ip_logs_wanted",
    "record_add_router_choice",
    "record_ip_logs_choice",
]

#: Where a choice came from (audit / support only).
SOURCE_ADD_ROUTER = "add_router"
SOURCE_SWITCH = "switch"


class IspRouterIpLogsDefault(BaseModel):
    __tablename__ = "isp_router_iplogs_defaults"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    wanted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)


async def ip_logs_wanted(db: Any, router_ids: list[uuid.UUID]) -> dict[uuid.UUID, bool]:
    """``{router_id: wanted}`` for the routers that have a recorded choice.
    Callers pass routers already resolved in the caller's scope."""
    if not router_ids:
        return {}
    rows = (
        await db.execute(
            select(
                IspRouterIpLogsDefault.router_id, IspRouterIpLogsDefault.wanted
            ).where(
                IspRouterIpLogsDefault.router_id.in_(router_ids),
                IspRouterIpLogsDefault.is_deleted.is_(False),
            )
        )
    ).all()
    return {rid: bool(w) for rid, w in rows}


async def record_ip_logs_choice(
    db: Any,
    *,
    isp_org_id: uuid.UUID,
    router_id: uuid.UUID,
    wanted: bool,
    actor: uuid.UUID | None,
    source: str,
) -> None:
    """Upsert the one row for ``router_id`` (flushed, not committed)."""
    row = (
        await db.execute(
            select(IspRouterIpLogsDefault).where(
                IspRouterIpLogsDefault.router_id == router_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = IspRouterIpLogsDefault(
            router_id=router_id,
            isp_organization_id=isp_org_id,
            created_by=actor,
        )
        db.add(row)
    row.is_deleted, row.deleted_at = False, None
    row.wanted = bool(wanted)
    row.source = source
    row.updated_by = actor
    await db.flush()


async def record_add_router_choice(
    db: Any, isp: Any, data: dict, ip_logs: bool | None
) -> dict:
    """Called by the two partner Add router routes right after the router is
    created (same transaction). ``ip_logs`` not sent, or the IP-logs flag
    off: nothing is written and ``data`` is returned unchanged, so the
    response is byte-identical to before."""
    if ip_logs is None:
        return data
    from .iplogs_router import get_iplogs_settings

    if not get_iplogs_settings().iplogs_selfserve_enabled:
        return data
    await record_ip_logs_choice(
        db,
        isp_org_id=isp.isp_org_id,
        router_id=uuid.UUID(str(data["id"])),
        wanted=bool(ip_logs),
        actor=isp.user_id,
        source=SOURCE_ADD_ROUTER,
    )
    return {**data, "ip_logs_wanted": bool(ip_logs)}
