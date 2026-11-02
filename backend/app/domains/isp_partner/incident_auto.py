"""SMALL-5: open an incident automatically when a router stays DOWN, resolve
it when the router stays UP.

Off unless BOTH ``ISP_INCIDENTS_ENABLED`` (INCIDENTS-1) and the ISP's own
switch (``PUT /isp/incident-auto/settings {enabled: true}``, default off) are
on.

* **Signal.** J14's own device list (``automation._device_statuses``, routers
  only): ``routers.status`` online/offline, unknown/pending skipped, and
  controller-managed rows (Omada / Aruba Instant On with no agent evidence,
  CI-INTEG's ``is_controller_managed_row``) skipped. On top of that, a venue
  that has ANY controller-managed router row is skipped entirely (its
  network is run by the vendor controller; an agent router there is not the
  whole picture), so nothing is auto-opened for controller-managed venues.
* **Debounce.** Per router, ``isp_incident_auto_routers`` keeps the observed
  status and since when. A change restarts the clock, so a flap shorter than
  ``down_minutes`` (default 10) opens nothing and one shorter than
  ``up_minutes`` (default 15) resolves nothing.
* **Open.** DOWN for ``down_minutes`` -> one incident on that router through
  ``IspIncidentsService.create`` (same affected-subscriber rule, numbering,
  audit), started at the moment it went down. At most one open
  auto-incident per router (partial unique index on ``isp_incident_autos``)
  and none while ANY open incident (manual too) is on that router.
* **Resolve.** UP for ``up_minutes`` -> ``set_status(resolved)`` with RFO
  ``auto_restored`` ("Power/link restored – auto"), resolved at the moment it
  came back. If staff resolved it first, the row is just closed
  (``auto_resolved`` false). Auto-resolved incidents never get auto-grace:
  ``auto_grace_allowed`` answers False for them (no automatic grace path
  exists today; staff can still grant grace by hand from the incident).
* **Job.** The 120 s pass, one ISP per transaction (own session each),
  idempotent: a re-run with no status change writes nothing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from .incident_auto_models import (
    IspIncidentAuto,
    IspIncidentAutoRouter,
    IspIncidentAutoSettings,
)

AUTO_RFO = "auto_restored"
AUTO_RFO_NOTE = "Power/link restored – auto"
DEFAULT_DOWN_MINUTES = 10
DEFAULT_UP_MINUTES = 15


def settings_view(row: IspIncidentAutoSettings | None) -> dict:
    return {
        "enabled": bool(row and row.enabled),
        "down_minutes": row.down_minutes if row else DEFAULT_DOWN_MINUTES,
        "up_minutes": row.up_minutes if row else DEFAULT_UP_MINUTES,
    }


async def get_settings(
    session: Any, isp_org_id: uuid.UUID
) -> IspIncidentAutoSettings | None:
    return (
        await session.execute(
            select(IspIncidentAutoSettings).where(
                IspIncidentAutoSettings.isp_organization_id == isp_org_id,
                IspIncidentAutoSettings.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


async def put_settings(session: Any, isp: Any, data: dict) -> dict:
    row = await get_settings(session, isp.isp_org_id)
    if row is None:
        row = IspIncidentAutoSettings(
            isp_organization_id=isp.isp_org_id,
            enabled=False,
            down_minutes=DEFAULT_DOWN_MINUTES,
            up_minutes=DEFAULT_UP_MINUTES,
            created_by=isp.user_id,
        )
        session.add(row)
    for k in ("enabled", "down_minutes", "up_minutes"):
        if data.get(k) is not None:
            setattr(row, k, data[k])
    row.updated_by = isp.user_id
    await session.flush()
    return settings_view(row)


async def auto_grace_allowed(session: Any, incident_id: uuid.UUID) -> bool:
    """False for an incident this job resolved (router came back by itself)."""
    row = (
        await session.execute(
            select(IspIncidentAuto).where(IspIncidentAuto.incident_id == incident_id)
        )
    ).scalar_one_or_none()
    return not (row is not None and row.auto_resolved)


async def auto_info(
    session: Any, incident_ids: list[uuid.UUID]
) -> dict[uuid.UUID, dict]:
    if not incident_ids:
        return {}
    rows = (
        await session.execute(
            select(IspIncidentAuto).where(IspIncidentAuto.incident_id.in_(incident_ids))
        )
    ).scalars()
    return {
        r.incident_id: {
            "auto": True,
            "down_since": r.down_since.isoformat(),
            "auto_resolved": r.auto_resolved,
            "auto_grace_allowed": not r.auto_resolved,
        }
        for r in rows
    }


async def _controller_venues(isp: Any, child_ids: list[uuid.UUID]) -> set[uuid.UUID]:
    """Venues with any controller-managed router row. Reads through the
    already-classified ``IspRepository.routers_for_organizations`` (no device
    work is done from it) and asks the row-aware vendor question."""
    from app.domains.router.vendor_capabilities import is_controller_managed_row

    if not child_ids:
        return set()
    rows = await isp.repository.routers_for_organizations(child_ids)
    return {r.organization_id for r in rows if is_controller_managed_row(r)}


async def run_for_isp(
    session: Any, isp: Any, *, now: datetime | None = None, audit: Any = None
) -> dict[str, int]:
    """One ISP. ``isp`` is a system context (tasks._system_ctx)."""
    from .automation import _device_statuses
    from .incidents_models import IspIncident
    from .incidents_service import IspIncidentsService

    out = {"opened": 0, "resolved": 0, "closed": 0, "skipped_controller": 0}
    st = await get_settings(session, isp.isp_org_id)
    if st is None or not st.enabled:
        return out
    now = now or datetime.now(UTC)
    svc = IspIncidentsService(session=session, audit=audit, clock=lambda: now)
    children = await isp.child_ids()
    skip_venues = await _controller_venues(isp, children)
    states = {
        s.router_id: s
        for s in (
            await session.execute(
                select(IspIncidentAutoRouter)
                .where(IspIncidentAutoRouter.isp_organization_id == isp.isp_org_id)
                .with_for_update()
            )
        ).scalars()
    }
    open_autos = {
        a.router_id: a
        for a in (
            await session.execute(
                select(IspIncidentAuto)
                .where(
                    IspIncidentAuto.isp_organization_id == isp.isp_org_id,
                    IspIncidentAuto.closed_at.is_(None),
                )
                .with_for_update()
            )
        ).scalars()
    }
    down_for = timedelta(minutes=st.down_minutes)
    up_for = timedelta(minutes=st.up_minutes)
    for kind, rid, _name, status, cid in await _device_statuses(
        session, children, False
    ):
        if kind != "router":
            continue
        if cid in skip_venues:
            out["skipped_controller"] += 1
            continue
        s = states.get(rid)
        if s is None:
            s = IspIncidentAutoRouter(
                isp_organization_id=isp.isp_org_id,
                router_id=rid,
                observed_status=status,
                observed_since=now,
            )
            session.add(s)
            states[rid] = s
        elif s.observed_status != status:
            s.observed_status, s.observed_since = status, now
        auto = open_autos.get(rid)
        if auto is not None:
            inc = await session.get(IspIncident, auto.incident_id)
            if inc is None or inc.status == "resolved":
                auto.closed_at = now  # staff resolved it by hand
                out["closed"] += 1
                continue
            if status == "up" and now - s.observed_since >= up_for:
                await svc.set_status(
                    isp,
                    inc.id,
                    {
                        "status": "resolved",
                        "rfo_reason": AUTO_RFO,
                        "rfo_note": AUTO_RFO_NOTE,
                        "resolved_at": max(s.observed_since, inc.started_at),
                        "note": (
                            "Router back up since "
                            f"{svc.local(isp, s.observed_since)}; resolved "
                            "automatically."
                        ),
                    },
                )
                auto.closed_at, auto.auto_resolved = now, True
                out["resolved"] += 1
            continue
        if status != "down" or now - s.observed_since < down_for:
            continue
        busy = (
            await session.execute(
                select(IspIncident.id)
                .where(
                    IspIncident.isp_organization_id == isp.isp_org_id,
                    IspIncident.router_id == rid,
                    IspIncident.status != "resolved",
                    IspIncident.is_deleted.is_(False),
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if busy is not None:
            continue
        async with session.begin_nested():
            d = await svc.create(
                isp,
                {
                    "scope_kind": "router",
                    "isp_router_id": rid,
                    "started_at": s.observed_since,
                    "severity": "major",
                    "note": (
                        f"Opened automatically: the router has been DOWN since "
                        f"{svc.local(isp, s.observed_since)}."
                    ),
                },
            )
            session.add(
                IspIncidentAuto(
                    isp_organization_id=isp.isp_org_id,
                    router_id=rid,
                    customer_organization_id=cid,
                    incident_id=uuid.UUID(str(d["id"])),
                    down_since=s.observed_since,
                    opened_at=now,
                )
            )
            await session.flush()
        out["opened"] += 1
    await session.flush()
    return out


async def run_incident_auto(*, now: datetime | None = None) -> dict[str, int]:
    """120 s pass hook: ISPs with the switch on, one per transaction."""
    from app.database.session import SessionLocal
    from app.domains.rbac.repository import RBACRepository

    from .dependencies import IspContext
    from .incidents_config import get_incidents_settings
    from .tasks import _own_tx, _system_ctx

    summary: dict[str, int] = {"isps": 0, "opened": 0, "resolved": 0, "closed": 0}
    if not get_incidents_settings().incidents_enabled:
        return summary
    async with SessionLocal() as session:
        isp_ids = list(
            (
                await session.execute(
                    select(IspIncidentAutoSettings.isp_organization_id).where(
                        IspIncidentAutoSettings.enabled.is_(True),
                        IspIncidentAutoSettings.is_deleted.is_(False),
                    )
                )
            ).scalars()
        )
    for isp_id in isp_ids:
        summary["isps"] += 1

        async def _one(session: Any, isp_id: uuid.UUID = isp_id) -> dict | None:
            sysctx = await _system_ctx(session, isp_id)
            if sysctx is None:
                return None
            # IncidentsService widens/narrows with dataclasses.replace, so it
            # needs a real IspContext: no actor, no confinement.
            isp = IspContext(
                isp_org_id=sysctx.isp_org_id,
                user_id=None,
                role_slug="system",
                role_id=None,
                confined_customer_ids=None,
                organization=sysctx.organization,
                profile=sysctx.profile,
                repository=sysctx.repository,
            )
            return await run_for_isp(
                session, isp, now=now, audit=RBACRepository(session)
            )

        res = await _own_tx("isp_incident_auto", _one, summary, isp=isp_id) or {}
        for k in ("opened", "resolved", "closed"):
            summary[k] += int(res.get(k, 0))
    return summary


__all__ = [
    "AUTO_RFO",
    "AUTO_RFO_NOTE",
    "auto_grace_allowed",
    "auto_info",
    "get_settings",
    "put_settings",
    "run_for_isp",
    "run_incident_auto",
    "settings_view",
]
