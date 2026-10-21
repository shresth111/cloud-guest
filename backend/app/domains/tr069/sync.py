"""Sync-on-read of an ISP's CPEs from GenieACS (API_CONTRACT §6.2, §6.4).

Ownership comes from one fact only: the device's
``ManagementServer.Username`` names one of this ISP's credentials. Usernames
are globally unique, so two ISPs can never both claim a device.

* first sight: ``customer_organization_id`` comes from the credential
  (customer credential -> that customer; ISP credential -> unassigned);
* an existing row's assignment is **never** overwritten (manual or not);
* a device whose username matches no credential of this ISP is never
  imported;
* a row of this ISP whose device no longer answers to its credentials is
  soft-deleted; if another ISP's credential now names it, that ISP's next
  sync takes the row over as unassigned and writes ``tr069_device_moved``.

Tags ``isp:<id>`` / ``cust:<id>`` are posted best-effort, for ops only.
"""

from __future__ import annotations

import contextlib
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from . import params as P
from .config import get_tr069_settings
from .exceptions import Tr069AcsUnavailableError
from .models import Tr069AcsCredential, Tr069Device, Tr069Task

logger = logging.getLogger(__name__)

TASK_EXPIRY = timedelta(hours=24)
AUDIT_DEVICE_MOVED = "tr069_device_moved"

#: In-process fallback throttle (per worker) when Redis is unavailable.
_last_sync: dict[uuid.UUID, float] = {}


def _parse_time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def username_query(usernames: list[str]) -> dict[str, Any]:
    clauses: list[dict[str, Any]] = []
    for name in usernames:
        clauses.append({"Device.ManagementServer.Username._value": name})
        clauses.append({"InternetGatewayDevice.ManagementServer.Username._value": name})
    return {"$or": clauses}


def apply_facts(row: Tr069Device, doc: dict[str, Any]) -> None:
    ident = doc.get("_deviceId") or {}
    row.oui = (ident.get("_OUI") or None) and str(ident["_OUI"])[:6]
    row.product_class = ident.get("_ProductClass") or row.product_class
    row.serial_number = ident.get("_SerialNumber") or P.scalar(doc, "serial_number")
    row.manufacturer = P.scalar(doc, "manufacturer") or ident.get("_Manufacturer")
    row.model = P.scalar(doc, "model") or row.product_class
    row.software_version = P.scalar(doc, "software_version")
    row.data_model = P.data_model(doc)
    row.wan_ip = P.first(doc, *P.WAN_IP_PATHS)
    informed = _parse_time(doc.get("_lastInform"))
    if informed is not None:
        row.last_inform_at = informed
    interval = P.scalar(doc, "periodic_inform_interval_s")
    with contextlib.suppress(TypeError, ValueError):
        row.periodic_inform_interval_s = int(interval) if interval is not None else None
    row.params_cache = P.curate(doc)
    row.params_refreshed_at = datetime.now(UTC)


class Tr069SyncService:
    def __init__(self, session: Any, nbi: Any, *, audit: Any = None) -> None:
        self.session = session
        self.nbi = nbi
        self.audit = audit

    async def _credentials(self, isp_org_id: uuid.UUID) -> list[Tr069AcsCredential]:
        rows = await self.session.execute(
            select(Tr069AcsCredential).where(
                Tr069AcsCredential.isp_organization_id == isp_org_id,
                Tr069AcsCredential.is_deleted.is_(False),
            )
        )
        return list(rows.scalars().all())

    async def _rows_by_genie_id(self, ids: list[str]) -> dict[str, Tr069Device]:
        if not ids:
            return {}
        rows = await self.session.execute(
            select(Tr069Device).where(Tr069Device.genieacs_device_id.in_(ids))
        )
        return {r.genieacs_device_id: r for r in rows.scalars().all()}

    async def sync_isp(self, isp_org_id: uuid.UUID) -> dict[str, int]:
        stats = {"imported": 0, "updated": 0, "moved_in": 0, "removed": 0}
        creds = await self._credentials(isp_org_id)
        if not creds:
            return stats
        by_username = {c.username: c for c in creds}
        docs = await self.nbi.query_devices(
            username_query(sorted(by_username)), P.projection()
        )
        seen: set[str] = set()
        existing = await self._rows_by_genie_id(
            [str(d.get("_id")) for d in docs if d.get("_id")]
        )
        now = datetime.now(UTC)
        for doc in docs:
            genie_id = doc.get("_id")
            if not genie_id:
                continue
            cred = by_username.get(str(P.scalar(doc, "acs_username") or ""))
            if cred is None:
                continue  # never import a device that names no credential of ours
            seen.add(genie_id)
            row = existing.get(genie_id)
            if row is None:
                row = Tr069Device(
                    isp_organization_id=isp_org_id,
                    customer_organization_id=cred.customer_organization_id,
                    genieacs_device_id=genie_id,
                    credential_id=cred.id,
                    first_seen_at=_parse_time(doc.get("_registered")) or now,
                    params_cache={},
                )
                apply_facts(row, doc)
                self.session.add(row)
                stats["imported"] += 1
            elif row.isp_organization_id != isp_org_id:
                old_isp = row.isp_organization_id
                row.isp_organization_id = isp_org_id
                row.customer_organization_id = cred.customer_organization_id
                row.location_id = None
                row.router_id = None
                row.label = None
                row.credential_id = cred.id
                row.restore_deleted()
                apply_facts(row, doc)
                stats["moved_in"] += 1
                await self._audit_move(row, old_isp, isp_org_id)
            else:
                if row.is_deleted:
                    row.restore_deleted()
                    row.customer_organization_id = cred.customer_organization_id
                row.credential_id = cred.id
                apply_facts(row, doc)
                stats["updated"] += 1
            await self._tag(genie_id, isp_org_id, row.customer_organization_id)

        mine = await self.session.execute(
            select(Tr069Device).where(
                Tr069Device.isp_organization_id == isp_org_id,
                Tr069Device.is_deleted.is_(False),
            )
        )
        for row in mine.scalars().all():
            if row.genieacs_device_id not in seen:
                row.mark_deleted()
                stats["removed"] += 1
        await self.session.flush()
        await self.reconcile_tasks(isp_org_id)
        return stats

    async def _tag(
        self, genie_id: str, isp_org_id: uuid.UUID, customer_id: uuid.UUID | None
    ) -> None:
        try:
            await self.nbi.add_tag(genie_id, f"isp:{isp_org_id}")
            if customer_id is not None:
                await self.nbi.add_tag(genie_id, f"cust:{customer_id}")
        except Exception:  # noqa: BLE001 -- tags are ops-only, best effort
            logger.info("tr069_tag_failed", extra={"device": genie_id})

    async def _audit_move(
        self, row: Tr069Device, old_isp: uuid.UUID, new_isp: uuid.UUID
    ) -> None:
        if self.audit is None:
            return
        await self.audit.create_audit_log_entry(
            actor_user_id=None,
            action=AUDIT_DEVICE_MOVED,
            entity_type="tr069_device",
            entity_id=row.id,
            description="TR-069 device moved to another ISP by credential",
            event_metadata={
                "from_isp_organization_id": str(old_isp),
                "to_isp_organization_id": str(new_isp),
                "genieacs_device_id": row.genieacs_device_id,
            },
            organization_id=new_isp,
            location_id=None,
        )

    async def reconcile_tasks(self, isp_org_id: uuid.UUID) -> None:
        """Queued tasks: consumed -> done (and refresh params), fault ->
        fault, older than 24 h -> expired (and deleted from GenieACS)."""
        rows = await self.session.execute(
            select(Tr069Task, Tr069Device)
            .join(Tr069Device, Tr069Device.id == Tr069Task.device_id)
            .where(
                Tr069Task.isp_organization_id == isp_org_id,
                Tr069Task.status == "queued",
            )
        )
        now = datetime.now(UTC)
        for task, device in rows.all():
            if task.created_at and now - task.created_at > TASK_EXPIRY:
                task.status = "expired"
                task.completed_at = now
                if task.genieacs_task_id:
                    with contextlib.suppress(Tr069AcsUnavailableError):
                        await self.nbi.delete_task(task.genieacs_task_id)
                continue
            if not task.genieacs_task_id:
                continue
            faults = await self.nbi.get_faults({"device": device.genieacs_device_id})
            if faults:
                task.status = "fault"
                task.fault = {
                    "code": str(faults[0].get("code") or ""),
                    "message": str(faults[0].get("message") or "")[:500],
                }
                task.completed_at = now
                continue
            pending = await self.nbi.get_tasks({"_id": task.genieacs_task_id})
            if not pending:
                task.status = "done"
                task.completed_at = now
                if task.kind == "refresh_params":
                    doc = await self.nbi.get_device(device.genieacs_device_id)
                    if doc:
                        apply_facts(device, doc)
        await self.session.flush()


async def _throttled(isp_org_id: uuid.UUID) -> bool:
    """True when this ISP synced less than TR069_SYNC_MIN_INTERVAL_S ago or
    another worker holds the lock."""
    interval = get_tr069_settings().sync_min_interval_s
    try:
        from app.database.redis import redis_client as redis

        acquired = await redis.set(
            f"tr069:sync:{isp_org_id}", "1", nx=True, ex=max(1, interval)
        )
        return not acquired
    except Exception:  # noqa: BLE001 -- fall back to a per-process throttle
        last = _last_sync.get(isp_org_id, 0.0)
        if time.monotonic() - last < interval:
            return True
        _last_sync[isp_org_id] = time.monotonic()
        return False


async def sync_on_read(isp: Any, *, nbi: Any = None, force: bool = False) -> None:
    """Called by the devices list, overview and reports. Never fails the
    read: an unreachable ACS leaves the cached inventory in place."""
    if not get_tr069_settings().enabled:
        return
    if not force and await _throttled(isp.isp_org_id):
        return
    from app.domains.rbac.repository import RBACRepository

    from .nbi_client import NbiClient

    session = isp.repository.session
    service = Tr069SyncService(
        session, nbi or NbiClient(), audit=RBACRepository(session)
    )
    try:
        async with session.begin_nested():
            await service.sync_isp(isp.isp_org_id)
    except Tr069AcsUnavailableError:
        logger.warning("tr069_sync_acs_unavailable", extra={"isp": str(isp.isp_org_id)})
