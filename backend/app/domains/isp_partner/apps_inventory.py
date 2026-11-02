"""J16 light inventory: serialised CPE/ONT/router stock.

States: ``in_stock -> assigned -> returned -> in_stock`` (re-issue) and
``faulty`` / ``retired`` from any non-retired state. Assigning needs a
customer of this ISP (optionally a subscriber of that customer); every move
writes an ``isp_inventory_movements`` row. Stock in the store (not with any
customer) is ISP-wide; a confined staff member sees store stock plus units
at the customers they cover.

CSV import: header ``serial,sku[,mac][,note]``; one unit per row, all
``in_stock``. Duplicate serials (in the file or already held) are reported
per row and skipped; the rest are imported.
"""

from __future__ import annotations

import csv
import io
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select

from .apps_common import (
    IspAppsConflictError,
    IspAppsInvalidError,
    IspAppsNotFoundError,
    UnitState,
    org_names,
    resolve_subscriber,
)
from .apps_models import IspInventoryItem, IspInventoryMovement, IspInventoryUnit
from .scoping import IspScope

UNIT_TRANSITIONS: dict[str, frozenset[str]] = {
    UnitState.IN_STOCK: frozenset(
        {UnitState.ASSIGNED, UnitState.FAULTY, UnitState.RETIRED}
    ),
    UnitState.ASSIGNED: frozenset({UnitState.RETURNED, UnitState.FAULTY}),
    UnitState.RETURNED: frozenset(
        {UnitState.IN_STOCK, UnitState.FAULTY, UnitState.RETIRED}
    ),
    UnitState.FAULTY: frozenset({UnitState.IN_STOCK, UnitState.RETIRED}),
    UnitState.RETIRED: frozenset(),
}

MAX_IMPORT_ROWS = 2000
_MAC_RE = re.compile(r"^[0-9A-F]{2}([:-][0-9A-F]{2}){5}$")


def _now() -> datetime:
    return datetime.now(UTC)


def normalise_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    m = mac.strip().upper().replace("-", ":")
    if not _MAC_RE.match(m):
        raise IspAppsInvalidError(f"Not a MAC address: {mac}", reason="ISP_MAC_INVALID")
    return m


def check_unit_transition(current: str, target: str) -> None:
    if target not in UNIT_TRANSITIONS.get(current, frozenset()):
        raise IspAppsInvalidError(
            f"A {current} unit cannot move to {target}", reason="ISP_STATUS_CHANGED"
        )


def parse_import(text: str) -> tuple[list[dict], list[dict]]:
    """Return ``(rows, errors)``. Rows are ``{line, serial, sku, mac, note}``."""
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    fields = {f.strip().lower() for f in (reader.fieldnames or [])}
    if not {"serial", "sku"} <= fields:
        raise IspAppsInvalidError("The CSV needs the columns serial and sku")
    rows: list[dict] = []
    errors: list[dict] = []
    seen: set[str] = set()
    for n, raw in enumerate(reader, start=2):
        if n - 1 > MAX_IMPORT_ROWS:
            errors.append(
                {
                    "line": n,
                    "error": f"over {MAX_IMPORT_ROWS} rows; the rest were not read",
                }
            )
            break
        r = {k.strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        serial, sku = r.get("serial", ""), r.get("sku", "")
        if not serial and not sku:
            continue
        if not serial or not sku:
            errors.append({"line": n, "error": "serial and sku are required"})
            continue
        if len(serial) > 64:
            errors.append({"line": n, "error": "serial is longer than 64 characters"})
            continue
        key = serial.upper()
        if key in seen:
            errors.append(
                {"line": n, "serial": serial, "error": "duplicate serial in this file"}
            )
            continue
        try:
            mac = normalise_mac(r.get("mac"))
        except IspAppsInvalidError as exc:
            errors.append(
                {
                    "line": n,
                    "serial": serial,
                    "error": str(exc.args[0] if exc.args else exc),
                }
            )
            continue
        seen.add(key)
        rows.append(
            {
                "line": n,
                "serial": serial,
                "sku": sku,
                "mac": mac,
                "note": r.get("note") or None,
            }
        )
    return rows, errors


class InventoryService:
    def __init__(self, session: Any) -> None:
        self.session = session

    # -- items ---------------------------------------------------------------
    @staticmethod
    def item_view(i: Any, counts: dict[str, int] | None = None) -> dict:
        return {
            "id": i.id,
            "name": i.name,
            "sku": i.sku,
            "category": i.category,
            "notes": i.notes,
            "counts": counts or {s.value: 0 for s in UnitState},
        }

    async def _item(self, isp: Any, item_id: uuid.UUID) -> IspInventoryItem:
        i = await self.session.get(IspInventoryItem, item_id)
        if i is None or i.is_deleted or i.isp_organization_id != isp.isp_org_id:
            raise IspAppsNotFoundError("Item not found")
        return i

    async def _item_by_sku(self, isp: Any, sku: str) -> IspInventoryItem | None:
        return (
            await self.session.execute(
                select(IspInventoryItem).where(
                    IspInventoryItem.isp_organization_id == isp.isp_org_id,
                    IspInventoryItem.is_deleted.is_(False),
                    func.upper(IspInventoryItem.sku) == sku.upper(),
                )
            )
        ).scalar_one_or_none()

    async def create_item(self, isp: Any, data: dict) -> dict:
        if await self._item_by_sku(isp, data["sku"]):
            raise IspAppsConflictError("An item with this SKU exists")
        i = IspInventoryItem(isp_organization_id=isp.isp_org_id, **data)
        self.session.add(i)
        await self.session.flush()
        return self.item_view(i)

    async def update_item(self, isp: Any, item_id: uuid.UUID, data: dict) -> dict:
        i = await self._item(isp, item_id)
        # P3-SWEEP: an explicit null on a required column used to reach the
        # flush as a NOT NULL violation (500); refuse it as a 422 instead.
        for k in ("name", "sku", "category"):
            if k in data and data[k] is None:
                raise IspAppsInvalidError(f"The item {k} cannot be empty")
        if "sku" in data:
            other = await self._item_by_sku(isp, data["sku"])
            if other is not None and other.id != i.id:
                raise IspAppsConflictError("An item with this SKU exists")
        for k, v in data.items():
            setattr(i, k, v)
        await self.session.flush()
        return self.item_view(i)

    async def list_items(self, isp: Any) -> list[dict]:
        items = (
            (
                await self.session.execute(
                    select(IspInventoryItem)
                    .where(
                        IspInventoryItem.isp_organization_id == isp.isp_org_id,
                        IspInventoryItem.is_deleted.is_(False),
                    )
                    .order_by(IspInventoryItem.name)
                )
            )
            .scalars()
            .all()
        )
        counts: dict[uuid.UUID, dict[str, int]] = {
            i.id: {s.value: 0 for s in UnitState} for i in items
        }
        if items:
            unit_conds = await self._unit_visibility(isp)
            rows = await self.session.execute(
                select(IspInventoryUnit.item_id, IspInventoryUnit.state, func.count())
                .where(IspInventoryUnit.item_id.in_(list(counts)), *unit_conds)
                .group_by(IspInventoryUnit.item_id, IspInventoryUnit.state)
            )
            for item_id, state, n in rows.all():
                counts[item_id][state] = int(n)
        return [self.item_view(i, counts[i.id]) for i in items]

    # -- units ---------------------------------------------------------------
    async def _unit_visibility(self, isp: Any) -> list[Any]:
        conds: list[Any] = [
            IspInventoryUnit.isp_organization_id == isp.isp_org_id,
            IspInventoryUnit.is_deleted.is_(False),
        ]
        if isp.confined_customer_ids is not None:
            customers = await isp.child_ids()
            conds.append(
                or_(
                    IspInventoryUnit.customer_organization_id.is_(None),
                    IspInventoryUnit.customer_organization_id.in_(customers),
                )
            )
        return conds

    async def _unit(self, isp: Any, unit_id: uuid.UUID) -> IspInventoryUnit:
        u = await self.session.get(IspInventoryUnit, unit_id)
        if u is None or u.is_deleted or u.isp_organization_id != isp.isp_org_id:
            raise IspAppsNotFoundError("Unit not found")
        if u.customer_organization_id is not None:
            try:
                await IspScope.assert_customer(isp, u.customer_organization_id)
            except Exception:  # noqa: BLE001
                raise IspAppsNotFoundError("Unit not found") from None
        return u

    async def _serial_taken(self, isp: Any, serials: list[str]) -> set[str]:
        if not serials:
            return set()
        rows = await self.session.execute(
            select(func.upper(IspInventoryUnit.serial)).where(
                IspInventoryUnit.isp_organization_id == isp.isp_org_id,
                IspInventoryUnit.is_deleted.is_(False),
                func.upper(IspInventoryUnit.serial).in_([s.upper() for s in serials]),
            )
        )
        return {r for (r,) in rows.all()}

    def _move(
        self,
        u: Any,
        frm: str | None,
        to: str,
        actor: uuid.UUID,
        note: str | None = None,
    ) -> None:
        self.session.add(
            IspInventoryMovement(
                unit_id=u.id,
                from_state=frm,
                to_state=to,
                customer_organization_id=u.customer_organization_id,
                subscriber_id=u.subscriber_id,
                note=note,
                actor_user_id=actor,
                at=_now(),
            )
        )

    async def add_unit(self, isp: Any, data: dict) -> dict:
        item = await self._item(isp, data["item_id"])
        if await self._serial_taken(isp, [data["serial"]]):
            raise IspAppsConflictError("A unit with this serial exists")
        u = IspInventoryUnit(
            isp_organization_id=isp.isp_org_id,
            item_id=item.id,
            serial=data["serial"],
            mac=normalise_mac(data.get("mac")),
            state=UnitState.IN_STOCK.value,
            state_changed_at=_now(),
            note=data.get("note"),
        )
        self.session.add(u)
        await self.session.flush()
        self._move(u, None, UnitState.IN_STOCK, isp.user_id, "stock in")
        await self.session.flush()
        return (await self.unit_views([u]))[0]

    async def import_csv(self, isp: Any, text: str) -> dict:
        rows, errors = parse_import(text)
        taken = await self._serial_taken(isp, [r["serial"] for r in rows])
        items: dict[str, IspInventoryItem | None] = {}
        created = 0
        for r in rows:
            if r["serial"].upper() in taken:
                errors.append(
                    {
                        "line": r["line"],
                        "serial": r["serial"],
                        "error": "serial already in stock records",
                    }
                )
                continue
            key = r["sku"].upper()
            if key not in items:
                items[key] = await self._item_by_sku(isp, r["sku"])
            item = items[key]
            if item is None:
                errors.append(
                    {
                        "line": r["line"],
                        "serial": r["serial"],
                        "error": f"unknown SKU {r['sku']}",
                    }
                )
                continue
            u = IspInventoryUnit(
                isp_organization_id=isp.isp_org_id,
                item_id=item.id,
                serial=r["serial"],
                mac=r["mac"],
                state=UnitState.IN_STOCK.value,
                state_changed_at=_now(),
                note=r["note"],
            )
            self.session.add(u)
            await self.session.flush()
            self._move(u, None, UnitState.IN_STOCK, isp.user_id, "CSV import")
            created += 1
        await self.session.flush()
        errors.sort(key=lambda e: e["line"])
        return {"created": created, "skipped": len(errors), "errors": errors}

    async def move_unit(self, isp: Any, unit_id: uuid.UUID, data: dict) -> dict:
        u = await self._unit(isp, unit_id)
        target = data["state"]
        check_unit_transition(u.state, target)
        before = u.state
        if target == UnitState.ASSIGNED:
            customer_id = data.get("isp_customer_id")
            if customer_id is None:
                raise IspAppsInvalidError("Pick the customer this unit goes to")
            await IspScope.assert_customer(isp, customer_id)
            if data.get("subscriber_id"):
                await resolve_subscriber(
                    isp, self.session, data["subscriber_id"], customer_id=customer_id
                )
            u.customer_organization_id = customer_id
            u.subscriber_id = data.get("subscriber_id")
        self._move(u, before, target, isp.user_id, data.get("note"))
        if target in (UnitState.RETURNED, UnitState.IN_STOCK, UnitState.RETIRED):
            # back in the store: it no longer belongs to a customer
            u.customer_organization_id = None
            u.subscriber_id = None
        u.state = target
        u.state_changed_at = _now()
        if data.get("note"):
            u.note = data["note"]
        await self.session.flush()
        return (await self.unit_views([u]))[0]

    async def list_units(
        self,
        isp: Any,
        *,
        item_id: uuid.UUID | None,
        state: str | None,
        isp_customer_id: uuid.UUID | None,
        subscriber_id: uuid.UUID | None,
        search: str | None,
        page: int,
        page_size: int,
        location_id: uuid.UUID | None = None,
    ) -> tuple[list[dict], int]:
        conds = await self._unit_visibility(isp)
        if location_id is not None:  # APPS-2 stock location
            from .apps2_models import IspInventoryUnitMeta

            conds.append(
                IspInventoryUnit.id.in_(
                    select(IspInventoryUnitMeta.unit_id).where(
                        IspInventoryUnitMeta.location_id == location_id,
                        IspInventoryUnitMeta.is_deleted.is_(False),
                    )
                )
            )
        if item_id is not None:
            conds.append(IspInventoryUnit.item_id == item_id)
        if state:
            conds.append(IspInventoryUnit.state == state)
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            conds.append(IspInventoryUnit.customer_organization_id == isp_customer_id)
        if subscriber_id is not None:
            conds.append(IspInventoryUnit.subscriber_id == subscriber_id)
        if search:
            like = f"%{search.strip()}%"
            conds.append(
                or_(
                    IspInventoryUnit.serial.ilike(like),
                    IspInventoryUnit.mac.ilike(like),
                )
            )
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(IspInventoryUnit).where(*conds)
                )
            ).scalar_one()
        )
        rows = (
            (
                await self.session.execute(
                    select(IspInventoryUnit)
                    .where(*conds)
                    .order_by(IspInventoryUnit.state_changed_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return await self.unit_views(rows), total

    async def unit_detail(self, isp: Any, unit_id: uuid.UUID) -> dict:
        u = await self._unit(isp, unit_id)
        view = (await self.unit_views([u]))[0]
        visible = set(await isp.child_ids())
        moves = (
            (
                await self.session.execute(
                    select(IspInventoryMovement)
                    .where(IspInventoryMovement.unit_id == u.id)
                    .order_by(IspInventoryMovement.at)
                )
            )
            .scalars()
            .all()
        )
        view["history"] = [
            {
                "from_state": m.from_state,
                "to_state": m.to_state,
                # never leak a customer the caller cannot see
                "isp_customer_id": m.customer_organization_id
                if m.customer_organization_id in visible
                else None,
                "note": m.note,
                "at": m.at,
            }
            for m in moves
        ]
        return view

    async def unit_views(self, rows: list[Any]) -> list[dict]:
        item_ids = {r.item_id for r in rows}
        items = {}
        if item_ids:
            for i in (
                await self.session.execute(
                    select(IspInventoryItem).where(IspInventoryItem.id.in_(item_ids))
                )
            ).scalars():
                items[i.id] = i
        orgs = await org_names(self.session, {r.customer_organization_id for r in rows})
        from .apps2_service import unit_meta_views

        meta = await unit_meta_views(self.session, rows)  # APPS-2 links
        return [
            {
                "id": r.id,
                "item_id": r.item_id,
                "item_name": items[r.item_id].name if r.item_id in items else None,
                "sku": items[r.item_id].sku if r.item_id in items else None,
                "serial": r.serial,
                "mac": r.mac,
                "state": r.state,
                "isp_customer_id": r.customer_organization_id,
                "customer_name": orgs.get(r.customer_organization_id),
                "subscriber_id": r.subscriber_id,
                "state_changed_at": r.state_changed_at,
                "note": r.note,
                **meta.get(r.id, {}),
            }
            for r in rows
        ]
