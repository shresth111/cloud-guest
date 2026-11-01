"""J22 fiber plant registry (ADDENDUM_05 §7, JAZE-6 part B).

A record of the ISP's passive plant: OLT -> joint closure / pole -> splitter
-> ONT, each with lat/long and its upstream parent (the route), and which
subscriber sits on which splitter port. Nothing is pushed to any device.

Flag ``ISP_FIBER_ENABLED`` (default OFF): while off every ``/isp/fiber``
route is a plain 404 (on top of ``ISP_PARTNER_ENABLED``).

Visibility: every node belongs to one ISP. A node may name one customer
(``customer_organization_id``); confined staff see shared nodes (no
customer) and nodes of customers they cover, and may only *change* nodes of
customers they cover. Subscribers listed under a node are always filtered to
the customers the caller can see.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from fastapi import HTTPException, status
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import func, or_, select

from .exceptions import IspError
from .fiber_models import IspFiberNode, IspFiberPortAssignment
from .plans_models import IspSubscriber
from .scoping import IspScope

__all__ = [
    "FIBER_KINDS",
    "IspFiberService",
    "IspFiberSettings",
    "RequireIspFiberEnabled",
    "get_isp_fiber_settings",
    "maps_url",
]


# -- flag ----------------------------------------------------------------------
class IspFiberSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_FIBER_", case_sensitive=False, extra="ignore"
    )

    enabled: bool = Field(default=False, description="ISP_FIBER_ENABLED")


@lru_cache(maxsize=1)
def get_isp_fiber_settings() -> IspFiberSettings:
    return IspFiberSettings()


async def RequireIspFiberEnabled() -> None:
    if not get_isp_fiber_settings().enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


# -- errors --------------------------------------------------------------------
class IspFiberNotFoundError(IspError):
    code = "ISP_FIBER_NOT_FOUND"
    status_code_default = status.HTTP_404_NOT_FOUND
    default_message = "Fiber node not found"


class IspFiberInvalidError(IspError):
    code = "ISP_FIBER_INVALID"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "That change is not valid for this fiber node"


class IspFiberConflictError(IspError):
    code = "ISP_FIBER_CONFLICT"
    status_code_default = status.HTTP_409_CONFLICT
    default_message = "That is already in use"


# -- rules ---------------------------------------------------------------------
FIBER_KINDS = ("olt", "pole", "splitter", "joint_closure", "ont", "other")
FIBER_STATUSES = ("active", "planned", "retired")
#: An ONT is the subscriber end: nothing hangs below it.
LEAF_KINDS = frozenset({"ont"})
#: How far ``route`` walks up before giving up (a guard, not a real limit).
MAX_ROUTE_DEPTH = 64


def maps_url(lat: float | None, lng: float | None) -> str | None:
    """A Google Maps link for the point (no API key, no tracking params)."""
    if lat is None or lng is None:
        return None
    return f"https://www.google.com/maps/search/?api=1&query={lat:.6f},{lng:.6f}"


def check_parent_port(parent: Any, port: int | None) -> None:
    if port is None:
        return
    if not parent.port_count:
        raise IspFiberInvalidError("The upstream node has no numbered ports")
    if not 1 <= port <= parent.port_count:
        raise IspFiberInvalidError(
            f"Port {port} does not exist on {parent.name} (1-{parent.port_count})"
        )


def node_view(n: Any) -> dict:
    return {
        "id": n.id,
        "kind": n.kind,
        "name": n.name,
        "code": n.code,
        "status": n.status,
        "latitude": n.latitude,
        "longitude": n.longitude,
        "maps_url": maps_url(n.latitude, n.longitude),
        "address": n.address,
        "parent_id": n.parent_id,
        "parent_port": n.parent_port,
        "port_count": n.port_count,
        "spec": n.spec,
        "isp_customer_id": n.customer_organization_id,
        "notes": n.notes,
        "created_at": getattr(n, "created_at", None),
    }


def _sub_label(s: Any) -> str:
    name = " ".join(p for p in (s.first_name, s.last_name) if p).strip()
    return name or s.display_name or s.identifier


class IspFiberService:
    def __init__(self, session: Any) -> None:
        self.session = session

    # -- visibility ------------------------------------------------------------
    async def _visible(self, isp: Any) -> set[uuid.UUID] | None:
        """None = every customer of this ISP (unconfined caller)."""
        if isp.confined_customer_ids is None:
            return None
        return set(await isp.child_ids())

    @staticmethod
    def _sees(node: Any, visible: set[uuid.UUID] | None) -> bool:
        return (
            visible is None
            or node.customer_organization_id is None
            or node.customer_organization_id in visible
        )

    @staticmethod
    def _may_change(node: Any, visible: set[uuid.UUID] | None) -> bool:
        return visible is None or (
            node.customer_organization_id is not None
            and node.customer_organization_id in visible
        )

    async def _node(
        self, isp: Any, node_id: uuid.UUID, *, write: bool = False
    ) -> IspFiberNode:
        n = await self.session.get(IspFiberNode, node_id)
        if n is None or n.is_deleted or n.isp_organization_id != isp.isp_org_id:
            raise IspFiberNotFoundError()
        visible = await self._visible(isp)
        if not self._sees(n, visible):
            raise IspFiberNotFoundError()
        if write and not self._may_change(n, visible):
            raise IspFiberInvalidError(
                "Only unconfined staff can change shared plant or another "
                "customer's plant"
            )
        return n

    async def _check_customer(self, isp: Any, customer_id: uuid.UUID | None) -> None:
        if customer_id is not None:
            await IspScope.assert_customer(isp, customer_id)
        elif isp.confined_customer_ids is not None:
            raise IspFiberInvalidError(
                "Confined staff must pick the customer this plant belongs to"
            )

    # -- tree helpers ------------------------------------------------------------
    async def descendant_ids(self, root_id: uuid.UUID) -> list[uuid.UUID]:
        """``root_id`` and every live node below it. ``UNION`` (not ALL)
        means a corrupt cycle still terminates."""
        tree = (
            select(IspFiberNode.id)
            .where(IspFiberNode.id == root_id)
            .cte("fiber_tree", recursive=True)
        )
        child = select(IspFiberNode.id).where(
            IspFiberNode.parent_id == tree.c.id, IspFiberNode.is_deleted.is_(False)
        )
        tree = tree.union(child)
        return list((await self.session.execute(select(tree.c.id))).scalars().all())

    async def _port_taken(
        self,
        node_id: uuid.UUID,
        port: int,
        *,
        except_child: uuid.UUID | None = None,
        except_assignment: uuid.UUID | None = None,
    ) -> str | None:
        q = select(IspFiberNode.name).where(
            IspFiberNode.parent_id == node_id,
            IspFiberNode.parent_port == port,
            IspFiberNode.is_deleted.is_(False),
        )
        if except_child is not None:
            q = q.where(IspFiberNode.id != except_child)
        child = (await self.session.execute(q)).scalars().first()
        if child is not None:
            return f"node {child}"
        q = select(IspFiberPortAssignment.id).where(
            IspFiberPortAssignment.node_id == node_id,
            IspFiberPortAssignment.port_no == port,
            IspFiberPortAssignment.is_deleted.is_(False),
        )
        if except_assignment is not None:
            q = q.where(IspFiberPortAssignment.id != except_assignment)
        if (await self.session.execute(q)).first() is not None:
            return "a subscriber"
        return None

    async def _highest_used_port(self, node_id: uuid.UUID) -> int:
        child = (
            await self.session.execute(
                select(func.max(IspFiberNode.parent_port)).where(
                    IspFiberNode.parent_id == node_id,
                    IspFiberNode.is_deleted.is_(False),
                )
            )
        ).scalar()
        assigned = (
            await self.session.execute(
                select(func.max(IspFiberPortAssignment.port_no)).where(
                    IspFiberPortAssignment.node_id == node_id,
                    IspFiberPortAssignment.is_deleted.is_(False),
                )
            )
        ).scalar()
        return max(int(child or 0), int(assigned or 0))

    async def _code_taken(
        self, isp: Any, code: str, exclude: uuid.UUID | None = None
    ) -> bool:
        q = select(IspFiberNode.id).where(
            IspFiberNode.isp_organization_id == isp.isp_org_id,
            IspFiberNode.is_deleted.is_(False),
            IspFiberNode.code == code,
        )
        if exclude is not None:
            q = q.where(IspFiberNode.id != exclude)
        return (await self.session.execute(q)).first() is not None

    async def _set_parent(
        self,
        isp: Any,
        node: IspFiberNode,
        parent_id: uuid.UUID | None,
        port: int | None,
    ) -> None:
        if parent_id is None:
            if port is not None:
                raise IspFiberInvalidError("A port needs an upstream node")
            node.parent_id, node.parent_port = None, None
            return
        parent = await self._node(isp, parent_id)
        if parent.kind in LEAF_KINDS:
            raise IspFiberInvalidError("Nothing can hang below an ONT")
        if node.id is not None and parent.id == node.id:
            raise IspFiberInvalidError("A node cannot feed itself")
        if node.id is not None and parent.id in set(await self.descendant_ids(node.id)):
            raise IspFiberInvalidError(
                "That upstream node is downstream of this one (a loop)"
            )
        check_parent_port(parent, port)
        if port is not None:
            used = await self._port_taken(parent.id, port, except_child=node.id)
            if used:
                raise IspFiberConflictError(f"Port {port} is already used by {used}")
        node.parent_id, node.parent_port = parent.id, port

    # -- nodes -------------------------------------------------------------------
    async def create(self, isp: Any, data: dict) -> dict:
        await self._check_customer(isp, data.get("isp_customer_id"))
        if data.get("kind") in LEAF_KINDS and data.get("port_count"):
            raise IspFiberInvalidError("An ONT has no splitter ports")
        code = data.get("code") or None
        if code and await self._code_taken(isp, code):
            raise IspFiberConflictError("Another node already has this code")
        n = IspFiberNode(
            id=uuid.uuid4(),
            isp_organization_id=isp.isp_org_id,
            customer_organization_id=data.get("isp_customer_id"),
            kind=data["kind"],
            name=data["name"],
            code=code,
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
            address=data.get("address"),
            port_count=data.get("port_count"),
            spec=data.get("spec"),
            status=data.get("status") or "active",
            notes=data.get("notes"),
            created_by=isp.user_id,
        )
        await self._set_parent(isp, n, data.get("parent_id"), data.get("parent_port"))
        self.session.add(n)
        await self.session.flush()
        return await self.detail(isp, n.id)

    async def update(self, isp: Any, node_id: uuid.UUID, data: dict) -> dict:
        n = await self._node(isp, node_id, write=True)
        if "isp_customer_id" in data:
            await self._check_customer(isp, data["isp_customer_id"])
            n.customer_organization_id = data["isp_customer_id"]
        kind = data.get("kind", n.kind)
        if kind in LEAF_KINDS:
            has_children = (
                await self.session.execute(
                    select(IspFiberNode.id).where(
                        IspFiberNode.parent_id == n.id,
                        IspFiberNode.is_deleted.is_(False),
                    )
                )
            ).first()
            if has_children is not None:
                raise IspFiberInvalidError(
                    "This node feeds others; it cannot be an ONT"
                )
        if "port_count" in data:
            new = data["port_count"]
            if new and kind in LEAF_KINDS:
                raise IspFiberInvalidError("An ONT has no splitter ports")
            used = await self._highest_used_port(n.id)
            if used and (not new or new < used):
                raise IspFiberInvalidError(
                    f"Port {used} is in use; free it before shrinking the ports"
                )
            n.port_count = new
        if "code" in data:
            code = data["code"] or None
            if code and await self._code_taken(isp, code, exclude=n.id):
                raise IspFiberConflictError("Another node already has this code")
            n.code = code
        if "parent_id" in data or "parent_port" in data:
            await self._set_parent(
                isp,
                n,
                data.get("parent_id", n.parent_id),
                data.get(
                    "parent_port", n.parent_port if "parent_id" not in data else None
                ),
            )
        for field in ("kind", "name", "latitude", "longitude", "address", "spec",
                      "status", "notes"):  # fmt: skip
            if field in data:
                setattr(n, field, data[field])
        n.updated_by = isp.user_id
        await self.session.flush()
        return await self.detail(isp, n.id)

    async def delete(self, isp: Any, node_id: uuid.UUID) -> None:
        n = await self._node(isp, node_id, write=True)
        child = (
            await self.session.execute(
                select(IspFiberNode.id).where(
                    IspFiberNode.parent_id == n.id, IspFiberNode.is_deleted.is_(False)
                )
            )
        ).first()
        if child is not None:
            raise IspFiberConflictError("Move or delete the nodes below this one first")
        used = (
            await self.session.execute(
                select(IspFiberPortAssignment.id).where(
                    IspFiberPortAssignment.node_id == n.id,
                    IspFiberPortAssignment.is_deleted.is_(False),
                )
            )
        ).first()
        if used is not None:
            raise IspFiberConflictError("Free this node's subscriber ports first")
        n.is_deleted = True
        n.deleted_at = datetime.now(UTC)
        n.updated_by = isp.user_id
        await self.session.flush()

    async def list(
        self,
        isp: Any,
        *,
        kind: str | None = None,
        parent_id: uuid.UUID | None = None,
        roots_only: bool = False,
        isp_customer_id: uuid.UUID | None = None,
        status: str | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[dict], int]:
        conds: list[Any] = [
            IspFiberNode.isp_organization_id == isp.isp_org_id,
            IspFiberNode.is_deleted.is_(False),
        ]
        visible = await self._visible(isp)
        if visible is not None:
            conds.append(
                or_(
                    IspFiberNode.customer_organization_id.is_(None),
                    IspFiberNode.customer_organization_id.in_(
                        visible or [uuid.UUID(int=0)]
                    ),
                )
            )
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            conds.append(IspFiberNode.customer_organization_id == isp_customer_id)
        if kind:
            conds.append(IspFiberNode.kind == kind)
        if status:
            conds.append(IspFiberNode.status == status)
        if parent_id is not None:
            conds.append(IspFiberNode.parent_id == parent_id)
        elif roots_only:
            conds.append(IspFiberNode.parent_id.is_(None))
        if search:
            like = f"%{search.strip()}%"
            conds.append(
                or_(
                    IspFiberNode.name.ilike(like),
                    IspFiberNode.code.ilike(like),
                    IspFiberNode.address.ilike(like),
                )
            )
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(IspFiberNode).where(*conds)
                )
            ).scalar_one()
        )
        rows = (
            (
                await self.session.execute(
                    select(IspFiberNode)
                    .where(*conds)
                    .order_by(IspFiberNode.kind, IspFiberNode.name)
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return [node_view(r) for r in rows], total

    async def route(self, isp: Any, node_id: uuid.UUID) -> list[dict]:
        """Root-first path from the top of the plant down to ``node_id``."""
        n = await self._node(isp, node_id)
        path = [n]
        seen = {n.id}
        while path[-1].parent_id is not None and len(path) < MAX_ROUTE_DEPTH:
            p = await self.session.get(IspFiberNode, path[-1].parent_id)
            if p is None or p.id in seen or p.isp_organization_id != isp.isp_org_id:
                break
            seen.add(p.id)
            path.append(p)
        return [
            {
                "id": p.id,
                "kind": p.kind,
                "name": p.name,
                "code": p.code,
                "parent_port": p.parent_port,
                "maps_url": maps_url(p.latitude, p.longitude),
            }
            for p in reversed(path)
        ]

    async def detail(self, isp: Any, node_id: uuid.UUID) -> dict:
        n = await self._node(isp, node_id)
        view = node_view(n)
        children = int(
            (
                await self.session.execute(
                    select(func.count())
                    .select_from(IspFiberNode)
                    .where(
                        IspFiberNode.parent_id == n.id,
                        IspFiberNode.is_deleted.is_(False),
                    )
                )
            ).scalar_one()
        )
        assigned = int(
            (
                await self.session.execute(
                    select(func.count())
                    .select_from(IspFiberPortAssignment)
                    .where(
                        IspFiberPortAssignment.node_id == n.id,
                        IspFiberPortAssignment.is_deleted.is_(False),
                    )
                )
            ).scalar_one()
        )
        view["child_count"] = children
        view["ports_assigned"] = assigned
        view["route"] = await self.route(isp, n.id)
        return view

    # -- ports -------------------------------------------------------------------
    async def _subscriber(self, isp: Any, subscriber_id: uuid.UUID) -> IspSubscriber:
        s = await self.session.get(IspSubscriber, subscriber_id)
        if s is None or s.is_deleted or s.isp_organization_id != isp.isp_org_id:
            raise IspFiberNotFoundError("Subscriber not found")
        try:
            await IspScope.assert_customer(isp, s.customer_organization_id)
        except Exception:  # noqa: BLE001 -- outside confinement: same 404
            raise IspFiberNotFoundError("Subscriber not found") from None
        return s

    async def ports(self, isp: Any, node_id: uuid.UUID) -> list[dict]:
        n = await self._node(isp, node_id)
        if not n.port_count:
            return []
        visible = await self._visible(isp)
        assignments = (
            (
                await self.session.execute(
                    select(IspFiberPortAssignment).where(
                        IspFiberPortAssignment.node_id == n.id,
                        IspFiberPortAssignment.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        subs = {}
        sub_ids = {a.subscriber_id for a in assignments}
        if sub_ids:
            for s in (
                await self.session.execute(
                    select(IspSubscriber).where(IspSubscriber.id.in_(sub_ids))
                )
            ).scalars():
                subs[s.id] = s
        children = (
            (
                await self.session.execute(
                    select(IspFiberNode).where(
                        IspFiberNode.parent_id == n.id,
                        IspFiberNode.parent_port.is_not(None),
                        IspFiberNode.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        by_port_a = {a.port_no: a for a in assignments}
        by_port_c = {c.parent_port: c for c in children}
        out = []
        for port in range(1, n.port_count + 1):
            a, c = by_port_a.get(port), by_port_c.get(port)
            row: dict[str, Any] = {"port_no": port, "state": "free"}
            if c is not None:
                row.update(
                    state="node", node={"id": c.id, "kind": c.kind, "name": c.name}
                )
            elif a is not None:
                hidden = (
                    visible is not None and a.customer_organization_id not in visible
                )
                s = subs.get(a.subscriber_id)
                row.update(state="subscriber")
                if hidden or s is None:
                    row["subscriber"] = None  # in use, outside the caller's scope
                else:
                    row["subscriber"] = {
                        "id": s.id,
                        "label": _sub_label(s),
                        "identifier": s.identifier,
                        "isp_customer_id": s.customer_organization_id,
                    }
                    row["assignment_id"] = a.id
                    row["notes"] = a.notes
            out.append(row)
        return out

    async def assign_port(
        self,
        isp: Any,
        node_id: uuid.UUID,
        port_no: int,
        subscriber_id: uuid.UUID,
        notes: str | None = None,
    ) -> dict:
        n = await self._node(isp, node_id)
        check_parent_port(n, port_no)
        s = await self._subscriber(isp, subscriber_id)
        existing = (
            (
                await self.session.execute(
                    select(IspFiberPortAssignment).where(
                        IspFiberPortAssignment.subscriber_id == s.id,
                        IspFiberPortAssignment.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )
        if existing is not None and (
            existing.node_id != n.id or existing.port_no != port_no
        ):
            raise IspFiberConflictError(
                "This subscriber already sits on another port; free it first"
            )
        if existing is None:
            used = await self._port_taken(n.id, port_no)
            if used:
                raise IspFiberConflictError(f"Port {port_no} is already used by {used}")
            existing = IspFiberPortAssignment(
                id=uuid.uuid4(),
                isp_organization_id=isp.isp_org_id,
                node_id=n.id,
                port_no=port_no,
                subscriber_id=s.id,
                customer_organization_id=s.customer_organization_id,
                created_by=isp.user_id,
            )
            self.session.add(existing)
        existing.notes = notes
        await self.session.flush()
        return {
            "node_id": n.id,
            "port_no": port_no,
            "subscriber_id": s.id,
            "assignment_id": existing.id,
        }

    async def release_port(self, isp: Any, node_id: uuid.UUID, port_no: int) -> None:
        n = await self._node(isp, node_id)
        a = (
            (
                await self.session.execute(
                    select(IspFiberPortAssignment).where(
                        IspFiberPortAssignment.node_id == n.id,
                        IspFiberPortAssignment.port_no == port_no,
                        IspFiberPortAssignment.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )
        if a is None:
            raise IspFiberNotFoundError("Nobody is on that port")
        visible = await self._visible(isp)
        if visible is not None and a.customer_organization_id not in visible:
            raise IspFiberNotFoundError("Nobody is on that port")
        a.is_deleted = True
        a.deleted_at = datetime.now(UTC)
        a.updated_by = isp.user_id
        await self.session.flush()

    # -- impact ------------------------------------------------------------------
    async def downstream(self, isp: Any, node_id: uuid.UUID) -> dict:
        """Who is affected if ``node_id`` goes dark: every node below it and
        every subscriber on a port of any of them (visible ones listed)."""
        n = await self._node(isp, node_id)
        ids = await self.descendant_ids(n.id)
        kinds = (
            await self.session.execute(
                select(IspFiberNode.kind, func.count())
                .where(IspFiberNode.id.in_(ids), IspFiberNode.id != n.id)
                .group_by(IspFiberNode.kind)
            )
        ).all()
        conds: list[Any] = [
            IspFiberPortAssignment.node_id.in_(ids),
            IspFiberPortAssignment.is_deleted.is_(False),
            IspFiberPortAssignment.isp_organization_id == isp.isp_org_id,
        ]
        visible = await self._visible(isp)
        if visible is not None:
            conds.append(
                IspFiberPortAssignment.customer_organization_id.in_(
                    visible or [uuid.UUID(int=0)]
                )
            )
        rows = (
            await self.session.execute(
                select(IspFiberPortAssignment, IspSubscriber, IspFiberNode.name)
                .join(
                    IspSubscriber,
                    IspSubscriber.id == IspFiberPortAssignment.subscriber_id,
                )
                .join(IspFiberNode, IspFiberNode.id == IspFiberPortAssignment.node_id)
                .where(*conds)
                .order_by(IspFiberNode.name, IspFiberPortAssignment.port_no)
            )
        ).all()
        subscribers = [
            {
                "subscriber_id": s.id,
                "label": _sub_label(s),
                "identifier": s.identifier,
                "phone": s.phone,
                "status": s.status,
                "isp_customer_id": s.customer_organization_id,
                "node_id": a.node_id,
                "node_name": node_name,
                "port_no": a.port_no,
            }
            for a, s, node_name in rows
        ]
        return {
            "node": {"id": n.id, "kind": n.kind, "name": n.name},
            "downstream_nodes": sum(int(c) for _k, c in kinds),
            "downstream_by_kind": {k: int(c) for k, c in kinds},
            "subscriber_count": len(subscribers),
            "subscribers": subscribers,
        }

    async def subscriber_location(self, isp: Any, subscriber_id: uuid.UUID) -> dict:
        """Where one subscriber hangs in the plant (for the 360 page)."""
        s = await self._subscriber(isp, subscriber_id)
        a = (
            (
                await self.session.execute(
                    select(IspFiberPortAssignment).where(
                        IspFiberPortAssignment.subscriber_id == s.id,
                        IspFiberPortAssignment.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )
        if a is None:
            return {"subscriber_id": s.id, "assigned": False, "port_no": None,
                    "node_id": None, "route": []}  # fmt: skip
        try:
            route = await self.route(isp, a.node_id)
        except IspFiberNotFoundError:  # shared node hidden by a confinement edge
            route = []
        return {
            "subscriber_id": s.id,
            "assigned": True,
            "node_id": a.node_id,
            "port_no": a.port_no,
            "route": route,
        }
