"""JAZE-2 API (ADDENDUM_05 J3/J8). Same guard stack as every ``/isp`` route;
ids are ``package_id`` / ``subscriber_id`` / ``binding_id`` /
``isp_location_id`` / ``pool_id`` (never a scope-alias name).

* ``GET|PUT /isp/packages/{package_id}/policy`` -- FUP, night boost,
  validity start, priority, MAC/IP/concurrency/timeouts.
* ``GET /isp/subscribers/{subscriber_id}/fup`` -- the FUP-status read the
  subscriber 360 page shows; ``POST .../fup/reset`` and ``.../fup/topup``.
* ``GET|POST /isp/subscribers/{subscriber_id}/mac-bindings`` and
  ``DELETE .../mac-bindings/{binding_id}``.
* ``GET /isp/subscribers/{subscriber_id}/enforcement-events``.
* Static IP: ``GET /isp/locations/{isp_location_id}/ip-pools``,
  ``GET .../ip-pools/{pool_id}/next-free``,
  ``GET|POST /isp/subscribers/{subscriber_id}/ip-bindings``,
  ``DELETE .../ip-bindings/{binding_id}``.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.queue_management.dependencies import get_queue_management_service

from .config import get_isp_partner_settings
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .enforcement import MB, fup_view, norm_mac, record_event
from .enforcement_models import (
    IspEnforcementEvent,
    IspPackagePolicy,
    IspSubscriberIpBinding,
    IspSubscriberMacBinding,
    IspSubscriberUsage,
)
from .exceptions import IspBadRequestError, IspError
from .http import ok
from .plans_models import IspPackage, IspSpeedGroup, IspSubscriber
from .plans_router import PLANS_READ, PLANS_UPDATE, SUBS_READ, SUBS_UPDATE
from .plans_service import (
    IspPackageNotFoundError,
    IspSpeedGroupNotFoundError,
    IspSubscriberNotFoundError,
)
from .scoping import IspScope

enforcement_router = APIRouter(tags=["ISP Partner: enforcement"])


class IspBindingNotFoundError(IspError):
    code = "ISP_BINDING_NOT_FOUND"
    status_code_default = 404
    default_message = "Binding not found"


class IspPoolNotFoundError(IspError):
    code = "ISP_IP_POOL_NOT_FOUND"
    status_code_default = 404
    default_message = "IP pool not found"


class IspIpTakenError(IspError):
    code = "ISP_IP_TAKEN"
    status_code_default = 409
    default_message = "That IP is already pinned to a subscriber at this location"


class IspPoolExhaustedError(IspError):
    code = "ISP_IP_POOL_EXHAUSTED"
    status_code_default = 409
    default_message = "No free address left in this pool"


# --------------------------------------------------------------------------
# Scoping helpers
# --------------------------------------------------------------------------


async def _package(db: AsyncSession, isp: IspContext, package_id: uuid.UUID) -> Any:
    p = await db.get(IspPackage, package_id)
    if p is None or p.is_deleted or p.isp_organization_id != isp.isp_org_id:
        raise IspPackageNotFoundError()
    return p


async def _subscriber(
    db: AsyncSession, isp: IspContext, subscriber_id: uuid.UUID
) -> Any:
    s = await db.get(IspSubscriber, subscriber_id)
    if s is None or s.is_deleted or s.isp_organization_id != isp.isp_org_id:
        raise IspSubscriberNotFoundError()
    try:
        await IspScope.assert_customer(isp, s.customer_organization_id)
    except Exception:  # noqa: BLE001 -- out of confinement: same 404
        raise IspSubscriberNotFoundError() from None
    return s


async def _group(db: AsyncSession, isp: IspContext, group_id: uuid.UUID | None) -> Any:
    if group_id is None:
        return None
    g = await db.get(IspSpeedGroup, group_id)
    if g is None or g.is_deleted or g.isp_organization_id != isp.isp_org_id:
        raise IspSpeedGroupNotFoundError()
    return g


async def _policy(db: AsyncSession, package_id: uuid.UUID) -> Any:
    return (
        await db.execute(
            select(IspPackagePolicy).where(
                IspPackagePolicy.package_id == package_id,
                IspPackagePolicy.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


async def _group_names(db: AsyncSession, isp: IspContext) -> dict[uuid.UUID, str]:
    rows = (
        await db.execute(
            select(IspSpeedGroup.id, IspSpeedGroup.name).where(
                IspSpeedGroup.isp_organization_id == isp.isp_org_id
            )
        )
    ).all()
    return {r[0]: r[1] for r in rows}


# --------------------------------------------------------------------------
# Package policy
# --------------------------------------------------------------------------


class PolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fup_limit_mb: int | None = Field(default=None, ge=1, le=1_000_000_000)
    fup_reset: str = Field(default="cycle", pattern="^(cycle|day|month)$")
    fup_fallback_speed_group_id: uuid.UUID | None = None
    fup_exclude_upload: bool = False
    fup_carry_forward: bool = False
    boost_speed_group_id: uuid.UUID | None = None
    boost_start_minute: int | None = Field(default=None, ge=0, le=1439)
    boost_end_minute: int | None = Field(default=None, ge=0, le=1439)
    validity_starts: str = Field(
        default="activation", pattern="^(activation|first_login)$"
    )
    queue_priority: int | None = Field(default=None, ge=1, le=8)
    mac_bind_count: int = Field(default=0, ge=0, le=16)
    mac_restriction: bool = False
    ip_restriction: bool = False
    max_simultaneous: int | None = Field(default=None, ge=1, le=64)
    idle_timeout_s: int | None = Field(default=None, ge=60, le=7 * 86400)
    hard_timeout_s: int | None = Field(default=None, ge=300, le=90 * 86400)


_POLICY_FIELDS = tuple(PolicyRequest.model_fields)


def _policy_view(policy: Any, package: Any, names: dict[uuid.UUID, str]) -> dict:
    data: dict[str, Any] = {
        "package_id": str(package.id),
        "configured": policy is not None,
        "enforcement_enabled": get_isp_partner_settings().enforcement_enabled,
        "live_mode": get_isp_partner_settings().enforcement_live_mode,
    }
    for f in _POLICY_FIELDS:
        v = (
            getattr(policy, f, None)
            if policy is not None
            else PolicyRequest.model_fields[f].default
        )
        data[f] = str(v) if isinstance(v, uuid.UUID) else v
    for f in ("fup_fallback_speed_group_id", "boost_speed_group_id"):
        gid = getattr(policy, f, None) if policy is not None else None
        data[f.replace("_id", "_name")] = names.get(gid) if gid else None
    return data


@enforcement_router.get(
    "/packages/{package_id}/policy", dependencies=isp_guards(PLANS_READ)
)
async def get_package_policy(
    request: Request,
    package_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    pkg = await _package(db, isp, package_id)
    return ok(
        request,
        _policy_view(await _policy(db, pkg.id), pkg, await _group_names(db, isp)),
        "Package policy",
    )


@enforcement_router.put(
    "/packages/{package_id}/policy", dependencies=isp_guards(PLANS_UPDATE)
)
async def put_package_policy(
    request: Request,
    package_id: uuid.UUID,
    payload: PolicyRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    pkg = await _package(db, isp, package_id)
    await _group(db, isp, payload.fup_fallback_speed_group_id)
    await _group(db, isp, payload.boost_speed_group_id)
    if payload.fup_fallback_speed_group_id and not payload.fup_limit_mb:
        raise IspBadRequestError("A fallback speed needs an FUP limit")
    boost = (
        payload.boost_speed_group_id,
        payload.boost_start_minute,
        payload.boost_end_minute,
    )
    if any(v is not None for v in boost) and not all(v is not None for v in boost):
        raise IspBadRequestError("Night boost needs a speed group, a start and an end")
    if payload.boost_start_minute is not None and (
        payload.boost_start_minute == payload.boost_end_minute
    ):
        raise IspBadRequestError("Boost start and end must differ")
    policy = await _policy(db, pkg.id)
    if policy is None:
        policy = IspPackagePolicy(isp_organization_id=isp.isp_org_id, package_id=pkg.id)
        db.add(policy)
    for f, v in payload.model_dump().items():
        setattr(policy, f, v)
    await db.flush()
    await db.commit()
    return ok(
        request,
        _policy_view(policy, pkg, await _group_names(db, isp)),
        "Package policy saved",
    )


# --------------------------------------------------------------------------
# FUP status / reset / top-up
# --------------------------------------------------------------------------


async def _usage(db: AsyncSession, sub_id: uuid.UUID) -> Any:
    return (
        await db.execute(
            select(IspSubscriberUsage).where(
                IspSubscriberUsage.subscriber_id == sub_id,
                IspSubscriberUsage.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


async def _fup_payload(db: AsyncSession, isp: IspContext, sub: Any) -> dict:
    policy = await _policy(db, sub.package_id) if sub.package_id else None
    data = fup_view(await _usage(db, sub.id), policy, await _group_names(db, isp))
    data["subscriber_id"] = str(sub.id)
    data["policy_configured"] = policy is not None
    data["enforcement_enabled"] = get_isp_partner_settings().enforcement_enabled
    return data


@enforcement_router.get(
    "/subscribers/{subscriber_id}/fup", dependencies=isp_guards(SUBS_READ)
)
async def get_subscriber_fup(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    return ok(request, await _fup_payload(db, isp, sub), "FUP status")


@enforcement_router.post(
    "/subscribers/{subscriber_id}/fup/reset", dependencies=isp_guards(SUBS_UPDATE)
)
async def reset_subscriber_fup(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Restart counting now: usage before this moment no longer counts this
    period. The throttle lifts at the next sweep / authorize."""
    sub = await _subscriber(db, isp, subscriber_id)
    row = await _usage(db, sub.id)
    now = datetime.now(UTC)
    if row is not None:
        row.period_start = now
        row.used_down_bytes = row.used_up_bytes = 0
        row.carry_bytes = row.topup_bytes = 0
        row.throttled, row.throttled_at = False, None
    await record_event(
        db,
        isp_id=isp.isp_org_id,
        subscriber_id=sub.id,
        kind="fup_reset",
        detail="reset by ISP staff",
        now=now,
    )
    await db.commit()
    return ok(request, await _fup_payload(db, isp, sub), "FUP counter reset")


class TopupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mb: int = Field(ge=1, le=100_000_000)


@enforcement_router.post(
    "/subscribers/{subscriber_id}/fup/topup", dependencies=isp_guards(SUBS_UPDATE)
)
async def topup_subscriber_fup(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: TopupRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    row = await _usage(db, sub.id)
    if row is None:
        raise IspBadRequestError(
            "No FUP period yet for this subscriber (package has no FUP limit, "
            "or the sweep has not run)"
        )
    row.topup_bytes = (row.topup_bytes or 0) + payload.mb * MB
    await record_event(
        db,
        isp_id=isp.isp_org_id,
        subscriber_id=sub.id,
        kind="fup_topup",
        detail=f"+{payload.mb} MB",
    )
    await db.commit()
    return ok(request, await _fup_payload(db, isp, sub), "FUP top-up added")


# --------------------------------------------------------------------------
# MAC bindings
# --------------------------------------------------------------------------


def _mac_view(b: Any) -> dict:
    return {
        "id": str(b.id),
        "mac": b.mac,
        "source": b.source,
        "bound_at": b.created_at.isoformat() if b.created_at else None,
    }


async def _macs(db: AsyncSession, sub_id: uuid.UUID) -> list[Any]:
    return list(
        (
            await db.execute(
                select(IspSubscriberMacBinding)
                .where(
                    IspSubscriberMacBinding.subscriber_id == sub_id,
                    IspSubscriberMacBinding.is_deleted.is_(False),
                )
                .order_by(IspSubscriberMacBinding.created_at)
            )
        ).scalars()
    )


@enforcement_router.get(
    "/subscribers/{subscriber_id}/mac-bindings", dependencies=isp_guards(SUBS_READ)
)
async def list_mac_bindings(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    return ok(request, [_mac_view(b) for b in await _macs(db, sub.id)], "MAC bindings")


class MacRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mac: str

    @field_validator("mac")
    @classmethod
    def _valid(cls, v: str) -> str:
        m = norm_mac(v)
        parts = (m or "").split(":")
        if len(parts) != 6 or not all(
            len(p) == 2 and all(c in "0123456789ABCDEF" for c in p) for p in parts
        ):
            raise ValueError("not a MAC address")
        return m  # type: ignore[return-value]


@enforcement_router.post(
    "/subscribers/{subscriber_id}/mac-bindings",
    status_code=201,
    dependencies=isp_guards(SUBS_UPDATE),
)
async def add_mac_binding(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: MacRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    existing = {b.mac: b for b in await _macs(db, sub.id)}
    b = existing.get(payload.mac)
    if b is None:
        b = IspSubscriberMacBinding(
            isp_organization_id=isp.isp_org_id,
            subscriber_id=sub.id,
            mac=payload.mac,
            source="manual",
        )
        db.add(b)
        await record_event(
            db,
            isp_id=isp.isp_org_id,
            subscriber_id=sub.id,
            kind="mac_bound",
            detail=f"{payload.mac} (manual)",
        )
        await db.flush()
        await db.commit()
    return ok(request, _mac_view(b), "MAC bound")


@enforcement_router.delete(
    "/subscribers/{subscriber_id}/mac-bindings/{binding_id}",
    dependencies=isp_guards(SUBS_UPDATE),
)
async def delete_mac_binding(
    request: Request,
    subscriber_id: uuid.UUID,
    binding_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Clears one bound MAC. With auto-bind on, the next device that logs in
    is bound in its place ("customer changed their router")."""
    sub = await _subscriber(db, isp, subscriber_id)
    b = await db.get(IspSubscriberMacBinding, binding_id)
    if b is None or b.is_deleted or b.subscriber_id != sub.id:
        raise IspBindingNotFoundError()
    b.is_deleted, b.deleted_at = True, datetime.now(UTC)
    await record_event(
        db,
        isp_id=isp.isp_org_id,
        subscriber_id=sub.id,
        kind="mac_bound",
        detail=f"{b.mac} cleared",
    )
    await db.commit()
    return ok(request, {"id": str(b.id), "deleted": True}, "MAC binding cleared")


# --------------------------------------------------------------------------
# Enforcement timeline
# --------------------------------------------------------------------------


@enforcement_router.get(
    "/subscribers/{subscriber_id}/enforcement-events",
    dependencies=isp_guards(SUBS_READ),
)
async def list_enforcement_events(
    request: Request,
    subscriber_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=200),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    rows = (
        await db.execute(
            select(IspEnforcementEvent)
            .where(IspEnforcementEvent.subscriber_id == sub.id)
            .order_by(IspEnforcementEvent.occurred_at.desc())
            .limit(limit)
        )
    ).scalars()
    return ok(
        request,
        [
            {
                "id": str(e.id),
                "kind": e.kind,
                "detail": e.detail,
                "session_id": str(e.session_id) if e.session_id else None,
                "occurred_at": e.occurred_at.isoformat(),
            }
            for e in rows
        ],
        "Enforcement events",
    )


# --------------------------------------------------------------------------
# Static IP (J8)
# --------------------------------------------------------------------------


def _pool_hosts(pool: Any) -> list[ipaddress.IPv4Address] | None:
    try:
        a = ipaddress.ip_address(pool.address_range_start)
        b = ipaddress.ip_address(pool.address_range_end)
    except ValueError:
        return None
    if a.version != 4 or b.version != 4 or int(b) < int(a) or int(b) - int(a) > 65535:
        return None
    return [ipaddress.IPv4Address(i) for i in range(int(a), int(b) + 1)]


async def _pools(db: AsyncSession, location_id: uuid.UUID) -> list[Any]:
    from app.domains.dhcp.models import DhcpPool

    return list(
        (
            await db.execute(
                select(DhcpPool).where(
                    DhcpPool.location_id == location_id,
                    DhcpPool.is_deleted.is_(False),
                )
            )
        ).scalars()
    )


async def _taken(db: AsyncSession, location_id: uuid.UUID) -> set[str]:
    return set(
        (
            await db.execute(
                select(IspSubscriberIpBinding.ip).where(
                    IspSubscriberIpBinding.location_id == location_id,
                    IspSubscriberIpBinding.is_deleted.is_(False),
                )
            )
        ).scalars()
    )


def _next_free(pool: Any, taken: set[str]) -> str | None:
    hosts = _pool_hosts(pool) or []
    skip = set(taken) | {pool.gateway_ip_address or ""}
    for h in hosts:
        s = str(h)
        if s not in skip:
            return s
    return None


@enforcement_router.get(
    "/locations/{isp_location_id}/ip-pools", dependencies=isp_guards(SUBS_READ)
)
async def list_ip_pools(
    request: Request,
    isp_location_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    loc = await IspScope.assert_location(isp, isp_location_id)
    taken = await _taken(db, loc.id)
    out = []
    for p in await _pools(db, loc.id):
        hosts = _pool_hosts(p)
        used = sum(1 for h in hosts or [] if str(h) in taken)
        out.append(
            {
                "id": str(p.id),
                "name": p.name,
                "range_start": p.address_range_start,
                "range_end": p.address_range_end,
                "gateway": p.gateway_ip_address,
                "router_id": str(p.router_id),
                "size": len(hosts) if hosts is not None else None,
                "pinned": used,
                "next_free": _next_free(p, taken),
            }
        )
    return ok(request, out, "IP pools")


async def _pool(db: AsyncSession, loc: Any, pool_id: uuid.UUID) -> Any:
    from app.domains.dhcp.models import DhcpPool

    p = await db.get(DhcpPool, pool_id)
    if p is None or p.is_deleted or p.location_id != loc.id:
        raise IspPoolNotFoundError()
    return p


@enforcement_router.get(
    "/locations/{isp_location_id}/ip-pools/{pool_id}/next-free",
    dependencies=isp_guards(SUBS_READ),
)
async def next_free_ip(
    request: Request,
    isp_location_id: uuid.UUID,
    pool_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    loc = await IspScope.assert_location(isp, isp_location_id)
    pool = await _pool(db, loc, pool_id)
    ip = _next_free(pool, await _taken(db, loc.id))
    if ip is None:
        raise IspPoolExhaustedError()
    return ok(request, {"ip": ip, "pool_id": str(pool.id)}, "Next free IP")


def _ip_view(b: Any) -> dict:
    return {
        "id": str(b.id),
        "ip": b.ip,
        "mac": b.mac,
        "location_id": str(b.location_id),
        "pool_id": str(b.dhcp_pool_id) if b.dhcp_pool_id else None,
        "router_id": str(b.router_id) if b.router_id else None,
        "static_queue": b.static_queue,
        "queue_status": b.queue_status,
        "queue_error": b.queue_error,
    }


@enforcement_router.get(
    "/subscribers/{subscriber_id}/ip-bindings", dependencies=isp_guards(SUBS_READ)
)
async def list_ip_bindings(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    rows = (
        await db.execute(
            select(IspSubscriberIpBinding).where(
                IspSubscriberIpBinding.subscriber_id == sub.id,
                IspSubscriberIpBinding.is_deleted.is_(False),
            )
        )
    ).scalars()
    return ok(request, [_ip_view(b) for b in rows], "Static IPs")


class IpBindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    isp_location_id: uuid.UUID
    pool_id: uuid.UUID
    #: omit to take the next free address in the pool
    ip: str | None = None
    mac: str | None = None
    static_queue: bool = False

    @field_validator("mac")
    @classmethod
    def _mac(cls, v: str | None) -> str | None:
        return None if not v else MacRequest(mac=v).mac


async def _push_static_queue(
    queue_service: Any, binding: Any, sub: Any, db: AsyncSession, actor: uuid.UUID
) -> None:
    """One ``/queue simple`` row for this IP at the package's speed, through
    the existing QueueManagementService (create + apply). Failure is recorded
    on the binding, never raised: the IP pin itself stands."""
    from app.domains.queue_management.constants import QueueTargetType

    from .plans_models import IspPackageMaterialization

    try:
        if binding.router_id is None or sub.package_id is None:
            raise ValueError("needs a router and a package")
        mat = (
            (
                await db.execute(
                    select(IspPackageMaterialization).where(
                        IspPackageMaterialization.package_id == sub.package_id,
                        IspPackageMaterialization.customer_organization_id
                        == sub.customer_organization_id,
                    )
                )
            )
            .scalars()
            .first()
        )
        if mat is None:
            raise ValueError("the package is not set up for this customer yet")
        assignment = await queue_service.create_assignment(
            actor_user_id=actor,
            requesting_organization_id=sub.customer_organization_id,
            target_type=QueueTargetType.DEVICE,
            target_id=binding.id,
            router_id=binding.router_id,
            location_id=binding.location_id,
            device_target=binding.ip,
            queue_profile_id=mat.queue_profile_id,
        )
        binding.queue_assignment_id = assignment.id
        await queue_service.apply_queue(
            assignment.id,
            actor_user_id=actor,
            requesting_organization_id=sub.customer_organization_id,
        )
        binding.queue_status, binding.queue_error = "active", None
    except Exception as exc:  # noqa: BLE001
        binding.queue_status = "failed"
        binding.queue_error = str(exc)[:255]


@enforcement_router.post(
    "/subscribers/{subscriber_id}/ip-bindings",
    status_code=201,
    dependencies=isp_guards(SUBS_UPDATE),
)
async def add_ip_binding(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: IpBindingRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    queue_service=Depends(get_queue_management_service),  # noqa: B008
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    loc = await IspScope.assert_location(isp, payload.isp_location_id)
    if loc.organization_id != sub.customer_organization_id:
        raise IspBadRequestError("That location belongs to another customer")
    pool = await _pool(db, loc, payload.pool_id)
    taken = await _taken(db, loc.id)
    ip = payload.ip
    if ip is None:
        ip = _next_free(pool, taken)
        if ip is None:
            raise IspPoolExhaustedError()
    else:
        hosts = {str(h) for h in _pool_hosts(pool) or []}
        if ip not in hosts:
            raise IspBadRequestError("That address is not inside the pool")
        if ip == pool.gateway_ip_address:
            raise IspBadRequestError("That address is the pool's gateway")
        if ip in taken:
            raise IspIpTakenError()
    b = IspSubscriberIpBinding(
        isp_organization_id=isp.isp_org_id,
        customer_organization_id=sub.customer_organization_id,
        subscriber_id=sub.id,
        location_id=loc.id,
        router_id=pool.router_id,
        dhcp_pool_id=pool.id,
        ip=ip,
        mac=payload.mac,
        static_queue=payload.static_queue,
        queue_status="none",
    )
    db.add(b)
    await db.flush()
    if payload.static_queue:
        await _push_static_queue(queue_service, b, sub, db, isp.user_id)
    await db.commit()
    return ok(request, _ip_view(b), "Static IP pinned")


@enforcement_router.delete(
    "/subscribers/{subscriber_id}/ip-bindings/{binding_id}",
    dependencies=isp_guards(SUBS_UPDATE),
)
async def delete_ip_binding(
    request: Request,
    subscriber_id: uuid.UUID,
    binding_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    queue_service=Depends(get_queue_management_service),  # noqa: B008
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    b = await db.get(IspSubscriberIpBinding, binding_id)
    if b is None or b.is_deleted or b.subscriber_id != sub.id:
        raise IspBindingNotFoundError()
    warning = None
    if b.queue_assignment_id is not None:
        try:
            await queue_service.remove_queue(
                b.queue_assignment_id,
                actor_user_id=isp.user_id,
                requesting_organization_id=sub.customer_organization_id,
            )
        except Exception as exc:  # noqa: BLE001
            warning = f"router queue not removed: {str(exc)[:150]}"
    b.is_deleted, b.deleted_at = True, datetime.now(UTC)
    await db.commit()
    return ok(
        request,
        {"id": str(b.id), "deleted": True, "warning": warning},
        "Static IP released",
    )


__all__ = ["enforcement_router"]
