"""P1-1: device count + MAC binding on speed templates.

Flag ``ISP_TEMPLATE_RULES_ENABLED`` (default OFF -> 404). Keys: the existing
``isp_plans.read`` / ``isp_plans.update`` (owner/admin only write; confined
roles read). Path ids are ``speed_group_id`` (never a scope-alias name).

* ``GET /speed-group-device-rules`` -> every template's rules for this ISP,
  so the package form can pre-fill from the picked template in one call.
* ``GET|PUT /speed-groups/{speed_group_id}/device-rules``.
* ``POST /speed-groups/{speed_group_id}/device-rules/apply`` with
  ``{"dry_run": true}`` (the default) lists what would change on each live
  package using the template; ``{"dry_run": false}`` writes it.

"Apply" writes the same fields the package form writes: ``isp_packages.
max_devices`` and the package policy's ``mac_bind_count``, ``mac_restriction``,
``max_simultaneous``. Every other policy field is left as it is. Enforcement
reads those fields exactly as before; this table is never read by it.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .dependencies import IspContext, RequireIspPartner, isp_guards
from .enforcement_models import IspPackagePolicy
from .exceptions import IspBadRequestError, IspFeatureDisabledError
from .http import ok
from .p1_config import get_p1_settings
from .p1_models import IspSpeedGroupDeviceRules
from .plans_models import IspPackage, IspSpeedGroup
from .plans_service import IspSpeedGroupNotFoundError

__all__ = ["RULE_FIELDS", "p1_templates_router"]

PLANS_READ, PLANS_UPDATE = "isp_plans.read", "isp_plans.update"
RULE_FIELDS = ("max_devices", "mac_bind_count", "mac_restriction", "max_simultaneous")
_POLICY_RULE_FIELDS = ("mac_bind_count", "mac_restriction", "max_simultaneous")
#: what a package policy row holds for these fields when it does not exist
_POLICY_DEFAULTS: dict[str, Any] = {
    "mac_bind_count": 0,
    "mac_restriction": False,
    "max_simultaneous": None,
}


async def RequireTemplateRulesEnabled() -> None:
    if not get_p1_settings().template_rules_enabled:
        raise IspFeatureDisabledError()


p1_templates_router = APIRouter(
    tags=["ISP Partner: speed template device rules"],
    dependencies=[Depends(RequireTemplateRulesEnabled)],
)


class DeviceRulesRequest(BaseModel):
    """Same bounds as the package form (``max_devices``) and ``PolicyRequest``."""

    model_config = ConfigDict(extra="forbid")
    max_devices: int = Field(default=1, ge=1, le=50)
    mac_bind_count: int = Field(default=0, ge=0, le=16)
    mac_restriction: bool = False
    max_simultaneous: int | None = Field(default=None, ge=1, le=64)


class ApplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dry_run: bool = True


def rules_view(group_id: uuid.UUID, row: Any) -> dict:
    data: dict[str, Any] = {
        "speed_group_id": str(group_id),
        "configured": row is not None,
    }
    for f in RULE_FIELDS:
        data[f] = (
            getattr(row, f)
            if row is not None
            else DeviceRulesRequest.model_fields[f].default
        )
    return data


def validate_rules(data: dict) -> None:
    """Combinations the evaluator cannot honour are refused up front."""
    if data["mac_restriction"] and data["mac_bind_count"] < 1:
        raise IspBadRequestError(
            "MAC restriction needs at least one bound device (bind the first N devices)"
        )
    if (
        data["max_simultaneous"] is not None
        and data["max_simultaneous"] > data["max_devices"]
    ):
        raise IspBadRequestError(
            "Devices online at once cannot exceed the device limit"
        )


def package_changes(package: Any, policy: Any, rules: Any) -> dict[str, dict]:
    """``{field: {"from": old, "to": new}}`` for every field that would move."""
    changes: dict[str, dict] = {}
    if package.max_devices != rules.max_devices:
        changes["max_devices"] = {"from": package.max_devices, "to": rules.max_devices}
    for f in _POLICY_RULE_FIELDS:
        old = getattr(policy, f) if policy is not None else _POLICY_DEFAULTS[f]
        new = getattr(rules, f)
        if old != new:
            changes[f] = {"from": old, "to": new}
    return changes


async def _group(db: AsyncSession, isp: IspContext, group_id: uuid.UUID) -> Any:
    g = await db.get(IspSpeedGroup, group_id)
    if g is None or g.is_deleted or g.isp_organization_id != isp.isp_org_id:
        raise IspSpeedGroupNotFoundError()
    return g


async def _rules(db: AsyncSession, group_id: uuid.UUID) -> Any:
    return (
        await db.execute(
            select(IspSpeedGroupDeviceRules).where(
                IspSpeedGroupDeviceRules.speed_group_id == group_id,
                IspSpeedGroupDeviceRules.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


@p1_templates_router.get(
    "/speed-group-device-rules", dependencies=isp_guards(PLANS_READ)
)
async def list_device_rules(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    rows = (
        (
            await db.execute(
                select(IspSpeedGroupDeviceRules)
                .join(
                    IspSpeedGroup,
                    IspSpeedGroup.id == IspSpeedGroupDeviceRules.speed_group_id,
                )
                .where(
                    IspSpeedGroupDeviceRules.isp_organization_id == isp.isp_org_id,
                    IspSpeedGroupDeviceRules.is_deleted.is_(False),
                    IspSpeedGroup.is_deleted.is_(False),
                )
            )
        )
        .scalars()
        .all()
    )
    return ok(
        request,
        {"items": [rules_view(r.speed_group_id, r) for r in rows]},
        "Template device rules",
    )


@p1_templates_router.get(
    "/speed-groups/{speed_group_id}/device-rules", dependencies=isp_guards(PLANS_READ)
)
async def get_device_rules(
    request: Request,
    speed_group_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    g = await _group(db, isp, speed_group_id)
    return ok(
        request, rules_view(g.id, await _rules(db, g.id)), "Template device rules"
    )


@p1_templates_router.put(
    "/speed-groups/{speed_group_id}/device-rules",
    dependencies=isp_guards(PLANS_UPDATE),
)
async def put_device_rules(
    request: Request,
    speed_group_id: uuid.UUID,
    payload: DeviceRulesRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    g = await _group(db, isp, speed_group_id)
    data = payload.model_dump()
    validate_rules(data)
    row = await _rules(db, g.id)
    if row is None:
        row = IspSpeedGroupDeviceRules(
            isp_organization_id=isp.isp_org_id,
            speed_group_id=g.id,
            created_by=isp.user_id,
        )
        db.add(row)
    for f, v in data.items():
        setattr(row, f, v)
    row.updated_by = isp.user_id
    await db.flush()
    await db.commit()
    return ok(request, rules_view(g.id, row), "Template device rules saved")


async def _packages_using(
    db: AsyncSession, isp: IspContext, group_id: uuid.UUID
) -> list:
    return list(
        (
            await db.execute(
                select(IspPackage)
                .where(
                    IspPackage.isp_organization_id == isp.isp_org_id,
                    IspPackage.speed_group_id == group_id,
                    IspPackage.is_deleted.is_(False),
                )
                .order_by(IspPackage.name, IspPackage.id)
            )
        )
        .scalars()
        .all()
    )


async def _policies(db: AsyncSession, package_ids: list[uuid.UUID]) -> dict:
    if not package_ids:
        return {}
    rows = (
        (
            await db.execute(
                select(IspPackagePolicy).where(
                    IspPackagePolicy.package_id.in_(package_ids),
                    IspPackagePolicy.is_deleted.is_(False),
                )
            )
        )
        .scalars()
        .all()
    )
    return {r.package_id: r for r in rows}


@p1_templates_router.post(
    "/speed-groups/{speed_group_id}/device-rules/apply",
    dependencies=isp_guards(PLANS_UPDATE),
)
async def apply_device_rules(
    request: Request,
    speed_group_id: uuid.UUID,
    payload: ApplyRequest | None = None,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    dry_run = True if payload is None else payload.dry_run
    g = await _group(db, isp, speed_group_id)
    rules = await _rules(db, g.id)
    if rules is None:
        raise IspBadRequestError("Save the template's device rules first")
    packages = await _packages_using(db, isp, g.id)
    policies = await _policies(db, [p.id for p in packages])
    items: list[dict] = []
    for p in packages:
        changes = package_changes(p, policies.get(p.id), rules)
        items.append(
            {
                "package_id": str(p.id),
                "name": p.name,
                "status": p.status,
                "changes": changes,
            }
        )
        if dry_run or not changes:
            continue
        if "max_devices" in changes:
            p.max_devices = rules.max_devices
        policy_moves = [f for f in _POLICY_RULE_FIELDS if f in changes]
        if policy_moves:
            policy = policies.get(p.id)
            if policy is None:
                # Same insert the package Network rules form makes; every other
                # field keeps its server default (= "no rule", as with no row).
                policy = IspPackagePolicy(
                    isp_organization_id=isp.isp_org_id, package_id=p.id
                )
                db.add(policy)
            for f in policy_moves:
                setattr(policy, f, getattr(rules, f))
    if not dry_run:
        await db.flush()
        await db.commit()
    return ok(
        request,
        {
            "speed_group_id": str(g.id),
            "dry_run": dry_run,
            "rules": rules_view(g.id, rules),
            "packages": items,
            "would_change": sum(1 for i in items if i["changes"]),
            "unchanged": sum(1 for i in items if not i["changes"]),
        },
        "Preview" if dry_run else "Template device rules applied",
    )
