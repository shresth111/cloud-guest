"""HTTP surface of speed tiers by WiFi network (SSID).

* ``GET  /locations/{location_id}/ssid-tiers`` -- the venue's SSID -> tier
  mapping, plus what to set in Instant On by hand.
* ``PUT  /locations/{location_id}/ssid-tiers`` -- replace the mapping.
* ``POST /locations/{location_id}/ssid-tiers/instant-on-sync`` -- Master only
  (GLOBAL): preview (default) or push the per-SSID speed caps to Instant On.
* ``POST /guest/ssid-access`` -- the guest portal's question for one session
  on one SSID (unauthenticated, keyed on the session id).

Tenant scoping (the path-id defect class): every location route resolves the
location through ``LocationService.get_location(requesting_organization_id=)``
-- which refuses another tenant's location -- and ``enforce_target_location``
against the location the permission check ran at, and then reads and writes
with the LOCATION ROW's organization, never a header or body value.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import build_response
from app.core.config import get_settings
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.location.dependencies import get_location_service
from app.domains.location.scoping import enforce_target_location
from app.domains.location.service import LocationService
from app.domains.rbac.dependencies import (
    CurrentLocation,
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .dependencies import get_ssid_tier_service
from .ssid_tier_instant_on import sync_ssid_tiers_to_instant_on
from .ssid_tier_service import (
    SsidTierInput,
    SsidTierService,
    instant_on_manual_steps,
)
from .ssid_tiers import MAX_SSID_LENGTH, MAX_TIER_MBPS, MIN_TIER_MBPS, SsidTierRule

_PLATFORM_UPDATE = RequirePermission(
    "network_integrations.update", scope=ScopeType.GLOBAL
)

ssid_tier_router = APIRouter(tags=["Speed tiers by WiFi network"])
ssid_tier_guest_router = APIRouter(prefix="/guest", tags=["Guest"])

#: The honest one-liner the UI repeats.
ONE_SPEED_PER_NETWORK = (
    "Each WiFi network has one speed for all its guests. Aruba Instant On "
    "cannot give one guest a different speed from another on the same network."
)


class SsidTierItem(BaseModel):
    ssid: str = Field(min_length=1, max_length=MAX_SSID_LENGTH)
    tier_name: str = Field(min_length=1, max_length=100)
    requires_entitlement: bool = False
    policy_id: uuid.UUID | None = None
    voucher_plan_ids: list[uuid.UUID] = Field(default_factory=list, max_length=20)
    download_mbps: int | None = Field(default=None, ge=MIN_TIER_MBPS, le=MAX_TIER_MBPS)
    upload_mbps: int | None = Field(default=None, ge=MIN_TIER_MBPS, le=MAX_TIER_MBPS)


class SsidTierReplaceRequest(BaseModel):
    items: list[SsidTierItem] = Field(default_factory=list, max_length=8)


class SsidTierSyncRequest(BaseModel):
    dry_run: bool = True


class GuestSsidAccessRequest(BaseModel):
    session_id: uuid.UUID
    ssid: str | None = Field(default=None, max_length=64)


def _item(rule: SsidTierRule) -> dict[str, Any]:
    return {
        "ssid": rule.ssid,
        "tier_name": rule.tier_name,
        "requires_entitlement": rule.requires_entitlement,
        "policy_id": str(rule.policy_id) if rule.policy_id else None,
        "voucher_plan_ids": [str(p) for p in rule.voucher_plan_ids],
        "download_mbps": rule.download_mbps,
        "upload_mbps": rule.upload_mbps,
    }


def _payload(rules: list[SsidTierRule]) -> dict[str, Any]:
    return {
        "items": [_item(rule) for rule in rules],
        "note": ONE_SPEED_PER_NETWORK,
        "instant_on_manual_steps": instant_on_manual_steps(rules),
        "instant_on_push_enabled": get_settings().instant_on_ssid_tier_push_enabled,
    }


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


async def _scoped_location(
    location_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None,
    scope_location_id: uuid.UUID | None,
    location_service: LocationService,
):  # noqa: ANN202 -- Location
    enforce_target_location(
        target_location_id=location_id,
        scope_location_id=scope_location_id,
        requesting_organization_id=requesting_organization_id,
    )
    return await location_service.get_location(
        location_id, requesting_organization_id=requesting_organization_id
    )


@ssid_tier_router.get(
    "/locations/{location_id}/ssid-tiers",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("policy.read"))],
)
async def list_ssid_tiers(
    request: Request,
    location_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    scope_location_id: uuid.UUID | None = Depends(CurrentLocation),
    location_service: LocationService = Depends(get_location_service),
    service: SsidTierService = Depends(get_ssid_tier_service),
):
    location = await _scoped_location(
        location_id, requesting_organization_id, scope_location_id, location_service
    )
    rules = await service.list_rules(
        organization_id=location.organization_id, location_id=location.id
    )
    return build_response(
        success=True,
        message="Speed tiers by WiFi network",
        data=_payload(rules),
        request_id=_request_id(request),
    )


@ssid_tier_router.put(
    "/locations/{location_id}/ssid-tiers",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("policy.update"))],
)
async def replace_ssid_tiers(
    request: Request,
    location_id: uuid.UUID,
    payload: SsidTierReplaceRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    scope_location_id: uuid.UUID | None = Depends(CurrentLocation),
    location_service: LocationService = Depends(get_location_service),
    service: SsidTierService = Depends(get_ssid_tier_service),
):
    location = await _scoped_location(
        location_id, requesting_organization_id, scope_location_id, location_service
    )
    rules = await service.replace(
        organization_id=location.organization_id,
        location_id=location.id,
        items=[
            SsidTierInput(
                ssid=item.ssid,
                tier_name=item.tier_name,
                requires_entitlement=item.requires_entitlement,
                policy_id=item.policy_id,
                voucher_plan_ids=tuple(item.voucher_plan_ids),
                download_mbps=item.download_mbps,
                upload_mbps=item.upload_mbps,
            )
            for item in payload.items
        ],
        actor_user_id=uuid.UUID(str(user.id)),
    )
    return build_response(
        success=True,
        message="Speed tiers by WiFi network saved",
        data=_payload(rules),
        request_id=_request_id(request),
    )


@ssid_tier_router.post(
    "/locations/{location_id}/ssid-tiers/instant-on-sync",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(_PLATFORM_UPDATE)],
)
async def sync_ssid_tiers(
    request: Request,
    location_id: uuid.UUID,
    payload: SsidTierSyncRequest,
    location_service: LocationService = Depends(get_location_service),
    service: SsidTierService = Depends(get_ssid_tier_service),
    db: AsyncSession = Depends(get_db_session),
):
    """Master only. Preview by default; ``dry_run: false`` writes each mapped
    SSID's cap to Instant On (read back per SSID). Closed gates answer
    ``status: manual`` with the steps for the owner."""
    location = await location_service.get_location(
        location_id, requesting_organization_id=None
    )
    rules = await service.list_rules(
        organization_id=location.organization_id, location_id=location.id
    )
    result = await sync_ssid_tiers_to_instant_on(
        db,
        organization_id=location.organization_id,
        location_id=location.id,
        rules=rules,
        dry_run=payload.dry_run,
        settings=get_settings(),
    )
    return build_response(
        success=True,
        message="Instant On speed caps",
        data=result.as_dict(),
        request_id=_request_id(request),
    )


@ssid_tier_guest_router.post("/ssid-access", status_code=status.HTTP_200_OK)
async def guest_ssid_access(
    request: Request,
    payload: GuestSsidAccessRequest,
    service: SsidTierService = Depends(get_ssid_tier_service),
):
    """Guest-facing, unauthenticated, keyed on the guest's own session id
    (the credential ``/guest/set-password`` already uses). Answers, for the
    SSID the AP put in its redirect (``network``): is this a paid network,
    may this guest join it, and which paid networks their pass opens. ``data``
    is ``null`` for an unknown session."""
    ssid = (payload.ssid or "").strip() or None
    access = await service.guest_access(session_id=payload.session_id, ssid=ssid)
    data = None
    if access is not None:
        data = {
            "ssid": access.ssid,
            "mapped": access.mapped,
            "requires_entitlement": access.requires_entitlement,
            "entitled": access.entitled,
            "tier_name": access.tier_name,
            "download_mbps": access.download_mbps,
            "upload_mbps": access.upload_mbps,
            "upgrade_networks": [
                {
                    "ssid": r.ssid,
                    "tier_name": r.tier_name,
                    "download_mbps": r.download_mbps,
                }
                for r in access.upgrade_networks
            ],
            "paid_networks": [
                {
                    "ssid": r.ssid,
                    "tier_name": r.tier_name,
                    "download_mbps": r.download_mbps,
                }
                for r in access.paid_networks
            ],
        }
    return build_response(
        success=True,
        message="WiFi network access",
        data=data,
        request_id=_request_id(request),
    )


__all__ = ["ONE_SPEED_PER_NETWORK", "ssid_tier_guest_router", "ssid_tier_router"]
