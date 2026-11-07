"""HTTP surface of speed tiers by WiFi network (SSID).

* ``GET  /locations/{location_id}/ssid-tiers`` -- the venue's SSID -> tier
  mapping, plus a neutral ``speed_status`` (applied / pending /
  not_applicable). Customer-facing: never carries vendor-app steps and
  never calls Instant On (status comes from the last cached live check).
* ``PUT  /locations/{location_id}/ssid-tiers`` -- replace the mapping.
* ``POST /locations/{location_id}/ssid-tiers/apply-speeds`` -- the customer
  (``bandwidth.update`` at ORGANIZATION, like the Usage Limits guest-speed
  write): preview (default) or apply the per-SSID speeds through cloud
  control. Acts only at a NAS-only venue whose cloud-control router is
  NAS-only; every other venue answers ``not_applicable``.
* ``POST /locations/{location_id}/ssid-tiers/instant-on-sync`` -- Master only
  (GLOBAL): preview (default) or push the per-SSID speed caps to Instant On.
  The only response that carries the by-hand steps (``manual_steps``).
* ``POST /guest/ssid-access`` -- the guest portal's question for one session
  on one SSID (unauthenticated, keyed on the session id).

Tenant scoping (the path-id defect class): every location route resolves the
location through ``LocationService.get_location(requesting_organization_id=)``
-- which refuses another tenant's location -- and ``enforce_target_location``
against the location the permission check ran at, and then reads and writes
with the LOCATION ROW's organization, never a header or body value.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import build_response
from app.core.config import get_settings
from app.database.redis import get_redis_client
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
    get_rbac_repository,
)
from app.domains.rbac.enums import ScopeType

from .dependencies import get_ssid_tier_service
from .ssid_tier_instant_on import (
    CustomerSpeedStatus,
    SpeedStatusCache,
    customer_apply_ssid_tier_speeds,
    customer_cached_speed_status,
    sync_ssid_tiers_to_instant_on,
)
from .ssid_tier_service import SsidTierInput, SsidTierService
from .ssid_tiers import MAX_SSID_LENGTH, MAX_TIER_MBPS, MIN_TIER_MBPS, SsidTierRule

_PLATFORM_UPDATE = RequirePermission(
    "network_integrations.update", scope=ScopeType.GLOBAL
)
# Scopes pinned, never inferred from the caller's headers (the scope-inference
# trap). LOCATION: an organization grant covers it for that organization, a
# location grant for that location; ``_scoped_location`` then holds the path
# id to the header location.
_TIERS_READ = RequirePermission("policy.read", scope=ScopeType.LOCATION)
_TIERS_UPDATE = RequirePermission("policy.update", scope=ScopeType.LOCATION)
# Same key and scope as the customer Usage Limits Instant On speed write
# (``instant_on_router._CUSTOMER_SPEED_UPDATE``).
_CUSTOMER_SPEED_UPDATE = RequirePermission(
    "bandwidth.update", scope=ScopeType.ORGANIZATION
)

logger = logging.getLogger(__name__)

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


def _payload(rules: list[SsidTierRule], speed_status: dict[str, Any]) -> dict[str, Any]:
    """Customer payload. No ``instant_on_manual_steps``: the by-hand steps
    live on the Master sync response only (owner rule 2026-11-07)."""
    return {
        "items": [_item(rule) for rule in rules],
        "note": ONE_SPEED_PER_NETWORK,
        "speed_status": speed_status,
        "instant_on_push_enabled": get_settings().instant_on_ssid_tier_push_enabled,
    }


async def _speed_status(
    db: AsyncSession, location: Any, rules: list[SsidTierRule], redis: Any
) -> dict[str, Any]:
    """Settings + database + the cached last live check. Never an Instant On
    call: a page load must not spend Instant On's rate budget or token
    refreshes (those are shared with the Master's block/unblock)."""
    status_ = await customer_cached_speed_status(
        db,
        organization_id=location.organization_id,
        location_id=location.id,
        rules=rules,
        settings=get_settings(),
        cache=SpeedStatusCache(redis),
    )
    return status_.as_dict()


async def _audit_apply(
    audit_writer: Any,
    *,
    user: AuthUser,
    location: Any,
    result: CustomerSpeedStatus,
) -> None:
    """Same shape as the other customer-visible writes' audit rows."""
    await audit_writer.create_audit_log_entry(
        actor_user_id=uuid.UUID(str(user.id)),
        action="ssid_tier_speeds.apply",
        entity_type="location",
        entity_id=location.id,
        description=f"Speeds by WiFi network applied: {result.status}",
        organization_id=location.organization_id,
        location_id=location.id,
        event_metadata={
            "status": result.status,
            "reason": result.reason,
            "items": [
                {
                    "ssid": i.ssid,
                    "download_mbps": i.download_mbps,
                    "upload_mbps": i.upload_mbps,
                    "status": i.status,
                    "reason": i.reason,
                }
                for i in result.items
            ],
        },
    )


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
    dependencies=[Depends(_TIERS_READ)],
)
async def list_ssid_tiers(
    request: Request,
    location_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    scope_location_id: uuid.UUID | None = Depends(CurrentLocation),
    location_service: LocationService = Depends(get_location_service),
    service: SsidTierService = Depends(get_ssid_tier_service),
    db: AsyncSession = Depends(get_db_session),
    redis: Any = Depends(get_redis_client),
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
        data=_payload(rules, await _speed_status(db, location, rules, redis)),
        request_id=_request_id(request),
    )


@ssid_tier_router.put(
    "/locations/{location_id}/ssid-tiers",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(_TIERS_UPDATE)],
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
    db: AsyncSession = Depends(get_db_session),
    redis: Any = Depends(get_redis_client),
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
        data=_payload(rules, await _speed_status(db, location, rules, redis)),
        request_id=_request_id(request),
    )


@ssid_tier_router.post(
    "/locations/{location_id}/ssid-tiers/apply-speeds",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(_CUSTOMER_SPEED_UPDATE)],
)
async def apply_ssid_tier_speeds(
    request: Request,
    location_id: uuid.UUID,
    payload: SsidTierSyncRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    scope_location_id: uuid.UUID | None = Depends(CurrentLocation),
    location_service: LocationService = Depends(get_location_service),
    service: SsidTierService = Depends(get_ssid_tier_service),
    db: AsyncSession = Depends(get_db_session),
    redis: Any = Depends(get_redis_client),
    audit_writer: Any = Depends(get_rbac_repository),
):
    """Customer: preview (default) or, with ``dry_run: false``, apply the
    venue's per-network speeds through cloud control -- the same sync the
    Master runs. Answers a neutral ``applied`` / ``pending`` /
    ``not_applicable`` and never vendor-app steps. ``not_applicable`` (and
    nothing read or written) unless the venue is NAS-only and its
    cloud-control router is NAS-only; ``pending`` / ``awaiting_setup`` while
    the push flag or the router's cloud control is off. The only customer
    path that talks to Instant On; its live answer is cached for GET/PUT.
    ``dry_run: false`` writes an audit row."""
    location = await _scoped_location(
        location_id, requesting_organization_id, scope_location_id, location_service
    )
    rules = await service.list_rules(
        organization_id=location.organization_id, location_id=location.id
    )
    result = await customer_apply_ssid_tier_speeds(
        db,
        organization_id=location.organization_id,
        location_id=location.id,
        rules=rules,
        dry_run=payload.dry_run,
        settings=get_settings(),
        cache=SpeedStatusCache(redis),
    )
    if not payload.dry_run:
        await _audit_apply(audit_writer, user=user, location=location, result=result)
        logger.info(
            "ssid_tier_customer_apply",
            extra={
                "organization_id": str(location.organization_id),
                "location_id": str(location.id),
                "actor_user_id": str(user.id),
                "status": result.status,
                "reason": result.reason,
            },
        )
    return build_response(
        success=True,
        message="Speeds by WiFi network",
        data=result.as_dict(),
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
