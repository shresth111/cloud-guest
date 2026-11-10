"""PROV-FIX routes: the partner "Generate setup script" path and self-serve
monitoring (QA_IPLOGS_SELFSERVE.md D1 / D4).

``ISP_PROV_FIX_ENABLED`` (default OFF): every route answers 404
``ISP_PROV_FIX_DISABLED`` while off, and the partner console then behaves
exactly as before (the FE probe turns the 404 into "not available").

* ``GET  /isp/setup-fixes`` -- the probe. Lists what this build offers.
* ``POST /isp/routers/{isp_router_id}/setup/check-in`` -- D1. The partner
  twin of ``POST /routers/provisioning/check-in``. A brand-new router has no
  management-connection peer, so the original's ``create_tunnel`` path would
  write a platform-generated keypair the hub agent cannot learn
  (``HubCannotLearnPlatformKeyError``, 409). Verified on wyfy-isp-test
  2026-11-10: its agent (``/usr/local/sbin/wg_agent.py``, sha256 1e9deadc...,
  identical to ``ops/hub-agents/wg_agent.py``) has only ``POST /wg/peer``
  with an empty body (generates its own pair), ``GET /wg/peers`` and
  ``DELETE /wg/peer``. So, when the hub cannot register keys and the router
  has no live peer, this twin first allocates through the hub bridge (the
  same ``allocate_tunnel_via_hub`` the allocate-external twin uses), then
  runs the ORIGINAL check-in handler, which now finds the peer and leaves it
  alone. The allocation body is returned as ``management_connection`` so the
  console does not allocate a second time. Any remaining "hub cannot learn
  the key" refusal becomes ``ISP_MANAGEMENT_CONNECTION_NOT_READY`` with copy
  an ISP user can act on.
* ``GET  /isp/routers/{isp_router_id}/monitoring`` -- D4: is traffic
  monitoring on for this router, and when was it last read.
* ``POST /isp/routers/{isp_router_id}/monitoring/enable`` and ``/disable`` --
  D4: the ISP owner/admin switches monitoring on for their own router. The
  same ``RouterSnmpService.update_config`` + ``apply_to_device`` the Master
  console uses; a per-router read-only community is minted when the router
  has none. A failed write to the router rolls the switch back.

Scope: ``IspScope.assert_router`` (another ISP's router, or one outside a
confined user's customers / zone = 404). Path ids are ``isp_router_id``.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router import router as router_routes
from app.domains.router.dependencies import get_router_service
from app.domains.router.schemas import ProvisioningCheckInRequest
from app.domains.router.service import RouterService, _hash_token
from app.domains.router.snmp import (
    RouterSnmpService,
    SnmpConfigInvalidError,
    SnmpDeviceUnreachableError,
    SnmpNotConfiguredError,
)
from app.domains.router_agent.dependencies import get_router_agent_service
from app.domains.router_agent.service import RouterAgentService
from app.domains.wireguard import router as wireguard_routes
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.exceptions import HubCannotLearnPlatformKeyError
from app.domains.wireguard.service import WireGuardService

from .constants import (
    ISP_PARTNER_EXECUTE,
    ISP_PARTNER_READ,
    SETUP_SCRIPT_ROLES,
    IspRole,
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .enforcement_models import IspPackagePolicy
from .exceptions import IspSetupNotAllowedError, _err
from .http import ok
from .plans_models import IspPackage
from .plans_router import PLANS_READ
from .scoping import IspScope

AUDIT_PREFIX = "isp_router_setup_"
#: Who may switch monitoring on or off (D4): the ISP's owner and admin.
MONITORING_ROLES: frozenset[str] = frozenset({IspRole.OWNER, IspRole.ADMIN})


class IspProvFixSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    prov_fix_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_prov_fix_settings() -> IspProvFixSettings:
    return IspProvFixSettings()


IspProvFixDisabledError = _err(
    "IspProvFixDisabledError", "ISP_PROV_FIX_DISABLED", 404, "Not Found"
)
IspManagementConnectionNotReadyError = _err(
    "IspManagementConnectionNotReadyError",
    "ISP_MANAGEMENT_CONNECTION_NOT_READY",
    409,
    "We could not prepare the management connection for this router, so no "
    "setup script was made. Nothing was changed. Try Generate again in a "
    "minute; if it keeps happening, contact Wyfy Guest support.",
)
IspSetupTokenMismatchError = _err(
    "IspSetupTokenMismatchError",
    "ISP_SETUP_TOKEN_MISMATCH",
    409,
    "This setup code belongs to a different router. Close the page and press "
    "Generate again on the router you are setting up.",
)
IspMonitoringNotAllowedError = _err(
    "IspMonitoringNotAllowedError",
    "ISP_MONITORING_NOT_ALLOWED",
    403,
    "Only an ISP owner or admin can switch monitoring on or off.",
)
IspMonitoringUnavailableError = _err(
    "IspMonitoringUnavailableError",
    "ISP_MONITORING_UNAVAILABLE",
    409,
    "Traffic monitoring is not available for this router yet. Contact Wyfy "
    "Guest support.",
)
IspMonitoringRouterUnreachableError = _err(
    "IspMonitoringRouterUnreachableError",
    "ISP_MONITORING_ROUTER_UNREACHABLE",
    502,
    "We could not reach the router. Check it is online and that Read now works "
    "on its page, then try again. If Read now fails, generate the setup script "
    "again and paste all of it.",
)


async def RequireProvFixEnabled() -> None:
    if not get_prov_fix_settings().prov_fix_enabled:
        raise IspProvFixDisabledError()


prov_fix_router = APIRouter(tags=["ISP Partner: router setup fixes"])
_ON = [Depends(RequireProvFixEnabled)]


async def _audit(
    audit: RBACRepositoryProtocol,
    isp: IspContext,
    router: Any,
    action: str,
    **extra: Any,
) -> None:
    await audit.create_audit_log_entry(
        actor_user_id=isp.user_id,
        action=f"{AUDIT_PREFIX}{action}",
        entity_type="router",
        entity_id=router.id,
        description=f"ISP router setup: {action.replace('_', ' ')}",
        event_metadata={
            "console": "isp",
            "isp_organization_id": str(isp.isp_org_id),
            "role": isp.role_slug,
            **extra,
        },
        organization_id=router.organization_id,
        location_id=router.location_id,
    )


@prov_fix_router.get("/setup-fixes", dependencies=[*_ON, *isp_guards(ISP_PARTNER_READ)])
async def setup_fixes(request: Request) -> dict:
    return ok(
        request,
        {
            "check_in_fallback": True,
            "api_access_always_on_fresh_router": True,
            "in_app_choices": True,
            "heartbeat_reports_version": True,
            "monitoring_self_serve": True,
            "package_policy_summaries": True,
        },
        "Setup fixes",
    )


# ---------------------------------------------------------------------------
# D1: check-in with the hub-allocation fallback
# ---------------------------------------------------------------------------


class IspSetupCheckInRequest(BaseModel):
    token: str = Field(min_length=1, max_length=512)


def _needs_hub_allocation(peer: Any, settings: Settings) -> bool:
    if settings.hub_wg_agent_supports_key_registration:
        return False
    return peer is None or peer.is_revoked()


@prov_fix_router.post(
    "/routers/{isp_router_id}/setup/check-in",
    dependencies=[*_ON, *isp_guards(ISP_PARTNER_EXECUTE)],
)
async def setup_check_in(
    request: Request,
    isp_router_id: uuid.UUID,
    payload: IspSetupCheckInRequest,
    isp: IspContext = Depends(RequireIspPartner),
    router_service: RouterService = Depends(get_router_service),
    agent_service: RouterAgentService = Depends(get_router_agent_service),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> dict:
    if isp.role_slug not in SETUP_SCRIPT_ROLES:
        raise IspSetupNotAllowedError()
    target = await IspScope.assert_router(isp, isp_router_id)

    # The token must be this router's, checked BEFORE anything is allocated:
    # a hub allocation cannot be undone.
    token = await router_service.repository.get_provisioning_token_by_hash(
        _hash_token(payload.token)
    )
    if token is not None and token.router_id != target.id:
        raise IspSetupTokenMismatchError()

    management_connection: dict | None = None
    peer = await wireguard_service.repository.get_peer_by_router_id(target.id)
    if token is not None and _needs_hub_allocation(peer, settings):
        try:
            allocation = await wireguard_routes.allocate_external_wireguard_peer(
                request,
                router_id=target.id,
                rotate=False,
                force=False,
                user=_ActingUser(isp.user_id),
                requesting_organization_id=target.organization_id,
                service=wireguard_service,
            )
        except HubCannotLearnPlatformKeyError:
            raise IspManagementConnectionNotReadyError() from None
        except Exception as exc:  # noqa: BLE001 -- hub bridge down etc.
            raise IspManagementConnectionNotReadyError(
                reason=type(exc).__name__
            ) from None
        management_connection = allocation["data"]

    try:
        checked_in = await router_routes.provisioning_check_in(
            ProvisioningCheckInRequest(token=payload.token),
            router_service=router_service,
            agent_service=agent_service,
            wireguard_service=wireguard_service,
        )
    except HubCannotLearnPlatformKeyError:
        raise IspManagementConnectionNotReadyError() from None

    await _audit(
        audit,
        isp,
        target,
        "check_in",
        allocated_management_connection=management_connection is not None,
    )
    data = checked_in.model_dump(mode="json")
    data["management_connection"] = management_connection
    return ok(request, data, "Router checked in")


class _ActingUser:
    """The ``AuthUser``-shaped object the original allocate handler reads
    ``.id`` from (it only ever uses ``uuid.UUID(user.id)``)."""

    def __init__(self, user_id: uuid.UUID) -> None:
        self.id = str(user_id)


# ---------------------------------------------------------------------------
# D4: self-serve traffic monitoring
# ---------------------------------------------------------------------------


def _snmp_service(
    router_service: RouterService = Depends(get_router_service),
    settings: Settings = Depends(get_settings),
) -> RouterSnmpService:
    return RouterSnmpService(router_service, settings=settings)


#: [POSTFIX-1] D10. Read-back "mismatches" that are only RouterOS's boolean
#: spelling. librouteros parses ``read-access=yes`` / ``write-access=no`` into
#: Python ``True`` / ``False`` (measured on CHR 7.25.1, 2026-11-10), while
#: ``mikrotik_snmp._compare`` compares ``str(actual)`` with the desired
#: ``"yes"`` / ``"no"``. So every real router reads back "NOT verified" and
#: enable answered 502 ISP_MONITORING_ROUTER_UNREACHABLE although the write
#: had landed. The same read-back's ``state`` judges these two fields
#: correctly (``community_read_only``, via ``_truthy``). Partner path only;
#: the shared writer is not changed here.
_BOOL_SPELLING_MISMATCHES: frozenset[str] = frozenset(
    {"community:read-access", "community:write-access"}
)


def _monitoring_read_back_ok(outcome: Any) -> bool:
    """True when the device holds what enable asked for. ``verified`` as
    reported, or every mismatch is a boolean spelling AND the read-back
    state shows the agent on and our community present, enabled and
    read-only. Any other mismatch (addresses, security, duplicate, public
    fence, agent off) still fails.

    MASTER-FIX (2026-11-10): the shared ``mikrotik_snmp._compare`` now reads
    RouterOS booleans by meaning, so a real router reports ``verified`` and
    the fallback below is no longer reached. Kept as a harmless guard for a
    gateway build without that fix."""
    if outcome.verified:
        return True
    mismatches = set(getattr(outcome, "mismatches", None) or ())
    if not mismatches or not mismatches <= _BOOL_SPELLING_MISMATCHES:
        return False
    state = getattr(outcome, "state", None)
    return bool(
        state is not None
        and state.agent_enabled
        and state.community_present
        and not state.community_disabled
        and state.community_read_only is True
    )


def _monitoring_view(router: Any) -> dict:
    return {
        "enabled": bool(router.snmp_enabled),
        "applied_on_router": router.snmp_device_applied_at is not None,
        "applied_at": (
            router.snmp_device_applied_at.isoformat()
            if router.snmp_device_applied_at
            else None
        ),
        "last_reading_at": (
            router.snmp_last_success_at.isoformat()
            if router.snmp_last_success_at
            else None
        ),
        "last_reading_ok": (
            None
            if router.snmp_last_poll_status is None
            else router.snmp_last_poll_status in ("ok", "success")
        ),
    }


@prov_fix_router.get(
    "/routers/{isp_router_id}/monitoring",
    dependencies=[*_ON, *isp_guards(ISP_PARTNER_READ)],
)
async def get_monitoring(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
) -> dict:
    target = await IspScope.assert_router(isp, isp_router_id)
    view = _monitoring_view(target)
    view["can_change"] = isp.role_slug in MONITORING_ROLES
    return ok(request, view, "Monitoring status")


async def _switch(
    request: Request,
    isp_router_id: uuid.UUID,
    on: bool,
    isp: IspContext,
    service: RouterSnmpService,
    audit: RBACRepositoryProtocol,
) -> dict:
    if isp.role_slug not in MONITORING_ROLES:
        raise IspMonitoringNotAllowedError()
    target = await IspScope.assert_router(isp, isp_router_id)
    data: dict[str, object] = {"enabled": on}
    if on and target.snmp_community_encrypted is None:
        # Our own read-only community for this router, never the platform
        # default and never a guessable one.
        data["version"] = "2c"
        data["community"] = "wyfy" + secrets.token_hex(8)
    try:
        await service.update_config(target.id, actor_user_id=isp.user_id, data=data)
        outcome = await service.apply_to_device(target.id, actor_user_id=isp.user_id)
    except SnmpDeviceUnreachableError:
        if not on:
            # Switching OFF must work even when the router cannot be
            # reached: polling stops at once (the stored switch), and the
            # community left on the device is read-only and ours.
            await _audit(audit, isp, target, "monitoring_off", verified=False)
            refreshed = await IspScope.assert_router(isp, isp_router_id)
            view = _monitoring_view(refreshed)
            view["can_change"] = True
            return ok(request, view, "Monitoring switched off")
        raise IspMonitoringRouterUnreachableError() from None
    except (SnmpConfigInvalidError, SnmpNotConfiguredError):
        raise IspMonitoringUnavailableError() from None
    except Exception as exc:  # noqa: BLE001 -- vendor not supported, no API login
        if getattr(exc, "status_code", 500) in (409, 422):
            raise IspMonitoringUnavailableError() from None
        raise
    verified = outcome.verified
    if on and not verified and _monitoring_read_back_ok(outcome):
        # [POSTFIX-1] D10: only the boolean spelling disagreed. Record the
        # apply the shared service left unrecorded (it clears the stamp on
        # any mismatch).
        router = await service._router(target.id)  # noqa: SLF001
        await service.router_service.repository.update_router(
            router, {"snmp_device_applied_at": datetime.now(UTC)}
        )
        verified = True
    if on and not verified:
        # Written but the read-back disagrees: do not leave it half on.
        raise IspMonitoringRouterUnreachableError(verified=False)
    await _audit(
        audit,
        isp,
        target,
        "monitoring_on" if on else "monitoring_off",
        verified=verified,
    )
    refreshed = await IspScope.assert_router(isp, isp_router_id)
    view = _monitoring_view(refreshed)
    view["can_change"] = True
    return ok(
        request,
        view,
        "Monitoring switched on" if on else "Monitoring switched off",
    )


@prov_fix_router.post(
    "/routers/{isp_router_id}/monitoring/enable",
    dependencies=[*_ON, *isp_guards(ISP_PARTNER_EXECUTE)],
)
async def enable_monitoring(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: RouterSnmpService = Depends(_snmp_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    return await _switch(request, isp_router_id, True, isp, service, audit)


@prov_fix_router.post(
    "/routers/{isp_router_id}/monitoring/disable",
    dependencies=[*_ON, *isp_guards(ISP_PARTNER_EXECUTE)],
)
async def disable_monitoring(
    request: Request,
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: RouterSnmpService = Depends(_snmp_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    return await _switch(request, isp_router_id, False, isp, service, audit)


# ---------------------------------------------------------------------------
# [POSTFIX-1] package list: FUP and validity start per package
# ---------------------------------------------------------------------------

#: More packages than one ISP ever sells; bounds the read.
_POLICY_SUMMARY_LIMIT = 2000


@prov_fix_router.get(
    "/package-policy-summaries",
    dependencies=[*_ON, *isp_guards(PLANS_READ)],
)
async def package_policy_summaries(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """The package list showed "30 d" and "Cap None" for a plan with a
    3000 GB FUP whose validity starts at first login (QA W8): both live in
    the package policy, which was only readable one package at a time. One
    row per package of THIS ISP that has a policy; packages without one use
    the defaults (no FUP, validity from activation). Read-only."""
    p, k = IspPackagePolicy, IspPackage
    rows = (
        await db.execute(
            select(p.package_id, p.fup_limit_mb, p.fup_reset, p.validity_starts)
            .join(k, k.id == p.package_id)
            .where(
                p.isp_organization_id == isp.isp_org_id,
                k.isp_organization_id == isp.isp_org_id,
                p.is_deleted.is_(False),
                k.is_deleted.is_(False),
            )
            .order_by(p.package_id)
            .limit(_POLICY_SUMMARY_LIMIT)
        )
    ).all()
    return ok(
        request,
        {
            "items": [
                {
                    "package_id": str(r.package_id),
                    "fup_limit_mb": r.fup_limit_mb,
                    "fup_reset": r.fup_reset,
                    "validity_starts": r.validity_starts,
                }
                for r in rows
            ]
        },
        "Package policy summaries",
    )


__all__ = ["prov_fix_router", "get_prov_fix_settings"]
