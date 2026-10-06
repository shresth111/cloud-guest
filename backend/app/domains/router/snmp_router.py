"""Master-console SNMP routes: ``/platform/routers/{router_id}/snmp...``.

Every route is pinned to ``ScopeType.GLOBAL`` (see the scope-inference trap
in ``RequirePermission``): an organization-scoped ``routers.*`` grant -- which
every venue owner holds -- can never satisfy these, whatever headers it
sends. SNMP credentials and the poller's source addresses are platform
internals, not something a venue owner configures.

No new permission keys: reading uses ``routers.read``, everything that
changes stored config, talks to the device, or sends the stored credentials
on the wire uses ``routers.update`` -- both already seeded.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.core.config import Settings, get_settings
from app.domains.auth.models import AuthUser
from app.domains.provisioning_engine.constants import (
    ROUTER_SNMP_METRICS_POLL_SWEEP_INTERVAL_SECONDS,
)
from app.domains.rbac.dependencies import CurrentUser, RequirePermission
from app.domains.rbac.enums import ScopeType

from .dependencies import get_router_service
from .models import Router
from .service import RouterService
from .snmp import (
    RouterSnmpService,
    SnmpApplyOutcome,
    SnmpTestOutcome,
    poller_source_addresses,
    snmp_support_for,
)
from .snmp_schemas import (
    RouterSnmpApplyResponse,
    RouterSnmpConfigRequest,
    RouterSnmpDeviceStateResponse,
    RouterSnmpIdentityResponse,
    RouterSnmpScriptResponse,
    RouterSnmpStatusResponse,
    RouterSnmpTestResponse,
)

router = APIRouter(tags=["Routers"])

_READ = [Depends(RequirePermission("routers.read", scope=ScopeType.GLOBAL))]
_WRITE = [Depends(RequirePermission("routers.update", scope=ScopeType.GLOBAL))]


def get_router_snmp_service(
    router_service: RouterService = Depends(get_router_service),
    settings: Settings = Depends(get_settings),
) -> RouterSnmpService:
    return RouterSnmpService(router_service, settings=settings)


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def snmp_status(router_device: Router, settings: Settings) -> RouterSnmpStatusResponse:
    support = snmp_support_for(router_device)
    version = router_device.snmp_version or settings.snmp_default_version
    has_own = router_device.snmp_community_encrypted is not None
    return RouterSnmpStatusResponse(
        router_id=router_device.id,
        vendor=support.vendor,
        support=support.support.value,
        support_reason=support.reason,
        metrics_via=support.metrics_via,
        enabled=router_device.snmp_enabled,
        version=version,
        port=router_device.snmp_port or settings.snmp_default_port,
        has_community=has_own,
        uses_platform_default_community=(
            not has_own and version != "3" and bool(settings.snmp_default_community)
        ),
        v3_auth_protocol=router_device.snmp_v3_auth_protocol,
        has_v3_auth_password=router_device.snmp_v3_auth_password_encrypted is not None,
        v3_priv_protocol=router_device.snmp_v3_priv_protocol,
        has_v3_priv_password=router_device.snmp_v3_priv_password_encrypted is not None,
        allowed_sources=list(poller_source_addresses(settings)),
        poll_interval_seconds=int(ROUTER_SNMP_METRICS_POLL_SWEEP_INTERVAL_SECONDS),
        last_poll_at=router_device.snmp_last_poll_at,
        last_poll_status=router_device.snmp_last_poll_status,
        last_poll_detail=router_device.snmp_last_poll_detail,
        last_success_at=router_device.snmp_last_success_at,
        device_applied_at=router_device.snmp_device_applied_at,
    )


def _test_response(outcome: SnmpTestOutcome) -> RouterSnmpTestResponse:
    identity = outcome.identity
    return RouterSnmpTestResponse(
        ok=outcome.ok,
        status=outcome.status.value,
        detail=outcome.detail,
        identity=(
            RouterSnmpIdentityResponse(
                sys_name=identity.sys_name,
                sys_descr=identity.sys_descr,
                uptime_seconds=identity.uptime_seconds,
            )
            if identity is not None
            else None
        ),
        target_host=outcome.target_host,
        target_port=outcome.target_port,
        version=outcome.version,
        tested_at=outcome.tested_at,
    )


def _state_response(state) -> RouterSnmpDeviceStateResponse | None:  # noqa: ANN001
    if state is None:
        return None
    return RouterSnmpDeviceStateResponse(
        agent_enabled=state.agent_enabled,
        community_present=state.community_present,
        community_disabled=state.community_disabled,
        community_addresses=state.community_addresses,
        community_security=state.community_security,
        community_read_only=state.community_read_only,
        default_public_open=state.default_public_open,
        other_communities=state.other_communities,
    )


def _apply_response(outcome: SnmpApplyOutcome) -> RouterSnmpApplyResponse:
    return RouterSnmpApplyResponse(
        action=outcome.action,
        verified=outcome.verified,
        changed=outcome.changed,
        mismatches=outcome.mismatches,
        unverified=outcome.unverified,
        state=_state_response(outcome.state),
        allowed_sources=list(outcome.allowed_sources),
        applied_at=outcome.applied_at,
    )


@router.get(
    "/platform/routers/{router_id}/snmp",
    response_model=ApiResponse[RouterSnmpStatusResponse],
    status_code=status.HTTP_200_OK,
    dependencies=_READ,
)
async def get_router_snmp(
    request: Request,
    router_id: uuid.UUID,
    service: RouterSnmpService = Depends(get_router_snmp_service),
    settings: Settings = Depends(get_settings),
):
    """SNMP support for this device type, its stored config (no secrets),
    and the last poll's real outcome."""
    router_device = await service.get(router_id)
    return build_response(
        success=True,
        message="Router SNMP status",
        data=snmp_status(router_device, settings).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/platform/routers/{router_id}/snmp",
    response_model=ApiResponse[RouterSnmpStatusResponse],
    status_code=status.HTTP_200_OK,
    dependencies=_WRITE,
)
async def update_router_snmp(
    request: Request,
    router_id: uuid.UUID,
    payload: RouterSnmpConfigRequest,
    user: AuthUser = Depends(CurrentUser),
    service: RouterSnmpService = Depends(get_router_snmp_service),
    settings: Settings = Depends(get_settings),
):
    """Store SNMP settings. This does not touch the device -- ``/apply``
    does, so an operator can save, test, and push as separate, visible
    steps."""
    updated = await service.update_config(
        router_id,
        actor_user_id=uuid.UUID(user.id),
        data=payload.model_dump(exclude_unset=True),
    )
    return build_response(
        success=True,
        message="Router SNMP settings saved",
        data=snmp_status(updated, settings).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/platform/routers/{router_id}/snmp/test",
    response_model=ApiResponse[RouterSnmpTestResponse],
    status_code=status.HTTP_200_OK,
    dependencies=_WRITE,
)
async def test_router_snmp(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    service: RouterSnmpService = Depends(get_router_snmp_service),
):
    """A real SNMP GET (sysName, sysDescr, sysUpTime) from the platform to
    the device with the stored credentials. ``ok: false`` is a result, not
    an error -- the body says what failed."""
    outcome = await service.test(router_id, actor_user_id=uuid.UUID(user.id))
    return build_response(
        success=True,
        message="SNMP test finished",
        data=_test_response(outcome).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/platform/routers/{router_id}/snmp/device",
    response_model=ApiResponse[RouterSnmpDeviceStateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=_READ,
)
async def read_router_snmp_device(
    request: Request,
    router_id: uuid.UUID,
    service: RouterSnmpService = Depends(get_router_snmp_service),
):
    """Read-only, live from the device over the RouterOS API: is the agent
    on, is the platform's community present and read-only, and is the
    factory ``public`` community still open."""
    state = await service.read_device(router_id)
    return build_response(
        success=True,
        message="Router SNMP device state",
        data=_state_response(state).model_dump(),  # type: ignore[union-attr]
        request_id=_request_id(request),
    )


@router.get(
    "/platform/routers/{router_id}/snmp/script",
    response_model=ApiResponse[RouterSnmpScriptResponse],
    status_code=status.HTTP_200_OK,
    dependencies=_READ,
)
async def get_router_snmp_script(
    request: Request,
    router_id: uuid.UUID,
    service: RouterSnmpService = Depends(get_router_snmp_service),
):
    """The RouterOS commands "Apply to router" is equivalent to, secrets
    masked -- for review, rendered from the same desired state the writer
    applies."""
    action, lines = await service.render_script(router_id)
    return build_response(
        success=True,
        message="Router SNMP script",
        data=RouterSnmpScriptResponse(action=action, lines=lines).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/platform/routers/{router_id}/snmp/apply",
    response_model=ApiResponse[RouterSnmpApplyResponse],
    status_code=status.HTTP_200_OK,
    dependencies=_WRITE,
)
async def apply_router_snmp(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    service: RouterSnmpService = Depends(get_router_snmp_service),
):
    """Write the stored SNMP config to the device over the RouterOS API and
    read it back. ``verified`` reflects the read-back."""
    outcome = await service.apply_to_device(router_id, actor_user_id=uuid.UUID(user.id))
    return build_response(
        success=True,
        message=(
            "SNMP settings written and verified on the device"
            if outcome.verified
            else "SNMP settings written but the device does not match"
        ),
        data=_apply_response(outcome).model_dump(),
        request_id=_request_id(request),
    )
