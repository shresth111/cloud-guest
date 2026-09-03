"""FastAPI routes for the Router Agent domain: the device-facing protocol a
real MikroTik RouterOS agent uses for its entire ongoing lifecycle after
zero-touch provisioning -- heartbeat, current-configuration pull, status
push, provisioning-action-queue poll/complete, and a real MikroTik
RouterOS Netwatch event call-in (``agent_netwatch_event``, this module's
own real device-initiated surface for
``app.domains.network_config.renderers.render_isp_netwatch_entry`` --
see that function's own module-docstring section for the full design).

**Every endpoint here is device-facing, not user-facing.** None of them
carry RBAC's ``RequirePermission``/``CurrentUser`` dependencies -- a
physical device has no platform user identity or JWT, exactly the same
posture BE-008's own ``POST /routers/provisioning/check-in`` already
established (see that endpoint's module docstring). Instead, every endpoint
here depends on this module's own ``dependencies.CurrentAgent``, which
resolves and validates the calling device's persistent agent credential
(presented via the ``X-Agent-Credential`` header -- see ``service.py``'s
module docstring for why a header, not the check-in precedent's request
body). Responses are deliberately minimal, non-``ApiResponse``-enveloped
Pydantic models, mirroring ``ProvisioningCheckInResponse``'s identical
"the calling device is not expected to parse a rich, user-facing API
contract" reasoning.

The persistent credential itself is issued by BE-008's own check-in
endpoint (``app.domains.router.router.provisioning_check_in``), not by any
endpoint in this file -- see that endpoint and ``service.py``'s module
docstring for why.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status

from app.domains.guest.dependencies import get_guest_repository
from app.domains.guest.repository import GuestRepositoryProtocol
from app.domains.isp.dependencies import get_isp_service
from app.domains.isp.service import IspService
from app.domains.mac_authorization.dependencies import (
    get_mac_authorization_service,
)
from app.domains.mac_authorization.service import MacAuthorizationService
from app.domains.monitoring.constants import HeartbeatComponentType
from app.domains.monitoring.dependencies import get_monitoring_service
from app.domains.monitoring.service import MonitoringService
from app.domains.router.enums import RouterStatus

from .dependencies import AgentIdentity, CurrentAgent, get_router_agent_service
from .schemas import (
    AgentActionCompleteRequest,
    AgentActionCompleteResponse,
    AgentActionItem,
    AgentActionListResponse,
    AgentConfigResponse,
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentNetwatchEventRequest,
    AgentNetwatchEventResponse,
    AgentStatusReportRequest,
    AgentStatusReportResponse,
    AuthorizedMacsResponse,
)
from .service import RouterAgentService
from .validators import (
    netwatch_status_to_ping_result,
    validate_netwatch_link_owned_by_router,
)

router = APIRouter(prefix="/agent", tags=["Router Agent"])


@router.post(
    "/heartbeat",
    response_model=AgentHeartbeatResponse,
    status_code=status.HTTP_200_OK,
)
async def agent_heartbeat(
    payload: AgentHeartbeatRequest,
    identity: AgentIdentity = Depends(CurrentAgent),
    service: RouterAgentService = Depends(get_router_agent_service),
    monitoring_service: MonitoringService = Depends(get_monitoring_service),
) -> AgentHeartbeatResponse:
    """Device-authenticated counterpart to BE-008's admin-testing
    ``POST /routers/{id}/heartbeat`` (which stays exactly as-is, gated by
    ``RequirePermission("routers.manage")``, for admin/manual use) --
    composes with ``RouterService.heartbeat`` directly.

    **BE-011 Part 1 additive hook:** after the real liveness update above,
    this also writes one row into ``app.domains.monitoring``'s platform-wide
    ``HeartbeatLog`` (``component_type=ROUTER``) -- see that model's module
    docstring for the full "composes with, does not replace, this
    endpoint's own liveness detection" write-up. This is the one, small,
    additive cross-domain call the monitoring module's directory rule
    permitted; it does not change this endpoint's request/response contract
    or its existing behavior in any way, and a failure to record the
    heartbeat log would not be a reason to fail this call -- but no such
    failure path currently exists (``record_heartbeat`` cannot itself raise
    a device-facing error)."""
    updated = await service.heartbeat(
        router=identity.router,
        routeros_version=payload.routeros_version,
        management_ip_address=payload.management_ip_address,
        public_ip_address=payload.public_ip_address,
    )
    await monitoring_service.record_heartbeat(
        component_type=HeartbeatComponentType.ROUTER,
        component_id=updated.id,
        payload={
            "routeros_version": payload.routeros_version,
            "management_ip_address": payload.management_ip_address,
            "public_ip_address": payload.public_ip_address,
            "status": updated.status,
        },
    )
    return AgentHeartbeatResponse(
        router_id=str(updated.id),
        status=RouterStatus(updated.status),
        last_seen_at=updated.last_seen_at,
    )


@router.get(
    "/config",
    response_model=AgentConfigResponse,
    status_code=status.HTTP_200_OK,
)
async def agent_pull_config(
    identity: AgentIdentity = Depends(CurrentAgent),
    service: RouterAgentService = Depends(get_router_agent_service),
) -> AgentConfigResponse:
    """Returns the router's current, latest-applied ``ConfigVersion``
    content (Module 009 Part 1) -- raises ``NoConfigAssignedError`` if
    nothing has ever been applied to this router yet."""
    version = await service.get_current_config(router_id=identity.router.id)
    return AgentConfigResponse(
        router_id=str(identity.router.id),
        version_id=str(version.id),
        version_number=version.version_number,
        rendered_content=version.rendered_content,
        applied_at=version.applied_at,
    )


@router.post(
    "/status",
    response_model=AgentStatusReportResponse,
    status_code=status.HTTP_200_OK,
)
async def agent_report_status(
    payload: AgentStatusReportRequest,
    identity: AgentIdentity = Depends(CurrentAgent),
    service: RouterAgentService = Depends(get_router_agent_service),
) -> AgentStatusReportResponse:
    """Records the agent's self-reported capabilities/software version/
    license state, and (only when it changed) refreshes BE-008's existing
    ``Router.routeros_version`` via ``RouterService.update_router``."""
    updated_credential = await service.report_status(
        router=identity.router,
        credential=identity.credential,
        routeros_version=payload.routeros_version,
        agent_software_version=payload.agent_software_version,
        capabilities=payload.capabilities,
        license_key=payload.license_key,
        license_status=payload.license_status,
    )
    return AgentStatusReportResponse(
        router_id=str(identity.router.id),
        agent_software_version=updated_credential.agent_software_version,
        license_status=payload.license_status,
        recorded_at=updated_credential.last_status_report_at,
    )


@router.get(
    "/actions",
    response_model=AgentActionListResponse,
    status_code=status.HTTP_200_OK,
)
async def agent_poll_actions(
    identity: AgentIdentity = Depends(CurrentAgent),
    service: RouterAgentService = Depends(get_router_agent_service),
) -> AgentActionListResponse:
    """Polls this router's pending/in-flight ``ProvisioningJob`` rows
    (Module 009 Part 1's provisioning queue -- the consumer side of the
    Redis dispatch signal that module's ``_enqueue_job`` pushes). Freshly
    -``queued`` jobs are atomically claimed (transitioned to ``running``)."""
    jobs = await service.poll_actions(router_id=identity.router.id)
    return AgentActionListResponse(
        items=[
            AgentActionItem(
                id=str(job.id),
                job_type=job.job_type,
                status=job.status,
                payload=job.payload,
                attempts=job.attempts,
                scheduled_at=job.scheduled_at,
            )
            for job in jobs
        ]
    )


@router.post(
    "/actions/{job_id}/complete",
    response_model=AgentActionCompleteResponse,
    status_code=status.HTTP_200_OK,
)
async def agent_complete_action(
    job_id: uuid.UUID,
    payload: AgentActionCompleteRequest,
    identity: AgentIdentity = Depends(CurrentAgent),
    service: RouterAgentService = Depends(get_router_agent_service),
) -> AgentActionCompleteResponse:
    """Reports a job's real-world outcome -- calls
    ``RouterProvisioningService.complete_provisioning_job``, the exact seam
    that service's own module docstring names this module as the caller
    of."""
    job = await service.complete_action(
        router_id=identity.router.id,
        job_id=job_id,
        success=payload.success,
        error_message=payload.error_message,
    )
    return AgentActionCompleteResponse(job_id=str(job.id), status=job.status)


@router.get(
    "/authorized-macs",
    response_model=AuthorizedMacsResponse,
    status_code=status.HTTP_200_OK,
)
async def agent_authorized_macs(
    identity: AgentIdentity = Depends(CurrentAgent),
    guest_repository: GuestRepositoryProtocol = Depends(get_guest_repository),
    mac_authorization_service: MacAuthorizationService = Depends(
        get_mac_authorization_service
    ),
) -> AuthorizedMacsResponse:
    """Every MAC this router should let straight through: guests with a
    currently ``ACTIVE`` session, **and** the devices an admin marked
    Trusted.

    The agent's heartbeat script polls this and applies a local
    ``/ip hotspot ip-binding type=bypassed`` for each MAC returned. This
    endpoint only ever reports state; it never grants anything itself.

    ## Why Trusted Devices had to be added here

    This used to return active sessions only, and nothing anywhere else
    reached a router either -- so "Trusted Devices" was a screen that
    wrote a row and changed nothing on any device, ever. The circularity
    is the part worth naming: a device could only appear here by already
    having a session, which is precisely what being trusted is supposed
    to grant it. A trusted device that had never logged in could never
    become trusted.

    ``list_active_entries_for_router`` already returns exactly the right
    set -- enabled, non-expired, and org/location-scoped to this router --
    so this is a union, not new policy.

    ## Safe against the scheduler that already runs on the fleet

    That script adds a binding only for a MAC that is *neither* already
    bound *nor* currently in ``/ip hotspot active``, so unioning a trusted
    MAC in cannot tear down a live session -- RouterOS drops the host when
    a binding appears for an active MAC, and the script's own guard is
    what prevents it. The removal half reconciles against this same list,
    so un-trusting a device really does withdraw its binding on the next
    poll.

    Union rather than a second response key, deliberately: a new key would
    be ignored by every script already deployed, so the fix would do
    nothing until every router in the fleet was re-provisioned by hand.
    """
    sessions = await guest_repository.list_active_sessions_for_router(
        identity.router.id
    )
    macs: list[str] = []
    for session in sessions:
        if session.device_id is None:
            continue
        device = await guest_repository.get_device_by_id(session.device_id)
        if device is not None:
            macs.append(device.mac_address)

    # Scoped by the service against this router's own organization and
    # location; the agent identity is the router, so there is no caller
    # organization to pass and none to check against.
    trusted = await mac_authorization_service.list_active_entries_for_router(
        identity.router.id, requesting_organization_id=None
    )
    macs.extend(entry.mac_address for entry in trusted)

    return AuthorizedMacsResponse(mac_addresses=sorted(set(macs)))


@router.post(
    "/netwatch-event",
    response_model=AgentNetwatchEventResponse,
    status_code=status.HTTP_200_OK,
)
async def agent_netwatch_event(
    payload: AgentNetwatchEventRequest,
    identity: AgentIdentity = Depends(CurrentAgent),
    service: RouterAgentService = Depends(get_router_agent_service),
    isp_service: IspService = Depends(get_isp_service),
) -> AgentNetwatchEventResponse:
    """Real MikroTik RouterOS Netwatch integration's device-initiated
    call-in: the endpoint a router's own Netwatch ``up-script``/
    ``down-script`` (``app.domains.network_config.renderers
    .render_isp_netwatch_entry``) calls the instant RouterOS itself
    notices the watched target change -- structurally faster than waiting
    for the next tick of ``app.domains.isp.service
    .run_health_check_sweep``'s own 30-second server-side poll, since
    there is no round-trip to a central server involved in the detection
    itself, only in this report of it.

    Feeds the exact same real pipeline the sweep uses
    (``IspService.record_health_check_result``), via a synthesized
    ``PingResult`` (see ``validators.netwatch_status_to_ping_result``) --
    a Netwatch-detected change advances the same
    ``consecutive_unhealthy_count``/failover machinery the sweep does, one
    recording path, not a second, parallel health signal. ``isp_link_id``
    is resolved with no ``requesting_organization_id`` (this is a device-
    authenticated call, not a platform-user one -- see module docstring),
    then explicitly checked against this call's own credential-derived
    ``identity.router.id`` (``validate_netwatch_link_owned_by_router``) so
    one router's agent can never advance another router's ISP link.

    ``RouterAgentService.report_netwatch_event`` additionally records a
    real, queryable ``RouterEvent`` proving this call landed -- see that
    method's own docstring."""
    link = await isp_service.get_link(payload.isp_link_id)
    validate_netwatch_link_owned_by_router(
        link.router_id, identity.router.id, isp_link_id=link.id
    )
    ping_result = netwatch_status_to_ping_result(payload.status)
    updated = await isp_service.record_health_check_result(
        link, ping_result=ping_result, traffic=None
    )
    await service.report_netwatch_event(
        router_id=identity.router.id,
        isp_link_id=link.id,
        status=payload.status,
        host=payload.host,
    )
    return AgentNetwatchEventResponse(
        isp_link_id=str(link.id),
        health_status=updated.health_status,
        recorded_at=updated.last_checked_at,
    )


__all__ = ["router"]
