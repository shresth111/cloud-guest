"""FastAPI routes for the Router Agent domain: the device-facing protocol a
real MikroTik RouterOS agent uses for its entire ongoing lifecycle after
zero-touch provisioning -- heartbeat, current-configuration pull, status
push, and provisioning-action-queue poll/complete.

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
    AgentStatusReportRequest,
    AgentStatusReportResponse,
)
from .service import RouterAgentService

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
) -> AgentHeartbeatResponse:
    """Device-authenticated counterpart to BE-008's admin-testing
    ``POST /routers/{id}/heartbeat`` (which stays exactly as-is, gated by
    ``RequirePermission("routers.manage")``, for admin/manual use) --
    composes with ``RouterService.heartbeat`` directly."""
    updated = await service.heartbeat(
        router=identity.router,
        routeros_version=payload.routeros_version,
        management_ip_address=payload.management_ip_address,
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


__all__ = ["router"]
