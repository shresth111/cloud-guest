"""FastAPI routes for the Network Configuration Management domain.

Version list/get/diff/apply responses reuse ``app.domains
.router_provisioning.schemas``'s own response schemas directly (see
``schemas.py``'s own module docstring for why) -- only the response
*builder functions* below are local to this router, mirroring that
module's own ``_version_response``/``_job_response`` shape (not
importable directly since they are that module's own private helpers,
not part of its public API).
"""

from __future__ import annotations

import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.core.config import Settings, get_settings
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService
from app.domains.router_provisioning.dependencies import get_router_provisioning_service
from app.domains.router_provisioning.models import ConfigVersion, ProvisioningJob
from app.domains.router_provisioning.schemas import (
    ConfigVersionApplyResponse,
    ConfigVersionDiffResponse,
    ConfigVersionListResponse,
    ConfigVersionResponse,
    ConfigVersionSummary,
    ProvisioningJobResponse,
)
from app.domains.router_provisioning.service import RouterProvisioningService

from .dependencies import get_network_config_service
from .schemas import (
    NetworkConfigApplyLiveResponse,
    NetworkConfigNetwatchPushResponse,
    NetworkConfigPreviewResponse,
)
from .service import NetworkConfigService

router = APIRouter(prefix="/network-config", tags=["Network Configuration Management"])

# The SSH-capable config-agent bridge this module's apply-live endpoint
# forwards to is a RETIRED transport (router-fleet plan section A1: the
# vendored wyfy_device_gateway over the WireGuard tunnel is the transport
# of record). Its URL and shared secret -- previously hardcoded module
# constants here, i.e. a live credential committed to source -- now live
# in Settings (config_agent_url / config_agent_secret) and default to
# empty, which disables the endpoint below with an honest
# "bridge disabled" response instead of a network call.


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _pagination_fields(meta) -> dict[str, int | bool]:  # noqa: ANN001
    return {
        "page": meta.page,
        "page_size": meta.page_size,
        "total_items": meta.total_items,
        "total_pages": meta.total_pages,
        "has_next": meta.has_next,
        "has_previous": meta.has_previous,
    }


def _version_summary(version: ConfigVersion) -> ConfigVersionSummary:
    return ConfigVersionSummary(
        id=str(version.id),
        router_id=str(version.router_id),
        profile_id=str(version.profile_id) if version.profile_id else None,
        version_number=version.version_number,
        status=version.status,
        is_backup=version.is_backup,
        rollback_of_version_id=(
            str(version.rollback_of_version_id)
            if version.rollback_of_version_id
            else None
        ),
        created_by_user_id=(
            str(version.created_by_user_id) if version.created_by_user_id else None
        ),
        applied_at=version.applied_at,
        created_at=version.created_at,
    )


def _version_response(version: ConfigVersion) -> ConfigVersionResponse:
    return ConfigVersionResponse(
        **_version_summary(version).model_dump(),
        rendered_content=version.rendered_content,
    )


def _job_response(job: ProvisioningJob) -> ProvisioningJobResponse:
    return ProvisioningJobResponse(
        id=str(job.id),
        router_id=str(job.router_id),
        job_type=job.job_type,
        status=job.status,
        payload=job.payload,
        attempts=job.attempts,
        max_attempts=job.max_attempts,
        scheduled_at=job.scheduled_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        error_message=job.error_message,
        requested_by_user_id=(
            str(job.requested_by_user_id) if job.requested_by_user_id else None
        ),
        created_at=job.created_at,
    )


@router.get(
    "/routers/{router_id}/preview",
    response_model=ApiResponse[NetworkConfigPreviewResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_config.read"))],
)
async def preview_network_config(
    request: Request,
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkConfigService = Depends(get_network_config_service),
):
    preview = await service.preview_config(
        router_id, requesting_organization_id=requesting_organization_id
    )
    payload = NetworkConfigPreviewResponse(
        router_id=str(preview.router_id),
        rendered_content=preview.rendered_content,
        dhcp_pool_count=preview.dhcp_pool_count,
        vlan_count=preview.vlan_count,
        port_forwarding_rule_count=preview.port_forwarding_rule_count,
        hotspot_profile_count=preview.hotspot_profile_count,
        qos_traffic_rule_count=preview.qos_traffic_rule_count,
        dns_record_count=preview.dns_record_count,
        firewall_rule_count=preview.firewall_rule_count,
        mac_authorization_entry_count=preview.mac_authorization_entry_count,
        content_filter_rule_count=preview.content_filter_rule_count,
    )
    return build_response(
        success=True,
        message="Network config preview rendered",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/push",
    response_model=ApiResponse[ConfigVersionApplyResponse],
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(RequirePermission("network_config.execute"))],
)
async def push_network_config(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkConfigService = Depends(get_network_config_service),
):
    version, job = await service.push_config(
        router_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
    )
    payload = ConfigVersionApplyResponse(
        version=_version_response(version), job=_job_response(job)
    )
    return build_response(
        success=True,
        message="Network config rendered and queued for application",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/versions/{version_id}/apply-live",
    response_model=ApiResponse[NetworkConfigApplyLiveResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_config.execute"))],
)
async def apply_network_config_live(
    request: Request,
    router_id: uuid.UUID,
    version_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    provisioning_service: RouterProvisioningService = Depends(
        get_router_provisioning_service
    ),
    router_service: RouterService = Depends(get_router_service),
    settings: Settings = Depends(get_settings),
):
    """Server-side equivalent of what ``ConfigTab.handlePush`` (frontend)
    previously did itself in two direct browser calls: fetch this
    router's real connection info, then hand the already-rendered
    ``ConfigVersion.rendered_content`` to the SSH-capable config-agent
    bridge. Moving both steps here fixes two real problems at once --
    the bridge is a plain ``http://`` endpoint with no CORS support,
    silently blocked as mixed content once called from an HTTPS page
    (confirmed live), and the frontend previously had to ship
    ``_CONFIG_AGENT_SECRET`` in its own JS bundle just to make the call
    at all. See ``get_device_connection``'s own docstring for why
    ``reveal_credentials`` (not a lower-tier read) is the right gate here
    too -- this is the same real, high-trust device operation, exposing
    the same decrypted secret, just consumed server-side instead of
    handed back to the browser.

    The bridge transport itself is retired (see the module-level note):
    unless a deployment explicitly re-enables it via
    ``CLOUDGUEST_CONFIG_AGENT_URL``/``CLOUDGUEST_CONFIG_AGENT_SECRET``,
    this endpoint reports the bridge as disabled -- before fetching the
    version or revealing any credential -- rather than calling it."""
    if not settings.config_agent_url or not settings.config_agent_secret:
        payload = NetworkConfigApplyLiveResponse(
            router_id=str(router_id),
            version_id=str(version_id),
            applied=False,
            detail=(
                "The config-agent bridge is disabled on this deployment "
                "(retired transport; not configured via "
                "CLOUDGUEST_CONFIG_AGENT_URL/CLOUDGUEST_CONFIG_AGENT_SECRET). "
                "Use the queued agent push instead."
            ),
        )
        return build_response(
            success=True,
            message="Config-agent bridge is disabled",
            data=payload.model_dump(),
            request_id=_request_id(request),
        )

    version = await provisioning_service.get_version(
        router_id=router_id,
        version_id=version_id,
        requesting_organization_id=requesting_organization_id,
    )
    router_row = await router_service.reveal_credentials(
        actor_user_id=uuid.UUID(user.id),
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
    )
    host = router_row.management_ip_address or router_row.public_ip_address
    username = router_row.api_username
    password = router_service.get_decrypted_api_secret(router_row)
    if not host or not username or not password:
        payload = NetworkConfigApplyLiveResponse(
            router_id=str(router_id),
            version_id=str(version_id),
            applied=False,
            detail="Router has no stored connection details -- can't apply live.",
        )
        return build_response(
            success=True,
            message="Router has no stored connection details",
            data=payload.model_dump(),
            request_id=_request_id(request),
        )

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                settings.config_agent_url,
                headers={"X-Agent-Secret": settings.config_agent_secret},
                json={
                    "tunnel_ip": host,
                    "username": username,
                    "password": password,
                    "script": version.rendered_content,
                },
            )
            resp.raise_for_status()
            result = resp.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502, detail="Could not reach the config-agent bridge"
        ) from exc

    payload = NetworkConfigApplyLiveResponse(
        router_id=str(router_id),
        version_id=str(version_id),
        applied=bool(result.get("applied")),
        detail=result.get("detail") or result.get("error"),
    )
    message = (
        "Config applied to the live device" if payload.applied else "Live apply failed"
    )
    return build_response(
        success=True,
        message=message,
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/netwatch/push",
    response_model=ApiResponse[NetworkConfigNetwatchPushResponse],
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(RequirePermission("network_config.execute"))],
)
async def push_isp_netwatch_config(
    request: Request,
    router_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkConfigService = Depends(get_network_config_service),
    settings: Settings = Depends(get_settings),
):
    """Configures real RouterOS Netwatch entries -- the faster, router-side
    complementary detection path alongside ``app.domains.isp``'s existing
    30-second server-side health-check sweep. Gated by the same
    ``network_config.execute`` permission ``push``/``rollback`` already
    require, since this is a real, on-demand device-config push, not a
    read. See ``NetworkConfigService.push_isp_netwatch_config``'s own
    docstring for what this actually does, including the real credential-
    rotation side effect."""
    result = await service.push_isp_netwatch_config(
        router_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        api_base_url=settings.api_public_base_url,
    )
    payload = NetworkConfigNetwatchPushResponse(
        version=_version_response(result.version),
        job=_job_response(result.job),
        watched_link_count=result.watched_link_count,
    )
    return build_response(
        success=True,
        message="ISP Netwatch config rendered and queued for application",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/routers/{router_id}/versions",
    response_model=ApiResponse[ConfigVersionListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_config.read"))],
)
async def list_network_config_versions(
    request: Request,
    router_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkConfigService = Depends(get_network_config_service),
):
    versions, meta = await service.list_versions(
        router_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = ConfigVersionListResponse(
        items=[_version_summary(v) for v in versions], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Network config versions retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/routers/{router_id}/versions/{version_id}",
    response_model=ApiResponse[ConfigVersionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_config.read"))],
)
async def get_network_config_version(
    request: Request,
    router_id: uuid.UUID,
    version_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkConfigService = Depends(get_network_config_service),
):
    version = await service.get_version(
        router_id, version_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Network config version retrieved",
        data=_version_response(version).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/routers/{router_id}/versions/{version_id}/diff/{other_version_id}",
    response_model=ApiResponse[ConfigVersionDiffResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("network_config.read"))],
)
async def diff_network_config_versions(
    request: Request,
    router_id: uuid.UUID,
    version_id: uuid.UUID,
    other_version_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkConfigService = Depends(get_network_config_service),
):
    version_a, version_b, diff_lines = await service.diff_versions(
        router_id,
        version_id,
        other_version_id,
        requesting_organization_id=requesting_organization_id,
    )
    payload = ConfigVersionDiffResponse(
        router_id=str(router_id),
        from_version_id=str(version_a.id),
        from_version_number=version_a.version_number,
        to_version_id=str(version_b.id),
        to_version_number=version_b.version_number,
        diff_lines=diff_lines,
    )
    return build_response(
        success=True,
        message="Network config version diff computed",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/routers/{router_id}/versions/{target_version_id}/rollback",
    response_model=ApiResponse[ConfigVersionApplyResponse],
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(RequirePermission("network_config.execute"))],
)
async def rollback_network_config(
    request: Request,
    router_id: uuid.UUID,
    target_version_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: NetworkConfigService = Depends(get_network_config_service),
):
    version, job = await service.rollback_and_apply(
        router_id,
        target_version_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
    )
    payload = ConfigVersionApplyResponse(
        version=_version_response(version), job=_job_response(job)
    )
    return build_response(
        success=True,
        message="Network config rollback queued for application",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
