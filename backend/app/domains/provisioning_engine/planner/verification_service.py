"""WAN verification orchestration (P7)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Protocol

from app.domains.isp.constants import IspLinkRole
from app.domains.isp.device_adapters import PingResult
from app.domains.isp.exceptions import (
    IspDeviceConnectionError,
    IspHealthCheckTargetUnavailableError,
    IspLinkDisabledError,
    IspMissingCredentialsError,
)
from app.domains.isp.models import IspLink
from app.domains.router.models import Router

from .constants import VerificationScope, WanVerificationOverall
from .exceptions import NoWanLinksToVerifyError
from .schemas import (
    WanLinkVerificationResponse,
    WanVerificationGateResponse,
    WanVerificationResponse,
)
from .verification_models import VerificationRun
from .verification_repository import VerificationRunRepositoryProtocol
from .wan_verification import (
    WanLinkVerificationInput,
    evaluate_wan_link_verification,
    wan_verification_gate_passes,
)


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Router: ...


class IspLinkLookupProtocol(Protocol):
    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[IspLink], object]: ...


class IspPingProtocol(Protocol):
    async def ping_link(self, link: IspLink) -> PingResult: ...


def _sort_links(links: list[IspLink]) -> list[IspLink]:
    return sorted(
        links,
        key=lambda link: (
            0 if link.role == IspLinkRole.PRIMARY.value else 1,
            link.priority,
        ),
    )


class WanVerificationService:
    def __init__(
        self,
        repository: VerificationRunRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        isp_link_lookup: IspLinkLookupProtocol,
        isp_ping: IspPingProtocol,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.isp_link_lookup = isp_link_lookup
        self.isp_ping = isp_ping

    async def verify_wan(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> WanVerificationResponse:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        links, _meta = await self.isp_link_lookup.list_links(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=1,
            page_size=100,
        )
        ordered = _sort_links([link for link in links if link.is_enabled])
        if not ordered:
            raise NoWanLinksToVerifyError(router_id)

        run_group_id = uuid.uuid4()
        started_at = datetime.now(UTC)
        link_results: list[WanLinkVerificationResponse] = []
        persisted: list[VerificationRun] = []

        for slot, link in enumerate(ordered, start=1):
            ping: PingResult | None = None
            error_message: str | None = None
            if link.is_enabled:
                try:
                    ping = await self.isp_ping.ping_link(link)
                except (
                    IspMissingCredentialsError,
                    IspHealthCheckTargetUnavailableError,
                    IspDeviceConnectionError,
                    IspLinkDisabledError,
                ) as exc:
                    error_message = str(exc)

            overall, checks = evaluate_wan_link_verification(
                WanLinkVerificationInput(
                    link=link, slot=slot, ping=ping, error_message=error_message
                )
            )
            completed_at = datetime.now(UTC)
            row = await self.repository.create(
                {
                    "router_id": router.id,
                    "organization_id": router.organization_id,
                    "location_id": router.location_id,
                    "scope": VerificationScope.WAN.value,
                    "run_group_id": run_group_id,
                    "isp_link_id": link.id,
                    "overall": overall.value,
                    "checks": [c.model_dump(mode="json") for c in checks],
                    "started_at": started_at,
                    "completed_at": completed_at,
                    "created_by": actor_user_id,
                }
            )
            persisted.append(row)
            link_results.append(
                WanLinkVerificationResponse(
                    isp_link_id=str(link.id),
                    slot=slot,
                    overall=overall,
                    checks=checks,
                )
            )

        enabled_ids = {link.id for link in ordered if link.is_enabled}
        gate_passes = wan_verification_gate_passes(
            enabled_link_ids=enabled_ids, runs=persisted
        )
        return WanVerificationResponse(
            router_id=str(router_id),
            run_group_id=str(run_group_id),
            gate_passes=gate_passes,
            links=link_results,
        )

    async def get_wan_gate(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> WanVerificationGateResponse:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        links, _meta = await self.isp_link_lookup.list_links(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=1,
            page_size=100,
        )
        enabled_ids = {link.id for link in links if link.is_enabled}
        if not enabled_ids:
            return WanVerificationGateResponse(
                router_id=str(router_id),
                passes=False,
                message="No enabled WAN links to verify",
            )

        runs = await self.repository.list_latest_group_for_router(
            router_id, scope=VerificationScope.WAN.value
        )
        if not runs:
            return WanVerificationGateResponse(
                router_id=str(router_id),
                passes=False,
                message="No WAN verification has been run yet",
            )

        passes = wan_verification_gate_passes(
            enabled_link_ids=enabled_ids, runs=runs
        )
        message = None if passes else "Latest WAN verification did not pass for all links"
        return WanVerificationGateResponse(
            router_id=str(router_id),
            passes=passes,
            run_group_id=str(runs[0].run_group_id),
            message=message,
        )
