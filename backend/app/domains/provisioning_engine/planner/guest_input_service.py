"""Guest interface availability orchestration (P10)."""

from __future__ import annotations

import uuid
from typing import Protocol

from app.domains.isp.models import IspLink
from app.domains.router.models import Router

from .exceptions import NoRouterSnapshotError
from .guest_input import evaluate_guest_interface_availability
from .repository import RouterSnapshotRepositoryProtocol
from .schemas import GuestInterfaceAvailabilityResponse


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


def _wan_interfaces_from_links(links: list[IspLink]) -> set[str]:
    names: set[str] = set()
    for link in links:
        if not link.is_enabled:
            continue
        for value in (
            link.physical_interface,
            link.routing_interface,
            link.interface,
        ):
            if value:
                names.add(str(value))
    return names


class GuestInputService:
    def __init__(
        self,
        repository: RouterSnapshotRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        isp_link_lookup: IspLinkLookupProtocol,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.isp_link_lookup = isp_link_lookup

    async def get_interface_availability(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> GuestInterfaceAvailabilityResponse:
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        snapshot = await self.repository.get_latest_for_router(router_id)
        if snapshot is None:
            raise NoRouterSnapshotError(router_id)

        links, _meta = await self.isp_link_lookup.list_links(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=1,
            page_size=100,
        )
        report = evaluate_guest_interface_availability(
            snapshot,
            wan_interfaces=_wan_interfaces_from_links(links),
            snapshot_id=str(snapshot.id),
        )
        return GuestInterfaceAvailabilityResponse(
            router_id=str(router_id),
            snapshot_id=str(snapshot.id),
            interfaces=report.interfaces,
            recommendation=report.recommendation,
        )


__all__ = ["GuestInputService"]
