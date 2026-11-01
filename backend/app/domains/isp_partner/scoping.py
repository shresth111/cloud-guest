"""``IspScope``: the only code allowed to turn an ``/isp`` path id into a row.

Every function answers **404** for "does not exist", "belongs to another ISP",
"is not a STANDARD child", "is archived" and "is outside your confinement"
alike, so ids cannot be probed. This plays the role
``organization.scoping.enforce_target_organization`` plays elsewhere, plus
confinement -- and unlike that helper it has no "platform caller sees
everything" branch, because GLOBAL callers never reach ``/isp`` at all.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from app.domains.organization.enums import OrganizationStatus, OrganizationType

from .exceptions import (
    IspCustomerNotFoundError,
    IspLocationNotFoundError,
    IspPortalConfigNotFoundError,
    IspRouterNotFoundError,
)

if TYPE_CHECKING:
    from .dependencies import IspContext


def _is_visible_customer(isp: IspContext, organization: Any) -> bool:
    if organization is None:
        return False
    if getattr(organization, "is_deleted", False):
        return False
    if organization.status == OrganizationStatus.ARCHIVED.value:
        return False
    if organization.org_type != OrganizationType.STANDARD.value:
        return False
    if organization.parent_organization_id != isp.isp_org_id:
        return False
    return isp.confined_customer_ids is None or (
        organization.id in isp.confined_customer_ids
    )


class IspScope:
    """Stateless; every method takes the caller's ``IspContext``."""

    @staticmethod
    async def assert_customer(isp: IspContext, isp_customer_id: uuid.UUID) -> Any:
        organization = await isp.repository.get_organization(isp_customer_id)
        if not _is_visible_customer(isp, organization):
            raise IspCustomerNotFoundError()
        return organization

    @staticmethod
    async def assert_location(isp: IspContext, isp_location_id: uuid.UUID) -> Any:
        location = await isp.repository.get_location(isp_location_id)
        if location is None or getattr(location, "is_deleted", False):
            raise IspLocationNotFoundError()
        try:
            await IspScope.assert_customer(isp, location.organization_id)
        except IspCustomerNotFoundError:
            raise IspLocationNotFoundError() from None
        return location

    @staticmethod
    async def assert_router(isp: IspContext, isp_router_id: uuid.UUID) -> Any:
        router = await isp.repository.get_router(isp_router_id)
        if router is None or getattr(router, "is_deleted", False):
            raise IspRouterNotFoundError()
        try:
            await IspScope.assert_customer(isp, router.organization_id)
        except IspCustomerNotFoundError:
            raise IspRouterNotFoundError() from None
        return router

    @staticmethod
    async def assert_portal_config(isp: IspContext, config_id: uuid.UUID) -> Any:
        config = await isp.repository.get_portal_config(config_id)
        if config is None or getattr(config, "is_deleted", False):
            raise IspPortalConfigNotFoundError()
        try:
            await IspScope.assert_customer(isp, config.organization_id)
        except IspCustomerNotFoundError:
            raise IspPortalConfigNotFoundError() from None
        return config

    @staticmethod
    async def assert_cpe(isp: IspContext, cpe_id: uuid.UUID) -> Any:
        # Imported here: tr069 imports this module, not the other way round.
        from app.domains.tr069.exceptions import Tr069DeviceNotFoundError

        device = await isp.repository.get_cpe(cpe_id)
        if (
            device is None
            or getattr(device, "is_deleted", False)
            or device.isp_organization_id != isp.isp_org_id
        ):
            raise Tr069DeviceNotFoundError()
        if device.customer_organization_id is not None:
            try:
                await IspScope.assert_customer(isp, device.customer_organization_id)
            except IspCustomerNotFoundError:
                raise Tr069DeviceNotFoundError() from None
        elif isp.confined_customer_ids is not None:
            # An unassigned CPE belongs to no customer; a confined user sees
            # only their customers' devices.
            raise Tr069DeviceNotFoundError()
        return device

    @staticmethod
    async def optional_filters(
        isp: IspContext,
        *,
        isp_customer_id: uuid.UUID | None = None,
        isp_location_id: uuid.UUID | None = None,
        isp_router_id: uuid.UUID | None = None,
    ) -> tuple[uuid.UUID | None, uuid.UUID | None, uuid.UUID | None]:
        """Validate the optional customer/location/router query filters and
        return ``(customer_id, location_id, router_id)``. A location or router
        implies its customer; naming a customer that disagrees is a 404."""
        customer_id = isp_customer_id
        location_id = None
        router_id = None
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
        if isp_location_id is not None:
            location = await IspScope.assert_location(isp, isp_location_id)
            if customer_id is not None and location.organization_id != customer_id:
                raise IspLocationNotFoundError()
            customer_id = location.organization_id
            location_id = location.id
        if isp_router_id is not None:
            router = await IspScope.assert_router(isp, isp_router_id)
            if customer_id is not None and router.organization_id != customer_id:
                raise IspRouterNotFoundError()
            if location_id is not None and router.location_id != location_id:
                raise IspRouterNotFoundError()
            customer_id = router.organization_id
            location_id = router.location_id
            router_id = router.id
        return customer_id, location_id, router_id


__all__ = ["IspScope"]
