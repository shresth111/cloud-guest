from __future__ import annotations

import uuid

from fastapi import Depends

from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.monitoring.default_alerting import ensure_default_alerting
from app.domains.monitoring.dependencies import (
    get_alert_service,
    get_notification_service,
)
from app.domains.monitoring.service import AlertService, NotificationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_service
from app.domains.rbac.service import RBACService

from .service import CustomerProvisioningService


def get_customer_provisioning_service(
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    rbac_service: RBACService = Depends(get_rbac_service),
    alert_service: AlertService = Depends(get_alert_service),
    notification_service: NotificationService = Depends(get_notification_service),
) -> CustomerProvisioningService:
    # Composed here rather than imported into the service, the same
    # orchestration-layer placement `app.domains.organization.router` uses
    # for its own `ensure_default_alerting` call: the provisioning service
    # stays unaware of what an alert is, and `monitoring` keeps ownership of
    # both services the helper needs.
    async def _default_alerting(
        *, organization_id: uuid.UUID, contact_email: str | None
    ) -> object:
        return await ensure_default_alerting(
            alert_service,
            notification_service,
            organization_id=organization_id,
            contact_email=contact_email,
        )

    return CustomerProvisioningService(
        organization_service=organization_service,
        location_service=location_service,
        rbac_service=rbac_service,
        default_alerting=_default_alerting,
    )
