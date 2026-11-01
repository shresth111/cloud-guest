"""FastAPI providers for the ISP services. Composes the existing services
through their own ``get_*`` dependency functions -- the same graph the live
API already builds -- never a second construction path."""

from __future__ import annotations

import uuid

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.billing.dependencies import get_subscription_service
from app.domains.billing.service import SubscriptionService
from app.domains.captive_portal.dependencies import get_captive_portal_service
from app.domains.captive_portal.service import CaptivePortalService
from app.domains.guest.dependencies import get_guest_service, get_radius_service
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.monitoring.default_alerting import ensure_default_alerting
from app.domains.monitoring.dependencies import get_alert_service
from app.domains.monitoring.dependencies import (
    get_notification_service as get_alert_notification_service,
)
from app.domains.monitoring.service import AlertService
from app.domains.monitoring.service import (
    NotificationService as AlertNotificationService,
)
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService
from app.domains.tr069.credentials import CredentialStore

from .dependencies import get_isp_repository
from .repository import IspRepository
from .service import IspPartnerService
from .service_control import IspServiceControl


def make_live_disconnect(guest_repository, terminator):  # noqa: ANN001, ANN201
    """Re-kick one already-ended session through the existing
    ``issue_live_disconnect`` (the session is DISCONNECTED in our records
    already, so ``disconnect_session`` would refuse the transition)."""

    async def _kick(row):  # noqa: ANN001, ANN202
        from app.domains.guest.service import issue_live_disconnect

        await issue_live_disconnect(
            guest_repository, session=row, terminator=terminator
        )
        return row.disconnect_enforced

    return _kick


def get_service_control(
    db: AsyncSession = Depends(get_db_session),
    radius_service=Depends(get_radius_service),  # noqa: B008
    guest_service=Depends(get_guest_service),  # noqa: B008
    captive_portal_service: CaptivePortalService = Depends(get_captive_portal_service),
    organization_service: OrganizationService = Depends(get_organization_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> IspServiceControl:
    return IspServiceControl(
        session=db,
        radius_service=radius_service,
        guest_service=guest_service,
        captive_portal_service=captive_portal_service,
        organization_service=organization_service,
        audit=audit,
        live_disconnect=make_live_disconnect(
            guest_service.repository, guest_service.session_end_hook
        ),
    )


def get_credential_store(db: AsyncSession = Depends(get_db_session)) -> CredentialStore:
    return CredentialStore(db)


def get_isp_partner_service(
    repository: IspRepository = Depends(get_isp_repository),
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    captive_portal_service: CaptivePortalService = Depends(get_captive_portal_service),
    subscription_service: SubscriptionService = Depends(get_subscription_service),
    router_service: RouterService = Depends(get_router_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
    credentials: CredentialStore = Depends(get_credential_store),
    alert_service: AlertService = Depends(get_alert_service),
    alert_notification_service: AlertNotificationService = Depends(
        get_alert_notification_service
    ),
) -> IspPartnerService:
    async def _default_alerting(
        *, organization_id: uuid.UUID, contact_email: str | None
    ) -> object:
        return await ensure_default_alerting(
            alert_service,
            alert_notification_service,
            organization_id=organization_id,
            contact_email=contact_email,
        )

    return IspPartnerService(
        repository=repository,
        organization_service=organization_service,
        location_service=location_service,
        captive_portal_service=captive_portal_service,
        subscription_service=subscription_service,
        router_service=router_service,
        audit=audit,
        credentials=credentials,
        default_alerting=_default_alerting,
    )
