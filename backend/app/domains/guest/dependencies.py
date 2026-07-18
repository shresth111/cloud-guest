"""FastAPI dependencies for the Guest domain.

Wires the repository/service layer, composing with
``app.domains.otp``/``app.domains.voucher``/``app.domains.captive_portal``/
``app.domains.router`` (via the narrow Protocol shapes ``service.py``
defines -- the real services already satisfy them structurally, no adapter
needed) and RBAC (for audit logging) rather than duplicating any of them.

``CurrentNas`` is this module's RADIUS-facing authentication mechanism --
deliberately not RBAC's ``RequirePermission``/``CurrentUser``. See
``service.py``'s module docstring for the full reasoning: FreeRADIUS has no
platform-user identity, so it authenticates via a registered NAS's own
shared secret (``constants.RADIUS_NAS_IDENTIFIER_HEADER``/
``RADIUS_SHARED_SECRET_HEADER``), the identical "device/service credential
via a custom header" posture ``app.domains.router_agent.dependencies
.CurrentAgent`` already established for its own non-platform-user caller.
"""

from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.captive_portal.dependencies import get_captive_portal_service
from app.domains.captive_portal.service import CaptivePortalService
from app.domains.otp.dependencies import get_otp_service
from app.domains.otp.service import OtpService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService
from app.domains.voucher.dependencies import get_voucher_service
from app.domains.voucher.service import VoucherService

from .constants import RADIUS_NAS_IDENTIFIER_HEADER, RADIUS_SHARED_SECRET_HEADER
from .exceptions import RadiusNasAuthenticationError
from .models import RadiusNasClient
from .repository import GuestRepository, GuestRepositoryProtocol
from .service import GuestAnalyticsService, GuestService, RadiusService


def get_guest_repository(
    db: AsyncSession = Depends(get_db_session),
) -> GuestRepositoryProtocol:
    return GuestRepository(db)


def get_guest_service(
    repository: GuestRepositoryProtocol = Depends(get_guest_repository),
    otp_service: OtpService = Depends(get_otp_service),
    voucher_service: VoucherService = Depends(get_voucher_service),
    captive_portal_service: CaptivePortalService = Depends(get_captive_portal_service),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> GuestService:
    return GuestService(
        repository,
        otp_service,
        voucher_service,
        captive_portal_service,
        router_service,
        audit_writer=audit_repository,
    )


def get_radius_service(
    repository: GuestRepositoryProtocol = Depends(get_guest_repository),
    guest_service: GuestService = Depends(get_guest_service),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> RadiusService:
    return RadiusService(
        repository,
        guest_service,
        router_service,
        audit_writer=audit_repository,
    )


def get_guest_analytics_service(
    repository: GuestRepositoryProtocol = Depends(get_guest_repository),
) -> GuestAnalyticsService:
    return GuestAnalyticsService(repository)


async def CurrentNas(
    request: Request,
    radius_service: RadiusService = Depends(get_radius_service),
) -> RadiusNasClient:
    """The authenticated NAS (router) identity for this RADIUS-facing
    request, resolved from ``X-RADIUS-NAS-Identifier``/
    ``X-RADIUS-Shared-Secret`` -- see module docstring."""
    nas_identifier = request.headers.get(RADIUS_NAS_IDENTIFIER_HEADER)
    shared_secret = request.headers.get(RADIUS_SHARED_SECRET_HEADER)
    if not nas_identifier or not shared_secret:
        raise RadiusNasAuthenticationError()
    return await radius_service.authenticate_nas(
        nas_identifier=nas_identifier, shared_secret=shared_secret
    )


__all__ = [
    "get_guest_repository",
    "get_guest_service",
    "get_radius_service",
    "get_guest_analytics_service",
    "CurrentNas",
]
