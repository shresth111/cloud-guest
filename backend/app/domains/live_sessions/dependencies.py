from __future__ import annotations

from fastapi import Depends

from app.domains.guest.dependencies import get_guest_service
from app.domains.guest.service import GuestService
from app.domains.rbac.dependencies import get_rbac_service
from app.domains.rbac.service import RBACService

from .service import LiveSessionService


def get_live_session_service(
    guest_service: GuestService = Depends(get_guest_service),
    rbac_service: RBACService = Depends(get_rbac_service),
) -> LiveSessionService:
    return LiveSessionService(
        guest_service=guest_service,
        rbac_service=rbac_service,
    )
