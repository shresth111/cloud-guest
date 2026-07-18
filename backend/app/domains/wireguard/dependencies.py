"""FastAPI dependencies for the WireGuard domain.

Authorization for the admin-facing peer endpoints is provided entirely by
RBAC's existing ``RequirePermission`` dependency
(``app.domains.rbac.dependencies``) against the already-seeded
``wireguard.*`` permission keys -- nothing here re-implements authorization.
This module only wires the repository/service layer, composing with
``app.domains.router`` (BE-008's ``RouterService``, for tenant-scoped router
lookups) and RBAC (for audit logging) rather than duplicating either.

The device-facing endpoints (``GET /agent/wireguard-config``,
``POST /agent/wireguard-config/handshake``) are authenticated entirely by
``app.domains.router_agent``'s own ``CurrentAgent`` dependency, imported and
reused as-is in ``router.py`` -- there is no separate device-credential
dependency defined here. See ``router.py``'s module docstring for the full
cross-domain composition.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import WireGuardRepository, WireGuardRepositoryProtocol
from .service import WireGuardService


def get_wireguard_repository(
    db: AsyncSession = Depends(get_db_session),
) -> WireGuardRepositoryProtocol:
    return WireGuardRepository(db)


def get_wireguard_service(
    repository: WireGuardRepositoryProtocol = Depends(get_wireguard_repository),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> WireGuardService:
    return WireGuardService(
        repository,
        router_service,
        audit_writer=audit_repository,
        handshake_stale_after_minutes=settings.wireguard_handshake_stale_after_minutes,
    )


__all__ = ["get_wireguard_repository", "get_wireguard_service"]
