"""FastAPI dependencies for router discovery / snapshot / compatibility."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.isp.dependencies import get_isp_service
from app.domains.isp.service import IspService
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import RouterSnapshotRepository, RouterSnapshotRepositoryProtocol
from .service import DiscoveryService
from .verification_repository import (
    VerificationRunRepository,
    VerificationRunRepositoryProtocol,
)
from .verification_service import WanVerificationService


def get_router_snapshot_repository(
    db: AsyncSession = Depends(get_db_session),
) -> RouterSnapshotRepositoryProtocol:
    return RouterSnapshotRepository(db)


def get_verification_run_repository(
    db: AsyncSession = Depends(get_db_session),
) -> VerificationRunRepositoryProtocol:
    return VerificationRunRepository(db)


def get_discovery_service(
    repository: RouterSnapshotRepositoryProtocol = Depends(
        get_router_snapshot_repository
    ),
    router_service: RouterService = Depends(get_router_service),
) -> DiscoveryService:
    return DiscoveryService(repository, router_service)


def get_wan_verification_service(
    repository: VerificationRunRepositoryProtocol = Depends(
        get_verification_run_repository
    ),
    router_service: RouterService = Depends(get_router_service),
    isp_service: IspService = Depends(get_isp_service),
) -> WanVerificationService:
    return WanVerificationService(
        repository, router_service, isp_service, isp_service
    )


__all__ = [
    "get_router_snapshot_repository",
    "get_verification_run_repository",
    "get_discovery_service",
    "get_wan_verification_service",
]
