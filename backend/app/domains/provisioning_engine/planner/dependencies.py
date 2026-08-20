"""FastAPI dependencies for router discovery / snapshot / compatibility."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import RouterSnapshotRepository, RouterSnapshotRepositoryProtocol
from .service import DiscoveryService


def get_router_snapshot_repository(
    db: AsyncSession = Depends(get_db_session),
) -> RouterSnapshotRepositoryProtocol:
    return RouterSnapshotRepository(db)


def get_discovery_service(
    repository: RouterSnapshotRepositoryProtocol = Depends(
        get_router_snapshot_repository
    ),
    router_service: RouterService = Depends(get_router_service),
) -> DiscoveryService:
    return DiscoveryService(repository, router_service)


__all__ = ["get_router_snapshot_repository", "get_discovery_service"]
