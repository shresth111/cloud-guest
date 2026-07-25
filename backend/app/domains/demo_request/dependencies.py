"""FastAPI dependencies for the Demo Request domain -- wires the
repository/service layer. No composition with any other domain is needed
(no tenant/location cross-reference, no audit-writer dependency): a demo
request is a standalone lead-capture row, the simplest domain shape in this
codebase."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .repository import DemoRequestRepository, DemoRequestRepositoryProtocol
from .service import DemoRequestService


def get_demo_request_repository(
    db: AsyncSession = Depends(get_db_session),
) -> DemoRequestRepositoryProtocol:
    return DemoRequestRepository(db)


def get_demo_request_service(
    repository: DemoRequestRepositoryProtocol = Depends(get_demo_request_repository),
) -> DemoRequestService:
    return DemoRequestService(repository)


__all__ = ["get_demo_request_repository", "get_demo_request_service"]
