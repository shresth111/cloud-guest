"""FastAPI dependencies for the Security domain.

Only two, both trivial: a repository over the request's own session, and the
service over that repository. There is no router-lookup, no audit writer and no
device adapter to inject, because this domain reads the platform's own tables
and nothing else -- the shape of the dependency graph is the read-only
guarantee, so it is worth keeping visibly small.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .repository import SecurityRepository, SecurityRepositoryProtocol
from .service import SecurityOverviewService


def get_security_repository(
    db: AsyncSession = Depends(get_db_session),
) -> SecurityRepositoryProtocol:
    return SecurityRepository(db)


def get_security_service(
    repository: SecurityRepositoryProtocol = Depends(get_security_repository),
) -> SecurityOverviewService:
    return SecurityOverviewService(repository)


__all__ = ["get_security_repository", "get_security_service"]
