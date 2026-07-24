"""FastAPI dependencies for the Support Tickets domain.

Wires the repository/service layer, composing with RBAC (for audit
logging) and Location (for the ``location_id``-belongs-to-``organization_id``
cross-reference check) rather than duplicating either -- mirrors
``app.domains.guest_access.dependencies``'s identical composition style.
"""

from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import TicketRepository, TicketRepositoryProtocol
from .service import TicketService


def get_ticket_repository(
    db: AsyncSession = Depends(get_db_session),
) -> TicketRepositoryProtocol:
    return TicketRepository(db)


def get_ticket_service(
    repository: TicketRepositoryProtocol = Depends(get_ticket_repository),
    location_service: LocationService = Depends(get_location_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    redis_client: Redis = Depends(get_redis_client),
) -> TicketService:
    return TicketService(
        repository,
        location_lookup=location_service,
        audit_writer=audit_repository,
        redis_client=redis_client,
    )


__all__ = ["get_ticket_repository", "get_ticket_service"]
