"""Demo Request business logic: ``DemoRequestService`` -- create (public,
unauthenticated)/list/get/update (Master console, RBAC-gated), with no
tenant scoping at all (see ``models.py``'s own module docstring: a demo
request belongs to no organization -- there is no ``organization_id`` to
scope by, unlike every other domain in this codebase)."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from app.database.utils.pagination import PaginationMeta

from .exceptions import DemoRequestNotFoundError
from .models import DemoRequest
from .repository import DemoRequestRepositoryProtocol

logger = logging.getLogger(__name__)


@dataclass
class DemoRequestListResult:
    items: list[DemoRequest]
    meta: PaginationMeta


class DemoRequestService:
    def __init__(self, repository: DemoRequestRepositoryProtocol) -> None:
        self.repository = repository

    # -- create (public) ---------------------------------------------------

    async def submit_demo_request(
        self,
        *,
        full_name: str,
        email: str,
        phone: str | None,
        company_name: str,
        message: str | None,
    ) -> DemoRequest:
        """The public "Book a Demo" form submission -- no actor/organization
        of any kind exists yet, so unlike every other domain's ``create_*``
        this never sets ``created_by``/``updated_by`` (both stay ``None``,
        ``BaseModel``'s own default)."""
        demo_request = await self.repository.create(
            full_name=full_name.strip(),
            email=str(email).strip().lower(),
            phone=phone.strip() if phone else None,
            company_name=company_name.strip(),
            message=message.strip() if message else None,
        )
        logger.info(
            "demo_request_submitted",
            extra={"demo_request_id": str(demo_request.id)},
        )
        return demo_request

    # -- read (Master console) ----------------------------------------------

    async def get_demo_request(self, demo_request_id: uuid.UUID) -> DemoRequest:
        demo_request = await self.repository.get_by_id(demo_request_id)
        if demo_request is None or demo_request.is_deleted:
            raise DemoRequestNotFoundError(demo_request_id)
        return demo_request

    async def list_demo_requests(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        status: str | None = None,
        search: str | None = None,
    ) -> DemoRequestListResult:
        items, meta = await self.repository.list_records(
            page=page, page_size=page_size, status=status, search=search
        )
        return DemoRequestListResult(items=items, meta=meta)

    # -- update (Master console) ---------------------------------------------

    async def update_demo_request(
        self,
        *,
        demo_request_id: uuid.UUID,
        data: dict[str, object],
        actor_user_id: uuid.UUID | None,
    ) -> DemoRequest:
        demo_request = await self.get_demo_request(demo_request_id)
        update_data = dict(data)
        update_data["updated_by"] = actor_user_id
        updated = await self.repository.update(demo_request, update_data)
        logger.info(
            "demo_request_updated",
            extra={"demo_request_id": str(updated.id)},
        )
        return updated


__all__ = ["DemoRequestService", "DemoRequestListResult"]
