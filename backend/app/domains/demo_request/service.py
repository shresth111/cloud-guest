"""Demo Request business logic: ``DemoRequestService`` -- create (public,
unauthenticated)/list/get/update (Master console, RBAC-gated), with no
tenant scoping at all (see ``models.py``'s own module docstring: a demo
request belongs to no organization -- there is no ``organization_id`` to
scope by, unlike every other domain in this codebase)."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Protocol

from app.core.email_layout import esc, heading, info_box, paragraph, render_email
from app.database.utils.pagination import PaginationMeta

from .exceptions import DemoRequestNotFoundError
from .models import DemoRequest
from .repository import DemoRequestRepositoryProtocol

logger = logging.getLogger(__name__)


class NotificationEnqueuer(Protocol):
    """The narrow subset of ``app.domains.notification.service
    .NotificationService`` this module needs -- composition, not
    duplication, mirrors ``app.domains.support_tickets.service``'s own
    ``AuditLogWriter``/``LocationLookupProtocol`` narrow-protocol pattern
    for the identical reason (depend on the one method actually used, not
    the concrete class)."""

    async def enqueue(self, **fields: object) -> object: ...


@dataclass
class DemoRequestListResult:
    items: list[DemoRequest]
    meta: PaginationMeta


class DemoRequestService:
    def __init__(
        self,
        repository: DemoRequestRepositoryProtocol,
        *,
        notification_service: NotificationEnqueuer | None = None,
        notify_email: str = "",
    ) -> None:
        self.repository = repository
        # Both default to inert (None/"") so every existing unit test that
        # builds a DemoRequestService directly keeps working unchanged --
        # mirrors app.domains.support_tickets.service.TicketService's own
        # "redis_client: Redis | None = None" posture for the identical
        # reason.
        self.notification_service = notification_service
        self.notify_email = notify_email

    # -- create (public) ---------------------------------------------------

    async def submit_demo_request(
        self,
        *,
        full_name: str,
        email: str,
        phone: str | None,
        company_name: str,
        message: str | None,
        property_type: str | None = None,
        location_count: int | None = None,
        router_count: int | None = None,
    ) -> DemoRequest:
        """The public "Book a Demo" form submission -- no actor/organization
        of any kind exists yet, so unlike every other domain's ``create_*``
        this never sets ``created_by``/``updated_by`` (both stay ``None``,
        ``BaseModel``'s own default). ``property_type``/``location_count``/
        ``router_count`` are the optional, structured lead-qualification
        fields -- validated/bounded already by ``schemas
        .DemoRequestCreateRequest`` before this method is ever called, so
        no further normalization is needed here beyond the same
        strip()-on-strings posture every other field already gets."""
        demo_request = await self.repository.create(
            full_name=full_name.strip(),
            email=str(email).strip().lower(),
            phone=phone.strip() if phone else None,
            company_name=company_name.strip(),
            message=message.strip() if message else None,
            property_type=property_type,
            location_count=location_count,
            router_count=router_count,
        )
        logger.info(
            "demo_request_submitted",
            extra={"demo_request_id": str(demo_request.id)},
        )
        await self._notify_team(demo_request)
        return demo_request

    async def _notify_team(self, demo_request: DemoRequest) -> None:
        """Best-effort internal-team email on every new submission --
        never raises out of ``submit_demo_request`` (a notification
        failure must never fail the prospect's own form submission, the
        same resilience posture ``app.domains.support_tickets.service
        ._publish_live_message`` documents for its own identical "never
        block/break the real write that already succeeded" reasoning). A
        genuine no-op, not a soft failure, when either dependency is unset
        -- see ``Settings.demo_request_notify_email``'s own docstring."""
        if self.notification_service is None or not self.notify_email:
            return
        try:
            from app.domains.notification.constants import (
                NotificationChannelType,
                NotificationEventType,
            )

            content = (
                heading("New demo request")
                + paragraph(
                    f"<strong>{esc(demo_request.full_name)}</strong> "
                    f"({esc(demo_request.email)}) from "
                    f"<strong>{esc(demo_request.company_name)}</strong> "
                    "requested a demo."
                )
                + info_box(
                    [
                        ("Property type", esc(demo_request.property_type or "—")),
                        (
                            "Locations",
                            esc(
                                str(demo_request.location_count)
                                if demo_request.location_count is not None
                                else "—"
                            ),
                        ),
                        (
                            "Routers",
                            esc(
                                str(demo_request.router_count)
                                if demo_request.router_count is not None
                                else "—"
                            ),
                        ),
                        ("Phone", esc(demo_request.phone or "—")),
                        ("Message", esc(demo_request.message or "—")),
                    ]
                )
                + paragraph(
                    "View it on the Master console under Demo Requests.",
                    muted=True,
                )
            )
            await self.notification_service.enqueue(
                event_type=NotificationEventType.DEMO_REQUEST_RECEIVED,
                channel=NotificationChannelType.EMAIL,
                recipient=self.notify_email,
                subject=f"New demo request: {demo_request.company_name}",
                body=render_email(
                    preheader=f"{demo_request.full_name} from "
                    f"{demo_request.company_name} requested a demo.",
                    content_html=content,
                    accent="#6366f1",
                ),
                organization_id=None,
            )
        except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
            logger.warning(
                "demo_request_notify_failed",
                extra={"demo_request_id": str(demo_request.id), "error": str(exc)},
            )

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
        property_type: str | None = None,
    ) -> DemoRequestListResult:
        items, meta = await self.repository.list_records(
            page=page,
            page_size=page_size,
            status=status,
            search=search,
            property_type=property_type,
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


__all__ = ["DemoRequestService", "DemoRequestListResult", "NotificationEnqueuer"]
