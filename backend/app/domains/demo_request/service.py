"""Demo Request business logic: ``DemoRequestService`` -- create (public,
unauthenticated)/list/get/update (Master console, RBAC-gated), with no
tenant scoping at all (see ``models.py``'s own module docstring: a demo
request belongs to no organization -- there is no ``organization_id`` to
scope by, unlike every other domain in this codebase)."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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


class SalesWebhookPublisherProtocol(Protocol):
    """The narrow surface of ``app.domains.notification.sales_webhook
    .SalesWebhookPublisher`` this module needs. ``publish`` never raises
    and is a no-op when the webhook is off."""

    async def publish(self, event: str, data: dict[str, object]) -> None: ...


def lead_webhook_payload(demo_request: DemoRequest) -> dict[str, object]:
    """The lead as the sales-automation webhook carries it. Shared with
    ``app.domains.demo_booking.service`` so both events describe a lead in
    the same shape. Excludes ``internal_notes`` (sales' own scratch pad)."""
    from .schemas import compute_lead_priority

    return {
        "id": str(demo_request.id),
        "full_name": demo_request.full_name,
        "email": demo_request.email,
        "phone": demo_request.phone,
        "company_name": demo_request.company_name,
        "message": demo_request.message,
        "property_type": demo_request.property_type,
        "location_count": demo_request.location_count,
        "router_count": demo_request.router_count,
        "lead_priority": compute_lead_priority(
            demo_request.location_count, demo_request.router_count
        ).value,
        "status": demo_request.status,
        "submitted_at": (
            demo_request.created_at.isoformat() if demo_request.created_at else None
        ),
    }


class DemoRequestService:
    def __init__(
        self,
        repository: DemoRequestRepositoryProtocol,
        *,
        notification_service: NotificationEnqueuer | None = None,
        notify_email: str = "",
        sales_webhook: SalesWebhookPublisherProtocol | None = None,
        dedupe_minutes: int = 10,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.repository = repository
        # Double-submit window -- see submit_demo_request. 0 disables.
        self.dedupe_minutes = dedupe_minutes
        # Injected so tests can pin "now" without patching a module clock;
        # same posture as DemoBookingService.
        self._clock = clock or (lambda: datetime.now(UTC))
        # Both default to inert (None/"") so every existing unit test that
        # builds a DemoRequestService directly keeps working unchanged --
        # mirrors app.domains.support_tickets.service.TicketService's own
        # "redis_client: Redis | None = None" posture for the identical
        # reason.
        self.notification_service = notification_service
        self.notify_email = notify_email
        # None (the default) and a disabled publisher are both no-ops.
        self.sales_webhook = sales_webhook

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
        strip()-on-strings posture every other field already gets.

        **Double-submit dedupe.** The marketing site's forms abort a POST
        after 20 s and show "try again"; a visitor on a slow mobile link
        whose first request the server *did* store then submits the very
        same lead a second time, and a fast double click can beat the
        button's disabled state. Within ``dedupe_minutes``, a submission
        identical in every field to the newest stored lead from the same
        address is answered with that stored lead -- no second row, no
        second team email, no second webhook event. Anything that differs
        in any field is a new lead: a prospect writing back with a changed
        message or a second property is exactly who sales wants to see
        twice."""
        fields: dict[str, object] = {
            "full_name": full_name.strip(),
            "email": str(email).strip().lower(),
            "phone": phone.strip() if phone else None,
            "company_name": company_name.strip(),
            "message": message.strip() if message else None,
            "property_type": property_type,
            "location_count": location_count,
            "router_count": router_count,
        }

        duplicate_of = await self._find_duplicate(fields)
        if duplicate_of is not None:
            logger.info(
                "demo_request_duplicate_suppressed",
                extra={"demo_request_id": str(duplicate_of.id)},
            )
            return duplicate_of

        demo_request = await self.repository.create(**fields)
        # The lead is committed BEFORE either side effect below runs. Both
        # the team email and the sales webhook are enqueued through
        # NotificationService.enqueue on this same request-scoped session,
        # and GenericRepository._flush_or_raise answers any flush-time
        # SQLAlchemyError with session.rollback() -- which, with the lead
        # still only flushed, discarded the lead INSERT along with the
        # delivery row. _notify_team/publish then swallowed the error (by
        # design: a notification must never fail a submission) and the
        # request went on to return 201 for a lead that no longer existed.
        # Same ordering, for the same reason, as
        # app.domains.demo_booking.service.DemoBookingService.book_slot.
        await self.repository.commit()
        logger.info(
            "demo_request_submitted",
            extra={"demo_request_id": str(demo_request.id)},
        )
        await self._notify_team(demo_request)
        if self.sales_webhook is not None:
            await self.sales_webhook.publish(
                "demo_request.created", {"lead": lead_webhook_payload(demo_request)}
            )
        return demo_request

    async def _find_duplicate(self, fields: dict[str, object]) -> DemoRequest | None:
        """The newest lead from the same address inside the dedupe window,
        if -- and only if -- every submitted field matches it exactly."""
        if self.dedupe_minutes <= 0:
            return None
        since = self._clock() - timedelta(minutes=self.dedupe_minutes)
        existing = await self.repository.find_recent_by_email(
            str(fields["email"]), since=since
        )
        if existing is None:
            return None
        if all(getattr(existing, key) == value for key, value in fields.items()):
            return existing
        return None

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


__all__ = [
    "DemoRequestListResult",
    "DemoRequestService",
    "NotificationEnqueuer",
    "SalesWebhookPublisherProtocol",
    "lead_webhook_payload",
]
