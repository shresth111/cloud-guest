"""Live session service.

Provides a unified view of active guest sessions by composing the existing
guest domain's session management — this is a thin orchestration layer,
not a new data store.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from app.domains.guest.constants import GuestSessionStatus
from app.domains.guest.service import GuestService
from app.domains.rbac.service import RBACService

from .schemas import LiveSession, LiveSessionListResponse, SessionActionResponse

logger = logging.getLogger(__name__)


def _elapsed_seconds(session, *, now: datetime) -> int:
    """How long this session has actually been running.

    ``GuestSession`` has no ``session_duration_seconds`` column -- the
    previous ``getattr(s, "session_duration_seconds", 0)`` therefore returned
    ``0`` for every session ever listed, which is why the "how long" column on
    the connected-guest screen was uniformly zero. It is derived, not stored:
    from ``started_at`` to ``ended_at`` for a finished session, or to now for a
    live one. Returns ``0`` rather than a negative number if the clock or the
    stored timestamp disagree.
    """
    started_at = session.started_at
    if started_at is None:
        return 0
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=UTC)
    end = session.ended_at or now
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    return max(0, int((end - started_at).total_seconds()))


class LiveSessionService:
    def __init__(
        self,
        guest_service: GuestService,
        rbac_service: RBACService,
    ) -> None:
        self.guest_service = guest_service
        self.rbac_service = rbac_service

    async def list_live_sessions(
        self,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        status: str | None = "active",
        search: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> LiveSessionListResponse:
        sessions = []
        # ``status`` arrives as the raw query-string value (defaulting to
        # "active"); ``GuestService.list_sessions`` filters on the
        # ``GuestSessionStatus`` enum, so coerce it and treat an unknown/blank
        # value as "no status filter" rather than raising.
        session_status: GuestSessionStatus | None = None
        if status:
            try:
                session_status = GuestSessionStatus(status)
            except ValueError:
                session_status = None
        # No try/except around the listing.
        #
        # This used to catch every exception, log a warning, and fall through
        # to `LiveSessionListResponse(items=[], total=0)` -- so a broken query,
        # a database blip or a scoping error all rendered as the sentence "no
        # guests are online right now" on the one screen an operator opens to
        # answer exactly that question. A venue with a full lobby and a failing
        # query looks identical to an empty venue. `GuestService` raises typed
        # `CloudGuestError`s that the app-wide handler turns into real non-2xx
        # responses; anything else is a genuine 500 and should be seen as one.
        rows, meta = await self.guest_service.list_sessions(
            requesting_organization_id=organization_id,
            location_id=location_id,
            status=session_status,
            page=page,
            page_size=page_size,
        )

        # One bulk lookup rather than a per-session device query -- the same
        # N+1 reasoning `GuestService.list_devices_by_ids` was built for.
        device_ids = [s.device_id for s in rows if s.device_id is not None]
        macs_by_device_id: dict[uuid.UUID, str] = {}
        if device_ids:
            devices = await self.guest_service.list_devices_by_ids(
                device_ids=list(dict.fromkeys(device_ids)),
                requesting_organization_id=organization_id,
            )
            macs_by_device_id = {d.id: d.mac_address for d in devices}

        now = datetime.now(UTC)
        for s in rows:
            sessions.append(
                LiveSession(
                    id=str(s.id),
                    guest_id=str(s.guest_id) if s.guest_id else None,
                    mac=macs_by_device_id.get(s.device_id),
                    ip=s.ip_address,
                    device=s.user_agent,
                    session_time_seconds=_elapsed_seconds(s, now=now),
                    download_bytes=s.bytes_downloaded or 0,
                    upload_bytes=s.bytes_uploaded or 0,
                    status=s.status,
                    router_id=str(s.router_id) if s.router_id else None,
                    location_id=str(s.location_id) if s.location_id else None,
                    organization_id=(
                        str(s.organization_id) if s.organization_id else None
                    ),
                    started_at=s.started_at,
                )
            )

        return LiveSessionListResponse(
            items=sessions,
            # The real matching-row count, not `len(sessions)`. Paging off the
            # page's own length told the client there was exactly one page of
            # results no matter how many sessions actually matched.
            total=meta.total_items,
            page=page,
            page_size=page_size,
        )

    # -- session actions -----------------------------------------------------
    #
    # All four of these were broken in the same three ways, and the
    # combination made them report success while doing nothing:
    #
    # 1. They called ``GuestService``'s methods **positionally**, but every
    #    one of those signatures is keyword-only (``async def
    #    disconnect_session(self, *, session_id, ...)``). Every call raised
    #    ``TypeError`` before reaching any logic.
    # 2. A bare ``except Exception`` swallowed that ``TypeError`` into a
    #    ``SessionActionResponse(success=False, message=str(exc))`` -- so the
    #    Python error text became the user-facing message.
    # 3. The router then wrapped that in a hardcoded ``success=True``
    #    envelope and returned 200, and the frontend interceptor never reads
    #    ``envelope.success`` -- so the UI showed a clean success.
    #
    # This is the control an operator reaches for during abuse, a compromised
    # device, or a lawful request. It was dead at every layer, and every
    # layer said it worked.
    #
    # The fix is to call correctly, thread the caller's identity and
    # organization through for scoping and audit, and let failures raise.
    # ``GuestService`` already raises typed ``CloudGuestError``s carrying
    # their own status codes; the app-wide handler turns them into real
    # non-2xx responses. Nothing here catches them any more.

    async def disconnect_session(
        self,
        session_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None = None,
        requesting_organization_id: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> SessionActionResponse:
        await self.guest_service.disconnect_session(
            session_id=session_id,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
            reason=reason,
        )
        return SessionActionResponse(
            session_id=str(session_id),
            action="disconnect",
            message="Session disconnected",
        )

    async def pause_session(
        self,
        session_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None = None,
        requesting_organization_id: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> SessionActionResponse:
        await self.guest_service.pause_session(
            session_id=session_id,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
            reason=reason,
        )
        return SessionActionResponse(
            session_id=str(session_id),
            action="pause",
            message="Session paused",
        )

    async def resume_session(
        self,
        session_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None = None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> SessionActionResponse:
        await self.guest_service.resume_session(
            session_id=session_id,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )
        return SessionActionResponse(
            session_id=str(session_id),
            action="resume",
            message="Session resumed",
        )

    async def extend_session(
        self,
        session_id: uuid.UUID,
        minutes: int = 30,
        *,
        actor_user_id: uuid.UUID | None = None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> SessionActionResponse:
        await self.guest_service.extend_session(
            session_id=session_id,
            additional_minutes=minutes,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
        )
        return SessionActionResponse(
            session_id=str(session_id),
            action="extend",
            message=f"Session extended by {minutes} minutes",
        )
