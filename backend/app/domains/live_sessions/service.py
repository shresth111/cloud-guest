"""Live session service.

Provides a unified view of active guest sessions by composing the existing
guest domain's session management — this is a thin orchestration layer,
not a new data store.
"""

from __future__ import annotations

import logging
import uuid

from app.domains.guest.constants import GuestSessionStatus
from app.domains.guest.service import GuestService
from app.domains.rbac.service import RBACService

from .schemas import LiveSession, LiveSessionListResponse, SessionActionResponse

logger = logging.getLogger(__name__)


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
        try:
            result = await self.guest_service.list_sessions(
                requesting_organization_id=organization_id,
                location_id=location_id,
                status=session_status,
                page=page,
                page_size=page_size,
            )
            # Adapt guest sessions to live session format
            for s in result[0] if isinstance(result, tuple) else result:
                sessions.append(
                    LiveSession(
                        id=str(getattr(s, "id", "")),
                        username=getattr(
                            s, "guest_username", str(getattr(s, "id", ""))
                        ),
                        mac=getattr(s, "mac_address", ""),
                        ip=getattr(s, "ip_address", ""),
                        ssid=getattr(s, "ssid", ""),
                        nas=getattr(s, "nas_identifier", ""),
                        router=getattr(s, "router_name", ""),
                        device=getattr(s, "user_agent", ""),
                        signal=getattr(s, "signal_strength", 0) or 0,
                        session_time_seconds=getattr(s, "session_duration_seconds", 0)
                        or 0,
                        download_bytes=getattr(s, "bytes_downloaded", 0) or 0,
                        upload_bytes=getattr(s, "bytes_uploaded", 0) or 0,
                        status=getattr(s, "status", "active"),
                        location_id=str(getattr(s, "location_id", "")),
                        organization_id=str(getattr(s, "organization_id", "")),
                        started_at=getattr(s, "started_at", None),
                    )
                )
        except Exception as exc:
            logger.warning("Could not fetch live sessions: %s", exc)

        return LiveSessionListResponse(
            items=sessions,
            total=len(sessions),
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
