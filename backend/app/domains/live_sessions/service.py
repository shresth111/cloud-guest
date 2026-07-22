"""Live session service.

Provides a unified view of active guest sessions by composing the existing
guest domain's session management — this is a thin orchestration layer,
not a new data store.
"""

from __future__ import annotations

import uuid
import logging
from typing import Any

from app.domains.guest.service import GuestService
from app.domains.guest.repository import GuestRepositoryProtocol
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
        try:
            result = await self.guest_service.list_sessions(
                organization_id=organization_id,
                location_id=location_id,
                page=page,
                page_size=page_size,
            )
            # Adapt guest sessions to live session format
            for s in result[0] if isinstance(result, tuple) else result:
                sessions.append(LiveSession(
                    id=str(getattr(s, "id", "")),
                    username=getattr(s, "guest_username", str(getattr(s, "id", ""))),
                    mac=getattr(s, "mac_address", ""),
                    ip=getattr(s, "ip_address", ""),
                    ssid=getattr(s, "ssid", ""),
                    nas=getattr(s, "nas_identifier", ""),
                    router=getattr(s, "router_name", ""),
                    device=getattr(s, "user_agent", ""),
                    signal=getattr(s, "signal_strength", 0) or 0,
                    session_time_seconds=getattr(s, "session_duration_seconds", 0) or 0,
                    download_bytes=getattr(s, "bytes_downloaded", 0) or 0,
                    upload_bytes=getattr(s, "bytes_uploaded", 0) or 0,
                    status=getattr(s, "status", "active"),
                    location_id=str(getattr(s, "location_id", "")),
                    organization_id=str(getattr(s, "organization_id", "")),
                    started_at=getattr(s, "connected_at", None),
                ))
        except Exception as exc:
            logger.warning("Could not fetch live sessions: %s", exc)

        return LiveSessionListResponse(
            items=sessions,
            total=len(sessions),
            page=page,
            page_size=page_size,
        )

    async def disconnect_session(self, session_id: uuid.UUID) -> SessionActionResponse:
        try:
            await self.guest_service.disconnect_session(session_id)
            return SessionActionResponse(
                session_id=str(session_id),
                action="disconnect",
                message="Session disconnected",
            )
        except Exception as exc:
            return SessionActionResponse(
                session_id=str(session_id),
                action="disconnect",
                success=False,
                message=str(exc),
            )

    async def pause_session(self, session_id: uuid.UUID) -> SessionActionResponse:
        try:
            await self.guest_service.pause_session(session_id)
            return SessionActionResponse(
                session_id=str(session_id),
                action="pause",
                message="Session paused",
            )
        except Exception as exc:
            return SessionActionResponse(
                session_id=str(session_id),
                action="pause",
                success=False,
                message=str(exc),
            )

    async def resume_session(self, session_id: uuid.UUID) -> SessionActionResponse:
        try:
            await self.guest_service.resume_session(session_id)
            return SessionActionResponse(
                session_id=str(session_id),
                action="resume",
                message="Session resumed",
            )
        except Exception as exc:
            return SessionActionResponse(
                session_id=str(session_id),
                action="resume",
                success=False,
                message=str(exc),
            )

    async def extend_session(
        self, session_id: uuid.UUID, minutes: int = 30
    ) -> SessionActionResponse:
        try:
            await self.guest_service.extend_session(session_id, extra_minutes=minutes)
            return SessionActionResponse(
                session_id=str(session_id),
                action="extend",
                message=f"Session extended by {minutes} minutes",
            )
        except Exception as exc:
            return SessionActionResponse(
                session_id=str(session_id),
                action="extend",
                success=False,
                message=str(exc),
            )
