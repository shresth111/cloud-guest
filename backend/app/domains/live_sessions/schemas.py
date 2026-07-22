from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class LiveSession(BaseModel):
    id: str
    username: str
    mac: str
    ip: str
    ssid: str
    nas: str
    router: str
    device: str | None = None
    signal: int = 0
    session_time_seconds: int = 0
    download_bytes: int = 0
    upload_bytes: int = 0
    status: str = "active"
    location_id: str | None = None
    organization_id: str | None = None
    started_at: datetime | None = None


class LiveSessionListResponse(BaseModel):
    items: list[LiveSession]
    total: int = 0
    page: int = 1
    page_size: int = 25


class SessionActionResponse(BaseModel):
    session_id: str
    action: str
    success: bool = True
    message: str = "Action performed"
