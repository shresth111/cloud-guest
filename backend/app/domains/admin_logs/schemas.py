"""Pydantic response schemas for the Admin Logs domain (see this
package's own ``__init__.py`` module docstring)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class DashboardLoginLogResponse(BaseModel):
    id: str
    user_id: str | None
    email: str
    ip_address: str
    success: bool
    failure_reason: str | None
    created_at: datetime


class DashboardLoginLogListResponse(BaseModel):
    items: list[DashboardLoginLogResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class RouterErrorLogResponse(BaseModel):
    id: str
    location_id: str
    location_name: str
    router_id: str
    router_name: str
    event_type: str
    message: str | None
    occurred_at: datetime
    is_error: bool


class RouterErrorLogListResponse(BaseModel):
    items: list[RouterErrorLogResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


__all__ = [
    "DashboardLoginLogResponse",
    "DashboardLoginLogListResponse",
    "RouterErrorLogResponse",
    "RouterErrorLogListResponse",
]
