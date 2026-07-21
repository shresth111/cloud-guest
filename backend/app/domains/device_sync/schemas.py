"""Pydantic request/response schemas for the Device Synchronization
domain API.

Follows the same pydantic v2 conventions as ``app.domains.isp.schemas``:
plain ``str`` fields for every UUID, explicit response-builder functions in
``router.py`` doing the ``str(...)`` conversion rather than
``ConfigDict(from_attributes=True)`` auto-mapping. No request body is
needed for the sync trigger itself -- the target router is the path
parameter, and there is nothing else for a caller to configure (see
``__init__.py``'s own module docstring for what always runs).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

__all__ = ["DeviceSyncRunResponse", "DeviceSyncRunListResponse"]


class DeviceSyncRunResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    status: str
    component_results: dict[str, object]
    started_at: datetime
    completed_at: datetime
    created_at: datetime


class DeviceSyncRunListResponse(BaseModel):
    items: list[DeviceSyncRunResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool
