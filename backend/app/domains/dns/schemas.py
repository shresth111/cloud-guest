"""Pydantic request/response schemas for the DNS Management domain API.

Follows the same pydantic v2 conventions as ``app.domains.dhcp.schemas``:
plain ``str`` fields for every UUID, explicit response-builder functions in
``router.py`` doing the ``str(...)`` conversion, and ``MessageResponse``
re-exported from the auth domain rather than duplicated.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.domains.auth.schemas import MessageResponse

from .constants import DEFAULT_TTL_SECONDS, DnsRecordType

__all__ = [
    "MessageResponse",
    "DnsRecordCreateRequest",
    "DnsRecordUpdateRequest",
    "DnsRecordResponse",
    "DnsRecordListResponse",
]


class DnsRecordCreateRequest(BaseModel):
    router_id: str
    name: str
    address: str
    record_type: DnsRecordType = DnsRecordType.A
    ttl_seconds: int = Field(default=DEFAULT_TTL_SECONDS, ge=1)
    comment: str | None = None
    is_enabled: bool = True


class DnsRecordUpdateRequest(BaseModel):
    name: str | None = None
    address: str | None = None
    record_type: DnsRecordType | None = None
    ttl_seconds: int | None = Field(default=None, ge=1)
    comment: str | None = None
    is_enabled: bool | None = None


class DnsRecordResponse(BaseModel):
    id: str
    router_id: str
    organization_id: str
    location_id: str
    name: str
    record_type: str
    address: str
    ttl_seconds: int
    comment: str | None
    is_enabled: bool
    created_at: datetime


class DnsRecordListResponse(BaseModel):
    items: list[DnsRecordResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool
