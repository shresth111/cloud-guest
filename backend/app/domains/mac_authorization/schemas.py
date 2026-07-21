"""Pydantic request/response schemas for the MAC Authorization domain
API.

Follows the same pydantic v2 conventions as ``app.domains.vlan.schemas``:
plain ``str`` fields for every UUID, explicit response-builder functions in
``router.py`` doing the ``str(...)`` conversion rather than
``ConfigDict(from_attributes=True)`` auto-mapping, and ``MessageResponse``
re-exported from the auth domain rather than duplicated.

``MacAuthorizationImportRequest.entries``'s ``max_length=1000`` mirrors
``app.domains.voucher.schemas.VoucherImportRequest``'s own identical
bound -- one request, one bounded batch, never an unbounded body.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.common.masking import MaskedMac
from app.domains.auth.schemas import MessageResponse

__all__ = [
    "MessageResponse",
    "MacAuthorizationEntryCreateRequest",
    "MacAuthorizationEntryUpdateRequest",
    "MacAuthorizationEntryResponse",
    "MacAuthorizationEntryListResponse",
    "MacAuthorizationImportRow",
    "MacAuthorizationImportRequest",
    "RejectedImportRowResponse",
    "MacAuthorizationImportResponse",
]


class MacAuthorizationEntryCreateRequest(BaseModel):
    mac_address: str
    authorization_type: str = "permanent"
    location_id: str | None = None
    expires_at: datetime | None = None
    comment: str | None = None
    is_enabled: bool = True


class MacAuthorizationEntryUpdateRequest(BaseModel):
    mac_address: str | None = None
    authorization_type: str | None = None
    location_id: str | None = None
    expires_at: datetime | None = None
    comment: str | None = None
    is_enabled: bool | None = None


class MacAuthorizationEntryResponse(BaseModel):
    id: str
    organization_id: str
    location_id: str | None
    mac_address: MaskedMac
    authorization_type: str
    expires_at: datetime | None
    comment: str | None
    is_enabled: bool
    created_at: datetime


class MacAuthorizationEntryListResponse(BaseModel):
    items: list[MacAuthorizationEntryResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class MacAuthorizationImportRow(BaseModel):
    mac_address: str
    authorization_type: str = "permanent"
    location_id: str | None = None
    expires_at: datetime | None = None
    comment: str | None = None
    is_enabled: bool = True


class MacAuthorizationImportRequest(BaseModel):
    entries: list[MacAuthorizationImportRow] = Field(..., min_length=1, max_length=1000)


class RejectedImportRowResponse(BaseModel):
    mac_address: str
    reason: str


class MacAuthorizationImportResponse(BaseModel):
    imported_count: int
    imported_ids: list[str]
    rejected: list[RejectedImportRowResponse]
