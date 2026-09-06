"""Pydantic request/response schemas for the Guest Access Control API.

Follows the same pydantic v2 conventions as every other domain
(``ConfigDict``, ``from_attributes``, explicit ``Field`` descriptions) and
is wrapped in the project's standard ``ApiResponse``/``build_response``
envelope by ``router.py``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .constants import (
    MAX_IMPORT_BATCH_SIZE,
    AccessRuleType,
    GuestRuleImportRejectionCode,
)

__all__ = [
    "GuestAccessRuleCreate",
    "GuestAccessRuleImportRow",
    "GuestAccessRuleImportRequest",
    "RejectedGuestRuleImportRowResponse",
    "GuestAccessRuleImportResponse",
    "DeviceAccessRuleCreate",
    "AccessCheckRequest",
    "GuestAccessRuleResponse",
    "DeviceAccessRuleResponse",
    "GuestAccessRuleListResponse",
    "DeviceAccessRuleListResponse",
    "AccessCheckResponse",
]


def _assume_utc_if_naive(v: datetime | None) -> datetime | None:
    """HTML's ``<input type="datetime-local">`` -- what the customer
    dashboard's Whitelist "End Date" field (``WhiteList.tsx``) submits --
    produces a value with no UTC offset, e.g. ``"2026-08-01T06:49"``.
    Pydantic parses that into a *naive* ``datetime``. ``validate_rule_expiry``/
    ``is_rule_expired`` then compare it against ``datetime.now(UTC)`` (aware),
    which raises ``TypeError: can't compare offset-naive and offset-aware
    datetimes`` -- an unhandled 500 that (since it escapes CORSMiddleware)
    the browser reports as a CORS failure, masking the real error. Treat a
    naive value as already-UTC, the same interpretation every other stored
    ``expires_at`` in this table uses, rather than crashing the request."""
    if v is not None and v.tzinfo is None:
        return v.replace(tzinfo=UTC)
    return v


# ============================================================================
# Request schemas
# ============================================================================


class GuestAccessRuleCreate(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = Field(
        default=None,
        description="Scopes the rule to one location. Omit for org-wide.",
    )
    identifier: str = Field(..., min_length=1, max_length=255)
    rule_type: AccessRuleType
    reason: str | None = Field(default=None, max_length=2000)
    email: EmailStr | None = Field(
        default=None,
        description="Optional contact email for whoever this rule was created for.",
    )
    expires_at: datetime | None = Field(
        default=None,
        description=(
            "Required for rule_type=temporary. Optional (but permitted) for "
            "every other rule type."
        ),
    )

    _normalize_expires_at = field_validator("expires_at")(_assume_utc_if_naive)


class DeviceAccessRuleCreate(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = Field(default=None)
    mac_address: str = Field(..., min_length=12, max_length=17)
    rule_type: AccessRuleType
    reason: str | None = Field(default=None, max_length=2000)
    email: EmailStr | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)

    _normalize_expires_at = field_validator("expires_at")(_assume_utc_if_naive)


class AccessCheckRequest(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = None
    identifier: str | None = Field(default=None, max_length=255)
    mac_address: str | None = Field(default=None, max_length=17)


# ----------------------------------------------------------------------------
# Bulk import
# ----------------------------------------------------------------------------


class GuestAccessRuleImportRow(BaseModel):
    """One row of an uploaded list.

    ## Why almost every field here is a loose ``str``

    Per-row rejection is the whole contract of this endpoint, and pydantic
    would quietly break it. A strongly-typed row (``rule_type:
    AccessRuleType``, ``expires_at: datetime``, ``email: EmailStr``) makes
    FastAPI answer **422 for the entire batch** the moment one cell is
    malformed -- so a 200-room hotel with one guest whose email column got
    a stray character loses all 200 rows and gets a pydantic error path
    (``body -> rules -> 137 -> email``) instead of a report naming the
    guest. That is exactly the all-or-nothing failure this endpoint exists
    to avoid, and it would have been invisible until a real file hit it.

    So the messy fields arrive as strings and are parsed by
    ``GuestAccessService.import_guest_rules``, which rejects the row it
    came from and keeps going. The *batch*-level fields on
    ``GuestAccessRuleImportRequest`` stay strongly typed: those come from
    the upload form rather than the file, and one bad value there really is
    a malformed request.

    ``reason``/``email`` keep a length bound because no real PMS export
    produces a 2000-character reason by accident -- that is a malformed
    request, not messy data.

    Only ``identifier`` carries meaning on its own; everything else falls
    back to the batch-level default.
    """

    identifier: str = Field(
        default="",
        description=(
            "The phone number or email address the guest signs in with. "
            "Phone numbers must carry a country code (+919876543210); a "
            "bare national number is rejected with an instruction rather "
            "than stored, because rules match by exact string equality "
            "and a national-format rule matches nobody. Deliberately "
            "unbounded and defaulted rather than required: an empty or "
            "over-long cell is a row to report, not a batch to fail."
        ),
    )
    rule_type: str | None = Field(
        default=None,
        description=(
            "Overrides the batch default. blocklist is not importable -- "
            "see constants.IMPORTABLE_RULE_TYPES."
        ),
    )
    location_id: uuid.UUID | str | None = Field(
        default=None, description="Overrides the batch default."
    )
    expires_at: datetime | str | None = Field(
        default=None,
        description=(
            "ISO-8601. Overrides the batch default -- e.g. a PMS export "
            "carrying a different checkout date per guest. An empty value "
            "inherits the batch's expiry rather than meaning 'permanent'."
        ),
    )
    reason: str | None = Field(default=None, max_length=2000)
    email: str | None = Field(default=None, max_length=255)


class GuestAccessRuleImportRequest(BaseModel):
    """One bounded batch: the whole-batch defaults, then the rows.

    ``rules``'s ``max_length`` is enforced by pydantic, so a 1001-row body
    is refused with a 422 before the handler runs and before a single row
    is written -- never a silent partial import of the first 1000. A venue
    with more than a thousand guests uploads more than one file, which is
    the same answer ``app.domains.mac_authorization`` and
    ``app.domains.voucher`` already give at the same number.
    """

    organization_id: uuid.UUID
    location_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Scopes every row to one location unless the row overrides it. "
            "Omit for org-wide. A hotel's list is one property, so this "
            "belongs on the request rather than repeated 200 times."
        ),
    )
    rule_type: AccessRuleType = Field(
        default=AccessRuleType.WHITELIST,
        description=(
            "The batch default. whitelist covers the case this endpoint "
            "exists for -- a property's Always Allowed list."
        ),
    )
    expires_at: datetime | None = Field(
        default=None,
        description=(
            "The batch default expiry: one checkout time for a nightly "
            "guest list, omitted entirely for a permanent staff list."
        ),
    )
    rules: list[GuestAccessRuleImportRow] = Field(
        ..., min_length=1, max_length=MAX_IMPORT_BATCH_SIZE
    )

    _normalize_expires_at = field_validator("expires_at")(_assume_utc_if_naive)


class RejectedGuestRuleImportRowResponse(BaseModel):
    """Why one row was not written.

    Same shape as ``app.domains.mac_authorization.schemas
    .RejectedImportRowResponse`` (the failing key, plus a reason) with two
    additions a 200-row upload needs: the row number the operator has to go
    and fix, and a stable ``code`` the upload screen can group forty
    identical failures by. See ``constants.GuestRuleImportRejectionCode``.
    """

    row_number: int
    identifier: str
    code: GuestRuleImportRejectionCode
    reason: str


class GuestAccessRuleImportResponse(BaseModel):
    """Created and updated are reported separately, never summed -- see
    ``service.GuestRuleImportResult``."""

    imported_count: int
    updated_count: int
    imported_ids: list[uuid.UUID]
    updated_ids: list[uuid.UUID]
    rejected: list[RejectedGuestRuleImportRowResponse]


# ============================================================================
# Response schemas
# ============================================================================


class GuestAccessRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    identifier: str
    rule_type: str
    reason: str | None
    email: str | None
    expires_at: datetime | None
    is_active: bool
    # -- block enforcement -------------------------------------------------
    #
    # Surfaced so the dashboard can stop asserting something it has no way
    # of knowing. "Blocked" and "blocked, and the two sessions they were in
    # were ended" are different outcomes, and before these fields existed
    # the UI showed the same toast for both -- and for the case where the
    # router could not be reached at all.
    #
    # ``sessions_ended`` is a count of sessions *confirmed* gone from the
    # router's own active table, never of removals attempted. It is
    # legitimately ``0`` for a blocked guest who was not online, which is
    # why the status is carried alongside it rather than inferred from it.
    #
    # See ``constants.BlockEnforcementStatus``. ``None`` on rows written
    # before enforcement existed -- see migration 0107 for why those are
    # not backfilled.
    enforcement_status: str | None = None
    enforcement_error: str | None = None
    enforced_at: datetime | None = None
    sessions_ended: int | None = None
    created_at: datetime
    updated_at: datetime


class DeviceAccessRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    mac_address: str
    rule_type: str
    reason: str | None
    email: str | None
    expires_at: datetime | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class GuestAccessRuleListResponse(BaseModel):
    items: list[GuestAccessRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class DeviceAccessRuleListResponse(BaseModel):
    items: list[DeviceAccessRuleResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class AccessCheckResponse(BaseModel):
    allowed: bool
    rule_type: str | None
    matched_rule_id: uuid.UUID | None
    reason: str | None
