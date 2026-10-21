"""Request and response bodies for the Master ISP-partner endpoints
(API_CONTRACT §3, ``/platform/isp-partners``).

Request bodies are ``extra="forbid"``: an unknown field (``org_type``,
``parent_organization_id``, ``slug`` on PATCH, ...) is a 422 before any
handler runs. The org type and parent are not inputs at all; the service
always creates a top-level ``msp`` organization.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SLUG = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"
_GSTIN = re.compile(r"^\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]$")


def _email(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not _EMAIL.match(value):
        raise ValueError("not a valid email address")
    return value.lower()


def _gstin(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    value = value.strip().upper()
    if not _GSTIN.match(value):
        raise ValueError("not a valid 15-character GSTIN")
    return value


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class IspOwnerRequest(_Body):
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    email: str = Field(max_length=255)
    phone: str | None = Field(default=None, max_length=20)
    send_welcome_email: bool = True

    _v_email = field_validator("email")(_email)


class IspPartnerCreateRequest(_Body):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(min_length=2, max_length=100, pattern=_SLUG)
    legal_name: str | None = Field(default=None, max_length=255)
    gstin: str | None = Field(default=None, max_length=15)
    contact_email: str = Field(max_length=255)
    contact_phone: str | None = Field(default=None, max_length=20)
    support_phone: str | None = Field(default=None, max_length=20)
    support_email: str | None = Field(default=None, max_length=255)
    timezone: str = Field(default="Asia/Kolkata", min_length=1, max_length=64)
    default_customer_plan_id: uuid.UUID
    max_customers: int | None = Field(default=None, ge=0, le=100_000)
    notes: str | None = Field(default=None, max_length=5000)
    owner: IspOwnerRequest

    _v_contact = field_validator("contact_email")(_email)
    _v_support = field_validator("support_email")(_email)
    _v_gstin = field_validator("gstin")(_gstin)


class IspPartnerUpdateRequest(_Body):
    """Every field optional. ``slug`` is immutable and therefore not listed,
    so sending it is a 422 (``extra="forbid"``)."""

    name: str | None = Field(default=None, min_length=2, max_length=200)
    legal_name: str | None = Field(default=None, max_length=255)
    gstin: str | None = Field(default=None, max_length=15)
    contact_email: str | None = Field(default=None, max_length=255)
    contact_phone: str | None = Field(default=None, max_length=20)
    support_phone: str | None = Field(default=None, max_length=20)
    support_email: str | None = Field(default=None, max_length=255)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    default_customer_plan_id: uuid.UUID | None = None
    max_customers: int | None = Field(default=None, ge=0, le=100_000)
    notes: str | None = Field(default=None, max_length=5000)

    _v_contact = field_validator("contact_email")(_email)
    _v_support = field_validator("support_email")(_email)
    _v_gstin = field_validator("gstin")(_gstin)


class IspPartnerSuspendRequest(_Body):
    reason: str = Field(min_length=1, max_length=255)


class IspPartnerActivateRequest(_Body):
    """Empty on purpose; present so an unexpected body is refused."""


# -- responses ----------------------------------------------------------------
class PlanRef(BaseModel):
    id: uuid.UUID
    name: str


class IspPartnerCounts(BaseModel):
    customers: int = 0
    customers_suspended: int = 0
    locations: int = 0
    routers_total: int = 0
    routers_online: int = 0
    cpes_total: int = 0
    cpes_online: int = 0
    users: int = 0


class IspPartnerOwnerView(BaseModel):
    user_id: uuid.UUID
    name: str
    email: str
    status: str  # active | disabled


class IspPartnerAcsView(BaseModel):
    """Status only. The password never leaves the ISP's own console."""

    username: str
    enabled: bool


class IspPartnerResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    legal_name: str | None
    gstin: str | None
    status: str
    org_status: str
    contact_email: str
    contact_phone: str | None
    support_phone: str | None
    support_email: str | None
    timezone: str
    default_customer_plan: PlanRef | None
    max_customers: int | None
    notes: str | None = None
    counts: IspPartnerCounts
    created_at: datetime
    suspended_at: datetime | None
    suspended_reason: str | None
    # Detail only (additive to API_CONTRACT §3; see LANE_NOTES).
    owners: list[IspPartnerOwnerView] | None = None
    acs: IspPartnerAcsView | None = None


class IspPartnerListResponse(BaseModel):
    items: list[IspPartnerResponse]
    total: int
    page: int
    page_size: int
    pages: int


class IspOwnerCredentialResponse(BaseModel):
    """``temporary_password`` is returned only in this response, once."""

    user_id: uuid.UUID
    username: str
    email: str
    temporary_password: str
    login_url: str


class IspPartnerCreateResponse(BaseModel):
    isp_partner: IspPartnerResponse
    owner: IspOwnerCredentialResponse


__all__ = [
    "IspOwnerCredentialResponse",
    "IspOwnerRequest",
    "IspPartnerAcsView",
    "IspPartnerActivateRequest",
    "IspPartnerCounts",
    "IspPartnerCreateRequest",
    "IspPartnerCreateResponse",
    "IspPartnerListResponse",
    "IspPartnerOwnerView",
    "IspPartnerResponse",
    "IspPartnerSuspendRequest",
    "IspPartnerUpdateRequest",
    "PlanRef",
]
