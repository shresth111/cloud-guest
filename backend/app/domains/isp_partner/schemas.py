"""Request bodies for ``/isp`` (API_CONTRACT §4).

Every body is ``extra="forbid"``: a body that names ``organization_id``,
``org_type``, ``parent_organization_id``, ``parent`` or anything else not
listed here is a 422 before any handler runs. No body ever carries an
organization id.
"""

from __future__ import annotations

import re
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domains.location.enums import PropertyType

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _email(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not _EMAIL.match(value):
        raise ValueError("not a valid email address")
    return value.lower()


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SuspendRequest(_Body):
    reason: str | None = Field(default=None, max_length=255)


# -- customers --------------------------------------------------------------
class CustomerCreateRequest(_Body):
    name: str = Field(min_length=1, max_length=200)
    slug: str | None = Field(
        default=None, min_length=2, max_length=150, pattern=r"^[a-z0-9][a-z0-9-]*$"
    )
    legal_name: str | None = Field(default=None, max_length=255)
    gstin: str | None = Field(default=None, max_length=15)
    external_ref: str | None = Field(default=None, max_length=64)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_email: str = Field(max_length=255)
    contact_phone: str | None = Field(default=None, max_length=20)
    address_line1: str | None = Field(default=None, max_length=255)
    city: str | None = Field(default=None, max_length=100)
    state_province: str | None = Field(default=None, max_length=100)
    postal_code: str | None = Field(default=None, max_length=20)
    timezone: str = Field(default="Asia/Kolkata", max_length=50)
    notes: str | None = None

    _check_email = field_validator("contact_email")(_email)


class CustomerUpdateRequest(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    #: ADDENDUM_03 §4; edit only, never on create.
    zone_id: uuid.UUID | None = None
    #: Present only so the 422 can say "immutable" rather than "unknown".
    slug: str | None = None
    legal_name: str | None = Field(default=None, max_length=255)
    gstin: str | None = Field(default=None, max_length=15)
    external_ref: str | None = Field(default=None, max_length=64)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_email: str | None = Field(default=None, max_length=255)
    contact_phone: str | None = Field(default=None, max_length=20)
    address_line1: str | None = Field(default=None, max_length=255)
    city: str | None = Field(default=None, max_length=100)
    state_province: str | None = Field(default=None, max_length=100)
    postal_code: str | None = Field(default=None, max_length=20)
    timezone: str | None = Field(default=None, max_length=50)
    notes: str | None = None

    _check_email = field_validator("contact_email")(_email)


# -- locations --------------------------------------------------------------
class IspLocationCreateRequest(_Body):
    name: str = Field(min_length=1, max_length=200)
    slug: str | None = Field(
        default=None, min_length=2, max_length=150, pattern=r"^[a-z0-9][a-z0-9-]*$"
    )
    property_type: PropertyType | None = None
    address_line1: str = Field(min_length=1, max_length=255)
    address_line2: str | None = Field(default=None, max_length=255)
    city: str = Field(min_length=1, max_length=100)
    state_province: str = Field(min_length=1, max_length=100)
    postal_code: str = Field(min_length=1, max_length=20)
    country: str = Field(default="IN", min_length=2, max_length=2)
    timezone: str = Field(default="Asia/Kolkata", max_length=50)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_phone: str | None = Field(default=None, max_length=20)
    contact_email: str | None = Field(default=None, max_length=255)

    _check_email = field_validator("contact_email")(_email)


class IspLocationUpdateRequest(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    property_type: PropertyType | None = None
    address_line1: str | None = Field(default=None, min_length=1, max_length=255)
    address_line2: str | None = Field(default=None, max_length=255)
    city: str | None = Field(default=None, min_length=1, max_length=100)
    state_province: str | None = Field(default=None, min_length=1, max_length=100)
    postal_code: str | None = Field(default=None, min_length=1, max_length=20)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    timezone: str | None = Field(default=None, max_length=50)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_phone: str | None = Field(default=None, max_length=20)
    contact_email: str | None = Field(default=None, max_length=255)

    _check_email = field_validator("contact_email")(_email)


# -- routers ----------------------------------------------------------------
class IspRouterCreateRequest(_Body):
    name: str = Field(min_length=1, max_length=200)
    serial_number: str = Field(min_length=1, max_length=100)
    mac_address: str = Field(
        min_length=17, max_length=17, pattern=r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$"
    )
    model: str = Field(min_length=1, max_length=100)
    vendor: str = Field(default="mikrotik", max_length=50)


class IspRouterUpdateRequest(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    model: str | None = Field(default=None, min_length=1, max_length=100)


# -- staff users ------------------------------------------------------------
class IspUserCreateRequest(_Body):
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    email: str = Field(max_length=255)
    phone: str | None = Field(default=None, max_length=20)
    role: str = Field(max_length=50)
    customer_ids: list[uuid.UUID] | None = None
    send_welcome_email: bool = True

    _check_email = field_validator("email")(_email)


class IspUserUpdateRequest(_Body):
    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    phone: str | None = Field(default=None, max_length=20)
    role: str | None = Field(default=None, max_length=50)


class IspUserScopeRequest(_Body):
    customer_ids: list[uuid.UUID] | None = None
