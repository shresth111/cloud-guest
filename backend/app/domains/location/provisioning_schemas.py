"""Pydantic request/response schemas for Smart Location Provisioning
(``POST /api/v1/locations/provision`` and
``POST /api/v1/locations/{id}/resend-welcome-email``).

Kept in their own module, separate from ``schemas.py`` -- the plain
Location CRUD schemas that file already holds are a stable, independently
reviewable surface; the provisioning request has ~40 fields across five
nested concerns (customer, location, owner, router, plan/feature
selection), and mixing the two would make ``schemas.py`` unwieldy for no
benefit (mirrors this same domain's own ``provisioning_service.py`` vs.
``service.py`` split decision -- see that module's docstring). Response
fields are exactly what the spec's "Success Screen" needs to render (see
``docs/location/FLOW.md``'s "Response payload" section): the temporary
password is returned here, and only here, exactly once.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator

from app.domains.billing.constants import PlanFeatureKey

from .enums import PropertyType

__all__ = [
    "NewOrganizationInputSchema",
    "ProvisionLocationRequest",
    "ProvisionLocationResponse",
    "ProvisionLocationPreviewResponse",
    "ResendWelcomeEmailResponse",
]


class NewOrganizationInputSchema(BaseModel):
    """ "Create Customer (if new)" -- required only when
    ``existing_organization_id`` is omitted from the enclosing request."""

    name: str = Field(..., min_length=1, max_length=200)
    slug: str = Field(..., min_length=1, max_length=150)
    contact_email: EmailStr
    contact_phone: str | None = Field(default=None, max_length=20)
    legal_name: str | None = Field(default=None, max_length=255)
    timezone: str = Field(default="UTC", max_length=50)
    default_locale: str = Field(default="en", max_length=10)


class LocationInputSchema(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    slug: str = Field(..., min_length=1, max_length=150)
    property_type: PropertyType | None = None
    address_line1: str = Field(..., min_length=1, max_length=255)
    address_line2: str | None = Field(default=None, max_length=255)
    city: str = Field(..., min_length=1, max_length=100)
    state_province: str = Field(..., min_length=1, max_length=100)
    postal_code: str = Field(..., min_length=1, max_length=20)
    country: str = Field(..., min_length=2, max_length=2)
    timezone: str = Field(default="UTC", max_length=50)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_phone: str | None = Field(default=None, max_length=20)
    contact_email: EmailStr | None = None
    settings: dict[str, Any] = Field(default_factory=dict)


class OwnerInputSchema(BaseModel):
    """ "Create Location Owner" -- ``username`` is auto-generated when
    omitted; the temporary password is always generated server-side and
    never accepted from the caller (see
    ``docs/location/FLOW.md``'s "shown-once temporary password" section)."""

    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr
    username: str | None = Field(default=None, min_length=3, max_length=100)
    phone: str | None = Field(default=None, max_length=20)
    designation: str | None = Field(default=None, max_length=100)
    department: str | None = Field(default=None, max_length=100)
    employee_id: str | None = Field(default=None, max_length=50)
    timezone: str = Field(default="UTC", max_length=50)
    language: str = Field(default="en", max_length=10)
    send_welcome_sms: bool = Field(
        default=False,
        description="Only takes effect if `phone` is also provided.",
    )


class RouterInputSchema(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    serial_number: str = Field(..., min_length=1, max_length=100)
    mac_address: str = Field(..., min_length=1, max_length=17)
    model: str = Field(..., min_length=1, max_length=100)
    management_ip_address: str | None = Field(default=None, max_length=45)
    public_ip_address: str | None = Field(default=None, max_length=45)
    api_username: str | None = Field(default=None, max_length=100)
    api_secret: str | None = Field(default=None, max_length=500)
    settings: dict[str, Any] = Field(default_factory=dict)


class FeatureOverrideInputSchema(BaseModel):
    """One Super-Admin-selected divergence from the selected Plan's own
    stock ``PlanFeature`` defaults -- see
    ``LocationProvisioningService``'s module docstring for the full
    "clone into a private custom Plan" design decision this feeds into."""

    feature_key: PlanFeatureKey
    limit_value: Decimal | None = Field(default=None, ge=0)
    is_enabled: bool | None = None
    tier_value: str | None = None


class ProvisionLocationRequest(BaseModel):
    existing_organization_id: str | None = Field(
        default=None,
        description=(
            "Provision a new location for an existing customer. Mutually "
            "exclusive with `new_organization`."
        ),
    )
    new_organization: NewOrganizationInputSchema | None = Field(
        default=None,
        description=(
            "Create a brand-new customer/organization. Mutually exclusive "
            "with `existing_organization_id`."
        ),
    )
    location: LocationInputSchema
    owner: OwnerInputSchema
    router: RouterInputSchema
    router_config_template_id: str | None = Field(
        default=None,
        description=(
            "Explicit config template to apply. When omitted, the most "
            "recently created active system template is used; if none "
            "exists, provisioning fails with a clear, documented error "
            "rather than silently skipping this step."
        ),
    )
    plan_id: str = Field(..., description="The base subscription Plan to apply.")
    feature_overrides: list[FeatureOverrideInputSchema] = Field(default_factory=list)
    coupon_code: str | None = None

    @model_validator(mode="after")
    def _validate_organization_selection(self) -> ProvisionLocationRequest:
        has_existing = self.existing_organization_id is not None
        has_new = self.new_organization is not None
        if has_existing == has_new:
            raise ValueError(
                "Exactly one of existing_organization_id or new_organization "
                "must be provided"
            )
        return self

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "new_organization": {
                    "name": "Grand Plaza Hotel",
                    "slug": "grand-plaza-hotel",
                    "contact_email": "ops@grandplaza.example.com",
                },
                "location": {
                    "name": "Grand Plaza Downtown",
                    "slug": "downtown",
                    "property_type": "hotel",
                    "address_line1": "1 Plaza Way",
                    "city": "Austin",
                    "state_province": "TX",
                    "postal_code": "78701",
                    "country": "US",
                },
                "owner": {
                    "first_name": "Priya",
                    "last_name": "Shah",
                    "email": "priya@grandplaza.example.com",
                },
                "router": {
                    "name": "Lobby Router",
                    "serial_number": "SN-00001",
                    "mac_address": "AA:BB:CC:DD:EE:01",
                    "model": "RB5009UG+S+",
                },
                "plan_id": "00000000-0000-0000-0000-000000000000",
            }
        }
    )


class ProvisionLocationResponse(BaseModel):
    organization_id: str
    organization_name: str
    location_id: str
    location_name: str
    location_code: str
    property_type: PropertyType | None = None
    plan_id: str
    plan_name: str
    feature_summary: dict[str, Any] = Field(default_factory=dict)
    router_id: str
    router_name: str
    tunnel_ip_address: str | None = None
    owner_user_id: str
    owner_name: str
    owner_username: str
    owner_email: str
    owner_temporary_password: str = Field(
        ...,
        description=(
            "Shown exactly once, in this response only -- never logged, "
            "never persisted in plaintext, and never retrievable again "
            "afterward."
        ),
    )
    login_url: str
    provisioned_at: str


class ProvisionLocationPreviewResponse(BaseModel):
    """The Organization Provisioning Wizard's "review summary before
    final provisioning" screen -- a read-only preview, never persisted.
    See ``provisioning_service.ProvisionLocationPreview``'s own
    docstring for exactly what each generated-ID field maps to and the
    honest boundary on what this preview does and does not guarantee."""

    organization_id: str | None = Field(
        default=None,
        description=(
            "Null when previewing a new organization -- it does not exist "
            "yet, so it has no id yet."
        ),
    )
    organization_name: str
    customer_id: str = Field(
        ..., description="The organization's slug -- this platform's Customer ID."
    )
    site_id: str = Field(..., description="Previewed Location.location_code.")
    nas_id: str = Field(..., description="Previewed RADIUS NAS code.")
    controller_id: str = Field(
        ..., description="The router's own serial_number -- the 'Controller ID'."
    )
    plan_id: str
    plan_name: str
    feature_summary: dict[str, Any] = Field(default_factory=dict)
    owner_name: str
    owner_email: str
    owner_username_preview: str
    router_name: str


class ResendWelcomeEmailResponse(BaseModel):
    message: str
    location_id: str
    owner_email: str
