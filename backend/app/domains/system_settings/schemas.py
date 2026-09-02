"""Pydantic schemas for the System Settings domain.

The request/response shape is *typed* even though the store underneath is a
generic key/value table -- the API contract a caller sees is a concrete
``PlatformSettingsResponse`` with named, typed fields, and the service is
the single seam that maps those named fields to/from the ``SystemSettingKey``
rows. A new setting adds a field here and a key in ``constants``; the store
and migration are untouched.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class FeatureOverride(BaseModel):
    """One default per-feature on/off override applied on top of the default
    plan's own features at provisioning time."""

    feature_key: str
    enabled: bool


class PlatformSettingsResponse(BaseModel):
    """The platform-wide new-customer defaults, resolved from the store.

    Every field is optional/empty when never configured -- an empty store
    reads as "no default plan, no overrides", never an error.
    """

    new_customer_default_plan_id: str | None = None
    new_customer_default_feature_overrides: list[FeatureOverride] = Field(
        default_factory=list
    )


class PlatformSettingsUpdateRequest(BaseModel):
    """``PUT /system-settings`` body.

    A field left unset (``None`` for the plan / omitted list) is a no-op for
    that setting rather than a clear -- see the router/service docstrings.
    ``new_customer_default_plan_id`` may be sent as an explicit empty string
    to positively clear the default plan.
    """

    new_customer_default_plan_id: str | None = None
    new_customer_default_feature_overrides: list[FeatureOverride] | None = None
