"""System Settings domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like
every other domain's exception hierarchy -- mirrors
``app.domains.channel_partner.exceptions``'s identical style.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "SystemSettingsError",
    "DefaultPlanNotFoundError",
    "UnknownFeatureOverrideError",
]


class SystemSettingsError(CloudGuestError):
    """Base exception for System Settings domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class DefaultPlanNotFoundError(SystemSettingsError):
    """``PUT /system-settings`` named a ``new_customer_default_plan_id`` that
    does not resolve to a real, non-deleted ``Plan``.

    A rejection, deliberately, rather than storing a dangling id: this
    setting exists to be *consumed* at provisioning time, and storing an id
    that points at nothing would only surface the failure later, on a real
    customer's first day, far from the operator who typed it. ``422`` (the
    request is well-formed, the referenced entity just doesn't exist) --
    the same shape ``billing``'s own plan-reference validators use.
    """

    def __init__(self, plan_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Plan not found: {plan_id}. Pick an existing plan as the "
            "new-customer default.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            data={"new_customer_default_plan_id": str(plan_id)},
        )


class UnknownFeatureOverrideError(SystemSettingsError):
    """A default feature override named a ``feature_key`` that is not a real
    platform feature key (``app.domains.billing.constants.PlanFeatureKey``).

    Same reasoning as ``DefaultPlanNotFoundError``: an override on a
    non-existent feature is inert noise that would silently do nothing at
    provisioning time, so it is refused at write time instead.
    """

    def __init__(self, feature_key: str) -> None:
        super().__init__(
            f"Unknown feature key: {feature_key!r}.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            data={"feature_key": feature_key},
        )
