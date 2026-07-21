"""Campaigns domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "CampaignsError",
    "CampaignNotFoundError",
    "CrossOrganizationCampaignAccessError",
    "InvalidCampaignStatusTransitionError",
    "CampaignNotSchedulableError",
    "InvalidQuestionOptionsError",
    "InvalidAssetUrlsError",
    "InvalidDisplayIntervalError",
    "CampaignQuestionNotFoundError",
    "CampaignAssetNotFoundError",
    "GuestSessionNotFoundError",
    "GuestSessionNotActiveError",
    "DuplicateFirstLoginResponseError",
    "CampaignNotActiveError",
    "WrongCampaignTypeError",
    "OrganizationRequiredError",
]


class CampaignsError(CloudGuestError):
    """Base exception for Campaigns domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class CampaignNotFoundError(CampaignsError):
    def __init__(self, campaign_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Campaign not found: {campaign_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationCampaignAccessError(CampaignsError):
    """A caller acting within organization A attempted to read/mutate a
    campaign belonging to organization B -- mirrors
    ``app.domains.qos.exceptions.CrossOrganizationQosTrafficRuleAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a campaign belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidCampaignStatusTransitionError(CampaignsError):
    def __init__(self, current: str, target: str) -> None:
        super().__init__(
            f"Cannot transition campaign from '{current}' to '{target}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class CampaignNotSchedulableError(CampaignsError):
    """Raised when a ``DRAFT`` campaign is scheduled without a real
    ``starts_at`` set."""

    def __init__(self, campaign_id: uuid.UUID) -> None:
        super().__init__(
            f"Campaign '{campaign_id}' cannot be scheduled without starts_at set",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidQuestionOptionsError(CampaignsError):
    """Raised when ``options`` is empty for a ``SINGLE_CHOICE``/
    ``MULTI_CHOICE`` question, or non-empty for ``RATING_5``/
    ``FREE_TEXT``."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Invalid question options: {reason}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidAssetUrlsError(CampaignsError):
    """Raised when a ``CampaignAsset`` has neither ``image_url`` nor
    ``click_url`` set -- a row with neither would be inert."""

    def __init__(self) -> None:
        super().__init__(
            "A campaign asset must set image_url and/or click_url",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class InvalidDisplayIntervalError(CampaignsError):
    """Raised when ``display_rule=ONCE_PER_N_DAYS`` but
    ``display_interval_days`` is missing or not a positive integer."""

    def __init__(self) -> None:
        super().__init__(
            "display_interval_days must be a positive integer when "
            "display_rule is once_per_n_days",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class CampaignQuestionNotFoundError(CampaignsError):
    def __init__(self, question_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Campaign question not found: {question_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CampaignAssetNotFoundError(CampaignsError):
    def __init__(self, asset_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Campaign asset not found: {asset_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class GuestSessionNotFoundError(CampaignsError):
    def __init__(self, guest_session_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Guest session not found: {guest_session_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class GuestSessionNotActiveError(CampaignsError):
    def __init__(self, guest_session_id: uuid.UUID) -> None:
        super().__init__(
            f"Guest session '{guest_session_id}' is not active",
            status_code=status.HTTP_409_CONFLICT,
        )


class DuplicateFirstLoginResponseError(CampaignsError):
    """See ``models.CampaignResponse``'s own module docstring for why
    this is a service-layer check, not a database constraint."""

    def __init__(self, campaign_id: uuid.UUID) -> None:
        super().__init__(
            f"Guest has already responded to campaign '{campaign_id}' "
            "(first_login_only)",
            status_code=status.HTTP_409_CONFLICT,
        )


class CampaignNotActiveError(CampaignsError):
    """Raised when a guest attempts to respond to/record an impression
    for a campaign whose *effective* status (see
    ``validators.compute_effective_status``) is not currently
    ``ACTIVE``."""

    def __init__(self, campaign_id: uuid.UUID) -> None:
        super().__init__(
            f"Campaign '{campaign_id}' is not currently active",
            status_code=status.HTTP_409_CONFLICT,
        )


class WrongCampaignTypeError(CampaignsError):
    def __init__(self, expected: str, actual: str) -> None:
        super().__init__(
            f"Expected a '{expected}' campaign, got '{actual}'",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


class OrganizationRequiredError(CampaignsError):
    """Raised when a create request carries no ``X-Organization-Id``
    context (``CurrentOrganization`` returns ``None``) -- every
    ``Campaign`` belongs to exactly one organization
    (``organization_id`` is not nullable), mirroring
    ``app.domains.mac_authorization.exceptions
    .OrganizationRequiredError``'s identical rationale."""

    def __init__(self) -> None:
        super().__init__(
            "An X-Organization-Id header is required to create a campaign",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
