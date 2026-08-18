"""Channel Partner domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like
every other domain's exception hierarchy -- mirrors
``app.domains.quotation.exceptions``'s identical style.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "ChannelPartnerError",
    "ChannelPartnerNotFoundError",
    "DuplicateGstNumberError",
]


class ChannelPartnerError(CloudGuestError):
    """Base exception for Channel Partner domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class ChannelPartnerNotFoundError(ChannelPartnerError):
    def __init__(self, channel_partner_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Channel partner not found: {channel_partner_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class DuplicateGstNumberError(ChannelPartnerError):
    def __init__(self, gst_number: str) -> None:
        super().__init__(
            f"A partner with GSTIN {gst_number} is already onboarded.",
            status_code=status.HTTP_409_CONFLICT,
        )
