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
    "ChannelPartnerEmailMissingError",
    "ChannelPartnerNotActiveError",
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


class ChannelPartnerEmailMissingError(ChannelPartnerError):
    """``resend_welcome_message`` was asked to resend the email channel for
    a partner whose ``email`` is ``NULL`` (it is optional at onboarding --
    see ``schemas.ChannelPartnerCreateRequest``).

    A refusal, deliberately, rather than a silently-skipped channel: the
    operator explicitly asked for the email to go out, and reporting
    anything other than "there is no address to send it to" would be the
    "reported success while doing nothing" failure this domain exists to
    avoid. ``409`` (not ``422``) for the same reason
    ``app.domains.location.provisioning_service.OwnerNotProvisionedError``
    uses it: the request is well-formed, the *row* is in the wrong state
    for the action."""

    def __init__(self, channel_partner_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Channel partner {channel_partner_id} has no email address on "
            "record, so the welcome email cannot be resent.",
            status_code=status.HTTP_409_CONFLICT,
        )


class ChannelPartnerNotActiveError(ChannelPartnerError):
    """``resend_welcome_message`` was called for a partner that is not
    ``ACTIVE`` -- see ``service.ChannelPartnerService.resend_welcome_message``'s
    own docstring for why a revoked partner is refused rather than
    re-welcomed."""

    def __init__(
        self, channel_partner_id: uuid.UUID | str, current_status: str
    ) -> None:
        super().__init__(
            f"Channel partner {channel_partner_id} is {current_status}, not "
            "active -- reactivate the partner before resending its welcome "
            "message.",
            status_code=status.HTTP_409_CONFLICT,
        )
