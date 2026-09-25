"""Guest Marketing errors. Every one carries ``data.error_code`` from the
contract's error index (§5.11) -- the frontend switches on it, never on the
message."""

from __future__ import annotations

from typing import Any

from fastapi import status

from app.common.exceptions import CloudGuestError


class MarketingError(CloudGuestError):
    error_code = "marketing_error"
    status_code_default = status.HTTP_400_BAD_REQUEST

    def __init__(self, message: str, **data: Any) -> None:
        super().__init__(
            message,
            status_code=self.status_code_default,
            data={"error_code": self.error_code, **data},
        )


class _NotFound(MarketingError):
    status_code_default = status.HTTP_404_NOT_FOUND


class _Conflict(MarketingError):
    status_code_default = status.HTTP_409_CONFLICT


class _Unprocessable(MarketingError):
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY


class _Forbidden(MarketingError):
    status_code_default = status.HTTP_403_FORBIDDEN


class MarketingNotFoundError(_NotFound):
    error_code = "not_found"


class LocationNotFoundForMarketingError(_NotFound):
    error_code = "location_not_found"


class TemplateNotFoundError(_NotFound):
    error_code = "template_not_found"


class InvalidTokenError(_NotFound):
    error_code = "invalid_token"


class CrossLocationError(_Forbidden):
    error_code = "cross_location"


class SystemTemplateReadOnlyError(_Forbidden):
    error_code = "system_template_read_only"


class SessionNotActiveError(_Forbidden):
    error_code = "session_not_active"


class OrganizationRequiredForMarketingError(MarketingError):
    error_code = "organization_required"


class TemplateEmptyError(_Unprocessable):
    error_code = "template_empty"


class UnknownVariableError(_Unprocessable):
    error_code = "unknown_variable"


class UnsubscribeLinkMissingError(_Unprocessable):
    error_code = "unsubscribe_link_missing"


class SmsTooLongError(_Unprocessable):
    error_code = "sms_too_long"


class WhatsAppCustomNotSupportedError(_Unprocessable):
    error_code = "whatsapp_custom_not_supported"


class ChannelMismatchError(_Unprocessable):
    error_code = "channel_mismatch"


class ChannelMissingInTemplateError(_Unprocessable):
    error_code = "channel_missing_in_template"


class QuietHoursError(_Unprocessable):
    error_code = "quiet_hours"


class ScheduleOutOfRangeError(_Unprocessable):
    error_code = "schedule_out_of_range"


class InvalidAddressError(_Unprocessable):
    error_code = "invalid_address"


class MarketingValidationError(_Unprocessable):
    error_code = "validation_error"


class TemplateNameTakenError(_Conflict):
    error_code = "template_name_taken"


class TemplateInUseError(_Conflict):
    error_code = "template_in_use"


class VersionConflictError(_Conflict):
    error_code = "version_conflict"


class InvalidStatusTransitionError(_Conflict):
    error_code = "invalid_status_transition"


class ChannelNotConfiguredError(_Conflict):
    error_code = "channel_not_configured"


class TemplateNotSendableError(_Conflict):
    error_code = "template_not_sendable"


class AudienceEmptyError(_Conflict):
    error_code = "audience_empty"


class AudienceTooLargeError(_Conflict):
    error_code = "audience_too_large"


class ConsentNotOfferedError(_Conflict):
    error_code = "consent_not_offered"


class StaleConsentTextError(_Conflict):
    error_code = "stale_consent_text"


class PortalConfigMissingError(_Conflict):
    error_code = "portal_config_missing"


class DailyTestSendLimitError(MarketingError):
    error_code = "test_send_limit"
    status_code_default = status.HTTP_429_TOO_MANY_REQUESTS


class PublicRateLimitedError(MarketingError):
    error_code = "rate_limited"
    status_code_default = status.HTTP_429_TOO_MANY_REQUESTS
