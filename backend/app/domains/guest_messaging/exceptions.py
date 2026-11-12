"""Login-messaging errors. Each carries ``data.error_code``; the frontend
switches on it, never on the message."""

from __future__ import annotations

from typing import Any

from fastapi import status

from app.common.exceptions import CloudGuestError


class GuestMessagingError(CloudGuestError):
    error_code = "guest_messaging_error"
    status_code_default = status.HTTP_400_BAD_REQUEST

    def __init__(self, message: str, **data: Any) -> None:
        super().__init__(
            message,
            status_code=self.status_code_default,
            data={"error_code": self.error_code, **data},
        )


class LoginProviderNotFoundError(GuestMessagingError):
    error_code = "not_found"
    status_code_default = status.HTTP_404_NOT_FOUND


class OrganizationNotFoundError(GuestMessagingError):
    error_code = "organization_not_found"
    status_code_default = status.HTTP_404_NOT_FOUND


class ProviderTypeNotSupportedError(GuestMessagingError):
    error_code = "provider_type_not_supported"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY


class ProviderConfigInvalidError(GuestMessagingError):
    error_code = "provider_config_invalid"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY


class InvalidPhoneError(GuestMessagingError):
    error_code = "invalid_phone"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY


class ByoNotAllowedError(GuestMessagingError):
    """The organization is not entitled to ``guest_login_byo``."""

    error_code = "byo_not_allowed"
    status_code_default = status.HTTP_403_FORBIDDEN


class VerificationNotStartedError(GuestMessagingError):
    error_code = "verification_not_started"
    status_code_default = status.HTTP_409_CONFLICT


class VerificationCodeInvalidError(GuestMessagingError):
    error_code = "verification_code_invalid"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY


class VerificationRateLimitedError(GuestMessagingError):
    error_code = "verification_rate_limited"
    status_code_default = status.HTTP_429_TOO_MANY_REQUESTS


class ProviderSendFailedError(GuestMessagingError):
    """The venue's provider refused the verification code."""

    error_code = "provider_send_failed"
    status_code_default = status.HTTP_502_BAD_GATEWAY


class ProviderEncryptionUnavailableHttpError(GuestMessagingError):
    error_code = "provider_encryption_unavailable"
    status_code_default = status.HTTP_503_SERVICE_UNAVAILABLE
