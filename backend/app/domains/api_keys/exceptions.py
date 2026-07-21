"""Domain exceptions for the API Keys domain."""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError


class ApiKeyError(CloudGuestError):
    """Base exception for API Keys domain errors."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code)


class ApiKeyNotFoundError(ApiKeyError):
    def __init__(self, api_key_id: uuid.UUID) -> None:
        super().__init__(
            f"API key {api_key_id} not found", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationApiKeyAccessError(ApiKeyError):
    def __init__(self) -> None:
        super().__init__(
            "Cannot access an API key outside your organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class ApiKeyAlreadyRevokedError(ApiKeyError):
    def __init__(self, api_key_id: uuid.UUID) -> None:
        super().__init__(
            f"API key {api_key_id} is already revoked",
            status_code=status.HTTP_409_CONFLICT,
        )


class OrganizationRequiredError(ApiKeyError):
    """Raised when creating an API key without an ``X-Organization-Id``
    scope -- ``PermissionModule.API_KEYS`` is ``ORGANIZATION``-scoped (see
    ``app.domains.rbac.seed``), so a key must belong to exactly one
    organization. Mirrors ``app.domains.campaigns.exceptions
    .OrganizationRequiredError``'s identical per-domain precedent."""

    def __init__(self) -> None:
        super().__init__(
            "An organization scope (X-Organization-Id) is required to "
            "create an API key",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ApiKeyOrganizationMismatchError(ApiKeyError):
    """Raised when an API-key-authenticated request's ``X-Organization-Id``
    header names a different organization than the key's own -- an API
    key is scoped to exactly one organization at creation (see
    ``models.ApiKey``'s own docstring); this rejects a real scope-
    escalation attempt rather than silently trusting the header."""

    def __init__(self) -> None:
        super().__init__(
            "X-Organization-Id does not match this API key's organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class ApiKeyAuthenticationError(ApiKeyError):
    """Raised by :func:`app.domains.api_keys.service.ApiKeyService
    .resolve_active_key` for any reason an ``X-API-Key`` header does not
    resolve to a usable key (no match, revoked, expired) -- deliberately
    one generic, non-distinguishing error for this path (unlike this
    module's own admin-facing exceptions above), the same information-
    leakage judgment call ``app.domains.otp``/``app.domains.voucher``
    already document for a presented secret: a mismatch and an expiry
    must not be distinguishable to whoever is presenting the key."""

    def __init__(self) -> None:
        super().__init__(
            "Invalid or expired API key", status_code=status.HTTP_401_UNAUTHORIZED
        )
