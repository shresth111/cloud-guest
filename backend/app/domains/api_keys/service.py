"""API Keys domain business logic: create (plaintext shown once), list,
revoke, and the real-time authentication resolution
(``resolve_active_key``) ``app.domains.auth.dependencies.get_current_user``
calls for every ``X-API-Key``-authenticated request.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime

from .constants import (
    API_KEY_DISPLAY_PREFIX_LENGTH,
    API_KEY_PREFIX,
    API_KEY_SECRET_BYTES,
)
from .exceptions import (
    ApiKeyAlreadyRevokedError,
    ApiKeyAuthenticationError,
    ApiKeyNotFoundError,
    CrossOrganizationApiKeyAccessError,
)
from .models import ApiKey
from .repository import ApiKeyRepositoryProtocol

logger = logging.getLogger(__name__)


def _hash_key(plaintext_key: str) -> str:
    """SHA-256 hex digest -- see ``models.ApiKey``'s own docstring for why
    this, not Argon2id, is the right hash for a high-entropy, randomly-
    generated bearer credential."""
    return hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()


def _generate_plaintext_key() -> str:
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(API_KEY_SECRET_BYTES)}"


class ApiKeyService:
    """Core API Keys business logic."""

    def __init__(self, repository: ApiKeyRepositoryProtocol) -> None:
        self.repository = repository

    async def create_api_key(
        self,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID,
        name: str,
        expires_at: datetime | None = None,
    ) -> tuple[ApiKey, str]:
        """Creates a new key. Returns ``(row, plaintext_key)`` -- the
        plaintext is shown exactly once; only its hash is ever persisted."""
        plaintext_key = _generate_plaintext_key()
        api_key = await self.repository.create_api_key(
            organization_id=requesting_organization_id,
            user_id=actor_user_id,
            name=name,
            key_hash=_hash_key(plaintext_key),
            display_prefix=plaintext_key[:API_KEY_DISPLAY_PREFIX_LENGTH],
            expires_at=expires_at,
            revoked_at=None,
            last_used_at=None,
            created_by=actor_user_id,
        )
        logger.info(
            "api_key_created",
            extra={
                "api_key_id": str(api_key.id),
                "organization_id": str(requesting_organization_id),
            },
        )
        return api_key, plaintext_key

    async def get_api_key(
        self, api_key_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> ApiKey:
        api_key = await self.repository.get_api_key_by_id(api_key_id)
        if api_key is None:
            raise ApiKeyNotFoundError(api_key_id)
        self._enforce_scope(api_key, requesting_organization_id)
        return api_key

    async def list_api_keys(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ):
        return await self.repository.list_api_keys(
            requesting_organization_id=requesting_organization_id,
            page=page,
            page_size=page_size,
        )

    async def revoke_api_key(
        self, api_key_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> ApiKey:
        api_key = await self.get_api_key(
            api_key_id, requesting_organization_id=requesting_organization_id
        )
        if api_key.revoked_at is not None:
            raise ApiKeyAlreadyRevokedError(api_key_id)
        return await self.repository.update_api_key(
            api_key, {"revoked_at": datetime.now(UTC)}
        )

    async def resolve_active_key(self, plaintext_key: str) -> ApiKey:
        """Real-time authentication resolution -- hash-compares
        ``plaintext_key`` and rejects it if revoked/expired. Raises the
        single, non-distinguishing ``ApiKeyAuthenticationError`` for every
        failure reason (see that exception's own docstring)."""
        api_key = await self.repository.get_active_api_key_by_hash(
            _hash_key(plaintext_key)
        )
        if api_key is None:
            raise ApiKeyAuthenticationError()
        if api_key.revoked_at is not None:
            raise ApiKeyAuthenticationError()
        if api_key.expires_at is not None and api_key.expires_at <= datetime.now(UTC):
            raise ApiKeyAuthenticationError()
        await self.repository.update_api_key(
            api_key, {"last_used_at": datetime.now(UTC)}
        )
        return api_key

    def _enforce_scope(
        self, api_key: ApiKey, requesting_organization_id: uuid.UUID | None
    ) -> None:
        if (
            requesting_organization_id is not None
            and api_key.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationApiKeyAccessError()


__all__ = ["ApiKeyService"]
