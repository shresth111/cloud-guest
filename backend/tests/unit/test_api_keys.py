"""Unit tests for the API Keys domain: create (plaintext shown once),
list, revoke, tenant isolation, and the real-time authentication
resolution (``resolve_active_key``) ``app.domains.auth.dependencies
.get_current_user`` calls for every ``X-API-Key``-authenticated request.

Follows this project's plain-``assert``/native-``async def`` style and its
"fake the narrow Protocol boundary" precedent (see
``tests/unit/test_isp_routing.py``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.api_keys.exceptions import (
    ApiKeyAlreadyRevokedError,
    ApiKeyAuthenticationError,
    ApiKeyNotFoundError,
    CrossOrganizationApiKeyAccessError,
)
from app.domains.api_keys.models import ApiKey
from app.domains.api_keys.service import ApiKeyService


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


def _make_api_key(**overrides: object) -> ApiKey:
    fields: dict[str, object] = {
        "organization_id": uuid.uuid4(),
        "user_id": uuid.uuid4(),
        "name": "CI pipeline",
        "key_hash": "unused",
        "display_prefix": "cgst_AbCd",
        "expires_at": None,
        "revoked_at": None,
        "last_used_at": None,
    }
    fields.update(overrides)
    return ApiKey(**_base_fields(**fields))


@dataclass
class FakeApiKeyRepository:
    keys_by_id: dict[uuid.UUID, ApiKey] = field(default_factory=dict)
    keys_by_hash: dict[str, ApiKey] = field(default_factory=dict)

    async def create_api_key(self, **fields: object) -> ApiKey:
        api_key = _make_api_key(**fields)
        self.keys_by_id[api_key.id] = api_key
        self.keys_by_hash[api_key.key_hash] = api_key
        return api_key

    async def get_api_key_by_id(self, api_key_id: uuid.UUID) -> ApiKey | None:
        return self.keys_by_id.get(api_key_id)

    async def get_active_api_key_by_hash(self, key_hash: str) -> ApiKey | None:
        return self.keys_by_hash.get(key_hash)

    async def update_api_key(self, api_key: ApiKey, data: dict[str, object]) -> ApiKey:
        for key, value in data.items():
            setattr(api_key, key, value)
        return api_key

    async def list_api_keys(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ApiKey], PaginationMeta]:
        values = list(self.keys_by_id.values())
        if requesting_organization_id is not None:
            values = [
                v for v in values if v.organization_id == requesting_organization_id
            ]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))


def make_service() -> tuple[ApiKeyService, FakeApiKeyRepository]:
    repository = FakeApiKeyRepository()
    return ApiKeyService(repository), repository


# ============================================================================
# create_api_key
# ============================================================================


async def test_create_api_key_returns_plaintext_once_and_stores_only_hash() -> None:
    service, repository = make_service()
    org_id = uuid.uuid4()
    actor_id = uuid.uuid4()

    api_key, plaintext_key = await service.create_api_key(
        actor_user_id=actor_id, requesting_organization_id=org_id, name="CI pipeline"
    )

    assert plaintext_key.startswith("cgst_")
    assert api_key.display_prefix == plaintext_key[:12]
    stored = repository.keys_by_id[api_key.id]
    assert stored.key_hash != plaintext_key
    assert stored.display_prefix != plaintext_key


async def test_created_key_resolves_via_resolve_active_key() -> None:
    service, _repository = make_service()
    org_id = uuid.uuid4()
    _api_key, plaintext_key = await service.create_api_key(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=org_id,
        name="CI pipeline",
    )

    resolved = await service.resolve_active_key(plaintext_key)

    assert resolved.organization_id == org_id


# ============================================================================
# resolve_active_key -- the real-time auth path
# ============================================================================


async def test_resolve_active_key_rejects_unknown_key() -> None:
    service, _repository = make_service()

    with pytest.raises(ApiKeyAuthenticationError):
        await service.resolve_active_key("cgst_does-not-exist")


async def test_resolve_active_key_rejects_revoked_key() -> None:
    service, repository = make_service()
    _api_key, plaintext_key = await service.create_api_key(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=uuid.uuid4(),
        name="CI pipeline",
    )
    stored = next(iter(repository.keys_by_id.values()))
    stored.revoked_at = _now()

    with pytest.raises(ApiKeyAuthenticationError):
        await service.resolve_active_key(plaintext_key)


async def test_resolve_active_key_rejects_expired_key() -> None:
    service, repository = make_service()
    _api_key, plaintext_key = await service.create_api_key(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=uuid.uuid4(),
        name="CI pipeline",
    )
    stored = next(iter(repository.keys_by_id.values()))
    stored.expires_at = _now() - timedelta(seconds=1)

    with pytest.raises(ApiKeyAuthenticationError):
        await service.resolve_active_key(plaintext_key)


async def test_resolve_active_key_updates_last_used_at() -> None:
    service, repository = make_service()
    _api_key, plaintext_key = await service.create_api_key(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=uuid.uuid4(),
        name="CI pipeline",
    )

    await service.resolve_active_key(plaintext_key)

    stored = next(iter(repository.keys_by_id.values()))
    assert stored.last_used_at is not None


# ============================================================================
# revoke_api_key / tenant isolation
# ============================================================================


async def test_revoke_api_key_sets_revoked_at() -> None:
    service, _repository = make_service()
    org_id = uuid.uuid4()
    api_key, _plaintext = await service.create_api_key(
        actor_user_id=uuid.uuid4(), requesting_organization_id=org_id, name="CI"
    )

    revoked = await service.revoke_api_key(
        api_key.id, requesting_organization_id=org_id
    )

    assert revoked.revoked_at is not None


async def test_revoke_api_key_rejects_already_revoked() -> None:
    service, _repository = make_service()
    org_id = uuid.uuid4()
    api_key, _plaintext = await service.create_api_key(
        actor_user_id=uuid.uuid4(), requesting_organization_id=org_id, name="CI"
    )
    await service.revoke_api_key(api_key.id, requesting_organization_id=org_id)

    with pytest.raises(ApiKeyAlreadyRevokedError):
        await service.revoke_api_key(api_key.id, requesting_organization_id=org_id)


async def test_get_api_key_rejects_cross_organization_access() -> None:
    service, _repository = make_service()
    api_key, _plaintext = await service.create_api_key(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=uuid.uuid4(),
        name="CI",
    )

    with pytest.raises(CrossOrganizationApiKeyAccessError):
        await service.get_api_key(
            api_key.id, requesting_organization_id=uuid.uuid4()
        )


async def test_get_api_key_raises_when_not_found() -> None:
    service, _repository = make_service()

    with pytest.raises(ApiKeyNotFoundError):
        await service.get_api_key(uuid.uuid4(), requesting_organization_id=None)


async def test_list_api_keys_scopes_to_organization() -> None:
    service, _repository = make_service()
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    await service.create_api_key(
        actor_user_id=uuid.uuid4(), requesting_organization_id=org_a, name="A"
    )
    await service.create_api_key(
        actor_user_id=uuid.uuid4(), requesting_organization_id=org_b, name="B"
    )

    keys, meta = await service.list_api_keys(requesting_organization_id=org_a)

    assert meta.total_items == 1
    assert keys[0].organization_id == org_a
