"""Redis-backed cache of a user's effective RBAC grants.

Caches the *serialized* output of ``PermissionResolver.resolve`` (see
``authorization.py``) keyed by user id, with a TTL pulled from
``Settings.rbac_permission_cache_ttl_seconds``. This is a real
write-through-invalidated cache, not a TTL-only one: every mutation that can
change a user's effective permissions (role assignment/revocation, role
permission changes, role activation toggles, permission override
changes) invalidates the affected user(s) immediately via
``RBACService`` -- see ``docs/rbac/RBAC_ARCHITECTURE.md`` for the full
invalidation matrix.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from typing import Any

from redis.asyncio import Redis

from app.core.config import get_settings

_CACHE_KEY_TEMPLATE = "rbac:effective_permissions:{user_id}"


class PermissionCache:
    """Thin async wrapper around Redis for effective-permission caching."""

    def __init__(self, redis: Redis, *, ttl_seconds: int | None = None) -> None:
        self._redis = redis
        self._ttl_seconds = (
            ttl_seconds or get_settings().rbac_permission_cache_ttl_seconds
        )

    @staticmethod
    def _key(user_id: uuid.UUID) -> str:
        return _CACHE_KEY_TEMPLATE.format(user_id=user_id)

    async def get(self, user_id: uuid.UUID) -> dict[str, Any] | None:
        raw = await self._redis.get(self._key(user_id))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            # Corrupt/incompatible cache payload -- treat as a miss rather
            # than fail the request.
            return None

    async def set(self, user_id: uuid.UUID, payload: dict[str, Any]) -> None:
        await self._redis.set(
            self._key(user_id), json.dumps(payload, default=str), ex=self._ttl_seconds
        )

    async def invalidate(self, user_id: uuid.UUID) -> None:
        await self._redis.delete(self._key(user_id))

    async def invalidate_many(self, user_ids: Iterable[uuid.UUID]) -> None:
        # Deleted one key at a time (rather than a single variadic ``DEL``)
        # so this works against both the real ``redis.asyncio.Redis`` client
        # and the minimal single-key fake used in the unit tests.
        for user_id in user_ids:
            await self.invalidate(user_id)
