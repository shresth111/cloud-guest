"""Redis-backed cache of an organization's current entitlement snapshot.

Mirrors ``app.domains.rbac.cache.PermissionCache`` exactly: caches the
*serialized* output of ``service.LicenseService.get_entitlement_snapshot``
(license status/expiry + the org's current plan's feature set), keyed by
organization id, with a TTL pulled from
``Settings.billing_entitlement_cache_ttl_seconds``. Real invalidation
happens on every ``LicenseService`` call that can change an organization's
entitlements (assign/activate/suspend/cancel/expire/upgrade/downgrade) --
see ``service.py``'s own call sites. Unlike ``PermissionCache``, a
``Plan``/``PlanFeature`` catalog edit (rare -- an admin editing a plan's
feature set, not an org's own license) does *not* fan out to every
organization currently on that plan; those changes rely on the TTL alone
as a backstop, the same documented trade-off ``PermissionCache`` accepts
for a missed invalidation.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from redis.asyncio import Redis

from app.core.config import get_settings

_CACHE_KEY_TEMPLATE = "billing:entitlement_snapshot:{organization_id}"


class EntitlementCache:
    """Thin async wrapper around Redis for entitlement-snapshot caching."""

    def __init__(self, redis: Redis, *, ttl_seconds: int | None = None) -> None:
        self._redis = redis
        self._ttl_seconds = (
            ttl_seconds or get_settings().billing_entitlement_cache_ttl_seconds
        )

    @staticmethod
    def _key(organization_id: uuid.UUID) -> str:
        return _CACHE_KEY_TEMPLATE.format(organization_id=organization_id)

    async def get(self, organization_id: uuid.UUID) -> dict[str, Any] | None:
        raw = await self._redis.get(self._key(organization_id))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            # Corrupt/incompatible cache payload -- treat as a miss rather
            # than fail the request.
            return None

    async def set(self, organization_id: uuid.UUID, payload: dict[str, Any]) -> None:
        await self._redis.set(
            self._key(organization_id),
            json.dumps(payload, default=str),
            ex=self._ttl_seconds,
        )

    async def invalidate(self, organization_id: uuid.UUID) -> None:
        await self._redis.delete(self._key(organization_id))


__all__ = ["EntitlementCache"]
