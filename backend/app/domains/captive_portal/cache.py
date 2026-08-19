"""Redis-backed cache of ``CaptivePortalService.resolve_portal_config``'s
resolution result.

Mirrors ``app.domains.billing.cache.EntitlementCache``/
``app.domains.rbac.cache.PermissionCache``'s identical shape: caches the
*serialized* output of a real DB lookup, keyed by the same parameters the
lookup itself takes, with a TTL pulled from
``Settings.captive_portal_resolve_cache_ttl_seconds``.

``GET /captive-portal/resolve`` is the first real API call a guest's
device/captive-portal frontend makes on every WiFi join -- unauthenticated,
high-volume, guest-facing traffic against a ``CaptivePortalConfig`` row that
only ever changes on a rare, admin-initiated write (see
``service.py``'s own module docstring on that write path's low-volume,
always-authenticated profile). That read/write ratio is exactly the shape
``EntitlementCache``/``PermissionCache`` already exist to optimize for their
own domains -- this is the same optimization applied here.

Real invalidation happens on every mutation to the exact
``(organization_id, location_id)`` pair the mutated config row itself
carries (``create_config``/``update_config``/``activate_config``/
``deactivate_config``/``delete_config`` -- see ``service.py``'s own call
sites). The one gap that TTL alone backstops, not active invalidation:
changing an **organization-level default** config does not fan out to
invalidate every *other* location under that org which falls back to it
(no dedicated per-org location index is kept here) -- the identical,
explicitly-documented trade-off ``EntitlementCache`` already accepts for a
``Plan``/``PlanFeature`` catalog edit not fanning out to every organization
on that plan.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from redis.asyncio import Redis

from app.core.config import get_settings

# Bump ``v<N>`` whenever the set of fields carried in the cached payload
# changes -- i.e. whenever ``_CACHED_CONFIG_SCALAR_FIELDS`` in
# ``service.py`` gains or loses a name. ``_config_from_cache_payload``
# indexes that payload unguarded (``payload[field_name]``), and the
# cache-hit call site has no ``try``/``except``, so a deploy that adds a
# field makes every payload written by the *previous* build raise
# ``KeyError`` straight out of the unauthenticated ``GET
# /captive-portal/resolve`` -- a 500 for every guest joining WiFi, for up
# to the full TTL. Versioning the key sidesteps that by making the old
# and new payloads live under different keys: the stale ones are simply
# never read again and expire on their own. Chosen over
# ``payload.get(name, default)`` deliberately -- a genuinely missing
# field should fail loudly in tests, not degrade silently in production.
# This is v2 because v6's guest_font_choice/background_overlay_strength
# are the first fields added since the cache shipped.
_CACHE_KEY_TEMPLATE = (
    "captive_portal:resolve:v2:{organization_id}:{location_id}"
)
_NONE_SENTINEL = "-"


class CaptivePortalResolveCache:
    """Thin async wrapper around Redis for captive-portal resolve caching."""

    def __init__(self, redis: Redis, *, ttl_seconds: int | None = None) -> None:
        self._redis = redis
        self._ttl_seconds = (
            ttl_seconds or get_settings().captive_portal_resolve_cache_ttl_seconds
        )

    @staticmethod
    def _key(
        organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> str:
        return _CACHE_KEY_TEMPLATE.format(
            organization_id=organization_id or _NONE_SENTINEL,
            location_id=location_id or _NONE_SENTINEL,
        )

    async def get(
        self,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> dict[str, Any] | None:
        raw = await self._redis.get(self._key(organization_id, location_id))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            # Corrupt/incompatible cache payload -- treat as a miss rather
            # than fail the request.
            return None

    async def set(
        self,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        payload: dict[str, Any],
    ) -> None:
        await self._redis.set(
            self._key(organization_id, location_id),
            json.dumps(payload, default=str),
            ex=self._ttl_seconds,
        )

    async def invalidate(
        self,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> None:
        """Deletes the cache entry for the exact ``(organization_id,
        location_id)`` pair a mutated config row itself carries -- see
        module docstring for why this is precise for that pair but does
        not fan out to other locations falling back to an org-level
        default."""
        await self._redis.delete(self._key(organization_id, location_id))


__all__ = ["CaptivePortalResolveCache"]
