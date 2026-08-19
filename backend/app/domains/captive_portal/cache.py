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
# v2 was v6's guest_font_choice/background_overlay_strength, the first
# fields added since the cache shipped. v3 is v7's background_focal_x/
# background_focal_y (design spec §1.4 C4), added to
# _CACHED_CONFIG_SCALAR_FIELDS by the same change -- the spec calls this
# bump out explicitly in §0.3 because skipping it is exactly the
# guest-facing 500 the versioning exists to prevent. v4 is design spec
# §5 S7: the resolved organization's own ``brandings`` row is now folded
# into the payload under a new top-level ``"branding"`` key, which
# ``ResolvedPortalConfig.from_cache_payload`` likewise indexes unguarded
# -- the identical KeyError-out-of-an-unauthenticated-endpoint hazard,
# so the identical bump.
_CACHE_KEY_TEMPLATE = "captive_portal:resolve:v4:{organization_id}:{location_id}"

# Redis SET of every resolve key currently written for one organization,
# so an organization-scoped edit can fan out to *all* of them (see
# ``invalidate_organization``). Deliberately versioned in lockstep with
# ``_CACHE_KEY_TEMPLATE`` -- an index holding keys from a previous
# payload version would fan a delete out to keys nothing reads anymore.
_ORG_INDEX_KEY_TEMPLATE = "captive_portal:resolve:v4:org-index:{organization_id}"

# The index set must outlive the payloads it points at, or a payload
# written at second 59 of the index's own TTL would be orphaned (indexed
# by a set that expires before it does) and survive an
# ``invalidate_organization`` call. One extra window is enough: every
# payload the set names expires no later than one TTL after the set's
# own last write, which is what refreshes the set's expiry too.
_ORG_INDEX_TTL_MULTIPLIER = 2

_NONE_SENTINEL = "-"


class CaptivePortalResolveCache:
    """Thin async wrapper around Redis for captive-portal resolve caching."""

    def __init__(
        self,
        redis: Redis,
        *,
        ttl_seconds: int | None = None,
        negative_ttl_seconds: int | None = None,
    ) -> None:
        settings = get_settings()
        self._redis = redis
        self._ttl_seconds = (
            ttl_seconds or settings.captive_portal_resolve_cache_ttl_seconds
        )
        self._negative_ttl_seconds = (
            negative_ttl_seconds
            or settings.captive_portal_resolve_negative_cache_ttl_seconds
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

    @staticmethod
    def _org_index_key(organization_id: uuid.UUID) -> str:
        return _ORG_INDEX_KEY_TEMPLATE.format(organization_id=organization_id)

    async def set(
        self,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        payload: dict[str, Any],
        *,
        index_organization_id: uuid.UUID | None = None,
        negative: bool = False,
    ) -> None:
        """Writes the payload, and -- when ``index_organization_id`` is
        given -- records this key in that organization's own index set so
        ``invalidate_organization`` can later find it.

        ``index_organization_id`` is the **resolved** organization, not
        the ``organization_id`` argument: the common real-world call shape
        is a location's QR code encoding only ``location_id``, which
        caches under an ``(None, location_id)`` key whose own organization
        is not knowable from the key alone. Passing it explicitly is what
        lets an organization-scoped edit (a branding upload, an org-level
        default config change) fan out to that key too.

        ``negative`` selects the much shorter negative TTL -- see
        ``Settings.captive_portal_resolve_negative_cache_ttl_seconds`` for
        why a "not configured" answer must not be held as long as a real
        one.
        """
        key = self._key(organization_id, location_id)
        ttl = self._negative_ttl_seconds if negative else self._ttl_seconds
        await self._redis.set(key, json.dumps(payload, default=str), ex=ttl)
        if index_organization_id is None:
            return
        index_key = self._org_index_key(index_organization_id)
        await self._redis.sadd(index_key, key)
        await self._redis.expire(
            index_key, self._ttl_seconds * _ORG_INDEX_TTL_MULTIPLIER
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

    async def invalidate_organization(self, organization_id: uuid.UUID) -> None:
        """Deletes *every* resolve key currently indexed for this
        organization -- the fan-out the per-pair ``invalidate`` above
        deliberately does not do.

        Closes the one gap this module's docstring documents as
        TTL-backstopped only: an organization-level edit reaching every
        *other* location that falls back to it. Design spec §5 S7 makes
        this load-bearing rather than merely nice -- once the
        organization's ``brandings`` row is folded into the cached
        payload, an admin uploading a logo would otherwise stay invisible
        to every already-cached location for up to a full TTL, which is a
        real regression against the uncached per-request fetch it
        replaces.
        """
        index_key = self._org_index_key(organization_id)
        keys = await self._redis.smembers(index_key)
        if keys:
            await self._redis.delete(*keys)
        await self._redis.delete(index_key)


__all__ = ["CaptivePortalResolveCache"]
