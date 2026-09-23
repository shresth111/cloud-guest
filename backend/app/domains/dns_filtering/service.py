"""Cloudflare Gateway DNS (category) filtering: business logic.

## The shape, and the two ceilings that decided it

Cloudflare Gateway allows, per account, **250 DNS locations** and **500 DNS
policies** (standard limits). This platform operates one Cloudflare account
on behalf of every tenant, so both are platform-wide budgets.

* **One Gateway location per router.** A location is what binds a router's
  DoH queries to a policy, and venue WAN addresses are dynamic, so the DoH
  subdomain -- not a source IP -- is the only identity that works. That
  makes locations the binding ceiling: **250 routers** on one account
  (the fleet is ~28 today). Past it, :meth:`enable_router` refuses with
  :class:`CloudflareGatewayCeilingError` *before* creating anything; the
  way forward is a limit increase from Cloudflare or a second account
  (sharding), and this module deliberately does not paper over it by
  sharing one location between venues, which would merge their filtering.
* **One Gateway rule per distinct category set ("profile"), not per venue.**
  A rule blocks ``dns.content_category``/``dns.security_category`` ids *and*
  ``dns.location in {...}`` -- every router, in any organization, whose
  venue chose exactly that set. The rule count grows with the number of
  different choices, which is small, instead of with venues, which would hit
  500. A profile whose last router leaves has its rule deleted at Cloudflare
  so the slot comes back.

## Tenant isolation is ours

The Cloudflare account is shared, so isolation is enforced here: a location
is named ``wyfy-router-<router uuid>`` (nothing a tenant chooses), a router
is reached only through ``RouterService`` scoped to the caller's
organization, a venue through ``LocationService`` likewise, the policy's
organization is read off the location row -- never off a header -- and a
location-confined caller is checked against the row's location. A profile
rule lists location ids from several tenants, but no tenant ever reads a
rule; they read their own policy and their own routers.

## Safety

Switching a router's resolver is a whole-router change: a broken DoH
upstream means no guest resolves anything. The device side
(``wyfy_device_gateway.mikrotik_dns_filtering``) snapshots, writes, reads
back, probes, and restores on failure. This side makes that record durable:
a failed switch is committed before it is re-raised (the session would
otherwise roll it back), the pre-switch snapshot is written once and never
overwritten by a re-push, and disable restores the router **before** it
touches Cloudflare, so a revoked token can never stop a venue getting its
own DNS back.
"""

from __future__ import annotations

import dataclasses
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.rbac.location_scope import LocationScope, enforce_entity_location
from app.domains.router.device_domain_gate import ensure_not_controller_managed
from app.domains.router.models import Router

from .cloudflare_client import (
    CloudflareApiError,
    GatewayCategory,
    GatewayLocation,
    GatewayRule,
)
from .constants import (
    CATEGORY_CACHE_TTL_SECONDS,
    FEATURE_NAME,
    SECURITY_THREATS_CATEGORY_ID,
    UNSELECTABLE_CATEGORY_CLASSES,
    BypassHardeningStatus,
    DevicePushStatus,
    ProfileSyncStatus,
    RouterFilteringState,
    build_rule_traffic,
    canonical_category_ids,
    doh_url,
    gateway_location_name,
    gateway_rule_name,
    profile_fingerprint,
)
from .device_adapters import DnsFilteringCredentials, get_dns_filtering_adapter
from .exceptions import (
    CategoryNotSelectableError,
    CloudflareGatewayCeilingError,
    CloudflareNotConfiguredError,
    CloudflareSyncError,
    CrossLocationDnsFilteringAccessError,
    DnsFilteringMissingCredentialsError,
    DnsFilteringNoCategoriesError,
    DnsFilteringNotEnabledError,
    UnknownCategoryError,
)
from .models import DnsFilteringPolicy, DnsFilteringProfile, DnsFilteringRouterLocation
from .repository import DnsFilteringRepositoryProtocol

logger = logging.getLogger(__name__)

_RULE_DESCRIPTION = (
    "Managed by Wyfy Guest (dns_filtering). Edits here are overwritten on the "
    "next sync."
)


class GatewayClientProtocol(Protocol):
    async def list_categories(self) -> list[GatewayCategory]: ...
    async def list_locations(self) -> list[GatewayLocation]: ...
    async def create_location(self, name: str) -> GatewayLocation: ...
    async def delete_location(self, location_id: str) -> None: ...
    async def create_rule(
        self, *, name: str, description: str, traffic: str, precedence: int
    ) -> GatewayRule: ...
    async def update_rule(
        self,
        rule_id: str,
        *,
        name: str,
        description: str,
        traffic: str,
        precedence: int,
    ) -> GatewayRule: ...
    async def delete_rule(self, rule_id: str) -> None: ...


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...

    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


class LocationLookupProtocol(Protocol):
    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Any: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class CategoryCache:
    """In-process TTL cache of the Gateway category catalogue.

    One per process, shared across requests (the catalogue is the same for
    every tenant). A miss costs one Cloudflare call.
    """

    def __init__(self, ttl_seconds: float = CATEGORY_CACHE_TTL_SECONDS) -> None:
        self.ttl_seconds = ttl_seconds
        self._value: list[GatewayCategory] | None = None
        self._expires_at = 0.0

    def get(self, now: float) -> list[GatewayCategory] | None:
        if self._value is not None and now < self._expires_at:
            return self._value
        return None

    def put(self, value: list[GatewayCategory], now: float) -> None:
        self._value = value
        self._expires_at = now + self.ttl_seconds


_PROCESS_CATEGORY_CACHE = CategoryCache()


def _flatten(categories: list[GatewayCategory]) -> dict[int, GatewayCategory]:
    out: dict[int, GatewayCategory] = {}
    for category in categories:
        out[category.id] = category
        for sub in category.subcategories:
            out[sub.id] = sub
    return out


def _security_ids(categories: list[GatewayCategory]) -> set[int]:
    for category in categories:
        if category.id == SECURITY_THREATS_CATEGORY_ID:
            return {category.id, *(sub.id for sub in category.subcategories)}
    return set()


@dataclasses.dataclass(frozen=True, slots=True)
class EffectivePolicy:
    """What a venue actually blocks, and where that came from."""

    location_policy: DnsFilteringPolicy | None
    organization_policy: DnsFilteringPolicy | None

    @property
    def source(self) -> str:
        if self.location_policy is not None:
            return "location"
        if self.organization_policy is not None:
            return "organization"
        return "none"

    @property
    def policy(self) -> DnsFilteringPolicy | None:
        return self.location_policy or self.organization_policy

    @property
    def category_ids(self) -> list[int]:
        policy = self.policy
        return list(policy.category_ids) if policy is not None else []

    @property
    def profile_id(self) -> uuid.UUID | None:
        policy = self.policy
        return policy.profile_id if policy is not None else None


class DnsFilteringService:
    def __init__(
        self,
        repository: DnsFilteringRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        location_lookup: LocationLookupProtocol,
        *,
        gateway: GatewayClientProtocol | None,
        audit_writer: AuditLogWriter | None = None,
        caller_location_scope: LocationScope = None,
        max_locations: int = 250,
        max_dns_rules: int = 500,
        probe_hostname: str = "cloudflare.com",
        category_cache: CategoryCache | None = None,
        clock: Any = time.monotonic,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.location_lookup = location_lookup
        self.gateway = gateway
        self.audit_writer = audit_writer
        self.caller_location_scope = caller_location_scope
        self.max_locations = max_locations
        self.max_dns_rules = max_dns_rules
        self.probe_hostname = probe_hostname
        self.category_cache = category_cache or _PROCESS_CATEGORY_CACHE
        self.clock = clock

    # ------------------------------------------------------------------
    # categories
    # ------------------------------------------------------------------

    def _require_gateway(self) -> GatewayClientProtocol:
        if self.gateway is None:
            raise CloudflareNotConfiguredError()
        return self.gateway

    async def list_categories(self) -> list[GatewayCategory]:
        now = self.clock()
        cached = self.category_cache.get(now)
        if cached is not None:
            return cached
        gateway = self._require_gateway()
        try:
            categories = await gateway.list_categories()
        except CloudflareApiError as exc:
            raise CloudflareSyncError(exc.message) from exc
        self.category_cache.put(categories, now)
        return categories

    async def _validated_ids(self, category_ids: list[int]) -> list[int]:
        ids = canonical_category_ids(category_ids)
        if not ids:
            return ids
        catalogue = _flatten(await self.list_categories())
        unknown = [i for i in ids if i not in catalogue]
        if unknown:
            raise UnknownCategoryError(unknown)
        refused = [
            i
            for i in ids
            if catalogue[i].category_class in UNSELECTABLE_CATEGORY_CLASSES
        ]
        if refused:
            raise CategoryNotSelectableError(refused)
        return ids

    # ------------------------------------------------------------------
    # policy
    # ------------------------------------------------------------------

    async def _load_location(
        self, location_id: uuid.UUID, requesting_organization_id: uuid.UUID | None
    ) -> Any:
        location = await self.location_lookup.get_location(
            location_id, requesting_organization_id=requesting_organization_id
        )
        enforce_entity_location(
            entity_location_id=location.id,
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationDnsFilteringAccessError(),
        )
        return location

    async def _effective(
        self, organization_id: uuid.UUID, location_id: uuid.UUID | None
    ) -> EffectivePolicy:
        location_policy = (
            await self.repository.get_policy(organization_id, location_id)
            if location_id is not None
            else None
        )
        organization_policy = await self.repository.get_policy(organization_id, None)
        return EffectivePolicy(location_policy, organization_policy)

    async def get_location_policy(
        self, location_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> tuple[Any, EffectivePolicy]:
        location = await self._load_location(location_id, requesting_organization_id)
        return location, await self._effective(location.organization_id, location.id)

    async def get_organization_policy(
        self, organization_id: uuid.UUID
    ) -> DnsFilteringPolicy | None:
        return await self.repository.get_policy(organization_id, None)

    async def set_location_policy(
        self,
        location_id: uuid.UUID,
        *,
        category_ids: list[int],
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[Any, EffectivePolicy]:
        location = await self._load_location(location_id, requesting_organization_id)
        # The organization comes from the location row -- never a header.
        await self._set_policy(
            organization_id=location.organization_id,
            location_id=location.id,
            category_ids=category_ids,
            actor_user_id=actor_user_id,
        )
        return location, await self._effective(location.organization_id, location.id)

    async def set_organization_policy(
        self,
        organization_id: uuid.UUID,
        *,
        category_ids: list[int],
        actor_user_id: uuid.UUID | None,
    ) -> DnsFilteringPolicy:
        return await self._set_policy(
            organization_id=organization_id,
            location_id=None,
            category_ids=category_ids,
            actor_user_id=actor_user_id,
        )

    async def _set_policy(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        category_ids: list[int],
        actor_user_id: uuid.UUID | None,
    ) -> DnsFilteringPolicy:
        ids = await self._validated_ids(category_ids)
        profile = await self._get_or_create_profile(ids)
        existing = await self.repository.get_policy(organization_id, location_id)
        fields = {
            "category_ids": ids,
            "profile_id": profile.id if profile is not None else None,
        }
        if existing is None:
            policy = await self.repository.create_policy(
                organization_id=organization_id,
                location_id=location_id,
                created_by=actor_user_id,
                **fields,
            )
        else:
            policy = await self.repository.update_policy(
                existing, {**fields, "updated_by": actor_user_id}
            )

        # Routers whose effective profile this changes move rules. New rule
        # first, old rule second: for a moment a router may be in both
        # (blocking the union), never in neither.
        to_sync_new: list[uuid.UUID] = []
        to_sync_old: list[uuid.UUID] = []
        for row in await self.repository.list_enabled_in_scope(
            organization_id, location_id
        ):
            effective = await self._effective(organization_id, row.location_id)
            if effective.profile_id == row.applied_profile_id:
                continue
            if row.applied_profile_id is not None:
                to_sync_old.append(row.applied_profile_id)
            if effective.profile_id is not None:
                to_sync_new.append(effective.profile_id)
            await self.repository.update_router_location(
                row, {"applied_profile_id": effective.profile_id}
            )
        await self.repository.commit()
        for profile_id in dict.fromkeys([*to_sync_new, *to_sync_old]):
            await self._sync_profile(profile_id)

        await self._audit(
            actor_user_id,
            AuditAction.DNS_FILTERING_POLICY_UPDATED,
            entity_type="dns_filtering_policy",
            entity_id=policy.id,
            organization_id=organization_id,
            description=(
                f"Blocked categories set to {ids} for "
                + (f"location {location_id}" if location_id else "the organization")
            ),
        )
        return policy

    # ------------------------------------------------------------------
    # profiles (shared Gateway rules)
    # ------------------------------------------------------------------

    async def _get_or_create_profile(
        self, ids: list[int]
    ) -> DnsFilteringProfile | None:
        if not ids:
            return None
        fingerprint = profile_fingerprint(ids)
        existing = await self.repository.get_profile_by_fingerprint(fingerprint)
        if existing is not None:
            return existing
        return await self.repository.create_profile(
            fingerprint=fingerprint,
            category_ids=ids,
            rule_precedence=await self.repository.next_rule_precedence(),
            sync_status=ProfileSyncStatus.PENDING.value,
        )

    async def _sync_profile(self, profile_id: uuid.UUID) -> DnsFilteringProfile | None:
        """Make the profile's Gateway rule list exactly its member routers.

        The member set is recomputed from the database under a row lock on
        the profile, then written whole (PUT). Two venues changing one
        shared rule at once serialize here rather than each writing a set
        that is missing the other's change.
        """
        gateway = self._require_gateway()
        profile = await self.repository.lock_profile(profile_id)
        if profile is None:
            return None
        members = await self.repository.list_profile_members(profile.id)
        location_ids = [m.cf_location_id for m in members if m.cf_location_id]
        try:
            if not location_ids:
                if profile.cf_rule_id:
                    await gateway.delete_rule(profile.cf_rule_id)
                data: dict[str, object] = {"cf_rule_id": None}
            else:
                catalogue = await self.list_categories()
                security = _security_ids(catalogue)
                traffic = build_rule_traffic(
                    content_ids=[i for i in profile.category_ids if i not in security],
                    security_ids=[i for i in profile.category_ids if i in security],
                    location_ids=location_ids,
                )
                rule = await self._upsert_rule(profile, traffic)
                data = {"cf_rule_id": rule.id}
        except CloudflareApiError as exc:
            await self.repository.update_profile(
                profile,
                {
                    "sync_status": ProfileSyncStatus.FAILED.value,
                    "sync_error": exc.message,
                },
            )
            await self.repository.commit()
            raise CloudflareSyncError(exc.message) from exc
        updated = await self.repository.update_profile(
            profile,
            {
                **data,
                "sync_status": ProfileSyncStatus.ACTIVE.value,
                "sync_error": None,
                "synced_at": datetime.now(UTC),
            },
        )
        await self.repository.commit()
        return updated

    async def _upsert_rule(
        self, profile: DnsFilteringProfile, traffic: str
    ) -> GatewayRule:
        gateway = self._require_gateway()
        body = {
            "name": gateway_rule_name(profile.id),
            "description": _RULE_DESCRIPTION,
            "traffic": traffic,
            "precedence": profile.rule_precedence,
        }
        if profile.cf_rule_id:
            try:
                return await gateway.update_rule(profile.cf_rule_id, **body)
            except CloudflareApiError as exc:
                # Deleted by hand in the Cloudflare dashboard: recreate
                # rather than leave the venue unfiltered and "active".
                if exc.status_code != 404:
                    raise
        if await self.repository.count_profiles_with_rule() >= self.max_dns_rules:
            raise CloudflareGatewayCeilingError(
                resource="DNS policies", limit=self.max_dns_rules
            )
        return await gateway.create_rule(**body)

    # ------------------------------------------------------------------
    # routers
    # ------------------------------------------------------------------

    async def _load_router(
        self, router_id: uuid.UUID, requesting_organization_id: uuid.UUID | None
    ) -> Router:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        enforce_entity_location(
            entity_location_id=getattr(router, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationDnsFilteringAccessError(),
        )
        return router

    async def get_router_status(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> tuple[Router, DnsFilteringRouterLocation | None, EffectivePolicy]:
        router = await self._load_router(router_id, requesting_organization_id)
        row = await self.repository.get_router_location(router.id)
        effective = await self._effective(router.organization_id, router.location_id)
        return router, row, effective

    async def enable_router(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> DnsFilteringRouterLocation:
        """Create (or adopt) the router's Gateway location, put it in its
        profile's rule, then switch the router's resolver -- verified, or
        rolled back.

        Every precondition is checked before Cloudflare or the router is
        contacted, and the controller-managed refusal before anything else.
        """
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        ensure_not_controller_managed(router, feature=FEATURE_NAME)
        enforce_entity_location(
            entity_location_id=getattr(router, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationDnsFilteringAccessError(),
        )
        gateway = self._require_gateway()
        adapter = get_dns_filtering_adapter(router.vendor)
        credentials = self._resolve_device_credentials(router)
        effective = await self._effective(router.organization_id, router.location_id)
        if effective.profile_id is None:
            raise DnsFilteringNoCategoriesError()

        row = await self.repository.get_router_location(router.id)
        if row is None:
            row = await self.repository.create_router_location(
                router_id=router.id,
                organization_id=router.organization_id,
                location_id=router.location_id,
                cf_location_name=gateway_location_name(router.id),
                state=RouterFilteringState.PENDING.value,
                device_push_status=DevicePushStatus.PENDING.value,
                created_by=actor_user_id,
            )

        if row.cf_location_id is None:
            if await self.repository.count_cloudflare_locations() >= self.max_locations:
                raise CloudflareGatewayCeilingError(
                    resource="DNS locations", limit=self.max_locations
                )
            location = await self._create_or_adopt_location(
                gateway, row.cf_location_name
            )
            row = await self.repository.update_router_location(
                row,
                {
                    "cf_location_id": location.id,
                    "doh_subdomain": location.doh_subdomain,
                },
            )
            # Committed now: a later failure must not forget a location that
            # exists at Cloudflare and counts against the 250.
            await self.repository.commit()

        previous_profile = row.applied_profile_id
        row = await self.repository.update_router_location(
            row,
            {
                "applied_profile_id": effective.profile_id,
                "state": RouterFilteringState.PENDING.value,
            },
        )
        await self.repository.commit()
        # Rule membership before the router switch: the reverse order would
        # leave a switched router briefly resolving unfiltered.
        await self._sync_profile(effective.profile_id)
        if previous_profile is not None and previous_profile != effective.profile_id:
            await self._sync_profile(previous_profile)

        url = doh_url(str(row.doh_subdomain))
        try:
            result = await adapter.apply_doh(
                credentials,
                doh_url=url,
                probe_hostname=self.probe_hostname,
                rollback_to=row.dns_snapshot,
            )
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            failure: dict[str, object] = {
                "state": RouterFilteringState.FAILED.value,
                "device_push_status": DevicePushStatus.FAILED.value,
                "device_push_error": str(exc),
            }
            snapshot = getattr(exc, "snapshot", None)
            if row.dns_snapshot is None and snapshot:
                failure["dns_snapshot"] = snapshot
            await self.repository.update_router_location(row, failure)
            await self.repository.commit()
            raise

        updated = await self.repository.update_router_location(
            row,
            {
                "state": RouterFilteringState.ACTIVE.value,
                "device_push_status": DevicePushStatus.ACTIVE.value,
                "device_push_error": None,
                "device_pushed_at": datetime.now(UTC),
                "routeros_version": result.routeros_version,
                # Written once: a re-push's "before" is our own state.
                "dns_snapshot": row.dns_snapshot or result.snapshot.to_dict(),
                "updated_by": actor_user_id,
            },
        )
        await self.repository.commit()
        await self._audit(
            actor_user_id,
            AuditAction.DNS_FILTERING_ENABLED,
            entity_type="router",
            entity_id=router.id,
            organization_id=router.organization_id,
            description=(
                f"Router {router.id} DNS switched to Cloudflare Gateway "
                f"(location {row.cf_location_id}); probe resolved "
                f"{self.probe_hostname} -> {result.probe_address}"
            ),
        )
        return updated

    async def _create_or_adopt_location(
        self, gateway: GatewayClientProtocol, name: str
    ) -> GatewayLocation:
        """A create that succeeded at Cloudflare but whose id was never
        committed here (crash, timeout) left a location named for this
        router. Adopt it rather than create a second one against the 250."""
        try:
            for location in await gateway.list_locations():
                if location.name == name:
                    return location
            return await gateway.create_location(name)
        except CloudflareApiError as exc:
            raise CloudflareSyncError(exc.message) from exc

    async def disable_router(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> DnsFilteringRouterLocation:
        """Restore the router's own DNS, then release its Cloudflare location.

        The router goes first and a router failure aborts: a venue must get
        its DNS back, and a Cloudflare location with no router behind it is
        harmless, whereas the reverse (location deleted, router still
        pointed at it) is a venue with no DNS at all. A Cloudflare failure
        *after* the router is restored is committed as such and reported;
        calling disable again finishes the Cloudflare side only.
        """
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        ensure_not_controller_managed(router, feature=FEATURE_NAME)
        enforce_entity_location(
            entity_location_id=getattr(router, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationDnsFilteringAccessError(),
        )
        row = await self.repository.get_router_location(router.id)
        if row is None:
            raise DnsFilteringNotEnabledError(router.id)
        if (
            row.state == RouterFilteringState.DISABLED.value
            and row.cf_location_id is None
        ):
            return row

        if row.state != RouterFilteringState.DISABLED.value:
            adapter = get_dns_filtering_adapter(router.vendor)
            credentials = self._resolve_device_credentials(router)
            if row.bypass_hardening_enabled:
                await adapter.remove_bypass_hardening(credentials)
                row = await self.repository.update_router_location(
                    row,
                    {
                        "bypass_hardening_enabled": False,
                        "bypass_hardening_status": BypassHardeningStatus.OFF.value,
                        "bypass_hardening_error": None,
                    },
                )
            note: str | None = None
            if row.dns_snapshot is not None or row.device_pushed_at is not None:
                result = await adapter.restore_dns(
                    credentials,
                    snapshot=row.dns_snapshot
                    or {"use_doh_server": "", "verify_doh_cert": False},
                    expected_doh_url=doh_url(row.doh_subdomain)
                    if row.doh_subdomain
                    else None,
                    probe_hostname=self.probe_hostname,
                )
                if not result.probe_ok:
                    note = (
                        "DNS settings restored, but the router could not resolve "
                        f"{self.probe_hostname} afterwards: {result.probe_error}"
                    )
            row = await self.repository.update_router_location(
                row,
                {
                    "state": RouterFilteringState.DISABLED.value,
                    "device_push_status": DevicePushStatus.PENDING.value,
                    "device_push_error": note,
                    "dns_snapshot": None,
                    "updated_by": actor_user_id,
                },
            )
            await self.repository.commit()

        previous_profile = row.applied_profile_id
        row = await self.repository.update_router_location(
            row, {"applied_profile_id": None}
        )
        await self.repository.commit()
        if previous_profile is not None:
            await self._sync_profile(previous_profile)
        if row.cf_location_id is not None:
            gateway = self._require_gateway()
            try:
                await gateway.delete_location(row.cf_location_id)
            except CloudflareApiError as exc:
                raise CloudflareSyncError(
                    "the router's DNS was restored, but releasing its Gateway "
                    f"location failed ({exc.message}); disable again to retry"
                ) from exc
            row = await self.repository.update_router_location(
                row, {"cf_location_id": None, "doh_subdomain": None}
            )
            await self.repository.commit()

        await self._audit(
            actor_user_id,
            AuditAction.DNS_FILTERING_DISABLED,
            entity_type="router",
            entity_id=router.id,
            organization_id=router.organization_id,
            description=f"Router {router.id} DNS restored from Cloudflare Gateway",
        )
        return row

    async def set_bypass_hardening(
        self,
        router_id: uuid.UUID,
        *,
        enabled: bool,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> DnsFilteringRouterLocation:
        """Opt-in: extend the DoT/DoH drops to logged-in guests and redirect
        their plain DNS to the router. Only on a router already switched to
        Gateway -- without it, forcing guests onto the router's resolver buys
        the category filter nothing."""
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        ensure_not_controller_managed(router, feature=FEATURE_NAME)
        enforce_entity_location(
            entity_location_id=getattr(router, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationDnsFilteringAccessError(),
        )
        row = await self.repository.get_router_location(router.id)
        if row is None or (enabled and row.state != RouterFilteringState.ACTIVE.value):
            raise DnsFilteringNotEnabledError(router.id)
        adapter = get_dns_filtering_adapter(router.vendor)
        credentials = self._resolve_device_credentials(router)
        try:
            if enabled:
                await adapter.apply_bypass_hardening(credentials)
            else:
                await adapter.remove_bypass_hardening(credentials)
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            await self.repository.update_router_location(
                row,
                {
                    "bypass_hardening_status": BypassHardeningStatus.FAILED.value,
                    "bypass_hardening_error": str(exc),
                },
            )
            await self.repository.commit()
            raise
        updated = await self.repository.update_router_location(
            row,
            {
                "bypass_hardening_enabled": enabled,
                "bypass_hardening_status": (
                    BypassHardeningStatus.ACTIVE
                    if enabled
                    else BypassHardeningStatus.OFF
                ).value,
                "bypass_hardening_error": None,
                "updated_by": actor_user_id,
            },
        )
        await self.repository.commit()
        await self._audit(
            actor_user_id,
            AuditAction.DNS_FILTERING_BYPASS_HARDENING_CHANGED,
            entity_type="router",
            entity_id=router.id,
            organization_id=router.organization_id,
            description=(
                f"DNS bypass hardening {'enabled' if enabled else 'disabled'} "
                f"on router {router.id}"
            ),
        )
        return updated

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _resolve_device_credentials(self, router: Router) -> DnsFilteringCredentials:
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise DnsFilteringMissingCredentialsError(router.id)
        return DnsFilteringCredentials(
            host=host, username=router.api_username, password=secret
        )

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_type: str,
        entity_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = [
    "CategoryCache",
    "DnsFilteringService",
    "EffectivePolicy",
    "GatewayClientProtocol",
]
