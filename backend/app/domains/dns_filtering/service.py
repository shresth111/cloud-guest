"""Cloudflare Gateway DNS (category) filtering: business logic.

## The shape: one Gateway location per category set, not per router

This platform operates one Cloudflare account on behalf of every tenant, so
Cloudflare's per-account budgets are platform-wide. Two of them matter:

* **DNS locations.** A location is what binds a router's DoH queries to a
  policy (venue WAN addresses are dynamic, so the DoH subdomain -- not a
  source IP -- is the only identity that works). The *plan* allowance is
  small and partly unknown: Zero Trust Standard lists 25 DNS filtering
  locations, Free lists no number at all, and the 250 in Cloudflare's
  account-limits doc is an upper bound, not what a plan grants. One
  location per router (~28 routers today) would already be past Standard.
* **DNS policies** (500).

So both are allocated **per profile** -- one profile per distinct category
set, shared by every venue, in any organization, whose effective policy
resolves to exactly that set. A profile in use owns one location (one DoH
endpoint) and one rule whose selector is that single location. Every router
of the profile points at the same endpoint. Locations in use therefore equal
the number of *distinct active category sets*, whatever the router count.

* **The cap is a setting** (``cloudflare_gateway_max_locations``, default 3
  until the plan's real allowance is measured). A change that needs a
  location for a **new** distinct set past the cap is refused with a 409
  (:class:`CategorySetLimitError`) *before anything is written*, naming the
  nearest set already in use. It never silently merges the venue into
  another set.
* **Switching sets moves the router, not the rule.** A venue whose set
  changes has each enabled router re-pointed at the new profile's endpoint
  through the same verified switch as enable (snapshot, write, read back,
  probe, restore on failure). The new profile's location and rule exist
  before the router is pointed at them, so a router is never on an
  unfiltered endpoint. When a profile's last router leaves (moved or
  disabled), its rule and then its location are deleted at Cloudflare and
  both slots come back.
* **What sharing costs.** Cloudflare's own DNS logs are per location, so
  they cannot tell apart the venues (or organizations) that share a
  profile. The platform does not surface those logs today; if it ever
  needs per-venue query logs, it needs per-venue locations and a plan that
  pays for them.

## Tenant isolation is ours

The Cloudflare account is shared, so isolation is enforced here. A profile
is platform-owned and holds only category ids; its location and rule are
named ``wyfy-profile-<profile uuid>`` -- no organization, venue or router
name ever reaches Cloudflare -- so sharing a profile across organizations
exposes nothing about any of them. A router is reached only through
``RouterService`` scoped to the caller's organization, a venue through
``LocationService`` likewise, the policy's organization is read off the
location row -- never off a header -- and a location-confined caller is
checked against the row's location. No tenant ever reads a profile; the
one place a profile's category ids are shown is the cap refusal's "nearest
selection" hint, which is category ids and nothing else.

## Safety

Switching a router's resolver is a whole-router change: a broken DoH
upstream means no guest resolves anything. The device side
(``wyfy_device_gateway.mikrotik_dns_filtering``) snapshots, writes, reads
back, probes, and restores on failure. This side makes that record durable:
a failed switch is committed before it is re-raised (the session would
otherwise roll it back), the pre-switch snapshot is written once and never
overwritten by a re-push or a move, disable restores the router **before**
it touches Cloudflare, so a revoked token can never stop a venue getting its
own DNS back, and a profile's location is never released while a router
points at it or is being switched to it (``switching_to_profile_id``).
"""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from app.common.exceptions import CloudGuestError
from app.domains.rbac.enums import AuditAction
from app.domains.rbac.location_scope import LocationScope, enforce_entity_location
from app.domains.router.device_domain_gate import ensure_not_controller_managed
from app.domains.router.models import Router

from .bypass_lists import hostnames_to_push, list_sha
from .cloudflare_client import (
    CloudflareApiError,
    GatewayCategory,
    GatewayLocation,
    GatewayRule,
)
from .constants import (
    ANONYMIZER_CATEGORY_ID,
    CATEGORY_CACHE_TTL_SECONDS,
    CURATED_DOH_HOSTNAMES,
    DEFAULT_BYPASS_LAYERS,
    FEATURE_NAME,
    LIST_BACKED_LAYERS,
    SECURITY_THREATS_CATEGORY_ID,
    UNSELECTABLE_CATEGORY_CLASSES,
    BlocklistKind,
    BypassHardeningStatus,
    BypassLayer,
    DevicePushStatus,
    ProfileSyncStatus,
    RouterFilteringState,
    build_rule_traffic,
    canonical_category_ids,
    category_distance,
    doh_url,
    gateway_location_name,
    gateway_rule_name,
    profile_fingerprint,
)
from .device_adapters import DnsFilteringCredentials, get_dns_filtering_adapter
from .exceptions import (
    BypassLayerInvalidError,
    CategoryNotSelectableError,
    CategorySetLimitError,
    CloudflareGatewayCeilingError,
    CloudflareNotConfiguredError,
    CloudflareSyncError,
    CrossLocationDnsFilteringAccessError,
    DnsFilteringError,
    DnsFilteringMissingCredentialsError,
    DnsFilteringNoCategoriesError,
    DnsFilteringNotEnabledError,
    DnsFilteringRoutersStillEnabledError,
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


def _vpn_block_on(row: DnsFilteringRouterLocation | None) -> bool:
    return row is not None and BypassLayer.VPN_BLOCK.value in (row.bypass_layers or [])


@dataclasses.dataclass(frozen=True, slots=True)
class BypassPayload:
    """What the list-backed layers put on a router, and its version."""

    doh_ipv4: list[str]
    doh_hostnames: list[str]
    sni_hostnames: list[str]
    sha: str


@dataclasses.dataclass(frozen=True, slots=True)
class LayerCountersView:
    layer: str
    enabled: bool
    available: bool
    packets: int | None
    bytes: int | None
    reason: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class BypassCountersView:
    available: bool
    reason: str | None
    router_uptime: str | None
    layers: list[LayerCountersView]


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
        max_locations: int = 3,
        max_dns_rules: int = 500,
        probe_hostname: str = "cloudflare.com",
        category_cache: CategoryCache | None = None,
        clock: Any = time.monotonic,
        ip_exclusions: tuple[str, ...] = ("172.64.36.0/24", "162.159.36.0/24"),
        hostname_exclusions: tuple[str, ...] = ("cloudflare-gateway.com",),
        list_max_entries: int = 5000,
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
        self.ip_exclusions = tuple(ip_exclusions)
        self.hostname_exclusions = tuple(hostname_exclusions)
        self.list_max_entries = list_max_entries

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

        # Every refusal is decided before the policy is written: which
        # enabled routers this moves, whether any would be left with nothing
        # to point at, and whether a new category set fits the location cap.
        moves = await self._planned_moves(
            organization_id=organization_id,
            location_id=location_id,
            ids=ids,
            profile=profile,
        )
        if any(target is None for _, target in moves):
            raise DnsFilteringRoutersStillEnabledError(
                sum(1 for _, target in moves if target is None)
            )
        if moves:
            self._require_gateway()
            await self._check_location_cap(ids, moves)

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
        await self.repository.commit()

        # Each affected router is re-pointed at the new set's endpoint with
        # the verified switch. One router failing (unreachable, probe failed
        # and rolled back) does not stop the others: its failure is recorded
        # on its own row, where the router status endpoint shows it.
        moved = failed = 0
        for row, target in moves:
            if await self._move_router(
                row,
                target,  # type: ignore[arg-type] -- None refused above
                organization_id=organization_id,
                actor_user_id=actor_user_id,
            ):
                moved += 1
            else:
                failed += 1

        description = f"Blocked categories set to {ids} for " + (
            f"location {location_id}" if location_id else "the organization"
        )
        if moves:
            description += f"; routers re-pointed: {moved}, failed: {failed}"
        await self._audit(
            actor_user_id,
            AuditAction.DNS_FILTERING_POLICY_UPDATED,
            entity_type="dns_filtering_policy",
            entity_id=policy.id,
            organization_id=organization_id,
            description=description,
        )
        return policy

    async def _planned_moves(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        ids: list[int],
        profile: DnsFilteringProfile | None,
    ) -> list[tuple[DnsFilteringRouterLocation, uuid.UUID | None]]:
        """The active routers whose target profile this policy change
        alters, and the profile each would move to -- computed against the
        policy as it *would* be, without writing it."""
        proposed = DnsFilteringPolicy(
            organization_id=organization_id,
            location_id=location_id,
            category_ids=ids,
            profile_id=profile.id if profile is not None else None,
        )
        organization_policy = (
            await self.repository.get_policy(organization_id, None)
            if location_id is not None
            else proposed
        )
        moves: list[tuple[DnsFilteringRouterLocation, uuid.UUID | None]] = []
        for row in await self.repository.list_enabled_in_scope(
            organization_id, location_id
        ):
            # Only routers already filtering are moved here. A router whose
            # first switch never succeeded is left for its next enable.
            if row.state != RouterFilteringState.ACTIVE.value:
                continue
            if location_id is None:
                # An organization default reaches only venues without their
                # own choice.
                own = await self.repository.get_policy(organization_id, row.location_id)
                if own is not None:
                    continue
                effective = EffectivePolicy(None, proposed)
            else:
                effective = EffectivePolicy(proposed, organization_policy)
            target = await self._target_profile_id(
                effective, vpn_block=_vpn_block_on(row)
            )
            if target == row.applied_profile_id:
                continue
            moves.append((row, target))
        return moves

    async def _move_router(
        self,
        row: DnsFilteringRouterLocation,
        target: uuid.UUID,
        *,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
    ) -> bool:
        """One router of a policy change: resolve it, then switch it. Never
        raises -- the outcome is on the row."""
        try:
            router = await self.router_lookup.get_router(
                row.router_id, requesting_organization_id=organization_id
            )
            adapter = get_dns_filtering_adapter(router.vendor)
            credentials = self._resolve_device_credentials(router)
        except CloudGuestError as exc:
            await self.repository.update_router_location(
                row,
                {
                    "device_push_status": DevicePushStatus.FAILED.value,
                    "device_push_error": (
                        "Could not move this router to the new category "
                        f"selection: {exc.message}. It still filters with its "
                        "previous selection."
                    ),
                },
            )
            await self.repository.commit()
            return False
        try:
            await self._switch_router(
                row,
                target,
                adapter=adapter,
                credentials=credentials,
                actor_user_id=actor_user_id,
            )
        except Exception:  # noqa: BLE001 -- recorded on the row by the switch
            logger.warning(
                "dns_filtering_policy_move_failed",
                extra={"router_id": str(row.router_id)},
                exc_info=True,
            )
            return False
        return True

    # ------------------------------------------------------------------
    # profiles (shared Gateway location + rule per category set)
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

    async def _target_profile_id(
        self, effective: EffectivePolicy, *, vpn_block: bool
    ) -> uuid.UUID | None:
        """The profile a router's Gateway location belongs in: the venue's
        effective one, plus Cloudflare's Anonymizer category while that
        router's VPN-blocking layer is on -- but only if the live catalogue
        still lists the category as blockable. Never adds a category the
        venue did not choose unless the venue turned VPN blocking on."""
        if effective.profile_id is None or not vpn_block:
            return effective.profile_id
        ids = effective.category_ids
        if ANONYMIZER_CATEGORY_ID in ids:
            return effective.profile_id
        category = _flatten(await self.list_categories()).get(ANONYMIZER_CATEGORY_ID)
        if category is None or category.category_class in UNSELECTABLE_CATEGORY_CLASSES:
            logger.warning(
                "dns_filtering_anonymizer_category_unavailable",
                extra={"category_id": ANONYMIZER_CATEGORY_ID},
            )
            return effective.profile_id
        profile = await self._get_or_create_profile(
            canonical_category_ids([*ids, ANONYMIZER_CATEGORY_ID])
        )
        return profile.id if profile is not None else effective.profile_id

    async def _check_location_cap(
        self,
        requested_ids: list[int],
        moves: list[tuple[DnsFilteringRouterLocation, uuid.UUID | None]],
    ) -> None:
        """Refuse (409) when these moves need more Gateway locations than the
        configured cap allows, counting the locations the same moves free.

        A move creates the new location before the old one is released (the
        router must never point at an endpoint that is gone), so for the
        length of one switch the account can hold one location more than
        the cap. The cap is deliberately set below the plan's allowance for
        that reason.

        Not serialized across concurrent requests: two different new sets
        created at the same instant can both pass. The window is one request
        long and Cloudflare's own limit still stops the create.
        """
        targets = {t for _, t in moves if t is not None}
        needed = 0
        for target in targets:
            profile = await self.repository.get_profile(target)
            if profile is not None and profile.cf_location_id is None:
                needed += 1
        if needed == 0:
            return
        moving = frozenset(row.id for row, _ in moves)
        freed = 0
        for previous in {r.applied_profile_id for r, _ in moves} - targets - {None}:
            profile = await self.repository.get_profile(previous)  # type: ignore[arg-type]
            if profile is None or profile.cf_location_id is None:
                continue
            if (
                await self.repository.count_profile_members(
                    profile.id, excluding_row_ids=moving
                )
                == 0
            ):
                freed += 1
        in_use = await self.repository.count_profiles_with_location()
        if in_use - freed + needed > self.max_locations:
            raise await self._location_cap_error(requested_ids, in_use)

    async def _location_cap_error(
        self, requested_ids: list[int], in_use: int
    ) -> CategorySetLimitError:
        """The refusal, with the nearest category set already in use (by
        symmetric difference) so the venue can pick it on purpose."""
        requested = canonical_category_ids(requested_ids)
        candidates = await self.repository.list_profiles_with_location()
        nearest = min(
            (canonical_category_ids(p.category_ids) for p in candidates),
            key=lambda ids: (category_distance(ids, requested), len(ids), ids),
            default=None,
        )
        adds = sorted(set(nearest or []) - set(requested))
        removes = sorted(set(requested) - set(nearest or []))
        label: str | None = None
        if nearest is not None:
            names = self._category_names()
            parts = []
            if adds:
                parts.append("also blocks " + ", ".join(names(adds)))
            if removes:
                parts.append("does not block " + ", ".join(names(removes)))
            label = " and ".join(parts) if parts else None
        return CategorySetLimitError(
            limit=self.max_locations,
            in_use=in_use,
            requested_category_ids=requested,
            nearest_category_ids=nearest,
            nearest_adds=adds,
            nearest_removes=removes,
            nearest_label=label,
        )

    def _category_names(self) -> Any:
        """Id -> display name from the cached catalogue (never a Cloudflare
        call from inside a refusal); falls back to the id."""
        cached = self.category_cache.get(self.clock())
        catalogue = _flatten(cached) if cached else {}

        def names(ids: list[int]) -> list[str]:
            return [
                catalogue[i].name if i in catalogue else f"category {i}" for i in ids
            ]

        return names

    async def _ensure_profile_endpoint(
        self, profile_id: uuid.UUID, row: DnsFilteringRouterLocation
    ) -> DnsFilteringProfile:
        """The profile's Gateway location and rule, created if missing, with
        ``row`` marked as switching to it first.

        The mark is written under the profile's row lock and committed with
        (or before) the location, so a concurrent release of the same
        profile -- which counts members under the same lock -- sees this
        router and leaves the location alone.
        """
        gateway = self._require_gateway()
        profile = await self.repository.lock_profile(profile_id)
        if profile is None:
            raise DnsFilteringNoCategoriesError()
        row = await self.repository.update_router_location(
            row, {"switching_to_profile_id": profile.id}
        )
        try:
            if profile.cf_location_id is None:
                location = await self._create_or_adopt_location(
                    gateway, gateway_location_name(profile.id)
                )
                profile = await self.repository.update_profile(
                    profile,
                    {
                        "cf_location_id": location.id,
                        "doh_subdomain": location.doh_subdomain,
                    },
                )
                # Committed now: a later failure must not forget a location
                # that exists at Cloudflare and counts against the cap.
                await self.repository.commit()
            catalogue = await self.list_categories()
            security = _security_ids(catalogue)
            traffic = build_rule_traffic(
                content_ids=[i for i in profile.category_ids if i not in security],
                security_ids=[i for i in profile.category_ids if i in security],
                location_ids=[str(profile.cf_location_id)],
            )
            rule = await self._upsert_rule(profile, traffic)
        except CloudflareApiError as exc:
            await self._endpoint_failed(profile, row, exc.message)
            raise CloudflareSyncError(exc.message) from exc
        except DnsFilteringError as exc:
            await self._endpoint_failed(profile, row, exc.message)
            raise
        profile = await self.repository.update_profile(
            profile,
            {
                "cf_rule_id": rule.id,
                "sync_status": ProfileSyncStatus.ACTIVE.value,
                "sync_error": None,
                "synced_at": datetime.now(UTC),
            },
        )
        await self.repository.commit()
        return profile

    async def _endpoint_failed(
        self,
        profile: DnsFilteringProfile,
        row: DnsFilteringRouterLocation,
        message: str,
    ) -> None:
        await self.repository.update_profile(
            profile,
            {"sync_status": ProfileSyncStatus.FAILED.value, "sync_error": message},
        )
        await self.repository.update_router_location(
            row,
            {
                "switching_to_profile_id": None,
                "device_push_status": DevicePushStatus.FAILED.value,
                "device_push_error": f"Cloudflare Gateway: {message}",
            },
        )
        await self.repository.commit()
        # A location created before the rule failed must not hold a slot.
        await self._release_quietly(profile.id)

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

    async def _release_profile_if_unused(self, profile_id: uuid.UUID) -> None:
        """Delete the profile's rule, then its location, at Cloudflare --
        only when no router points at it or is being switched to it,
        counted under the profile's row lock."""
        profile = await self.repository.lock_profile(profile_id)
        if profile is None or (
            profile.cf_location_id is None and profile.cf_rule_id is None
        ):
            return
        if await self.repository.count_profile_members(profile.id) > 0:
            return
        gateway = self._require_gateway()
        try:
            # Rule first: it is the thing that references the location.
            if profile.cf_rule_id:
                await gateway.delete_rule(profile.cf_rule_id)
                profile = await self.repository.update_profile(
                    profile, {"cf_rule_id": None}
                )
            if profile.cf_location_id:
                await gateway.delete_location(profile.cf_location_id)
                profile = await self.repository.update_profile(
                    profile, {"cf_location_id": None, "doh_subdomain": None}
                )
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
        await self.repository.update_profile(
            profile,
            {
                "sync_status": ProfileSyncStatus.PENDING.value,
                "sync_error": None,
                "synced_at": datetime.now(UTC),
            },
        )
        await self.repository.commit()

    async def _release_quietly(self, profile_id: uuid.UUID) -> None:
        """Release after a router already moved away: a Cloudflare failure
        here leaves an unused location holding a slot (recorded on the
        profile, retried by the next disable's sweep), never a router
        without DNS -- so it is logged, not raised."""
        try:
            await self._release_profile_if_unused(profile_id)
        except DnsFilteringError:
            logger.warning(
                "dns_filtering_profile_release_failed",
                extra={"profile_id": str(profile_id)},
                exc_info=True,
            )

    async def _reclaim_unused_profiles(self) -> None:
        """Sweep: release every profile still holding a Cloudflare location
        or rule with no router behind it."""
        repository = self.repository
        for profile in await repository.list_profiles_holding_cloudflare_resources():
            await self._release_profile_if_unused(profile.id)

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
        """Point the router at its category set's shared Gateway endpoint
        (creating that set's location and rule if it is the set's first
        router) -- verified, or rolled back.

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
        self._require_gateway()
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
                state=RouterFilteringState.PENDING.value,
                device_push_status=DevicePushStatus.PENDING.value,
                created_by=actor_user_id,
            )
        target = await self._target_profile_id(effective, vpn_block=_vpn_block_on(row))
        target_profile = await self.repository.get_profile(target)
        await self._check_location_cap(
            list(target_profile.category_ids)
            if target_profile is not None
            else effective.category_ids,
            [(row, target)],
        )

        updated = await self._switch_router(
            row,
            target,
            adapter=adapter,
            credentials=credentials,
            actor_user_id=actor_user_id,
        )
        await self._audit(
            actor_user_id,
            AuditAction.DNS_FILTERING_ENABLED,
            entity_type="router",
            entity_id=router.id,
            organization_id=router.organization_id,
            description=(
                f"Router {router.id} DNS switched to Cloudflare Gateway "
                f"(category profile {target}); probe resolved "
                f"{self.probe_hostname}"
            ),
        )
        return updated

    async def _switch_router(
        self,
        row: DnsFilteringRouterLocation,
        target: uuid.UUID,
        *,
        adapter: Any,
        credentials: DnsFilteringCredentials,
        actor_user_id: uuid.UUID | None,
    ) -> DnsFilteringRouterLocation:
        """Point one router at ``target``'s endpoint: first enable, re-push,
        or a move from another profile. The target's location and rule are
        in place before the router is touched; the previous profile is
        released only after the router has verifiably left it."""
        previous = row.applied_profile_id
        was_active = row.state == RouterFilteringState.ACTIVE.value
        profile = await self._ensure_profile_endpoint(target, row)
        url = doh_url(str(profile.doh_subdomain))
        try:
            result = await adapter.apply_doh(
                credentials,
                doh_url=url,
                probe_hostname=self.probe_hostname,
                rollback_to=row.dns_snapshot,
            )
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            rolled_back = (getattr(exc, "data", None) or {}).get("rolled_back")
            # Where the router is now. A rollback that did not read back
            # clean leaves it on the new endpoint. A clean rollback puts back
            # what the device snapshotted: the previous profile's endpoint on
            # a move, the pre-platform DNS on a re-push of the same one.
            # Anything else (refused before writing, unreachable) changed
            # nothing.
            if rolled_back is False:
                now_on: uuid.UUID | None = target
            elif rolled_back is True:
                now_on = None if previous == target else previous
            else:
                now_on = previous
            still_filtering = was_active and now_on is not None and now_on == previous
            detail = str(exc)
            if still_filtering and previous != target:
                detail += (
                    " The router still filters with its previous category " "selection."
                )
            failure: dict[str, object] = {
                "switching_to_profile_id": None,
                "applied_profile_id": now_on,
                "state": (
                    RouterFilteringState.ACTIVE
                    if still_filtering
                    else RouterFilteringState.FAILED
                ).value,
                "device_push_status": DevicePushStatus.FAILED.value,
                "device_push_error": detail,
            }
            snapshot = getattr(exc, "snapshot", None)
            if row.dns_snapshot is None and snapshot and previous is None:
                failure["dns_snapshot"] = snapshot
            await self.repository.update_router_location(row, failure)
            await self.repository.commit()
            for other in {previous, target} - {now_on, None}:
                await self._release_quietly(other)  # type: ignore[arg-type]
            raise

        updated = await self.repository.update_router_location(
            row,
            {
                "applied_profile_id": target,
                "switching_to_profile_id": None,
                "state": RouterFilteringState.ACTIVE.value,
                "device_push_status": DevicePushStatus.ACTIVE.value,
                "device_push_error": None,
                "device_pushed_at": datetime.now(UTC),
                "routeros_version": result.routeros_version,
                # Written once: a re-push's or a move's "before" is our own
                # state, never the venue's.
                "dns_snapshot": row.dns_snapshot or result.snapshot.to_dict(),
                "updated_by": actor_user_id,
            },
        )
        await self.repository.commit()
        if previous is not None and previous != target:
            await self._release_quietly(previous)
        return updated

    async def _create_or_adopt_location(
        self, gateway: GatewayClientProtocol, name: str
    ) -> GatewayLocation:
        """A create that succeeded at Cloudflare but whose id was never
        committed here (crash, timeout) left a location named for this
        profile. Adopt it rather than create a second one against the cap."""
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
        """Restore the router's own DNS, then release its profile's Cloudflare
        location and rule if it was the profile's last router.

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
        if row.state == RouterFilteringState.DISABLED.value:
            # The router is already restored. Finish any Cloudflare release
            # an earlier disable could not complete.
            if self.gateway is not None:
                await self._reclaim_or_report()
            return row

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
                    "bypass_layers": [],
                    "bypass_lists_sha": None,
                },
            )
        previous = row.applied_profile_id
        note: str | None = None
        if row.dns_snapshot is not None or row.device_pushed_at is not None:
            applied = (
                await self.repository.get_profile(previous)
                if previous is not None
                else None
            )
            result = await adapter.restore_dns(
                credentials,
                snapshot=row.dns_snapshot
                or {"use_doh_server": "", "verify_doh_cert": False},
                expected_doh_url=doh_url(applied.doh_subdomain)
                if applied is not None and applied.doh_subdomain
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
                "applied_profile_id": None,
                "switching_to_profile_id": None,
                "device_push_status": DevicePushStatus.PENDING.value,
                "device_push_error": note,
                "dns_snapshot": None,
                "updated_by": actor_user_id,
            },
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
        if previous is not None:
            await self._reclaim_or_report(previous)
        return row

    async def _reclaim_or_report(self, profile_id: uuid.UUID | None = None) -> None:
        try:
            if profile_id is not None:
                await self._release_profile_if_unused(profile_id)
            else:
                await self._reclaim_unused_profiles()
        except CloudflareSyncError as exc:
            raise CloudflareSyncError(
                "the router's DNS was restored, but releasing its category "
                f"set's Gateway location failed ({exc.message}); disable again "
                "to retry"
            ) from exc

    async def set_bypass_hardening(
        self,
        router_id: uuid.UUID,
        *,
        enabled: bool,
        layers: list[str] | None = None,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> DnsFilteringRouterLocation:
        """Opt-in: converge the router's DNS-bypass layers on exactly
        ``layers`` (default: every layer except VPN blocking), or remove all
        of them when ``enabled`` is false. Only on a router already switched
        to Gateway -- without it, forcing guests onto the router's resolver
        buys the category filter nothing.

        Turning the VPN layer on or off also re-points the router between
        its venue's category set and the same set plus Cloudflare's
        Anonymizer category -- a different Gateway location, so it counts
        against the location cap and is checked before the router is
        touched."""
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        ensure_not_controller_managed(router, feature=FEATURE_NAME)
        enforce_entity_location(
            entity_location_id=getattr(router, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationDnsFilteringAccessError(),
        )
        chosen = self._chosen_layers(enabled, layers)
        row = await self.repository.get_router_location(router.id)
        if row is None or (enabled and row.state != RouterFilteringState.ACTIVE.value):
            raise DnsFilteringNotEnabledError(router.id)
        adapter = get_dns_filtering_adapter(router.vendor)
        credentials = self._resolve_device_credentials(router)
        vpn_after = BypassLayer.VPN_BLOCK.value in chosen
        if (
            vpn_after != _vpn_block_on(row)
            and row.state == RouterFilteringState.ACTIVE.value
        ):
            # The VPN layer moves the router to another category set (its
            # venue's plus Anonymizer) -- which may be a new distinct set and
            # need a Gateway location of its own. Refused before the router
            # is touched.
            effective = await self._effective(row.organization_id, row.location_id)
            target = await self._target_profile_id(effective, vpn_block=vpn_after)
            if target is not None and target != row.applied_profile_id:
                target_profile = await self.repository.get_profile(target)
                await self._check_location_cap(
                    list(target_profile.category_ids) if target_profile else [],
                    [(row, target)],
                )
        payload = await self._bypass_payload() if chosen & LIST_BACKED_LAYERS else None
        try:
            if enabled:
                await adapter.apply_bypass_hardening(
                    credentials,
                    layers=chosen,
                    doh_ipv4=payload.doh_ipv4 if payload else [],
                    doh_hostnames=payload.doh_hostnames if payload else [],
                    sni_hostnames=payload.sni_hostnames if payload else [],
                )
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
        vpn_before = _vpn_block_on(row)
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
                "bypass_layers": sorted(chosen),
                "bypass_lists_sha": payload.sha if payload else None,
                "bypass_lists_pushed_at": datetime.now(UTC) if payload else None,
                "updated_by": actor_user_id,
            },
        )
        await self.repository.commit()
        if (
            vpn_before != _vpn_block_on(updated)
            and updated.state == RouterFilteringState.ACTIVE.value
        ):
            updated = await self._move_to_target_profile(
                updated,
                adapter=adapter,
                credentials=credentials,
                actor_user_id=actor_user_id,
            )
        await self._audit(
            actor_user_id,
            AuditAction.DNS_FILTERING_BYPASS_HARDENING_CHANGED,
            entity_type="router",
            entity_id=router.id,
            organization_id=router.organization_id,
            description=(
                f"DNS bypass hardening {'enabled' if enabled else 'disabled'} "
                f"on router {router.id}; layers: {sorted(chosen) or 'none'}"
            ),
        )
        return updated

    @staticmethod
    def _chosen_layers(enabled: bool, layers: list[str] | None) -> frozenset[str]:
        if not enabled:
            return frozenset()
        if layers is None:
            return DEFAULT_BYPASS_LAYERS
        valid = {layer.value for layer in BypassLayer}
        unknown = sorted(set(layers) - valid)
        if unknown:
            raise BypassLayerInvalidError(f"Unknown bypass layer(s): {unknown}")
        if not layers:
            raise BypassLayerInvalidError(
                "Name at least one layer, or send enabled=false to turn bypass "
                "protection off."
            )
        return frozenset(layers)

    async def _move_to_target_profile(
        self,
        row: DnsFilteringRouterLocation,
        *,
        adapter: Any,
        credentials: DnsFilteringCredentials,
        actor_user_id: uuid.UUID | None,
    ) -> DnsFilteringRouterLocation:
        """Re-point the router after its VPN layer changed: Gateway locations
        are per category set, so "venue's set plus Anonymizer" is a
        different endpoint, reached with the same verified switch as any
        other set change. The bypass rules are already committed on the
        device; a failed switch is recorded on the row and raised, and the
        router keeps filtering with the set it was on."""
        effective = await self._effective(row.organization_id, row.location_id)
        target = await self._target_profile_id(effective, vpn_block=_vpn_block_on(row))
        if target is None or target == row.applied_profile_id:
            return row
        try:
            return await self._switch_router(
                row,
                target,
                adapter=adapter,
                credentials=credentials,
                actor_user_id=actor_user_id,
            )
        except DnsFilteringError as exc:
            await self.repository.update_router_location(
                row,
                {
                    "bypass_hardening_error": (
                        "The router's bypass rules were updated, but moving it "
                        "to the category selection with Cloudflare's "
                        f"Anonymizer category failed: {exc.message}"
                    )
                },
            )
            await self.repository.commit()
            raise

    async def _bypass_payload(self) -> BypassPayload:
        """The platform's last good DoH lists, re-filtered against the
        current exclusions (a setting change must not wait for the next
        refresh), plus the curated hostnames that also get ``tls-host``."""
        ipv4_row = await self.repository.get_blocklist(BlocklistKind.DOH_IPV4.value)
        names_row = await self.repository.get_blocklist(BlocklistKind.DOH_DOMAINS.value)
        networks = [ipaddress.ip_network(n, strict=False) for n in self.ip_exclusions]
        ipv4 = [
            a
            for a in (ipv4_row.entries if ipv4_row is not None else [])
            if not any(
                ipaddress.ip_address(a).version == n.version
                and ipaddress.ip_address(a) in n
                for n in networks
            )
        ][: self.list_max_entries]
        names = hostnames_to_push(
            names_row.entries if names_row is not None else [],
            exclusions=self.hostname_exclusions,
            probe_hostname=self.probe_hostname,
            max_entries=self.list_max_entries,
        )
        sni = hostnames_to_push(
            [],
            exclusions=self.hostname_exclusions,
            probe_hostname=self.probe_hostname,
            max_entries=len(CURATED_DOH_HOSTNAMES),
        )
        return BypassPayload(
            doh_ipv4=ipv4,
            doh_hostnames=names,
            sni_hostnames=sni,
            sha=list_sha([*ipv4, *(f"name:{n}" for n in names)]),
        )

    async def push_bypass_lists_to_router(self, router_id: uuid.UUID) -> str:
        """The scheduled refresh's per-router leaf: re-converge a router's
        layers when the platform lists moved since its last push.

        Never raises for a device problem -- one unreachable router must not
        fail the task; the error is recorded on the row. Returns
        ``pushed`` / ``unchanged`` / ``skipped`` / ``failed``."""
        router = await self.router_lookup.get_router(router_id)
        ensure_not_controller_managed(router, feature=FEATURE_NAME)
        row = await self.repository.get_router_location(router.id)
        if (
            row is None
            or not row.bypass_hardening_enabled
            or row.state != RouterFilteringState.ACTIVE.value
        ):
            return "skipped"
        layers = frozenset(row.bypass_layers or [])
        if not layers & LIST_BACKED_LAYERS:
            return "skipped"
        payload = await self._bypass_payload()
        if row.bypass_lists_sha == payload.sha:
            return "unchanged"
        adapter = get_dns_filtering_adapter(router.vendor)
        try:
            credentials = self._resolve_device_credentials(router)
            await adapter.apply_bypass_hardening(
                credentials,
                layers=layers,
                doh_ipv4=payload.doh_ipv4,
                doh_hostnames=payload.doh_hostnames,
                sni_hostnames=payload.sni_hostnames,
            )
        except DnsFilteringError as exc:
            # The rules already on the router stay in force; only the list
            # refresh did not land.
            await self.repository.update_router_location(
                row,
                {"bypass_hardening_error": f"DoH list refresh failed: {exc.message}"},
            )
            await self.repository.commit()
            return "failed"
        await self.repository.update_router_location(
            row,
            {
                "bypass_lists_sha": payload.sha,
                "bypass_lists_pushed_at": datetime.now(UTC),
                "bypass_hardening_error": None,
            },
        )
        await self.repository.commit()
        return "pushed"

    async def get_bypass_counters(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> BypassCountersView:
        """Per-layer drop counters read off the router's own marked rules.
        Honest by construction: anything that cannot be read is
        ``available=False`` with the reason, never a zero."""
        router = await self._load_router(router_id, requesting_organization_id)
        ensure_not_controller_managed(router, feature=FEATURE_NAME)
        row = await self.repository.get_router_location(router.id)
        enabled_layers = set(row.bypass_layers or []) if row is not None else set()

        def unavailable(reason: str) -> BypassCountersView:
            return BypassCountersView(
                available=False,
                reason=reason,
                router_uptime=None,
                layers=[
                    LayerCountersView(
                        layer.value,
                        layer.value in enabled_layers,
                        False,
                        None,
                        None,
                        reason,
                    )
                    for layer in BypassLayer
                ],
            )

        if row is None or not row.bypass_hardening_enabled:
            return unavailable("Bypass protection is off on this router.")
        try:
            adapter = get_dns_filtering_adapter(router.vendor)
            credentials = self._resolve_device_credentials(router)
            counters = await adapter.read_bypass_counters(credentials)
        except DnsFilteringError as exc:
            return unavailable(f"Could not read the router: {exc.message}")
        by_layer = {c.layer: c for c in counters.layers}
        views: list[LayerCountersView] = []
        for layer in BypassLayer:
            c = by_layer.get(layer.value)
            if c is None:
                views.append(
                    LayerCountersView(
                        layer.value,
                        layer.value in enabled_layers,
                        False,
                        None,
                        None,
                        "the router returned nothing for this layer",
                    )
                )
                continue
            views.append(
                LayerCountersView(
                    layer.value,
                    layer.value in enabled_layers,
                    c.counters_available,
                    c.packets,
                    c.bytes,
                    c.reason,
                )
            )
        return BypassCountersView(
            available=any(v.available for v in views),
            reason=None
            if any(v.available for v in views)
            else "No layer on this router has a readable counter.",
            router_uptime=counters.router_uptime,
            layers=views,
        )

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
    "BypassCountersView",
    "BypassPayload",
    "CategoryCache",
    "DnsFilteringService",
    "EffectivePolicy",
    "GatewayClientProtocol",
]
