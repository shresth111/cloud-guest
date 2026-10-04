"""Speed tiers by WiFi network: storage, entitlement lookup, the guest-facing
answer, and the Instant On sync plan. The decision itself is pure and lives in
``app.domains.guest.ssid_tiers``.

Tenant scoping: every read and write takes the organization the caller was
authorised for and puts it in the WHERE clause together with the location. The
router layer resolves the location through ``LocationService.get_location``
(organization guard) and ``enforce_target_location`` (location guard) before
calling in here, and ``organization_id`` on a written row always comes from the
location row, never from a request body.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.exceptions import CloudGuestError

from .constants import GuestSessionStatus
from .models import GuestSession, LocationSsidTier
from .ssid_tiers import (
    MAX_SSID_LENGTH,
    MAX_TIER_MBPS,
    MIN_TIER_MBPS,
    GuestEntitlement,
    SsidTierRule,
    entitles,
    find_rule,
    ssid_key,
    upgrade_networks,
)

logger = logging.getLogger(__name__)

#: An Instant On site carries a handful of SSIDs; more rows than this is a typo
#: or abuse, not a venue.
MAX_SSID_TIERS_PER_LOCATION = 8


class SsidTierValidationError(CloudGuestError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=422, data={"code": "SSID_TIER_INVALID"})


# ---------------------------------------------------------------------------
# Conversions
# ---------------------------------------------------------------------------


def _uuid_list(value: Any) -> tuple[uuid.UUID, ...]:
    out: list[uuid.UUID] = []
    for item in value or []:
        try:
            out.append(uuid.UUID(str(item)))
        except (TypeError, ValueError):
            continue
    return tuple(out)


def rule_from_row(row: LocationSsidTier) -> SsidTierRule:
    return SsidTierRule(
        ssid=row.ssid,
        tier_name=row.tier_name,
        requires_entitlement=bool(row.requires_entitlement),
        policy_id=row.policy_id,
        voucher_plan_ids=_uuid_list(row.voucher_plan_ids),
        download_mbps=row.download_mbps,
        upload_mbps=row.upload_mbps,
    )


@dataclass(frozen=True, slots=True)
class SsidTierInput:
    ssid: str
    tier_name: str
    requires_entitlement: bool = False
    policy_id: uuid.UUID | None = None
    voucher_plan_ids: tuple[uuid.UUID, ...] = ()
    download_mbps: int | None = None
    upload_mbps: int | None = None


def _check_mbps(value: int | None, what: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise SsidTierValidationError(f"{what} must be a whole number of Mbps.")
    if not MIN_TIER_MBPS <= value <= MAX_TIER_MBPS:
        raise SsidTierValidationError(
            f"{what} must be between {MIN_TIER_MBPS} and {MAX_TIER_MBPS} Mbps "
            "(the range Aruba Instant On accepts)."
        )


def validate_inputs(items: Sequence[SsidTierInput]) -> list[SsidTierInput]:
    """Shape checks that need no database. Returns the items with names
    trimmed. Raises ``SsidTierValidationError`` with a sentence an operator
    can act on."""
    if len(items) > MAX_SSID_TIERS_PER_LOCATION:
        raise SsidTierValidationError(
            f"At most {MAX_SSID_TIERS_PER_LOCATION} WiFi networks per location."
        )
    seen: set[str] = set()
    cleaned: list[SsidTierInput] = []
    for item in items:
        ssid = (item.ssid or "").strip()
        if not ssid:
            raise SsidTierValidationError("Each row needs a WiFi network name.")
        if len(ssid) > MAX_SSID_LENGTH:
            raise SsidTierValidationError(
                f"WiFi network names are at most {MAX_SSID_LENGTH} characters."
            )
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in ssid):
            raise SsidTierValidationError(
                "A WiFi network name cannot contain control characters."
            )
        key = ssid_key(ssid)
        if key in seen:
            raise SsidTierValidationError(f"The WiFi network {ssid!r} is listed twice.")
        seen.add(key)
        tier_name = (item.tier_name or "").strip()
        if not tier_name:
            raise SsidTierValidationError(f"Give the tier for {ssid!r} a name.")
        if len(tier_name) > 100:
            raise SsidTierValidationError("Tier names are at most 100 characters.")
        _check_mbps(item.download_mbps, "Download speed")
        _check_mbps(item.upload_mbps, "Upload speed")
        if not item.requires_entitlement and (item.policy_id or item.voucher_plan_ids):
            raise SsidTierValidationError(
                f"{ssid!r} is open to every guest, so it cannot also name an "
                "Access Tier or voucher plans. Switch on 'Paid / voucher guests "
                "only' first."
            )
        cleaned.append(
            SsidTierInput(
                ssid=ssid,
                tier_name=tier_name,
                requires_entitlement=item.requires_entitlement,
                policy_id=item.policy_id,
                voucher_plan_ids=tuple(dict.fromkeys(item.voucher_plan_ids)),
                download_mbps=item.download_mbps,
                upload_mbps=item.upload_mbps,
            )
        )
    return cleaned


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------


class SsidTierLookupProtocol(Protocol):
    async def rules_for_location(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> list[SsidTierRule]: ...

    async def entitlement_for(
        self,
        *,
        guest_id: uuid.UUID,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        now: datetime | None = None,
    ) -> GuestEntitlement: ...


class SsidTierRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_rows(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> list[LocationSsidTier]:
        statement = (
            select(LocationSsidTier)
            .where(
                LocationSsidTier.organization_id == organization_id,
                LocationSsidTier.location_id == location_id,
                LocationSsidTier.is_deleted.is_(False),
            )
            .order_by(LocationSsidTier.sort_order.asc(), LocationSsidTier.ssid.asc())
        )
        return list((await self.session.execute(statement)).scalars().all())

    async def rules_for_location(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> list[SsidTierRule]:
        rows = await self.list_rows(
            organization_id=organization_id, location_id=location_id
        )
        return [rule_from_row(row) for row in rows]

    async def replace_rows(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        items: Sequence[SsidTierInput],
        actor_user_id: uuid.UUID | None,
    ) -> list[LocationSsidTier]:
        await self.session.execute(
            delete(LocationSsidTier).where(
                LocationSsidTier.organization_id == organization_id,
                LocationSsidTier.location_id == location_id,
            )
        )
        rows: list[LocationSsidTier] = []
        for index, item in enumerate(items):
            row = LocationSsidTier(
                organization_id=organization_id,
                location_id=location_id,
                ssid=item.ssid,
                tier_name=item.tier_name,
                requires_entitlement=item.requires_entitlement,
                policy_id=item.policy_id,
                voucher_plan_ids=[str(p) for p in item.voucher_plan_ids],
                download_mbps=item.download_mbps,
                upload_mbps=item.upload_mbps,
                sort_order=index,
                created_by=actor_user_id,
                updated_by=actor_user_id,
            )
            self.session.add(row)
            rows.append(row)
        await self.session.flush()
        await self.session.commit()
        return rows

    async def foreign_policy_ids(
        self, *, organization_id: uuid.UUID, policy_ids: set[uuid.UUID]
    ) -> set[uuid.UUID]:
        """The ids in ``policy_ids`` that are NOT an active BANDWIDTH policy
        (Access Tier) of this organization."""
        if not policy_ids:
            return set()
        from app.domains.policy.constants import PolicyType
        from app.domains.policy.models import Policy

        statement = select(Policy.id).where(
            Policy.id.in_(policy_ids),
            Policy.organization_id == organization_id,
            Policy.policy_type == PolicyType.BANDWIDTH.value,
            Policy.is_deleted.is_(False),
        )
        found = set((await self.session.execute(statement)).scalars().all())
        return policy_ids - found

    async def foreign_voucher_plan_ids(
        self, *, organization_id: uuid.UUID, plan_ids: set[uuid.UUID]
    ) -> set[uuid.UUID]:
        """The ids in ``plan_ids`` that are neither this organization's voucher
        plans nor platform-wide ones."""
        if not plan_ids:
            return set()
        from app.domains.voucher.models import VoucherPlan

        statement = select(VoucherPlan.id).where(
            VoucherPlan.id.in_(plan_ids),
            (VoucherPlan.organization_id == organization_id)
            | VoucherPlan.organization_id.is_(None),
            VoucherPlan.is_deleted.is_(False),
        )
        found = set((await self.session.execute(statement)).scalars().all())
        return plan_ids - found

    async def entitlement_for(
        self,
        *,
        guest_id: uuid.UUID,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        now: datetime | None = None,
    ) -> GuestEntitlement:
        """What this guest holds at this location right now:

        * the plan of every voucher they signed in with HERE that is still a
          valid pass (redeemed, not revoked/expired, ``expires_at`` in the
          future or unset). Read through their sessions, so the guest is
          matched by ``guest_id`` -- the same person after a phone gives a
          new per-SSID random MAC on the premium network;
        * every Access Tier (BANDWIDTH policy) they are mapped into
          (``PolicyAssignment`` target GUEST, active)."""
        from app.domains.policy.constants import (
            PolicyAssignmentTargetType,
            PolicyType,
        )
        from app.domains.policy.models import Policy, PolicyAssignment
        from app.domains.rbac.enums import ScopeType
        from app.domains.voucher.constants import VoucherStatus
        from app.domains.voucher.models import Voucher

        now = now or datetime.now(UTC)
        voucher_rows = await self.session.execute(
            select(Voucher.plan_id, Voucher.expires_at)
            .join(GuestSession, GuestSession.voucher_id == Voucher.id)
            .where(
                GuestSession.guest_id == guest_id,
                GuestSession.organization_id == organization_id,
                GuestSession.location_id == location_id,
                Voucher.organization_id == organization_id,
                Voucher.status.in_(
                    (VoucherStatus.ACTIVE.value, VoucherStatus.EXHAUSTED.value)
                ),
            )
        )
        plans: set[uuid.UUID | None] = set()
        for plan_id, expires_at in voucher_rows.all():
            if expires_at is not None and expires_at <= now:
                continue
            plans.add(plan_id)
        tier_rows = await self.session.execute(
            select(PolicyAssignment.policy_id)
            .join(Policy, Policy.id == PolicyAssignment.policy_id)
            .where(
                PolicyAssignment.target_type == PolicyAssignmentTargetType.GUEST.value,
                PolicyAssignment.target_id == guest_id,
                PolicyAssignment.is_active.is_(True),
                PolicyAssignment.is_deleted.is_(False),
                Policy.organization_id == organization_id,
                Policy.policy_type == PolicyType.BANDWIDTH.value,
                Policy.is_active.is_(True),
                Policy.is_deleted.is_(False),
                Policy.current_version_id.is_not(None),
                # Mapped into the tier HERE (the dashboard writes
                # scope_type=location), not at another of the account's
                # venues -- the same scope rule Access Tier enforcement
                # (PolicyService.resolve_access_tier) applies.
                or_(
                    PolicyAssignment.scope_type == ScopeType.GLOBAL.value,
                    (PolicyAssignment.scope_type == ScopeType.ORGANIZATION.value)
                    & (PolicyAssignment.scope_id == organization_id),
                    (PolicyAssignment.scope_type == ScopeType.LOCATION.value)
                    & (PolicyAssignment.scope_id == location_id),
                ),
            )
        )
        tiers = {pid for (pid,) in tier_rows.all() if pid is not None}
        return GuestEntitlement(
            voucher_plan_ids=frozenset(plans), tier_policy_ids=frozenset(tiers)
        )

    async def get_session(self, session_id: uuid.UUID) -> GuestSession | None:
        statement = select(GuestSession).where(
            GuestSession.id == session_id, GuestSession.is_deleted.is_(False)
        )
        return (await self.session.execute(statement)).scalars().first()


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GuestSsidAccess:
    """The portal's answer for one guest on one SSID."""

    ssid: str | None
    mapped: bool
    requires_entitlement: bool
    entitled: bool
    tier_name: str | None
    download_mbps: int | None
    upload_mbps: int | None
    upgrade_networks: list[SsidTierRule] = field(default_factory=list)
    paid_networks: list[SsidTierRule] = field(default_factory=list)


def instant_on_manual_steps(rules: Sequence[SsidTierRule]) -> list[str]:
    """What the owner sets in the Instant On app when cloud control is off.
    One sentence per SSID, in Instant On's own words."""
    steps: list[str] = []
    for rule in rules:
        if rule.download_mbps is None and rule.upload_mbps is None:
            limit = "Bandwidth limit: off (no speed cap)"
        else:
            parts = []
            if rule.download_mbps is not None:
                parts.append(f"download {rule.download_mbps} Mbps")
            if rule.upload_mbps is not None:
                parts.append(f"upload {rule.upload_mbps} Mbps")
            limit = "Bandwidth limit: Per client, " + ", ".join(parts)
        steps.append(
            f"Instant On app > Networks > {rule.ssid} > Show advanced settings > "
            f"{limit}. Type Guest, Open, Show guest portal ON."
        )
    return steps


class SsidTierService:
    def __init__(self, repository: SsidTierRepository) -> None:
        self.repository = repository

    async def list_rules(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> list[SsidTierRule]:
        return await self.repository.rules_for_location(
            organization_id=organization_id, location_id=location_id
        )

    async def replace(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        items: Sequence[SsidTierInput],
        actor_user_id: uuid.UUID | None,
    ) -> list[SsidTierRule]:
        cleaned = validate_inputs(items)
        policy_ids = {i.policy_id for i in cleaned if i.policy_id is not None}
        foreign = await self.repository.foreign_policy_ids(
            organization_id=organization_id, policy_ids=policy_ids
        )
        if foreign:
            raise SsidTierValidationError(
                "One of the Access Tiers is not an Access Tier of this account."
            )
        plan_ids = {p for i in cleaned for p in i.voucher_plan_ids}
        foreign_plans = await self.repository.foreign_voucher_plan_ids(
            organization_id=organization_id, plan_ids=plan_ids
        )
        if foreign_plans:
            raise SsidTierValidationError(
                "One of the voucher plans is not available to this account."
            )
        rows = await self.repository.replace_rows(
            organization_id=organization_id,
            location_id=location_id,
            items=cleaned,
            actor_user_id=actor_user_id,
        )
        logger.info(
            "ssid_tiers_replaced",
            extra={
                "organization_id": str(organization_id),
                "location_id": str(location_id),
                "count": len(rows),
                "actor_user_id": str(actor_user_id) if actor_user_id else None,
            },
        )
        return [rule_from_row(row) for row in rows]

    async def guest_access(
        self, *, session_id: uuid.UUID, ssid: str | None
    ) -> GuestSsidAccess | None:
        """The portal's question, keyed on the guest's own session id (an
        unguessable UUID the portal holds after sign-in, the same credential
        ``/guest/set-password`` uses). ``None`` when there is no such
        session. Never reveals anything outside that session's own location."""
        guest_session = await self.repository.get_session(session_id)
        if guest_session is None:
            return None
        rules = await self.repository.rules_for_location(
            organization_id=guest_session.organization_id,
            location_id=guest_session.location_id,
        )
        paid = [rule for rule in rules if rule.requires_entitlement]
        if not rules:
            return GuestSsidAccess(
                ssid=ssid,
                mapped=False,
                requires_entitlement=False,
                entitled=True,
                tier_name=None,
                download_mbps=None,
                upload_mbps=None,
            )
        entitlement = await self.repository.entitlement_for(
            guest_id=guest_session.guest_id,
            organization_id=guest_session.organization_id,
            location_id=guest_session.location_id,
        )
        rule = find_rule(rules, ssid)
        return GuestSsidAccess(
            ssid=ssid,
            mapped=rule is not None,
            requires_entitlement=bool(rule and rule.requires_entitlement),
            entitled=True if rule is None else entitles(rule, entitlement),
            tier_name=rule.tier_name if rule else None,
            download_mbps=rule.download_mbps if rule else None,
            upload_mbps=rule.upload_mbps if rule else None,
            upgrade_networks=upgrade_networks(rules, entitlement, current_ssid=ssid),
            paid_networks=paid,
        )

    async def guest_session_is_active(self, session_id: uuid.UUID) -> bool:
        row = await self.repository.get_session(session_id)
        return row is not None and row.status == GuestSessionStatus.ACTIVE.value


__all__ = [
    "MAX_SSID_TIERS_PER_LOCATION",
    "GuestSsidAccess",
    "SsidTierInput",
    "SsidTierLookupProtocol",
    "SsidTierRepository",
    "SsidTierService",
    "SsidTierValidationError",
    "instant_on_manual_steps",
    "rule_from_row",
    "validate_inputs",
]
