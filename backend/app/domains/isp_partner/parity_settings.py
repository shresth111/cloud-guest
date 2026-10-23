"""ADDENDUM_04 founder questions F1-F3, built with the coordinator defaults as
PER-ISP settings Master (or the ISP owner/admin) can change. Nothing here is a
hard-coded answer; ``policy.py``'s env values are only the fallback for an ISP
with no settings row.

F1 -- pricing and credits
    * Allowance rows (``isp_addons``) carry an optional
      ``price_per_customer_paise``: a RECORD of what was agreed. The ISP pays
      Wyfy in cash; nothing bills from it.
    * ONE messaging credit wallet per ISP: the existing ``credit_wallets`` row
      of the ISP ORGANIZATION (``CreditWalletService``, bucket ``marketing``),
      topped up by Master through ``POST /platform/isp-partners/{id}/wallet/
      topups``. A customer's send draws from it: just before a twinned
      schedule or test-send, ``fund_customer`` moves exactly the shortfall
      (estimate - what the customer wallet already holds) from the ISP wallet
      to the customer wallet, as two ``adjust`` ledger rows with one
      idempotency key. At zero the send is refused with 402
      ``ISP_WALLET_EMPTY`` before anything is reserved. The existing
      reserve/debit/release flow then runs unchanged on the customer wallet;
      anything not spent stays there as "held" and is used first next time.

F2 -- PII
    * ``pii_unmask_enabled`` per ISP, Master-set (default off). When on, ONLY
      ``isp-owner``/``isp-admin`` get unmasked guest identifiers and Traffic
      Lens flow records; every such view is written to ``audit_log_entries``
      (action ``isp_pii_unmasked_view``), which Staff Activity reads.

F3 -- BYO sender
    * One ISP-level sender per channel, stored as the ISP organization's own
      ``org_marketing_providers`` row through the ORIGINAL provider handlers,
      then copied (ciphertext, never plaintext) to each customer that does not
      have its own. ``byo_customer_override_enabled`` (ISP owner/admin) lets a
      customer be switched to its own sender (``isp_customer_messaging``);
      such a customer is never overwritten by the sync. SMS DLT registration
      stays the ISP's responsibility, as on the customer host.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.billing.credits_constants import MINOR_PER_CREDIT, CreditBucket
from app.domains.billing.credits_repository import CreditRepository
from app.domains.billing.credits_service import CreditWalletService, wallet_summary
from app.domains.rbac.dependencies import CurrentUser, RequirePermission
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.models import AuditLogEntry

from .addon_models import IspCustomerMessaging, IspParitySetting
from .constants import ISP_ENGAGE_MANAGE, ISP_ENGAGE_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspError, IspPartnerNotFoundError
from .http import ok
from .models import IspPartnerProfile
from .policy import get_isp_partner_policy
from .scoping import IspScope

__all__ = [
    "AUDIT_PII_UNMASKED_VIEW",
    "IspWalletEmptyError",
    "fund_customer",
    "get_parity_setting",
    "isp_parity_router",
    "parity_platform_router",
    "pii_unmasked_for",
    "record_unmasked_view",
]

AUDIT_PII_UNMASKED_VIEW = "isp_pii_unmasked_view"
UNMASK_ROLES = frozenset({"isp-owner", "isp-admin"})


class IspWalletEmptyError(IspError):
    code = "ISP_WALLET_EMPTY"
    status_code_default = status.HTTP_402_PAYMENT_REQUIRED
    default_message = (
        "Your messaging credit wallet does not cover this send. Ask Wyfy to top it up."
    )


class IspOverrideNotEnabledError(IspError):
    code = "ISP_BYO_OVERRIDE_NOT_ENABLED"
    status_code_default = status.HTTP_403_FORBIDDEN
    default_message = (
        "Per-customer senders are off for your account. Turn them on in "
        "Messaging settings first."
    )


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


async def _setting_row(db: AsyncSession, isp_org_id: uuid.UUID) -> Any:
    return (
        await db.execute(
            select(IspParitySetting).where(
                IspParitySetting.isp_organization_id == isp_org_id,
                IspParitySetting.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


async def get_parity_setting(
    db: AsyncSession, isp_org_id: uuid.UUID
) -> dict[str, bool]:
    policy = get_isp_partner_policy()
    row = await _setting_row(db, isp_org_id)
    if row is None:
        return {
            "pii_unmask_enabled": bool(policy.pii_unmasked),
            "byo_customer_override_enabled": policy.byo_sender_scope == "customer",
            "source": "default",
        }
    return {
        "pii_unmask_enabled": bool(row.pii_unmask_enabled),
        "byo_customer_override_enabled": bool(row.byo_customer_override_enabled),
        "source": "isp",
    }


async def _upsert_setting(
    db: AsyncSession, isp_org_id: uuid.UUID, actor_id: uuid.UUID, **values: bool
) -> None:
    row = await _setting_row(db, isp_org_id)
    if row is None:
        current = await get_parity_setting(db, isp_org_id)
        row = IspParitySetting(
            isp_organization_id=isp_org_id,
            pii_unmask_enabled=current["pii_unmask_enabled"],
            byo_customer_override_enabled=current["byo_customer_override_enabled"],
            created_by=actor_id,
        )
        db.add(row)
    for key, value in values.items():
        setattr(row, key, value)
    row.updated_by = actor_id


async def pii_unmasked_for(db: AsyncSession, isp: IspContext) -> bool:
    """F2: True only when Master enabled unmasking for THIS ISP and the caller
    is its owner or admin."""
    if isp.role_slug not in UNMASK_ROLES:
        return False
    return (await get_parity_setting(db, isp.isp_org_id))["pii_unmask_enabled"]


async def record_unmasked_view(
    db: AsyncSession,
    isp: IspContext,
    *,
    what: str,
    customer_org_id: uuid.UUID | None,
    location_id: uuid.UUID | None = None,
) -> None:
    """One audit row per unmasked view, in the ISP org (Staff Activity)."""
    db.add(
        AuditLogEntry(
            actor_user_id=isp.user_id,
            action=AUDIT_PII_UNMASKED_VIEW,
            entity_type="isp_partner",
            entity_id=customer_org_id,
            organization_id=isp.isp_org_id,
            location_id=None,
            description=f"Unmasked view: {what}"[:500],
            event_metadata={
                "what": what,
                "isp_customer_id": str(customer_org_id) if customer_org_id else None,
                "isp_location_id": str(location_id) if location_id else None,
            },
        )
    )
    await db.commit()


# ---------------------------------------------------------------------------
# F1 wallet
# ---------------------------------------------------------------------------


def _wallets(db: AsyncSession) -> CreditWalletService:
    return CreditWalletService(CreditRepository(db))


async def _available(db: AsyncSession, org_id: uuid.UUID) -> int:
    wallet = await CreditRepository(db).get_wallet(org_id, CreditBucket.MARKETING.value)
    return wallet_summary(wallet)["available_minor"]


async def fund_customer(
    db: AsyncSession,
    *,
    isp_org_id: uuid.UUID,
    customer_org_id: uuid.UUID,
    needed_minor: int,
    idempotency_key: str,
    actor_user_id: uuid.UUID | None,
) -> int:
    """Move the shortfall from the ISP wallet to the customer wallet. Returns
    the amount moved (0 when the customer already holds enough). Does not
    commit: the original handler that follows owns the transaction."""
    if needed_minor <= 0:
        return 0
    shortfall = needed_minor - await _available(db, customer_org_id)
    if shortfall <= 0:
        return 0
    if await _available(db, isp_org_id) < shortfall:
        raise IspWalletEmptyError(needed_minor=needed_minor, shortfall_minor=shortfall)
    wallets = _wallets(db)
    note = f"ISP wallet -> customer {customer_org_id}"
    await wallets.adjust(
        isp_org_id,
        -shortfall,
        idempotency_key=f"{idempotency_key}:out",
        actor_user_id=actor_user_id,
        reference=f"isp-fund:{customer_org_id}",
        note=note,
    )
    await wallets.adjust(
        customer_org_id,
        shortfall,
        idempotency_key=f"{idempotency_key}:in",
        actor_user_id=actor_user_id,
        reference=f"isp-fund:{isp_org_id}",
        note="Funded from the ISP's messaging wallet",
    )
    return shortfall


async def _wallet_view(
    db: AsyncSession, isp_org_id: uuid.UUID, customers: list[uuid.UUID]
) -> dict:
    repo = CreditRepository(db)
    pool = wallet_summary(
        await repo.get_wallet(isp_org_id, CreditBucket.MARKETING.value)
    )
    held = []
    for cid in customers:
        w = wallet_summary(await repo.get_wallet(cid, CreditBucket.MARKETING.value))
        if w["available_minor"] or w["reserved_minor"]:
            held.append({"isp_customer_id": str(cid), **w})
    return {
        "minor_per_credit": MINOR_PER_CREDIT,
        "pool": pool,
        "held_by_customers": held,
        "held_total_minor": sum(h["available_minor"] for h in held),
    }


# ---------------------------------------------------------------------------
# F3 sender sync (ciphertext copy; the original handlers own every write to
# the ISP org's own row)
# ---------------------------------------------------------------------------

_SYNC_MARK = "isp_managed"


async def own_sender(db: AsyncSession, customer_org_id: uuid.UUID) -> bool:
    row = (
        await db.execute(
            select(IspCustomerMessaging).where(
                IspCustomerMessaging.customer_organization_id == customer_org_id,
                IspCustomerMessaging.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    return bool(row and row.own_sender)


async def sync_sender_to_customer(
    db: AsyncSession,
    *,
    isp_org_id: uuid.UUID,
    customer_org_id: uuid.UUID,
    actor_user_id: uuid.UUID | None,
) -> list[str]:
    """Make the customer's provider rows mirror the ISP's, channel by channel.
    Skips a customer with its own sender. Only rows this sync created
    (``display.isp_managed``) are ever replaced or removed."""
    from app.domains.marketing.constants import Channel
    from app.domains.marketing.repository import MarketingRepository

    if await own_sender(db, customer_org_id):
        return []
    repo = MarketingRepository(db)
    src_rows = await repo.list_providers(isp_org_id)
    dst_rows = await repo.list_providers(customer_org_id)
    changed: list[str] = []
    for channel in Channel:
        src = src_rows.get(channel.value)
        dst = dst_rows.get(channel.value)
        if dst is not None and not (dst.display or {}).get(_SYNC_MARK):
            continue  # the customer's own row from before; never touched
        if src is None:
            if dst is not None:
                await repo.soft_delete_provider(dst)
                changed.append(channel.value)
            continue
        fields = {
            "provider_type": src.provider_type,
            "config_encrypted": src.config_encrypted,
            "display": {**(src.display or {}), _SYNC_MARK: True},
            "status": src.status,
            "enabled": src.enabled,
            "last_verified_at": src.last_verified_at,
            "last_error": src.last_error,
            "verified_by_user_id": src.verified_by_user_id,
            "updated_by_user_id": actor_user_id,
        }
        if dst is None:
            await repo.create_provider(
                organization_id=customer_org_id,
                channel=channel.value,
                created_by=actor_user_id,
                **fields,
            )
        else:
            await repo.update_provider(dst, fields)
        changed.append(channel.value)
    return changed


async def sync_sender_to_all(
    db: AsyncSession, isp: IspContext, actor_user_id: uuid.UUID | None
) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for cid in await isp.repository.child_ids(isp.isp_org_id):
        changed = await sync_sender_to_customer(
            db,
            isp_org_id=isp.isp_org_id,
            customer_org_id=cid,
            actor_user_id=actor_user_id,
        )
        if changed:
            out[str(cid)] = changed
    return out


# ---------------------------------------------------------------------------
# ISP routes
# ---------------------------------------------------------------------------

isp_parity_router = APIRouter(tags=["ISP Partner: messaging & wallet"])


@isp_parity_router.get("/wallet", dependencies=isp_guards(ISP_ENGAGE_READ))
async def get_isp_wallet(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
):
    customers = await isp.child_ids()
    return ok(request, await _wallet_view(db, isp.isp_org_id, customers))


@isp_parity_router.get("/messaging/settings", dependencies=isp_guards(ISP_ENGAGE_READ))
async def get_messaging_settings(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
):
    s = await get_parity_setting(db, isp.isp_org_id)
    return ok(
        request,
        {
            "byo_customer_override_enabled": s["byo_customer_override_enabled"],
            "pii_unmask_enabled": s["pii_unmask_enabled"],
            "pii_unmasked_for_me": await pii_unmasked_for(db, isp),
        },
    )


class MessagingSettingsUpdate(BaseModel):
    byo_customer_override_enabled: bool


@isp_parity_router.put(
    "/messaging/settings", dependencies=isp_guards(ISP_ENGAGE_MANAGE)
)
async def put_messaging_settings(
    request: Request,
    payload: MessagingSettingsUpdate,
    isp: IspContext = Depends(RequireIspPartner),
    actor: AuthUser = Depends(CurrentUser),
    db: AsyncSession = Depends(get_db_session),
):
    actor_id = uuid.UUID(str(actor.id))
    await _upsert_setting(
        db,
        isp.isp_org_id,
        actor_id,
        byo_customer_override_enabled=payload.byo_customer_override_enabled,
    )
    synced: dict[str, list[str]] = {}
    if not payload.byo_customer_override_enabled:
        # Overrides off: every customer goes back to the ISP-level sender.
        for row in (
            await db.execute(
                select(IspCustomerMessaging).where(
                    IspCustomerMessaging.customer_organization_id.in_(
                        await isp.repository.child_ids(isp.isp_org_id)
                    ),
                    IspCustomerMessaging.is_deleted.is_(False),
                    IspCustomerMessaging.own_sender.is_(True),
                )
            )
        ).scalars():
            row.own_sender = False
            row.updated_by = actor_id
        synced = await sync_sender_to_all(db, isp, actor_id)
    db.add(
        AuditLogEntry(
            actor_user_id=actor_id,
            action="isp_messaging_settings_set",
            entity_type="isp_partner",
            entity_id=isp.isp_org_id,
            organization_id=isp.isp_org_id,
            description="Messaging settings updated",
            event_metadata=payload.model_dump(),
        )
    )
    await db.commit()
    return ok(request, {**payload.model_dump(), "synced": synced})


class CustomerSenderUpdate(BaseModel):
    own_sender: bool


@isp_parity_router.put(
    "/customers/{isp_customer_id}/messaging", dependencies=isp_guards(ISP_ENGAGE_MANAGE)
)
async def put_customer_sender(
    request: Request,
    isp_customer_id: uuid.UUID,
    payload: CustomerSenderUpdate,
    isp: IspContext = Depends(RequireIspPartner),
    actor: AuthUser = Depends(CurrentUser),
    db: AsyncSession = Depends(get_db_session),
):
    customer = await IspScope.assert_customer(isp, isp_customer_id)
    if (
        payload.own_sender
        and not (await get_parity_setting(db, isp.isp_org_id))[
            "byo_customer_override_enabled"
        ]
    ):
        raise IspOverrideNotEnabledError()
    actor_id = uuid.UUID(str(actor.id))
    row = (
        await db.execute(
            select(IspCustomerMessaging).where(
                IspCustomerMessaging.customer_organization_id == customer.id,
                IspCustomerMessaging.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = IspCustomerMessaging(
            customer_organization_id=customer.id, created_by=actor_id
        )
        db.add(row)
    row.own_sender = payload.own_sender
    row.updated_by = actor_id
    await db.flush()
    synced: list[str] = []
    if not payload.own_sender:
        synced = await sync_sender_to_customer(
            db,
            isp_org_id=isp.isp_org_id,
            customer_org_id=customer.id,
            actor_user_id=actor_id,
        )
    await db.commit()
    return ok(
        request,
        {
            "isp_customer_id": str(customer.id),
            "own_sender": payload.own_sender,
            "synced": synced,
        },
    )


@isp_parity_router.get(
    "/customers/{isp_customer_id}/messaging", dependencies=isp_guards(ISP_ENGAGE_READ)
)
async def get_customer_sender(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
):
    customer = await IspScope.assert_customer(isp, isp_customer_id)
    return ok(
        request,
        {
            "isp_customer_id": str(customer.id),
            "own_sender": await own_sender(db, customer.id),
            "override_allowed": (await get_parity_setting(db, isp.isp_org_id))[
                "byo_customer_override_enabled"
            ],
        },
    )


# ---------------------------------------------------------------------------
# Master routes (GLOBAL-pinned, mounted on /platform/isp-partners)
# ---------------------------------------------------------------------------

parity_platform_router = APIRouter(tags=["ISP Partners (Master): settings & wallet"])


async def _require_isp(db: AsyncSession, isp_partner_id: uuid.UUID) -> None:
    found = (
        await db.execute(
            select(IspPartnerProfile.id).where(
                IspPartnerProfile.organization_id == isp_partner_id,
                IspPartnerProfile.is_deleted.is_(False),
            )
        )
    ).first()
    if found is None:
        raise IspPartnerNotFoundError()


async def _children(db: AsyncSession, isp_partner_id: uuid.UUID) -> list[uuid.UUID]:
    from .repository import IspRepository

    return await IspRepository(db).child_ids(isp_partner_id)


@parity_platform_router.get(
    "/{isp_partner_id}/parity-settings",
    dependencies=[
        Depends(RequirePermission("organizations.read", scope=ScopeType.GLOBAL))
    ],
)
async def get_isp_parity_settings(
    request: Request,
    isp_partner_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
):
    await _require_isp(db, isp_partner_id)
    return ok(
        request,
        {
            "isp_partner_id": str(isp_partner_id),
            **await get_parity_setting(db, isp_partner_id),
        },
    )


class ParitySettingsUpdate(BaseModel):
    pii_unmask_enabled: bool


@parity_platform_router.put(
    "/{isp_partner_id}/parity-settings",
    dependencies=[
        Depends(RequirePermission("organizations.manage", scope=ScopeType.GLOBAL))
    ],
)
async def put_isp_parity_settings(
    request: Request,
    isp_partner_id: uuid.UUID,
    payload: ParitySettingsUpdate,
    actor: AuthUser = Depends(CurrentUser),
    db: AsyncSession = Depends(get_db_session),
):
    await _require_isp(db, isp_partner_id)
    actor_id = uuid.UUID(str(actor.id))
    await _upsert_setting(
        db, isp_partner_id, actor_id, pii_unmask_enabled=payload.pii_unmask_enabled
    )
    db.add(
        AuditLogEntry(
            actor_user_id=actor_id,
            action="isp_pii_unmask_set",
            entity_type="isp_partner",
            entity_id=isp_partner_id,
            organization_id=isp_partner_id,
            description=(
                "Master "
                + ("enabled" if payload.pii_unmask_enabled else "disabled")
                + " unmasked guest identifiers for this ISP's owner/admin"
            ),
            event_metadata=payload.model_dump(),
        )
    )
    await db.commit()
    return ok(
        request,
        {
            "isp_partner_id": str(isp_partner_id),
            **await get_parity_setting(db, isp_partner_id),
        },
    )


@parity_platform_router.get(
    "/{isp_partner_id}/wallet",
    dependencies=[
        Depends(RequirePermission("organizations.read", scope=ScopeType.GLOBAL))
    ],
)
async def get_isp_wallet_master(
    request: Request,
    isp_partner_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
):
    await _require_isp(db, isp_partner_id)
    view = await _wallet_view(db, isp_partner_id, await _children(db, isp_partner_id))
    return ok(request, {"isp_partner_id": str(isp_partner_id), **view})


class WalletTopupRequest(BaseModel):
    amount_minor: int = Field(..., gt=0, le=10_000_000_00)
    reference: str | None = Field(default=None, max_length=120)
    note: str | None = Field(default=None, max_length=500)
    #: Same key = same top-up (a double click does not credit twice).
    idempotency_key: str = Field(..., min_length=8, max_length=80)


@parity_platform_router.post(
    "/{isp_partner_id}/wallet/topups",
    status_code=201,
    dependencies=[
        Depends(RequirePermission("organizations.manage", scope=ScopeType.GLOBAL))
    ],
)
async def topup_isp_wallet(
    request: Request,
    isp_partner_id: uuid.UUID,
    payload: WalletTopupRequest,
    actor: AuthUser = Depends(CurrentUser),
    db: AsyncSession = Depends(get_db_session),
):
    """Master credits the ISP's ONE messaging wallet (cash received offline;
    no invoice is generated here)."""
    await _require_isp(db, isp_partner_id)
    actor_id = uuid.UUID(str(actor.id))
    write = await _wallets(db).topup(
        isp_partner_id,
        payload.amount_minor,
        idempotency_key=f"isp-topup:{payload.idempotency_key}",
        actor_user_id=actor_id,
        reference=payload.reference,
        note=payload.note or "ISP messaging wallet top-up (Master)",
    )
    db.add(
        AuditLogEntry(
            actor_user_id=actor_id,
            action="isp_wallet_topup",
            entity_type="isp_partner",
            entity_id=isp_partner_id,
            organization_id=isp_partner_id,
            description=f"ISP messaging wallet top-up: {payload.amount_minor} minor",
            event_metadata=json.loads(payload.model_dump_json()),
        )
    )
    await db.commit()
    view = await _wallet_view(db, isp_partner_id, await _children(db, isp_partner_id))
    return ok(request, {"created": bool(getattr(write, "created", True)), **view})
