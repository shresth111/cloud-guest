"""APPS-2 #5: ``GET /isp/integrations/status`` -- one read-only status card per
external integration the ISP console already has, composed from rows other
lanes already write. Nothing here configures, probes or calls out: a card
reports what the database (and the process settings) already record, and
``None`` where nothing is recorded.

* ``whatsapp`` / ``email`` -- the ISP-level BYO sender (``org_marketing_providers``
  of the ISP organization, F3) plus, for WhatsApp, the J14 automation sends in
  ``isp_message_log``.
* ``telegram`` -- J14 alerts: bot token set, chat id set, last sent / failed.
* ``acs`` -- TR-069: the platform flag, the ISP's ACS credentials, devices and
  the newest inform.
* ``payment_gateway`` -- always ``coming_soon`` (Phase 1c is not built).
* ``ipdr_archive`` -- where IPDR day files of this ISP's customers are written
  (``s3`` = the Object-Locked off-site bucket, ``local`` = the app host) and the
  newest one built. NAT / IPDR *exports* have no off-site copy, so that is
  reported as ``not_set_up``.

No secret, hint, chat id or bucket name is returned.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .constants import ISP_PARTNER_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok

integrations_router = APIRouter(tags=["ISP Partner: integrations status"])

#: Where each card's existing configuration screen lives in the console.
LINKS = {
    "whatsapp": "/partner/messaging",
    "email": "/partner/messaging",
    "telegram": "/partner/finance?tab=automation",
    "acs": "/partner/settings",
    "ipdr_archive": "/partner/compliance",
}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def provider_card(row: Any, log: dict[str, datetime | None] | None = None) -> dict:
    """``row`` is the ISP organization's own ``OrgMarketingProvider`` (or None)."""
    card: dict[str, Any] = {
        "state": "configured" if row is not None else "not_configured",
        "configured": row is not None,
        "enabled": bool(row is not None and row.enabled),
        "provider_type": row.provider_type if row is not None else None,
        "status": row.status if row is not None else None,
        "last_verified_at": _iso(row.last_verified_at) if row is not None else None,
        "last_error": row.last_error if row is not None else None,
    }
    if log is not None:
        card["last_sent_at"] = _iso(log.get("sent"))
        card["last_failed_at"] = _iso(log.get("failed"))
    return card


def telegram_card(st: Any, log: dict[str, datetime | None], flag_on: bool) -> dict:
    token = bool(st is not None and st.telegram_bot_token_encrypted)
    chat = bool(st is not None and st.telegram_chat_id)
    return {
        "state": "configured" if token and chat else "not_configured",
        "configured": token and chat,
        "enabled": bool(st is not None and st.telegram_enabled),
        "feature_enabled": flag_on,
        "bot_token_set": token,
        "chat_id_set": chat,
        "last_sent_at": _iso(log.get("sent")),
        "last_failed_at": _iso(log.get("failed")),
    }


def acs_card(
    flag_on: bool,
    credentials: int,
    enabled_credentials: int,
    devices: int,
    last_inform: datetime | None,
) -> dict:
    return {
        "state": "configured" if enabled_credentials else "not_configured",
        "configured": enabled_credentials > 0,
        "feature_enabled": flag_on,
        "credentials": credentials,
        "enabled_credentials": enabled_credentials,
        "devices": devices,
        "last_inform_at": _iso(last_inform),
    }


def ipdr_card(store: str, last_built: datetime | None, last_built_s3: datetime | None):
    return {
        "state": "configured" if store == "s3" else "not_set_up",
        "configured": store == "s3",
        "store": store,
        "last_built_at": _iso(last_built),
        "last_offsite_built_at": _iso(last_built_s3),
        "exports_offsite": "not_set_up",
    }


async def _log_times(
    db: AsyncSession, isp_org_id: uuid.UUID, channel: str
) -> dict[str, datetime | None]:
    from .finance_models import IspMessageLog as L

    rows = (
        await db.execute(
            select(L.status, func.max(L.created_at))
            .where(
                L.isp_organization_id == isp_org_id,
                L.channel == channel,
                L.status.in_(("sent", "failed")),
                L.is_deleted.is_(False),
            )
            .group_by(L.status)
        )
    ).all()
    return {status: at for status, at in rows}


@integrations_router.get(
    "/integrations/status", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def integrations_status(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from app.core.config import get_settings
    from app.domains.ipdr.constants import STORE_LOCAL, STORE_S3
    from app.domains.ipdr.models import IpdrDayFile
    from app.domains.marketing.models import OrgMarketingProvider as P
    from app.domains.tr069.config import get_tr069_settings
    from app.domains.tr069.models import Tr069AcsCredential as C
    from app.domains.tr069.models import Tr069Device as D

    from .automation import automation_settings
    from .finance_config import get_finance_settings

    providers = {
        row.channel: row
        for row in (
            await db.execute(
                select(P).where(
                    P.organization_id == isp.isp_org_id,
                    P.channel.in_(("whatsapp", "email")),
                    P.is_deleted.is_(False),
                )
            )
        ).scalars()
    }
    st = await automation_settings(db, isp.isp_org_id)
    fin = get_finance_settings()

    cred_total, cred_enabled = (
        await db.execute(
            select(
                func.count(C.id),
                func.count(C.id).filter(C.enabled.is_(True)),
            ).where(C.isp_organization_id == isp.isp_org_id, C.is_deleted.is_(False))
        )
    ).one()
    dev_q = select(func.count(D.id), func.max(D.last_inform_at)).where(
        D.isp_organization_id == isp.isp_org_id, D.is_deleted.is_(False)
    )
    if isp.confined_customer_ids is not None:
        dev_q = dev_q.where(D.customer_organization_id.in_(await isp.child_ids()))
    devices, last_inform = (await db.execute(dev_q)).one()

    settings = get_settings()
    store = STORE_S3 if (settings.ipdr_archive_bucket or "").strip() else STORE_LOCAL
    org_ids = await isp.child_ids()
    last_built = last_s3 = None
    if org_ids:
        last_built, last_s3 = (
            await db.execute(
                select(
                    func.max(IpdrDayFile.built_at),
                    func.max(IpdrDayFile.built_at).filter(
                        IpdrDayFile.store == STORE_S3
                    ),
                ).where(IpdrDayFile.organization_id.in_(org_ids))
            )
        ).one()

    whatsapp = provider_card(
        providers.get("whatsapp"), await _log_times(db, isp.isp_org_id, "whatsapp")
    )
    whatsapp["automation_enabled"] = bool(st is not None and st.whatsapp_enabled)
    whatsapp["automation_feature_enabled"] = fin.whatsapp_automation_enabled
    cards = {
        "whatsapp": whatsapp,
        "email": provider_card(providers.get("email")),
        "telegram": telegram_card(
            st,
            await _log_times(db, isp.isp_org_id, "telegram"),
            fin.telegram_alerts_enabled,
        ),
        "acs": acs_card(
            get_tr069_settings().enabled,
            int(cred_total or 0),
            int(cred_enabled or 0),
            int(devices or 0),
            last_inform,
        ),
        "payment_gateway": {"state": "coming_soon", "configured": False},
        "ipdr_archive": ipdr_card(store, last_built, last_s3),
    }
    for key, card in cards.items():
        card["link"] = LINKS.get(key)
    return ok(request, {"cards": cards}, "Integrations status")


__all__ = [
    "integrations_router",
    "provider_card",
    "telegram_card",
    "acs_card",
    "ipdr_card",
]
