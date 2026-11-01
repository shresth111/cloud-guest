# ruff: noqa: E501 -- scenario test
"""APPS-2 #5 integrations status on real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN``). Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55441/integ \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56381/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \\
    python -m pytest tests/unit/test_isp_integrations_postgres.py

ISP A has a WhatsApp sender, Telegram token + chat, J14 sends (sent and
failed) and an ACS credential; ISP B has nothing. A's cards show A's rows,
B's cards show nothing (no leak across ISPs), and no secret comes back.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_integrations_status_end_to_end() -> None:
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.finance_models import (
        IspAutomationSettings,
        IspMessageLog,
    )
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.marketing.models import OrgMarketingProvider
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.domains.tr069.models import Tr069AcsCredential
    from app.main import create_app

    tag = uuid.uuid4().hex[:8]
    now = datetime.now(UTC)
    async with SessionLocal() as s:
        await seed_rbac(s)
        await seed_isp_partner_rbac(RBACRepository(s))
        await s.commit()
    users, isps = {}, {}
    async with SessionLocal() as s:
        plan = Plan(
            name=f"P {tag}",
            slug=f"pint-{tag}",
            plan_type="standard",
            billing_cycle="monthly",
            base_price=Decimal("0"),
            currency="INR",
            is_active=True,
            is_public=False,
        )
        s.add(plan)
        owner = (
            await s.execute(select(Role).where(Role.slug == "isp-owner"))
        ).scalar_one()
        for n in ("A", "B"):
            org = Organization(
                name=f"Int {n} {tag}",
                slug=f"intnet{n.lower()}{tag}",
                org_type="msp",
                status="active",
                contact_email=f"i{n}{tag}@example.com",
                timezone="Asia/Kolkata",
                settings={},
            )
            user = User(
                first_name=n,
                last_name="T",
                email=f"int{n.lower()}{tag}@example.com",
                username=f"int{n.lower()}{tag}",
                password_hash="x",
                is_active=True,
                is_verified=True,
            )
            s.add_all([org, user])
            await s.flush()
            s.add(
                IspPartnerProfile(
                    organization_id=org.id, default_customer_plan_id=plan.id
                )
            )
            s.add_all(
                [
                    OrganizationMember(
                        organization_id=org.id, user_id=user.id, status="active"
                    ),
                    UserRole(
                        user_id=user.id,
                        role_id=owner.id,
                        scope_type="organization",
                        organization_id=org.id,
                        granted_at=now,
                        is_active=True,
                    ),
                ]
            )
            users[n], isps[n] = user.id, org.id
        a = isps["A"]
        s.add(
            OrgMarketingProvider(
                organization_id=a,
                channel="whatsapp",
                provider_type="meta_cloud",
                config_encrypted="CIPHERTEXT-SECRET",
                display={},
                status="verified",
                enabled=True,
                last_verified_at=now,
            )
        )
        s.add(
            IspAutomationSettings(
                isp_organization_id=a,
                telegram_enabled=True,
                telegram_bot_token_encrypted="TOKEN-SECRET",
                telegram_bot_token_hint="…abcd",
                telegram_chat_id="-100999",
            )
        )

        def log(channel: str, status: str, at: datetime) -> IspMessageLog:
            row = IspMessageLog(
                isp_organization_id=a,
                channel=channel,
                trigger="router_down",
                recipient_masked="***",
                summary="t",
                status=status,
            )
            row.created_at = at
            return row

        s.add_all(
            [
                log("telegram", "sent", now - timedelta(hours=2)),
                log("telegram", "sent", now - timedelta(hours=1)),
                log("telegram", "failed", now - timedelta(minutes=5)),
                log("whatsapp", "failed", now - timedelta(minutes=9)),
                log("whatsapp", "skipped", now),
            ]
        )
        s.add(
            Tr069AcsCredential(
                isp_organization_id=a,
                username=f"acs-{tag}",
                password_hash="h",
                password_encrypted="ACS-SECRET",
                enabled=True,
            )
        )
        await s.commit()

    app = create_app()
    state = {"user": users["A"]}
    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(state["user"]), email="o@example.com"
    )
    url = "/api/v1/isp/integrations/status"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as c:
        r = await c.get(url, headers={"X-Organization-Id": str(isps["A"])})
        assert r.status_code == 200, r.text
        body = r.text
        for secret in (
            "CIPHERTEXT-SECRET",
            "TOKEN-SECRET",
            "abcd",
            "-100999",
            "ACS-SECRET",
        ):
            assert secret not in body, secret
        cards = r.json()["data"]["cards"]
        assert set(cards) == {
            "whatsapp",
            "email",
            "telegram",
            "acs",
            "payment_gateway",
            "ipdr_archive",
        }
        wa = cards["whatsapp"]
        assert wa["configured"] and wa["status"] == "verified"
        assert wa["last_sent_at"] is None  # only a failure (and a skip) recorded
        assert wa["last_failed_at"] is not None
        assert cards["email"]["configured"] is False
        tg = cards["telegram"]
        assert tg["configured"] and tg["bot_token_set"] and tg["chat_id_set"]
        assert datetime.fromisoformat(tg["last_sent_at"]) > now - timedelta(
            hours=1, minutes=1
        )
        assert datetime.fromisoformat(tg["last_failed_at"]) > now - timedelta(minutes=6)
        assert cards["acs"]["configured"] and cards["acs"]["enabled_credentials"] == 1
        assert cards["acs"]["devices"] == 0 and cards["acs"]["last_inform_at"] is None
        assert cards["payment_gateway"]["state"] == "coming_soon"
        assert cards["ipdr_archive"]["exports_offsite"] == "not_set_up"
        assert cards["ipdr_archive"]["last_built_at"] is None  # no customers yet
        assert cards["telegram"]["link"] == "/partner/finance?tab=automation"

        state["user"] = users["B"]
        r = await c.get(url, headers={"X-Organization-Id": str(isps["B"])})
        assert r.status_code == 200, r.text
        cards = r.json()["data"]["cards"]
        assert not cards["whatsapp"]["configured"]
        assert cards["whatsapp"]["last_failed_at"] is None
        assert not cards["telegram"]["configured"]
        assert cards["telegram"]["last_sent_at"] is None
        assert not cards["acs"]["configured"] and cards["acs"]["credentials"] == 0

        # B's owner asking with A's org header is refused.
        r = await c.get(url, headers={"X-Organization-Id": str(isps["A"])})
        assert r.status_code in (403, 404), r.text
