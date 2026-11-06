"""Security detection rules against a real Postgres.

Every rule is raw SQL (recursive CTEs, ``~`` regex, ``ANY(:list)``, JSONB
``->>``, ``make_interval``), so a fake proves nothing. Gated on
``CLOUDGUEST_TEST_POSTGRES_URL`` like ``test_marketing_credits_postgres.py``:

    createdb secdetect_test
    export CLOUDGUEST_TEST_POSTGRES_URL=postgresql+asyncpg://localhost/secdetect_test
    python -m pytest tests/unit/test_security_detections_postgres.py

Each test gets a throwaway schema holding minimal stubs of the tables the
rules read (only the columns they use) plus the real ``platform_events``
table from its model. ``test_stub_columns_exist_on_models`` (no database
needed) pins every stub column to a real model column, so a rename on a
model fails here instead of in production.

Per rule: one dataset that must produce the hit, one that must not.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.domains.auth.models  # noqa: F401
import app.domains.billing.models  # noqa: F401
import app.domains.guest.models  # noqa: F401
import app.domains.location.models  # noqa: F401
import app.domains.organization.models  # noqa: F401
import app.domains.otp.models  # noqa: F401
import app.domains.rbac.models  # noqa: F401
import app.domains.router.models  # noqa: F401
import app.domains.voucher.models  # noqa: F401
from app.core.config import Settings
from app.database.base import Base
from app.domains.monitoring import security_detections as sd
from app.domains.monitoring.models import PlatformEvent

_PG_URL = os.environ.get("CLOUDGUEST_TEST_POSTGRES_URL")
requires_pg = pytest.mark.skipif(
    not _PG_URL, reason="CLOUDGUEST_TEST_POSTGRES_URL not set"
)

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
WINDOW = sd.DetectionWindow(since=NOW - timedelta(minutes=10), now=NOW)
CFG = sd.Thresholds()
RECENT = NOW - timedelta(minutes=2)

# table -> [(column, type)] -- only what the rules read.
_STUBS: dict[str, list[tuple[str, str]]] = {
    "organizations": [("id", "uuid PRIMARY KEY")],
    "locations": [("id", "uuid PRIMARY KEY")],
    "users": [("id", "uuid PRIMARY KEY"), ("email", "varchar(255)")],
    "routers": [
        ("id", "uuid PRIMARY KEY"),
        ("organization_id", "uuid"),
        ("location_id", "uuid"),
    ],
    "roles": [
        ("id", "uuid PRIMARY KEY"),
        ("slug", "varchar(150) NOT NULL"),
        ("scope_type", "varchar(20) NOT NULL"),
        ("organization_id", "uuid"),
        ("parent_role_id", "uuid"),
        ("is_system_role", "boolean NOT NULL DEFAULT false"),
        ("is_deleted", "boolean NOT NULL DEFAULT false"),
        ("created_by", "uuid"),
        ("updated_by", "uuid"),
        ("created_at", "timestamptz NOT NULL"),
        ("updated_at", "timestamptz NOT NULL"),
    ],
    "role_scopes": [
        ("id", "uuid PRIMARY KEY"),
        ("role_id", "uuid NOT NULL"),
        ("scope_type", "varchar(20) NOT NULL"),
        ("is_deleted", "boolean NOT NULL DEFAULT false"),
        ("created_at", "timestamptz NOT NULL"),
    ],
    "permissions": [("id", "uuid PRIMARY KEY"), ("key", "varchar(150) NOT NULL")],
    "role_permissions": [
        ("id", "uuid PRIMARY KEY"),
        ("role_id", "uuid NOT NULL"),
        ("permission_id", "uuid NOT NULL"),
        ("granted_by", "uuid"),
        ("is_deleted", "boolean NOT NULL DEFAULT false"),
        ("created_at", "timestamptz NOT NULL"),
    ],
    "user_roles": [
        ("id", "uuid PRIMARY KEY"),
        ("user_id", "uuid NOT NULL"),
        ("role_id", "uuid NOT NULL"),
        ("scope_type", "varchar(20) NOT NULL"),
        ("is_active", "boolean NOT NULL DEFAULT true"),
        ("is_deleted", "boolean NOT NULL DEFAULT false"),
        ("expires_at", "timestamptz"),
    ],
    "permission_overrides": [
        ("id", "uuid PRIMARY KEY"),
        ("user_id", "uuid NOT NULL"),
        ("permission_id", "uuid NOT NULL"),
        ("effect", "varchar(10) NOT NULL"),
        ("organization_id", "uuid"),
        ("granted_by", "uuid"),
        ("is_active", "boolean NOT NULL DEFAULT true"),
        ("is_deleted", "boolean NOT NULL DEFAULT false"),
        ("created_at", "timestamptz NOT NULL"),
    ],
    "audit_log_entries": [
        ("id", "uuid PRIMARY KEY"),
        ("actor_user_id", "uuid"),
        ("action", "varchar(50) NOT NULL"),
        ("entity_type", "varchar(50) NOT NULL"),
        ("entity_id", "uuid"),
        ("metadata", "jsonb NOT NULL DEFAULT '{}'"),
        ("organization_id", "uuid"),
        ("location_id", "uuid"),
        ("created_at", "timestamptz NOT NULL"),
    ],
    "otp_requests": [
        ("id", "uuid PRIMARY KEY"),
        ("identifier", "varchar(255) NOT NULL"),
        ("channel", "varchar(20) NOT NULL"),
        ("organization_id", "uuid"),
        ("location_id", "uuid"),
        ("verified_at", "timestamptz"),
        ("created_at", "timestamptz NOT NULL"),
    ],
    "voucher_batches": [
        ("id", "uuid PRIMARY KEY"),
        ("organization_id", "uuid NOT NULL"),
        ("location_id", "uuid"),
    ],
    "vouchers": [
        ("id", "uuid PRIMARY KEY"),
        ("organization_id", "uuid NOT NULL"),
        ("batch_id", "uuid NOT NULL"),
    ],
    "guest_sessions": [
        ("id", "uuid PRIMARY KEY"),
        ("organization_id", "uuid NOT NULL"),
        ("location_id", "uuid NOT NULL"),
        ("router_id", "uuid NOT NULL"),
        ("voucher_id", "uuid"),
        ("created_at", "timestamptz NOT NULL"),
    ],
    "payments": [
        ("id", "uuid PRIMARY KEY"),
        ("organization_id", "uuid NOT NULL"),
        ("status", "varchar(20) NOT NULL"),
        ("is_deleted", "boolean NOT NULL DEFAULT false"),
        ("created_at", "timestamptz NOT NULL"),
        ("updated_at", "timestamptz NOT NULL"),
    ],
    "login_attempts": [
        ("id", "uuid PRIMARY KEY"),
        ("email", "varchar(255) NOT NULL"),
        ("success", "boolean NOT NULL DEFAULT false"),
        ("created_at", "timestamptz NOT NULL"),
    ],
}


def test_stub_columns_exist_on_models() -> None:
    """Runs without Postgres: every stub column is a real model column."""
    for table, columns in _STUBS.items():
        model_columns = set(Base.metadata.tables[table].c.keys())
        missing = {name for name, _ in columns} - model_columns
        assert not missing, f"{table}: {missing}"


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
async def engine():
    schema = f"secdet_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(_PG_URL, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        _PG_URL, connect_args={"server_settings": {"search_path": schema}}
    )
    try:
        async with engine.begin() as conn:
            for table, columns in _STUBS.items():
                cols = ", ".join(f"{name} {kind}" for name, kind in columns)
                await conn.execute(text(f"CREATE TABLE {table} ({cols})"))
            await conn.run_sync(
                lambda sync: Base.metadata.create_all(
                    sync, tables=[PlatformEvent.__table__]
                )
            )
        yield engine
    finally:
        await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


@pytest.fixture
def session_factory(engine):
    return async_sessionmaker(engine, expire_on_commit=False)


class World:
    """Seeds rows with sensible defaults. ``ids`` names the fixed actors."""

    def __init__(self, factory) -> None:
        self.factory = factory
        self.org = uuid.uuid4()
        self.org_b = uuid.uuid4()
        self.loc = uuid.uuid4()
        self.loc_b = uuid.uuid4()
        self.router = uuid.uuid4()
        self.operator = uuid.uuid4()
        self.tenant = uuid.uuid4()
        self.msp_user = uuid.uuid4()
        self.super_admin_role = uuid.uuid4()
        self.org_owner_role = uuid.uuid4()
        self.org_admin_role = uuid.uuid4()
        self.msp_owner_role = uuid.uuid4()
        self.perms: dict[str, uuid.UUID] = {}

    async def sql(self, statement: str, **params) -> None:
        async with self.factory() as session:
            await session.execute(text(statement), params)
            await session.commit()

    async def seed_base(self) -> None:
        for org in (self.org, self.org_b):
            await self.sql("INSERT INTO organizations VALUES (:id)", id=org)
        for loc in (self.loc, self.loc_b):
            await self.sql("INSERT INTO locations VALUES (:id)", id=loc)
        await self.sql(
            "INSERT INTO routers VALUES (:id, :org, :loc)",
            id=self.router,
            org=self.org,
            loc=self.loc,
        )
        for user, email in (
            (self.operator, "ops.person@wyfyguest.com"),
            (self.tenant, "tenant.admin@cafe.example"),
            (self.msp_user, "msp.owner@partner.example"),
        ):
            await self.sql("INSERT INTO users VALUES (:id, :e)", id=user, e=email)
        old = NOW - timedelta(days=30)
        await self.role(self.super_admin_role, "super-admin", "global", None, True, old)
        await self.role(
            self.org_owner_role, "organization-owner", "organization", None, True, old
        )
        await self.role(
            self.org_admin_role, "organization-admin", "organization", None, True, old
        )
        await self.role(
            self.msp_owner_role, "msp-owner", "organization", None, True, old
        )
        await self.user_role(self.operator, self.super_admin_role, "global")
        await self.user_role(self.tenant, self.org_owner_role, "organization")
        await self.user_role(self.msp_user, self.msp_owner_role, "organization")
        for key in (
            "routers.read",
            "guests.read",
            "quotations.read",
            "users.impersonate",
        ):
            self.perms[key] = uuid.uuid4()
            await self.sql(
                "INSERT INTO permissions VALUES (:id, :k)", id=self.perms[key], k=key
            )
        for key in ("routers.read", "guests.read"):
            await self.grant(self.org_owner_role, key, at=old)

    async def role(
        self,
        role_id,
        slug,
        scope,
        org,
        system=False,
        at=RECENT,
        parent=None,
        created_by=None,
    ) -> None:
        await self.sql(
            "INSERT INTO roles (id, slug, scope_type, organization_id, "
            "parent_role_id, is_system_role, created_by, created_at, updated_at) "
            "VALUES (:id, :slug, :scope, :org, :parent, :sys, :cb, :at, :at)",
            id=role_id,
            slug=slug,
            scope=scope,
            org=org,
            parent=parent,
            sys=system,
            cb=created_by,
            at=at,
        )

    async def user_role(self, user, role, scope) -> None:
        await self.sql(
            "INSERT INTO user_roles (id, user_id, role_id, scope_type) "
            "VALUES (:id, :u, :r, :s)",
            id=uuid.uuid4(),
            u=user,
            r=role,
            s=scope,
        )

    async def grant(self, role, key, at=RECENT, by=None) -> None:
        await self.sql(
            "INSERT INTO role_permissions (id, role_id, permission_id, granted_by, "
            "created_at) VALUES (:id, :r, :p, :by, :at)",
            id=uuid.uuid4(),
            r=role,
            p=self.perms[key],
            by=by,
            at=at,
        )

    async def audit(
        self,
        action,
        actor=None,
        *,
        entity_type="x",
        entity_id=None,
        metadata="{}",
        org=None,
        loc=None,
        at=RECENT,
    ) -> None:
        await self.sql(
            "INSERT INTO audit_log_entries (id, actor_user_id, action, entity_type, "
            "entity_id, metadata, organization_id, location_id, created_at) "
            "VALUES (:id, :a, :act, :et, :eid, CAST(:m AS jsonb), :org, :loc, :at)",
            id=uuid.uuid4(),
            a=actor,
            act=action,
            et=entity_type,
            eid=entity_id or uuid.uuid4(),
            m=metadata,
            org=org,
            loc=loc,
            at=at,
        )

    async def otps(
        self,
        count,
        *,
        channel="sms",
        org=None,
        loc=None,
        verified=False,
        start=NOW - timedelta(minutes=50),
    ) -> None:
        await self.sql(
            "INSERT INTO otp_requests (id, identifier, channel, organization_id, "
            "location_id, verified_at, created_at) "
            "SELECT gen_random_uuid(), '+9198765' || lpad(g::text, 5, '0'), :ch, "
            ":org, :loc, CASE WHEN :v THEN CAST(:start AS timestamptz) END, "
            "CAST(:start AS timestamptz) + (g * interval '1 second') "
            "FROM generate_series(1, :n) AS g",
            ch=channel,
            org=org,
            loc=loc,
            v=verified,
            start=start,
            n=count,
        )

    async def voucher_session(self, *, session_org, voucher_org, batch_loc=None):
        batch, voucher = uuid.uuid4(), uuid.uuid4()
        await self.sql(
            "INSERT INTO voucher_batches VALUES (:id, :org, :loc)",
            id=batch,
            org=voucher_org,
            loc=batch_loc,
        )
        await self.sql(
            "INSERT INTO vouchers VALUES (:id, :org, :b)",
            id=voucher,
            org=voucher_org,
            b=batch,
        )
        await self.session(org=session_org, voucher=voucher)

    async def session(self, *, org=None, loc=None, voucher=None, at=RECENT) -> None:
        await self.sql(
            "INSERT INTO guest_sessions VALUES (:id, :org, :loc, :r, :v, :at)",
            id=uuid.uuid4(),
            org=org or self.org,
            loc=loc or self.loc,
            r=self.router,
            v=voucher,
            at=at,
        )


@pytest.fixture
async def world(session_factory) -> World:
    w = World(session_factory)
    await w.seed_base()
    return w


async def run(world: World, rule, window=WINDOW, cfg=CFG):
    async with world.factory() as session:
        return await rule(session, window, cfg)


# ============================================================================
# P1: RBAC
# ============================================================================


@requires_pg
class TestTenantRolePlatformKey:
    async def test_platform_key_on_tenant_role_hits(self, world: World) -> None:
        role = uuid.uuid4()
        await world.role(role, "my-role", "organization", world.org)
        await world.grant(role, "quotations.read", by=world.tenant)
        hits = await run(world, sd.rule_tenant_role_platform_key)
        assert [h.details["permission_key"] for h in hits] == ["quotations.read"]
        assert hits[0].priority == sd.P1
        assert hits[0].organization_id == str(world.org)
        assert hits[0].details["granted_by"] == "t****n@cafe.example"

    async def test_owner_held_key_and_old_grant_are_clean(self, world: World) -> None:
        role = uuid.uuid4()
        await world.role(role, "my-role", "organization", world.org)
        await world.grant(role, "routers.read")
        await world.grant(role, "quotations.read", at=NOW - timedelta(hours=2))
        assert await run(world, sd.rule_tenant_role_platform_key) == []


@requires_pg
class TestTenantRoleGlobalScope:
    async def test_global_scope_hits(self, world: World) -> None:
        role = uuid.uuid4()
        await world.role(role, "sneaky", "global", world.org)
        hits = await run(world, sd.rule_tenant_role_global_scope)
        assert [h.details["role_id"] for h in hits] == [str(role)]

    async def test_allowed_global_scope_hits(self, world: World) -> None:
        role = uuid.uuid4()
        await world.role(role, "sneaky", "organization", world.org)
        await world.sql(
            "INSERT INTO role_scopes VALUES (:id, :r, 'global', false, :at)",
            id=uuid.uuid4(),
            r=role,
            at=RECENT,
        )
        assert len(await run(world, sd.rule_tenant_role_global_scope)) == 1

    async def test_operator_custom_global_role_is_clean(self, world: World) -> None:
        await world.role(
            uuid.uuid4(), "ops-role", "global", None, created_by=world.operator
        )
        await world.role(uuid.uuid4(), "fine", "organization", world.org)
        assert await run(world, sd.rule_tenant_role_global_scope) == []


@requires_pg
class TestTenantRoleInheritsPlatformRole:
    async def test_parent_chain_to_super_admin_hits(self, world: World) -> None:
        middle, leaf = uuid.uuid4(), uuid.uuid4()
        old = NOW - timedelta(days=3)
        await world.role(
            middle,
            "mid",
            "organization",
            world.org,
            at=old,
            parent=world.super_admin_role,
        )
        await world.role(leaf, "leaf", "organization", world.org, parent=middle)
        hits = await run(world, sd.rule_tenant_role_inherits_platform_role)
        assert [(h.details["role_id"], h.details["ancestor_slug"]) for h in hits] == [
            (str(leaf), "super-admin")
        ]

    async def test_parent_tenant_system_role_is_clean(self, world: World) -> None:
        await world.role(
            uuid.uuid4(), "leaf", "organization", world.org, parent=world.org_admin_role
        )
        assert await run(world, sd.rule_tenant_role_inherits_platform_role) == []


@requires_pg
class TestTenantOverridePlatformKey:
    async def _override(self, world: World, user) -> None:
        await world.sql(
            "INSERT INTO permission_overrides (id, user_id, permission_id, effect, "
            "organization_id, created_at) VALUES (:id, :u, :p, 'allow', :o, :at)",
            id=uuid.uuid4(),
            u=user,
            p=world.perms["users.impersonate"],
            o=world.org,
            at=RECENT,
        )

    async def test_tenant_user_hits(self, world: World) -> None:
        await self._override(world, world.tenant)
        hits = await run(world, sd.rule_tenant_override_platform_key)
        assert len(hits) == 1
        assert hits[0].details["user"] == "t****n@cafe.example"

    async def test_operator_is_clean(self, world: World) -> None:
        await self._override(world, world.operator)
        assert await run(world, sd.rule_tenant_override_platform_key) == []


# ============================================================================
# P1: platform actions
# ============================================================================


@requires_pg
class TestCredentialReveal:
    async def test_tenant_reveal_hits(self, world: World) -> None:
        await world.audit(
            "router_credentials_revealed",
            world.tenant,
            entity_id=world.router,
            org=world.org,
        )
        hits = await run(world, sd.rule_credential_reveal_by_non_operator)
        assert [h.details["router_id"] for h in hits] == [str(world.router)]
        assert "tenant.admin@cafe.example" not in hits[0].message

    async def test_operator_and_impersonating_operator_are_clean(
        self, world: World
    ) -> None:
        await world.audit("router_credentials_revealed", world.operator)
        await world.audit(
            "router_credentials_revealed",
            world.tenant,
            metadata=f'{{"impersonator_user_id": "{world.operator}"}}',
        )
        await world.audit("router_viewed", world.tenant)
        assert await run(world, sd.rule_credential_reveal_by_non_operator) == []


@requires_pg
class TestPlatformActionByTenant:
    async def test_tenant_license_activation_hits(self, world: World) -> None:
        await world.audit("license_activated", world.tenant, org=world.org)
        await world.audit("device_console_command_executed", world.tenant)
        hits = await run(world, sd.rule_platform_action_by_tenant)
        assert sorted(h.details["action"] for h in hits) == [
            "device_console_command_executed",
            "license_activated",
        ]

    async def test_operator_system_and_msp_org_create_are_clean(
        self, world: World
    ) -> None:
        await world.audit("license_activated", world.operator)
        await world.audit("license_activated", None)
        await world.audit("organization_created", world.msp_user)
        await world.audit("role_updated", world.tenant)
        assert await run(world, sd.rule_platform_action_by_tenant) == []


# ============================================================================
# P1: OTP volume
# ============================================================================


@requires_pg
class TestOtpSmsVolume:
    async def test_over_hourly_cap_hits(self, world: World) -> None:
        await world.otps(301, org=world.org, loc=world.loc)
        hits = await run(world, sd.rule_otp_sms_volume)
        assert len(hits) == 1
        assert hits[0].details["last_hour"] == 301

    async def test_over_baseline_hits(self, world: World) -> None:
        for day in range(1, 8):
            await world.otps(
                5,
                org=world.org,
                loc=world.loc,
                start=NOW - timedelta(days=day, minutes=50),
            )
        await world.otps(40, org=world.org, loc=world.loc)
        hits = await run(world, sd.rule_otp_sms_volume)
        assert hits[0].details["baseline_hourly_avg"] == 5.0

    async def test_normal_volume_is_clean(self, world: World) -> None:
        for day in range(1, 8):
            await world.otps(
                30, org=world.org, start=NOW - timedelta(days=day, minutes=50)
            )
        await world.otps(60, org=world.org, loc=world.loc)
        await world.otps(400, channel="email", org=world.org)
        assert await run(world, sd.rule_otp_sms_volume) == []


@requires_pg
class TestOtpVenuelessVolume:
    async def test_over_threshold_hits(self, world: World) -> None:
        await world.otps(21)
        hits = await run(world, sd.rule_otp_venueless_volume)
        assert hits[0].details["last_hour"] == 21
        assert "+91" not in hits[0].message

    async def test_at_threshold_is_clean(self, world: World) -> None:
        await world.otps(20)
        await world.otps(50, org=world.org)
        assert await run(world, sd.rule_otp_venueless_volume) == []


# ============================================================================
# P1: billing
# ============================================================================


@requires_pg
class TestBillingWebhookUnmatched:
    async def test_unmatched_payment_event_hits(self, world: World) -> None:
        await world.audit(
            "billing_webhook_received",
            entity_type="webhook_event",
            metadata='{"provider": "razorpay", "event_type": "payment.captured"}',
        )
        hits = await run(world, sd.rule_billing_webhook_unmatched)
        assert hits[0].details["event_type"] == "payment.captured"

    async def test_matched_or_unhandled_events_are_clean(self, world: World) -> None:
        await world.audit(
            "billing_webhook_received",
            entity_type="payment",
            metadata='{"provider": "razorpay", "event_type": "payment.captured"}',
        )
        await world.audit(
            "billing_webhook_received",
            entity_type="webhook_event",
            metadata='{"provider": "stripe", "event_type": "customer.created"}',
        )
        assert await run(world, sd.rule_billing_webhook_unmatched) == []


@requires_pg
class TestLicenseActivatedWithoutPayment:
    async def test_no_payment_hits(self, world: World) -> None:
        await world.audit("license_activated", None, org=world.org)
        hits = await run(world, sd.rule_license_activated_without_payment)
        assert hits[0].organization_id == str(world.org)

    async def test_succeeded_payment_is_clean(self, world: World) -> None:
        await world.sql(
            "INSERT INTO payments (id, organization_id, status, created_at, updated_at)"
            " VALUES (:id, :o, 'succeeded', :c, :u)",
            id=uuid.uuid4(),
            o=world.org,
            c=NOW - timedelta(minutes=30),
            u=RECENT,
        )
        await world.audit("license_activated", None, org=world.org)
        assert await run(world, sd.rule_license_activated_without_payment) == []


# ============================================================================
# P1: vouchers
# ============================================================================


@requires_pg
class TestVoucherCrossTenant:
    async def test_cross_org_hits_p1(self, world: World) -> None:
        await world.voucher_session(session_org=world.org, voucher_org=world.org_b)
        hits = await run(world, sd.rule_voucher_cross_tenant)
        assert [(h.rule, h.priority) for h in hits] == [("voucher_cross_org", sd.P1)]
        assert hits[0].severity == "critical"

    async def test_cross_venue_hits_p2(self, world: World) -> None:
        await world.voucher_session(
            session_org=world.org, voucher_org=world.org, batch_loc=world.loc_b
        )
        hits = await run(world, sd.rule_voucher_cross_tenant)
        assert [(h.rule, h.priority) for h in hits] == [("voucher_cross_venue", sd.P2)]

    async def test_same_venue_is_clean(self, world: World) -> None:
        await world.voucher_session(
            session_org=world.org, voucher_org=world.org, batch_loc=world.loc
        )
        await world.voucher_session(session_org=world.org, voucher_org=world.org)
        await world.session()
        assert await run(world, sd.rule_voucher_cross_tenant) == []


# ============================================================================
# P2 / P3
# ============================================================================


@requires_pg
class TestP2Rules:
    async def test_role_self_assigned(self, world: World) -> None:
        await world.audit(
            "role_assigned",
            world.tenant,
            metadata=f'{{"target_user_id": "{world.operator}", "role_id": "r"}}',
        )
        assert await run(world, sd.rule_role_self_assigned) == []
        await world.audit(
            "role_assigned",
            world.tenant,
            metadata=f'{{"target_user_id": "{world.tenant}", "role_id": "r"}}',
        )
        assert len(await run(world, sd.rule_role_self_assigned)) == 1

    async def test_session_router_venue_mismatch(self, world: World) -> None:
        await world.session()
        assert await run(world, sd.rule_session_router_venue_mismatch) == []
        await world.session(loc=world.loc_b)
        hits = await run(world, sd.rule_session_router_venue_mismatch)
        assert hits[0].details["session_location_id"] == str(world.loc_b)

    async def test_otp_venue_volume(self, world: World) -> None:
        await world.otps(100, org=world.org, loc=world.loc)
        assert await run(world, sd.rule_otp_venue_volume) == []
        await world.otps(1, org=world.org, loc=world.loc)
        hits = await run(world, sd.rule_otp_venue_volume)
        assert hits[0].details["location_id"] == str(world.loc)

    async def test_otp_verify_ratio(self, world: World) -> None:
        await world.otps(20, org=world.org, verified=True)
        await world.otps(30, org=world.org)
        assert await run(world, sd.rule_otp_verify_ratio) == []  # 40% verified
        await world.otps(60, org=world.org)
        assert len(await run(world, sd.rule_otp_verify_ratio)) == 1

    async def test_billing_webhook_rejections(self, world: World) -> None:
        for _ in range(4):
            await world.audit("billing_webhook_rejected")
        assert await run(world, sd.rule_billing_webhook_rejections) == []
        await world.audit("billing_webhook_rejected")
        assert len(await run(world, sd.rule_billing_webhook_rejections)) == 1

    async def test_dashboard_login_bruteforce(self, world: World) -> None:
        async def fails(email: str, n: int) -> None:
            await world.sql(
                "INSERT INTO login_attempts (id, email, created_at) "
                "SELECT gen_random_uuid(), :e, :at FROM generate_series(1, :n)",
                e=email,
                at=RECENT,
                n=n,
            )

        await fails("victim.person@example.com", 20)
        assert await run(world, sd.rule_dashboard_login_bruteforce) == []
        await fails("victim.person@example.com", 1)
        hits = await run(world, sd.rule_dashboard_login_bruteforce)
        assert [h.rule for h in hits] == ["dashboard_login_bruteforce"]
        assert hits[0].details["account"] == "v****n@example.com"
        assert "victim.person" not in hits[0].message
        for i in range(11):
            await fails(f"user{i}@example.com", 3)
        rules = {h.rule for h in await run(world, sd.rule_dashboard_login_bruteforce)}
        assert rules == {"dashboard_login_bruteforce", "dashboard_login_stuffing"}

    async def test_voucher_guessing(self, world: World) -> None:
        for _ in range(30):
            await world.audit("voucher_redemption_failed", loc=world.loc)
        assert await run(world, sd.rule_voucher_guessing) == []
        await world.audit("voucher_redemption_failed", loc=world.loc)
        assert len(await run(world, sd.rule_voucher_guessing)) == 1

    async def test_otp_guessing(self, world: World) -> None:
        otp = uuid.uuid4()
        for _ in range(10):
            await world.audit("otp_verification_failed", entity_id=otp)
        assert await run(world, sd.rule_otp_guessing) == []
        await world.audit("otp_verification_failed", entity_id=otp)
        assert len(await run(world, sd.rule_otp_guessing)) == 1


# ============================================================================
# The whole sweep: platform_events + email + dedup, real DB
# ============================================================================


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def get(self, key: str):
        return self.store.get(key)

    async def set(self, key: str, value: str, *, nx: bool = False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def delete(self, *keys: str) -> int:
        return sum(self.store.pop(k, None) is not None for k in keys)


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        **{
            name: info.default
            for name, info in Settings.model_fields.items()
            if name.startswith("security_detection_")
        }
    )


class EmailSpy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, subject: str, body: str) -> int:
        self.calls.append((subject, body))
        return 1


async def _security_events(factory) -> list[PlatformEvent]:
    from sqlalchemy import select

    async with factory() as session:
        result = await session.execute(select(PlatformEvent))
        return list(result.scalars().all())


@requires_pg
class TestSweepEndToEnd:
    async def test_hits_write_events_email_once_and_dedup(self, world: World) -> None:
        role = uuid.uuid4()
        await world.role(role, "my-role", "organization", world.org)
        await world.grant(role, "quotations.read")
        await world.otps(21)
        await world.sql(
            "INSERT INTO login_attempts (id, email, created_at) "
            "SELECT gen_random_uuid(), 'victim.person@example.com', :at "
            "FROM generate_series(1, 25)",
            at=RECENT,
        )
        redis, email = FakeRedis(), EmailSpy()

        result = await sd.run_security_detection_sweep(
            session_factory=world.factory,
            redis=redis,
            settings=_settings(),
            send_email=email,
            now=NOW,
        )

        assert result.rule_errors == {}
        assert result.rules_run == len(sd.RULES)
        events = await _security_events(world.factory)
        assert sorted(e.event_type for e in events) == [
            "security.dashboard_login_bruteforce",
            "security.otp_venueless_volume",
            "security.tenant_role_platform_key",
        ]
        assert {e.category for e in events} == {"security"}
        assert {e.organization_id for e in events} == {None}
        role_event = next(e for e in events if e.event_type.endswith("platform_key"))
        assert role_event.severity == "critical"
        assert role_event.event_metadata["organization_id"] == str(world.org)

        assert len(email.calls) == 1
        subject, body = email.calls[0]
        assert subject.startswith("[Wyfy security] P1: 3 new detections")
        assert "victim.person@example.com" not in body
        assert "v****n@example.com" in body
        assert "+9198765" not in body

        again = await sd.run_security_detection_sweep(
            session_factory=world.factory,
            redis=redis,
            settings=_settings(),
            send_email=email,
            now=NOW + timedelta(minutes=5),
        )
        assert again.hits >= 2 and again.new_hits == 0
        assert len(await _security_events(world.factory)) == 3
        assert len(email.calls) == 1

    async def test_clean_dataset_writes_nothing(self, world: World) -> None:
        role = uuid.uuid4()
        await world.role(role, "my-role", "organization", world.org)
        await world.grant(role, "routers.read")
        await world.otps(10, org=world.org, loc=world.loc, verified=True)
        await world.session()
        email = EmailSpy()
        result = await sd.run_security_detection_sweep(
            session_factory=world.factory,
            redis=FakeRedis(),
            settings=_settings(),
            send_email=email,
            now=NOW,
        )
        assert result.rule_errors == {}
        assert result.hits == 0
        assert await _security_events(world.factory) == []
        assert email.calls == []

    async def test_statement_timeout_cancels_a_slow_rule_only(
        self, world: World
    ) -> None:
        async def slow(session, window, cfg):
            await session.execute(text("SELECT pg_sleep(2)"))
            return []

        settings = _settings()
        settings.security_detection_statement_timeout_ms = 100
        result = await sd.run_security_detection_sweep(
            session_factory=world.factory,
            redis=FakeRedis(),
            settings=settings,
            send_email=EmailSpy(),
            rules=(
                sd.DetectionRule("slow", slow),
                sd.DetectionRule("otp_venueless_volume", sd.rule_otp_venueless_volume),
            ),
            now=NOW,
        )
        assert set(result.rule_errors) == {"slow"}
        assert result.rules_run == 1

    async def test_rule_transaction_is_read_only(self, world: World) -> None:
        async def writer(session, window, cfg):
            await session.execute(text("DELETE FROM users"))
            return []

        result = await sd.run_security_detection_sweep(
            session_factory=world.factory,
            redis=FakeRedis(),
            settings=_settings(),
            send_email=EmailSpy(),
            rules=(sd.DetectionRule("writer", writer),),
            now=NOW,
        )
        assert set(result.rule_errors) == {"writer"}
        async with world.factory() as session:
            count = (await session.execute(text("SELECT count(*) FROM users"))).scalar()
        assert count == 3
