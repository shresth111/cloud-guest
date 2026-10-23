"""Master ISP-partner endpoints (TASKS FS-1, API_CONTRACT §3).

Three altitudes for the GLOBAL pin (memory: permission scope-inference trap):

1. the mounted routes: every route carries ``RequirePermission(<key>,
   scope=ScopeType.GLOBAL)`` (deleting a ``scope=`` fails this file);
2. ``ScopeResolver``: an ORGANIZATION or LOCATION grant cannot satisfy GLOBAL;
3. ``AccessValidator.has_permission``, the engine the dependency calls, and
   the HTTP stack end to end: an ISP owner, an MSP Owner and an Organization
   Owner each get 403 on ``POST /platform/isp-partners`` (BE-T #10).

Plus the service invariants: the ISP is always a top-level MSP, the owner
lands in the ISP org with ``isp-owner`` and ``must_change_password``, create
is one transaction (nothing commits; a late failure rolls everything back),
and suspend/activate disables/re-enables exactly the ACS credentials it
should.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.domains.auth.models  # noqa: F401  (FK targets for the mappers)
import app.domains.organization.models  # noqa: F401
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.auth.service import EmailAlreadyExistsError
from app.domains.billing.exceptions import PlanNotFoundError
from app.domains.isp_partner import config as isp_config
from app.domains.isp_partner.config import RequireIspFeatureEnabled
from app.domains.isp_partner.exceptions import (
    IspPartnerNotFoundError,
    IspSlugTakenError,
    IspUserNotFoundError,
    UserEmailTakenError,
)
from app.domains.isp_partner.models import IspPartnerProfile
from app.domains.isp_partner.platform_repository import Counts, OwnerRow, PartnerPage
from app.domains.isp_partner.platform_router import (
    PLATFORM_ROUTE_PERMISSIONS,
    get_isp_partner_platform_service,
    isp_partner_platform_router,
)
from app.domains.isp_partner.platform_schemas import (
    IspOwnerRequest,
    IspPartnerCreateRequest,
    IspPartnerUpdateRequest,
)
from app.domains.isp_partner.platform_service import (
    AUDIT_ISP_PARTNER_CREATED,
    IspPartnerPlatformService,
    IspPlanNotFoundError,
    generate_temporary_password,
)
from app.domains.organization.enums import OrganizationStatus, OrganizationType
from app.domains.organization.exceptions import DuplicateSlugError
from app.domains.rbac.authorization import (
    AccessValidator,
    EffectiveGrant,
    EffectiveGrants,
    GrantScope,
    ScopeContext,
    ScopeResolver,
)
from app.domains.rbac.dependencies import get_access_validator, get_current_user
from app.domains.rbac.enums import ScopeType

SCOPE_ALIASES = {"organization_id", "customer_id", "location_id", "router_id"}


# =============================================================================
# 1. Structure of the mounted routes
# =============================================================================
def _closure_values(route) -> list[Any]:
    out: list[Any] = []
    for dep in route.dependant.dependencies:
        for cell in getattr(dep.call, "__closure__", None) or ():
            out.append(cell.cell_contents)
    return out


def _routes():
    return [r for r in isp_partner_platform_router.routes if hasattr(r, "dependant")]


class TestRouteStructure:
    def test_routes_match_the_contract_table(self) -> None:
        mounted = {
            (m, r.path.removeprefix("/platform/isp-partners"))
            for r in _routes()
            for m in r.methods
        }
        assert mounted == set(PLATFORM_ROUTE_PERMISSIONS)
        assert len(mounted) == 10  # +2 ADDENDUM_04 B6 add-on allowance (PARITY-2)

    @pytest.mark.parametrize(
        "route", _routes(), ids=lambda r: f"{sorted(r.methods)}{r.path}"
    )
    def test_every_route_pins_its_permission_to_global(self, route) -> None:
        values = _closure_values(route)
        assert ScopeType.GLOBAL in values, (
            f"{route.path} must pass scope=ScopeType.GLOBAL; without it the "
            "caller's own headers pick the scope its permission is checked at."
        )
        method = next(iter(route.methods))
        key = PLATFORM_ROUTE_PERMISSIONS[
            (method, route.path.removeprefix("/platform/isp-partners"))
        ]
        assert key in values
        assert key.startswith("organizations.")

    @pytest.mark.parametrize(
        "route", _routes(), ids=lambda r: f"{sorted(r.methods)}{r.path}"
    )
    def test_feature_flag_runs_first_and_no_scope_alias_params(self, route) -> None:
        first = route.dependant.dependencies[0].call
        assert first is RequireIspFeatureEnabled
        names = {
            p.name for p in route.dependant.path_params + route.dependant.query_params
        }
        assert not (names & SCOPE_ALIASES), names

    def test_router_never_uses_require_organization(self) -> None:
        for route in _routes():
            for dep in route.dependant.dependencies:
                assert "RequireOrganization" not in getattr(
                    dep.call, "__qualname__", ""
                )


# =============================================================================
# 2. + 3. ScopeResolver and AccessValidator
# =============================================================================
class _StubValidator(AccessValidator):
    def __init__(self, grants: EffectiveGrants) -> None:
        self._grants = grants
        self.cache = None
        self.denial_audit_repository = None
        self.scope_resolver = ScopeResolver()

    async def get_effective_grants(self, _user_id: uuid.UUID) -> EffectiveGrants:
        return self._grants


def _grants(keys: list[str], scope: GrantScope) -> EffectiveGrants:
    return EffectiveGrants(
        allow=tuple(
            EffectiveGrant(permission_key=k, effect="allow", scope=scope, source="test")
            for k in keys
        ),
        deny=(),
    )


ALL_KEYS = sorted(set(PLATFORM_ROUTE_PERMISSIONS.values()))
ORG = uuid.uuid4()


class TestScopeResolver:
    def test_narrower_grants_never_satisfy_global(self) -> None:
        ctx = ScopeContext(organization_id=ORG)
        org_grant = GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=ORG)
        loc_grant = GrantScope(scope_type=ScopeType.LOCATION, location_id=uuid.uuid4())
        assert ScopeResolver.satisfies(org_grant, ScopeType.GLOBAL, ctx) is False
        assert ScopeResolver.satisfies(loc_grant, ScopeType.GLOBAL, ctx) is False
        assert (
            ScopeResolver.satisfies(
                GrantScope(scope_type=ScopeType.GLOBAL), ScopeType.GLOBAL, ctx
            )
            is True
        )


class TestAccessValidator:
    @pytest.mark.parametrize("key", ALL_KEYS)
    async def test_org_scoped_grant_is_refused_at_global(self, key: str) -> None:
        """MSP Owner / Organization Owner hold organizations.* at
        ORGANIZATION scope; that is not permission to manage ISPs."""
        v = _StubValidator(
            _grants(
                [key],
                GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=ORG),
            )
        )
        assert (
            await v.has_permission(
                uuid.uuid4(),
                key,
                scope_type=ScopeType.GLOBAL,
                scope_context=ScopeContext(organization_id=ORG),
            )
            is False
        )

    @pytest.mark.parametrize("key", ALL_KEYS)
    async def test_global_grant_passes(self, key: str) -> None:
        v = _StubValidator(_grants([key], GrantScope(scope_type=ScopeType.GLOBAL)))
        assert (
            await v.has_permission(
                uuid.uuid4(),
                key,
                scope_type=ScopeType.GLOBAL,
                scope_context=ScopeContext.global_scope(),
            )
            is True
        )


# =============================================================================
# HTTP stack: flag, 403 for every non-platform caller, 201 for Master
# =============================================================================
class _RecordingService:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def create_partner(self, **kwargs: Any):
        self.calls.append("create")
        from app.domains.isp_partner.platform_schemas import (
            IspOwnerCredentialResponse,
            IspPartnerCounts,
            IspPartnerCreateResponse,
            IspPartnerResponse,
        )

        now = datetime.now(UTC)
        return IspPartnerCreateResponse(
            isp_partner=IspPartnerResponse(
                id=ORG,
                name="Airlink",
                slug="airlink",
                legal_name=None,
                gstin=None,
                status="active",
                org_status="active",
                contact_email="ops@airlink.in",
                contact_phone=None,
                support_phone=None,
                support_email=None,
                timezone="Asia/Kolkata",
                default_customer_plan=None,
                max_customers=None,
                counts=IspPartnerCounts(),
                created_at=now,
                suspended_at=None,
                suspended_reason=None,
            ),
            owner=IspOwnerCredentialResponse(
                user_id=uuid.uuid4(),
                username="ravi@airlink.in",
                email="ravi@airlink.in",
                temporary_password="x",
                login_url="https://network.wyfyguest.com",
            ),
        )


def _create_body() -> dict[str, Any]:
    return {
        "name": "Airlink Broadband",
        "slug": "airlink-broadband",
        "contact_email": "ops@airlink.in",
        "default_customer_plan_id": str(uuid.uuid4()),
        "owner": {
            "first_name": "Ravi",
            "last_name": "Kumar",
            "email": "ravi@airlink.in",
        },
    }


@pytest.fixture
def make_client(monkeypatch):
    from app.main import create_app

    def _make(*, enabled: bool, grants: EffectiveGrants, service: _RecordingService):
        monkeypatch.setattr(
            isp_config,
            "get_isp_partner_settings",
            lambda: isp_config.IspPartnerSettings(enabled=enabled),
        )
        app: FastAPI = create_app()
        app.include_router(isp_partner_platform_router, prefix="/api/v1")
        user = AuthUser(id=str(uuid.uuid4()), email="x@y.z")

        async def _db():
            yield SimpleNamespace()

        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[get_access_validator] = lambda: _StubValidator(grants)
        app.dependency_overrides[get_db_session] = _db
        app.dependency_overrides[get_isp_partner_platform_service] = lambda: service
        return TestClient(app, raise_server_exceptions=False)

    return _make


ISP_OWNER_GRANTS = _grants(
    ["isp_partner.read", "isp_partner.create", "isp_partner.assign", "tr069.manage"],
    GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=ORG),
)
ORG_OWNER_GRANTS = _grants(
    [
        "organizations.read",
        "organizations.create",
        "organizations.update",
        "organizations.manage",
    ],
    GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=ORG),
)
SUPER_ADMIN_GRANTS = _grants(ALL_KEYS, GrantScope(scope_type=ScopeType.GLOBAL))


class TestHttp:
    def test_flag_off_is_404_even_for_super_admin(self, make_client) -> None:
        svc = _RecordingService()
        client = make_client(enabled=False, grants=SUPER_ADMIN_GRANTS, service=svc)
        r = client.post("/api/v1/platform/isp-partners", json=_create_body())
        assert r.status_code == 404
        assert svc.calls == []

    @pytest.mark.parametrize(
        "grants,headers",
        [
            (ISP_OWNER_GRANTS, {"X-Organization-Id": str(ORG)}),  # an ISP user
            (
                ORG_OWNER_GRANTS,
                {"X-Organization-Id": str(ORG)},
            ),  # MSP / Organization Owner
            (ORG_OWNER_GRANTS, {}),
        ],
        ids=["isp-owner", "org-owner-with-header", "org-owner-no-header"],
    )
    def test_non_platform_callers_get_403_and_nothing_runs(
        self, make_client, grants, headers
    ) -> None:
        svc = _RecordingService()
        client = make_client(enabled=True, grants=grants, service=svc)
        r = client.post(
            "/api/v1/platform/isp-partners", json=_create_body(), headers=headers
        )
        assert r.status_code == 403, r.text
        assert svc.calls == []

    def test_super_admin_creates(self, make_client) -> None:
        svc = _RecordingService()
        client = make_client(enabled=True, grants=SUPER_ADMIN_GRANTS, service=svc)
        r = client.post("/api/v1/platform/isp-partners", json=_create_body())
        assert r.status_code == 201, r.text
        assert r.json()["data"]["owner"]["temporary_password"] == "x"
        assert svc.calls == ["create"]

    @pytest.mark.parametrize(
        "extra",
        [
            {"org_type": "standard"},
            {"parent_organization_id": str(uuid.uuid4())},
            {"organization_id": str(uuid.uuid4())},
        ],
    )
    def test_body_cannot_name_org_type_or_parent(self, make_client, extra) -> None:
        svc = _RecordingService()
        client = make_client(enabled=True, grants=SUPER_ADMIN_GRANTS, service=svc)
        r = client.post(
            "/api/v1/platform/isp-partners", json={**_create_body(), **extra}
        )
        assert r.status_code == 422
        assert svc.calls == []


def test_patch_cannot_change_slug() -> None:
    with pytest.raises(ValueError):
        IspPartnerUpdateRequest.model_validate({"slug": "other"})


# =============================================================================
# Service invariants (fakes; every collaborator is an existing service)
# =============================================================================
class FakeSession:
    def __init__(self) -> None:
        self.added: list[Any] = []
        self.commits = 0

    def add(self, obj: Any) -> None:
        if getattr(obj, "id", None) is None:
            obj.id = uuid.uuid4()
        self.added.append(obj)

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:  # pragma: no cover - must never be called
        self.commits += 1


class FakeRepo:
    def __init__(self) -> None:
        self.session = FakeSession()
        self.partners: dict[uuid.UUID, tuple[IspPartnerProfile, Any]] = {}
        self.enabled_ids: list[uuid.UUID] = []
        self.set_calls: list[tuple[list[uuid.UUID], bool]] = []
        self.suspension_meta: dict | None = None
        self.isp_cred = None

    async def get(self, isp_org_id):
        return self.partners.get(isp_org_id)

    async def list(self, **kwargs):
        rows = list(self.partners.values())
        return PartnerPage(rows=rows, total=len(rows), page=1, page_size=25)

    async def counts(self, ids):
        return {i: Counts(customers=2) for i in ids}

    async def plan_names(self, ids):
        return {i: "Starter" for i in ids if i}

    async def owners(self, isp_org_id):
        return [
            OwnerRow(
                user_id=uuid.uuid4(),
                name="Ravi Kumar",
                email="ravi@airlink.in",
                is_active=True,
            )
        ]

    async def isp_credential(self, isp_org_id):
        return self.isp_cred

    async def enabled_credential_ids(self, isp_org_id):
        return list(self.enabled_ids)

    async def set_credentials_enabled(self, isp_org_id, ids, enabled, *, actor_user_id):
        self.set_calls.append((list(ids), enabled))
        return len(ids)

    async def last_suspension_metadata(self, isp_org_id):
        return self.suspension_meta


def _org(**over: Any) -> SimpleNamespace:
    base = dict(
        id=uuid.uuid4(),
        name="Airlink Broadband",
        slug="airlink-broadband",
        legal_name=None,
        status=OrganizationStatus.ACTIVE.value,
        contact_email="ops@airlink.in",
        contact_phone=None,
        timezone="Asia/Kolkata",
        created_at=datetime.now(UTC),
        org_type=OrganizationType.MSP.value,
        parent_organization_id=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


class FakeOrgService:
    def __init__(self, fail_slug: bool = False) -> None:
        self.created: list[dict] = []
        self.status_calls: list[tuple[str, dict]] = []
        self.fail_slug = fail_slug

    async def create_organization(self, **kw):
        if self.fail_slug:
            raise DuplicateSlugError(kw["slug"])
        self.created.append(kw)
        return _org(name=kw["name"], slug=kw["slug"], timezone=kw["timezone"])

    async def update_organization(self, **kw):
        return _org(id=kw["organization_id"], **{k: v for k, v in kw["data"].items()})

    async def suspend_organization(self, **kw):
        self.status_calls.append(("suspend", kw))
        return _org(id=kw["organization_id"], status=OrganizationStatus.SUSPENDED.value)

    async def activate_organization(self, **kw):
        self.status_calls.append(("activate", kw))
        return _org(id=kw["organization_id"])


class FakeUserService:
    def __init__(self, fail: Exception | None = None) -> None:
        self.created: list[dict] = []
        self.logouts: list[dict] = []
        self.fail = fail

    async def create_user(self, **kw):
        if self.fail:
            raise self.fail
        self.created.append(kw)
        return SimpleNamespace(
            id=uuid.uuid4(),
            email=kw["email"],
            first_name=kw["first_name"],
            username=kw["username"],
        )

    async def force_logout_user(self, **kw):
        self.logouts.append(kw)
        return None


class FakeIdentity:
    def __init__(self) -> None:
        self.updates: list[dict] = []
        self.users: dict[uuid.UUID, Any] = {}

    async def update_user(self, user, **fields):
        self.updates.append(fields)
        for k, v in fields.items():
            setattr(user, k, v)
        return user

    async def get_user_by_id(self, user_id):
        return self.users.get(user_id)


class FakeRbac:
    def __init__(self, seeded: bool = True, audit_fails: bool = False) -> None:
        self.role = (
            SimpleNamespace(id=uuid.uuid4(), slug="isp-owner", organization_id=None)
            if seeded
            else None
        )
        self.audits: list[dict] = []
        self.role_rows: list[dict] = []
        self.audit_fails = audit_fails

    async def create_user_role(self, **fields):
        self.role_rows.append(fields)

    async def get_role_by_slug(self, slug, organization_id):
        assert slug == "isp-owner" and organization_id is None
        return self.role

    async def create_audit_log_entry(self, **fields):
        if self.audit_fails:
            raise RuntimeError("audit write failed")
        self.audits.append(fields)


class FakePlans:
    def __init__(self, missing: bool = False) -> None:
        self.missing = missing

    async def get_plan(self, plan_id):
        if self.missing:
            raise PlanNotFoundError(plan_id)
        return SimpleNamespace(id=plan_id, name="Starter")


class FakeCreds:
    def __init__(self) -> None:
        self.ensured: list[tuple] = []

    async def ensure(self, isp, customer, **kw):
        self.ensured.append((isp, customer, kw))
        return SimpleNamespace(username="isp-deadbeef", enabled=True)


class FakeRoles:
    def __init__(self, slugs: list[str] | None = None) -> None:
        self.slugs = slugs or []

    async def isp_role_assignments(self, isp_org_id, *, user_id=None):
        return [(SimpleNamespace(), SimpleNamespace(slug=s)) for s in self.slugs]


class FakeNotify:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def enqueue(self, **kw):
        self.sent.append(kw)


def _service(**over: Any) -> tuple[IspPartnerPlatformService, SimpleNamespace]:
    parts = SimpleNamespace(
        repo=over.get("repo", FakeRepo()),
        orgs=over.get("orgs", FakeOrgService()),
        users=over.get("users", FakeUserService()),
        identity=over.get("identity", FakeIdentity()),
        rbac=over.get("rbac", FakeRbac()),
        plans=over.get("plans", FakePlans()),
        creds=over.get("creds", FakeCreds()),
        roles=over.get("roles", FakeRoles()),
        notify=over.get("notify", FakeNotify()),
    )
    svc = IspPartnerPlatformService(
        parts.repo,
        parts.orgs,
        parts.users,
        parts.identity,
        parts.rbac,
        parts.plans,
        parts.creds,
        parts.roles,
        parts.notify,
        login_url="https://network-staging.wyfyguest.com/",
    )
    return svc, parts


def _create_request(**over: Any) -> IspPartnerCreateRequest:
    body = _create_body()
    body.update(over)
    return IspPartnerCreateRequest.model_validate(body)


ACTOR = uuid.uuid4()


class TestCreate:
    async def test_creates_a_top_level_msp_with_an_isp_owner(self) -> None:
        svc, p = _service()
        result = await svc.create_partner(actor_user_id=ACTOR, data=_create_request())

        (org_call,) = p.orgs.created
        assert org_call["org_type"] is OrganizationType.MSP
        assert org_call["parent_organization_id"] is None

        profiles = [o for o in p.repo.session.added if isinstance(o, IspPartnerProfile)]
        assert len(profiles) == 1 and profiles[0].status == "active"

        (isp_id, customer, kw) = p.creds.ensured[0]
        assert customer is None and kw["enabled"] is True

        (user_call,) = p.users.created
        assert user_call["organization_id"] == result.isp_partner.id
        # initial_role_id would run RBACService.assign_role_to_user, whose
        # escalation guard refuses isp-owner for a Super Admin (staging E2E,
        # 2026-10-22); the role row is written directly instead.
        assert user_call["initial_role_id"] is None
        (role_row,) = p.rbac.role_rows
        assert role_row["role_id"] == p.rbac.role.id
        assert role_row["organization_id"] == result.isp_partner.id
        assert role_row["scope_type"] == "organization"
        assert role_row["is_active"] is True
        assert user_call["requesting_organization_id"] is None
        assert {"must_change_password": True} in p.identity.updates

        assert [a["action"] for a in p.rbac.audits] == [AUDIT_ISP_PARTNER_CREATED]
        assert result.owner.temporary_password
        assert result.owner.login_url == "https://network-staging.wyfyguest.com"
        assert (
            len(p.notify.sent) == 1
            and p.notify.sent[0]["recipient"] == "ravi@airlink.in"
        )
        assert p.repo.session.commits == 0

    async def test_no_welcome_when_not_asked(self) -> None:
        svc, p = _service()
        body = _create_body()
        body["owner"]["send_welcome_email"] = False
        await svc.create_partner(
            actor_user_id=ACTOR, data=IspPartnerCreateRequest.model_validate(body)
        )
        assert p.notify.sent == []

    async def test_slug_taken_maps_to_isp_slug_taken(self) -> None:
        svc, _ = _service(orgs=FakeOrgService(fail_slug=True))
        with pytest.raises(IspSlugTakenError) as exc:
            await svc.create_partner(actor_user_id=ACTOR, data=_create_request())
        assert (
            exc.value.status_code == 409 and exc.value.data["code"] == "ISP_SLUG_TAKEN"
        )

    async def test_email_taken_maps_to_user_email_taken(self) -> None:
        svc, _ = _service(
            users=FakeUserService(fail=EmailAlreadyExistsError("ravi@airlink.in"))
        )
        with pytest.raises(UserEmailTakenError) as exc:
            await svc.create_partner(actor_user_id=ACTOR, data=_create_request())
        assert exc.value.status_code == 409

    async def test_missing_plan_is_422_before_any_write(self) -> None:
        svc, p = _service(plans=FakePlans(missing=True))
        with pytest.raises(IspPlanNotFoundError) as exc:
            await svc.create_partner(actor_user_id=ACTOR, data=_create_request())
        assert (
            exc.value.status_code == 422 and exc.value.data["code"] == "PLAN_NOT_FOUND"
        )
        assert p.orgs.created == [] and p.repo.session.added == []

    async def test_late_failure_rolls_the_whole_request_back(self, monkeypatch) -> None:
        """Forced failure AFTER the owner exists (the audit write). The
        service never commits; ``get_db_session`` then rolls back the one
        session every step wrote through, so no org, profile or user remains."""
        import app.database.session as session_module

        events: list[str] = []

        class _Session(FakeSession):
            async def commit(self) -> None:
                events.append("commit")

            async def rollback(self) -> None:
                events.append("rollback")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

        monkeypatch.setattr(session_module, "SessionLocal", lambda: _Session())
        gen = session_module.get_db_session()
        session = await gen.__anext__()

        repo = FakeRepo()
        repo.session = session
        svc, p = _service(repo=repo, rbac=FakeRbac(audit_fails=True))
        with pytest.raises(RuntimeError):
            try:
                await svc.create_partner(actor_user_id=ACTOR, data=_create_request())
            except RuntimeError as exc:
                await gen.athrow(exc)
        assert p.users.created, "the owner was created before the failure"
        assert events == ["rollback"]


class TestSuspendActivate:
    def _seed(self, repo: FakeRepo, *, status: str = "active") -> uuid.UUID:
        org = _org(
            status=OrganizationStatus.SUSPENDED.value
            if status == "suspended"
            else "active"
        )
        profile = IspPartnerProfile(
            organization_id=org.id, status=status, default_customer_plan_id=uuid.uuid4()
        )
        repo.partners[org.id] = (profile, org)
        return org.id

    async def test_suspend_disables_every_enabled_credential_and_records_them(
        self,
    ) -> None:
        repo = FakeRepo()
        isp = self._seed(repo)
        repo.enabled_ids = [uuid.uuid4(), uuid.uuid4()]
        svc, p = _service(repo=repo)
        view = await svc.suspend_partner(
            actor_user_id=ACTOR, isp_org_id=isp, reason="unpaid"
        )
        assert view.status == "suspended" and view.suspended_reason == "unpaid"
        assert repo.set_calls == [(repo.enabled_ids, False)]
        assert p.orgs.status_calls[0][0] == "suspend"
        assert p.orgs.status_calls[0][1]["requesting_organization_id"] is None
        meta = p.rbac.audits[-1]["event_metadata"]
        assert meta["disabled_credential_ids"] == [str(i) for i in repo.enabled_ids]

    async def test_activate_reenables_exactly_what_suspend_disabled_plus_isp_cred(
        self,
    ) -> None:
        repo = FakeRepo()
        isp = self._seed(repo, status="suspended")
        disabled = [uuid.uuid4()]
        repo.suspension_meta = {"disabled_credential_ids": [str(i) for i in disabled]}
        repo.isp_cred = SimpleNamespace(
            id=uuid.uuid4(), username="isp-1", enabled=False
        )
        svc, p = _service(repo=repo)
        view = await svc.activate_partner(actor_user_id=ACTOR, isp_org_id=isp)
        assert view.status == "active" and view.suspended_at is None
        assert repo.set_calls == [([*disabled, repo.isp_cred.id], True)]
        assert p.orgs.status_calls[0][0] == "activate"

    async def test_unknown_partner_is_404(self) -> None:
        svc, _ = _service()
        with pytest.raises(IspPartnerNotFoundError) as exc:
            await svc.suspend_partner(
                actor_user_id=ACTOR, isp_org_id=uuid.uuid4(), reason="x"
            )
        assert exc.value.status_code == 404


class TestOwnersAndReset:
    async def test_add_owner_lands_in_the_isp_org(self) -> None:
        repo = FakeRepo()
        isp = TestSuspendActivate()._seed(repo)
        svc, p = _service(repo=repo)
        cred = await svc.add_owner(
            actor_user_id=ACTOR,
            isp_org_id=isp,
            data=IspOwnerRequest(first_name="A", last_name="B", email="a@b.in"),
        )
        assert p.users.created[0]["organization_id"] == isp
        assert p.users.created[0]["initial_role_id"] is None
        assert p.rbac.role_rows[0]["organization_id"] == isp
        assert p.rbac.role_rows[0]["role_id"] == p.rbac.role.id
        assert cred.temporary_password

    async def test_reset_requires_an_isp_role_on_this_isp(self) -> None:
        repo = FakeRepo()
        isp = TestSuspendActivate()._seed(repo)
        svc, _ = _service(repo=repo, roles=FakeRoles([]))
        with pytest.raises(IspUserNotFoundError):
            await svc.reset_user_password(
                actor_user_id=ACTOR, isp_org_id=isp, isp_user_id=uuid.uuid4()
            )

    async def test_reset_sets_must_change_and_ends_sessions(self) -> None:
        repo = FakeRepo()
        isp = TestSuspendActivate()._seed(repo)
        identity = FakeIdentity()
        uid = uuid.uuid4()
        identity.users[uid] = SimpleNamespace(
            id=uid, email="t@isp.in", username="t@isp.in"
        )
        svc, p = _service(
            repo=repo, roles=FakeRoles(["isp-technician"]), identity=identity
        )
        cred = await svc.reset_user_password(
            actor_user_id=ACTOR, isp_org_id=isp, isp_user_id=uid
        )
        assert identity.updates[-1]["must_change_password"] is True
        assert p.users.logouts and p.users.logouts[0]["user_id"] == uid
        assert cred.temporary_password and cred.username == "t@isp.in"


def test_temporary_password_meets_the_existing_policy() -> None:
    from app.domains.auth.password import PasswordManager

    for _ in range(50):
        pw = generate_temporary_password()
        assert len(pw) == 16
        PasswordManager.hash(pw)  # raises PasswordStrengthError if weak


# =============================================================================
# The direct isp-owner role write bypasses RBACService's escalation guard.
# Pin where it can be reached from and what it can grant.
# =============================================================================
class TestDirectOwnerGrantIsContained:
    def test_service_is_only_constructed_by_the_platform_router(self) -> None:
        import pathlib

        app_dir = pathlib.Path(__file__).resolve().parents[2] / "app"
        users = sorted(
            str(f.relative_to(app_dir))
            for f in app_dir.rglob("*.py")
            if "IspPartnerPlatformService" in f.read_text()
            and f.name != "platform_service.py"
        )
        assert users == ["domains/isp_partner/platform_router.py"], users

    def test_only_create_and_add_owner_call_the_direct_write(self) -> None:
        import inspect

        import app.domains.isp_partner.platform_service as mod

        src = inspect.getsource(mod)
        assert src.count("self._create_owner(") == 2
        assert src.count(".create_user_role(") == 1
        for name in ("create_partner", "add_owner"):
            assert "self._create_owner(" in inspect.getsource(
                getattr(IspPartnerPlatformService, name)
            )

    @pytest.mark.parametrize(
        "path", ["", "/{isp_partner_id}/owners"], ids=["create", "add-owner"]
    )
    def test_both_entry_routes_are_global_pinned(self, path) -> None:
        route = next(
            r
            for r in _routes()
            if r.path == "/platform/isp-partners" + path and "POST" in r.methods
        )
        values = _closure_values(route)
        assert ScopeType.GLOBAL in values
        assert {"organizations.create", "organizations.manage"} & set(values)

    async def test_refuses_any_role_but_system_isp_owner(self) -> None:
        from app.domains.isp_partner.platform_service import IspOwnerGrantRefusedError

        for bad in (
            SimpleNamespace(
                id=uuid.uuid4(), slug="organization-owner", organization_id=None
            ),
            SimpleNamespace(id=uuid.uuid4(), slug="super-admin", organization_id=None),
            SimpleNamespace(
                id=uuid.uuid4(), slug="isp-owner", organization_id=uuid.uuid4()
            ),
        ):
            rbac = FakeRbac()
            rbac.role = bad
            svc, p = _service(rbac=rbac)
            with pytest.raises(IspOwnerGrantRefusedError):
                await svc.create_partner(actor_user_id=ACTOR, data=_create_request())
            assert p.rbac.role_rows == [] and p.users.created == []

    async def test_refuses_a_non_isp_org(self) -> None:
        from app.domains.isp_partner.platform_service import IspOwnerGrantRefusedError

        for org in (
            _org(org_type=OrganizationType.STANDARD.value),
            _org(parent_organization_id=uuid.uuid4()),
        ):
            repo = FakeRepo()
            profile = IspPartnerProfile(
                organization_id=org.id,
                status="active",
                default_customer_plan_id=uuid.uuid4(),
            )
            repo.partners[org.id] = (profile, org)
            svc, p = _service(repo=repo)
            with pytest.raises(IspOwnerGrantRefusedError):
                await svc.add_owner(
                    actor_user_id=ACTOR,
                    isp_org_id=org.id,
                    data=IspOwnerRequest(first_name="A", last_name="B", email="a@b.in"),
                )
            assert p.rbac.role_rows == [] and p.users.created == []

    @pytest.mark.parametrize(
        "grants", [ISP_OWNER_GRANTS, ORG_OWNER_GRANTS], ids=["isp-owner", "org-owner"]
    )
    def test_isp_scoped_callers_cannot_reach_add_owner_or_reset(
        self, make_client, grants
    ) -> None:
        svc = _RecordingService()
        client = make_client(enabled=True, grants=grants, service=svc)
        isp = uuid.uuid4()
        hdr = {"X-Organization-Id": str(isp)}
        r1 = client.post(
            f"/api/v1/platform/isp-partners/{isp}/owners",
            json={"first_name": "A", "last_name": "B", "email": "a@b.in"},
            headers=hdr,
        )
        r2 = client.post(
            f"/api/v1/platform/isp-partners/{isp}/users/{uuid.uuid4()}/reset-password",
            headers=hdr,
        )
        assert (r1.status_code, r2.status_code) == (403, 403)
        assert svc.calls == []
