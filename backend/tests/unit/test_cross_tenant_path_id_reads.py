"""Every handler that names its target by path id must compare it against the
caller's own organization.

``RequirePermission`` resolves the scope it checks from
``_current_scope_context`` (``app.domains.rbac.dependencies``), which prefers
the ``X-Organization-Id`` **header** over a path parameter. A handler that
reads by path id and declares no organization dependency therefore runs its
permission check against one organization and its read against another.

``GET /billing/dashboard/{organization_id}`` had this shape and was fixed
inline. An audit then found the same pattern across the billing,
organization, monitoring, rbac and controller-logs domains. These tests pin
each one shut.

Two complementary layers, because the defect can reappear in either:

* behavioural -- the guard actually refuses a foreign target;
* structural -- the route still *declares* an organization dependency, so a
  future edit that drops it fails here rather than in production.

Plain-``assert``/native-``async def`` style, in-memory fakes, no live
Postgres -- same convention as the rest of this suite.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.monitoring.service import AlertService
from app.domains.organization.exceptions import CrossOrganizationAccessError
from app.domains.organization.scoping import enforce_target_organization
from app.domains.rbac.dependencies import CurrentOrganization


class _ReachedRead(Exception):
    """Raised by a fake once the guard has been cleared, so a test never has
    to build a full response just to prove the boundary holds."""


# ---------------------------------------------------------------------------
# The shared guard
# ---------------------------------------------------------------------------


class _FakeOrgService:
    def __init__(self, parent_of_target: uuid.UUID | None = None) -> None:
        self._parent = parent_of_target

    async def get_organization(self, organization_id: uuid.UUID):
        return SimpleNamespace(
            id=organization_id, parent_organization_id=self._parent
        )


class TestEnforceTargetOrganization:
    async def test_foreign_organization_is_refused(self) -> None:
        with pytest.raises(CrossOrganizationAccessError):
            await enforce_target_organization(
                target_organization_id=uuid.uuid4(),
                requesting_organization_id=uuid.uuid4(),
                organization_service=_FakeOrgService(),
            )

    async def test_own_organization_is_allowed(self) -> None:
        own = uuid.uuid4()
        await enforce_target_organization(
            target_organization_id=own,
            requesting_organization_id=own,
            organization_service=_FakeOrgService(),
        )

    async def test_msp_parent_may_reach_a_child(self) -> None:
        parent, child = uuid.uuid4(), uuid.uuid4()
        await enforce_target_organization(
            target_organization_id=child,
            requesting_organization_id=parent,
            organization_service=_FakeOrgService(parent_of_target=parent),
        )

    async def test_platform_caller_may_target_anything(self) -> None:
        """A global-scope operator has no organization context; the guard must
        not turn that into a denial."""
        await enforce_target_organization(
            target_organization_id=uuid.uuid4(),
            requesting_organization_id=None,
            organization_service=_FakeOrgService(),
        )


# ---------------------------------------------------------------------------
# Alerts: a cross-tenant read *and* two cross-tenant writes
# ---------------------------------------------------------------------------


class _FakeAlertRepo:
    def __init__(self, alert) -> None:
        self._alert = alert
        self.updated = False

    async def get_alert(self, alert_id: uuid.UUID):
        return self._alert

    async def update_alert(self, alert, data):
        self.updated = True
        raise _ReachedRead


def _alert_owned_by(organization_id: uuid.UUID):
    return SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        status="triggered",
        rule_id=uuid.uuid4(),
    )


class TestAlertTenantScoping:
    async def test_foreign_alert_cannot_be_read(self) -> None:
        victim, attacker = uuid.uuid4(), uuid.uuid4()
        service = AlertService(_FakeAlertRepo(_alert_owned_by(victim)))
        with pytest.raises(CrossOrganizationAccessError):
            await service.get_alert(
                uuid.uuid4(), requesting_organization_id=attacker
            )

    async def test_foreign_alert_cannot_be_acknowledged(self) -> None:
        """The write path matters more than the read: acknowledging another
        tenant's alert silences their monitoring."""
        victim, attacker = uuid.uuid4(), uuid.uuid4()
        repo = _FakeAlertRepo(_alert_owned_by(victim))
        service = AlertService(repo)
        with pytest.raises(CrossOrganizationAccessError):
            await service.acknowledge_alert(
                uuid.uuid4(),
                user_id=uuid.uuid4(),
                requesting_organization_id=attacker,
            )
        assert repo.updated is False

    async def test_foreign_alert_cannot_be_resolved(self) -> None:
        victim, attacker = uuid.uuid4(), uuid.uuid4()
        repo = _FakeAlertRepo(_alert_owned_by(victim))
        service = AlertService(repo)
        with pytest.raises(CrossOrganizationAccessError):
            await service.resolve_alert(
                uuid.uuid4(), requesting_organization_id=attacker
            )
        assert repo.updated is False

    async def test_own_alert_is_readable(self) -> None:
        own = uuid.uuid4()
        service = AlertService(_FakeAlertRepo(_alert_owned_by(own)))
        alert = await service.get_alert(uuid.uuid4(), requesting_organization_id=own)
        assert alert.organization_id == own

    async def test_platform_caller_may_read_any_alert(self) -> None:
        service = AlertService(_FakeAlertRepo(_alert_owned_by(uuid.uuid4())))
        alert = await service.get_alert(uuid.uuid4(), requesting_organization_id=None)
        assert alert is not None


# ---------------------------------------------------------------------------
# Structural: the routes still declare an organization dependency
# ---------------------------------------------------------------------------


def _route(app, path: str, method: str):
    return next(
        r
        for r in app.routes
        if getattr(r, "path", None) == path and method in getattr(r, "methods", set())
    )


def _dependency_calls(dependant) -> set:
    calls = {d.call for d in dependant.dependencies}
    for d in dependant.dependencies:
        calls |= _dependency_calls(d)
    return calls


# Every route below reads a resource named in its own path. Each must resolve
# the caller's organization so the guard inside can compare the two.
_PATH_ID_ROUTES = [
    ("/api/v1/billing/dashboard/{organization_id}", "GET"),
    ("/api/v1/subscriptions/{organization_id}", "GET"),
    ("/api/v1/usage/{organization_id}", "GET"),
    ("/api/v1/usage/{organization_id}/refresh", "POST"),
    ("/api/v1/billing/profile/{organization_id}", "GET"),
    ("/api/v1/organizations/{organization_id}", "GET"),
    ("/api/v1/organizations/{organization_id}/children", "GET"),
    ("/api/v1/organizations/{organization_id}/members", "GET"),
    ("/api/v1/alerts/{alert_id}", "GET"),
    ("/api/v1/alerts/{alert_id}/acknowledge", "POST"),
    ("/api/v1/alerts/{alert_id}/resolve", "POST"),
    ("/api/v1/users/{user_id}/roles", "GET"),
    ("/api/v1/users/{user_id}/permissions", "GET"),
]


@pytest.mark.parametrize(("path", "method"), _PATH_ID_ROUTES)
def test_path_id_route_resolves_the_callers_organization(path, method) -> None:
    from app.main import create_app

    app = create_app()
    route = _route(app, path, method)
    assert CurrentOrganization in _dependency_calls(route.dependant), (
        f"{method} {path} reads a resource by path id but never resolves the "
        "caller's organization, so RequirePermission checks a different "
        "organization than the handler reads."
    )


def test_admin_login_attempts_are_gated_at_global_scope() -> None:
    """``LoginAttempt`` has no ``organization_id``, so this listing cannot be
    tenant-filtered and must not be reachable with an organization-scoped
    grant. An Organization Owner holds ``audit_logs.read`` at ORGANIZATION
    scope, which is why the bare permission was not enough."""
    from app.domains.rbac.enums import ScopeType
    from app.main import create_app

    app = create_app()
    route = _route(app, "/api/v1/controller-logs/authentication/admin", "GET")

    scopes = []
    for dep in _dependency_calls(route.dependant):
        scope = getattr(dep, "__closure__", None)
        if scope:
            scopes.extend(
                cell.cell_contents
                for cell in scope
                if isinstance(cell.cell_contents, ScopeType)
            )
    assert ScopeType.GLOBAL in scopes, (
        "platform-wide login attempts must require GLOBAL scope"
    )
