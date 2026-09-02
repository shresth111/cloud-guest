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

from app.domains.monitoring.service import (
    AlertService,
    IncidentService,
    NotificationService,
    SlaService,
)
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
# The rest of the monitoring domain's by-id resources
#
# AlertRule, NotificationChannel, Incident and SlaTarget all carry a
# *nullable* organization_id, where NULL means a platform-wide object (a
# "Database Down" system rule, a platform-ops Slack channel). The guard
# refuses those for an org-scoped caller, which matches what the list
# endpoints already do: apply_filters turns {"organization_id": org} into
# WHERE organization_id = org, and that never matches NULL.
# ---------------------------------------------------------------------------


class _FakeByIdRepo:
    """One row, returned for any id, plus a flag proving whether the mutation
    underneath the guard was ever reached."""

    def __init__(self, row) -> None:
        self._row = row
        self.mutated = False

    async def get_alert_rule(self, rule_id):
        return self._row

    async def get_notification_channel(self, channel_id):
        return self._row

    async def get_incident(self, incident_id):
        return self._row

    async def get_sla_target(self, target_id):
        return self._row

    async def soft_delete_alert_rule(self, rule):
        self.mutated = True
        raise _ReachedRead

    async def soft_delete_notification_channel(self, channel):
        self.mutated = True
        raise _ReachedRead

    async def list_alerts_for_incident(self, incident_id):
        self.mutated = True
        raise _ReachedRead

    async def list_sla_reports(self, **kwargs):
        self.mutated = True
        raise _ReachedRead


def _owned_by(organization_id: uuid.UUID | None):
    return SimpleNamespace(id=uuid.uuid4(), organization_id=organization_id)


class TestAlertRuleTenantScoping:
    async def test_foreign_rule_cannot_be_read(self) -> None:
        service = AlertService(_FakeByIdRepo(_owned_by(uuid.uuid4())))
        with pytest.raises(CrossOrganizationAccessError):
            await service.get_alert_rule(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )

    async def test_foreign_rule_cannot_be_deleted(self) -> None:
        repo = _FakeByIdRepo(_owned_by(uuid.uuid4()))
        service = AlertService(repo)
        with pytest.raises(CrossOrganizationAccessError):
            await service.delete_alert_rule(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )
        assert repo.mutated is False

    async def test_platform_wide_rule_is_refused_for_an_org_caller(self) -> None:
        """NULL organization_id is a platform system rule, not the caller's --
        and the org-scoped list endpoint never returns it either."""
        service = AlertService(_FakeByIdRepo(_owned_by(None)))
        with pytest.raises(CrossOrganizationAccessError):
            await service.get_alert_rule(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )

    async def test_platform_caller_may_read_a_platform_wide_rule(self) -> None:
        service = AlertService(_FakeByIdRepo(_owned_by(None)))
        rule = await service.get_alert_rule(
            uuid.uuid4(), requesting_organization_id=None
        )
        assert rule is not None


class TestNotificationChannelTenantScoping:
    async def test_foreign_channel_cannot_be_read(self) -> None:
        """A channel carries config_encrypted -- the webhook URL or API
        credential it delivers through."""
        service = NotificationService(
            _FakeByIdRepo(_owned_by(uuid.uuid4())), http_client=None
        )
        with pytest.raises(CrossOrganizationAccessError):
            await service.get_channel(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )

    async def test_platform_ops_channel_is_refused_for_an_org_caller(self) -> None:
        service = NotificationService(_FakeByIdRepo(_owned_by(None)), http_client=None)
        with pytest.raises(CrossOrganizationAccessError):
            await service.get_channel(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )

    async def test_foreign_channel_cannot_be_deleted(self) -> None:
        repo = _FakeByIdRepo(_owned_by(uuid.uuid4()))
        service = NotificationService(repo, http_client=None)
        with pytest.raises(CrossOrganizationAccessError):
            await service.delete_channel(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )
        assert repo.mutated is False

    async def test_own_channel_is_readable(self) -> None:
        own = uuid.uuid4()
        service = NotificationService(_FakeByIdRepo(_owned_by(own)), http_client=None)
        channel = await service.get_channel(
            uuid.uuid4(), requesting_organization_id=own
        )
        assert channel.organization_id == own


class TestIncidentTenantScoping:
    async def test_foreign_incident_cannot_be_read(self) -> None:
        service = IncidentService(_FakeByIdRepo(_owned_by(uuid.uuid4())))
        with pytest.raises(CrossOrganizationAccessError):
            await service.get_incident(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )

    async def test_foreign_incidents_alerts_are_not_listable(self) -> None:
        """The guard lives on the incident: reaching its alerts is reaching
        it, so the listing must never get past the check."""
        repo = _FakeByIdRepo(_owned_by(uuid.uuid4()))
        service = IncidentService(repo)
        with pytest.raises(CrossOrganizationAccessError):
            await service.list_alerts_for_incident(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )
        assert repo.mutated is False


class TestSlaTargetTenantScoping:
    async def test_foreign_target_cannot_be_read(self) -> None:
        service = SlaService(_FakeByIdRepo(_owned_by(uuid.uuid4())))
        with pytest.raises(CrossOrganizationAccessError):
            await service.get_target(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )

    async def test_foreign_targets_reports_are_not_listable(self) -> None:
        repo = _FakeByIdRepo(_owned_by(uuid.uuid4()))
        service = SlaService(repo)
        with pytest.raises(CrossOrganizationAccessError):
            await service.list_reports(
                uuid.uuid4(), requesting_organization_id=uuid.uuid4()
            )
        assert repo.mutated is False


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
    ("/api/v1/alerts/rules/{rule_id}", "GET"),
    ("/api/v1/alerts/rules/{rule_id}", "PUT"),
    ("/api/v1/alerts/rules/{rule_id}", "DELETE"),
    ("/api/v1/notifications/channels/{channel_id}", "GET"),
    ("/api/v1/notifications/channels/{channel_id}", "PUT"),
    ("/api/v1/notifications/channels/{channel_id}", "DELETE"),
    ("/api/v1/incidents/{incident_id}", "GET"),
    ("/api/v1/incidents/{incident_id}/alerts", "GET"),
    ("/api/v1/sla/{target_id}/reports", "GET"),
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


def _global_scopes_on(route) -> list:
    """The ScopeType values baked into a route's RequirePermission closures."""
    from app.domains.rbac.enums import ScopeType

    scopes = []
    for dep in _dependency_calls(route.dependant):
        closure = getattr(dep, "__closure__", None)
        if closure:
            scopes.extend(
                cell.cell_contents
                for cell in closure
                if isinstance(cell.cell_contents, ScopeType)
            )
    return scopes


# Platform-only surfaces: the underlying models have no organization_id at
# all, so these cannot be filtered per tenant -- only withheld. Each must
# therefore require GLOBAL scope rather than a bare permission key that
# org-side roles also hold.
_PLATFORM_ONLY_ROUTES = [
    ("/api/v1/controller-logs/authentication/admin", "GET"),
    ("/api/v1/monitoring/health", "GET"),
    ("/api/v1/monitoring/health/{component}", "GET"),
    ("/api/v1/monitoring/health/run", "POST"),
]


@pytest.mark.parametrize(("path", "method"), _PLATFORM_ONLY_ROUTES)
def test_platform_only_route_requires_global_scope(path, method) -> None:
    from app.domains.rbac.enums import ScopeType
    from app.main import create_app

    app = create_app()
    route = _route(app, path, method)
    assert ScopeType.GLOBAL in _global_scopes_on(route), (
        f"{method} {path} returns platform-wide state with no organization_id "
        "to filter on, so it must require GLOBAL scope -- a bare permission "
        "key is also held by org-side roles."
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
