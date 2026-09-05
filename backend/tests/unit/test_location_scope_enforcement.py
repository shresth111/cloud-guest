"""A handler that narrows to one location must compare it against the location
the permission check actually ran against.

Sibling of ``test_cross_tenant_path_id_reads.py``, one scope level down. That
file closed the *cross-organization* case; this one closes the case an
organization-level guard structurally cannot see: two locations under the
**same** organization, where a caller scoped to site A reaches site B.

``RequirePermission`` resolves its scope from ``_current_scope_context``
(``app.domains.rbac.dependencies``), which prefers the ``X-Location-Id``
**header** over a same-named path parameter. So both of these leak:

* ``GET /guests?location_id=<B>`` with ``X-Location-Id: A`` -- the check runs
  at LOCATION scope for A, the read returns B's guests (with their PII);
* ``GET /locations/{B}/nas`` with ``X-Location-Id: A`` -- the path fallback is
  only a *fallback*, so a supplied header still wins and is checked instead.

Two complementary layers, because the defect can reappear in either:

* behavioural -- the guard actually refuses a foreign location;
* structural -- the route still *declares* ``CurrentLocation``, so a future
  edit that drops the dependency fails here rather than in production.

Plain-``assert``/native-``async def`` style, in-memory fakes, no live
Postgres -- same convention as the rest of this suite.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.location.exceptions import CrossLocationScopeAccessError
from app.domains.location.scoping import enforce_target_location
from app.domains.rbac.dependencies import CurrentLocation

# ---------------------------------------------------------------------------
# The shared guard
# ---------------------------------------------------------------------------


class TestEnforceTargetLocation:
    def test_sibling_location_under_the_same_organization_is_refused(self) -> None:
        """The whole point of this guard: both locations belong to one
        organization, so the organization-level guard sees nothing wrong."""
        org = uuid.uuid4()
        with pytest.raises(CrossLocationScopeAccessError):
            enforce_target_location(
                target_location_id=uuid.uuid4(),
                scope_location_id=uuid.uuid4(),
                requesting_organization_id=org,
            )

    def test_own_location_is_allowed(self) -> None:
        own = uuid.uuid4()
        enforce_target_location(
            target_location_id=own,
            scope_location_id=own,
            requesting_organization_id=uuid.uuid4(),
        )

    def test_platform_caller_may_target_anything(self) -> None:
        """A platform-level operator has no organization context. Mirrors
        ``enforce_target_organization``'s first rule, and keeps a super-admin
        holding a stale ``X-Location-Id`` from being locked out."""
        enforce_target_location(
            target_location_id=uuid.uuid4(),
            scope_location_id=uuid.uuid4(),
            requesting_organization_id=None,
        )

    def test_unfiltered_listing_is_allowed(self) -> None:
        """``GET /guests`` with no ``location_id`` narrows to nothing, so there
        is no target to compare; the service's organization scoping still
        applies."""
        enforce_target_location(
            target_location_id=None,
            scope_location_id=uuid.uuid4(),
            requesting_organization_id=uuid.uuid4(),
        )

    def test_organization_scoped_caller_is_left_to_the_organization_guard(self) -> None:
        """No location context means the check ran at ORGANIZATION scope. A
        caller holding *only* a LOCATION-scoped grant cannot reach this branch
        by dropping the header: ``_infer_scope_type`` would resolve
        ORGANIZATION and ``ScopeResolver.satisfies`` refuses a narrower grant
        against a broader check, so the request 403s before any handler runs.
        """
        enforce_target_location(
            target_location_id=uuid.uuid4(),
            scope_location_id=None,
            requesting_organization_id=uuid.uuid4(),
        )

    def test_guard_is_not_fooled_by_equal_looking_distinct_uuids(self) -> None:
        a = uuid.UUID("00000000-0000-0000-0000-00000000000a")
        b = uuid.UUID("00000000-0000-0000-0000-00000000000b")
        with pytest.raises(CrossLocationScopeAccessError):
            enforce_target_location(
                target_location_id=b,
                scope_location_id=a,
                requesting_organization_id=uuid.uuid4(),
            )

    def test_refusal_is_a_403_not_a_500(self) -> None:
        """It must surface as a deliberate denial, not an unhandled error."""
        try:
            enforce_target_location(
                target_location_id=uuid.uuid4(),
                scope_location_id=uuid.uuid4(),
                requesting_organization_id=uuid.uuid4(),
            )
        except CrossLocationScopeAccessError as exc:
            assert exc.status_code == 403
        else:  # pragma: no cover - the call above must raise
            raise AssertionError("guard did not refuse a foreign location")


# ---------------------------------------------------------------------------
# The root invariant: ``None`` means "platform caller", never "no header sent"
# ---------------------------------------------------------------------------
#
# ``ScopeResolver.satisfies`` compares *only* ``location_id`` for a LOCATION
# grant and never consults the organization -- its own docstring says it
# "relies entirely on the caller ... supplying ``organization_id`` alongside
# ``location_id``". So before this guard, a front-desk account holding a
# LOCATION grant on its own site could send ``X-Location-Id: <own site>`` and
# simply **omit** ``X-Organization-Id``: the permission check passed, and the
# handler then ran with ``requesting_organization_id=None``, which every
# tenant guard and every list service reads as "platform caller, no filter".
# That is a cross-*organization* read from an ordinary staff account, and it
# is strictly worse than the sibling-location case above.


class _FakeRole:
    def __init__(self, scope_type: str) -> None:
        self.scope_type = scope_type
        self.is_active = True
        self.is_deleted = False


class _FakeAssignmentRow:
    def __init__(self, scope_type: str) -> None:
        self.role = _FakeRole(scope_type)


class _FakeRbacRepo:
    def __init__(self, scope_types: list[str]) -> None:
        self._rows = [_FakeAssignmentRow(s) for s in scope_types]

    async def get_active_user_roles(self, user_id, *, now=None):
        return self._rows


class _HeaderlessRequest:
    """A request that sent no ``X-Organization-Id``."""

    headers: dict[str, str] = {}


class TestOrganizationContextRequiresAHeader:
    async def test_location_scoped_caller_omitting_the_header_is_refused(self) -> None:
        """The bypass itself. A LOCATION-scoped user must not be able to
        become a platform caller by dropping a header."""
        from app.domains.rbac.dependencies import CurrentOrganization
        from app.domains.rbac.exceptions import MissingScopeContextError

        with pytest.raises(MissingScopeContextError):
            await CurrentOrganization(
                _HeaderlessRequest(),
                user=SimpleNamespace(id=str(uuid.uuid4())),
                db=None,
                repository=_FakeRbacRepo(["location"]),
            )

    async def test_organization_scoped_caller_omitting_the_header_is_refused(
        self,
    ) -> None:
        from app.domains.rbac.dependencies import CurrentOrganization
        from app.domains.rbac.exceptions import MissingScopeContextError

        with pytest.raises(MissingScopeContextError):
            await CurrentOrganization(
                _HeaderlessRequest(),
                user=SimpleNamespace(id=str(uuid.uuid4())),
                db=None,
                repository=_FakeRbacRepo(["organization"]),
            )

    async def test_genuine_platform_caller_still_gets_none(self) -> None:
        """A GLOBAL-scoped operator legitimately has no tenant. This is the
        population the ``None`` return was written for, and it must keep
        working -- the Master console's cross-tenant pages depend on it."""
        from app.domains.rbac.dependencies import CurrentOrganization

        result = await CurrentOrganization(
            _HeaderlessRequest(),
            user=SimpleNamespace(id=str(uuid.uuid4())),
            db=None,
            repository=_FakeRbacRepo(["global"]),
        )
        assert result is None

    async def test_a_user_with_no_roles_at_all_is_refused(self) -> None:
        from app.domains.rbac.dependencies import CurrentOrganization
        from app.domains.rbac.exceptions import MissingScopeContextError

        with pytest.raises(MissingScopeContextError):
            await CurrentOrganization(
                _HeaderlessRequest(),
                user=SimpleNamespace(id=str(uuid.uuid4())),
                db=None,
                repository=_FakeRbacRepo([]),
            )


# ---------------------------------------------------------------------------
# Structural: the routes still declare a location dependency
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


# Every route below narrows to a single location taken from a query parameter
# or a path segment. Each must resolve the caller's own location scope so the
# guard inside can compare the two.
_LOCATION_NARROWING_ROUTES = [
    ("/api/v1/guests", "GET"),
    ("/api/v1/guest-sessions", "GET"),
    ("/api/v1/guest-login-history", "GET"),
    ("/api/v1/radius/nas", "GET"),
    ("/api/v1/locations/{location_id}/nas", "GET"),
    ("/api/v1/guest-analytics/summary", "GET"),
    ("/api/v1/guest-analytics/otp-success-rate", "GET"),
    ("/api/v1/guest-analytics/voucher-usage", "GET"),
]


@pytest.mark.parametrize(("path", "method"), _LOCATION_NARROWING_ROUTES)
def test_location_narrowing_route_declares_current_location(path, method) -> None:
    from app.main import create_app

    route = _route(create_app(), path, method)
    assert CurrentLocation in _dependency_calls(route.dependant), (
        f"{method} {path} narrows to one location but no longer resolves the "
        "caller's own location scope -- the permission check and the read can "
        "now disagree again. See app.domains.location.scoping."
    )
