"""Unit tests for the org-scope-inference authorization bug fix:
``app.domains.rbac.dependencies._current_scope_context`` (and, through it,
``RequirePermission``/``RequireScope``/``RequireRole``) now falls back to
the request's own URL *path parameters* (``organization_id``/
``location_id``/``router_id``) when the corresponding ``X-*-Id`` header is
absent, instead of unconditionally inferring ``GLOBAL`` scope.

## The bug this covers

``GET /organizations/{organization_id}/locations`` (see
``app.domains.location.router.list_locations``) already names its
organization unambiguously in the URL. Before this fix, a caller that
didn't *also* separately repeat that id via ``X-Organization-Id`` (or any
caller whose header didn't reach the server) had their permission check
silently forced to ``GLOBAL`` scope by ``_infer_scope_type``'s fallback --
rejecting a real Organization Owner who legitimately holds
``locations.read`` at ORGANIZATION scope, not GLOBAL. Confirmed live in
production against ``demo-owner@wyfyguest.com`` (Organization Owner,
org ``58c9bb5f-caa7-4c81-9eef-4aaad5ca3e82``) trying to see location
"Grand Plaza Hotel".

Structured in two layers, mirroring how ``tests/unit/test_rbac.py`` itself
is split:

* ``TestParseUuidPathParam`` / ``TestCurrentScopeContext`` -- narrow,
  direct tests of the two new/changed functions against a bare Starlette
  ``Request`` built from a raw ASGI scope (the same construction pattern
  ``test_masking.py``/``test_auth.py`` already use).
* ``TestRequirePermissionPathParamInference`` -- an end-to-end style test
  that wires a real ``AccessValidator``/``RoleResolver`` against
  ``test_rbac.py``'s own ``FakeRBACRepository`` (imported, not
  reimplemented) and calls ``RequirePermission(...)``'s inner dependency
  function directly, proving the exact production scenario: an
  Organization-Owner-shaped role, holding the permission at ORGANIZATION
  scope, succeeds against a path-param-only request with **no** scope
  header at all -- and that a user who does *not* hold the permission at
  any scope is still correctly rejected (no loosening of the actual grant
  check, only of how its scope *context* is derived).
"""

from __future__ import annotations

import uuid

import pytest
from starlette.requests import Request

from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.context import ScopeContext
from app.domains.rbac.dependencies import (
    RequirePermission,
    _current_scope_context,
    _parse_uuid_path_param,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.exceptions import PermissionDeniedError

from .test_rbac import FakeRBACRepository, assign_role, make_permission, make_role


def _make_request(
    *,
    headers: dict[str, str] | None = None,
    path_params: dict[str, object] | None = None,
    path: str = "/api/v1/organizations/x/locations",
) -> Request:
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": raw_headers,
        "path_params": path_params or {},
    }
    return Request(scope)


class _FakeUser:
    def __init__(self, user_id: uuid.UUID | None = None) -> None:
        self.id = str(user_id or uuid.uuid4())


# ============================================================================
# _parse_uuid_path_param
# ============================================================================


class TestParseUuidPathParam:
    def test_returns_none_when_param_absent(self) -> None:
        request = _make_request(path_params={})
        assert _parse_uuid_path_param(request, "organization_id") is None

    def test_parses_string_uuid_from_path_params(self) -> None:
        org_id = uuid.uuid4()
        request = _make_request(path_params={"organization_id": str(org_id)})
        assert _parse_uuid_path_param(request, "organization_id") == org_id

    def test_passes_through_an_already_uuid_typed_value(self) -> None:
        org_id = uuid.uuid4()
        request = _make_request(path_params={"organization_id": org_id})
        assert _parse_uuid_path_param(request, "organization_id") == org_id

    def test_malformed_value_returns_none_rather_than_raising(self) -> None:
        # Unlike _parse_uuid_header (which raises InvalidScopeHeaderError on
        # a malformed header), a malformed path param is never this
        # dependency's problem -- FastAPI's own endpoint-signature
        # validation independently 422s a genuinely malformed path param.
        request = _make_request(path_params={"organization_id": "not-a-uuid"})
        assert _parse_uuid_path_param(request, "organization_id") is None

    def test_missing_path_params_attribute_is_tolerated(self) -> None:
        # A handful of existing unit tests (e.g.
        # test_billing_plans_licenses_usage.py's TestPlanCatalogRbacGate)
        # construct a minimal fake Request double that only stubs
        # `.headers`. This must not raise AttributeError for those.
        class _BareRequest:
            headers: dict[str, str] = {}

        assert _parse_uuid_path_param(_BareRequest(), "organization_id") is None


# ============================================================================
# _current_scope_context: header vs. path-param precedence
# ============================================================================


class TestCurrentScopeContext:
    async def test_no_header_no_path_param_resolves_to_global(self) -> None:
        request = _make_request()
        context = await _current_scope_context(request)
        assert context == ScopeContext.global_scope()

    async def test_falls_back_to_path_param_when_header_absent(self) -> None:
        org_id = uuid.uuid4()
        request = _make_request(path_params={"organization_id": str(org_id)})
        context = await _current_scope_context(request)
        assert context.organization_id == org_id
        assert context.location_id is None
        assert context.router_id is None

    async def test_the_url_wins_over_the_header(self) -> None:
        """Inverted deliberately. This test used to assert the opposite, and
        the opposite was the root of a whole defect class.

        The URL names the entity the handler is about to act on; the header
        only says which tenant the caller *claims* to be working within. When
        they disagree, letting the header win means the permission check is
        evaluated against one organization and the read or write happens
        against another -- which is exactly how
        ``GET /billing/dashboard/{organization_id}`` came to need a
        hand-placed ``enforce_target_organization`` guard, and how
        ``/customers/{customer_id}/features`` leaked another tenant's plan
        because its parameter was not even spelled ``organization_id``.

        With the URL winning, the check is evaluated against the thing being
        acted on, and those guards become belt-and-braces rather than the only
        thing standing between tenants.
        """
        header_org_id = uuid.uuid4()
        path_org_id = uuid.uuid4()
        request = _make_request(
            headers={"X-Organization-Id": str(header_org_id)},
            path_params={"organization_id": str(path_org_id)},
        )
        context = await _current_scope_context(request)
        assert context.organization_id == path_org_id

    async def test_location_and_router_path_params_also_resolved(self) -> None:
        location_id = uuid.uuid4()
        router_id = uuid.uuid4()
        request = _make_request(
            path_params={"location_id": str(location_id), "router_id": str(router_id)}
        )
        context = await _current_scope_context(request)
        assert context.location_id == location_id
        assert context.router_id == router_id
        assert context.organization_id is None

    async def test_route_with_no_matching_path_params_is_unaffected(self) -> None:
        # A route with none of organization_id/location_id/router_id in its
        # path (the overwhelming majority of routes) sees no behavior
        # change at all -- still resolves to GLOBAL exactly as before this
        # fix, with an unrelated path param present.
        request = _make_request(path_params={"member_id": str(uuid.uuid4())})
        context = await _current_scope_context(request)
        assert context == ScopeContext.global_scope()

    async def test_existing_header_only_behavior_still_works_unchanged(self) -> None:
        org_id = uuid.uuid4()
        location_id = uuid.uuid4()
        router_id = uuid.uuid4()
        request = _make_request(
            headers={
                "X-Organization-Id": str(org_id),
                "X-Location-Id": str(location_id),
                "X-Router-Id": str(router_id),
            }
        )
        context = await _current_scope_context(request)
        assert context.organization_id == org_id
        assert context.location_id == location_id
        assert context.router_id == router_id


# ============================================================================
# End-to-end: RequirePermission's inner dependency against a real
# AccessValidator/RoleResolver wired to FakeRBACRepository.
# ============================================================================


class TestRequirePermissionPathParamInference:
    async def test_org_scoped_user_succeeds_via_path_param_alone(self) -> None:
        """The exact confirmed-bug scenario: an Organization-Owner-shaped
        role holding `locations.read` at ORGANIZATION scope, hitting a
        route whose only source of organization context is the URL path
        (`organization_id` in path_params) -- no X-Organization-Id header
        sent at all."""
        repo = FakeRBACRepository()
        validator = AccessValidator(repo)
        permission = await make_permission(repo, "locations", "read")
        role = await make_role(
            repo, "Organization Owner", scope_type=ScopeType.ORGANIZATION
        )
        await repo.add_role_permission(role.id, permission.id, granted_by=None)

        user_id = uuid.uuid4()
        org_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=user_id,
            role=role,
            scope_type=ScopeType.ORGANIZATION,
            organization_id=org_id,
        )

        dependency = RequirePermission("locations.read")
        request = _make_request(path_params={"organization_id": str(org_id)})
        user = _FakeUser(user_id)

        result = await dependency(request, user=user, access_validator=validator)

        assert result is user

    async def test_user_without_permission_at_any_scope_is_still_rejected(self) -> None:
        """No regression toward being too permissive: a user with zero role
        assignments (or one that doesn't carry this permission) must still
        be denied, even though the URL path names an organization."""
        repo = FakeRBACRepository()
        validator = AccessValidator(repo)
        await make_permission(repo, "locations", "read")  # exists, but never granted

        dependency = RequirePermission("locations.read")
        org_id = uuid.uuid4()
        request = _make_request(path_params={"organization_id": str(org_id)})
        user = _FakeUser()

        with pytest.raises(PermissionDeniedError):
            await dependency(request, user=user, access_validator=validator)

    async def test_org_scoped_user_still_rejected_for_a_different_organization(
        self,
    ) -> None:
        """The path-param fallback must not let a caller's grant for
        organization A satisfy a request whose path names organization B --
        the underlying ScopeResolver / access_validator.check comparison is
        completely untouched by this fix, only how the scope *context* is
        assembled."""
        repo = FakeRBACRepository()
        validator = AccessValidator(repo)
        permission = await make_permission(repo, "locations", "read")
        role = await make_role(
            repo, "Organization Owner", scope_type=ScopeType.ORGANIZATION
        )
        await repo.add_role_permission(role.id, permission.id, granted_by=None)

        user_id = uuid.uuid4()
        granted_org_id = uuid.uuid4()
        other_org_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=user_id,
            role=role,
            scope_type=ScopeType.ORGANIZATION,
            organization_id=granted_org_id,
        )

        dependency = RequirePermission("locations.read")
        request = _make_request(path_params={"organization_id": str(other_org_id)})
        user = _FakeUser(user_id)

        with pytest.raises(PermissionDeniedError):
            await dependency(request, user=user, access_validator=validator)

    async def test_header_based_resolution_for_the_same_route_shape_still_works(
        self,
    ) -> None:
        """Same permission/role setup as the path-param test above, but via
        the pre-existing X-Organization-Id header mechanism and no path
        param at all -- proving the header path is completely unaffected by
        this change."""
        repo = FakeRBACRepository()
        validator = AccessValidator(repo)
        permission = await make_permission(repo, "locations", "read")
        role = await make_role(
            repo, "Organization Owner", scope_type=ScopeType.ORGANIZATION
        )
        await repo.add_role_permission(role.id, permission.id, granted_by=None)

        user_id = uuid.uuid4()
        org_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=user_id,
            role=role,
            scope_type=ScopeType.ORGANIZATION,
            organization_id=org_id,
        )

        dependency = RequirePermission("locations.read")
        request = _make_request(headers={"X-Organization-Id": str(org_id)})
        user = _FakeUser(user_id)

        result = await dependency(request, user=user, access_validator=validator)

        assert result is user

    async def test_explicit_scope_argument_still_overrides_inference(self) -> None:
        """RequirePermission(..., scope=ScopeType.GLOBAL) -- as
        location.router.py's own list_locations/create_location now also
        declare explicitly, belt-and-suspenders alongside the general
        inference fix -- must still demand exactly that scope regardless of
        what the path/headers would otherwise infer."""
        repo = FakeRBACRepository()
        validator = AccessValidator(repo)
        permission = await make_permission(repo, "locations", "read")
        role = await make_role(
            repo, "Organization Owner", scope_type=ScopeType.ORGANIZATION
        )
        await repo.add_role_permission(role.id, permission.id, granted_by=None)

        user_id = uuid.uuid4()
        org_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=user_id,
            role=role,
            scope_type=ScopeType.ORGANIZATION,
            organization_id=org_id,
        )

        # An ORGANIZATION-scoped grant does not satisfy an explicit
        # GLOBAL-scope requirement -- this must still fail even though the
        # path names the same organization the grant is for.
        dependency = RequirePermission("locations.read", scope=ScopeType.GLOBAL)
        request = _make_request(path_params={"organization_id": str(org_id)})
        user = _FakeUser(user_id)

        with pytest.raises(PermissionDeniedError):
            await dependency(request, user=user, access_validator=validator)
