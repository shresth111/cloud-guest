"""The default tenancy of a request is one organization, never all of them.

## The bug these cover

A founder holding ``Super Admin`` at ``scope_type = 'global'`` opened a report
about his own venue and got a report blended across all fourteen organizations
in the database -- mostly demo and QA fixtures (``Wyfy Demo``, ``testyyy``,
``QA Test Co``, ``TechQA-4471``, ...). His account is entitled to every one of
those rows, so this was never a permissions hole. It was a *default*:
``CurrentOrganization`` returned ``None`` for a GLOBAL-scoped caller who named
no organization, ~90 repositories read ``None`` as "no ``WHERE`` clause", and
nothing on the screen distinguished a fourteen-tenant ``COUNT(*)`` from a
one-tenant one.

``CurrentOrganizationScope`` replaces the nullable with a value object that
cannot represent "unspecified", so the two meanings ``None`` used to carry are
now separate states and only one of them is reachable without asking.

## The two halves, and why the second one is the dangerous half

Fixing the default meant *widening where an organization id may come from* --
the route's own ``organization_id`` path/query parameter now counts, not just
the ``X-Organization-Id`` header. This codebase has prior history with exactly
that shape: a defect class found in 14 endpoints where the permission check
evaluated against the header's organization while the handler went on to
operate on the path's. So these tests assert both halves:

* ``TestGlobalCallerDefault`` -- the founder's case. A platform admin who names
  an organization gets that organization; one who names none is told to say
  which, rather than being handed the estate.
* ``TestTenantCallerCannotWiden`` -- the security half. Widening the *sources*
  of an id must not widen *who may use one*: a caller with no GLOBAL role and
  no active membership is refused the same way whether the id arrived in the
  header, the path, or the query string.
* ``TestPermissionCheckAndDataScopeAgree`` -- the anti-regression for the prior
  defect class itself: whatever ``RequirePermission`` is evaluated against and
  whatever the handler filters on must be the same organization.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from starlette.requests import Request

from app.domains.organization.exceptions import (
    OrganizationMembershipRequiredError,
    OrganizationNotFoundError,
)
from app.domains.rbac import dependencies as deps
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentOrganizationScope,
    RequireOrganization,
    _current_scope_context,
    _requested_organization_id,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.exceptions import (
    CrossOrganizationScopeDeniedError,
    MissingScopeContextError,
    SingleOrganizationRequiredError,
    UnspecifiedOrganizationScopeError,
)
from app.domains.rbac.organization_scope import (
    ALL_ORGANIZATIONS_VALUE,
    ORGANIZATION_SCOPE_HEADER,
    ORGANIZATION_SCOPE_QUERY_PARAM,
    OrganizationScope,
    wants_all_organizations,
)

from .test_rbac import FakeRBACRepository, assign_role, make_role

# The two organizations in every scenario below: the venue the caller means,
# and one of the demo/QA fixtures that used to come back alongside it.
REAL_ORG = uuid.UUID("08ec098b-1fb0-4bd0-bcc2-fe489d01ec4c")  # "WyFy Guest"
OTHER_ORG = uuid.UUID("11111111-2222-3333-4444-555555555555")  # a demo fixture


def _make_request(
    *,
    headers: dict[str, str] | None = None,
    path_params: dict[str, object] | None = None,
    query_string: str = "",
    path: str = "/api/v1/alerts",
) -> Request:
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": raw_headers,
            "path_params": path_params or {},
            "query_string": query_string.encode(),
        }
    )


class _FakeUser:
    def __init__(self, user_id: uuid.UUID) -> None:
        self.id = str(user_id)


class _FakeGenericRepository:
    """Stands in for ``GenericRepository`` for the two lookups the dependency makes.

    Patched over the name ``dependencies`` imports rather than faked at the
    ``AsyncSession`` level: the dependency constructs the repository itself, and
    what these tests are about is the *decision*, not SQL.
    """

    existing_organizations: set[uuid.UUID] = set()
    memberships: set[tuple[uuid.UUID, uuid.UUID]] = set()

    def __init__(self, model: Any, session: Any) -> None:
        self.model_name = getattr(model, "__name__", str(model))

    async def get_by_id(self, identifier: uuid.UUID) -> object | None:
        return object() if identifier in self.existing_organizations else None

    async def get_all(
        self, *, filters: dict[str, Any] | None = None, limit: int | None = None
    ) -> list[object]:
        filters = filters or {}
        key = (filters.get("organization_id"), filters.get("user_id"))
        return [object()] if key in self.memberships else []


@pytest.fixture
def fake_repositories(monkeypatch: pytest.MonkeyPatch) -> type[_FakeGenericRepository]:
    _FakeGenericRepository.existing_organizations = {REAL_ORG, OTHER_ORG}
    _FakeGenericRepository.memberships = set()
    monkeypatch.setattr(deps, "GenericRepository", _FakeGenericRepository)
    return _FakeGenericRepository


async def _global_admin(repo: FakeRBACRepository) -> _FakeUser:
    """The founder's shape: Super Admin held at GLOBAL scope."""
    user_id = uuid.uuid4()
    role = await make_role(repo, "Super Admin", scope_type=ScopeType.GLOBAL)
    await assign_role(repo, user_id=user_id, role=role, scope_type=ScopeType.GLOBAL)
    return _FakeUser(user_id)


async def _tenant_member(
    repo: FakeRBACRepository, *, organization_id: uuid.UUID
) -> _FakeUser:
    """An ordinary Organization Owner, member of exactly one organization."""
    user_id = uuid.uuid4()
    role = await make_role(
        repo,
        f"Organization Owner {uuid.uuid4().hex[:6]}",
        scope_type=ScopeType.ORGANIZATION,
        organization_id=organization_id,
    )
    await assign_role(
        repo,
        user_id=user_id,
        role=role,
        scope_type=ScopeType.ORGANIZATION,
        organization_id=organization_id,
    )
    _FakeGenericRepository.memberships.add((organization_id, user_id))
    return _FakeUser(user_id)


async def _resolve(
    request: Request, user: _FakeUser, repo: FakeRBACRepository
) -> OrganizationScope:
    return await CurrentOrganizationScope(
        request=request, user=user, db=object(), repository=repo
    )


# ============================================================================
# wants_all_organizations -- the parsing rule, in isolation
# ============================================================================


class TestWantsAllOrganizations:
    @pytest.mark.parametrize("raw", ["all", "ALL", "  All  "])
    def test_recognises_the_opt_in(self, raw: str) -> None:
        assert wants_all_organizations(raw, None) is True
        assert wants_all_organizations(None, raw) is True

    @pytest.mark.parametrize("raw", [None, "", "every", "true", "1", "organization"])
    def test_fails_closed_on_anything_else(self, raw: str | None) -> None:
        # Fail *closed* deliberately: a mistyped or stale value must scope the
        # request to one tenant, never widen it to fourteen.
        assert wants_all_organizations(raw, None) is False

    def test_scope_object_cannot_be_both_or_neither(self) -> None:
        with pytest.raises(ValueError):
            OrganizationScope(organization_id=REAL_ORG, all_organizations=True)
        with pytest.raises(ValueError):
            OrganizationScope(organization_id=None, all_organizations=False)


# ============================================================================
# The founder's case
# ============================================================================


class TestGlobalCallerDefault:
    @pytest.mark.asyncio
    async def test_selected_organization_wins_over_the_estate(
        self, fake_repositories: type[_FakeGenericRepository]
    ) -> None:
        """A platform admin looking at one venue gets that venue.

        This is the report the founder was reading. Before the fix his session
        sent no ``X-Organization-Id`` at all (the frontend interceptor skipped
        it for GLOBAL-role sessions), so this resolved to ``None`` and every
        repository dropped its ``WHERE``.
        """
        repo = FakeRBACRepository()
        user = await _global_admin(repo)
        request = _make_request(headers={"X-Organization-Id": str(REAL_ORG)})

        scope = await _resolve(request, user, repo)

        assert scope == OrganizationScope.for_organization(REAL_ORG)
        assert scope.all_organizations is False

    @pytest.mark.asyncio
    async def test_organization_named_by_the_route_is_honoured(
        self, fake_repositories: type[_FakeGenericRepository]
    ) -> None:
        """``?organization_id=`` counts, with no header at all.

        The frontend was already sending this on ``/alerts``; the handler read
        only the header and so ignored it, which is how a request that named
        its tenant in its own URL still came back platform-wide.
        """
        repo = FakeRBACRepository()
        user = await _global_admin(repo)
        request = _make_request(query_string=f"organization_id={REAL_ORG}")

        scope = await _resolve(request, user, repo)

        assert scope.organization_id == REAL_ORG

    @pytest.mark.asyncio
    async def test_naming_nothing_is_now_an_error_not_the_whole_estate(
        self, fake_repositories: type[_FakeGenericRepository]
    ) -> None:
        """The core regression. Before the fix this returned ``None``."""
        repo = FakeRBACRepository()
        user = await _global_admin(repo)
        request = _make_request()

        with pytest.raises(UnspecifiedOrganizationScopeError):
            await _resolve(request, user, repo)

    @pytest.mark.asyncio
    async def test_the_estate_is_available_when_asked_for(
        self, fake_repositories: type[_FakeGenericRepository]
    ) -> None:
        """Cross-tenant reads are not removed -- they are made deliberate."""
        repo = FakeRBACRepository()
        user = await _global_admin(repo)
        request = _make_request(
            headers={ORGANIZATION_SCOPE_HEADER: ALL_ORGANIZATIONS_VALUE}
        )

        scope = await _resolve(request, user, repo)

        assert scope == OrganizationScope.all()
        assert await CurrentOrganization(scope=scope) is None

    @pytest.mark.asyncio
    async def test_the_query_string_can_ask_too(
        self, fake_repositories: type[_FakeGenericRepository]
    ) -> None:
        """For a CSV/PDF export opened as a plain navigation, which carries no
        custom headers."""
        repo = FakeRBACRepository()
        user = await _global_admin(repo)
        request = _make_request(
            query_string=f"{ORGANIZATION_SCOPE_QUERY_PARAM}={ALL_ORGANIZATIONS_VALUE}"
        )

        assert (await _resolve(request, user, repo)).all_organizations is True

    @pytest.mark.asyncio
    async def test_a_named_organization_beats_a_stale_all(
        self, fake_repositories: type[_FakeGenericRepository]
    ) -> None:
        """Contradictions resolve by narrowing.

        A client that still has "all organizations" selected but asks about one
        venue gets the venue. The reverse rule would let a leftover header
        silently widen a request that had said exactly what it wanted.
        """
        repo = FakeRBACRepository()
        user = await _global_admin(repo)
        request = _make_request(
            headers={
                "X-Organization-Id": str(REAL_ORG),
                ORGANIZATION_SCOPE_HEADER: ALL_ORGANIZATIONS_VALUE,
            }
        )

        scope = await _resolve(request, user, repo)

        assert scope.organization_id == REAL_ORG
        assert scope.all_organizations is False

    @pytest.mark.asyncio
    async def test_unknown_organization_is_still_404(
        self, fake_repositories: type[_FakeGenericRepository]
    ) -> None:
        repo = FakeRBACRepository()
        user = await _global_admin(repo)
        request = _make_request(headers={"X-Organization-Id": str(uuid.uuid4())})

        with pytest.raises(OrganizationNotFoundError):
            await _resolve(request, user, repo)


# ============================================================================
# The security half
# ============================================================================


class TestTenantCallerCannotWiden:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("source", ["header", "query", "path"])
    async def test_supplying_another_tenants_id_is_refused_from_every_source(
        self, fake_repositories: type[_FakeGenericRepository], source: str
    ) -> None:
        """The point of the whole exercise.

        The id may now arrive from the route as well as the header. That must
        change nothing about *who* may use one: an active membership (or a
        GLOBAL role) is still required, whichever door the id came through.
        """
        repo = FakeRBACRepository()
        user = await _tenant_member(repo, organization_id=REAL_ORG)

        requests = {
            "header": _make_request(headers={"X-Organization-Id": str(OTHER_ORG)}),
            "query": _make_request(query_string=f"organization_id={OTHER_ORG}"),
            "path": _make_request(
                path_params={"organization_id": str(OTHER_ORG)},
                path=f"/api/v1/organizations/{OTHER_ORG}/locations",
            ),
        }

        with pytest.raises(OrganizationMembershipRequiredError):
            await _resolve(requests[source], user, repo)

    @pytest.mark.asyncio
    async def test_own_organization_still_resolves(
        self, fake_repositories: type[_FakeGenericRepository]
    ) -> None:
        repo = FakeRBACRepository()
        user = await _tenant_member(repo, organization_id=REAL_ORG)
        request = _make_request(query_string=f"organization_id={REAL_ORG}")

        assert (await _resolve(request, user, repo)).organization_id == REAL_ORG

    @pytest.mark.asyncio
    async def test_asking_for_all_organizations_is_forbidden_not_ignored(
        self, fake_repositories: type[_FakeGenericRepository]
    ) -> None:
        """403, not a silent narrowing to their own tenant.

        A caller who believes they are looking at the whole estate and is in
        fact looking at one venue makes worse decisions than one who is told no.
        """
        repo = FakeRBACRepository()
        user = await _tenant_member(repo, organization_id=REAL_ORG)
        request = _make_request(
            headers={ORGANIZATION_SCOPE_HEADER: ALL_ORGANIZATIONS_VALUE}
        )

        with pytest.raises(CrossOrganizationScopeDeniedError):
            await _resolve(request, user, repo)

    @pytest.mark.asyncio
    async def test_naming_nothing_still_fails_for_a_tenant_caller(
        self, fake_repositories: type[_FakeGenericRepository]
    ) -> None:
        repo = FakeRBACRepository()
        user = await _tenant_member(repo, organization_id=REAL_ORG)

        with pytest.raises(MissingScopeContextError):
            await _resolve(_make_request(), user, repo)


# ============================================================================
# No divergence between what is checked and what is read
# ============================================================================


class TestPermissionCheckAndDataScopeAgree:
    @pytest.mark.asyncio
    async def test_route_named_organization_wins_in_both_resolvers(self) -> None:
        """The anti-regression for the 14-endpoint defect class.

        ``_current_scope_context`` (what ``RequirePermission`` is evaluated
        against) and ``_requested_organization_id`` (what the handler filters
        on) must never disagree about which organization a request is about.
        Here the two sources deliberately conflict; both resolvers must pick
        the same one -- the route's.
        """
        request = _make_request(
            headers={"X-Organization-Id": str(OTHER_ORG)},
            path_params={"organization_id": str(REAL_ORG)},
            path=f"/api/v1/organizations/{REAL_ORG}/locations",
        )

        checked_against = (await _current_scope_context(request)).organization_id
        read_by_handler = _requested_organization_id(request)

        assert checked_against == read_by_handler == REAL_ORG

    @pytest.mark.asyncio
    async def test_header_is_used_when_the_route_names_nothing(self) -> None:
        request = _make_request(headers={"X-Organization-Id": str(REAL_ORG)})

        checked_against = (await _current_scope_context(request)).organization_id
        read_by_handler = _requested_organization_id(request)

        assert checked_against == read_by_handler == REAL_ORG


# ============================================================================
# RequireOrganization
# ============================================================================


class TestRequireOrganization:
    @pytest.mark.asyncio
    async def test_returns_the_selected_organization(self) -> None:
        scope = OrganizationScope.for_organization(REAL_ORG)
        assert await RequireOrganization(scope=scope) == REAL_ORG

    @pytest.mark.asyncio
    async def test_refuses_an_all_organizations_request(self) -> None:
        """A per-tenant report has no honest all-organizations answer.

        Summing one across fourteen tenants produces a number that is true of
        nobody, so this refuses rather than inventing it.
        """
        with pytest.raises(SingleOrganizationRequiredError):
            await RequireOrganization(scope=OrganizationScope.all())
