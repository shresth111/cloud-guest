"""Unit tests for the User management/aggregation domain (Module 007):
admin-driven account creation (with/without an organization + initial role),
tenant-scoped listing/search, aggregated user-detail assembly, admin-vs-self
profile-update field restrictions, deactivate/reactivate (including that a
deactivated user fails ``auth.dependencies.get_current_user``'s
``is_active`` check), and duplicate-email/username rejection.

Follows this project's plain-``assert`` / native-``async def`` style (see
``tests/unit/test_organization.py``, ``tests/unit/test_location.py``);
``asyncio_mode = "auto"`` runs async tests directly. Exercises
``UserService`` against small in-memory fakes for each of the narrow
protocols it composes (``IdentityRepositoryProtocol``,
``OrganizationLookupProtocol``, ``RoleAssignmentProtocol``,
``RoleResolverProtocol``, ``AuditLogWriter``), mirroring
``FakeOrganizationRepository``/``FakeLocationRepository``, since there is no
live Postgres/Redis in this environment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.auth.dependencies import get_current_user
from app.domains.auth.jwt import JWTManager
from app.domains.auth.models import User
from app.domains.auth.service import EmailAlreadyExistsError, UsernameAlreadyExistsError
from app.domains.organization.enums import MembershipStatus, OrganizationType
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization, OrganizationMember
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.models import Role, UserRole
from app.domains.user.exceptions import (
    CrossOrganizationUserAccessError,
    InitialRoleRequiresOrganizationError,
    SelfDeactivationNotAllowedError,
)
from app.domains.user.service import UserService

STRONG_PASSWORD = "TempPass123!@#"

# ============================================================================
# Test doubles
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakeIdentityRepository:
    """In-memory stand-in for ``UserService.IdentityRepositoryProtocol``
    (a narrow subset of the real ``AuthRepositoryProtocol``)."""

    users_by_id: dict[uuid.UUID, User] = field(default_factory=dict)

    async def get_user_by_id(self, user_id: uuid.UUID) -> User | None:
        return self.users_by_id.get(user_id)

    async def get_user_by_email(self, email: str) -> User | None:
        return next(
            (u for u in self.users_by_id.values() if u.email == email.lower()), None
        )

    async def get_user_by_username(self, username: str) -> User | None:
        return next(
            (u for u in self.users_by_id.values() if u.username == username.lower()),
            None,
        )

    async def create_user(self, **fields: object) -> User:
        # SQLAlchemy's Python-side column defaults (e.g. failed_login_attempts=0)
        # are only applied on flush to a real engine; since these objects are
        # never flushed here, fill in the same defaults a real insert would
        # (mirrors ``FakeAuthRepository.create_user`` in ``test_auth.py``).
        defaults: dict[str, object] = {
            "status": "active",
            "failed_login_attempts": 0,
            "locked_until": None,
            "email_verified_at": None,
            "phone_verified_at": None,
            "last_login_at": None,
            "password_changed_at": None,
            "phone": None,
            "profile_photo": None,
            "designation": None,
            "department": None,
            "employee_id": None,
            "password_hash": "unused-in-tests",
            "must_change_password": False,
        }
        user = User(
            **_base_fields(
                **{
                    **defaults,
                    **fields,
                    "email": str(fields["email"]).lower(),
                    "username": str(fields["username"]).lower(),
                }
            )
        )
        self.users_by_id[user.id] = user
        return user

    async def update_user(self, user: User, **fields: object) -> User:
        for key, value in fields.items():
            setattr(user, key, value)
        user.version += 1
        return user

    async def list_users(
        self,
        *,
        page: int,
        page_size: int,
        search: str | None = None,
        is_active: bool | None = None,
        user_ids: list[uuid.UUID] | None = None,
    ) -> tuple[list[User], PaginationMeta]:
        values = list(self.users_by_id.values())
        if is_active is not None:
            values = [u for u in values if u.is_active == is_active]
        if user_ids is not None:
            id_set = set(user_ids)
            values = [u for u in values if u.id in id_set]
        if search:
            lowered = search.lower()
            values = [
                u
                for u in values
                if lowered in u.first_name.lower()
                or lowered in u.last_name.lower()
                or lowered in u.email.lower()
                or lowered in u.username.lower()
            ]
        values.sort(key=lambda u: u.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))


@dataclass
class FakeOrganizationLookup:
    """In-memory stand-in for ``UserService.OrganizationLookupProtocol``
    (a narrow subset of the real ``OrganizationService``)."""

    organizations: dict[uuid.UUID, Organization] = field(default_factory=dict)
    member_rows: list[OrganizationMember] = field(default_factory=list)

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization:
        organization = self.organizations.get(organization_id)
        if organization is None or (organization.is_deleted and not include_deleted):
            raise OrganizationNotFoundError(organization_id)
        return organization

    async def list_children(self, organization_id: uuid.UUID) -> list[Organization]:
        return [
            org
            for org in self.organizations.values()
            if org.parent_organization_id == organization_id
        ]

    async def list_members(
        self, organization_id: uuid.UUID, *, status: MembershipStatus | None = None
    ) -> list[OrganizationMember]:
        rows = [r for r in self.member_rows if r.organization_id == organization_id]
        if status is not None:
            rows = [r for r in rows if r.status == status.value]
        return rows

    async def list_user_organizations(
        self, user_id: uuid.UUID, *, status: MembershipStatus | None = None
    ) -> list[OrganizationMember]:
        rows = [r for r in self.member_rows if r.user_id == user_id]
        if status is not None:
            rows = [r for r in rows if r.status == status.value]
        return rows

    async def invite_member(
        self,
        *,
        actor_user_id: uuid.UUID,
        organization_id: uuid.UUID,
        user_id: uuid.UUID,
        is_primary_contact: bool = False,
    ) -> OrganizationMember:
        member = OrganizationMember(
            **_base_fields(
                organization_id=organization_id,
                user_id=user_id,
                status=MembershipStatus.INVITED.value,
                invited_by_user_id=actor_user_id,
                invited_at=_now(),
                joined_at=None,
                is_primary_contact=is_primary_contact,
            )
        )
        self.member_rows.append(member)
        return member

    async def accept_invite(
        self, *, user_id: uuid.UUID, organization_id: uuid.UUID, member_id: uuid.UUID
    ) -> OrganizationMember:
        member = next(r for r in self.member_rows if r.id == member_id)
        member.status = MembershipStatus.ACTIVE.value
        member.joined_at = _now()
        return member

    def add_organization(
        self,
        *,
        name: str = "Org",
        org_type: str = OrganizationType.STANDARD.value,
        status: str = "active",
        parent_organization_id: uuid.UUID | None = None,
    ) -> Organization:
        organization = Organization(
            **_base_fields(
                name=name,
                slug=f"org-{uuid.uuid4()}",
                legal_name=None,
                org_type=org_type,
                status=status,
                parent_organization_id=parent_organization_id,
                contact_email="admin@example.com",
                contact_phone=None,
                timezone="UTC",
                default_locale="en",
                settings={},
                subscription_tier=None,
            )
        )
        self.organizations[organization.id] = organization
        return organization

    def add_active_member(
        self, *, organization_id: uuid.UUID, user_id: uuid.UUID
    ) -> OrganizationMember:
        member = OrganizationMember(
            **_base_fields(
                organization_id=organization_id,
                user_id=user_id,
                status=MembershipStatus.ACTIVE.value,
                invited_by_user_id=None,
                invited_at=_now(),
                joined_at=_now(),
                is_primary_contact=False,
            )
        )
        self.member_rows.append(member)
        return member


@dataclass
class FakeRoleAssigner:
    """In-memory stand-in for ``UserService.RoleAssignmentProtocol`` (a
    narrow subset of the real ``RBACService``)."""

    calls: list[dict[str, object]] = field(default_factory=list)

    async def assign_role_to_user(self, **kwargs: object) -> UserRole:
        self.calls.append(kwargs)
        return UserRole(
            **_base_fields(
                user_id=kwargs["target_user_id"],
                role_id=kwargs["role_id"],
                scope_type=kwargs["scope_type"].value,  # type: ignore[union-attr]
                msp_id=None,
                organization_id=kwargs.get("organization_id"),
                location_id=kwargs.get("location_id"),
                router_id=kwargs.get("router_id"),
                granted_at=_now(),
                granted_by=kwargs["actor_user_id"],
                expires_at=kwargs.get("expires_at"),
                is_active=True,
            )
        )


@dataclass
class FakeRoleResolver:
    """In-memory stand-in for ``UserService.RoleResolverProtocol`` (a
    narrow subset of RBAC's real ``RoleResolver``)."""

    roles_by_user: dict[uuid.UUID, list[Role]] = field(default_factory=dict)

    async def get_active_roles(
        self, user_id: uuid.UUID, **_kwargs: object
    ) -> list[Role]:
        return self.roles_by_user.get(user_id, [])

    def add_role(
        self,
        user_id: uuid.UUID,
        *,
        name: str = "Location Manager",
        slug: str = "location-manager",
        scope_type: ScopeType = ScopeType.ORGANIZATION,
        organization_id: uuid.UUID | None = None,
    ) -> Role:
        role = Role(
            **_base_fields(
                name=name,
                slug=slug,
                description=None,
                is_system_role=True,
                is_template=False,
                is_active=True,
                scope_type=scope_type.value,
                organization_id=organization_id,
                parent_role_id=None,
            )
        )
        self.roles_by_user.setdefault(user_id, []).append(role)
        return role


@dataclass
class FakeAuditLogWriter:
    """In-memory stand-in for the ``AuditLogWriter`` protocol, mirroring
    ``test_organization.py``'s/``test_location.py``'s own fake."""

    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


def make_service() -> (
    tuple[
        UserService,
        FakeIdentityRepository,
        FakeOrganizationLookup,
        FakeRoleAssigner,
        FakeRoleResolver,
        FakeAuditLogWriter,
    ]
):
    identity_repository = FakeIdentityRepository()
    organization_lookup = FakeOrganizationLookup()
    role_assigner = FakeRoleAssigner()
    role_resolver = FakeRoleResolver()
    audit_writer = FakeAuditLogWriter()
    service = UserService(
        identity_repository,
        organization_lookup,
        role_assigner,
        role_resolver,
        audit_writer=audit_writer,
    )
    return (
        service,
        identity_repository,
        organization_lookup,
        role_assigner,
        role_resolver,
        audit_writer,
    )


def _create_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "actor_user_id": uuid.uuid4(),
        "first_name": "Jamie",
        "last_name": "Rivera",
        "email": "jamie@example.com",
        "username": "jamie",
        "temporary_password": STRONG_PASSWORD,
        "requesting_organization_id": None,
    }
    base.update(overrides)
    return base


# ============================================================================
# Admin-driven user creation
# ============================================================================


class TestUserCreation:
    async def test_create_user_without_org_or_role(self) -> None:
        service, _identity, _org, role_assigner, _resolver, audit = make_service()

        user = await service.create_user(**_create_kwargs())

        assert user.email == "jamie@example.com"
        assert user.username == "jamie"
        assert user.is_active is True
        assert user.is_verified is True
        assert role_assigner.calls == []
        assert any(e["action"] == "user_created" for e in audit.entries)

    async def test_create_user_with_org_creates_active_membership(self) -> None:
        service, _identity, org_lookup, _assigner, _resolver, _audit = make_service()
        organization = org_lookup.add_organization()

        user = await service.create_user(
            **_create_kwargs(organization_id=organization.id)
        )

        memberships = [m for m in org_lookup.member_rows if m.user_id == user.id]
        assert len(memberships) == 1
        assert memberships[0].status == MembershipStatus.ACTIVE.value
        assert memberships[0].joined_at is not None

    async def test_create_user_with_org_and_initial_role_assigns_role(self) -> None:
        service, _identity, org_lookup, role_assigner, _resolver, _audit = (
            make_service()
        )
        organization = org_lookup.add_organization()
        role_id = uuid.uuid4()

        user = await service.create_user(
            **_create_kwargs(organization_id=organization.id, initial_role_id=role_id)
        )

        assert len(role_assigner.calls) == 1
        call = role_assigner.calls[0]
        assert call["target_user_id"] == user.id
        assert call["role_id"] == role_id
        assert call["scope_type"] == ScopeType.ORGANIZATION
        assert call["organization_id"] == organization.id

    async def test_create_user_initial_role_without_organization_raises(self) -> None:
        service, *_rest = make_service()

        with pytest.raises(InitialRoleRequiresOrganizationError):
            await service.create_user(**_create_kwargs(initial_role_id=uuid.uuid4()))

    async def test_create_user_rejects_duplicate_email(self) -> None:
        service, *_rest = make_service()
        await service.create_user(**_create_kwargs())

        with pytest.raises(EmailAlreadyExistsError):
            await service.create_user(**_create_kwargs(username="someoneelse"))

    async def test_create_user_rejects_duplicate_username(self) -> None:
        service, *_rest = make_service()
        await service.create_user(**_create_kwargs())

        with pytest.raises(UsernameAlreadyExistsError):
            await service.create_user(**_create_kwargs(email="other@example.com"))

    async def test_create_user_into_organization_outside_scope_raises(self) -> None:
        service, _identity, org_lookup, *_rest = make_service()
        org_a = org_lookup.add_organization(name="Org A")
        org_b = org_lookup.add_organization(name="Org B")

        with pytest.raises(CrossOrganizationUserAccessError):
            await service.create_user(
                **_create_kwargs(
                    organization_id=org_b.id, requesting_organization_id=org_a.id
                )
            )


# ============================================================================
# Tenant-scoped listing / search
# ============================================================================


class TestListingAndScoping:
    async def test_platform_scope_lists_all_users(self) -> None:
        service, _identity, _org, *_rest = make_service()
        await service.create_user(**_create_kwargs(email="a@example.com", username="a"))
        await service.create_user(**_create_kwargs(email="b@example.com", username="b"))

        users, meta = await service.list_users(requesting_organization_id=None)

        assert meta.total_items == 2
        assert {u.email for u in users} == {"a@example.com", "b@example.com"}

    async def test_org_scoped_lists_only_org_members(self) -> None:
        service, _identity, org_lookup, *_rest = make_service()
        org_a = org_lookup.add_organization(name="Org A")
        org_b = org_lookup.add_organization(name="Org B")
        member_of_a = await service.create_user(
            **_create_kwargs(
                email="member-a@example.com",
                username="membera",
                organization_id=org_a.id,
            )
        )
        await service.create_user(
            **_create_kwargs(
                email="member-b@example.com",
                username="memberb",
                organization_id=org_b.id,
            )
        )

        users, meta = await service.list_users(requesting_organization_id=org_a.id)

        assert meta.total_items == 1
        assert users[0].id == member_of_a.id

    async def test_org_scoped_msp_includes_child_org_members(self) -> None:
        service, _identity, org_lookup, *_rest = make_service()
        msp = org_lookup.add_organization(
            name="Reseller MSP", org_type=OrganizationType.MSP.value
        )
        child = org_lookup.add_organization(
            name="Client A", parent_organization_id=msp.id
        )
        child_member = await service.create_user(
            **_create_kwargs(
                email="child-member@example.com",
                username="childmember",
                organization_id=child.id,
            )
        )

        users, meta = await service.list_users(requesting_organization_id=msp.id)

        assert meta.total_items == 1
        assert users[0].id == child_member.id

    async def test_search_filters_by_name_or_email(self) -> None:
        service, *_rest = make_service()
        await service.create_user(
            **_create_kwargs(
                first_name="Alice",
                last_name="Anderson",
                email="alice@example.com",
                username="alice",
            )
        )
        await service.create_user(
            **_create_kwargs(
                first_name="Bob",
                last_name="Baker",
                email="bob@example.com",
                username="bob",
            )
        )

        users, meta = await service.list_users(
            requesting_organization_id=None, search="alice"
        )

        assert meta.total_items == 1
        assert users[0].email == "alice@example.com"


# ============================================================================
# Aggregated user detail
# ============================================================================


class TestAggregatedDetail:
    async def test_get_user_detail_assembles_identity_memberships_roles(self) -> None:
        service, _identity, org_lookup, _assigner, role_resolver, _audit = (
            make_service()
        )
        organization = org_lookup.add_organization(name="Acme Corp")
        user = await service.create_user(
            **_create_kwargs(organization_id=organization.id)
        )
        role_resolver.add_role(user.id, organization_id=organization.id)

        aggregate = await service.get_user_detail(
            user.id, requesting_organization_id=None
        )

        assert aggregate.user.id == user.id
        assert len(aggregate.memberships) == 1
        assert aggregate.memberships[0].organization_name == "Acme Corp"
        assert aggregate.memberships[0].membership.status == (
            MembershipStatus.ACTIVE.value
        )
        assert len(aggregate.roles) == 1
        assert aggregate.roles[0].slug == "location-manager"

    async def test_get_user_detail_cross_organization_raises(self) -> None:
        service, _identity, org_lookup, *_rest = make_service()
        org_a = org_lookup.add_organization(name="Org A")
        org_b = org_lookup.add_organization(name="Org B")
        user = await service.create_user(**_create_kwargs(organization_id=org_b.id))

        with pytest.raises(CrossOrganizationUserAccessError):
            await service.get_user_detail(user.id, requesting_organization_id=org_a.id)

    async def test_get_me_is_never_tenant_scoped(self) -> None:
        service, *_rest = make_service()
        user = await service.create_user(**_create_kwargs())

        aggregate = await service.get_me(user.id)

        assert aggregate.user.id == user.id
        assert aggregate.memberships == []
        assert aggregate.roles == []


# ============================================================================
# Profile update: admin vs. self field restrictions
# ============================================================================


class TestProfileUpdate:
    async def test_admin_update_applies_admin_editable_fields(self) -> None:
        service, *_rest = make_service()
        user = await service.create_user(**_create_kwargs())

        updated = await service.update_user(
            actor_user_id=uuid.uuid4(),
            user_id=user.id,
            requesting_organization_id=None,
            data={"designation": "VP Engineering", "is_verified": False},
        )

        assert updated.designation == "VP Engineering"
        assert updated.is_verified is False

    async def test_admin_update_ignores_email_and_status_fields(self) -> None:
        """``email``/``is_active``/``status`` are not admin-editable via this
        endpoint (see ``ADMIN_EDITABLE_FIELDS``) -- even if a caller
        constructs the ``data`` dict by hand with those keys, they must be
        silently dropped, not applied."""
        service, *_rest = make_service()
        user = await service.create_user(**_create_kwargs())
        original_email = user.email

        updated = await service.update_user(
            actor_user_id=uuid.uuid4(),
            user_id=user.id,
            requesting_organization_id=None,
            data={"email": "changed@example.com", "is_active": False, "status": "x"},
        )

        assert updated.email == original_email
        assert updated.is_active is True

    async def test_self_update_allows_only_self_editable_fields(self) -> None:
        service, *_rest = make_service()
        user = await service.create_user(**_create_kwargs())

        updated = await service.update_self(
            user_id=user.id,
            data={
                "first_name": "Jamie-Updated",
                "designation": "Should Not Apply",
                "is_verified": False,
            },
        )

        assert updated.first_name == "Jamie-Updated"
        assert updated.designation is None
        assert updated.is_verified is True


# ============================================================================
# Deactivate / reactivate
# ============================================================================


class TestDeactivateReactivate:
    async def test_deactivate_sets_inactive_and_audits(self) -> None:
        service, *_rest, audit = make_service()
        user = await service.create_user(**_create_kwargs())

        updated = await service.deactivate_user(
            actor_user_id=uuid.uuid4(),
            user_id=user.id,
            requesting_organization_id=None,
        )

        assert updated.is_active is False
        assert updated.status == "inactive"
        assert any(e["action"] == "user_deactivated" for e in audit.entries)

    async def test_admin_cannot_deactivate_self(self) -> None:
        service, *_rest = make_service()
        user = await service.create_user(**_create_kwargs())

        with pytest.raises(SelfDeactivationNotAllowedError):
            await service.deactivate_user(
                actor_user_id=user.id,
                user_id=user.id,
                requesting_organization_id=None,
            )

    async def test_reactivate_clears_lockout_and_sets_active(self) -> None:
        service, identity, *_rest, audit = make_service()
        user = await service.create_user(**_create_kwargs())
        await service.deactivate_user(
            actor_user_id=uuid.uuid4(), user_id=user.id, requesting_organization_id=None
        )
        user.failed_login_attempts = 5
        user.locked_until = _now()

        updated = await service.reactivate_user(
            actor_user_id=uuid.uuid4(),
            user_id=user.id,
            requesting_organization_id=None,
        )

        assert updated.is_active is True
        assert updated.status == "active"
        assert updated.failed_login_attempts == 0
        assert updated.locked_until is None
        assert any(e["action"] == "user_reactivated" for e in audit.entries)

    async def test_deactivated_user_fails_get_current_user_active_check(self) -> None:
        """Confirms ``auth.dependencies.get_current_user`` (Module 003)
        already rejects a deactivated user's access token -- deactivation
        through this module needs no separate session-revocation step."""
        service, identity, *_rest = make_service()
        user = await service.create_user(**_create_kwargs())
        await service.deactivate_user(
            actor_user_id=uuid.uuid4(), user_id=user.id, requesting_organization_id=None
        )

        token, _jti = JWTManager.create_access_token(str(user.id), user.email)
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials=credentials, repository=identity)

        assert exc_info.value.status_code == 401
