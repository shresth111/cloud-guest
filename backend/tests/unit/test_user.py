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

import inspect
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.auth.dependencies import get_current_user
from app.domains.auth.jwt import JWTManager
from app.domains.auth.models import User
from app.domains.auth.service import EmailAlreadyExistsError, UsernameAlreadyExistsError
from app.domains.organization.enums import MembershipStatus, OrganizationType
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization, OrganizationMember
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.exceptions import PermissionDeniedError
from app.domains.rbac.models import Role, UserRole
from app.domains.user.exceptions import (
    CrossOrganizationUserAccessError,
    ImpersonationTargetInactiveError,
    InitialRoleRequiresOrganizationError,
    SelfDeactivationNotAllowedError,
    SelfImpersonationNotAllowedError,
    StaffImpersonationNotAllowedError,
)
from app.domains.user.router import router as user_router
from app.domains.user.service import UserService

from .test_rbac import FakeRBACRepository

STRONG_PASSWORD = "TempPass123!@#"


def _permission_keys(route: object) -> list[str]:
    """The permission strings a route's ``RequirePermission`` dependencies
    actually enforce -- mirrors ``test_channel_partner.py``'s own helper of
    the same name/shape (``RequirePermission`` is a closure factory, so the
    key lives in ``_dependency``'s nonlocals)."""
    return [
        inspect.getclosurevars(dependency.dependency).nonlocals["permission_key"]
        for dependency in route.dependencies  # type: ignore[attr-defined]
    ]

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
    # Records each force-logout's session revocation so the force_logout_user
    # test can assert the "real, immediate session termination" half of the
    # two-step flow actually happened (not just the tokens_invalidated_at
    # timestamp half).
    revoked_session_user_ids: list[uuid.UUID] = field(default_factory=list)

    async def get_user_by_id(self, user_id: uuid.UUID) -> User | None:
        return self.users_by_id.get(user_id)

    async def revoke_all_sessions(self, user_id: uuid.UUID) -> int:
        self.revoked_session_user_ids.append(user_id)
        return 1

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
    invite_requesting_organization_ids: list[uuid.UUID | None] = field(
        default_factory=list
    )

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
        requesting_organization_id: uuid.UUID | None,
        is_primary_contact: bool = False,
    ) -> OrganizationMember:
        # Recorded rather than ignored: this fake matching the real
        # signature is the whole reason these tests are worth running.
        # While it did not, every test here passed against a Protocol that
        # no longer described OrganizationService, and
        # /locations/provision returned 500 in production.
        self.invite_requesting_organization_ids.append(requesting_organization_id)
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

    async def test_create_user_passes_its_tenant_scope_into_invite_member(self) -> None:
        """`invite_member` performs its own tenant check and takes
        `requesting_organization_id` with no default precisely so a
        forgotten call site fails loudly. It was forgotten here, and
        `POST /locations/provision` returned 500 in production until it was
        passed. Asserting the value *arrives* rather than only that the
        signature accepts it: a call site that passed `None` to silence the
        TypeError would satisfy the signature and reopen the cross-tenant
        write the argument exists to prevent.
        """
        service, _identity, org_lookup, _assigner, _resolver, _audit = make_service()
        organization = org_lookup.add_organization()

        await service.create_user(
            **_create_kwargs(
                organization_id=organization.id,
                requesting_organization_id=organization.id,
            )
        )

        assert org_lookup.invite_requesting_organization_ids == [organization.id]

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
# Real invitation workflow (Enterprise SaaS Phase D)
# ============================================================================


@dataclass
class FakeNotificationSender:
    """In-memory stand-in for ``UserService.NotificationSenderProtocol``."""

    sent: list[dict[str, object]] = field(default_factory=list)

    async def enqueue(
        self,
        *,
        event_type,
        channel,
        recipient,
        body,
        organization_id,
        subject=None,
    ) -> dict[str, object]:
        record = {
            "event_type": event_type,
            "channel": channel,
            "recipient": recipient,
            "body": body,
            "organization_id": organization_id,
            "subject": subject,
        }
        self.sent.append(record)
        return record


def make_service_with_notifications() -> tuple[
    UserService,
    FakeIdentityRepository,
    FakeOrganizationLookup,
    FakeRoleAssigner,
    FakeRoleResolver,
    FakeAuditLogWriter,
    FakeNotificationSender,
]:
    identity_repository = FakeIdentityRepository()
    organization_lookup = FakeOrganizationLookup()
    role_assigner = FakeRoleAssigner()
    role_resolver = FakeRoleResolver()
    audit_writer = FakeAuditLogWriter()
    notification_sender = FakeNotificationSender()
    service = UserService(
        identity_repository,
        organization_lookup,
        role_assigner,
        role_resolver,
        audit_writer=audit_writer,
        notification_service=notification_sender,
    )
    return (
        service,
        identity_repository,
        organization_lookup,
        role_assigner,
        role_resolver,
        audit_writer,
        notification_sender,
    )


def _invite_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "actor_user_id": uuid.uuid4(),
        "first_name": "Jamie",
        "last_name": "Rivera",
        "email": "jamie@example.com",
        "username": "jamie",
        "requesting_organization_id": None,
    }
    base.update(overrides)
    return base


class TestUserInvitation:
    async def test_invite_generates_a_real_random_password(self) -> None:
        service, *_rest = make_service_with_notifications()

        result = await service.invite_user(**_invite_kwargs())

        assert len(result.temporary_password) >= 12
        assert result.temporary_password != STRONG_PASSWORD
        assert any(c.isupper() for c in result.temporary_password)
        assert any(c.islower() for c in result.temporary_password)
        assert any(c.isdigit() for c in result.temporary_password)

    async def test_invite_forces_password_change_on_first_login(self) -> None:
        service, *_rest = make_service_with_notifications()

        result = await service.invite_user(**_invite_kwargs())

        assert result.user.must_change_password is True

    async def test_invite_sends_a_real_email_with_credentials(self) -> None:
        service, *_rest, notification_sender = make_service_with_notifications()

        result = await service.invite_user(**_invite_kwargs())

        assert len(notification_sender.sent) == 1
        sent = notification_sender.sent[0]
        assert sent["recipient"] == "jamie@example.com"
        assert result.temporary_password in sent["body"]
        assert "jamie" in sent["body"]

    async def test_invite_two_different_users_get_different_passwords(self) -> None:
        service, *_rest = make_service_with_notifications()

        first = await service.invite_user(**_invite_kwargs())
        second = await service.invite_user(
            **_invite_kwargs(email="other@example.com", username="other")
        )

        assert first.temporary_password != second.temporary_password

    async def test_invite_rejects_duplicate_email(self) -> None:
        service, *_rest = make_service_with_notifications()
        await service.invite_user(**_invite_kwargs())

        with pytest.raises(EmailAlreadyExistsError):
            await service.invite_user(**_invite_kwargs(username="someoneelse"))

    async def test_invite_with_organization_creates_active_membership(self) -> None:
        service, _identity, org_lookup, *_rest = make_service_with_notifications()
        organization = org_lookup.add_organization()

        result = await service.invite_user(
            **_invite_kwargs(organization_id=organization.id)
        )

        memberships = [
            m for m in org_lookup.member_rows if m.organization_id == organization.id
        ]
        assert any(m.user_id == result.user.id for m in memberships)

    async def test_no_real_notification_sender_falls_back_to_noop(self) -> None:
        """Mirrors ``AuthService``'s own ``_NoopNotificationSender``
        precedent -- an unwired invite still succeeds (logged, not
        faked, not silently dropped, and never raises)."""
        service, *_rest = make_service()

        result = await service.invite_user(**_invite_kwargs())

        assert result.user.email == "jamie@example.com"


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
# Response schema -- serializing an already-persisted, non-`EmailStr`-
# validating email
# ============================================================================


class TestUserResponseAcceptsAnyPersistedEmail:
    """Live outage, reproduced: a demo/seed account's
    ``demo-owner-brewline@demo.invalid`` address (created directly via
    ``UserService.create_user``, not through the ``EmailStr``-validated
    ``UserCreateRequest``/``InviteUserRequest`` HTTP schemas) made pydantic
    raise while constructing the response for the whole ``GET /users`` list
    -- one row with an RFC 2606 special-use domain 500'd every caller, not
    just a request touching that row. ``UserResponse.email`` is `str`
    for exactly this reason: it serializes what's already in the database,
    it does not re-validate it."""

    def test_user_schemas_user_response_accepts_special_use_domain(self) -> None:
        from app.domains.user.schemas import UserResponse

        now = datetime.now(UTC)
        response = UserResponse(
            id="00000000-0000-0000-0000-000000000000",
            first_name="Demo",
            last_name="Owner",
            full_name="Demo Owner",
            email="demo-owner-brewline@demo.invalid",
            username="demo-owner-brewline",
            timezone="UTC",
            language="en",
            status="active",
            is_active=True,
            is_verified=False,
            data_masking_enabled=False,
            created_at=now,
            updated_at=now,
        )
        assert response.email == "demo-owner-brewline@demo.invalid"

    def test_auth_schemas_user_response_accepts_special_use_domain(self) -> None:
        from app.domains.auth.schemas import UserResponse as AuthUserResponse

        now = datetime.now(UTC)
        response = AuthUserResponse(
            id="00000000-0000-0000-0000-000000000000",
            first_name="Demo",
            last_name="Owner",
            email="demo-owner-brewline@demo.invalid",
            username="demo-owner-brewline",
            timezone="UTC",
            language="en",
            status="active",
            created_at=now,
            updated_at=now,
        )
        assert response.email == "demo-owner-brewline@demo.invalid"


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

    async def test_force_logout_revokes_sessions_and_sets_invalidation_timestamp(
        self,
    ) -> None:
        """The "revoke access when someone leaves" action's real teeth:
        force_logout does BOTH halves -- revokes existing sessions (so a
        still-valid refresh token can't mint a fresh access token) AND sets
        ``tokens_invalidated_at`` (so an already-issued access token is
        rejected on its next request) -- while leaving ``is_active``
        untouched. See ``UserService.force_logout_user``'s own docstring."""
        service, identity, *_rest, audit = make_service()
        user = await service.create_user(**_create_kwargs())

        updated = await service.force_logout_user(
            actor_user_id=uuid.uuid4(),
            user_id=user.id,
            requesting_organization_id=None,
        )

        assert user.id in identity.revoked_session_user_ids
        assert updated.tokens_invalidated_at is not None
        assert updated.is_active is True  # account itself stays usable
        assert any(e["action"] == "user_force_logged_out" for e in audit.entries)

    async def test_force_logged_out_user_token_issued_before_is_rejected(self) -> None:
        """Adversarial "revoked-token" case: an access token minted *before*
        an admin force-logout must be rejected on its very next request,
        even though its own ``exp`` hasn't lapsed -- proving revoke actually
        kills a live session, not just future logins."""
        service, identity, *_rest = make_service()
        user = await service.create_user(**_create_kwargs())

        token, _jti = JWTManager.create_access_token(str(user.id), user.email)
        await service.force_logout_user(
            actor_user_id=uuid.uuid4(),
            user_id=user.id,
            requesting_organization_id=None,
        )

        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(
                request=request,
                credentials=credentials,
                repository=identity,
                api_key_service=None,
            )

        assert exc_info.value.status_code == 401

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
        request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(
                request=request,
                credentials=credentials,
                repository=identity,
                api_key_service=None,
            )

        assert exc_info.value.status_code == 401


# ============================================================================
# Impersonation ("staff can impersonate a customer to view their
# dashboard") -- see ``UserService.impersonate_user``'s own docstring for
# the full validation/audit contract.
# ============================================================================


class TestImpersonation:
    async def test_impersonate_mints_target_identity_token_and_audits(self) -> None:
        service, *_rest, audit = make_service()
        target = await service.create_user(**_create_kwargs())
        actor_id = uuid.uuid4()
        actor_email = "operator@wyfy.test"
        before = datetime.now(UTC)

        result = await service.impersonate_user(
            actor_user_id=actor_id,
            actor_email=actor_email,
            user_id=target.id,
            reason="Investigating a support ticket",
        )

        # -- response shape --------------------------------------------------
        assert result.target_user.id == target.id
        assert result.expires_at > before

        # -- the minted token identifies the TARGET, not the actor ----------
        payload = JWTManager.decode(result.access_token)
        assert payload["sub"] == str(target.id)
        assert payload["email"] == target.email
        assert payload["type"] == "access"

        # -- deliberately shorter than a normal login session ---------------
        assert payload["exp"] - payload["iat"] == 30 * 60

        # -- the impersonation claim identifies the real actor ---------------
        claim = payload["impersonation"]
        assert claim["actor_user_id"] == str(actor_id)
        assert claim["actor_email"] == actor_email
        assert "started_at" in claim

        # -- every start is audited ------------------------------------------
        entry = next(e for e in audit.entries if e["action"] == "impersonation_started")
        assert entry["actor_user_id"] == actor_id
        assert entry["entity_type"] == "user"
        assert entry["entity_id"] == target.id
        assert entry["event_metadata"]["reason"] == "Investigating a support ticket"
        assert entry["event_metadata"]["target_email"] == target.email
        assert "expires_at" in entry["event_metadata"]

    async def test_impersonate_with_no_reason_audits_a_null_reason(self) -> None:
        service, *_rest, audit = make_service()
        target = await service.create_user(**_create_kwargs())

        await service.impersonate_user(
            actor_user_id=uuid.uuid4(),
            actor_email="operator@wyfy.test",
            user_id=target.id,
            reason=None,
        )

        entry = next(e for e in audit.entries if e["action"] == "impersonation_started")
        assert entry["event_metadata"]["reason"] is None

    async def test_rejects_impersonating_an_inactive_user(self) -> None:
        service, *_rest = make_service()
        target = await service.create_user(**_create_kwargs())
        await service.deactivate_user(
            actor_user_id=uuid.uuid4(),
            user_id=target.id,
            requesting_organization_id=None,
        )

        with pytest.raises(ImpersonationTargetInactiveError) as exc_info:
            await service.impersonate_user(
                actor_user_id=uuid.uuid4(),
                actor_email="operator@wyfy.test",
                user_id=target.id,
                reason=None,
            )
        assert exc_info.value.status_code == 409

    async def test_rejects_impersonating_a_user_holding_a_global_role(self) -> None:
        """The privilege-escalation-chain guard: a target holding ANY
        active GLOBAL-scope role (a platform staff/operator account, not a
        customer) can never be impersonated."""
        service, _identity, _org, _assigner, role_resolver, _audit = make_service()
        target = await service.create_user(**_create_kwargs())
        role_resolver.add_role(
            target.id,
            name="Platform Support",
            slug="platform-support",
            scope_type=ScopeType.GLOBAL,
        )

        with pytest.raises(StaffImpersonationNotAllowedError) as exc_info:
            await service.impersonate_user(
                actor_user_id=uuid.uuid4(),
                actor_email="operator@wyfy.test",
                user_id=target.id,
                reason=None,
            )
        assert exc_info.value.status_code == 403

    async def test_org_scoped_role_does_not_block_impersonation(self) -> None:
        """Contrast case for the guard above: an ordinary org/location-
        scoped role on the target (a real customer with real roles in
        their own organization) must NOT trip the "holds a global role"
        rejection."""
        service, _identity, _org, _assigner, role_resolver, _audit = make_service()
        target = await service.create_user(**_create_kwargs())
        role_resolver.add_role(
            target.id,
            name="Location Manager",
            slug="location-manager",
            scope_type=ScopeType.ORGANIZATION,
        )

        result = await service.impersonate_user(
            actor_user_id=uuid.uuid4(),
            actor_email="operator@wyfy.test",
            user_id=target.id,
            reason=None,
        )
        assert result.target_user.id == target.id

    async def test_rejects_self_impersonation(self) -> None:
        service, *_rest = make_service()
        user = await service.create_user(**_create_kwargs())

        with pytest.raises(SelfImpersonationNotAllowedError) as exc_info:
            await service.impersonate_user(
                actor_user_id=user.id,
                actor_email=user.email,
                user_id=user.id,
                reason=None,
            )
        assert exc_info.value.status_code == 400


class TestImpersonateRouteRequiresPermission:
    """A genuine, executable 403 for the ``users.impersonate``-gated route,
    the same "underlying AccessValidator.check logic is what's exercised"
    convention ``test_channel_partner.py``'s own
    ``TestRevokeRequiresManagePermission`` establishes."""

    def _route(self):
        return next(
            route
            for route in user_router.routes
            if route.path.endswith("/impersonate")
        )

    def test_route_is_gated_by_users_impersonate(self) -> None:
        route = self._route()
        assert route.methods == {"POST"}
        assert _permission_keys(route) == ["users.impersonate"]

    def test_route_checks_global_scope_explicitly(self) -> None:
        """The endpoint must only ever succeed for a caller holding a
        genuinely platform-wide role -- checked via an explicit
        ``scope=ScopeType.GLOBAL``, not left to be inferred from whatever
        ``X-Organization-Id`` header happens to be on the request."""
        route = self._route()
        (dependency,) = route.dependencies
        nonlocals = inspect.getclosurevars(dependency.dependency).nonlocals
        assert nonlocals["scope"] == ScopeType.GLOBAL

    async def test_actor_without_impersonate_permission_gets_403(self) -> None:
        route = self._route()
        (permission_key,) = _permission_keys(route)
        validator = AccessValidator(FakeRBACRepository())

        with pytest.raises(PermissionDeniedError) as exc_info:
            await validator.check(
                uuid.uuid4(), permission_key, scope_type=ScopeType.GLOBAL
            )

        assert exc_info.value.status_code == 403
