"""User management/aggregation business logic.

Composes three existing domains rather than owning a persisted model of its
own (see the module ``__init__.py`` docstring and
``docs/user/USER_ARCHITECTURE.md`` for the full design):

* ``app.domains.auth`` for identity CRUD (``IdentityRepositoryProtocol`` --
  a narrow, duck-typed subset of ``AuthRepositoryProtocol``, the same
  compose-not-duplicate pattern ``LocationService`` uses for
  ``OrganizationLookupProtocol``).
* ``app.domains.organization`` for membership (``OrganizationLookupProtocol``
  -- the exact public surface of ``OrganizationService`` this domain needs:
  membership reads/writes and MSP-hierarchy reads for tenant scoping).
* ``app.domains.rbac`` for roles: ``RoleAssignmentProtocol`` (the exact
  shape of ``RBACService.assign_role_to_user``, used only as an *optional
  convenience* at creation time -- this domain never reimplements RBAC's own
  role-assignment/removal endpoints) and ``RoleResolverProtocol`` (the exact
  shape of ``RoleResolver.get_active_roles``, used for the aggregated detail
  view's "active roles" section).

Audit logging reuses RBAC's ``audit_log_entries`` table via the same narrow
``AuditLogWriter`` protocol shape ``OrganizationService``/``LocationService``
use.
"""

from __future__ import annotations

import logging
import secrets
import string
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from app.common.exceptions import CloudGuestError
from app.core.config import get_settings
from app.core.email_layout import (
    button,
    esc,
    heading,
    info_box,
    paragraph,
    render_email,
)
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.jwt import JWTManager
from app.domains.auth.models import User
from app.domains.auth.password import PasswordManager, PasswordStrengthError
from app.domains.auth.service import EmailAlreadyExistsError, UsernameAlreadyExistsError
from app.domains.notification.constants import (
    NotificationChannelType,
    NotificationEventType,
)
from app.domains.organization.enums import MembershipStatus
from app.domains.organization.models import Organization, OrganizationMember
from app.domains.rbac.context import ScopeContext
from app.domains.rbac.enums import AuditAction, ScopeType
from app.domains.rbac.models import Role, UserRole

from .enums import UserAccountStatus
from .exceptions import (
    CrossOrganizationUserAccessError,
    ImpersonationTargetInactiveError,
    InitialRoleRequiresOrganizationError,
    SelfDeactivationNotAllowedError,
    SelfImpersonationNotAllowedError,
    StaffImpersonationNotAllowedError,
    UserNotFoundError,
    UserPasswordTooWeakError,
)

# An impersonation session is deliberately shorter-lived than a normal
# login session (``settings.access_token_expire_minutes``) -- staff acting
# as a customer should have to re-mint the session to keep working, on
# principle, regardless of how long a normal login token is configured
# for. Hard-coded rather than a ``Settings`` field: this is a fixed
# security property of the feature, not an operator-tunable knob.
IMPERSONATION_ACCESS_TOKEN_EXPIRE_MINUTES = 30

logger = logging.getLogger(__name__)

# Fields an administrator may set via ``PUT /api/v1/users/{id}``.
# Deliberately excludes ``email``/``username`` (a login-identifier change is
# a sensitive auth-domain operation -- re-verification, uniqueness re-check,
# notification -- out of scope for this aggregation layer's endpoints; see
# ``docs/user/USER_ARCHITECTURE.md``) and ``is_active``/``status`` (owned
# exclusively by the dedicated ``deactivate``/``activate`` endpoints, the
# same "one way to do it" convention ``LocationUpdateRequest`` uses for
# ``status``).
ADMIN_EDITABLE_FIELDS: frozenset[str] = frozenset(
    {
        "first_name",
        "last_name",
        "phone",
        "profile_photo",
        "designation",
        "department",
        "employee_id",
        "timezone",
        "language",
        "is_verified",
        "data_masking_enabled",
    }
)

# Fields a user may set on their own profile via ``PUT /api/v1/me``.
# Narrower than ``ADMIN_EDITABLE_FIELDS``: excludes ``designation``/
# ``department``/``employee_id`` (organization-/HR-managed attributes, not
# self-editable) and ``is_verified`` (a user must never be able to
# self-promote their own verification status).
SELF_EDITABLE_FIELDS: frozenset[str] = frozenset(
    {"first_name", "last_name", "phone", "profile_photo", "timezone", "language"}
)


class IdentityRepositoryProtocol(Protocol):
    """The minimal surface this service needs from ``AuthRepositoryProtocol``
    for identity CRUD, without depending on session/password-history/login-
    attempt operations that belong to auth's own login/register/token
    flows."""

    async def get_user_by_id(self, user_id: uuid.UUID) -> User | None: ...

    async def get_user_by_email(self, email: str) -> User | None: ...

    async def get_user_by_username(self, username: str) -> User | None: ...

    async def create_user(self, **fields: object) -> User: ...

    async def update_user(self, user: User, **fields: object) -> User: ...

    async def list_users(
        self,
        *,
        page: int,
        page_size: int,
        search: str | None = None,
        is_active: bool | None = None,
        user_ids: list[uuid.UUID] | None = None,
    ) -> tuple[list[User], PaginationMeta]: ...


class OrganizationLookupProtocol(Protocol):
    """The minimal surface this service needs from ``OrganizationService``
    for membership reads/writes and MSP-hierarchy tenant scoping, without
    depending on the rest of its CRUD surface."""

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization: ...

    async def list_children(self, organization_id: uuid.UUID) -> list[Organization]: ...

    async def list_members(
        self, organization_id: uuid.UUID, *, status: MembershipStatus | None = None
    ) -> list[OrganizationMember]: ...

    async def list_user_organizations(
        self, user_id: uuid.UUID, *, status: MembershipStatus | None = None
    ) -> list[OrganizationMember]: ...

    async def invite_member(
        self,
        *,
        actor_user_id: uuid.UUID,
        organization_id: uuid.UUID,
        user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        is_primary_contact: bool = False,
    ) -> OrganizationMember: ...

    async def accept_invite(
        self, *, user_id: uuid.UUID, organization_id: uuid.UUID, member_id: uuid.UUID
    ) -> OrganizationMember: ...


class RoleAssignmentProtocol(Protocol):
    """The minimal surface this service needs from ``RBACService`` for the
    optional initial-role-assignment convenience at creation time. This
    service never removes/lists role assignments itself -- that remains
    RBAC's own ``POST/DELETE /users/{id}/roles`` endpoints' job."""

    async def assign_role_to_user(
        self,
        *,
        actor_user_id: uuid.UUID,
        target_user_id: uuid.UUID,
        role_id: uuid.UUID,
        scope_type: ScopeType,
        requesting_organization_id: uuid.UUID | None,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        expires_at: datetime | None = None,
    ) -> UserRole: ...


class RoleResolverProtocol(Protocol):
    """The minimal surface this service needs from RBAC's ``RoleResolver``
    for the aggregated detail view's "active roles" section -- role
    *lookup*, never role assignment/removal."""

    async def get_active_roles(
        self,
        user_id: uuid.UUID,
        *,
        scope_context: ScopeContext | None = None,
        now: datetime | None = None,
    ) -> list[Role]: ...


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table, without depending on the rest of
    ``RBACRepositoryProtocol``."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


class NotificationSenderProtocol(Protocol):
    """The minimal surface ``invite_user`` needs to actually deliver an
    invite email -- satisfied structurally by
    ``app.domains.notification.service.NotificationService``, the exact
    same narrow-``Protocol`` composition pattern
    ``app.domains.auth.service.AuthService``'s own
    ``NotificationSenderProtocol`` already establishes."""

    async def enqueue(
        self,
        *,
        event_type: NotificationEventType,
        channel: NotificationChannelType,
        recipient: str,
        body: str,
        organization_id: uuid.UUID | None,
        subject: str | None = None,
    ) -> object: ...


class _NoopNotificationSender:
    """Honest fallback when no real ``NotificationSenderProtocol`` is
    wired in -- logs instead of silently discarding the invite, mirroring
    ``app.domains.auth.service._NoopNotificationSender``'s identical
    "logged, not faked, not silently dropped" precedent."""

    async def enqueue(
        self,
        *,
        event_type: NotificationEventType,
        channel: NotificationChannelType,
        recipient: str,
        body: str,
        organization_id: uuid.UUID | None,
        subject: str | None = None,
    ) -> None:
        logger.info(
            "user_invite_notification_would_send",
            extra={"event_type": event_type.value, "recipient": recipient},
        )


_TEMPORARY_PASSWORD_LENGTH = 16
# Excludes look-alike characters (0/O, 1/l/I) and keeps exactly one special
# character from a small, unambiguous set -- still satisfies
# PasswordManager.validate_strength's upper/lower/digit/special requirement,
# but reads and types cleanly when handed to a staff member over chat/phone.
_TEMPORARY_PASSWORD_AMBIGUOUS = "0O1lI"
_TEMPORARY_PASSWORD_UPPER = "".join(
    c for c in string.ascii_uppercase if c not in _TEMPORARY_PASSWORD_AMBIGUOUS
)
_TEMPORARY_PASSWORD_LOWER = "".join(
    c for c in string.ascii_lowercase if c not in _TEMPORARY_PASSWORD_AMBIGUOUS
)
_TEMPORARY_PASSWORD_DIGITS = "".join(
    c for c in string.digits if c not in _TEMPORARY_PASSWORD_AMBIGUOUS
)
_TEMPORARY_PASSWORD_SPECIALS = "!@#$"


def _generate_temporary_password(length: int = _TEMPORARY_PASSWORD_LENGTH) -> str:
    """A real, cryptographically secure (``secrets``, never ``random``)
    temporary password, guaranteed to contain at least one uppercase,
    lowercase, digit, and exactly one special character. A small, deliberate,
    self-contained duplication of
    ``app.domains.location.provisioning_service._generate_temporary_password``
    -- the same "trivial, self-contained utility, not a business rule"
    precedent ``app.domains.router_provisioning.validators``'s own MAC
    validator already establishes for why this is not cross-domain
    imported."""
    alnum_categories = [
        _TEMPORARY_PASSWORD_UPPER,
        _TEMPORARY_PASSWORD_LOWER,
        _TEMPORARY_PASSWORD_DIGITS,
    ]
    chars = [secrets.choice(category) for category in alnum_categories]
    chars.append(secrets.choice(_TEMPORARY_PASSWORD_SPECIALS))
    all_alnum = "".join(alnum_categories)
    chars.extend(secrets.choice(all_alnum) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


@dataclass(frozen=True, slots=True)
class OrganizationMembershipView:
    """An ``OrganizationMember`` row paired with its organization's display
    name, assembled for the aggregated user-detail response without
    exposing the caller to a second round trip."""

    membership: OrganizationMember
    organization_name: str


@dataclass(frozen=True, slots=True)
class InviteUserResult:
    """Result of :meth:`UserService.invite_user` -- pairs the created
    ``User`` with the generated temporary password, shown exactly once,
    the same "shown once, in this response only" convention
    ``app.domains.location.provisioning_service.ProvisionLocationResult
    .owner_temporary_password`` already establishes."""

    user: User
    temporary_password: str


@dataclass(frozen=True, slots=True)
class ImpersonationResult:
    """Result of :meth:`UserService.impersonate_user` -- the minted
    target-identity access token, its expiry, and the target user, for
    ``POST /api/v1/users/{id}/impersonate`` to shape into its response."""

    access_token: str
    expires_at: datetime
    target_user: User


@dataclass(frozen=True, slots=True)
class UserAggregate:
    """Read-composition, not a persisted model: identity (``auth.User``) +
    org memberships (``organization.OrganizationMember``) + active roles
    (``rbac.Role``) assembled into one object for
    ``GET /api/v1/users/{id}`` and ``GET /api/v1/me``."""

    user: User
    memberships: list[OrganizationMembershipView]
    roles: list[Role]


class UserService:
    """Core user management/aggregation business logic."""

    def __init__(
        self,
        identity_repository: IdentityRepositoryProtocol,
        organization_lookup: OrganizationLookupProtocol,
        role_assigner: RoleAssignmentProtocol,
        role_resolver: RoleResolverProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        notification_service: NotificationSenderProtocol | None = None,
    ) -> None:
        self.identity_repository = identity_repository
        self.organization_lookup = organization_lookup
        self.role_assigner = role_assigner
        self.role_resolver = role_resolver
        self.audit_writer = audit_writer
        self.notification_service: NotificationSenderProtocol = (
            notification_service or _NoopNotificationSender()
        )

    # -- reads -----------------------------------------------------------------

    async def list_users(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
        search: str | None = None,
        is_active: bool | None = None,
    ) -> tuple[list[User], PaginationMeta]:
        """Platform-level callers (no ``requesting_organization_id`` -- a
        GLOBAL-scoped role) see every user. Org-scoped callers see only
        active members of their own organization plus its children (if it
        is an MSP) -- the same tenant-scoping shape
        ``OrganizationService.list_organizations`` uses for organizations
        themselves."""
        if requesting_organization_id is None:
            return await self.identity_repository.list_users(
                page=page, page_size=page_size, search=search, is_active=is_active
            )
        member_user_ids = await self._member_user_ids_in_scope(
            requesting_organization_id
        )
        return await self.identity_repository.list_users(
            page=page,
            page_size=page_size,
            search=search,
            is_active=is_active,
            user_ids=member_user_ids,
        )

    async def get_user_detail(
        self, user_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> UserAggregate:
        user = await self._get_user_or_raise(user_id)
        await self._enforce_user_tenant_access(user, requesting_organization_id)
        return await self._assemble_aggregate(user)

    async def get_me(self, user_id: uuid.UUID) -> UserAggregate:
        """A user's own aggregated profile is never tenant-scoped -- you can
        always see your own identity/memberships/roles regardless of which
        ``X-Organization-Id`` context (if any) the request carries."""
        user = await self._get_user_or_raise(user_id)
        return await self._assemble_aggregate(user)

    # -- writes ------------------------------------------------------------------

    async def create_user(
        self,
        *,
        actor_user_id: uuid.UUID,
        first_name: str,
        last_name: str,
        email: str,
        username: str,
        temporary_password: str,
        requesting_organization_id: uuid.UUID | None,
        phone: str | None = None,
        designation: str | None = None,
        department: str | None = None,
        employee_id: str | None = None,
        timezone: str = "UTC",
        language: str = "en",
        organization_id: uuid.UUID | None = None,
        initial_role_id: uuid.UUID | None = None,
    ) -> User:
        """Admin-driven account creation: creates the identity row and,
        optionally, an active organization membership plus an initial role
        assignment -- one orchestrated flow instead of three disconnected
        API calls (see ``docs/user/USER_ARCHITECTURE.md`` §"Admin-created
        organization membership: invited vs. active" for why membership is
        created directly ``ACTIVE`` here rather than left ``INVITED``)."""
        if initial_role_id is not None and organization_id is None:
            raise InitialRoleRequiresOrganizationError()
        if organization_id is not None:
            await self._assert_organization_in_scope(
                organization_id, requesting_organization_id
            )

        if await self.identity_repository.get_user_by_email(email):
            logger.warning("admin_user_creation_existing_email", extra={"email": email})
            raise EmailAlreadyExistsError(email)
        if await self.identity_repository.get_user_by_username(username):
            logger.warning(
                "admin_user_creation_existing_username", extra={"username": username}
            )
            raise UsernameAlreadyExistsError(username)

        try:
            password_hash = PasswordManager.hash(temporary_password)
        except PasswordStrengthError as exc:
            raise UserPasswordTooWeakError(str(exc)) from exc
        user = await self.identity_repository.create_user(
            first_name=first_name,
            last_name=last_name,
            email=email,
            username=username,
            password_hash=password_hash,
            phone=phone,
            designation=designation,
            department=department,
            employee_id=employee_id,
            timezone=timezone,
            language=language,
            # Admin-provisioned accounts are active and verified immediately
            # (unlike self-service ``register()``, which requires email
            # verification) -- see ``docs/user/USER_ARCHITECTURE.md`` for
            # why: there is no verification-email-delivery infrastructure in
            # this codebase, and an administrator directly provisioning an
            # account is a stronger identity assertion than an
            # unauthenticated self-signup.
            is_active=True,
            is_verified=True,
        )

        if organization_id is not None:
            invite = await self.organization_lookup.invite_member(
                actor_user_id=actor_user_id,
                organization_id=organization_id,
                user_id=user.id,
                # Same value this method already checked at the top via
                # _assert_organization_in_scope, so invite_member's own
                # tenant guard reaches the same verdict rather than a
                # second, differently-derived one.
                requesting_organization_id=requesting_organization_id,
            )
            await self.organization_lookup.accept_invite(
                user_id=user.id,
                organization_id=organization_id,
                member_id=invite.id,
            )
            if initial_role_id is not None:
                await self.role_assigner.assign_role_to_user(
                    actor_user_id=actor_user_id,
                    target_user_id=user.id,
                    role_id=initial_role_id,
                    scope_type=ScopeType.ORGANIZATION,
                    requesting_organization_id=requesting_organization_id,
                    organization_id=organization_id,
                )

        await self._audit(
            actor_user_id,
            AuditAction.USER_CREATED,
            entity_id=user.id,
            description=f"User '{user.email}' created",
            organization_id=organization_id,
        )
        return user

    async def invite_user(
        self,
        *,
        actor_user_id: uuid.UUID,
        first_name: str,
        last_name: str,
        email: str,
        username: str,
        requesting_organization_id: uuid.UUID | None,
        phone: str | None = None,
        designation: str | None = None,
        department: str | None = None,
        employee_id: str | None = None,
        timezone: str = "UTC",
        language: str = "en",
        organization_id: uuid.UUID | None = None,
        initial_role_id: uuid.UUID | None = None,
    ) -> InviteUserResult:
        """A real invitation workflow: unlike ``create_user`` (which
        requires the caller to type a plaintext ``temporary_password``),
        this generates a cryptographically secure one, forces a password
        change on first login (``must_change_password``), and emails the
        invitee a real, notification-domain-delivered invite -- closing
        the gap ``create_user``'s own docstring comment used to
        acknowledge ("no verification-email-delivery infrastructure...
        for admin flow" -- no longer true, ``app.domains.notification``
        now exists). Delegates every existing validation/creation/
        membership/role-assignment step to ``create_user`` unchanged --
        this is a thin wrapper, not a second implementation of it."""
        temporary_password = _generate_temporary_password()
        user = await self.create_user(
            actor_user_id=actor_user_id,
            first_name=first_name,
            last_name=last_name,
            email=email,
            username=username,
            temporary_password=temporary_password,
            requesting_organization_id=requesting_organization_id,
            phone=phone,
            designation=designation,
            department=department,
            employee_id=employee_id,
            timezone=timezone,
            language=language,
            organization_id=organization_id,
            initial_role_id=initial_role_id,
        )
        user = await self.identity_repository.update_user(
            user, must_change_password=True
        )
        login_url = f"{get_settings().frontend_base_url.rstrip('/')}/login"
        content = (
            heading("You've been invited to Wyfy Guest")
            + paragraph(
                f"Hi {esc(user.first_name)}, an account has been created for "
                "you. Use the credentials below to sign in -- you'll be asked "
                "to set a new password the first time you log in."
            )
            + info_box(
                [
                    ("Username", esc(username)),
                    ("Temporary password", esc(temporary_password)),
                ],
                mono_values=True,
            )
            + button("Log In to Wyfy Guest", login_url)
        )
        await self.notification_service.enqueue(
            event_type=NotificationEventType.USER_INVITED,
            channel=NotificationChannelType.EMAIL,
            recipient=user.email,
            subject="You've been invited to Wyfy Guest",
            body=render_email(
                preheader="An account has been created for you on Wyfy Guest.",
                content_html=content,
            ),
            organization_id=organization_id,
        )
        return InviteUserResult(user=user, temporary_password=temporary_password)

    async def update_user(
        self,
        *,
        actor_user_id: uuid.UUID,
        user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> User:
        """Administrator profile update -- see ``ADMIN_EDITABLE_FIELDS``.
        Fields are defensively filtered here (not just left unexposed by the
        request schema) so behavior can never silently diverge from the
        documented admin-vs-self field split, mirroring
        ``LocationService.update_location``'s own defensive
        ``organization_id``-stripping convention."""
        user = await self._get_user_or_raise(user_id)
        await self._enforce_user_tenant_access(user, requesting_organization_id)
        update_data = {k: v for k, v in data.items() if k in ADMIN_EDITABLE_FIELDS}
        updated = await self.identity_repository.update_user(user, **update_data)
        await self._audit(
            actor_user_id,
            AuditAction.USER_UPDATED,
            entity_id=updated.id,
            description=f"User '{updated.email}' updated",
            organization_id=requesting_organization_id,
        )
        return updated

    async def update_self(self, *, user_id: uuid.UUID, data: dict[str, object]) -> User:
        """Self-service profile update -- see ``SELF_EDITABLE_FIELDS``."""
        user = await self._get_user_or_raise(user_id)
        update_data = {k: v for k, v in data.items() if k in SELF_EDITABLE_FIELDS}
        updated = await self.identity_repository.update_user(user, **update_data)
        await self._audit(
            user_id,
            AuditAction.USER_UPDATED,
            entity_id=updated.id,
            description=f"User '{updated.email}' updated their own profile",
            organization_id=None,
        )
        return updated

    async def set_own_data_masking(self, *, user_id: uuid.UUID, masked: bool) -> User:
        """Flip the caller's own ``data_masking_enabled`` after they've
        completed OTP step-up verification (see
        ``app.domains.otp.constants.OtpPurpose.ACCOUNT_DATA_MASKING`` and
        the ``/users/me/data-masking`` endpoints in ``router.py``, which are
        the only callers of this method -- the OTP verification *is* the
        authorization for this one field, deliberately bypassing
        ``SELF_EDITABLE_FIELDS`` rather than adding ``data_masking_enabled``
        to that set generally (which would let a user flip it with no
        verification at all, the exact gap this feature exists to close)."""
        user = await self._get_user_or_raise(user_id)
        updated = await self.identity_repository.update_user(
            user, data_masking_enabled=masked
        )
        await self._audit(
            user_id,
            AuditAction.USER_UPDATED,
            entity_id=updated.id,
            description=(
                f"User '{updated.email}' {'enabled' if masked else 'disabled'} "
                "their own guest-data masking after OTP verification"
            ),
            organization_id=None,
        )
        return updated

    async def deactivate_user(
        self,
        *,
        actor_user_id: uuid.UUID,
        user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> User:
        """Sets ``is_active=False`` -- ``auth.dependencies.get_current_user``
        already rejects any bearer token belonging to an inactive user, so a
        deactivated user's existing access tokens stop working on their very
        next authenticated request with no separate session-revocation step
        needed here (see ``docs/user/USER_ARCHITECTURE.md``)."""
        if actor_user_id == user_id:
            raise SelfDeactivationNotAllowedError(user_id)
        user = await self._get_user_or_raise(user_id)
        await self._enforce_user_tenant_access(user, requesting_organization_id)
        updated = await self.identity_repository.update_user(
            user, is_active=False, status=UserAccountStatus.INACTIVE.value
        )
        await self._audit(
            actor_user_id,
            AuditAction.USER_DEACTIVATED,
            entity_id=updated.id,
            description=f"User '{updated.email}' deactivated",
            organization_id=requesting_organization_id,
        )
        return updated

    async def reactivate_user(
        self,
        *,
        actor_user_id: uuid.UUID,
        user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> User:
        user = await self._get_user_or_raise(user_id)
        await self._enforce_user_tenant_access(user, requesting_organization_id)
        updated = await self.identity_repository.update_user(
            user,
            is_active=True,
            status=UserAccountStatus.ACTIVE.value,
            failed_login_attempts=0,
            locked_until=None,
        )
        await self._audit(
            actor_user_id,
            AuditAction.USER_REACTIVATED,
            entity_id=updated.id,
            description=f"User '{updated.email}' reactivated",
            organization_id=requesting_organization_id,
        )
        return updated

    async def force_logout_user(
        self,
        *,
        actor_user_id: uuid.UUID,
        user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> User:
        """Real, immediate session termination -- unlike ``deactivate_user``
        (which only takes effect reactively, on the target's *next*
        request, and also locks them out of the account entirely), this
        ends their current sessions right now without touching
        ``is_active``: they're logged out everywhere, but can sign back in
        immediately.

        Two real, independent steps, both required: ``revoke_all_sessions``
        stops a *new* access token being minted via a still-valid refresh
        token; setting ``tokens_invalidated_at`` rejects any access token
        already issued, on its very next authenticated request, regardless
        of how much of its normal ~15-minute expiry window is left (see
        ``auth.dependencies._resolve_user_from_jwt``). Neither alone is a
        complete "force logout" -- revoking sessions without the timestamp
        would leave an already-issued access token working for up to 15
        more minutes; setting the timestamp without revoking sessions
        would let a still-valid refresh token quietly mint a fresh one
        right after."""
        user = await self._get_user_or_raise(user_id)
        await self._enforce_user_tenant_access(user, requesting_organization_id)
        revoked = await self.identity_repository.revoke_all_sessions(user_id)
        updated = await self.identity_repository.update_user(
            user, tokens_invalidated_at=datetime.now(UTC)
        )
        await self._audit(
            actor_user_id,
            AuditAction.USER_FORCE_LOGGED_OUT,
            entity_id=updated.id,
            description=(
                f"User '{updated.email}' force-logged-out "
                f"({revoked} session(s) revoked)"
            ),
            organization_id=requesting_organization_id,
        )
        return updated

    async def impersonate_user(
        self,
        *,
        actor_user_id: uuid.UUID,
        actor_email: str,
        user_id: uuid.UUID,
        reason: str | None,
    ) -> ImpersonationResult:
        """Mint a short-lived, target-identity access token so a platform
        staff member (holding the Super-Admin-exclusive
        ``users.impersonate`` permission -- enforced by the router's own
        ``RequirePermission`` dependency, not re-checked here) can view a
        customer's dashboard exactly as that customer would see it.

        Three checks, each with its own dedicated exception (see
        ``exceptions.py``):

        * the caller cannot impersonate themselves
          (:class:`SelfImpersonationNotAllowedError`);
        * the target must exist and be active
          (:class:`UserNotFoundError` / :class:`ImpersonationTargetInactiveError`);
        * the target must hold no active GLOBAL-scope role assignment of
          their own (:class:`StaffImpersonationNotAllowedError`) -- staff
          can never impersonate another staff/operator account, which
          would otherwise let one operator's session quietly ride
          another's platform-wide permissions (a privilege-escalation
          chain). This mirrors ``app.domains.rbac.dependencies
          .CurrentOrganization``'s own GLOBAL-scope-bypass check: any
          active role whose own ``scope_type`` is GLOBAL.

        The minted token's ``sub``/identity is the *target* user, deliberately
        shorter-lived than a normal login session
        (``IMPERSONATION_ACCESS_TOKEN_EXPIRE_MINUTES``, not
        ``settings.access_token_expire_minutes``), and carries an
        ``impersonation`` claim naming the real actor -- so every
        downstream permission/org-membership check resolves as if the
        target had logged in themselves, while the fact of impersonation
        (and who is really behind it) is always recoverable straight from
        the token, for both backend logic and the frontend's own
        always-visible "impersonating" banner. Every call that reaches
        this point (i.e. passes all three checks above) writes a real
        ``AuditAction.IMPERSONATION_STARTED`` entry -- never skipped, the
        same "every single invocation is logged" posture
        ``DEVICE_CONSOLE_COMMAND_EXECUTED``/``ROUTER_CREDENTIALS_REVEALED``
        already establish for other genuinely sensitive, human-triggered
        actions."""
        if actor_user_id == user_id:
            raise SelfImpersonationNotAllowedError(user_id)

        target = await self._get_user_or_raise(user_id)
        if not target.is_active:
            raise ImpersonationTargetInactiveError(user_id)

        target_roles = await self.role_resolver.get_active_roles(user_id)
        if any(role.scope_type == ScopeType.GLOBAL.value for role in target_roles):
            raise StaffImpersonationNotAllowedError(user_id)

        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=IMPERSONATION_ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token, _jti = JWTManager.create_access_token(
            str(target.id),
            target.email,
            additional_claims={
                "impersonation": {
                    "actor_user_id": str(actor_user_id),
                    "actor_email": actor_email,
                    "started_at": now.isoformat(),
                }
            },
            expires_in_minutes=IMPERSONATION_ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        await self._audit(
            actor_user_id,
            AuditAction.IMPERSONATION_STARTED,
            entity_id=target.id,
            description=(
                f"'{actor_email}' ({actor_user_id}) started impersonating "
                f"'{target.email}' ({target.id})"
            ),
            organization_id=None,
            metadata={
                "reason": reason,
                "target_email": target.email,
                "expires_at": expires_at.isoformat(),
            },
        )
        return ImpersonationResult(
            access_token=access_token, expires_at=expires_at, target_user=target
        )

    # -- internal helpers -------------------------------------------------------

    async def _get_user_or_raise(self, user_id: uuid.UUID) -> User:
        user = await self.identity_repository.get_user_by_id(user_id)
        if user is None:
            raise UserNotFoundError(user_id)
        return user

    async def _assemble_aggregate(self, user: User) -> UserAggregate:
        memberships = await self._membership_views(user.id)
        roles = await self.role_resolver.get_active_roles(user.id)
        return UserAggregate(user=user, memberships=memberships, roles=roles)

    async def _membership_views(
        self, user_id: uuid.UUID
    ) -> list[OrganizationMembershipView]:
        memberships = await self.organization_lookup.list_user_organizations(user_id)
        views: list[OrganizationMembershipView] = []
        for membership in memberships:
            organization = await self.organization_lookup.get_organization(
                membership.organization_id, include_deleted=True
            )
            views.append(
                OrganizationMembershipView(
                    membership=membership, organization_name=organization.name
                )
            )
        return views

    async def _member_user_ids_in_scope(
        self, organization_id: uuid.UUID
    ) -> list[uuid.UUID]:
        """Active members of ``organization_id`` plus, if it is an MSP,
        active members of every child organization -- the same "self or
        child" tenant-scoping shape ``OrganizationService.list_organizations``
        /``LocationService`` use."""
        organization = await self.organization_lookup.get_organization(organization_id)
        scope_org_ids = [organization.id]
        if organization.is_msp():
            children = await self.organization_lookup.list_children(organization.id)
            scope_org_ids.extend(child.id for child in children)

        user_ids: set[uuid.UUID] = set()
        for org_id in scope_org_ids:
            members = await self.organization_lookup.list_members(
                org_id, status=MembershipStatus.ACTIVE
            )
            user_ids.update(member.user_id for member in members)
        return list(user_ids)

    async def _assert_organization_in_scope(
        self,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        if requesting_organization_id is None:
            return
        if organization_id == requesting_organization_id:
            return
        organization = await self.organization_lookup.get_organization(
            organization_id, include_deleted=True
        )
        if organization.parent_organization_id == requesting_organization_id:
            return
        raise CrossOrganizationUserAccessError()

    async def assert_user_accessible(
        self, user_id: uuid.UUID, requesting_organization_id: uuid.UUID | None
    ) -> None:
        """Public tenant check for callers that need the guard without the
        aggregate ``get_user_detail`` assembles.

        The RBAC domain's ``/users/{id}/roles`` and ``/users/{id}/permissions``
        reads had no tenant check at all: ``RequirePermission("users.read")``
        scopes off the ``X-Organization-Id`` header while both handlers read
        by path id, so any organization user could enumerate the role
        assignments and effective permissions of any user on the platform,
        including platform administrators.
        """
        user = await self._get_user_or_raise(user_id)
        await self._enforce_user_tenant_access(user, requesting_organization_id)

    async def _enforce_user_tenant_access(
        self, user: User, requesting_organization_id: uuid.UUID | None
    ) -> None:
        if requesting_organization_id is None:
            return
        member_user_ids = await self._member_user_ids_in_scope(
            requesting_organization_id
        )
        if user.id not in member_user_ids:
            raise CrossOrganizationUserAccessError()

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID | None,
        description: str,
        organization_id: uuid.UUID | None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="user",
                entity_id=entity_id,
                description=description,
                event_metadata=metadata or {},
                organization_id=organization_id,
                location_id=None,
            )
        logger.info(
            "user_audit_event",
            extra={
                "action": action.value,
                "entity_id": str(entity_id) if entity_id else None,
            },
        )


__all__ = [
    "UserService",
    "IdentityRepositoryProtocol",
    "OrganizationLookupProtocol",
    "RoleAssignmentProtocol",
    "RoleResolverProtocol",
    "AuditLogWriter",
    "OrganizationMembershipView",
    "UserAggregate",
    "InviteUserResult",
    "ImpersonationResult",
    "IMPERSONATION_ACCESS_TOKEN_EXPIRE_MINUTES",
    "ADMIN_EDITABLE_FIELDS",
    "SELF_EDITABLE_FIELDS",
    "CloudGuestError",
]
