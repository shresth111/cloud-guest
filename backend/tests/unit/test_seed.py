"""Unit tests for ``scripts/seed.py``'s three idempotent bootstrap steps:
Super Admin user creation, Super Admin role assignment, and default system
``ConfigTemplate`` creation.

Follows this project's plain-``assert``/native-``async def`` style and its
"fake the narrow Protocol boundary" precedent (see ``tests/unit/test_auth.py``,
``tests/unit/test_isp_routing.py``). ``seed_rbac`` itself and ``run_seed``/the
CLI wiring (which bind concrete, SQLAlchemy-backed repositories to a real
``AsyncSession``) are out of scope here -- they need a running Postgres to do
anything meaningful, the same boundary ``test_auth.py`` already draws around
the real ``AuthRepository``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.auth.models import User
from app.domains.auth.password import PasswordManager, PasswordStrengthError
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.models import Role, UserRole
from app.domains.router_provisioning.models import ConfigTemplate
from scripts.seed import (
    SUPER_ADMIN_ROLE_SLUG,
    ensure_default_system_template,
    ensure_superadmin_role_assignment,
    ensure_superadmin_user,
)

STRONG_PASSWORD = "SecurePass123!@#"


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


def _make_user(**overrides: object) -> User:
    fields: dict[str, object] = {
        "first_name": "Super",
        "last_name": "Admin",
        "email": "admin@example.com",
        "username": "admin",
        "password_hash": "hashed",
        "timezone": "UTC",
        "language": "en",
        "status": "active",
        "is_active": True,
        "is_verified": True,
        "email_verified_at": None,
        "phone_verified_at": None,
        "last_login_at": None,
        "failed_login_attempts": 0,
        "locked_until": None,
        "password_changed_at": None,
        "must_change_password": False,
    }
    fields.update(overrides)
    return User(**_base_fields(**fields))


def _make_role(**overrides: object) -> Role:
    fields: dict[str, object] = {
        "name": "Super Admin",
        "slug": SUPER_ADMIN_ROLE_SLUG,
        "description": "Unrestricted platform-wide access.",
        "is_system_role": True,
        "is_template": False,
        "is_active": True,
        "scope_type": ScopeType.GLOBAL.value,
        "organization_id": None,
        "parent_role_id": None,
    }
    fields.update(overrides)
    return Role(**_base_fields(**fields))


def _make_user_role(**overrides: object) -> UserRole:
    fields: dict[str, object] = {
        "user_id": uuid.uuid4(),
        "role_id": uuid.uuid4(),
        "scope_type": ScopeType.GLOBAL.value,
        "msp_id": None,
        "organization_id": None,
        "location_id": None,
        "router_id": None,
        "granted_at": _now(),
        "granted_by": None,
        "expires_at": None,
        "is_active": True,
    }
    fields.update(overrides)
    return UserRole(**_base_fields(**fields))


def _make_template(**overrides: object) -> ConfigTemplate:
    fields: dict[str, object] = {
        "organization_id": None,
        "name": "Existing System Template",
        "description": None,
        "is_system_template": True,
        "applicable_router_model": None,
        "vendor": "mikrotik",
        "template_content": "/system identity set name={{router_name}}",
        "is_active": True,
    }
    fields.update(overrides)
    return ConfigTemplate(**_base_fields(**fields))


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeAuthRepository:
    users_by_email: dict[str, User] = field(default_factory=dict)
    created: list[dict[str, object]] = field(default_factory=list)

    async def get_user_by_email(self, email: str) -> User | None:
        return self.users_by_email.get(email.lower())

    async def create_user(self, **fields: object) -> User:
        self.created.append(fields)
        user = _make_user(**fields)
        self.users_by_email[user.email] = user
        return user


@dataclass
class FakeRBACRepository:
    roles_by_slug: dict[str, Role] = field(default_factory=dict)
    active_roles_by_user: dict[uuid.UUID, list[UserRole]] = field(default_factory=dict)
    created_user_roles: list[dict[str, object]] = field(default_factory=list)

    async def get_role_by_slug(
        self, slug: str, organization_id: uuid.UUID | None
    ) -> Role | None:
        return self.roles_by_slug.get(slug)

    async def get_active_user_roles(self, user_id: uuid.UUID) -> list[UserRole]:
        return self.active_roles_by_user.get(user_id, [])

    async def create_user_role(self, **fields: object) -> UserRole:
        self.created_user_roles.append(fields)
        assignment = _make_user_role(**fields)
        self.active_roles_by_user.setdefault(assignment.user_id, []).append(assignment)
        return assignment


@dataclass
class FakeRouterProvisioningRepository:
    templates: list[ConfigTemplate] = field(default_factory=list)
    created: list[dict[str, object]] = field(default_factory=list)

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[ConfigTemplate], PaginationMeta]:
        values = [
            t
            for t in self.templates
            if (requesting_organization_id is None) == (t.organization_id is None)
        ]
        params = PageParams(page=page, page_size=page_size)
        return values, PaginationMeta.from_total(params, len(values))

    async def create_template(self, **fields: object) -> ConfigTemplate:
        self.created.append(fields)
        template = _make_template(**fields)
        self.templates.append(template)
        return template


# ============================================================================
# ensure_superadmin_user
# ============================================================================


async def test_ensure_superadmin_user_creates_when_absent() -> None:
    repo = FakeAuthRepository()

    user, created = await ensure_superadmin_user(
        repo,
        email="admin@example.com",
        username="admin",
        first_name="Super",
        last_name="Admin",
        password=STRONG_PASSWORD,
    )

    assert created is True
    assert user.email == "admin@example.com"
    assert user.is_verified is True
    assert PasswordManager.verify(STRONG_PASSWORD, user.password_hash)


async def test_ensure_superadmin_user_idempotent_when_present() -> None:
    repo = FakeAuthRepository()
    existing = _make_user(email="admin@example.com")
    repo.users_by_email[existing.email] = existing

    user, created = await ensure_superadmin_user(
        repo,
        email="admin@example.com",
        username="admin",
        first_name="Super",
        last_name="Admin",
        password=STRONG_PASSWORD,
    )

    assert created is False
    assert user is existing
    assert repo.created == []


async def test_ensure_superadmin_user_rejects_weak_password() -> None:
    repo = FakeAuthRepository()

    with pytest.raises(PasswordStrengthError):
        await ensure_superadmin_user(
            repo,
            email="admin@example.com",
            username="admin",
            first_name="Super",
            last_name="Admin",
            password="weak",
        )

    assert repo.created == []


# ============================================================================
# ensure_superadmin_role_assignment
# ============================================================================


async def test_ensure_superadmin_role_assignment_creates_when_absent() -> None:
    repo = FakeRBACRepository()
    role = _make_role()
    repo.roles_by_slug[SUPER_ADMIN_ROLE_SLUG] = role
    user_id = uuid.uuid4()

    assignment, created = await ensure_superadmin_role_assignment(
        repo, user_id=user_id
    )

    assert created is True
    assert assignment is not None
    assert assignment.role_id == role.id
    assert assignment.scope_type == ScopeType.GLOBAL.value
    assert assignment.organization_id is None


async def test_ensure_superadmin_role_assignment_idempotent_when_already_held() -> None:
    repo = FakeRBACRepository()
    role = _make_role()
    repo.roles_by_slug[SUPER_ADMIN_ROLE_SLUG] = role
    user_id = uuid.uuid4()
    repo.active_roles_by_user[user_id] = [
        _make_user_role(user_id=user_id, role_id=role.id)
    ]

    assignment, created = await ensure_superadmin_role_assignment(
        repo, user_id=user_id
    )

    assert created is False
    assert assignment is None
    assert repo.created_user_roles == []


async def test_ensure_superadmin_role_assignment_none_when_rbac_not_seeded() -> None:
    repo = FakeRBACRepository()

    assignment, created = await ensure_superadmin_role_assignment(
        repo, user_id=uuid.uuid4()
    )

    assert assignment is None
    assert created is False
    assert repo.created_user_roles == []


# ============================================================================
# ensure_default_system_template
# ============================================================================


async def test_ensure_default_system_template_creates_when_absent() -> None:
    repo = FakeRouterProvisioningRepository()
    actor_id = uuid.uuid4()

    template, created = await ensure_default_system_template(
        repo, actor_user_id=actor_id
    )

    assert created is True
    assert template.is_system_template is True
    assert template.organization_id is None
    assert repo.created[0]["created_by"] == actor_id


async def test_ensure_default_system_template_idempotent_when_present() -> None:
    repo = FakeRouterProvisioningRepository()
    existing = _make_template()
    repo.templates.append(existing)

    template, created = await ensure_default_system_template(
        repo, actor_user_id=uuid.uuid4()
    )

    assert created is False
    assert template is existing
    assert repo.created == []


async def test_ensure_default_system_template_ignores_stale_rows() -> None:
    repo = FakeRouterProvisioningRepository()
    repo.templates.append(
        _make_template(organization_id=uuid.uuid4(), is_system_template=False)
    )
    repo.templates.append(_make_template(is_active=False))

    template, created = await ensure_default_system_template(
        repo, actor_user_id=uuid.uuid4()
    )

    assert created is True
    assert template not in repo.templates[:2]
