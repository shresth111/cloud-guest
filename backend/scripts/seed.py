"""Idempotent bootstrap CLI for a fresh CloudGuest database.

Seeds, in order:

1. RBAC permission groups/permissions/permission scopes/system roles, via
   ``app.domains.rbac.seed.seed_rbac`` -- reused as-is, not reimplemented.
2. The first Super Admin user, assigned the seeded ``"super-admin"`` role
   at ``ScopeType.GLOBAL``.
3. The platform's default system ``ConfigTemplate`` (``organization_id`` is
   ``None``, ``is_system_template=True``). Its absence is exactly what makes
   ``app.domains.location.provisioning_service.LocationProvisioningService
   ._resolve_default_template_id`` raise ``DefaultConfigTemplateNotFoundError``
   on a fresh deployment.

Every step first checks whether its row already exists -- safe to run
repeatedly against the same database (e.g. on every deploy).

The Super Admin user/role assignment go straight through ``AuthRepository``/
``RBACRepository`` rather than ``AuthService.register``/
``RBACService.assign_role_to_user``: those service methods assume,
respectively, a public self-registration flow (email verification token,
``is_verified=False``) and an already-privileged actor performing the
assignment -- neither applies at bootstrap, when no user or verified email
exists yet. The default template goes through ``RouterProvisioningRepository``
directly for a related reason: ``RouterProvisioningService`` requires
``router_lookup``/``location_lookup``/``queue_dispatcher`` collaborators that
have nothing to do with seeding a single template row.

Run with (from the ``backend/`` directory):

    python -m scripts.seed \\
        --superadmin-email admin@example.com \\
        --superadmin-username admin

The password is never accepted as a bare CLI flag -- it would leak into
shell history and process listings. Provide it via the
``CLOUDGUEST_SEED_SUPERADMIN_PASSWORD`` environment variable, or omit it
and you will be prompted for it (hidden input, via ``getpass``).
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from app.database.session import SessionLocal
from app.domains.auth.models import User
from app.domains.auth.password import PasswordManager
from app.domains.auth.repository import AuthRepository, AuthRepositoryProtocol
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.models import UserRole
from app.domains.rbac.repository import RBACRepository, RBACRepositoryProtocol
from app.domains.rbac.seed import SeedSummary, seed_rbac
from app.domains.router_provisioning.models import ConfigTemplate
from app.domains.router_provisioning.repository import (
    RouterProvisioningRepository,
    RouterProvisioningRepositoryProtocol,
)
from app.domains.router_provisioning.validators import validate_template_scope

logger = logging.getLogger(__name__)

SUPER_ADMIN_ROLE_SLUG = "super-admin"

DEFAULT_SYSTEM_TEMPLATE_NAME = "Default MikroTik Base Configuration"
# A minimal, real RouterOS command -- an honest, intentionally-minimal
# bootstrap default an operator is expected to replace/extend with a real
# vendor/environment-specific template, not a fabricated production config.
# See docs/router_provisioning for the ``{{variable_name}}`` placeholder
# syntax this renders against.
DEFAULT_SYSTEM_TEMPLATE_CONTENT = "/system identity set name={{router_name}}\n"
DEFAULT_SYSTEM_TEMPLATE_DESCRIPTION = (
    "Bootstrap default template created by scripts/seed.py. Replace or "
    "extend with a real vendor/environment-specific template before "
    "provisioning production routers."
)


@dataclass
class SeedResult:
    rbac: SeedSummary
    superadmin_user_id: uuid.UUID
    superadmin_user_created: bool
    superadmin_role_assigned: bool
    default_template_id: uuid.UUID
    default_template_created: bool


async def ensure_superadmin_user(
    auth_repository: AuthRepositoryProtocol,
    *,
    email: str,
    username: str,
    first_name: str,
    last_name: str,
    password: str,
) -> tuple[User, bool]:
    """Idempotently ensure the bootstrap Super Admin user exists.

    Returns ``(user, created)``.
    """
    existing = await auth_repository.get_user_by_email(email)
    if existing is not None:
        return existing, False

    password_hash = PasswordManager.hash(password)
    user = await auth_repository.create_user(
        first_name=first_name,
        last_name=last_name,
        email=email,
        username=username,
        password_hash=password_hash,
        is_active=True,
        is_verified=True,
    )
    return user, True


async def ensure_superadmin_role_assignment(
    rbac_repository: RBACRepositoryProtocol, *, user_id: uuid.UUID
) -> tuple[UserRole | None, bool]:
    """Idempotently ensure ``user_id`` holds the seeded ``"super-admin"``
    role at ``ScopeType.GLOBAL``.

    Returns ``(assignment, created)``. ``assignment`` is ``None`` both when
    nothing needed creating and when ``seed_rbac`` has not run yet (the role
    does not exist) -- callers of :func:`run_seed` never hit the latter case
    since ``seed_rbac`` always runs first.
    """
    role = await rbac_repository.get_role_by_slug(SUPER_ADMIN_ROLE_SLUG, None)
    if role is None:
        return None, False

    existing_roles = await rbac_repository.get_active_user_roles(user_id)
    if any(existing.role_id == role.id for existing in existing_roles):
        return None, False

    assignment = await rbac_repository.create_user_role(
        user_id=user_id,
        role_id=role.id,
        scope_type=ScopeType.GLOBAL.value,
        organization_id=None,
        location_id=None,
        router_id=None,
        granted_at=datetime.now(UTC),
        granted_by=None,
        expires_at=None,
        is_active=True,
    )
    return assignment, True


async def ensure_default_system_template(
    provisioning_repository: RouterProvisioningRepositoryProtocol,
    *,
    actor_user_id: uuid.UUID,
) -> tuple[ConfigTemplate, bool]:
    """Idempotently ensure at least one active, system-wide ``ConfigTemplate``
    exists. See module docstring for why its absence breaks location
    provisioning.
    """
    templates, _meta = await provisioning_repository.list_templates(
        requesting_organization_id=None, page=1, page_size=100
    )
    existing = [t for t in templates if t.is_system_template and t.is_active]
    if existing:
        existing.sort(key=lambda t: t.created_at, reverse=True)
        return existing[0], False

    validate_template_scope(is_system_template=True, organization_id=None)
    template = await provisioning_repository.create_template(
        organization_id=None,
        name=DEFAULT_SYSTEM_TEMPLATE_NAME,
        description=DEFAULT_SYSTEM_TEMPLATE_DESCRIPTION,
        is_system_template=True,
        applicable_router_model=None,
        vendor="mikrotik",
        template_content=DEFAULT_SYSTEM_TEMPLATE_CONTENT,
        is_active=True,
        created_by=actor_user_id,
    )
    return template, True


async def run_seed(
    session,
    *,
    email: str,
    username: str,
    first_name: str,
    last_name: str,
    password: str,
) -> SeedResult:
    """Run every bootstrap step against ``session``. Does not commit --
    callers control the transaction boundary (the CLI entrypoint below
    commits once, after every step succeeds)."""
    rbac_repository = RBACRepository(session)
    auth_repository = AuthRepository(session)
    provisioning_repository = RouterProvisioningRepository(session)

    rbac_summary = await seed_rbac(session)

    user, user_created = await ensure_superadmin_user(
        auth_repository,
        email=email,
        username=username,
        first_name=first_name,
        last_name=last_name,
        password=password,
    )

    _assignment, role_assigned = await ensure_superadmin_role_assignment(
        rbac_repository, user_id=user.id
    )

    template, template_created = await ensure_default_system_template(
        provisioning_repository, actor_user_id=user.id
    )

    return SeedResult(
        rbac=rbac_summary,
        superadmin_user_id=user.id,
        superadmin_user_created=user_created,
        superadmin_role_assigned=role_assigned,
        default_template_id=template.id,
        default_template_created=template_created,
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Bootstrap a fresh CloudGuest database: RBAC seed, first Super "
            "Admin user, default system ConfigTemplate. Safe to re-run."
        )
    )
    env_email = os.environ.get("CLOUDGUEST_SEED_SUPERADMIN_EMAIL")
    env_username = os.environ.get("CLOUDGUEST_SEED_SUPERADMIN_USERNAME")
    parser.add_argument(
        "--superadmin-email", default=env_email, required=env_email is None
    )
    parser.add_argument(
        "--superadmin-username", default=env_username, required=env_username is None
    )
    parser.add_argument(
        "--superadmin-first-name",
        default=os.environ.get("CLOUDGUEST_SEED_SUPERADMIN_FIRST_NAME", "Super"),
    )
    parser.add_argument(
        "--superadmin-last-name",
        default=os.environ.get("CLOUDGUEST_SEED_SUPERADMIN_LAST_NAME", "Admin"),
    )
    return parser.parse_args(argv)


def _resolve_password() -> str:
    password = os.environ.get("CLOUDGUEST_SEED_SUPERADMIN_PASSWORD")
    if password:
        return password
    password = getpass.getpass("Super Admin password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    return password


async def _main_async(args: argparse.Namespace, password: str) -> None:
    async with SessionLocal() as session:
        result = await run_seed(
            session,
            email=args.superadmin_email,
            username=args.superadmin_username,
            first_name=args.superadmin_first_name,
            last_name=args.superadmin_last_name,
            password=password,
        )
        await session.commit()

    logger.info("seed_completed", extra={"result": result})
    print(  # noqa: T201 -- CLI entrypoint output
        f"RBAC: {result.rbac}\n"
        f"Super Admin user: {result.superadmin_user_id} "
        f"({'created' if result.superadmin_user_created else 'already existed'})\n"
        "Super Admin role assignment: "
        f"{'created' if result.superadmin_role_assigned else 'already held'}\n"
        f"Default system template: {result.default_template_id} "
        f"({'created' if result.default_template_created else 'already existed'})"
    )


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    password = _resolve_password()
    asyncio.run(_main_async(args, password))


if __name__ == "__main__":
    main()
