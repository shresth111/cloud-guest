"""``python -m app.domains.isp_partner.seed``: create the ISP RBAC rows.

New rows only, idempotent, and it never touches an existing role,
permission or grant:

* a permission group is created only if its key is absent;
* a permission is created only if its key is absent, and only the
  ORGANIZATION scope is added to it;
* an ``isp-*`` role is created only if its slug is absent, and only the
  ``role_permissions`` listed in ``rbac_roles`` are added to it.

Nothing here reads or writes a role whose slug is not one of the five
``isp-*`` slugs, so running ``python -m app.domains.rbac.seed`` before or
after this changes nothing either way (that seeder only walks
``SYSTEM_ROLES`` and ``MODULE_ACTIONS``, which do not name these rows).

After a deploy: run this, then flush ``rbac:effective_permissions:*`` for
affected users -- the deploy itself does not seed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .rbac_roles import (
    ALLOWED_SCOPE_TYPES,
    PERMISSION_GROUPS,
    ROLE_SCOPE_TYPE,
    ROLES,
)

logger = logging.getLogger(__name__)


@dataclass
class IspSeedSummary:
    permission_groups_created: int = 0
    permissions_created: int = 0
    permission_scopes_created: int = 0
    roles_created: int = 0
    role_scopes_created: int = 0
    role_permissions_created: int = 0
    #: Roles found under an isp-* slug that were not created by this seeder
    #: run and were left exactly as found (never "corrected").
    roles_skipped_existing: list[str] = field(default_factory=list)


class IspSeedConflictError(RuntimeError):
    """A slug we own exists but is not a system role. Refuse rather than
    grant ISP keys to something somebody else created."""


async def seed_isp_partner_rbac(repository: Any) -> IspSeedSummary:
    """Seed through the same ``RBACRepository`` calls ``rbac.seed`` uses."""
    summary = IspSeedSummary()

    permission_by_key: dict[str, Any] = {}
    for group_def in PERMISSION_GROUPS:
        group = await repository.get_permission_group_by_key(group_def.key)
        if group is None:
            group = await repository.create_permission_group(
                key=group_def.key,
                name=group_def.name,
                sort_order=group_def.sort_order,
            )
            summary.permission_groups_created += 1
        for action in group_def.actions:
            key = f"{group_def.key}.{action}"
            permission = await repository.get_permission_by_key(key)
            if permission is None:
                permission = await repository.create_permission(
                    permission_group_id=group.id,
                    key=key,
                    action=action,
                    name=f"{group_def.name}: {action.title()}",
                    description=f"{action.title()} access for {group_def.name}.",
                )
                summary.permissions_created += 1
            existing_scopes = set(
                await repository.get_permission_scope_types(permission.id)
            )
            for scope_type in ALLOWED_SCOPE_TYPES:
                if scope_type.value not in existing_scopes:
                    await repository.add_permission_scope(permission.id, scope_type)
                    summary.permission_scopes_created += 1
            permission_by_key[key] = permission

    for role_def in ROLES:
        role = await repository.get_role_by_slug(role_def.slug, None)
        if role is None:
            role = await repository.create_role(
                name=role_def.name,
                slug=role_def.slug,
                description=role_def.description,
                is_system_role=True,
                is_template=False,
                is_active=True,
                scope_type=ROLE_SCOPE_TYPE.value,
                organization_id=None,
                parent_role_id=None,
            )
            summary.roles_created += 1
        elif not getattr(role, "is_system_role", False):
            raise IspSeedConflictError(
                f"role slug {role_def.slug!r} exists and is not a system role"
            )

        if ROLE_SCOPE_TYPE.value not in set(
            await repository.get_role_scope_types(role.id)
        ):
            await repository.add_role_scope(role.id, ROLE_SCOPE_TYPE, is_default=True)
            summary.role_scopes_created += 1

        existing = {
            row.permission_id for row in await repository.get_role_permissions(role.id)
        }
        for key in role_def.permission_keys:
            permission = permission_by_key[key]
            if permission.id not in existing:
                await repository.add_role_permission(
                    role.id, permission.id, granted_by=None
                )
                summary.role_permissions_created += 1

    logger.info("isp_partner_seed_completed", extra={"summary": vars(summary)})
    return summary


async def _main() -> None:
    """CLI entrypoint. Imports the four model modules first, exactly as
    ``rbac.seed._main`` does, so ``roles.organization_id``'s FK resolves."""
    from app.database.session import SessionLocal
    from app.domains.auth.models import User  # noqa: F401
    from app.domains.location.models import Location  # noqa: F401
    from app.domains.organization.models import Organization  # noqa: F401
    from app.domains.rbac.repository import RBACRepository
    from app.domains.router.models import Router  # noqa: F401

    async with SessionLocal() as session:
        summary = await seed_isp_partner_rbac(RBACRepository(session))
        await session.commit()
        print(summary)  # noqa: T201 -- CLI entrypoint output


if __name__ == "__main__":
    import asyncio

    asyncio.run(_main())
