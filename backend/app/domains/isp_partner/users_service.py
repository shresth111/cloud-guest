"""ISP staff users (API_CONTRACT §4.11).

Users are created only in the ISP's own organization and only with an
``isp-*`` role. ``UserService.create_user`` is called **without**
``initial_role_id`` (that path runs ``RBACService.assign_role_to_user``,
which checks ``roles.assign`` -- a key ISP roles intentionally lack); the
role row is written here through ``RBACRepository`` and the permission cache
is invalidated. ``_assert_isp_role`` runs before every role write, so this
module can never write a role id that does not resolve to an ``isp-*`` slug,
or with an organization other than the ISP's.

Service rules (§1.3):

* ``isp-admin`` cannot create, modify, disable or reset an ``isp-owner``;
* only ``isp-owner`` can grant ``isp-owner`` or ``isp-admin``;
* owners and admins cannot be confined;
* the last active ``isp-owner`` cannot be disabled or demoted (409).
"""

from __future__ import annotations

import secrets
import string
import uuid
from datetime import UTC, datetime
from typing import Any

from app.core.email_layout import button, esc, heading, info_box, paragraph, render_email
from app.domains.auth.password import PasswordManager
from app.domains.auth.service import EmailAlreadyExistsError, UsernameAlreadyExistsError
from app.domains.notification.constants import (
    NotificationChannelType,
    NotificationEventType,
)
from app.domains.rbac.enums import ScopeType

from .config import get_isp_partner_settings
from .constants import (
    AUDIT_ISP_USER_CREATED,
    AUDIT_ISP_USER_PASSWORD_RESET,
    AUDIT_ISP_USER_SCOPE_CHANGED,
    AUDIT_ROLE_ASSIGNED,
    ISP_ROLE_SLUGS,
    OWNER_GRANTED_ROLES,
    UNCONFINABLE_ROLES,
    IspRole,
)
from .dependencies import IspContext
from .exceptions import (
    IspConfinementNotAllowedError,
    IspLastOwnerError,
    IspRoleEscalationError,
    IspRoleInvalidError,
    IspUserNotFoundError,
    UserEmailTakenError,
)
from .rbac_roles import ROLES
from .scoping import IspScope
from .views import page

_SPECIALS = "!@#%^&*-_=+"


def temporary_password(length: int = 16) -> str:
    """Satisfies ``PasswordManager.validate_strength`` by construction."""
    alphabet = string.ascii_letters + string.digits
    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(_SPECIALS),
    ] + [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class IspUsersService:
    def __init__(
        self,
        *,
        repository: Any,
        user_service: Any,
        identity_repository: Any,
        rbac_repository: Any,
        permission_cache: Any,
        audit: Any,
    ) -> None:
        self.repository = repository
        self.user_service = user_service
        self.identity_repository = identity_repository
        self.rbac_repository = rbac_repository
        self.permission_cache = permission_cache
        self.audit = audit

    # -- helpers ---------------------------------------------------------
    async def _audit(
        self, isp: IspContext, action: str, user_id: uuid.UUID, description: str, **meta: Any
    ) -> None:
        await self.audit.create_audit_log_entry(
            actor_user_id=isp.user_id,
            action=action,
            entity_type="user",
            entity_id=user_id,
            description=description,
            event_metadata={
                "console": "isp",
                "isp_organization_id": str(isp.isp_org_id),
                **meta,
            },
            organization_id=isp.isp_org_id,
            location_id=None,
        )

    @staticmethod
    def _check_role(slug: str) -> None:
        if slug not in ISP_ROLE_SLUGS:
            raise IspRoleInvalidError()

    @staticmethod
    def _check_grant(isp: IspContext, slug: str) -> None:
        if slug in OWNER_GRANTED_ROLES and isp.role_slug != IspRole.OWNER:
            raise IspRoleEscalationError("Only an ISP owner can grant owner or admin")

    @staticmethod
    def _check_target(isp: IspContext, target_role: str) -> None:
        if target_role == IspRole.OWNER and isp.role_slug != IspRole.OWNER:
            raise IspRoleEscalationError("Only an ISP owner can manage an owner")

    async def _role_row(self, slug: str) -> Any:
        role = await self.rbac_repository.get_role_by_slug(slug, None)
        if role is None:
            raise IspRoleInvalidError("ISP roles are not seeded on this platform yet")
        await self._assert_isp_role(role)
        return role

    @staticmethod
    async def _assert_isp_role(role: Any) -> None:
        """The only role ids this module ever writes."""
        if role.slug not in ISP_ROLE_SLUGS or role.organization_id is not None:
            raise IspRoleInvalidError()

    async def _confinement(
        self, isp: IspContext, slug: str, customer_ids: list[uuid.UUID] | None
    ) -> list[uuid.UUID] | None:
        if customer_ids is None:
            return None
        if slug in UNCONFINABLE_ROLES:
            raise IspConfinementNotAllowedError()
        out: list[uuid.UUID] = []
        for customer_id in customer_ids:
            await IspScope.assert_customer(isp, customer_id)
            if customer_id not in out:
                out.append(customer_id)
        return out

    async def _target(self, isp: IspContext, isp_user_id: uuid.UUID) -> tuple[Any, Any, Any]:
        """(user, assignment, role) for a user whose isp-* role is on this
        ISP org; anything else is the same 404."""
        rows = await self.repository.isp_role_assignments(isp.isp_org_id, user_id=isp_user_id)
        user = await self.repository.get_user(isp_user_id)
        if not rows or user is None or getattr(user, "is_deleted", False):
            raise IspUserNotFoundError()
        assignment, role = rows[0]
        return user, assignment, role

    async def _view(self, isp: IspContext, user: Any, role_slug: str) -> dict:
        scopes = await self.repository.scopes_for_users(isp.isp_org_id, [user.id])
        scope_ids = scopes.get(user.id)
        names = {}
        if scope_ids:
            from app.domains.organization.models import Organization

            names = await self.repository.names(Organization, scope_ids)
        return {
            "id": str(user.id),
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "phone": user.phone,
            "username": user.username,
            "role": role_slug,
            "status": "active" if user.is_active else "disabled",
            "customer_scope": (
                [{"isp_customer_id": str(c), "name": names.get(c)} for c in scope_ids]
                if scope_ids
                else None
            ),
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }

    async def _grant(self, isp: IspContext, user_id: uuid.UUID, role: Any) -> None:
        await self._assert_isp_role(role)
        await self.rbac_repository.create_user_role(
            user_id=user_id,
            role_id=role.id,
            scope_type=ScopeType.ORGANIZATION.value,
            organization_id=isp.isp_org_id,
            location_id=None,
            router_id=None,
            granted_at=datetime.now(UTC),
            granted_by=isp.user_id,
            expires_at=None,
            is_active=True,
        )
        await self.permission_cache.invalidate(user_id)
        await self._audit(isp, AUDIT_ROLE_ASSIGNED, user_id, f"Role '{role.slug}' assigned", role=role.slug)

    async def _send_welcome(self, user: Any, password: str, isp: IspContext) -> None:
        login_url = get_isp_partner_settings().login_url
        content = (
            heading("Your Wyfy Guest Network account")
            + paragraph(
                f"Hi {esc(user.first_name)}, {esc(isp.organization.name)} has created "
                "an account for you. You'll be asked to set a new password the first "
                "time you sign in."
            )
            + info_box(
                [("Username", esc(user.username)), ("Temporary password", esc(password))],
                mono_values=True,
            )
            + button("Sign in", login_url)
        )
        await self.user_service.notification_service.enqueue(
            event_type=NotificationEventType.USER_INVITED,
            channel=NotificationChannelType.EMAIL,
            recipient=user.email,
            subject="Your Wyfy Guest Network account",
            body=render_email(
                preheader="An account has been created for you.", content_html=content
            ),
            organization_id=isp.isp_org_id,
        )

    # -- reads -----------------------------------------------------------
    async def list_users(
        self,
        isp: IspContext,
        *,
        search: str | None,
        role: str | None,
        status: str | None,
        page_no: int,
        page_size: int,
    ) -> dict:
        rows, total = await self.repository.list_staff(
            isp.isp_org_id,
            search=search,
            role=role,
            status=status,
            page=page_no,
            page_size=page_size,
        )
        items = [await self._view(isp, u, slug) for u, slug in rows]
        return page(items, total, page_no, page_size)

    async def get_user(self, isp: IspContext, isp_user_id: uuid.UUID) -> dict:
        user, _, role = await self._target(isp, isp_user_id)
        return await self._view(isp, user, role.slug)

    @staticmethod
    def roles() -> list[dict]:
        return [
            {
                "slug": r.slug,
                "name": r.name,
                "description": r.description,
                "permissions": list(r.permission_keys),
                "confinable": r.slug not in UNCONFINABLE_ROLES,
            }
            for r in ROLES
        ]

    # -- writes ----------------------------------------------------------
    async def create_user(self, isp: IspContext, data: dict[str, Any]) -> dict:
        slug = data["role"]
        self._check_role(slug)
        self._check_grant(isp, slug)
        confinement = await self._confinement(isp, slug, data.get("customer_ids"))
        role = await self._role_row(slug)
        password = temporary_password()
        try:
            user = await self.user_service.create_user(
                actor_user_id=isp.user_id,
                first_name=data["first_name"],
                last_name=data["last_name"],
                email=data["email"],
                username=data["email"],
                temporary_password=password,
                requesting_organization_id=isp.isp_org_id,
                phone=data.get("phone"),
                timezone=isp.organization.timezone or "UTC",
                organization_id=isp.isp_org_id,
                initial_role_id=None,
            )
        except (EmailAlreadyExistsError, UsernameAlreadyExistsError) as exc:
            raise UserEmailTakenError() from exc
        user = await self.identity_repository.update_user(user, must_change_password=True)
        await self._grant(isp, user.id, role)
        if confinement:
            await self.repository.replace_scopes(
                isp.isp_org_id, user.id, confinement, actor_user_id=isp.user_id
            )
        await self._audit(isp, AUDIT_ISP_USER_CREATED, user.id, "ISP user created", role=slug)
        if data.get("send_welcome_email", True):
            try:
                await self._send_welcome(user, password, isp)
            except Exception:  # noqa: BLE001 -- the account exists either way
                import logging

                logging.getLogger(__name__).exception("isp_user_welcome_email_failed")
        return {"user": await self._view(isp, user, slug), "temporary_password": password}

    async def update_user(
        self, isp: IspContext, isp_user_id: uuid.UUID, data: dict[str, Any]
    ) -> dict:
        user, assignment, role = await self._target(isp, isp_user_id)
        self._check_target(isp, role.slug)
        new_slug = data.pop("role", None)
        profile = {k: v for k, v in data.items() if k in {"first_name", "last_name", "phone"}}
        if profile:
            user = await self.identity_repository.update_user(user, **profile)
        if new_slug is not None and new_slug != role.slug:
            self._check_role(new_slug)
            self._check_grant(isp, new_slug)
            if (
                role.slug == IspRole.OWNER
                and await self.repository.count_active_owners(isp.isp_org_id) <= 1
            ):
                raise IspLastOwnerError()
            new_role = await self._role_row(new_slug)
            await self.rbac_repository.deactivate_user_role(assignment)
            await self._grant(isp, user.id, new_role)
            if new_slug in UNCONFINABLE_ROLES:
                await self.repository.replace_scopes(
                    isp.isp_org_id, user.id, None, actor_user_id=isp.user_id
                )
            role = new_role
        return await self._view(isp, user, role.slug)

    async def set_scope(
        self, isp: IspContext, isp_user_id: uuid.UUID, customer_ids: list[uuid.UUID] | None
    ) -> dict:
        user, _, role = await self._target(isp, isp_user_id)
        self._check_target(isp, role.slug)
        confinement = await self._confinement(isp, role.slug, customer_ids)
        await self.repository.replace_scopes(
            isp.isp_org_id, user.id, confinement, actor_user_id=isp.user_id
        )
        await self.permission_cache.invalidate(user.id)
        await self._audit(
            isp,
            AUDIT_ISP_USER_SCOPE_CHANGED,
            user.id,
            "ISP user customer scope changed",
            customer_ids=[str(c) for c in confinement or []],
        )
        return await self._view(isp, user, role.slug)

    async def set_enabled(self, isp: IspContext, isp_user_id: uuid.UUID, enabled: bool) -> dict:
        user, _, role = await self._target(isp, isp_user_id)
        self._check_target(isp, role.slug)
        if enabled:
            user = await self.user_service.reactivate_user(
                actor_user_id=isp.user_id,
                user_id=user.id,
                requesting_organization_id=isp.isp_org_id,
            )
        else:
            if (
                role.slug == IspRole.OWNER
                and await self.repository.count_active_owners(isp.isp_org_id) <= 1
            ):
                raise IspLastOwnerError()
            user = await self.user_service.deactivate_user(
                actor_user_id=isp.user_id,
                user_id=user.id,
                requesting_organization_id=isp.isp_org_id,
            )
        return await self._view(isp, user, role.slug)

    async def reset_password(self, isp: IspContext, isp_user_id: uuid.UUID) -> dict:
        user, _, role = await self._target(isp, isp_user_id)
        self._check_target(isp, role.slug)
        password = temporary_password()
        user = await self.identity_repository.update_user(
            user,
            password_hash=PasswordManager.hash(password),
            must_change_password=True,
            password_changed_at=datetime.now(UTC),
            failed_login_attempts=0,
            locked_until=None,
        )
        # Old sessions end with the old password.
        user = await self.user_service.force_logout_user(
            actor_user_id=isp.user_id, user_id=user.id, requesting_organization_id=isp.isp_org_id
        )
        await self._audit(isp, AUDIT_ISP_USER_PASSWORD_RESET, user.id, "ISP user password reset")
        return {"user": await self._view(isp, user, role.slug), "temporary_password": password}

    async def force_logout(self, isp: IspContext, isp_user_id: uuid.UUID) -> dict:
        user, _, role = await self._target(isp, isp_user_id)
        self._check_target(isp, role.slug)
        user = await self.user_service.force_logout_user(
            actor_user_id=isp.user_id, user_id=user.id, requesting_organization_id=isp.isp_org_id
        )
        return await self._view(isp, user, role.slug)
