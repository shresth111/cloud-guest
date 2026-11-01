"""Master-side ISP partner management (API_CONTRACT §3, TASKS FS-1).

Only the Master console creates an ISP partner (founder rule 3). The router
pins every route to ``ScopeType.GLOBAL``; this service adds the invariants
that make "only Master creates dashboards" true at the data level too:

* the ISP organization is always ``org_type="msp"`` with **no parent**. Neither
  is an input; ``IspPartnerCreateRequest`` cannot express them;
* the first owner is created **in the ISP organization only**, with the
  seeded system role ``isp-owner`` and ``must_change_password=True``;
* create is **one transaction**: every step writes through the request's
  single ``AsyncSession`` (no step commits), so any failure after the org or
  the owner exists rolls the whole request back in ``get_db_session``.

Suspension sets the profile ``suspended``, suspends the ISP organization, and
disables every enabled ACS credential of the ISP, so CPEs get 401 at the edge.
The ids it disabled are recorded in the ``isp_partner_suspended`` audit row,
and activation re-enables exactly those. A customer whose TR-069 was already
off stays off. Customers' organizations, guest sessions, RADIUS and portals
are not touched (STATUS Q4 default).
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from fastapi import status

from app.core.email_layout import (
    button,
    esc,
    heading,
    info_box,
    paragraph,
    render_email,
)
from app.domains.auth.models import User
from app.domains.auth.password import PasswordManager
from app.domains.auth.service import EmailAlreadyExistsError, UsernameAlreadyExistsError
from app.domains.billing.exceptions import PlanNotFoundError
from app.domains.notification.constants import (
    NotificationChannelType,
    NotificationEventType,
)
from app.domains.organization.enums import OrganizationStatus, OrganizationType
from app.domains.organization.exceptions import DuplicateSlugError
from app.domains.organization.models import Organization
from app.domains.rbac.enums import ScopeType

from .constants import (
    AUDIT_ISP_USER_PASSWORD_RESET,
    ISP_ROLE_SLUGS,
    IspProfileStatus,
    IspRole,
)
from .exceptions import (
    IspError,
    IspPartnerNotFoundError,
    IspSlugTakenError,
    IspUserNotFoundError,
    UserEmailTakenError,
)
from .models import IspPartnerProfile
from .platform_repository import AUDIT_ENTITY_ISP_PARTNER, Counts, IspPlatformRepository
from .platform_schemas import (
    IspOwnerCredentialResponse,
    IspOwnerRequest,
    IspPartnerAcsView,
    IspPartnerCounts,
    IspPartnerCreateRequest,
    IspPartnerCreateResponse,
    IspPartnerListResponse,
    IspPartnerOwnerView,
    IspPartnerResponse,
    IspPartnerUpdateRequest,
    PlanRef,
)

AUDIT_ISP_PARTNER_CREATED = "isp_partner_created"
AUDIT_ISP_PARTNER_UPDATED = "isp_partner_updated"
AUDIT_ISP_PARTNER_SUSPENDED = "isp_partner_suspended"
AUDIT_ISP_PARTNER_ACTIVATED = "isp_partner_activated"
AUDIT_ISP_PARTNER_OWNER_ADDED = "isp_partner_owner_added"

_PROFILE_FIELDS = ("gstin", "support_phone", "support_email", "max_customers", "notes")
_ORG_FIELDS = ("name", "legal_name", "contact_email", "contact_phone", "timezone")


class IspPlanNotFoundError(IspError):
    code = "PLAN_NOT_FOUND"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_message = "The selected plan does not exist."


class IspRolesNotSeededError(IspError):
    """``python -m app.domains.isp_partner.seed`` has not run on this
    database, so there is no ``isp-owner`` role to grant."""

    code = "ISP_ROLES_NOT_SEEDED"
    status_code_default = status.HTTP_503_SERVICE_UNAVAILABLE
    default_message = (
        "ISP roles are not seeded on this server. "
        "Run python -m app.domains.isp_partner.seed."
    )


# -- collaborators (existing services, composed, never modified) ---------------
class _OrganizationService(Protocol):
    async def create_organization(self, **kwargs: Any) -> Organization: ...
    async def update_organization(self, **kwargs: Any) -> Organization: ...
    async def suspend_organization(self, **kwargs: Any) -> Organization: ...
    async def activate_organization(self, **kwargs: Any) -> Organization: ...


class _UserService(Protocol):
    async def create_user(self, **kwargs: Any) -> User: ...
    async def force_logout_user(self, **kwargs: Any) -> Any: ...


class _IdentityRepository(Protocol):
    async def update_user(self, user: Any, **fields: object) -> Any: ...
    async def get_user_by_id(self, user_id: uuid.UUID) -> Any: ...


class _RbacRepository(Protocol):
    async def get_role_by_slug(
        self, slug: str, organization_id: uuid.UUID | None
    ) -> Any: ...
    async def create_audit_log_entry(self, **fields: object) -> object: ...
    async def create_user_role(self, **fields: object) -> object: ...


class _PlanService(Protocol):
    async def get_plan(self, plan_id: uuid.UUID) -> Any: ...


class _CredentialStore(Protocol):
    async def ensure(
        self, isp_org_id: uuid.UUID, customer_org_id: uuid.UUID | None, **kwargs: Any
    ) -> Any: ...


class _IspRoleLookup(Protocol):
    async def isp_role_assignments(
        self, isp_org_id: uuid.UUID, *, user_id: uuid.UUID | None = None
    ) -> list[tuple[Any, Any]]: ...


class _Notifications(Protocol):
    async def enqueue(self, **kwargs: Any) -> Any: ...


# -- helpers ---------------------------------------------------------------------
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_LOWER = "abcdefghijkmnopqrstuvwxyz"
_DIGITS = "23456789"
_SPECIAL = "!@#$"


def generate_temporary_password(length: int = 16) -> str:
    """Same policy as the existing provisioning flows: ``secrets``, one of each
    class, exactly one special character, no look-alike glyphs."""
    chars = [secrets.choice(_UPPER), secrets.choice(_LOWER), secrets.choice(_DIGITS)]
    chars.append(secrets.choice(_SPECIAL))
    pool = _UPPER + _LOWER + _DIGITS
    chars.extend(secrets.choice(pool) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _username_for(email: str) -> str:
    return email.strip().lower()


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


class IspOwnerGrantRefusedError(IspError):
    """Defence in depth: the direct isp-owner write was asked to grant
    something other than the system isp-owner role on an MSP org."""

    code = "ISP_OWNER_GRANT_REFUSED"
    status_code_default = status.HTTP_403_FORBIDDEN
    default_message = (
        "Only the isp-owner role on an ISP organization can be granted here."
    )


def _assert_owner_grant(role: Any, isp_org: Any) -> None:
    if (
        getattr(role, "slug", None) != IspRole.OWNER.value
        or getattr(role, "organization_id", None) is not None
        or getattr(isp_org, "org_type", None) != OrganizationType.MSP.value
        or getattr(isp_org, "parent_organization_id", None) is not None
    ):
        raise IspOwnerGrantRefusedError()


@dataclass(frozen=True, slots=True)
class OwnerCredential:
    user: Any
    username: str
    temporary_password: str


class IspPartnerPlatformService:
    def __init__(
        self,
        repository: IspPlatformRepository,
        organization_service: _OrganizationService,
        user_service: _UserService,
        identity_repository: _IdentityRepository,
        rbac_repository: _RbacRepository,
        plan_service: _PlanService,
        credentials: _CredentialStore,
        isp_roles: _IspRoleLookup,
        notifications: _Notifications,
        *,
        login_url: str,
        permission_cache: Any = None,
    ) -> None:
        self.repository = repository
        self.organization_service = organization_service
        self.user_service = user_service
        self.identity_repository = identity_repository
        self.rbac_repository = rbac_repository
        self.plan_service = plan_service
        self.credentials = credentials
        self.isp_roles = isp_roles
        self.notifications = notifications
        self.login_url = login_url.rstrip("/") or login_url
        self.permission_cache = permission_cache

    # ---------------------------------------------------------------- reads
    async def list_partners(
        self,
        *,
        page: int,
        page_size: int,
        status_filter: str | None,
        search: str | None,
    ) -> IspPartnerListResponse:
        result = await self.repository.list(
            page=page, page_size=page_size, status=status_filter, search=search
        )
        ids = [org.id for _, org in result.rows]
        counts = await self.repository.counts(ids)
        plans = await self.repository.plan_names(
            [p.default_customer_plan_id for p, _ in result.rows]
        )
        return IspPartnerListResponse(
            items=[
                self._view(p, o, counts.get(o.id, Counts()), plans)
                for p, o in result.rows
            ],
            total=result.total,
            page=result.page,
            page_size=result.page_size,
            pages=result.pages,
        )

    async def get_partner(self, isp_org_id: uuid.UUID) -> IspPartnerResponse:
        profile, org = await self._load(isp_org_id)
        return await self._detail(profile, org)

    # --------------------------------------------------------------- create
    async def create_partner(
        self, *, actor_user_id: uuid.UUID, data: IspPartnerCreateRequest
    ) -> IspPartnerCreateResponse:
        await self._assert_plan(data.default_customer_plan_id)
        owner_role = await self._owner_role()

        # 1. the ISP organization: always a top-level MSP
        try:
            org = await self.organization_service.create_organization(
                actor_user_id=actor_user_id,
                name=data.name,
                slug=data.slug,
                contact_email=data.contact_email,
                legal_name=_clean(data.legal_name),
                org_type=OrganizationType.MSP,
                status=OrganizationStatus.ACTIVE,
                parent_organization_id=None,
                contact_phone=_clean(data.contact_phone),
                timezone=data.timezone,
                settings={"onboarded_via": "isp_partner_platform"},
            )
        except DuplicateSlugError as exc:
            raise IspSlugTakenError(
                "This slug is already taken.", slug=data.slug
            ) from exc

        # 2. the profile that makes it an ISP
        profile = IspPartnerProfile(
            organization_id=org.id,
            status=IspProfileStatus.ACTIVE.value,
            gstin=data.gstin,
            support_phone=_clean(data.support_phone),
            support_email=data.support_email,
            default_customer_plan_id=data.default_customer_plan_id,
            max_customers=data.max_customers,
            notes=_clean(data.notes),
            created_by=actor_user_id,
        )
        self.repository.session.add(profile)
        await self.repository.session.flush()

        # 3. the ISP's own ACS credential (customer NULL: CPEs arrive unassigned)
        await self.credentials.ensure(
            org.id, None, actor_user_id=actor_user_id, enabled=True
        )

        # 4. the first isp-owner, in the ISP org only
        credential = await self._create_owner(
            actor_user_id=actor_user_id,
            isp_org=org,
            role=owner_role,
            owner=data.owner,
        )

        # 5. audit
        await self._audit(
            actor_user_id,
            AUDIT_ISP_PARTNER_CREATED,
            org.id,
            f"ISP partner '{org.name}' created",
            {
                "owner_user_id": str(credential.user.id),
                "default_customer_plan_id": str(data.default_customer_plan_id),
            },
        )

        # 6. optional welcome mail (outbox row in the same transaction)
        if data.owner.send_welcome_email:
            await self._send_welcome(org, credential)

        return IspPartnerCreateResponse(
            isp_partner=await self._detail(profile, org),
            owner=self._credential_view(credential),
        )

    # ---------------------------------------------------------------- update
    async def update_partner(
        self,
        *,
        actor_user_id: uuid.UUID,
        isp_org_id: uuid.UUID,
        data: IspPartnerUpdateRequest,
    ) -> IspPartnerResponse:
        profile, org = await self._load(isp_org_id)
        fields = data.model_dump(exclude_unset=True)

        if fields.get("default_customer_plan_id") is not None:
            await self._assert_plan(fields["default_customer_plan_id"])
            profile.default_customer_plan_id = fields["default_customer_plan_id"]
        for key in _PROFILE_FIELDS:
            if key in fields:
                value = fields[key]
                setattr(
                    profile, key, _clean(value) if isinstance(value, str) else value
                )

        org_changes = {k: fields[k] for k in _ORG_FIELDS if k in fields}
        if "name" in org_changes and org_changes["name"] is None:
            org_changes.pop("name")
        if "contact_email" in org_changes and org_changes["contact_email"] is None:
            org_changes.pop("contact_email")  # organizations.contact_email is NOT NULL
        if org_changes:
            org = await self.organization_service.update_organization(
                actor_user_id=actor_user_id,
                organization_id=org.id,
                requesting_organization_id=None,
                data=org_changes,
            )
        profile.updated_by = actor_user_id
        await self.repository.session.flush()
        await self._audit(
            actor_user_id,
            AUDIT_ISP_PARTNER_UPDATED,
            org.id,
            f"ISP partner '{org.name}' updated",
            {"fields": sorted(fields)},
        )
        return await self._detail(profile, org)

    # ------------------------------------------------------ suspend/activate
    async def suspend_partner(
        self, *, actor_user_id: uuid.UUID, isp_org_id: uuid.UUID, reason: str
    ) -> IspPartnerResponse:
        profile, org = await self._load(isp_org_id)
        disabled: list[uuid.UUID] = []
        if profile.status != IspProfileStatus.SUSPENDED.value:
            profile.status = IspProfileStatus.SUSPENDED.value
            profile.suspended_at = datetime.now(UTC)
            profile.suspended_reason = reason.strip()
            profile.updated_by = actor_user_id
            disabled = await self.repository.enabled_credential_ids(org.id)
            await self.repository.set_credentials_enabled(
                org.id, disabled, False, actor_user_id=actor_user_id
            )
            await self.repository.session.flush()
        if org.status != OrganizationStatus.SUSPENDED.value:
            org = await self.organization_service.suspend_organization(
                actor_user_id=actor_user_id,
                organization_id=org.id,
                requesting_organization_id=None,
            )
        await self._audit(
            actor_user_id,
            AUDIT_ISP_PARTNER_SUSPENDED,
            org.id,
            f"ISP partner '{org.name}' suspended",
            {
                "reason": reason.strip(),
                "disabled_credential_ids": [str(i) for i in disabled],
            },
        )
        return await self._detail(profile, org)

    async def activate_partner(
        self, *, actor_user_id: uuid.UUID, isp_org_id: uuid.UUID
    ) -> IspPartnerResponse:
        profile, org = await self._load(isp_org_id)
        reenabled: list[uuid.UUID] = []
        if profile.status != IspProfileStatus.ACTIVE.value:
            meta = await self.repository.last_suspension_metadata(org.id) or {}
            reenabled = [uuid.UUID(i) for i in meta.get("disabled_credential_ids", [])]
            isp_cred = await self.repository.isp_credential(org.id)
            if isp_cred is not None and isp_cred.id not in reenabled:
                # the ISP credential always comes back with the ISP
                reenabled.append(isp_cred.id)
            await self.repository.set_credentials_enabled(
                org.id, reenabled, True, actor_user_id=actor_user_id
            )
            profile.status = IspProfileStatus.ACTIVE.value
            profile.suspended_at = None
            profile.suspended_reason = None
            profile.updated_by = actor_user_id
            await self.repository.session.flush()
        if org.status != OrganizationStatus.ACTIVE.value:
            org = await self.organization_service.activate_organization(
                actor_user_id=actor_user_id,
                organization_id=org.id,
                requesting_organization_id=None,
            )
        await self._audit(
            actor_user_id,
            AUDIT_ISP_PARTNER_ACTIVATED,
            org.id,
            f"ISP partner '{org.name}' reactivated",
            {"reenabled_credential_ids": [str(i) for i in reenabled]},
        )
        return await self._detail(profile, org)

    # ------------------------------------------------------- owners / users
    async def add_owner(
        self, *, actor_user_id: uuid.UUID, isp_org_id: uuid.UUID, data: IspOwnerRequest
    ) -> IspOwnerCredentialResponse:
        _, org = await self._load(isp_org_id)
        role = await self._owner_role()
        credential = await self._create_owner(
            actor_user_id=actor_user_id, isp_org=org, role=role, owner=data
        )
        await self._audit(
            actor_user_id,
            AUDIT_ISP_PARTNER_OWNER_ADDED,
            org.id,
            f"ISP owner '{credential.user.email}' added to '{org.name}'",
            {"owner_user_id": str(credential.user.id)},
        )
        if data.send_welcome_email:
            await self._send_welcome(org, credential)
        return self._credential_view(credential)

    async def reset_user_password(
        self, *, actor_user_id: uuid.UUID, isp_org_id: uuid.UUID, isp_user_id: uuid.UUID
    ) -> IspOwnerCredentialResponse:
        _, org = await self._load(isp_org_id)
        assignments = await self.isp_roles.isp_role_assignments(
            org.id, user_id=isp_user_id
        )
        if not any(role.slug in ISP_ROLE_SLUGS for _, role in assignments):
            raise IspUserNotFoundError("No ISP user with this id on this ISP.")
        user = await self.identity_repository.get_user_by_id(isp_user_id)
        if user is None:
            raise IspUserNotFoundError("No ISP user with this id on this ISP.")
        password = generate_temporary_password()
        user = await self.identity_repository.update_user(
            user,
            password_hash=PasswordManager.hash(password),
            must_change_password=True,
            password_changed_at=datetime.now(UTC),
            failed_login_attempts=0,
            locked_until=None,
        )
        # Existing sessions end with the old password.
        await self.user_service.force_logout_user(
            actor_user_id=actor_user_id,
            user_id=user.id,
            requesting_organization_id=None,
        )
        await self._audit(
            actor_user_id,
            AUDIT_ISP_USER_PASSWORD_RESET,
            org.id,
            f"Password reset for ISP user '{user.email}' by Master",
            {"isp_user_id": str(user.id)},
        )
        return self._credential_view(
            OwnerCredential(
                user=user, username=user.username, temporary_password=password
            )
        )

    # -------------------------------------------------------------- internals
    async def _load(
        self, isp_org_id: uuid.UUID
    ) -> tuple[IspPartnerProfile, Organization]:
        found = await self.repository.get(isp_org_id)
        if found is None:
            raise IspPartnerNotFoundError("No ISP partner with this id.")
        return found

    async def _assert_plan(self, plan_id: uuid.UUID) -> None:
        try:
            await self.plan_service.get_plan(plan_id)
        except PlanNotFoundError as exc:
            raise IspPlanNotFoundError(plan_id=str(plan_id)) from exc

    async def _owner_role(self) -> Any:
        role = await self.rbac_repository.get_role_by_slug(IspRole.OWNER.value, None)
        if role is None:
            raise IspRolesNotSeededError()
        return role

    async def _create_owner(
        self,
        *,
        actor_user_id: uuid.UUID,
        isp_org: Organization,
        role: Any,
        owner: IspOwnerRequest,
    ) -> OwnerCredential:
        # This method writes a user_roles row WITHOUT RBACService's escalation
        # guard (see the comment at create_user below). Its blast radius is
        # therefore pinned here, independently of the GLOBAL-pinned routes
        # that are its only callers: it can only ever grant the system
        # isp-owner role, and only on an MSP organization that is an ISP.
        _assert_owner_grant(role, isp_org)
        username = _username_for(owner.email)
        password = generate_temporary_password()
        try:
            user = await self.user_service.create_user(
                actor_user_id=actor_user_id,
                first_name=owner.first_name,
                last_name=owner.last_name,
                email=owner.email,
                username=username,
                temporary_password=password,
                requesting_organization_id=None,
                phone=_clean(owner.phone),
                timezone=isp_org.timezone or "UTC",
                organization_id=isp_org.id,
                # Not initial_role_id: that path runs
                # RBACService.assign_role_to_user, whose escalation guard
                # refuses a role granting keys the actor lacks, and by design
                # no existing role (Super Admin included) holds an isp_* key.
                # The isp-owner row is written directly below, as the BE
                # lane's users_service does for ISP staff.
                initial_role_id=None,
            )
        except (EmailAlreadyExistsError, UsernameAlreadyExistsError) as exc:
            raise UserEmailTakenError(
                "A user with this email already exists.", email=owner.email
            ) from exc
        await self.rbac_repository.create_user_role(
            user_id=user.id,
            role_id=role.id,
            scope_type=ScopeType.ORGANIZATION.value,
            organization_id=isp_org.id,
            location_id=None,
            router_id=None,
            granted_at=datetime.now(UTC),
            granted_by=actor_user_id,
            expires_at=None,
            is_active=True,
        )
        if self.permission_cache is not None:
            await self.permission_cache.invalidate(user.id)
        user = await self.identity_repository.update_user(
            user, must_change_password=True
        )
        return OwnerCredential(
            user=user, username=username, temporary_password=password
        )

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: str,
        isp_org_id: uuid.UUID,
        description: str,
        metadata: dict[str, Any],
    ) -> None:
        await self.rbac_repository.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=AUDIT_ENTITY_ISP_PARTNER,
            entity_id=isp_org_id,
            description=description,
            event_metadata={"console": "master", **metadata},
            organization_id=isp_org_id,
        )

    async def _send_welcome(
        self, org: Organization, credential: OwnerCredential
    ) -> None:
        user = credential.user
        content = (
            heading(f"Welcome to Wyfy Guest Network, {esc(user.first_name)}")
            + paragraph(
                f"The network dashboard for <strong>{esc(org.name)}</strong> is ready. "
                "Use these details to sign in for the first time."
            )
            + info_box(
                [
                    ("Username", esc(credential.username)),
                    ("Temporary password", esc(credential.temporary_password)),
                ],
                mono_values=True,
            )
            + button("Sign in to Wyfy Guest Network", self.login_url)
            + paragraph(
                "You'll be asked to set a new password at first sign-in.", muted=True
            )
        )
        await self.notifications.enqueue(
            event_type=NotificationEventType.USER_INVITED,
            channel=NotificationChannelType.EMAIL,
            recipient=user.email,
            subject=f"Your Wyfy Guest Network account for {org.name}",
            body=render_email(
                preheader=f"The network dashboard for {org.name} is ready.",
                content_html=content,
            ),
            organization_id=org.id,
        )

    def _credential_view(
        self, credential: OwnerCredential
    ) -> IspOwnerCredentialResponse:
        return IspOwnerCredentialResponse(
            user_id=credential.user.id,
            username=credential.username,
            email=credential.user.email,
            temporary_password=credential.temporary_password,
            login_url=self.login_url,
        )

    async def _detail(
        self, profile: IspPartnerProfile, org: Organization
    ) -> IspPartnerResponse:
        counts = (await self.repository.counts([org.id])).get(org.id, Counts())
        plans = await self.repository.plan_names([profile.default_customer_plan_id])
        view = self._view(profile, org, counts, plans)
        view.owners = [
            IspPartnerOwnerView(
                user_id=o.user_id,
                name=o.name,
                email=o.email,
                status="active" if o.is_active else "disabled",
            )
            for o in await self.repository.owners(org.id)
        ]
        cred = await self.repository.isp_credential(org.id)
        view.acs = (
            IspPartnerAcsView(username=cred.username, enabled=bool(cred.enabled))
            if cred
            else None
        )
        return view

    @staticmethod
    def _view(
        profile: IspPartnerProfile,
        org: Organization,
        counts: Counts,
        plans: dict[uuid.UUID, str],
    ) -> IspPartnerResponse:
        plan_name = plans.get(profile.default_customer_plan_id)
        return IspPartnerResponse(
            id=org.id,
            name=org.name,
            slug=org.slug,
            legal_name=org.legal_name,
            gstin=profile.gstin,
            status=profile.status,
            org_status=org.status,
            contact_email=org.contact_email,
            contact_phone=org.contact_phone,
            support_phone=profile.support_phone,
            support_email=profile.support_email,
            timezone=org.timezone,
            default_customer_plan=(
                PlanRef(id=profile.default_customer_plan_id, name=plan_name)
                if plan_name is not None
                else None
            ),
            max_customers=profile.max_customers,
            notes=profile.notes,
            counts=IspPartnerCounts(**counts.__dict__),
            created_at=org.created_at,
            suspended_at=profile.suspended_at,
            suspended_reason=profile.suspended_reason,
        )


__all__ = [
    "AUDIT_ISP_PARTNER_ACTIVATED",
    "AUDIT_ISP_PARTNER_CREATED",
    "AUDIT_ISP_PARTNER_OWNER_ADDED",
    "AUDIT_ISP_PARTNER_SUSPENDED",
    "AUDIT_ISP_PARTNER_UPDATED",
    "IspPartnerPlatformService",
    "IspPlanNotFoundError",
    "IspRolesNotSeededError",
    "generate_temporary_password",
]
