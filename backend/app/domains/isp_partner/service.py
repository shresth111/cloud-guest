"""ISP business logic: me, overview, customers, locations, routers, guests.

Composes existing services; never reimplements them. Every write into a
customer goes through ``IspScope`` first and then calls the existing service
with ``requesting_organization_id=<the customer>`` -- never ``None`` and never
the ISP id -- so the service-level tenant checks still bite.

Hard rules enforced here as well as in the schemas (BE-T 1-3):

* a customer is always ``org_type=STANDARD`` with ``parent = the ISP``;
  ``create_customer`` takes no org type or parent argument at all;
* no user, membership or role row is ever created for a customer.
"""

from __future__ import annotations

import logging
import re
import secrets
import uuid
from collections import Counter
from datetime import UTC, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.domains.captive_portal.validators import default_splash_headline
from app.domains.location.enums import LocationStatus
from app.domains.location.exceptions import DuplicateLocationSlugError
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationStatus, OrganizationType
from app.domains.organization.exceptions import DuplicateSlugError
from app.domains.organization.models import Organization
from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router
from app.domains.router.vendor_capabilities import is_agent_managed_row
from app.domains.tr069.credentials import CredentialStore

from .constants import (
    ATTENTION_CAP,
    ATTENTION_ROUTER_OFFLINE_MINUTES,
    ATTENTION_ROUTER_PENDING_HOURS,
    AUDIT_ISP_CUSTOMER_ACTIVATED,
    AUDIT_ISP_CUSTOMER_CREATED,
    AUDIT_ISP_CUSTOMER_SUSPENDED,
    AUDIT_ISP_CUSTOMER_UPDATED,
    SUSPEND_REASONS,
)
from .dependencies import IspContext
from .exceptions import (
    IspCustomerLimitError,
    IspCustomerSlugTakenError,
    IspExternalRefTakenError,
    IspImmutableFieldError,
    IspVendorNotSupportedError,
)
from .models import IspCustomerProfile
from .scoping import IspScope
from .views import (
    cloud_link,
    cpe_online,
    customer_view,
    location_view,
    page,
    router_view,
)

logger = logging.getLogger(__name__)

PENDING_STATUSES = {
    RouterStatus.PENDING_PROVISIONING.value,
    RouterStatus.PROVISIONING.value,
}
_SUSPEND_MARKER = "isp_tr069_disabled_by_suspension"
_PROFILE_FIELDS = (
    "zone_id",
    "external_ref",
    "contact_name",
    "gstin",
    "address_line1",
    "city",
    "state_province",
    "postal_code",
    "notes",
)
_ORG_FIELDS = ("name", "legal_name", "contact_email", "contact_phone", "timezone")


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:140] or "customer"


def zone_of(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or "Asia/Kolkata")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("Asia/Kolkata")


def start_of_today(tz_name: str | None, *, now: datetime | None = None) -> datetime:
    zone = zone_of(tz_name)
    local = (now or datetime.now(UTC)).astimezone(zone)
    return datetime.combine(local.date(), time.min, tzinfo=zone).astimezone(UTC)


class IspPartnerService:
    def __init__(
        self,
        *,
        repository: Any,
        organization_service: Any,
        location_service: Any,
        captive_portal_service: Any,
        subscription_service: Any,
        router_service: Any,
        audit: Any,
        credentials: CredentialStore | Any,
        default_alerting: Any = None,
        service_control: Any = None,
        clock: Any = None,
    ) -> None:
        self.service_control = service_control
        self.repository = repository
        self.organization_service = organization_service
        self.location_service = location_service
        self.captive_portal_service = captive_portal_service
        self.subscription_service = subscription_service
        self.router_service = router_service
        self.audit = audit
        self.credentials = credentials
        self.default_alerting = default_alerting
        self._clock = clock or (lambda: datetime.now(UTC))

    # -- audit -----------------------------------------------------------
    async def _audit(
        self,
        isp: IspContext,
        action: str,
        *,
        entity_type: str,
        entity_id: uuid.UUID | None,
        description: str,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        **metadata: Any,
    ) -> None:
        await self.audit.create_audit_log_entry(
            actor_user_id=isp.user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            event_metadata={
                "console": "isp",
                "isp_organization_id": str(isp.isp_org_id),
                **{
                    k: (str(v) if isinstance(v, uuid.UUID) else v)
                    for k, v in metadata.items()
                },
            },
            organization_id=organization_id or isp.isp_org_id,
            location_id=location_id,
        )

    # -- me --------------------------------------------------------------
    async def me(self, isp: IspContext, *, user: Any, permissions: list[str]) -> dict:
        org = isp.organization
        name = " ".join(
            p
            for p in (
                getattr(user, "first_name", None),
                getattr(user, "last_name", None),
            )
            if p
        )
        return {
            "isp": {
                "id": str(org.id),
                "name": org.name,
                "slug": org.slug,
                "status": isp.profile.status,
                "support_phone": isp.profile.support_phone,
                "support_email": isp.profile.support_email,
                "timezone": org.timezone,
            },
            "user": {
                "id": str(isp.user_id),
                "name": name or getattr(user, "email", ""),
                "email": getattr(user, "email", None),
                "role": isp.role_slug,
            },
            "permissions": sorted(permissions),
            "confined_customer_ids": (
                sorted(str(c) for c in isp.confined_customer_ids)
                if isp.confined_customer_ids is not None
                else None
            ),
        }

    # -- batched facts for views ------------------------------------------
    async def _facts(self, customer_ids: list[uuid.UUID]) -> dict[str, Any]:
        locations = await self.repository.locations_for_organizations(customer_ids)
        routers = await self.repository.routers_for_organizations(customer_ids)
        return {"locations": locations, "routers": routers}

    async def _tr069_facts(self, isp: IspContext) -> dict[str, Any]:
        creds = await self.repository.credentials_for_isp(isp.isp_org_id)
        devices = await self.repository.cpes_for_isp(isp.isp_org_id)
        return {
            "customer_enabled": {
                c.customer_organization_id
                for c in creds
                if c.customer_organization_id is not None and c.enabled
            },
            "isp_enabled": any(
                c.customer_organization_id is None and c.enabled for c in creds
            ),
            "devices": devices,
        }

    async def _location_tr069(self, location_ids: list[uuid.UUID]) -> set[uuid.UUID]:
        from sqlalchemy import select

        from app.domains.tr069.models import Tr069LocationSetting

        if not location_ids:
            return set()
        rows = await self.repository.session.execute(
            select(Tr069LocationSetting.location_id).where(
                Tr069LocationSetting.location_id.in_(location_ids),
                Tr069LocationSetting.enabled.is_(True),
                Tr069LocationSetting.is_deleted.is_(False),
            )
        )
        return set(rows.scalars().all())

    async def _customer_views(
        self, isp: IspContext, organizations: list[Organization]
    ) -> list[dict]:
        ids = [o.id for o in organizations]
        profiles = await self.repository.customer_profiles(ids)
        facts = await self._facts(ids)
        tr = await self._tr069_facts(isp)
        states = await self.repository.service_states(ids)
        return [
            customer_view(
                o,
                profiles.get(o.id),
                locations=[x for x in facts["locations"] if x.organization_id == o.id],
                routers=[x for x in facts["routers"] if x.organization_id == o.id],
                cpes=sum(
                    1 for d in tr["devices"] if d.customer_organization_id == o.id
                ),
                tr069_enabled=o.id in tr["customer_enabled"],
                service_state=states.get(o.id, "active"),
            )
            for o in organizations
        ]

    # -- overview --------------------------------------------------------
    async def overview(self, isp: IspContext) -> dict:
        now = self._clock()
        ids = await isp.child_ids()
        orgs = await self.repository.organizations_by_id(ids)
        facts = await self._facts(ids)
        tr = await self._tr069_facts(isp)
        today = start_of_today(isp.organization.timezone, now=now)
        per_org_today = await self.repository.guests_today(ids, since=today)
        routers: list[Router] = facts["routers"]
        locations: list[Location] = facts["locations"]

        devices = [
            d
            for d in tr["devices"]
            if (
                d.customer_organization_id is None and isp.confined_customer_ids is None
            )
            or d.customer_organization_id in orgs
        ]
        online_cpes = [d for d in devices if cpe_online(d, now=now)]

        attention: list[dict] = []
        for r in routers:
            org = orgs.get(r.organization_id)
            if org is None:
                continue
            # A controller-managed row (e.g. Omada) has no agent heartbeat:
            # its status is not evidence of broken hardware, so it is never
            # an "offline" or "pending" attention item.
            if not is_agent_managed_row(r):
                continue
            since = r.last_seen_at or r.created_at
            if (
                r.status == RouterStatus.OFFLINE.value
                and since
                and (now - since >= timedelta(minutes=ATTENTION_ROUTER_OFFLINE_MINUTES))
            ):
                kind = "router_offline"
            elif (
                r.status in PENDING_STATUSES
                and r.created_at
                and (
                    now - r.created_at
                    >= timedelta(hours=ATTENTION_ROUTER_PENDING_HOURS)
                )
            ):
                kind = "router_pending"
                since = r.created_at
            else:
                continue
            attention.append(
                {
                    "kind": kind,
                    "isp_customer_id": str(org.id),
                    "customer_name": org.name,
                    "isp_location_id": str(r.location_id),
                    "isp_router_id": str(r.id),
                    "cpe_id": None,
                    "label": r.name,
                    "since": since.isoformat() if since else None,
                }
            )
        for d in devices:
            interval = d.periodic_inform_interval_s or 300
            if d.last_inform_at is None or now - d.last_inform_at < timedelta(
                seconds=3 * interval
            ):
                continue
            org = (
                orgs.get(d.customer_organization_id)
                if d.customer_organization_id
                else None
            )
            if org is None:
                continue  # unassigned CPEs have no customer to attach the item to
            attention.append(
                {
                    "kind": "cpe_silent",
                    "isp_customer_id": str(org.id),
                    "customer_name": org.name,
                    "isp_location_id": str(d.location_id) if d.location_id else None,
                    "isp_router_id": str(d.router_id) if d.router_id else None,
                    "cpe_id": str(d.id),
                    "label": d.label or d.genieacs_device_id,
                    "since": d.last_inform_at.isoformat(),
                }
            )
        attention.sort(key=lambda a: a["since"] or "")

        statuses = Counter(o.status for o in orgs.values())
        return {
            "customers": {
                "total": len(orgs),
                "active": statuses.get(OrganizationStatus.ACTIVE.value, 0),
                "suspended": statuses.get(OrganizationStatus.SUSPENDED.value, 0),
            },
            "locations": {
                "total": len(locations),
                "active": sum(
                    1 for x in locations if x.status == LocationStatus.ACTIVE.value
                ),
            },
            "routers": {
                "total": len(routers),
                "online": sum(
                    1 for r in routers if r.status == RouterStatus.ONLINE.value
                ),
                "offline": sum(
                    1 for r in routers if r.status == RouterStatus.OFFLINE.value
                ),
                "pending": sum(1 for r in routers if r.status in PENDING_STATUSES),
            },
            "guests": {
                "today_unique": await self.repository.distinct_guests_since(
                    ids, since=today
                ),
                "active_sessions": await self.repository.active_sessions(ids),
            },
            "cpes": {
                "total": len(devices),
                "online": len(online_cpes),
                "offline": len(devices) - len(online_cpes),
                "unassigned": sum(
                    1 for d in devices if d.customer_organization_id is None
                ),
            },
            "attention": attention[:ATTENTION_CAP],
            "per_customer": [
                {
                    "isp_customer_id": str(o.id),
                    "name": o.name,
                    "status": o.status,
                    "locations": sum(1 for x in locations if x.organization_id == o.id),
                    "routers_online": sum(
                        1
                        for r in routers
                        if r.organization_id == o.id
                        and r.status == RouterStatus.ONLINE.value
                    ),
                    "routers_total": sum(
                        1 for r in routers if r.organization_id == o.id
                    ),
                    "guests_today": per_org_today.get(o.id, (0, 0))[0],
                    "bytes_today": per_org_today.get(o.id, (0, 0))[1],
                }
                for o in (orgs[i] for i in ids if i in orgs)
            ],
            "generated_at": now.isoformat(),
        }

    # -- customers -------------------------------------------------------
    async def list_customers(
        self,
        isp: IspContext,
        *,
        status: str | None,
        search: str | None,
        page_no: int,
        page_size: int,
    ) -> dict:
        ids = await isp.child_ids()
        rows, total = await self.repository.list_customers(
            ids, status=status, search=search, page=page_no, page_size=page_size
        )
        return page(await self._customer_views(isp, rows), total, page_no, page_size)

    async def get_customer(self, isp: IspContext, isp_customer_id: uuid.UUID) -> dict:
        org = await IspScope.assert_customer(isp, isp_customer_id)
        return (await self._customer_views(isp, [org]))[0]

    async def _unique_slug(self, base: str) -> str:
        for _ in range(8):
            candidate = f"{base[:140]}-{secrets.token_hex(2)}"
            try:
                await self.organization_service.get_by_slug(
                    candidate, include_deleted=True
                )
            except Exception:  # noqa: BLE001 -- not found: free
                return candidate
        return f"{base[:130]}-{secrets.token_hex(6)}"

    async def create_customer(self, isp: IspContext, data: dict[str, Any]) -> dict:
        """Hard rule: always STANDARD, always parented to ``isp.isp_org_id``.
        There is deliberately no parameter that could say otherwise."""
        profile = isp.profile
        if profile.max_customers is not None:
            existing = await self.repository.count_customers(isp.isp_org_id)
            if existing >= profile.max_customers:
                raise IspCustomerLimitError()
        external_ref = data.get("external_ref")
        if external_ref and await self.repository.external_ref_taken(
            isp.isp_org_id, external_ref
        ):
            raise IspExternalRefTakenError()

        slug = data.get("slug") or await self._unique_slug(slugify(data["name"]))
        try:
            org = await self.organization_service.create_organization(
                actor_user_id=isp.user_id,
                name=data["name"],
                slug=slug,
                contact_email=data["contact_email"],
                legal_name=data.get("legal_name"),
                org_type=OrganizationType.STANDARD,
                status=OrganizationStatus.ACTIVE,
                parent_organization_id=isp.isp_org_id,
                contact_phone=data.get("contact_phone"),
                timezone=data.get("timezone") or "Asia/Kolkata",
                settings={
                    "onboarded_via": "isp_partner",
                    "isp_organization_id": str(isp.isp_org_id),
                },
            )
        except DuplicateSlugError as exc:
            raise IspCustomerSlugTakenError() from exc
        assert org.org_type == OrganizationType.STANDARD.value
        assert org.parent_organization_id == isp.isp_org_id

        await self.repository.add(
            IspCustomerProfile(
                isp_organization_id=isp.isp_org_id,
                customer_organization_id=org.id,
                created_by=isp.user_id,
                **{f: data.get(f) for f in _PROFILE_FIELDS},
            )
        )
        await self.subscription_service.create_subscription(
            actor_user_id=isp.user_id,
            organization_id=org.id,
            plan_id=profile.default_customer_plan_id,
        )
        if self.default_alerting is not None:
            try:
                async with self.repository.session.begin_nested():
                    await self.default_alerting(
                        organization_id=org.id, contact_email=org.contact_email
                    )
            except Exception:  # noqa: BLE001 -- as customer_provisioning: log and go on
                logger.exception("isp_customer_default_alerting_failed")
        await self._audit(
            isp,
            AUDIT_ISP_CUSTOMER_CREATED,
            entity_type="organization",
            entity_id=org.id,
            description=f"ISP customer '{org.name}' created",
            organization_id=org.id,
        )
        return (await self._customer_views(isp, [org]))[0]

    async def update_customer(
        self, isp: IspContext, isp_customer_id: uuid.UUID, data: dict[str, Any]
    ) -> dict:
        if "slug" in data:
            raise IspImmutableFieldError(
                "A customer's slug cannot be changed", field="slug"
            )
        org = await IspScope.assert_customer(isp, isp_customer_id)
        if data.get("zone_id") is not None:
            from .billing_models import IspZone

            zone = await self.repository.session.get(IspZone, data["zone_id"])
            if zone is None or zone.is_deleted or zone.isp_organization_id != isp.isp_org_id:
                from .exceptions import IspZoneNotFoundError

                raise IspZoneNotFoundError()
        if data.get("external_ref") and await self.repository.external_ref_taken(
            isp.isp_org_id, data["external_ref"], except_customer_id=org.id
        ):
            raise IspExternalRefTakenError()
        org_data = {k: data[k] for k in _ORG_FIELDS if k in data}
        if org_data:
            org = await self.organization_service.update_organization(
                actor_user_id=isp.user_id,
                organization_id=org.id,
                requesting_organization_id=org.id,
                data=org_data,
            )
        profile_data = {k: data[k] for k in _PROFILE_FIELDS if k in data}
        if profile_data:
            profiles = await self.repository.customer_profiles([org.id])
            profile = profiles.get(org.id)
            if profile is None:
                profile = await self.repository.add(
                    IspCustomerProfile(
                        isp_organization_id=isp.isp_org_id,
                        customer_organization_id=org.id,
                        created_by=isp.user_id,
                    )
                )
            for key, value in profile_data.items():
                setattr(profile, key, value)
            profile.updated_by = isp.user_id
            await self.repository.flush()
        await self._audit(
            isp,
            AUDIT_ISP_CUSTOMER_UPDATED,
            entity_type="organization",
            entity_id=org.id,
            description=f"ISP customer '{org.name}' updated",
            organization_id=org.id,
            fields=sorted(data),
        )
        return (await self._customer_views(isp, [org]))[0]

    async def suspend_customer(
        self, isp: IspContext, isp_customer_id: uuid.UUID, *, reason: str | None
    ) -> dict:
        """Phase 1b (ADDENDUM_01 §A, Q4 answered): delegates to
        ``IspServiceControl.suspend`` -- the org goes ``suspended`` AND the
        customer's internet is cut (NAS rows disabled, live sessions kicked).
        The free-text Phase 1 ``reason`` maps onto the service reasons.
        TR-069 credentials stay enabled (§A.6)."""
        org = await IspScope.assert_customer(isp, isp_customer_id)
        known = reason if reason in SUSPEND_REASONS else "other"
        await self.service_control.suspend(
            isp.isp_org_id,
            org,
            actor=isp.user_id,
            reason=known,
            note=None if reason == known else reason,
            show_suspended_page=True,
            support_line=isp.profile.support_phone,
            isp_name=isp.organization.name,
        )
        org = await IspScope.assert_customer(isp, isp_customer_id)
        await self._audit(
            isp,
            AUDIT_ISP_CUSTOMER_SUSPENDED,
            entity_type="organization",
            entity_id=org.id,
            description=f"ISP customer '{org.name}' suspended",
            organization_id=org.id,
            reason=reason,
        )
        return (await self._customer_views(isp, [org]))[0]

    async def activate_customer(
        self, isp: IspContext, isp_customer_id: uuid.UUID
    ) -> dict:
        org = await IspScope.assert_customer(isp, isp_customer_id)
        await self.service_control.resume(isp.isp_org_id, org, actor=isp.user_id)
        org = await IspScope.assert_customer(isp, isp_customer_id)
        if org.status == "suspended":
            org = await self.organization_service.activate_organization(
                actor_user_id=isp.user_id,
                organization_id=org.id,
                requesting_organization_id=org.id,
            )
        # A customer suspended by the Phase 1 code had its TR-069 credential
        # disabled; re-enable it if (and only if) that is what happened.
        if (org.settings or {}).get(_SUSPEND_MARKER):
            await self.credentials.set_enabled(
                isp.isp_org_id, org.id, True, actor_user_id=isp.user_id
            )
            await self._set_marker(isp, org, False)
        await self._audit(
            isp,
            AUDIT_ISP_CUSTOMER_ACTIVATED,
            entity_type="organization",
            entity_id=org.id,
            description=f"ISP customer '{org.name}' activated",
            organization_id=org.id,
        )
        return (await self._customer_views(isp, [org]))[0]

    async def _set_marker(self, isp: IspContext, org: Organization, on: bool) -> None:
        settings = dict(org.settings or {})
        if on:
            settings[_SUSPEND_MARKER] = True
        else:
            settings.pop(_SUSPEND_MARKER, None)
        await self.organization_service.update_organization(
            actor_user_id=isp.user_id,
            organization_id=org.id,
            requesting_organization_id=org.id,
            data={"settings": settings},
        )

    # -- locations -------------------------------------------------------
    async def _location_views(
        self, isp: IspContext, locations: list[Location]
    ) -> list[dict]:
        names = await self.repository.names(
            Organization, [loc.organization_id for loc in locations]
        )
        routers = await self.repository.routers_for_organizations(
            list({loc.organization_id for loc in locations})
        )
        enabled = await self._location_tr069([loc.id for loc in locations])
        return [
            location_view(
                loc,
                customer_name=names.get(loc.organization_id),
                routers=[r for r in routers if r.location_id == loc.id],
                tr069_enabled=loc.id in enabled,
            )
            for loc in locations
        ]

    async def list_locations(
        self,
        isp: IspContext,
        *,
        isp_customer_id: uuid.UUID | None,
        status: str | None,
        search: str | None,
        page_no: int,
        page_size: int,
    ) -> dict:
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            ids = [isp_customer_id]
        else:
            ids = await isp.child_ids()
        rows, total = await self.repository.list_locations(
            ids, status=status, search=search, page=page_no, page_size=page_size
        )
        return page(await self._location_views(isp, rows), total, page_no, page_size)

    async def get_location(self, isp: IspContext, isp_location_id: uuid.UUID) -> dict:
        location = await IspScope.assert_location(isp, isp_location_id)
        return (await self._location_views(isp, [location]))[0]

    async def create_location(
        self, isp: IspContext, isp_customer_id: uuid.UUID, data: dict[str, Any]
    ) -> dict:
        customer = await IspScope.assert_customer(isp, isp_customer_id)
        slug = data.get("slug") or slugify(data["name"])
        fields = {k: v for k, v in data.items() if k != "slug"}
        try:
            location = await self.location_service.create_location(
                actor_user_id=isp.user_id,
                organization_id=customer.id,
                requesting_organization_id=customer.id,
                slug=slug,
                **fields,
            )
        except DuplicateLocationSlugError:
            if data.get("slug"):
                raise
            location = await self.location_service.create_location(
                actor_user_id=isp.user_id,
                organization_id=customer.id,
                requesting_organization_id=customer.id,
                slug=f"{slug[:140]}-{secrets.token_hex(2)}",
                **fields,
            )
        # Mirrors POST /organizations/{id}/locations (location/router.py) call
        # for call, so an ISP location starts from the same portal baseline.
        await self.captive_portal_service.create_config(
            actor_user_id=isp.user_id,
            requesting_organization_id=customer.id,
            organization_id=customer.id,
            location_id=location.id,
            name=f"{location.name} Guest WiFi",
            is_active=True,
            is_default=False,
            theme="default",
            logo_url=None,
            background_image_url=None,
            primary_color="#6D28D9",
            secondary_color="#1E1B4B",
            default_language="en",
            supported_languages=["en"],
            advertisement_banner_url=None,
            advertisement_banner_link=None,
            terms_and_conditions_text=None,
            terms_and_conditions_url=None,
            privacy_policy_text=None,
            privacy_policy_url=None,
            splash_headline=default_splash_headline(location.name),
            splash_welcome_message="Connect to continue.",
            redirect_url=None,
            otp_sms_enabled=False,
            otp_email_enabled=True,
            otp_whatsapp_enabled=False,
            voucher_enabled=False,
            username_password_enabled=True,
            social_login_enabled=False,
            social_login_providers=[],
        )
        return (await self._location_views(isp, [location]))[0]

    async def update_location(
        self, isp: IspContext, isp_location_id: uuid.UUID, data: dict[str, Any]
    ) -> dict:
        location = await IspScope.assert_location(isp, isp_location_id)
        if "property_type" in data and data["property_type"] is not None:
            data["property_type"] = getattr(
                data["property_type"], "value", data["property_type"]
            )
        location = await self.location_service.update_location(
            actor_user_id=isp.user_id,
            location_id=location.id,
            requesting_organization_id=location.organization_id,
            data=data,
        )
        return (await self._location_views(isp, [location]))[0]

    async def set_location_status(
        self, isp: IspContext, isp_location_id: uuid.UUID, *, suspend: bool
    ) -> dict:
        location = await IspScope.assert_location(isp, isp_location_id)
        method = (
            self.location_service.suspend_location
            if suspend
            else self.location_service.activate_location
        )
        location = await method(
            actor_user_id=isp.user_id,
            location_id=location.id,
            requesting_organization_id=location.organization_id,
        )
        return (await self._location_views(isp, [location]))[0]

    # -- routers ---------------------------------------------------------
    async def _router_views(self, isp: IspContext, routers: list[Router]) -> list[dict]:
        orgs = await self.repository.names(
            Organization, [r.organization_id for r in routers]
        )
        locs = await self.repository.names(Location, [r.location_id for r in routers])
        enabled = await self._location_tr069(list({r.location_id for r in routers}))
        devices = await self.repository.cpes_for_isp(isp.isp_org_id)
        cpe_by_router = {d.router_id: d.id for d in devices if d.router_id is not None}
        now = self._clock()
        return [
            router_view(
                r,
                customer_name=orgs.get(r.organization_id),
                location_name=locs.get(r.location_id),
                cloud_link=cloud_link(r, now=now),
                tr069_enabled=r.location_id in enabled,
                cpe_id=cpe_by_router.get(r.id),
            )
            for r in routers
        ]

    async def list_routers(
        self,
        isp: IspContext,
        *,
        isp_customer_id: uuid.UUID | None,
        isp_location_id: uuid.UUID | None,
        status: str | None,
        page_no: int,
        page_size: int,
    ) -> dict:
        customer_id, location_id, _ = await IspScope.optional_filters(
            isp, isp_customer_id=isp_customer_id, isp_location_id=isp_location_id
        )
        ids = [customer_id] if customer_id is not None else await isp.child_ids()
        rows, total = await self.repository.list_routers(
            ids,
            location_id=location_id,
            status=status,
            page=page_no,
            page_size=page_size,
        )
        return page(await self._router_views(isp, rows), total, page_no, page_size)

    async def get_router(self, isp: IspContext, isp_router_id: uuid.UUID) -> dict:
        router = await IspScope.assert_router(isp, isp_router_id)
        return (await self._router_views(isp, [router]))[0]

    async def create_router(
        self, isp: IspContext, isp_location_id: uuid.UUID, data: dict[str, Any]
    ) -> dict:
        if (data.get("vendor") or "mikrotik").lower() != "mikrotik":
            raise IspVendorNotSupportedError()
        location = await IspScope.assert_location(isp, isp_location_id)
        router = await self.router_service.create_router(
            actor_user_id=isp.user_id,
            location_id=location.id,
            requesting_organization_id=location.organization_id,
            name=data["name"],
            serial_number=data["serial_number"],
            mac_address=data["mac_address"].upper(),
            model=data["model"],
            vendor="mikrotik",
        )
        return (await self._router_views(isp, [router]))[0]

    async def update_router(
        self, isp: IspContext, isp_router_id: uuid.UUID, data: dict[str, Any]
    ) -> dict:
        router = await IspScope.assert_router(isp, isp_router_id)
        if data:
            router = await self.router_service.update_router(
                actor_user_id=isp.user_id,
                router_id=router.id,
                requesting_organization_id=router.organization_id,
                data=data,
            )
        return (await self._router_views(isp, [router]))[0]
