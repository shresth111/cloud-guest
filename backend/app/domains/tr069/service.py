"""TR-069 control plane for one ISP (API_CONTRACT §5).

Every device action starts at ``IspScope.assert_cpe``; GenieACS is called
only after our own ``tr069_devices`` row says the caller may act on it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select

from app.domains.isp_partner.dependencies import IspContext
from app.domains.isp_partner.exceptions import IspLocationNotFoundError
from app.domains.isp_partner.scoping import IspScope
from app.domains.isp_partner.views import cpe_online, page
from app.domains.location.models import Location
from app.domains.organization.models import Organization

from . import params as P
from .config import get_tr069_settings
from .credentials import CredentialStore
from .exceptions import Tr069DisabledForCustomerError, Tr069TaskPendingError
from .models import Tr069AcsCredential, Tr069Device, Tr069LocationSetting, Tr069Task
from .script import render_tr069_script
from .sync import apply_facts

RECOMMENDED_INTERVAL_S = 300
AUDIT_SCRIPT_GENERATED = "tr069_script_generated"
AUDIT_TASK_QUEUED = "tr069_task_queued"
AUDIT_DEVICE_ASSIGNED = "tr069_device_assigned"
AUDIT_CREDENTIAL_ROTATED = "tr069_credential_rotated"
AUDIT_CUSTOMER_TOGGLED = "tr069_customer_toggled"
QUEUED_MESSAGE = (
    "Queued. The device runs it at its next check-in (within about 5 minutes)."
)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


class Tr069Service:
    def __init__(
        self, *, session: Any, nbi: Any, audit: Any, clock: Any = None
    ) -> None:
        self.session = session
        self.nbi = nbi
        self.audit = audit
        self.credentials = CredentialStore(session)
        self._clock = clock or (lambda: datetime.now(UTC))

    async def _audit(
        self,
        isp: IspContext,
        action: str,
        *,
        entity_type: str,
        entity_id: Any,
        organization_id: Any = None,
        **meta: Any,
    ) -> None:
        await self.audit.create_audit_log_entry(
            actor_user_id=isp.user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            description=action.replace("_", " "),
            event_metadata={
                "console": "isp",
                "isp_organization_id": str(isp.isp_org_id),
                **meta,
            },
            organization_id=organization_id or isp.isp_org_id,
            location_id=None,
        )

    # -- credentials -------------------------------------------------------
    @staticmethod
    def _acs_url() -> str:
        return get_tr069_settings().acs_public_url

    def _credential_view(
        self, credential: Tr069AcsCredential | None, *, show_password: bool, note: str
    ) -> dict:
        enabled = bool(credential and credential.enabled)
        return {
            "acs_url": self._acs_url(),
            "username": credential.username if credential else None,
            "password": (
                CredentialStore.plaintext(credential)
                if credential is not None and enabled and show_password
                else None
            ),
            "enabled": enabled,
            "periodic_inform_interval_s_recommended": RECOMMENDED_INTERVAL_S,
            "notes": note,
        }

    async def isp_acs(self, isp: IspContext) -> dict:
        credential = await self.credentials.get(isp.isp_org_id, None)
        if credential is None:
            # Master mints it at ISP creation; this covers an ISP created
            # before TR-069 was switched on.
            credential = await self.credentials.ensure(
                isp.isp_org_id, None, actor_user_id=isp.user_id
            )
        return self._credential_view(
            credential,
            show_password=True,
            note="Devices using this credential arrive unassigned.",
        )

    async def rotate_isp(self, isp: IspContext) -> dict:
        credential = await self.credentials.get(isp.isp_org_id, None)
        if credential is None:
            credential = await self.credentials.ensure(
                isp.isp_org_id, None, actor_user_id=isp.user_id
            )
        else:
            await self.credentials.rotate(credential, actor_user_id=isp.user_id)
        await self._audit(
            isp,
            AUDIT_CREDENTIAL_ROTATED,
            entity_type="tr069_acs_credential",
            entity_id=credential.id,
        )
        return self._credential_view(
            credential,
            show_password=True,
            note="Devices using this credential arrive unassigned.",
        )

    async def customer_state(
        self, isp: IspContext, isp_customer_id: uuid.UUID, *, show_password: bool
    ) -> dict:
        customer = await IspScope.assert_customer(isp, isp_customer_id)
        credential = await self.credentials.get(isp.isp_org_id, customer.id)
        view = self._credential_view(
            credential,
            show_password=show_password,
            note="Devices using this credential are assigned to this customer.",
        )
        view["isp_customer_id"] = str(customer.id)
        return view

    async def set_customer_enabled(
        self, isp: IspContext, isp_customer_id: uuid.UUID, enabled: bool
    ) -> dict:
        customer = await IspScope.assert_customer(isp, isp_customer_id)
        if enabled:
            await self.credentials.ensure(
                isp.isp_org_id, customer.id, actor_user_id=isp.user_id, enabled=True
            )
        else:
            await self.credentials.set_enabled(
                isp.isp_org_id, customer.id, False, actor_user_id=isp.user_id
            )
        await self._audit(
            isp,
            AUDIT_CUSTOMER_TOGGLED,
            entity_type="organization",
            entity_id=customer.id,
            organization_id=customer.id,
            enabled=enabled,
        )
        return await self.customer_state(isp, customer.id, show_password=True)

    async def rotate_customer(
        self, isp: IspContext, isp_customer_id: uuid.UUID
    ) -> dict:
        customer = await IspScope.assert_customer(isp, isp_customer_id)
        credential = await self.credentials.get(isp.isp_org_id, customer.id)
        if credential is None:
            credential = await self.credentials.ensure(
                isp.isp_org_id, customer.id, actor_user_id=isp.user_id
            )
        else:
            await self.credentials.rotate(credential, actor_user_id=isp.user_id)
        await self._audit(
            isp,
            AUDIT_CREDENTIAL_ROTATED,
            entity_type="tr069_acs_credential",
            entity_id=credential.id,
            organization_id=customer.id,
        )
        return await self.customer_state(isp, customer.id, show_password=True)

    # -- locations ---------------------------------------------------------
    async def _location_setting(
        self, location_id: uuid.UUID
    ) -> Tr069LocationSetting | None:
        return (
            await self.session.execute(
                select(Tr069LocationSetting).where(
                    Tr069LocationSetting.location_id == location_id,
                    Tr069LocationSetting.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def location_state(self, isp: IspContext, isp_location_id: uuid.UUID) -> dict:
        location = await IspScope.assert_location(isp, isp_location_id)
        setting = await self._location_setting(location.id)
        return {
            "isp_location_id": str(location.id),
            "enabled": bool(setting and setting.enabled),
            "periodic_inform_interval_s": (
                setting.periodic_inform_interval_s
                if setting
                else RECOMMENDED_INTERVAL_S
            ),
        }

    async def set_location(
        self,
        isp: IspContext,
        isp_location_id: uuid.UUID,
        *,
        enabled: bool,
        interval_s: int | None,
    ) -> dict:
        location = await IspScope.assert_location(isp, isp_location_id)
        setting = await self._location_setting(location.id)
        if setting is None:
            setting = Tr069LocationSetting(
                location_id=location.id,
                enabled=enabled,
                periodic_inform_interval_s=interval_s or RECOMMENDED_INTERVAL_S,
                created_by=isp.user_id,
            )
            self.session.add(setting)
        else:
            setting.enabled = enabled
            if interval_s is not None:
                setting.periodic_inform_interval_s = interval_s
            setting.updated_by = isp.user_id
        await self.session.flush()
        return await self.location_state(isp, location.id)

    async def router_script(self, isp: IspContext, isp_router_id: uuid.UUID) -> str:
        router = await IspScope.assert_router(isp, isp_router_id)
        setting = await self._location_setting(router.location_id)
        credential = await self.credentials.get(isp.isp_org_id, router.organization_id)
        if credential is None or not credential.enabled:
            credential = await self.credentials.get(isp.isp_org_id, None)
            if credential is None:
                credential = await self.credentials.ensure(
                    isp.isp_org_id, None, actor_user_id=isp.user_id
                )
        script = render_tr069_script(
            acs_url=self._acs_url(),
            username=credential.username,
            password=CredentialStore.plaintext(credential),
            interval_s=setting.periodic_inform_interval_s
            if setting
            else RECOMMENDED_INTERVAL_S,
            enabled=bool(setting and setting.enabled),
            now=self._clock(),
        )
        await self._audit(
            isp,
            AUDIT_SCRIPT_GENERATED,
            entity_type="router",
            entity_id=router.id,
            organization_id=router.organization_id,
            credential_username=credential.username,
        )
        return script

    # -- devices -----------------------------------------------------------
    async def _management_enabled(
        self, isp: IspContext, devices: list[Tr069Device]
    ) -> dict:
        rows = await self.session.execute(
            select(Tr069AcsCredential).where(
                Tr069AcsCredential.isp_organization_id == isp.isp_org_id,
                Tr069AcsCredential.is_deleted.is_(False),
            )
        )
        creds = list(rows.scalars().all())
        customer_on = {
            c.customer_organization_id
            for c in creds
            if c.customer_organization_id and c.enabled
        }
        isp_on = any(c.customer_organization_id is None and c.enabled for c in creds)
        return {
            d.id: (d.customer_organization_id in customer_on)
            if d.customer_organization_id is not None
            else isp_on
            for d in devices
        }

    async def _views(self, isp: IspContext, devices: list[Tr069Device]) -> list[dict]:
        orgs = await isp.repository.names(
            Organization, [d.customer_organization_id for d in devices]
        )
        locs = await isp.repository.names(Location, [d.location_id for d in devices])
        mgmt = await self._management_enabled(isp, devices)
        now = self._clock()
        return [
            {
                "id": str(d.id),
                "genieacs_device_id": d.genieacs_device_id,
                "label": d.label,
                "isp_customer_id": str(d.customer_organization_id)
                if d.customer_organization_id
                else None,
                "customer_name": orgs.get(d.customer_organization_id),
                "isp_location_id": str(d.location_id) if d.location_id else None,
                "location_name": locs.get(d.location_id),
                "isp_router_id": str(d.router_id) if d.router_id else None,
                "manufacturer": d.manufacturer,
                "model": d.model,
                "serial_number": d.serial_number,
                "software_version": d.software_version,
                "data_model": d.data_model,
                "wan_ip": d.wan_ip,
                "online": cpe_online(d, now=now),
                "last_inform_at": _iso(d.last_inform_at),
                "first_seen_at": _iso(d.first_seen_at),
                "management_enabled": mgmt[d.id],
            }
            for d in devices
        ]

    async def list_devices(
        self,
        isp: IspContext,
        *,
        isp_customer_id: uuid.UUID | None,
        assigned: bool | None,
        online: bool | None,
        search: str | None,
        page_no: int,
        page_size: int,
    ) -> dict:
        conditions: list[Any] = [
            Tr069Device.isp_organization_id == isp.isp_org_id,
            Tr069Device.is_deleted.is_(False),
        ]
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            conditions.append(Tr069Device.customer_organization_id == isp_customer_id)
        elif isp.confined_customer_ids is not None:
            conditions.append(
                Tr069Device.customer_organization_id.in_(
                    await isp.child_ids() or [uuid.UUID(int=0)]
                )
            )
        else:
            children = await isp.child_ids()
            conditions.append(
                or_(
                    Tr069Device.customer_organization_id.is_(None),
                    Tr069Device.customer_organization_id.in_(
                        children or [uuid.UUID(int=0)]
                    ),
                )
            )
        if assigned is True:
            conditions.append(Tr069Device.customer_organization_id.is_not(None))
        elif assigned is False:
            conditions.append(Tr069Device.customer_organization_id.is_(None))
        if search:
            pattern = f"%{search.strip()}%"
            conditions.append(
                or_(
                    Tr069Device.genieacs_device_id.ilike(pattern),
                    Tr069Device.serial_number.ilike(pattern),
                    Tr069Device.label.ilike(pattern),
                    Tr069Device.model.ilike(pattern),
                )
            )
        rows = await self.session.execute(
            select(Tr069Device)
            .where(*conditions)
            .order_by(Tr069Device.first_seen_at.desc(), Tr069Device.id)
        )
        devices = list(rows.scalars().all())
        if online is not None:
            now = self._clock()
            devices = [d for d in devices if cpe_online(d, now=now) is online]
        total = len(devices)
        chunk = devices[(page_no - 1) * page_size : page_no * page_size]
        return page(await self._views(isp, chunk), total, page_no, page_size)

    async def _last_task(self, device_id: uuid.UUID) -> Tr069Task | None:
        return (
            await self.session.execute(
                select(Tr069Task)
                .where(Tr069Task.device_id == device_id)
                .order_by(Tr069Task.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    async def device_detail(self, isp: IspContext, cpe_id: uuid.UUID) -> dict:
        device = await IspScope.assert_cpe(isp, cpe_id)
        view = (await self._views(isp, [device]))[0]
        cache = dict(device.params_cache or {})
        allowed = {
            "uptime_s",
            "wan_ip",
            "wan_connection_type",
            "pppoe_username",
            "wifi",
            "lan_hosts",
            "hardware_version",
            "software_version",
        }
        view["params"] = {k: cache.get(k) for k in sorted(allowed)}
        view["params"]["wifi"] = cache.get("wifi") or []
        view["params_refreshed_at"] = _iso(device.params_refreshed_at)
        last = await self._last_task(device.id)
        view["last_task"] = (
            {
                "kind": last.kind,
                "status": last.status,
                "created_at": _iso(last.created_at),
            }
            if last
            else None
        )
        return view

    async def assign_device(
        self, isp: IspContext, cpe_id: uuid.UUID, data: dict
    ) -> dict:
        device = await IspScope.assert_cpe(isp, cpe_id)
        if "isp_customer_id" in data:
            customer_id = data["isp_customer_id"]
            if customer_id is not None:
                await IspScope.assert_customer(isp, customer_id)
            if customer_id != device.customer_organization_id:
                device.location_id = None
                device.router_id = None
            device.customer_organization_id = customer_id
        if "isp_location_id" in data:
            location_id = data["isp_location_id"]
            if location_id is not None:
                location = await IspScope.assert_location(isp, location_id)
                if location.organization_id != device.customer_organization_id:
                    raise IspLocationNotFoundError()
            device.location_id = location_id
        if "label" in data:
            device.label = data["label"]
        device.updated_by = isp.user_id
        await self.session.flush()
        await self._audit(
            isp,
            AUDIT_DEVICE_ASSIGNED,
            entity_type="tr069_device",
            entity_id=device.id,
            fields=sorted(data),
            isp_customer_id=str(device.customer_organization_id)
            if device.customer_organization_id
            else None,
        )
        return await self.device_detail(isp, device.id)

    async def queue_task(self, isp: IspContext, cpe_id: uuid.UUID, kind: str) -> dict:
        device = await IspScope.assert_cpe(isp, cpe_id)
        if not (await self._management_enabled(isp, [device]))[device.id]:
            raise Tr069DisabledForCustomerError()
        pending = (
            await self.session.execute(
                select(func.count()).where(
                    Tr069Task.device_id == device.id,
                    Tr069Task.kind == kind,
                    Tr069Task.status == "queued",
                )
            )
        ).scalar_one()
        if pending:
            raise Tr069TaskPendingError()
        if kind == "reboot":
            body: dict[str, Any] = {"name": "reboot"}
        else:
            body = {
                "name": "getParameterValues",
                "parameterNames": P.refresh_parameter_names(device.data_model),
            }
        status_code, task_json = await self.nbi.post_task(
            device.genieacs_device_id, body
        )
        now = self._clock()
        done = status_code == 200
        task = Tr069Task(
            device_id=device.id,
            isp_organization_id=isp.isp_org_id,
            requested_by=isp.user_id,
            kind=kind,
            genieacs_task_id=(
                str(task_json.get("_id")) if task_json.get("_id") else None
            ),
            status="done" if done else "queued",
            completed_at=now if done else None,
            created_by=isp.user_id,
        )
        self.session.add(task)
        if done and kind == "refresh_params":
            doc = await self.nbi.get_device(device.genieacs_device_id)
            if doc:
                apply_facts(device, doc)
        await self.session.flush()
        await self._audit(
            isp,
            AUDIT_TASK_QUEUED,
            entity_type="tr069_device",
            entity_id=device.id,
            kind=kind,
            status=task.status,
        )
        return {
            "task_id": str(task.id),
            "kind": kind,
            "status": task.status,
            "message": "Done." if done else QUEUED_MESSAGE,
        }

    async def list_tasks(
        self, isp: IspContext, cpe_id: uuid.UUID, *, page_no: int, page_size: int
    ) -> dict:
        device = await IspScope.assert_cpe(isp, cpe_id)
        total = int(
            (
                await self.session.execute(
                    select(func.count()).where(Tr069Task.device_id == device.id)
                )
            ).scalar_one()
        )
        rows = await self.session.execute(
            select(Tr069Task)
            .where(Tr069Task.device_id == device.id)
            .order_by(Tr069Task.created_at.desc())
            .offset((page_no - 1) * page_size)
            .limit(page_size)
        )
        items = [
            {
                "id": str(t.id),
                "kind": t.kind,
                "status": t.status,
                "fault": t.fault,
                "requested_by": str(t.requested_by),
                "created_at": _iso(t.created_at),
                "completed_at": _iso(t.completed_at),
            }
            for t in rows.scalars().all()
        ]
        return page(items, total, page_no, page_size)
