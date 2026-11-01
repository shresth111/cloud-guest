"""Phase 2b PPPoE on our RADIUS (JAZE-6).

Two callers:

* **FreeRADIUS** (the X2 virtual server, box-only) via
  ``/isp/internal/pppoe/{authorize,accounting}``. NAS-authenticated with the
  existing ``CurrentNas`` dependency *and* the ``ISP_PPPOE_REST_SECRET``
  header. ``authorize`` answers in rlm_rest's attribute-name JSON. On accept
  it returns ``control:Cleartext-Password`` so FreeRADIUS itself verifies
  PAP, CHAP or MS-CHAPv2; the platform never sees the client's hash.
* **ISP staff** via ``/isp/subscribers/{id}/pppoe``, ``/isp/pppoe/...``,
  through ``IspScope`` (404 outside the ISP or the caller's confinement).

Hard rule (ADDENDUM_01 §A.9 spirit): only NAS rows whose organization is an
ISP customer can ever authorize a PPPoE login, and a credential authorizes
only on its own customer's routers.
"""

from __future__ import annotations

import logging
import re
import secrets
import string
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select, update

from app.domains.router.crypto import decrypt_secret, encrypt_secret

from .billing_models import IspCustomerServiceState
from .dependencies import IspContext
from .exceptions import _err
from .models import IspCustomerProfile, IspPartnerProfile
from .plans_models import IspPackage, IspSpeedGroup, IspSubscriber
from .pppoe_config import get_isp_pppoe_settings
from .pppoe_device import PppoeDeviceError, end_ppp_sessions
from .pppoe_hooks import (
    PppoeAuthorizeContext,
    SpeedGroupRate,
    pppoe_gates,
    pppoe_rate_resolvers,
)
from .pppoe_models import IspPppoeCredential, IspPppoeSession
from .pppoe_script import PppoeScriptParams, render_pppoe_script
from .scoping import IspScope

logger = logging.getLogger(__name__)

__all__ = [
    "IspPppoeService",
    "format_rate_limit",
    "normalize_mac",
]

IspPppoeUsernameTakenError = _err(
    "IspPppoeUsernameTakenError",
    "ISP_PPPOE_USERNAME_TAKEN",
    409,
    "That PPPoE username is already used by another subscriber of this ISP",
)
IspPppoeBadUsernameError = _err(
    "IspPppoeBadUsernameError",
    "ISP_PPPOE_BAD_USERNAME",
    422,
    "Username: 3-64 characters, letters, digits and . _ @ - only",
)
IspPppoeBadPasswordError = _err(
    "IspPppoeBadPasswordError",
    "ISP_PPPOE_BAD_PASSWORD",
    422,
    "Password: 8-64 printable characters, no spaces or quotes",
)
IspPppoeNotConfiguredError = _err(
    "IspPppoeNotConfiguredError",
    "ISP_PPPOE_NOT_CONFIGURED",
    404,
    "This subscriber has no PPPoE login yet",
)
IspPppoeSessionNotFoundError = _err(
    "IspPppoeSessionNotFoundError",
    "ISP_PPPOE_SESSION_NOT_FOUND",
    404,
    "PPPoE session not found",
)
IspPppoeRouterNotReadyError = _err(
    "IspPppoeRouterNotReadyError",
    "ISP_PPPOE_ROUTER_NOT_READY",
    409,
    "This router is not set up yet (no management tunnel or RADIUS NAS). "
    "Run the main setup script first.",
)
IspPppoeScriptParamError = _err(
    "IspPppoeScriptParamError", "ISP_PPPOE_SCRIPT_PARAM", 422, "Invalid script value"
)
IspPppoeDeviceUnreachableError = _err(
    "IspPppoeDeviceUnreachableError",
    "ISP_PPPOE_DEVICE_UNREACHABLE",
    502,
    "Could not reach the router to end the session",
)
IspPppoeSubscriberNotFoundError = _err(
    "IspPppoeSubscriberNotFoundError",
    "ISP_SUBSCRIBER_NOT_FOUND",
    404,
    "Subscriber not found",
)

_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{3,64}$")
_PASSWORD_BAD = set(" \t\r\n\"'\\$`")
_PW_ALPHABET = string.ascii_letters + string.digits
_MAC_RE = re.compile(r"^[0-9A-F]{12}$")

AUDIT_CRED_SET = "isp_pppoe_credential_set"
AUDIT_CRED_STATUS = "isp_pppoe_credential_status"
AUDIT_DISCONNECT = "isp_pppoe_session_disconnect"
AUDIT_SCRIPT = "isp_pppoe_script_generated"

#: Reject reason codes (stored in last_auth_result, shown on the 360 page).
R_DISABLED_FEATURE = "feature_off"
R_NOT_ISP = "not_isp_nas"
R_ISP_SUSPENDED = "isp_suspended"
R_CUSTOMER_SUSPENDED = "customer_suspended"
R_UNKNOWN = "unknown_user"
R_CRED_DISABLED = "login_disabled"
R_SUB_DISABLED = "subscriber_disabled"
R_EXPIRED = "expired"


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    raw = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
    if not _MAC_RE.match(raw):
        return value.strip()[:64] or None
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def format_rate_limit(rate: SpeedGroupRate) -> str:
    """``Mikrotik-Rate-Limit``: rx/tx from the router's side, i.e. the
    client's upload first. Same grammar as
    ``queue_management.format_mikrotik_rate_limit``."""
    parts = [f"{rate.upload_kbps}k/{rate.download_kbps}k"]
    if rate.burst_upload_kbps is not None or rate.burst_download_kbps is not None:
        parts.append(f"{rate.burst_upload_kbps or 0}k/{rate.burst_download_kbps or 0}k")
        thr = rate.burst_threshold_kbps or 0
        parts.append(f"{thr}k/{thr}k")
        bt = rate.burst_time_seconds or 0
        parts.append(f"{bt}/{bt}")
        parts.append(str(rate.priority or 8))
    return " ".join(parts)


def _rate_from_group(g: IspSpeedGroup) -> SpeedGroupRate:
    return SpeedGroupRate(
        download_kbps=int(g.download_kbps),
        upload_kbps=int(g.upload_kbps),
        burst_download_kbps=g.burst_download_kbps,
        burst_upload_kbps=g.burst_upload_kbps,
        burst_threshold_kbps=g.burst_threshold_kbps,
        burst_time_seconds=g.burst_time_seconds,
        priority=int(g.priority or 8),
        speed_group_id=g.id,
    )


def _reject(reason: str) -> dict:
    return {
        "control:Auth-Type": "Reject",
        "reply:Reply-Message": f"wyfy:{reason}",
    }


def generate_password(length: int = 12) -> str:
    return "".join(secrets.choice(_PW_ALPHABET) for _ in range(length))


def _check_password(pw: str) -> str:
    if not (8 <= len(pw) <= 64) or any(c in _PASSWORD_BAD for c in pw):
        raise IspPppoeBadPasswordError()
    if any(ord(c) < 33 or ord(c) > 126 for c in pw):
        raise IspPppoeBadPasswordError()
    return pw


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


class IspPppoeService:
    def __init__(self, *, session: Any, audit: Any = None, clock=None) -> None:  # noqa: ANN001
        self.session = session
        self.audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))

    # ------------------------------------------------------------------
    # RADIUS: authorize
    # ------------------------------------------------------------------
    async def _isp_for_customer(self, customer_org_id: uuid.UUID) -> uuid.UUID | None:
        return (
            await self.session.execute(
                select(IspCustomerProfile.isp_organization_id).where(
                    IspCustomerProfile.customer_organization_id == customer_org_id,
                    IspCustomerProfile.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def _isp_active(self, isp_org_id: uuid.UUID) -> bool:
        status = (
            await self.session.execute(
                select(IspPartnerProfile.status).where(
                    IspPartnerProfile.organization_id == isp_org_id,
                    IspPartnerProfile.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()
        return status == "active"

    async def _customer_suspended(self, customer_org_id: uuid.UUID) -> bool:
        state = (
            await self.session.execute(
                select(IspCustomerServiceState.state).where(
                    IspCustomerServiceState.customer_organization_id == customer_org_id,
                    IspCustomerServiceState.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()
        return state in ("suspended", "suspend_pending")

    async def _find_credential(
        self, customer_org: uuid.UUID, isp_org: uuid.UUID, uname: str
    ) -> IspPppoeCredential | None:
        return (
            (
                await self.session.execute(
                    select(IspPppoeCredential).where(
                        IspPppoeCredential.customer_organization_id == customer_org,
                        IspPppoeCredential.isp_organization_id == isp_org,
                        IspPppoeCredential.username_lower == uname,
                        IspPppoeCredential.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )

    async def _get_subscriber(self, subscriber_id: uuid.UUID) -> IspSubscriber | None:
        return await self.session.get(IspSubscriber, subscriber_id)

    async def _base_rate(self, sub: IspSubscriber) -> SpeedGroupRate | None:
        group_id = sub.speed_group_id
        if group_id is None and sub.package_id is not None:
            pkg = await self.session.get(IspPackage, sub.package_id)
            group_id = pkg.speed_group_id if pkg is not None else None
        if group_id is None:
            return None
        g = await self.session.get(IspSpeedGroup, group_id)
        if g is None or g.is_deleted:
            return None
        if not g.download_kbps and not g.upload_kbps:
            return None
        return _rate_from_group(g)

    async def _note_auth(
        self, cred: IspPppoeCredential | None, result: str, mac: str | None
    ) -> None:
        if cred is None:
            return
        cred.last_auth_at = self._clock()
        cred.last_auth_result = result[:32]
        cred.last_calling_station_id = mac
        try:
            await self.session.flush()
        except Exception:  # noqa: BLE001 -- bookkeeping never fails a verdict
            logger.exception("isp_pppoe_note_auth_failed")

    async def authorize(
        self,
        *,
        nas_client: Any,
        username: str,
        calling_station_id: str | None,
        nas_port_id: str | None = None,
    ) -> dict:
        settings = get_isp_pppoe_settings()
        mac = normalize_mac(calling_station_id)
        uname = (username or "").strip().lower()
        if not settings.enabled:
            return _reject(R_DISABLED_FEATURE)
        customer_org = nas_client.organization_id
        isp_org = await self._isp_for_customer(customer_org)
        if isp_org is None:
            return _reject(R_NOT_ISP)
        if not await self._isp_active(isp_org):
            return _reject(R_ISP_SUSPENDED)
        cred = await self._find_credential(customer_org, isp_org, uname)
        if cred is None:
            return _reject(R_UNKNOWN)
        if await self._customer_suspended(customer_org):
            await self._note_auth(cred, R_CUSTOMER_SUSPENDED, mac)
            return _reject(R_CUSTOMER_SUSPENDED)
        if cred.status != "active":
            await self._note_auth(cred, R_CRED_DISABLED, mac)
            return _reject(R_CRED_DISABLED)
        sub = await self._get_subscriber(cred.subscriber_id)
        if sub is None or sub.is_deleted or sub.status == "disabled":
            await self._note_auth(cred, R_SUB_DISABLED, mac)
            return _reject(R_SUB_DISABLED)
        now = self._clock()
        if sub.valid_until is not None and sub.valid_until <= now:
            await self._note_auth(cred, R_EXPIRED, mac)
            return _reject(R_EXPIRED)

        ctx = PppoeAuthorizeContext(
            session=self.session,
            now=now,
            isp_organization_id=isp_org,
            customer_organization_id=customer_org,
            location_id=getattr(nas_client, "location_id", None),
            router_id=getattr(nas_client, "router_id", None),
            nas_client_id=nas_client.id,
            subscriber=sub,
            credential=cred,
            calling_station_id=mac,
            nas_port_id=nas_port_id,
        )
        extra_reply: dict[str, Any] = {}
        for gate in pppoe_gates():
            try:
                res = await gate(ctx)
            except Exception:  # noqa: BLE001 -- optional policy must not lock out
                logger.exception("isp_pppoe_gate_failed")
                continue
            if res is None:
                continue
            if not res.allow:
                reason = (res.reason or "policy")[:32]
                await self._note_auth(cred, reason, mac)
                return _reject(reason)
            extra_reply.update(res.reply or {})

        rate = await self._base_rate(sub)
        for resolver in pppoe_rate_resolvers():
            try:
                rate = await resolver(ctx, rate)
            except Exception:  # noqa: BLE001
                logger.exception("isp_pppoe_rate_resolver_failed")

        try:
            password = decrypt_secret(cred.password_encrypted)
        except Exception:  # noqa: BLE001 -- unreadable secret: refuse, loudly
            logger.exception("isp_pppoe_password_decrypt_failed")
            await self._note_auth(cred, "secret_unreadable", mac)
            return _reject("secret_unreadable")

        timeout = settings.max_session_timeout_seconds
        if sub.valid_until is not None:
            timeout = min(
                timeout, max(60, int((sub.valid_until - now).total_seconds()))
            )
        reply: dict[str, Any] = {
            "control:Cleartext-Password": password,
            "reply:Acct-Interim-Interval": settings.interim_interval_seconds,
            "reply:Session-Timeout": timeout,
        }
        if rate is not None:
            reply["reply:Mikrotik-Rate-Limit"] = format_rate_limit(rate)
        if cred.static_ip:
            reply["reply:Framed-IP-Address"] = cred.static_ip
        elif cred.ip_pool_name:
            reply["reply:Framed-Pool"] = cred.ip_pool_name
        reply.update(extra_reply)
        await self._note_auth(cred, "accepted", mac)
        return reply

    # ------------------------------------------------------------------
    # RADIUS: accounting
    # ------------------------------------------------------------------
    async def _close_nas_sessions(self, nas_client_id: uuid.UUID, cause: str) -> int:
        now = self._clock()
        res = await self.session.execute(
            update(IspPppoeSession)
            .where(
                IspPppoeSession.nas_client_id == nas_client_id,
                IspPppoeSession.status == "active",
            )
            .values(
                status="closed",
                stopped_at=now,
                last_update_at=now,
                terminate_cause=cause,
            )
        )
        await self.session.flush()
        return int(res.rowcount or 0)

    async def accounting(self, *, nas_client: Any, payload: dict) -> dict:
        status_type = str(payload.get("status_type") or "").strip().lower()
        if status_type in ("accounting-on", "accounting-off"):
            closed = await self._close_nas_sessions(nas_client.id, status_type)
            return {"status": status_type, "closed": closed}
        if status_type not in ("start", "interim-update", "stop"):
            return {"status": "ignored", "reason": "status_type"}
        acct_id = str(payload.get("session_id") or "").strip()[:128]
        uname = str(payload.get("username") or "").strip()[:64]
        if not acct_id or not uname:
            return {"status": "ignored", "reason": "missing ids"}
        customer_org = nas_client.organization_id
        isp_org = await self._isp_for_customer(customer_org)
        if isp_org is None:
            return {"status": "ignored", "reason": "not an ISP NAS"}
        now = self._clock()
        row = (
            (
                await self.session.execute(
                    select(IspPppoeSession).where(
                        IspPppoeSession.nas_client_id == nas_client.id,
                        IspPppoeSession.acct_session_id == acct_id,
                    )
                )
            )
            .scalars()
            .first()
        )
        if row is None:
            cred = (
                (
                    await self.session.execute(
                        select(IspPppoeCredential).where(
                            IspPppoeCredential.customer_organization_id == customer_org,
                            IspPppoeCredential.username_lower == uname.lower(),
                            IspPppoeCredential.is_deleted.is_(False),
                        )
                    )
                )
                .scalars()
                .first()
            )
            row = IspPppoeSession(
                isp_organization_id=isp_org,
                customer_organization_id=customer_org,
                location_id=getattr(nas_client, "location_id", None),
                router_id=getattr(nas_client, "router_id", None),
                nas_client_id=nas_client.id,
                subscriber_id=cred.subscriber_id if cred else None,
                credential_id=cred.id if cred else None,
                username=uname,
                acct_session_id=acct_id,
                started_at=now,
                last_update_at=now,
                status="active",
            )
            self.session.add(row)
        mac = normalize_mac(payload.get("calling_station_id"))
        if mac:
            row.calling_station_id = mac
        for field, key in (
            ("framed_ip_address", "framed_ip"),
            ("framed_ipv6_prefix", "framed_ipv6_prefix"),
            ("delegated_ipv6_prefix", "delegated_ipv6_prefix"),
            ("nas_port_id", "nas_port_id"),
        ):
            value = str(payload.get(key) or "").strip()
            if value:
                setattr(row, field, value[:64])
        # Totals, never deltas; a retransmit or an out-of-order interim can
        # only move a counter forward.
        row.bytes_uploaded = max(
            _int(row.bytes_uploaded), _int(payload.get("bytes_uploaded_total"))
        )
        row.bytes_downloaded = max(
            _int(row.bytes_downloaded), _int(payload.get("bytes_downloaded_total"))
        )
        row.last_update_at = now
        if status_type == "stop":
            row.status = "closed"
            row.stopped_at = now
            row.terminate_cause = (
                str(payload.get("disconnect_reason") or "").strip() or None
            )
        elif row.status != "closed":
            row.status = "active"
        await self.session.flush()
        return {"status": row.status, "session_id": str(row.id)}

    # ------------------------------------------------------------------
    # ISP staff: credentials
    # ------------------------------------------------------------------
    async def _subscriber(
        self, isp: IspContext, subscriber_id: uuid.UUID
    ) -> IspSubscriber:
        s = await self.session.get(IspSubscriber, subscriber_id)
        if s is None or s.is_deleted or s.isp_organization_id != isp.isp_org_id:
            raise IspPppoeSubscriberNotFoundError()
        try:
            await IspScope.assert_customer(isp, s.customer_organization_id)
        except Exception:  # noqa: BLE001 -- outside confinement: same 404
            raise IspPppoeSubscriberNotFoundError() from None
        return s

    async def _credential(self, subscriber_id: uuid.UUID) -> IspPppoeCredential | None:
        return (
            (
                await self.session.execute(
                    select(IspPppoeCredential).where(
                        IspPppoeCredential.subscriber_id == subscriber_id,
                        IspPppoeCredential.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )

    async def _active_sessions(self, subscriber_id: uuid.UUID) -> list[IspPppoeSession]:
        return list(
            (
                await self.session.execute(
                    select(IspPppoeSession)
                    .where(
                        IspPppoeSession.subscriber_id == subscriber_id,
                        IspPppoeSession.status == "active",
                    )
                    .order_by(IspPppoeSession.started_at.desc())
                )
            )
            .scalars()
            .all()
        )

    @staticmethod
    def session_view(s: IspPppoeSession) -> dict:
        return {
            "id": str(s.id),
            "subscriber_id": str(s.subscriber_id) if s.subscriber_id else None,
            "customer_id": str(s.customer_organization_id),
            "location_id": str(s.location_id) if s.location_id else None,
            "router_id": str(s.router_id) if s.router_id else None,
            "username": s.username,
            "acct_session_id": s.acct_session_id,
            "mac": s.calling_station_id,
            "ip": s.framed_ip_address,
            "ipv6_prefix": s.framed_ipv6_prefix,
            "delegated_ipv6_prefix": s.delegated_ipv6_prefix,
            "nas_port_id": s.nas_port_id,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "last_update_at": s.last_update_at.isoformat()
            if s.last_update_at
            else None,
            "stopped_at": s.stopped_at.isoformat() if s.stopped_at else None,
            "status": s.status,
            "bytes_uploaded": int(s.bytes_uploaded or 0),
            "bytes_downloaded": int(s.bytes_downloaded or 0),
            "terminate_cause": s.terminate_cause,
        }

    async def credential_view(self, isp: IspContext, subscriber_id: uuid.UUID) -> dict:
        sub = await self._subscriber(isp, subscriber_id)
        cred = await self._credential(sub.id)
        if cred is None:
            return {"configured": False, "subscriber_id": str(sub.id)}
        sessions = await self._active_sessions(sub.id)
        return {
            "configured": True,
            "subscriber_id": str(sub.id),
            "username": cred.username,
            "status": cred.status,
            "static_ip": cred.static_ip,
            "ip_pool_name": cred.ip_pool_name,
            "password_set_at": cred.password_set_at.isoformat()
            if cred.password_set_at
            else None,
            "last_auth_at": cred.last_auth_at.isoformat()
            if cred.last_auth_at
            else None,
            "last_auth_result": cred.last_auth_result,
            "last_mac": cred.last_calling_station_id,
            "online": bool(sessions),
            "active_sessions": [self.session_view(s) for s in sessions],
        }

    async def set_credential(
        self, isp: IspContext, subscriber_id: uuid.UUID, body: dict
    ) -> dict:
        """Create or update. Returns the view, plus ``password`` exactly once
        when it was set or generated by this call."""
        sub = await self._subscriber(isp, subscriber_id)
        cred = await self._credential(sub.id)
        username = body.get("username")
        if username is None and cred is None:
            username = sub.identifier
        new_password: str | None = None
        if body.get("password"):
            new_password = _check_password(str(body["password"]))
        elif body.get("generate_password") or cred is None:
            new_password = generate_password()

        if username is not None:
            username = str(username).strip()
            if not _USERNAME_RE.match(username):
                raise IspPppoeBadUsernameError()
            clash = (
                await self.session.execute(
                    select(IspPppoeCredential.id).where(
                        IspPppoeCredential.isp_organization_id == isp.isp_org_id,
                        IspPppoeCredential.username_lower == username.lower(),
                        IspPppoeCredential.is_deleted.is_(False),
                        IspPppoeCredential.subscriber_id != sub.id,
                    )
                )
            ).first()
            if clash is not None:
                raise IspPppoeUsernameTakenError()

        static_ip = body.get("static_ip", ...)
        if static_ip is not ... and static_ip:
            import ipaddress

            try:
                static_ip = str(ipaddress.ip_address(str(static_ip).strip()))
            except ValueError:
                raise IspPppoeScriptParamError(
                    "static_ip is not an IP address"
                ) from None
        pool = body.get("ip_pool_name", ...)
        if pool is not ... and pool:
            pool = str(pool).strip()
            if not re.match(r"^[A-Za-z0-9._-]{1,64}$", pool):
                raise IspPppoeScriptParamError("ip_pool_name: letters, digits, . _ -")

        now = self._clock()
        if cred is None:
            cred = IspPppoeCredential(
                isp_organization_id=isp.isp_org_id,
                customer_organization_id=sub.customer_organization_id,
                subscriber_id=sub.id,
                username=username,
                username_lower=username.lower(),
                password_encrypted=encrypt_secret(new_password or generate_password()),
                status="active",
                password_set_at=now,
                created_by=isp.user_id,
            )
            self.session.add(cred)
        else:
            if username is not None:
                cred.username = username
                cred.username_lower = username.lower()
            if new_password is not None:
                cred.password_encrypted = encrypt_secret(new_password)
                cred.password_set_at = now
            cred.updated_by = isp.user_id
        if static_ip is not ...:
            cred.static_ip = static_ip or None
        if pool is not ...:
            cred.ip_pool_name = pool or None
        await self.session.flush()
        await self._audit(
            isp,
            AUDIT_CRED_SET,
            entity_id=sub.id,
            organization_id=sub.customer_organization_id,
            username=cred.username,
            password_changed=new_password is not None,
        )
        view = await self.credential_view(isp, sub.id)
        if new_password is not None:
            view["password"] = new_password
        return view

    async def set_credential_status(
        self, isp: IspContext, subscriber_id: uuid.UUID, enabled: bool
    ) -> dict:
        sub = await self._subscriber(isp, subscriber_id)
        cred = await self._credential(sub.id)
        if cred is None:
            raise IspPppoeNotConfiguredError()
        cred.status = "active" if enabled else "disabled"
        cred.updated_by = isp.user_id
        await self.session.flush()
        kicked: list[dict] = []
        if not enabled:
            for s in await self._active_sessions(sub.id):
                kicked.append(await self._kick(s))
        await self._audit(
            isp,
            AUDIT_CRED_STATUS,
            entity_id=sub.id,
            organization_id=sub.customer_organization_id,
            enabled=enabled,
            kicked=len(kicked),
        )
        view = await self.credential_view(isp, sub.id)
        view["disconnects"] = kicked
        return view

    # ------------------------------------------------------------------
    # ISP staff: sessions
    # ------------------------------------------------------------------
    async def list_sessions(
        self,
        isp: IspContext,
        *,
        isp_customer_id: uuid.UUID | None,
        status: str | None,
        search: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[dict], int]:
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            customers = [isp_customer_id]
        else:
            customers = await isp.child_ids()
        if not customers:
            return [], 0
        q = select(IspPppoeSession).where(
            IspPppoeSession.isp_organization_id == isp.isp_org_id,
            IspPppoeSession.customer_organization_id.in_(customers),
        )
        if status:
            q = q.where(IspPppoeSession.status == status)
        if search:
            like = f"%{search.strip()}%"
            q = q.where(
                or_(
                    IspPppoeSession.username.ilike(like),
                    IspPppoeSession.framed_ip_address.ilike(like),
                    IspPppoeSession.calling_station_id.ilike(like),
                )
            )
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(q.subquery())
                )
            ).scalar()
            or 0
        )
        rows = (
            (
                await self.session.execute(
                    q.order_by(IspPppoeSession.started_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return [self.session_view(r) for r in rows], total

    async def _session_scoped(
        self, isp: IspContext, pppoe_session_id: uuid.UUID
    ) -> IspPppoeSession:
        s = await self.session.get(IspPppoeSession, pppoe_session_id)
        if s is None or s.isp_organization_id != isp.isp_org_id:
            raise IspPppoeSessionNotFoundError()
        try:
            await IspScope.assert_customer(isp, s.customer_organization_id)
        except Exception:  # noqa: BLE001
            raise IspPppoeSessionNotFoundError() from None
        return s

    async def _kick(self, s: IspPppoeSession) -> dict:
        """Best-effort 8728 removal; reports, never raises."""
        from app.domains.router.models import Router

        out = {"session_id": str(s.id), "ended": False, "detail": None}
        router = await self.session.get(Router, s.router_id) if s.router_id else None
        if router is None:
            out["detail"] = "no router"
            return out
        host = router.management_ip_address or getattr(
            router, "public_ip_address", None
        )
        secret = (
            decrypt_secret(router.api_credentials_encrypted)
            if getattr(router, "api_credentials_encrypted", None)
            else None
        )
        if not host or not router.api_username or not secret:
            out["detail"] = "router has no API credentials"
            return out
        try:
            res = await end_ppp_sessions(
                host=host,
                api_username=router.api_username,
                api_password=secret,
                api_port=None,
                ppp_name=s.username,
                caller_id=s.calling_station_id,
            )
        except PppoeDeviceError as exc:
            out["detail"] = exc.detail[:200]
            return out
        out["ended"] = res.still_active == 0
        out["detail"] = (
            f"matched {res.matched}, removed {res.removed}, left {res.still_active}"
        )
        return out

    async def disconnect(self, isp: IspContext, pppoe_session_id: uuid.UUID) -> dict:
        s = await self._session_scoped(isp, pppoe_session_id)
        result = await self._kick(s)
        await self._audit(
            isp,
            AUDIT_DISCONNECT,
            entity_id=s.id,
            organization_id=s.customer_organization_id,
            username=s.username,
            ended=result["ended"],
        )
        if (
            not result["ended"]
            and result["detail"]
            and result["detail"].startswith("connect")
        ):
            raise IspPppoeDeviceUnreachableError(detail=result["detail"])
        return result

    async def disconnect_subscriber(
        self, isp: IspContext, subscriber_id: uuid.UUID
    ) -> dict:
        sub = await self._subscriber(isp, subscriber_id)
        results = [await self._kick(s) for s in await self._active_sessions(sub.id)]
        await self._audit(
            isp,
            AUDIT_DISCONNECT,
            entity_id=sub.id,
            organization_id=sub.customer_organization_id,
            sessions=len(results),
        )
        return {"subscriber_id": str(sub.id), "results": results}

    # ------------------------------------------------------------------
    # ISP staff: the setup-script step
    # ------------------------------------------------------------------
    async def router_script(
        self, isp: IspContext, isp_router_id: uuid.UUID, params: dict
    ) -> str:
        from app.domains.guest.models import RadiusNasClient
        from app.domains.wireguard.models import WireGuardPeer, WireGuardServer
        from app.domains.wireguard.validators import hub_reserved_ip

        settings = get_isp_pppoe_settings()
        router = await IspScope.assert_router(isp, isp_router_id)
        peer = (
            (
                await self.session.execute(
                    select(WireGuardPeer)
                    .where(
                        WireGuardPeer.router_id == router.id,
                        WireGuardPeer.is_deleted.is_(False),
                        WireGuardPeer.revoked_at.is_(None),
                    )
                    .order_by(WireGuardPeer.created_at.desc())
                )
            )
            .scalars()
            .first()
        )
        server = (
            await self.session.get(WireGuardServer, peer.server_id) if peer else None
        )
        nas = (
            (
                await self.session.execute(
                    select(RadiusNasClient).where(
                        RadiusNasClient.router_id == router.id,
                        RadiusNasClient.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )
        if peer is None or server is None or nas is None:
            raise IspPppoeRouterNotReadyError()
        dns = params.get("dns_servers") or ""
        try:
            text = render_pppoe_script(
                PppoeScriptParams(
                    interface=params.get("interface") or "bridge1",
                    local_address=params.get("local_address")
                    or settings.default_local_address,
                    pool_range=params.get("pool_range") or settings.default_pool_range,
                    pool_cidr=params.get("pool_cidr") or settings.default_pool_cidr,
                    dns_servers=tuple(
                        d for d in (x.strip() for x in dns.split(",")) if d
                    ),
                    hub_tunnel_ip=hub_reserved_ip(server.tunnel_network_cidr),
                    router_tunnel_ip=peer.tunnel_ip_address.split("/")[0],
                    nas_secret=decrypt_secret(nas.shared_secret_encrypted),
                    auth_port=settings.auth_port,
                    acct_port=settings.acct_port,
                    interim_seconds=settings.interim_interval_seconds,
                )
            )
        except ValueError as exc:
            raise IspPppoeScriptParamError(str(exc)) from None
        await self._audit(
            isp,
            AUDIT_SCRIPT,
            entity_id=router.id,
            organization_id=router.organization_id,
            entity_type="router",
            interface=params.get("interface") or "bridge1",
        )
        return text

    # ------------------------------------------------------------------
    async def _audit(
        self,
        isp: IspContext,
        action: str,
        *,
        entity_id: Any,
        organization_id: Any,
        entity_type: str = "isp_subscriber",
        **meta: Any,
    ) -> None:
        if self.audit is None:
            return
        await self.audit.create_audit_log_entry(
            actor_user_id=isp.user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            description=action.replace("_", " "),
            event_metadata={
                "console": "isp",
                "isp_organization_id": str(isp.isp_org_id),
                **{
                    k: (str(v) if isinstance(v, uuid.UUID) else v)
                    for k, v in meta.items()
                },
            },
            organization_id=organization_id or isp.isp_org_id,
            location_id=None,
        )
