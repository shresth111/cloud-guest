"""``GET /internal/tr069/acs-auth`` -- nginx ``auth_request`` only.

* 404 unless ``ISP_PARTNER_ENABLED`` and ``TR069_ENABLED`` are on, a gate
  secret is configured, and the request carries it in ``X-Wyfy-Acs-Gate``
  (constant-time compare). To anything else this endpoint does not exist.
* 204 + ``X-Wyfy-Acs-User`` when the forwarded HTTP Basic credential matches
  an enabled ``tr069_acs_credentials`` row of an active ISP (and, for a
  customer credential, an active customer). 401 otherwise.

No body and no DB write on the hot path. The credential row and the
owner state (ISP profile, ISP org, customer org) are READ on every request,
so turning TR-069 off for a customer, suspending the ISP or disabling the
customer takes effect on the very next request. Only the Argon2id verify is
cached: in-process for 60 s, keyed by (username, password digest, stored
hash). A rotation writes a new hash, so the old password misses the cache and
fails the verify on the next request. Nothing has to invalidate the cache,
so there is no window between a commit and an invalidation, and it stays
correct with several API processes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import time
from collections import OrderedDict

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.isp_partner.config import RequireIspFeatureEnabled
from app.domains.organization.enums import OrganizationStatus, OrganizationType

from .config import get_tr069_settings
from .credentials import CredentialStore, verify_password

GATE_HEADER = "X-Wyfy-Acs-Gate"
USER_HEADER = "X-Wyfy-Acs-User"
CACHE_TTL_S = 60.0
CACHE_MAX = 4096


async def RequireAcsGate(request: Request) -> None:
    settings = get_tr069_settings()
    secret = settings.edge_shared_secret or ""
    presented = request.headers.get(GATE_HEADER) or ""
    if (
        not settings.enabled
        or not secret
        or not hmac.compare_digest(presented.encode(), secret.encode())
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


tr069_internal_router = APIRouter(
    prefix="/internal/tr069",
    tags=["Internal: TR-069"],
    include_in_schema=False,
    dependencies=[Depends(RequireIspFeatureEnabled), Depends(RequireAcsGate)],
)


class _PositiveCache:
    def __init__(self) -> None:
        self._items: OrderedDict[tuple[str, str, str], float] = OrderedDict()

    def hit(self, key: tuple[str, str, str]) -> bool:
        expires = self._items.get(key)
        if expires is None:
            return False
        if expires < time.monotonic():
            self._items.pop(key, None)
            return False
        self._items.move_to_end(key)
        return True

    def put(self, key: tuple[str, str, str]) -> None:
        self._items[key] = time.monotonic() + CACHE_TTL_S
        self._items.move_to_end(key)
        while len(self._items) > CACHE_MAX:
            self._items.popitem(last=False)

    def clear(self) -> None:
        self._items.clear()


positive_cache = _PositiveCache()


def parse_basic(header: str | None) -> tuple[str, str] | None:
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    if not username or not password:
        return None
    return username, password


def _unauthorized() -> Response:
    return Response(status_code=status.HTTP_401_UNAUTHORIZED)


async def _owner_active(session: AsyncSession, credential: object) -> bool:
    from app.domains.isp_partner.models import IspPartnerProfile  # noqa: F401
    from app.domains.isp_partner.repository import IspRepository

    repo = IspRepository(session)
    profile = await repo.get_profile(credential.isp_organization_id)  # type: ignore[attr-defined]
    isp_org = await repo.get_organization(credential.isp_organization_id)  # type: ignore[attr-defined]
    if (
        profile is None
        or profile.status != "active"
        or isp_org is None
        or isp_org.org_type != OrganizationType.MSP.value
        or isp_org.status != OrganizationStatus.ACTIVE.value
    ):
        return False
    customer_id = credential.customer_organization_id  # type: ignore[attr-defined]
    if customer_id is not None:
        customer = await repo.get_organization(customer_id)
        if (
            customer is None
            or customer.parent_organization_id != isp_org.id
            or customer.status != OrganizationStatus.ACTIVE.value
        ):
            return False
    return True


@tr069_internal_router.get("/acs-auth", status_code=status.HTTP_204_NO_CONTENT)
async def acs_auth(
    request: Request, session: AsyncSession = Depends(get_db_session)
) -> Response:
    parsed = parse_basic(request.headers.get("Authorization"))
    if parsed is None:
        return _unauthorized()
    username, password = parsed
    credential = await CredentialStore(session).get_by_username(username)
    if credential is None or not credential.enabled:
        return _unauthorized()
    key = (
        username,
        hashlib.sha256(password.encode()).hexdigest(),
        credential.password_hash,
    )
    if not positive_cache.hit(key):
        if not verify_password(password, credential.password_hash):
            return _unauthorized()
        positive_cache.put(key)
    if not await _owner_active(session, credential):
        return _unauthorized()
    return Response(
        status_code=status.HTTP_204_NO_CONTENT, headers={USER_HEADER: username}
    )
