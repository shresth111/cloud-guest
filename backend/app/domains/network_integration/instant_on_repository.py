"""Persistence for the Aruba Instant On read-only poller.

Three stores, three access patterns:

* :class:`InstantOnRepository` -- ``instant_on_sites`` and
  ``instant_on_snapshots`` on the caller's session (request or sweep).
  Every customer-facing read carries the organization **and** the location
  in its WHERE clause.
* :class:`DbInstantOnTokenStore` -- the service account's tokens, on a
  **session of its own, committed on every save**. The rotated refresh token
  is the only copy in existence; it must not sit in the poll's transaction
  waiting for a commit that a later failure can roll back.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from .crypto import (
    NetworkIntegrationCredentialDecryptionError,
    decrypt_credentials,
    encrypt_credentials,
)
from .models import InstantOnAccountToken, InstantOnSite, InstantOnSnapshot
from .providers.aruba_instant_on_client import InstantOnTokenState

__all__ = [
    "DbInstantOnTokenStore",
    "InstantOnRepository",
    "InstantOnRepositoryProtocol",
    "account_key_for",
]


class InstantOnRepositoryProtocol(Protocol):
    async def get_site_for_router(
        self, router_id: uuid.UUID
    ) -> InstantOnSite | None: ...

    async def get_site_for_location(
        self, *, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> InstantOnSite | None: ...

    async def list_sites(self, *, limit: int) -> list[InstantOnSite]: ...

    async def list_pollable_sites(self, *, limit: int) -> list[InstantOnSite]: ...

    async def get_snapshots(
        self, site: InstantOnSite
    ) -> dict[str, InstantOnSnapshot]: ...

    async def create_site(self, data: dict[str, Any]) -> InstantOnSite: ...

    async def update_site(
        self, site: InstantOnSite, data: dict[str, Any]
    ) -> InstantOnSite: ...

    async def record_snapshot_success(
        self,
        site: InstantOnSite,
        *,
        kind: str,
        payload: Any,
        payload_hash: str,
        at: datetime,
    ) -> None: ...

    async def record_snapshot_failure(
        self,
        site: InstantOnSite,
        *,
        kind: str,
        error_code: str,
        error_message: str,
        at: datetime,
    ) -> None: ...


class InstantOnRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_site_for_router(self, router_id: uuid.UUID) -> InstantOnSite | None:
        statement = select(InstantOnSite).where(
            InstantOnSite.router_id == router_id,
            InstantOnSite.is_deleted.is_(False),
        )
        return (await self.session.execute(statement)).scalars().first()

    async def get_site_for_location(
        self, *, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> InstantOnSite | None:
        """Tenant-scoped in the query: another tenant's location id finds
        nothing, exactly like a location of the caller's own with no site."""
        statement = (
            select(InstantOnSite)
            .where(
                InstantOnSite.location_id == location_id,
                InstantOnSite.organization_id == organization_id,
                InstantOnSite.is_deleted.is_(False),
            )
            .order_by(InstantOnSite.created_at.asc())
            .limit(1)
        )
        return (await self.session.execute(statement)).scalars().first()

    async def list_sites(self, *, limit: int) -> list[InstantOnSite]:
        statement = (
            select(InstantOnSite)
            .where(InstantOnSite.is_deleted.is_(False))
            .order_by(InstantOnSite.created_at.asc())
            .limit(limit)
        )
        return list((await self.session.execute(statement)).scalars().all())

    async def list_pollable_sites(self, *, limit: int) -> list[InstantOnSite]:
        """Enabled sites whose fleet router is still live and still a
        NAS-only vendor -- a router re-labelled to another vendor stops being
        polled without anybody having to remember the flag."""
        from app.domains.router.models import Router
        from app.domains.router.vendor_capabilities import NAS_ONLY_VENDORS

        statement = (
            select(InstantOnSite)
            .join(Router, Router.id == InstantOnSite.router_id)
            .where(
                InstantOnSite.is_deleted.is_(False),
                InstantOnSite.poll_enabled.is_(True),
                Router.is_deleted.is_(False),
                Router.vendor.in_(sorted(NAS_ONLY_VENDORS)),
            )
            .order_by(InstantOnSite.last_poll_at.asc().nulls_first())
            .limit(limit)
        )
        return list((await self.session.execute(statement)).scalars().all())

    async def get_snapshots(self, site: InstantOnSite) -> dict[str, InstantOnSnapshot]:
        statement = select(InstantOnSnapshot).where(
            InstantOnSnapshot.instant_on_site_id == site.id,
            InstantOnSnapshot.is_deleted.is_(False),
        )
        rows = (await self.session.execute(statement)).scalars().all()
        return {row.kind: row for row in rows}

    async def create_site(self, data: dict[str, Any]) -> InstantOnSite:
        site = InstantOnSite(**data)
        self.session.add(site)
        await self.session.flush()
        return site

    async def update_site(
        self, site: InstantOnSite, data: dict[str, Any]
    ) -> InstantOnSite:
        for key, value in data.items():
            setattr(site, key, value)
        await self.session.flush()
        return site

    async def record_snapshot_success(
        self,
        site: InstantOnSite,
        *,
        kind: str,
        payload: Any,
        payload_hash: str,
        at: datetime,
    ) -> None:
        values = {
            "instant_on_site_id": site.id,
            "organization_id": site.organization_id,
            "kind": kind,
            "payload": payload,
            "payload_hash": payload_hash,
            "fetched_at": at,
            "last_attempt_at": at,
            "last_attempt_ok": True,
            "error_code": None,
            "error_message": None,
        }
        await self._upsert(values)

    async def record_snapshot_failure(
        self,
        site: InstantOnSite,
        *,
        kind: str,
        error_code: str,
        error_message: str,
        at: datetime,
    ) -> None:
        # payload/fetched_at are deliberately NOT touched: they remain the
        # last good read, which the API reports only as "last good read at",
        # never as current data.
        values = {
            "instant_on_site_id": site.id,
            "organization_id": site.organization_id,
            "kind": kind,
            "last_attempt_at": at,
            "last_attempt_ok": False,
            "error_code": error_code[:64],
            "error_message": error_message[:500],
        }
        await self._upsert(values)

    async def _upsert(self, values: dict[str, Any]) -> None:
        update = {
            k: v for k, v in values.items() if k not in ("instant_on_site_id", "kind")
        }
        # ON CONFLICT DO UPDATE does not fire the ORM's onupdate.
        update["updated_at"] = func.now()
        statement = (
            pg_insert(InstantOnSnapshot)
            .values(**values)
            .on_conflict_do_update(
                index_elements=["instant_on_site_id", "kind"], set_=update
            )
        )
        await self.session.execute(statement)


def account_key_for(secret_arn: str) -> str:
    """Stable row key for a service account: a hash of its secret's ARN."""
    return hashlib.sha256((secret_arn or "unconfigured").encode()).hexdigest()[:64]


class DbInstantOnTokenStore:
    """:class:`~.providers.aruba_instant_on_client.InstantOnTokenStore`
    over ``instant_on_account_tokens``. Each call opens and commits its own
    session (see module docstring)."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        *,
        account_key: str,
    ) -> None:
        self._session_factory = session_factory
        self._account_key = account_key

    async def load(self) -> InstantOnTokenState:
        async with self._session_factory() as session:
            row = await self._row(session)
            if row is None:
                return InstantOnTokenState()
            tokens: dict[str, str] = {}
            if row.tokens_encrypted:
                try:
                    tokens = decrypt_credentials(row.tokens_encrypted)
                except NetworkIntegrationCredentialDecryptionError:
                    tokens = {}
            return InstantOnTokenState(
                access_token=tokens.get("access_token"),
                access_expires_at=row.access_expires_at,
                refresh_token=tokens.get("refresh_token"),
                refresh_obtained_at=row.refresh_obtained_at,
                auth_state=row.auth_state,
                auth_error_code=row.auth_error_code,
                login_blocked_until=row.login_blocked_until,
            )

    async def save(self, state: InstantOnTokenState) -> None:
        tokens = {
            k: v
            for k, v in (
                ("access_token", state.access_token),
                ("refresh_token", state.refresh_token),
            )
            if v
        }
        ciphertext = encrypt_credentials(tokens) if tokens else None
        async with self._session_factory() as session:
            values = {
                "account_key": self._account_key,
                "tokens_encrypted": ciphertext,
                "access_expires_at": state.access_expires_at,
                "refresh_obtained_at": state.refresh_obtained_at,
                "auth_state": state.auth_state,
                "auth_error_code": state.auth_error_code,
                "login_blocked_until": state.login_blocked_until,
            }
            statement = (
                pg_insert(InstantOnAccountToken)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=["account_key"],
                    set_={
                        **{k: v for k, v in values.items() if k != "account_key"},
                        "updated_at": func.now(),
                    },
                )
            )
            await session.execute(statement)
            await session.commit()

    async def _row(self, session: AsyncSession) -> InstantOnAccountToken | None:
        statement = select(InstantOnAccountToken).where(
            InstantOnAccountToken.account_key == self._account_key
        )
        return (await session.execute(statement)).scalars().first()
