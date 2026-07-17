"""Data access layer for the auth domain.

Built on top of the project's ``GenericRepository`` (one instance per
entity) for standard CRUD/filter/sort/paginate access, with a handful of
hand-written queries only where ``GenericRepository``'s equality-only
filters genuinely can't express the auth use case (time-window and
"greater than" comparisons for session expiry / login-attempt cutoffs).

Preserves the original stub's ``AuthRepositoryProtocol`` / ``AuthRepository``
names and its three original methods (``get_user_by_email``,
``create_refresh_token``, ``revoke_refresh_token``), extended with the
session, password-history, and login-attempt operations the real auth
service needs.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository

from .models import LoginAttempt, PasswordHistory, Session, User


class AuthRepositoryProtocol(Protocol):
    async def get_user_by_email(self, email: str) -> User | None: ...

    async def get_user_by_username(self, username: str) -> User | None: ...

    async def get_user_by_id(self, user_id: uuid.UUID) -> User | None: ...

    async def create_user(self, **fields: object) -> User: ...

    async def update_user(self, user: User, **fields: object) -> User: ...

    async def create_refresh_token(
        self,
        user_id: uuid.UUID,
        token: str,
        *,
        device_id: str,
        device_name: str | None,
        ip_address: str,
        user_agent: str,
        location: str | None,
        expires_at: datetime,
    ) -> Session: ...

    async def revoke_refresh_token(self, token: str) -> None: ...

    async def get_session_by_refresh_token(self, token: str) -> Session | None: ...

    async def rotate_refresh_token(
        self, session: Session, new_refresh_jti: str
    ) -> Session: ...

    async def get_active_sessions(self, user_id: uuid.UUID) -> list[Session]: ...

    async def revoke_session(self, session_id: uuid.UUID) -> None: ...

    async def revoke_all_sessions(self, user_id: uuid.UUID) -> int: ...

    async def add_password_history(
        self, user_id: uuid.UUID, password_hash: str
    ) -> PasswordHistory: ...

    async def get_recent_password_hashes(
        self, user_id: uuid.UUID, limit: int
    ) -> list[str]: ...

    async def record_login_attempt(
        self,
        *,
        user_id: uuid.UUID | None,
        email: str,
        ip_address: str,
        user_agent: str,
        success: bool,
        failure_reason: str | None = None,
    ) -> LoginAttempt: ...

    async def get_recent_failed_attempts(
        self, email: str, ip_address: str, *, minutes: int = 15
    ) -> list[LoginAttempt]: ...


class AuthRepository:
    """Real, SQLAlchemy-backed implementation of :class:`AuthRepositoryProtocol`."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.users = GenericRepository(User, session)
        self.sessions = GenericRepository(Session, session)
        self.password_history = GenericRepository(PasswordHistory, session)
        self.login_attempts = GenericRepository(LoginAttempt, session)

    # -- users ---------------------------------------------------------

    async def get_user_by_email(self, email: str) -> User | None:
        results = await self.users.get_all(filters={"email": email.lower()}, limit=1)
        return results[0] if results else None

    async def get_user_by_username(self, username: str) -> User | None:
        results = await self.users.get_all(
            filters={"username": username.lower()}, limit=1
        )
        return results[0] if results else None

    async def get_user_by_id(self, user_id: uuid.UUID) -> User | None:
        return await self.users.get_by_id(user_id)

    async def create_user(self, **fields: object) -> User:
        if "email" in fields and isinstance(fields["email"], str):
            fields["email"] = fields["email"].lower()
        if "username" in fields and isinstance(fields["username"], str):
            fields["username"] = fields["username"].lower()
        return await self.users.create(fields)

    async def update_user(self, user: User, **fields: object) -> User:
        return await self.users.update(user, fields)

    # -- sessions / refresh tokens ---------------------------------------

    async def create_refresh_token(
        self,
        user_id: uuid.UUID,
        token: str,
        *,
        device_id: str = "unknown",
        device_name: str | None = None,
        ip_address: str = "unknown",
        user_agent: str = "unknown",
        location: str | None = None,
        expires_at: datetime | None = None,
    ) -> Session:
        return await self.sessions.create(
            {
                "user_id": user_id,
                "device_id": device_id,
                "device_name": device_name,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "location": location,
                "refresh_token_jti": token,
                "expires_at": expires_at or (datetime.now(UTC) + timedelta(days=7)),
            }
        )

    async def revoke_refresh_token(self, token: str) -> None:
        session_row = await self.get_session_by_refresh_token(token)
        if session_row is not None:
            await self.sessions.update(session_row, {"is_active": False})

    async def get_session_by_refresh_token(self, token: str) -> Session | None:
        results = await self.sessions.get_all(
            filters={"refresh_token_jti": token}, limit=1
        )
        return results[0] if results else None

    async def rotate_refresh_token(
        self, session: Session, new_refresh_jti: str
    ) -> Session:
        session.mark_activity()
        return await self.sessions.update(
            session,
            {
                "refresh_token_jti": new_refresh_jti,
                "last_activity_at": session.last_activity_at,
            },
        )

    async def get_session_by_id(self, session_id: uuid.UUID) -> Session | None:
        return await self.sessions.get_by_id(session_id)

    async def get_active_sessions(self, user_id: uuid.UUID) -> list[Session]:
        candidates = await self.sessions.get_all(
            filters={"user_id": user_id, "is_active": True},
            sort_by="created_at",
            sort_order=SortOrder.DESC,
        )
        now = datetime.now(UTC)
        return [row for row in candidates if row.expires_at > now]

    async def revoke_session(self, session_id: uuid.UUID) -> None:
        session_row = await self.sessions.get_by_id(session_id)
        if session_row is not None:
            await self.sessions.update(session_row, {"is_active": False})

    async def revoke_all_sessions(self, user_id: uuid.UUID) -> int:
        active = await self.sessions.get_all(
            filters={"user_id": user_id, "is_active": True}
        )
        for row in active:
            await self.sessions.update(row, {"is_active": False})
        return len(active)

    async def cleanup_expired_sessions(self) -> int:
        statement = select(Session).where(Session.expires_at < datetime.now(UTC))
        result = await self.session.execute(statement)
        expired = list(result.scalars().all())
        for row in expired:
            await self.sessions.delete(row)
        return len(expired)

    # -- password history --------------------------------------------------

    async def add_password_history(
        self, user_id: uuid.UUID, password_hash: str
    ) -> PasswordHistory:
        return await self.password_history.create(
            {"user_id": user_id, "password_hash": password_hash}
        )

    async def get_recent_password_hashes(
        self, user_id: uuid.UUID, limit: int = 5
    ) -> list[str]:
        rows = await self.password_history.get_all(
            filters={"user_id": user_id},
            sort_by="created_at",
            sort_order=SortOrder.DESC,
            limit=limit,
        )
        return [row.password_hash for row in rows]

    # -- login attempts ------------------------------------------------------

    async def record_login_attempt(
        self,
        *,
        user_id: uuid.UUID | None,
        email: str,
        ip_address: str,
        user_agent: str,
        success: bool,
        failure_reason: str | None = None,
    ) -> LoginAttempt:
        return await self.login_attempts.create(
            {
                "user_id": user_id,
                "email": email.lower(),
                "ip_address": ip_address,
                "user_agent": user_agent,
                "success": success,
                "failure_reason": failure_reason,
            }
        )

    async def get_recent_failed_attempts(
        self, email: str, ip_address: str, *, minutes: int = 15
    ) -> list[LoginAttempt]:
        cutoff = datetime.now(UTC) - timedelta(minutes=minutes)
        statement = select(LoginAttempt).where(
            LoginAttempt.email == email.lower(),
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.success.is_(False),
            LoginAttempt.created_at > cutoff,
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def cleanup_old_login_attempts(self, *, days: int = 30) -> int:
        cutoff = datetime.now(UTC) - timedelta(days=days)
        statement = select(LoginAttempt).where(LoginAttempt.created_at < cutoff)
        result = await self.session.execute(statement)
        stale = list(result.scalars().all())
        for row in stale:
            await self.login_attempts.delete(row)
        return len(stale)
