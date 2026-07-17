"""
Repository layer for data access and persistence.

Implements the repository pattern for decoupling business logic from data access.

Architecture: Infrastructure Layer - Persistence
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import LoginAttempt, PasswordHistory, Session, User


class BaseRepository:
    """Base repository with common CRUD operations."""

    def __init__(self, model):
        """Initialize repository with model class."""
        self.model = model

    async def create(self, db: AsyncSession, **kwargs):
        """Create and return a new entity."""
        entity = self.model(**kwargs)
        db.add(entity)
        await db.flush()
        return entity

    async def get_by_id(self, db: AsyncSession, id: str):
        """Get entity by ID."""
        return await db.get(self.model, id)

    async def update(self, db: AsyncSession, entity):
        """Update an entity."""
        await db.merge(entity)
        await db.flush()
        return entity

    async def delete(self, db: AsyncSession, entity):
        """Delete an entity."""
        await db.delete(entity)
        await db.flush()

    async def list(self, db: AsyncSession, skip: int = 0, limit: int = 100):
        """List all entities with pagination."""
        query = select(self.model).offset(skip).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()


class UserRepository(BaseRepository):
    """Repository for User entity."""

    def __init__(self):
        super().__init__(User)

    async def get_by_email(self, db: AsyncSession, email: str) -> Optional[User]:
        """Get user by email address."""
        query = select(User).where(User.email == email.lower())
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def get_by_username(self, db: AsyncSession, username: str) -> Optional[User]:
        """Get user by username."""
        query = select(User).where(User.username == username.lower())
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def get_by_id(self, db: AsyncSession, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return await db.get(User, user_id)

    async def get_active_users(self, db: AsyncSession, skip: int = 0, limit: int = 100):
        """Get all active users."""
        query = (
            select(User)
            .where(and_(User.is_active == True, User.status == "active"))
            .offset(skip)
            .limit(limit)
        )
        result = await db.execute(query)
        return result.scalars().all()

    async def search(self, db: AsyncSession, search_term: str, skip: int = 0, limit: int = 100):
        """Search users by email or username."""
        query = (
            select(User)
            .where(
                (User.email.ilike(f"%{search_term}%"))
                | (User.username.ilike(f"%{search_term}%"))
            )
            .offset(skip)
            .limit(limit)
        )
        result = await db.execute(query)
        return result.scalars().all()

    async def count(self, db: AsyncSession) -> int:
        """Count total users."""
        query = select(User)
        result = await db.execute(query)
        return len(result.scalars().all())


class SessionRepository(BaseRepository):
    """Repository for Session entity."""

    def __init__(self):
        super().__init__(Session)

    async def get_by_id(self, db: AsyncSession, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        return await db.get(Session, session_id)

    async def get_by_refresh_token_jti(
        self, db: AsyncSession, refresh_token_jti: str
    ) -> Optional[Session]:
        """Get session by refresh token JTI."""
        query = select(Session).where(Session.refresh_token_jti == refresh_token_jti)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def get_user_sessions(
        self, db: AsyncSession, user_id: str, active_only: bool = True
    ) -> list[Session]:
        """Get all sessions for a user."""
        conditions = [Session.user_id == user_id]
        if active_only:
            conditions.append(Session.is_active == True)
            conditions.append(Session.expires_at > datetime.utcnow())

        query = select(Session).where(and_(*conditions))
        result = await db.execute(query)
        return result.scalars().all()

    async def get_active_sessions(
        self, db: AsyncSession, user_id: str
    ) -> list[Session]:
        """Get active sessions for a user."""
        return await self.get_user_sessions(db, user_id, active_only=True)

    async def revoke_session(self, db: AsyncSession, session_id: str) -> None:
        """Revoke a session."""
        session = await self.get_by_id(db, session_id)
        if session:
            session.is_active = False
            await self.update(db, session)

    async def revoke_all(self, db: AsyncSession, user_id: str) -> int:
        """Revoke all sessions for a user."""
        query = select(Session).where(
            and_(Session.user_id == user_id, Session.is_active == True)
        )
        result = await db.execute(query)
        sessions = result.scalars().all()

        for session in sessions:
            session.is_active = False
            await self.update(db, session)

        return len(sessions)

    async def cleanup_expired_sessions(self, db: AsyncSession) -> int:
        """Delete expired sessions (cleanup)."""
        query = select(Session).where(Session.expires_at < datetime.utcnow())
        result = await db.execute(query)
        sessions = result.scalars().all()

        for session in sessions:
            await self.delete(db, session)

        return len(sessions)


class PasswordHistoryRepository(BaseRepository):
    """Repository for PasswordHistory entity."""

    def __init__(self):
        super().__init__(PasswordHistory)

    async def get_recent(
        self, db: AsyncSession, user_id: str, limit: int = 5
    ) -> list[PasswordHistory]:
        """Get recent password hashes for a user."""
        query = (
            select(PasswordHistory)
            .where(PasswordHistory.user_id == user_id)
            .order_by(desc(PasswordHistory.created_at))
            .limit(limit)
        )
        result = await db.execute(query)
        return result.scalars().all()

    async def cleanup_old_history(
        self, db: AsyncSession, user_id: str, keep_count: int = 5
    ) -> int:
        """Keep only recent password hashes, delete older ones."""
        # Get all history ordered by date
        query = (
            select(PasswordHistory)
            .where(PasswordHistory.user_id == user_id)
            .order_by(desc(PasswordHistory.created_at))
        )
        result = await db.execute(query)
        histories = result.scalars().all()

        # Delete older than keep_count
        deleted = 0
        for history in histories[keep_count:]:
            await self.delete(db, history)
            deleted += 1

        return deleted


class LoginAttemptRepository(BaseRepository):
    """Repository for LoginAttempt entity."""

    def __init__(self):
        super().__init__(LoginAttempt)

    async def get_recent_attempts(
        self,
        db: AsyncSession,
        email: str,
        ip_address: Optional[str] = None,
        minutes: int = 15,
    ) -> list[LoginAttempt]:
        """Get recent login attempts."""
        from datetime import timedelta

        cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)

        conditions = [
            LoginAttempt.email == email,
            LoginAttempt.created_at > cutoff_time,
        ]

        if ip_address:
            conditions.append(LoginAttempt.ip_address == ip_address)

        query = (
            select(LoginAttempt)
            .where(and_(*conditions))
            .order_by(desc(LoginAttempt.created_at))
        )

        result = await db.execute(query)
        return result.scalars().all()

    async def get_failed_attempts(
        self,
        db: AsyncSession,
        email: str,
        ip_address: Optional[str] = None,
        minutes: int = 15,
    ) -> list[LoginAttempt]:
        """Get failed login attempts."""
        all_attempts = await self.get_recent_attempts(
            db, email, ip_address, minutes
        )
        return [a for a in all_attempts if not a.success]

    async def get_by_user(
        self,
        db: AsyncSession,
        user_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> list[LoginAttempt]:
        """Get login attempts for a user."""
        query = (
            select(LoginAttempt)
            .where(LoginAttempt.user_id == user_id)
            .order_by(desc(LoginAttempt.created_at))
            .offset(skip)
            .limit(limit)
        )
        result = await db.execute(query)
        return result.scalars().all()

    async def cleanup_old_attempts(
        self, db: AsyncSession, days: int = 30
    ) -> int:
        """Delete login attempts older than specified days."""
        from datetime import timedelta

        cutoff_time = datetime.utcnow() - timedelta(days=days)

        query = select(LoginAttempt).where(LoginAttempt.created_at < cutoff_time)
        result = await db.execute(query)
        attempts = result.scalars().all()

        for attempt in attempts:
            await self.delete(db, attempt)

        return len(attempts)


# Repository Factory for dependency injection
class RepositoryFactory:
    """Factory for creating repository instances."""

    @staticmethod
    def create_user_repository() -> UserRepository:
        """Create user repository."""
        return UserRepository()

    @staticmethod
    def create_session_repository() -> SessionRepository:
        """Create session repository."""
        return SessionRepository()

    @staticmethod
    def create_password_history_repository() -> PasswordHistoryRepository:
        """Create password history repository."""
        return PasswordHistoryRepository()

    @staticmethod
    def create_login_attempt_repository() -> LoginAttemptRepository:
        """Create login attempt repository."""
        return LoginAttemptRepository()

    @staticmethod
    def create_all_repositories() -> dict:
        """Create all repositories."""
        return {
            "user": RepositoryFactory.create_user_repository(),
            "session": RepositoryFactory.create_session_repository(),
            "password_history": RepositoryFactory.create_password_history_repository(),
            "login_attempt": RepositoryFactory.create_login_attempt_repository(),
        }
