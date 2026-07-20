"""Unit tests for the auth domain: password hashing, JWT handling, brute-force
defenses, and the register/login/refresh service flows.

Follows this project's plain-``assert`` / native-``async def`` style (see
``tests/unit/test_generic_repository.py``, ``tests/unit/test_health.py``);
``asyncio_mode = "auto"`` in ``pyproject.toml`` runs async tests directly
without needing ``@pytest.mark.asyncio``.

The service-level tests exercise ``AuthService`` against a small in-memory
fake repository/cache rather than a real Postgres + Redis, since no
database is available in this environment. ``AuthRepository`` itself (the
real, SQLAlchemy-backed implementation) is only exercised at the
import/construction level -- it needs a running Postgres to do anything
meaningful, which is out of scope here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.auth.jwt import InvalidTokenError, JWTManager, TokenExpiredError
from app.domains.auth.models import LoginAttempt, PasswordHistory, Session, User
from app.domains.auth.password import PasswordManager, PasswordStrengthError
from app.domains.auth.security import AccountLockedError, AuthSecurity
from app.domains.auth.service import (
    AuthService,
    DeviceInfo,
    EmailAlreadyExistsError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
    UsernameAlreadyExistsError,
)

STRONG_PASSWORD = "SecurePass123!@#"


# ============================================================================
# Test doubles
# ============================================================================


class FakeRedis:
    """Minimal async in-memory stand-in for ``redis.asyncio.Redis``."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self._ttl: dict[str, int] = {}

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = str(value)
        if ex is not None:
            self._ttl[key] = ex

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)
        self._ttl.pop(key, None)

    async def incr(self, key: str) -> int:
        current = int(self._store.get(key, "0")) + 1
        self._store[key] = str(current)
        return current

    async def expire(self, key: str, seconds: int) -> None:
        self._ttl[key] = seconds

    async def ttl(self, key: str) -> int:
        return self._ttl.get(key, -1)


@dataclass
class FakeAuthRepository:
    """In-memory stand-in for :class:`AuthRepositoryProtocol`."""

    users_by_id: dict[uuid.UUID, User] = field(default_factory=dict)
    sessions_by_jti: dict[str, Session] = field(default_factory=dict)
    password_history: dict[uuid.UUID, list[str]] = field(default_factory=dict)
    login_attempts: list[LoginAttempt] = field(default_factory=list)

    async def get_user_by_email(self, email: str) -> User | None:
        return next(
            (u for u in self.users_by_id.values() if u.email == email.lower()), None
        )

    async def get_user_by_username(self, username: str) -> User | None:
        return next(
            (u for u in self.users_by_id.values() if u.username == username.lower()),
            None,
        )

    async def get_user_by_id(self, user_id: uuid.UUID) -> User | None:
        return self.users_by_id.get(user_id)

    async def create_user(self, **fields: object) -> User:
        # SQLAlchemy's Python-side column defaults (e.g. failed_login_attempts=0)
        # are only applied on flush to a real engine; since these objects are
        # never flushed here, fill in the same defaults a real insert would.
        defaults: dict[str, object] = {
            "status": "active",
            "failed_login_attempts": 0,
            "locked_until": None,
            "email_verified_at": None,
            "phone_verified_at": None,
            "last_login_at": None,
            "password_changed_at": None,
            "timezone": "UTC",
            "language": "en",
            "must_change_password": False,
        }
        user = User(
            id=uuid.uuid4(),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            **{
                **defaults,
                **fields,
                "email": str(fields["email"]).lower(),
                "username": str(fields["username"]).lower(),
            },
        )
        self.users_by_id[user.id] = user
        return user

    async def update_user(self, user: User, **fields: object) -> User:
        for key, value in fields.items():
            setattr(user, key, value)
        return user

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
        session = Session(
            id=uuid.uuid4(),
            user_id=user_id,
            device_id=device_id,
            device_name=device_name,
            ip_address=ip_address,
            user_agent=user_agent,
            location=location,
            refresh_token_jti=token,
            expires_at=expires_at or (datetime.now(UTC) + timedelta(days=7)),
            last_activity_at=datetime.now(UTC),
            is_active=True,
        )
        self.sessions_by_jti[token] = session
        return session

    async def revoke_refresh_token(self, token: str) -> None:
        session = self.sessions_by_jti.get(token)
        if session:
            session.is_active = False

    async def get_session_by_refresh_token(self, token: str) -> Session | None:
        return self.sessions_by_jti.get(token)

    async def rotate_refresh_token(
        self, session: Session, new_refresh_jti: str
    ) -> Session:
        del self.sessions_by_jti[session.refresh_token_jti]
        session.refresh_token_jti = new_refresh_jti
        session.mark_activity()
        self.sessions_by_jti[new_refresh_jti] = session
        return session

    async def get_active_sessions(self, user_id: uuid.UUID) -> list[Session]:
        return [
            s
            for s in self.sessions_by_jti.values()
            if s.user_id == user_id and s.is_active and s.expires_at > datetime.now(UTC)
        ]

    async def revoke_session(self, session_id: uuid.UUID) -> None:
        for session in self.sessions_by_jti.values():
            if session.id == session_id:
                session.is_active = False

    async def revoke_all_sessions(self, user_id: uuid.UUID) -> int:
        revoked = 0
        for session in self.sessions_by_jti.values():
            if session.user_id == user_id and session.is_active:
                session.is_active = False
                revoked += 1
        return revoked

    async def add_password_history(
        self, user_id: uuid.UUID, password_hash: str
    ) -> PasswordHistory:
        self.password_history.setdefault(user_id, []).insert(0, password_hash)
        return PasswordHistory(
            id=uuid.uuid4(), user_id=user_id, password_hash=password_hash
        )

    async def get_recent_password_hashes(
        self, user_id: uuid.UUID, limit: int
    ) -> list[str]:
        return self.password_history.get(user_id, [])[:limit]

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
        attempt = LoginAttempt(
            id=uuid.uuid4(),
            user_id=user_id,
            email=email.lower(),
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            failure_reason=failure_reason,
        )
        self.login_attempts.append(attempt)
        return attempt

    async def get_recent_failed_attempts(
        self, email: str, ip_address: str, *, minutes: int = 15
    ) -> list[LoginAttempt]:
        return [
            a
            for a in self.login_attempts
            if a.email == email.lower() and a.ip_address == ip_address and not a.success
        ]


def make_service() -> tuple[AuthService, FakeAuthRepository, FakeRedis]:
    repository = FakeAuthRepository()
    redis = FakeRedis()
    return AuthService(repository, redis), repository, redis


def make_device_info() -> DeviceInfo:
    return DeviceInfo(
        ip_address="192.168.1.1", user_agent="pytest-agent", device_name="pytest"
    )


# ============================================================================
# Password hashing
# ============================================================================


class TestPasswordManager:
    def test_hash_and_verify_roundtrip(self) -> None:
        hashed = PasswordManager.hash(STRONG_PASSWORD)

        assert hashed != STRONG_PASSWORD
        assert PasswordManager.verify(STRONG_PASSWORD, hashed) is True
        assert PasswordManager.verify("WrongPassword123!@#", hashed) is False

    @pytest.mark.parametrize(
        "weak_password",
        [
            "short",
            "nouppercase123!",
            "NOLOWERCASE123!",
            "NoDigitsHere!",
            "NoSpecialChars123",
        ],
    )
    def test_rejects_weak_passwords(self, weak_password: str) -> None:
        with pytest.raises(PasswordStrengthError):
            PasswordManager.hash(weak_password)

    def test_strength_score_increases_with_complexity(self) -> None:
        weak = PasswordManager.strength_score("Pass123!")
        medium = PasswordManager.strength_score("SecurePass123!")
        strong = PasswordManager.strength_score("VerySecurePassword123!@#$%")

        assert weak < medium < strong


# ============================================================================
# JWT handling
# ============================================================================


class TestJWTManager:
    def test_create_access_token(self) -> None:
        token, jti = JWTManager.create_access_token(
            str(uuid.uuid4()), "test@example.com"
        )

        assert token
        assert jti

    def test_create_token_pair_shape(self) -> None:
        tokens = JWTManager.create_token_pair(str(uuid.uuid4()), "test@example.com")

        assert tokens["token_type"] == "bearer"
        assert tokens["expires_in"] > 0
        assert tokens["refresh_expires_in"] > tokens["expires_in"]

    def test_decode_round_trips_claims(self) -> None:
        user_id = str(uuid.uuid4())
        token, jti = JWTManager.create_access_token(user_id, "test@example.com")

        payload = JWTManager.decode(token)

        assert payload["sub"] == user_id
        assert payload["jti"] == jti
        assert payload["type"] == "access"

    def test_validate_token_type_mismatch_raises(self) -> None:
        token, _ = JWTManager.create_access_token(str(uuid.uuid4()), "test@example.com")

        with pytest.raises(InvalidTokenError):
            JWTManager.validate_token(token, expected_type="refresh")

    def test_expired_token_raises(self) -> None:
        import jwt as pyjwt

        from app.core.config import get_settings

        settings = get_settings()
        payload = {
            "sub": str(uuid.uuid4()),
            "email": "test@example.com",
            "jti": str(uuid.uuid4()),
            "type": "access",
            "iat": int((datetime.now(UTC) - timedelta(hours=1)).timestamp()),
            "exp": int((datetime.now(UTC) - timedelta(minutes=1)).timestamp()),
        }
        token = pyjwt.encode(
            payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
        )

        with pytest.raises(TokenExpiredError):
            JWTManager.decode(token)

        assert JWTManager.is_token_expired(token) is True


# ============================================================================
# Security: device ids, lockout, rate limiting
# ============================================================================


class TestAuthSecurity:
    def test_generate_device_id_is_deterministic(self) -> None:
        first = AuthSecurity.generate_device_id("1.2.3.4", "agent-a")
        second = AuthSecurity.generate_device_id("1.2.3.4", "agent-a")
        third = AuthSecurity.generate_device_id("1.2.3.4", "agent-b")

        assert first == second
        assert first != third

    def test_check_account_lock_raises_when_locked(self) -> None:
        with pytest.raises(AccountLockedError):
            AuthSecurity.check_account_lock(datetime.now(UTC) + timedelta(minutes=5))

    def test_check_account_lock_allows_when_expired(self) -> None:
        AuthSecurity.check_account_lock(datetime.now(UTC) - timedelta(minutes=5))

    async def test_rate_limit_clears_on_success(self) -> None:
        redis = FakeRedis()

        await AuthSecurity.record_login_attempt(
            redis, "user@example.com", "1.2.3.4", success=False
        )
        await AuthSecurity.record_login_attempt(
            redis, "user@example.com", "1.2.3.4", success=True
        )

        await AuthSecurity.check_rate_limit(redis, "user@example.com", "1.2.3.4")


# ============================================================================
# AuthService: register / login / refresh
# ============================================================================


class TestAuthServiceRegister:
    async def test_register_success(self) -> None:
        service, _repository, _redis = make_service()

        user, verification_token = await service.register(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password=STRONG_PASSWORD,
        )

        assert user.email == "test@example.com"
        assert user.is_verified is False
        assert verification_token

    async def test_register_rejects_duplicate_email(self) -> None:
        service, _repository, _redis = make_service()
        await service.register(
            first_name="Test",
            last_name="User",
            email="dup@example.com",
            username="firstuser",
            password=STRONG_PASSWORD,
        )

        with pytest.raises(EmailAlreadyExistsError):
            await service.register(
                first_name="Other",
                last_name="User",
                email="dup@example.com",
                username="seconduser",
                password=STRONG_PASSWORD,
            )

    async def test_register_rejects_duplicate_username(self) -> None:
        service, _repository, _redis = make_service()
        await service.register(
            first_name="Test",
            last_name="User",
            email="first@example.com",
            username="dupuser",
            password=STRONG_PASSWORD,
        )

        with pytest.raises(UsernameAlreadyExistsError):
            await service.register(
                first_name="Other",
                last_name="User",
                email="second@example.com",
                username="dupuser",
                password=STRONG_PASSWORD,
            )


class TestAuthServiceLogin:
    async def test_login_rejects_unknown_email(self) -> None:
        service, _repository, _redis = make_service()

        with pytest.raises(InvalidCredentialsError):
            await service.login(
                "nobody@example.com", STRONG_PASSWORD, make_device_info()
            )

    async def test_login_rejects_unverified_email(self) -> None:
        service, _repository, _redis = make_service()
        await service.register(
            first_name="Test",
            last_name="User",
            email="unverified@example.com",
            username="unverified",
            password=STRONG_PASSWORD,
        )

        with pytest.raises(EmailNotVerifiedError):
            await service.login(
                "unverified@example.com", STRONG_PASSWORD, make_device_info()
            )

    async def test_login_success_issues_tokens_and_session(self) -> None:
        service, repository, _redis = make_service()
        user, verification_token = await service.register(
            first_name="Test",
            last_name="User",
            email="verified@example.com",
            username="verified",
            password=STRONG_PASSWORD,
        )
        await service.verify_email(verification_token)

        logged_in_user, tokens, session_id = await service.login(
            "verified@example.com", STRONG_PASSWORD, make_device_info()
        )

        assert logged_in_user.id == user.id
        assert tokens.access_token
        assert tokens.refresh_token
        assert session_id in {s.id for s in repository.sessions_by_jti.values()}

    async def test_login_rejects_wrong_password(self) -> None:
        service, _repository, _redis = make_service()
        _user, verification_token = await service.register(
            first_name="Test",
            last_name="User",
            email="wrongpass@example.com",
            username="wrongpass",
            password=STRONG_PASSWORD,
        )
        await service.verify_email(verification_token)

        with pytest.raises(InvalidCredentialsError):
            await service.login(
                "wrongpass@example.com", "NotTheRightPass123!@#", make_device_info()
            )


class TestAuthServiceRefreshAndSessions:
    async def _login(self, service: AuthService, email: str, username: str):
        _user, verification_token = await service.register(
            first_name="Test",
            last_name="User",
            email=email,
            username=username,
            password=STRONG_PASSWORD,
        )
        await service.verify_email(verification_token)
        return await service.login(email, STRONG_PASSWORD, make_device_info())

    async def test_refresh_rotates_token(self) -> None:
        service, _repository, _redis = make_service()
        _user, tokens, _session_id = await self._login(
            service, "refresh@example.com", "refreshuser"
        )

        new_tokens = await service.refresh(tokens.refresh_token)

        assert new_tokens.access_token != tokens.access_token
        assert new_tokens.refresh_token != tokens.refresh_token

    async def test_logout_all_revokes_sessions(self) -> None:
        service, repository, _redis = make_service()
        user, _tokens, _session_id = await self._login(
            service, "logout@example.com", "logoutuser"
        )

        revoked = await service.logout_all(user.id)

        assert revoked == 1
        assert await repository.get_active_sessions(user.id) == []

    async def test_change_password_rejects_reused_password(self) -> None:
        service, _repository, _redis = make_service()
        user, _tokens, _session_id = await self._login(
            service, "changepw@example.com", "changepwuser"
        )

        from app.domains.auth.service import PasswordReuseError

        with pytest.raises(PasswordReuseError):
            await service.change_password(user.id, STRONG_PASSWORD, STRONG_PASSWORD)
