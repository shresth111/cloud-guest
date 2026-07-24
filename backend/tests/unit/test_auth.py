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

import pyotp
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.api_keys.exceptions import ApiKeyAuthenticationError
from app.domains.auth import mfa as mfa_module
from app.domains.auth.dependencies import get_current_user
from app.domains.auth.jwt import InvalidTokenError, JWTManager, TokenExpiredError
from app.domains.auth.models import (
    LoginAttempt,
    PasswordHistory,
    Session,
    User,
    UserMfaCredential,
    UserMfaRecoveryCode,
)
from app.domains.auth.password import PasswordManager, PasswordStrengthError
from app.domains.auth.security import AccountLockedError, AuthSecurity
from app.domains.auth.service import (
    AuthService,
    DeviceInfo,
    EmailAlreadyExistsError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
    InvalidMfaCodeError,
    MfaAlreadyEnabledError,
    MfaNotEnabledError,
    MfaNotEnrolledError,
    MfaRequiredError,
    UsernameAlreadyExistsError,
)
from app.domains.auth.service import InvalidTokenError as ResetTokenInvalidError

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
    mfa_credentials_by_user: dict[uuid.UUID, UserMfaCredential] = field(
        default_factory=dict
    )
    recovery_codes_by_user: dict[uuid.UUID, list[UserMfaRecoveryCode]] = field(
        default_factory=dict
    )

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
            "mfa_enabled": False,
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

    async def list_login_attempts(
        self,
        *,
        email: str | None = None,
        success: bool | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[LoginAttempt], PaginationMeta]:
        values = list(self.login_attempts)
        if email is not None:
            values = [a for a in values if a.email == email.lower()]
        if success is not None:
            values = [a for a in values if a.success == success]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    # -- MFA -------------------------------------------------------------

    async def get_mfa_credential(self, user_id: uuid.UUID) -> UserMfaCredential | None:
        return self.mfa_credentials_by_user.get(user_id)

    async def create_mfa_credential(self, **fields: object) -> UserMfaCredential:
        credential = UserMfaCredential(
            id=uuid.uuid4(),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            **fields,
        )
        self.mfa_credentials_by_user[credential.user_id] = credential
        return credential

    async def update_mfa_credential(
        self, credential: UserMfaCredential, data: dict[str, object]
    ) -> UserMfaCredential:
        for key, value in data.items():
            setattr(credential, key, value)
        return credential

    async def delete_mfa_credential(self, credential: UserMfaCredential) -> None:
        self.mfa_credentials_by_user.pop(credential.user_id, None)

    async def replace_recovery_codes(
        self, user_id: uuid.UUID, code_hashes: list[str]
    ) -> list[UserMfaRecoveryCode]:
        codes = [
            UserMfaRecoveryCode(
                id=uuid.uuid4(),
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                user_id=user_id,
                code_hash=code_hash,
                used_at=None,
            )
            for code_hash in code_hashes
        ]
        self.recovery_codes_by_user[user_id] = codes
        return codes

    async def get_active_recovery_code(
        self, user_id: uuid.UUID, code_hash: str
    ) -> UserMfaRecoveryCode | None:
        for code in self.recovery_codes_by_user.get(user_id, []):
            if code.code_hash == code_hash and code.used_at is None:
                return code
        return None

    async def mark_recovery_code_used(
        self, recovery_code: UserMfaRecoveryCode
    ) -> UserMfaRecoveryCode:
        recovery_code.used_at = datetime.now(UTC)
        return recovery_code


def make_service() -> tuple[AuthService, FakeAuthRepository, FakeRedis]:
    repository = FakeAuthRepository()
    redis = FakeRedis()
    return AuthService(repository, redis), repository, redis


@dataclass
class FakeNotificationSender:
    """In-memory stand-in for ``AuthService``'s own
    ``NotificationSenderProtocol`` -- mirrors ``FakeAuthRepository``'s
    identical "fake the narrow Protocol boundary" precedent."""

    enqueued: list[dict[str, object]] = field(default_factory=list)

    async def enqueue(self, **kwargs: object) -> None:
        self.enqueued.append(kwargs)


def make_service_with_notification_sender() -> (
    tuple[AuthService, FakeAuthRepository, FakeRedis, FakeNotificationSender]
):
    repository = FakeAuthRepository()
    redis = FakeRedis()
    notification_sender = FakeNotificationSender()
    service = AuthService(repository, redis, notification_service=notification_sender)
    return service, repository, redis, notification_sender


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


class TestAuthServiceNotificationWiring:
    """``register``/``initiate_password_reset``/``resend_verification``
    previously only logged a token and never delivered it anywhere (see
    ``app.domains.notification``'s own module docstring for the write-up
    of this exact gap). These assert the real enqueue call now happens."""

    async def test_register_enqueues_verification_email(self) -> None:
        service, _repository, _redis, sender = make_service_with_notification_sender()

        user, verification_token = await service.register(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password=STRONG_PASSWORD,
        )

        assert len(sender.enqueued) == 1
        call = sender.enqueued[0]
        assert call["recipient"] == user.email
        assert verification_token in call["body"]

    async def test_initiate_password_reset_enqueues_email_for_known_user(
        self,
    ) -> None:
        service, _repository, _redis, sender = make_service_with_notification_sender()
        await service.register(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password=STRONG_PASSWORD,
        )
        sender.enqueued.clear()

        await service.initiate_password_reset("test@example.com")

        assert len(sender.enqueued) == 1
        assert sender.enqueued[0]["recipient"] == "test@example.com"

    async def test_initiate_password_reset_does_not_enqueue_for_unknown_email(
        self,
    ) -> None:
        service, _repository, _redis, sender = make_service_with_notification_sender()

        await service.initiate_password_reset("nobody@example.com")

        assert sender.enqueued == []

    async def test_resend_verification_enqueues_email_for_unverified_user(
        self,
    ) -> None:
        service, _repository, _redis, sender = make_service_with_notification_sender()
        await service.register(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password=STRONG_PASSWORD,
        )
        sender.enqueued.clear()

        await service.resend_verification("test@example.com")

        assert len(sender.enqueued) == 1
        assert sender.enqueued[0]["recipient"] == "test@example.com"


class TestAuthServicePasswordResetRoundTrip:
    """``initiate_password_reset`` (issues the token, emails the link) and
    ``reset_password`` (consumes it) previously had no test exercising the
    real, full flow a self-service "forgot password" click-through
    actually performs -- only the notification-enqueue side was covered
    above. These close that gap."""

    @staticmethod
    def _extract_token(body: object) -> str:
        text = str(body)
        assert "/reset-password?token=" in text
        return text.split("token=", 1)[1].split()[0].strip()

    async def test_reset_link_points_at_configured_frontend_base_url(self) -> None:
        from app.core.config import get_settings

        service, _repository, _redis, sender = make_service_with_notification_sender()
        await service.register(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password=STRONG_PASSWORD,
        )
        sender.enqueued.clear()

        await service.initiate_password_reset("test@example.com")

        body = str(sender.enqueued[0]["body"])
        settings = get_settings()
        assert f"{settings.frontend_base_url.rstrip('/')}/reset-password?token=" in body

    async def test_full_round_trip_updates_password(self) -> None:
        service, repository, _redis, sender = make_service_with_notification_sender()
        await service.register(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password=STRONG_PASSWORD,
        )
        sender.enqueued.clear()

        await service.initiate_password_reset("test@example.com")
        token = self._extract_token(sender.enqueued[0]["body"])

        new_password = "AnotherSecurePass456!@#"
        await service.reset_password(token, new_password)

        user = await repository.get_user_by_email("test@example.com")
        assert user is not None
        assert PasswordManager.verify(new_password, user.password_hash) is True
        assert PasswordManager.verify(STRONG_PASSWORD, user.password_hash) is False

    async def test_reset_token_is_single_use(self) -> None:
        service, _repository, _redis, sender = make_service_with_notification_sender()
        await service.register(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password=STRONG_PASSWORD,
        )
        sender.enqueued.clear()
        await service.initiate_password_reset("test@example.com")
        token = self._extract_token(sender.enqueued[0]["body"])

        await service.reset_password(token, "AnotherSecurePass456!@#")

        with pytest.raises(ResetTokenInvalidError):
            await service.reset_password(token, "YetAnotherPass789!@#")

    async def test_reset_password_rejects_unknown_token(self) -> None:
        service, _repository, _redis, _sender = make_service_with_notification_sender()

        with pytest.raises(ResetTokenInvalidError):
            await service.reset_password("not-a-real-token", "AnotherSecurePass456!@#")

    async def test_reset_token_not_stored_as_plaintext_in_redis(self) -> None:
        """The Redis key must be a hash of the token, not the token
        itself -- mirrors ``app.domains.api_keys`` never persisting a
        plaintext API key. See ``AuthService._hash_token``."""
        service, _repository, redis, sender = make_service_with_notification_sender()
        await service.register(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password=STRONG_PASSWORD,
        )
        sender.enqueued.clear()
        await service.initiate_password_reset("test@example.com")
        token = self._extract_token(sender.enqueued[0]["body"])

        assert f"auth:password_reset:{token}" not in redis._store


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


# ============================================================================
# Login attempt history (real read source for app.domains.controller_logs)
# ============================================================================


class TestListLoginAttempts:
    async def test_lists_all_attempts_by_default(self) -> None:
        service, repository, _redis = make_service()
        await repository.record_login_attempt(
            user_id=None,
            email="a@example.com",
            ip_address="10.0.0.1",
            user_agent="agent",
            success=True,
        )
        await repository.record_login_attempt(
            user_id=None,
            email="b@example.com",
            ip_address="10.0.0.2",
            user_agent="agent",
            success=False,
            failure_reason="bad_password",
        )
        attempts, meta = await service.list_login_attempts()
        assert meta.total_items == 2
        assert len(attempts) == 2

    async def test_filters_by_email_and_success(self) -> None:
        service, repository, _redis = make_service()
        await repository.record_login_attempt(
            user_id=None,
            email="a@example.com",
            ip_address="10.0.0.1",
            user_agent="agent",
            success=True,
        )
        await repository.record_login_attempt(
            user_id=None,
            email="a@example.com",
            ip_address="10.0.0.1",
            user_agent="agent",
            success=False,
            failure_reason="bad_password",
        )
        attempts, meta = await service.list_login_attempts(
            email="a@example.com", success=False
        )
        assert meta.total_items == 1
        assert attempts[0].success is False


# ============================================================================
# get_current_user: X-API-Key as an alternative to a JWT
# ============================================================================


def _make_request(*, headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request(
        {"type": "http", "method": "GET", "path": "/", "headers": raw_headers}
    )


@dataclass
class _ResolvedApiKey:
    organization_id: uuid.UUID
    user_id: uuid.UUID


@dataclass
class FakeApiKeyService:
    resolved: _ResolvedApiKey | None = None
    should_fail: bool = False

    async def resolve_active_key(self, plaintext_key: str) -> _ResolvedApiKey:
        if self.should_fail or self.resolved is None:
            raise ApiKeyAuthenticationError()
        return self.resolved


class TestGetCurrentUserApiKey:
    async def test_resolves_user_via_x_api_key_header(self) -> None:
        repository = FakeAuthRepository()
        user = await repository.create_user(
            first_name="Api",
            last_name="Caller",
            email="apicaller@example.com",
            username="apicaller",
            password_hash="hashed",
            is_active=True,
            is_verified=True,
        )
        org_id = uuid.uuid4()
        api_key_service = FakeApiKeyService(
            resolved=_ResolvedApiKey(organization_id=org_id, user_id=user.id)
        )
        request = _make_request(headers={"X-API-Key": "cgst_whatever"})

        auth_user = await get_current_user(
            request=request,
            credentials=None,
            repository=repository,
            api_key_service=api_key_service,
        )

        assert auth_user.id == str(user.id)

    async def test_rejects_invalid_api_key(self) -> None:
        repository = FakeAuthRepository()
        api_key_service = FakeApiKeyService(should_fail=True)
        request = _make_request(headers={"X-API-Key": "cgst_bad"})

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(
                request=request,
                credentials=None,
                repository=repository,
                api_key_service=api_key_service,
            )

        assert exc_info.value.status_code == 401

    async def test_rejects_organization_header_mismatch(self) -> None:
        repository = FakeAuthRepository()
        user = await repository.create_user(
            first_name="Api",
            last_name="Caller",
            email="apicaller2@example.com",
            username="apicaller2",
            password_hash="hashed",
            is_active=True,
            is_verified=True,
        )
        key_org_id = uuid.uuid4()
        other_org_id = uuid.uuid4()
        api_key_service = FakeApiKeyService(
            resolved=_ResolvedApiKey(organization_id=key_org_id, user_id=user.id)
        )
        request = _make_request(
            headers={
                "X-API-Key": "cgst_whatever",
                "X-Organization-Id": str(other_org_id),
            }
        )

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(
                request=request,
                credentials=None,
                repository=repository,
                api_key_service=api_key_service,
            )

        assert exc_info.value.status_code == 403

    async def test_missing_credentials_raises_401(self) -> None:
        repository = FakeAuthRepository()
        request = _make_request()

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(
                request=request,
                credentials=None,
                repository=repository,
                api_key_service=FakeApiKeyService(),
            )

        assert exc_info.value.status_code == 401


# ============================================================================
# MFA/TOTP: enroll, verify+enable, login gating, disable, recovery codes
# ============================================================================


class TestMfa:
    async def test_enroll_returns_secret_and_provisioning_uri(self) -> None:
        service, _repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )

        secret, uri = await service.enroll_mfa(user.id)

        assert len(secret) >= 16
        assert "otpauth://totp/" in uri
        assert user.mfa_enabled is False

    async def test_enroll_rejects_already_enabled(self) -> None:
        service, _repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )
        secret, _uri = await service.enroll_mfa(user.id)
        await service.verify_and_enable_mfa(user.id, pyotp.TOTP(secret).now())

        with pytest.raises(MfaAlreadyEnabledError):
            await service.enroll_mfa(user.id)

    async def test_verify_and_enable_requires_prior_enrollment(self) -> None:
        service, _repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )

        with pytest.raises(MfaNotEnrolledError):
            await service.verify_and_enable_mfa(user.id, "123456")

    async def test_verify_and_enable_rejects_wrong_code(self) -> None:
        service, _repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )
        await service.enroll_mfa(user.id)

        with pytest.raises(InvalidMfaCodeError):
            await service.verify_and_enable_mfa(user.id, "000000")

    async def test_verify_and_enable_flips_flag_and_returns_recovery_codes(
        self,
    ) -> None:
        service, _repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )
        secret, _uri = await service.enroll_mfa(user.id)
        recovery_codes = await service.verify_and_enable_mfa(
            user.id, pyotp.TOTP(secret).now()
        )

        assert user.mfa_enabled is True
        assert len(recovery_codes) == 10  # Settings.mfa_recovery_code_count default

    async def test_login_requires_mfa_code_when_enabled(self) -> None:
        service, _repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )
        await _enable_mfa(service, user.id)
        await _verify_email(service, user)

        with pytest.raises(MfaRequiredError):
            await service.login("mfa@example.com", STRONG_PASSWORD, make_device_info())

    async def test_login_succeeds_with_correct_totp_code(self) -> None:
        service, _repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )
        secret = await _enable_mfa(service, user.id)
        await _verify_email(service, user)
        _user, tokens, _session_id = await service.login(
            "mfa@example.com",
            STRONG_PASSWORD,
            make_device_info(),
            mfa_code=pyotp.TOTP(secret).now(),
        )

        assert tokens.access_token

    async def test_login_succeeds_with_recovery_code_and_consumes_it(self) -> None:
        service, repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )
        _secret = await _enable_mfa(service, user.id)
        await _verify_email(service, user)
        recovery_code = repository.recovery_codes_by_user[user.id][0]
        # We only have the hash in the fake repo's stored row; regenerate a
        # known plaintext/hash pair directly via the mfa module instead.

        plaintext = "ABCDE-12345"
        recovery_code.code_hash = mfa_module.hash_recovery_code(plaintext)

        await service.login(
            "mfa@example.com",
            STRONG_PASSWORD,
            make_device_info(),
            mfa_code=plaintext,
        )

        assert recovery_code.used_at is not None

    async def test_login_rejects_wrong_mfa_code(self) -> None:
        service, _repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )
        await _enable_mfa(service, user.id)
        await _verify_email(service, user)

        with pytest.raises(InvalidMfaCodeError):
            await service.login(
                "mfa@example.com",
                STRONG_PASSWORD,
                make_device_info(),
                mfa_code="000000",
            )

    async def test_disable_requires_correct_password_and_code(self) -> None:
        service, _repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )
        secret = await _enable_mfa(service, user.id)
        with pytest.raises(InvalidCredentialsError):
            await service.disable_mfa(
                user.id, password="wrong-password", code=pyotp.TOTP(secret).now()
            )

    async def test_disable_clears_mfa_state(self) -> None:
        service, repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )
        secret = await _enable_mfa(service, user.id)
        await service.disable_mfa(
            user.id, password=STRONG_PASSWORD, code=pyotp.TOTP(secret).now()
        )

        assert user.mfa_enabled is False
        assert repository.mfa_credentials_by_user.get(user.id) is None

    async def test_disable_rejects_when_not_enabled(self) -> None:
        service, _repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )

        with pytest.raises(MfaNotEnabledError):
            await service.disable_mfa(user.id, password=STRONG_PASSWORD, code="123456")

    async def test_regenerate_recovery_codes_replaces_old_ones(self) -> None:
        service, repository, _redis = make_service()
        user, _token = await service.register(
            first_name="Test",
            last_name="User",
            email="mfa@example.com",
            username="mfauser",
            password=STRONG_PASSWORD,
        )
        secret = await _enable_mfa(service, user.id)
        old_codes = list(repository.recovery_codes_by_user[user.id])
        new_codes = await service.regenerate_recovery_codes(
            user.id, code=pyotp.TOTP(secret).now()
        )

        assert len(new_codes) == 10
        new_hashes = {c.code_hash for c in repository.recovery_codes_by_user[user.id]}
        old_hashes = {c.code_hash for c in old_codes}
        assert new_hashes.isdisjoint(old_hashes)


async def _enable_mfa(service: AuthService, user_id: uuid.UUID) -> str:
    """Enrolls and verifies MFA for ``user_id``, returning the raw TOTP
    secret so a test can generate further valid codes."""
    import pyotp

    secret, _uri = await service.enroll_mfa(user_id)
    await service.verify_and_enable_mfa(user_id, pyotp.TOTP(secret).now())
    return secret


async def _verify_email(service: AuthService, user: User) -> None:
    """Marks ``user`` verified directly through the repository -- MFA
    login tests need a verified account but don't exercise the
    verification flow itself."""
    await service.repository.update_user(user, is_verified=True)
