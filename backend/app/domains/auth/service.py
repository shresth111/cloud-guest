"""Auth business logic: registration, login, token refresh, password/session management.

Ported from the old ``auth_service.py``. Domain errors subclass
``CloudGuestError`` (see ``app.common.exceptions``) instead of bare
``Exception`` so they flow through the app's existing exception-handler /
response-envelope machinery without every route needing its own
try/except translation.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

from fastapi import status
from redis.asyncio import Redis

from app.common.exceptions import CloudGuestError
from app.core.config import get_settings
from app.database.redis import redis_client as _default_redis_client
from app.domains.notification.constants import (
    NotificationChannelType,
    NotificationEventType,
)

from . import mfa
from .jwt import InvalidTokenError as JWTInvalidTokenError
from .jwt import JWTManager
from .jwt import TokenExpiredError as JWTTokenExpiredError
from .models import AuthUser, TokenPair, User
from .password import PasswordManager
from .repository import AuthRepositoryProtocol
from .security import AuthSecurity

logger = logging.getLogger(__name__)


class AuthServiceError(CloudGuestError):
    """Base exception for auth service errors."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code)


class UserNotFoundError(AuthServiceError):
    def __init__(self, message: str = "User not found") -> None:
        super().__init__(message, status_code=status.HTTP_404_NOT_FOUND)


class InvalidCredentialsError(AuthServiceError):
    def __init__(self, message: str = "Invalid email or password") -> None:
        super().__init__(message, status_code=status.HTTP_401_UNAUTHORIZED)


class EmailAlreadyExistsError(AuthServiceError):
    def __init__(self, email: str) -> None:
        super().__init__(
            f"Email {email} is already registered", status_code=status.HTTP_409_CONFLICT
        )


class UsernameAlreadyExistsError(AuthServiceError):
    def __init__(self, username: str) -> None:
        super().__init__(
            f"Username {username} is already taken",
            status_code=status.HTTP_409_CONFLICT,
        )


class EmailNotVerifiedError(AuthServiceError):
    def __init__(
        self,
        message: str = (
            "Email not verified. Please check your email for the verification link."
        ),
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class PasswordChangeRequiredError(AuthServiceError):
    """Raised by ``AuthService.login`` instead of issuing a normal session
    when ``User.must_change_password`` is set -- see that flag's own
    docstring in ``app.domains.auth.models`` and ``docs/location/FLOW.md``
    for why Smart Location Provisioning needed this narrow, additive check.
    Mirrors ``EmailNotVerifiedError``'s identical shape (a distinct,
    ``CloudGuestError``-flowing 403 raised *before* any token pair is
    created), which is exactly the "minimally-invasive way to signal this"
    precedent already established in this same method -- no rewriting of
    the surrounding login logic was needed."""

    def __init__(
        self,
        message: str = (
            "Password change required. Use the forgot-password flow to set a new "
            "password before logging in."
        ),
    ) -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class PasswordReuseError(AuthServiceError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)


class InvalidTokenError(AuthServiceError):
    def __init__(self, message: str = "Token is invalid or expired") -> None:
        super().__init__(message, status_code=status.HTTP_401_UNAUTHORIZED)


class MfaAlreadyEnabledError(AuthServiceError):
    def __init__(self) -> None:
        super().__init__(
            "MFA is already enabled for this account",
            status_code=status.HTTP_409_CONFLICT,
        )


class MfaNotEnrolledError(AuthServiceError):
    def __init__(self) -> None:
        super().__init__(
            "MFA enrollment has not been started for this account",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class MfaNotEnabledError(AuthServiceError):
    def __init__(self) -> None:
        super().__init__(
            "MFA is not enabled for this account",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class MfaRequiredError(AuthServiceError):
    """Raised by ``login`` instead of issuing tokens when the account has
    MFA enabled and no ``mfa_code`` was supplied -- mirrors
    ``PasswordChangeRequiredError``'s identical "credentials correct but a
    special state blocks a normal login" precedent. The caller retries the
    same ``login`` call with ``mfa_code`` included."""

    def __init__(self) -> None:
        super().__init__(
            "MFA code required to complete login",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class InvalidMfaCodeError(AuthServiceError):
    def __init__(self) -> None:
        super().__init__(
            "Invalid MFA code or recovery code",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


@dataclass
class DeviceInfo:
    """Client device/network context captured at login, for session tracking."""

    ip_address: str
    user_agent: str
    device_name: str | None = None
    location: str | None = None
    device_id: str | None = None

    def __post_init__(self) -> None:
        if not self.device_id:
            self.device_id = AuthSecurity.generate_device_id(
                self.ip_address, self.user_agent
            )


_VERIFICATION_TOKEN_KEY = "auth:email_verification:{token}"
_RESET_TOKEN_KEY = "auth:password_reset:{token}"


class NotificationSenderProtocol(Protocol):
    """The minimal surface ``AuthService`` needs to actually deliver an
    email -- satisfied structurally by
    ``app.domains.notification.service.NotificationService`` (see
    ``app.domains.notification``'s own module docstring for the full
    outbox/dispatch design). A narrow ``Protocol``, not a hard import of
    that concrete class -- the same cross-domain composition pattern every
    other domain's service already uses."""

    async def enqueue(
        self,
        *,
        event_type: NotificationEventType,
        channel: NotificationChannelType,
        recipient: str,
        body: str,
        organization_id: uuid.UUID | None,
        subject: str | None = None,
    ) -> object: ...


class _NoopNotificationSender:
    """Honest fallback when no real ``NotificationSenderProtocol`` is
    wired in -- logs instead of silently discarding the token, mirroring
    ``app.domains.otp.service.LoggingEmailProvider``'s identical "logged,
    not faked, not silently dropped" precedent."""

    async def enqueue(
        self,
        *,
        event_type: NotificationEventType,
        channel: NotificationChannelType,
        recipient: str,
        body: str,
        organization_id: uuid.UUID | None,
        subject: str | None = None,
    ) -> None:
        logger.info(
            "auth_notification_would_send",
            extra={"event_type": event_type.value, "recipient": recipient},
        )


class AuthService:
    """Core authentication business logic."""

    def __init__(
        self,
        repository: AuthRepositoryProtocol,
        redis: Redis | None = None,
        *,
        notification_service: NotificationSenderProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.redis = redis or _default_redis_client
        self.notification_service: NotificationSenderProtocol = (
            notification_service or _NoopNotificationSender()
        )

    # -- registration -----------------------------------------------------

    async def register(
        self,
        *,
        first_name: str,
        last_name: str,
        email: str,
        username: str,
        password: str,
        phone: str | None = None,
        timezone: str = "UTC",
        language: str = "en",
    ) -> tuple[User, str]:
        """Create a new user account. Returns ``(user, verification_token)``."""
        if await self.repository.get_user_by_email(email):
            logger.warning(
                "registration_attempt_existing_email", extra={"email": email}
            )
            raise EmailAlreadyExistsError(email)
        if await self.repository.get_user_by_username(username):
            logger.warning(
                "registration_attempt_existing_username", extra={"username": username}
            )
            raise UsernameAlreadyExistsError(username)

        password_hash = PasswordManager.hash(password)

        user = await self.repository.create_user(
            first_name=first_name,
            last_name=last_name,
            email=email,
            username=username,
            password_hash=password_hash,
            phone=phone,
            timezone=timezone,
            language=language,
            is_active=True,
            is_verified=False,
        )
        await self.repository.add_password_history(user.id, password_hash)

        verification_token = await self._issue_cache_token(
            _VERIFICATION_TOKEN_KEY, user.id, ttl=timedelta(hours=24)
        )
        await self.notification_service.enqueue(
            event_type=NotificationEventType.EMAIL_VERIFICATION,
            channel=NotificationChannelType.EMAIL,
            recipient=user.email,
            subject="Verify your CloudGuest account",
            body=(
                f"Welcome to CloudGuest, {user.first_name}. Use this code to "
                f"verify your account: {verification_token}"
            ),
            organization_id=None,
        )

        logger.info("user_registered", extra={"email": user.email})
        return user, verification_token

    # -- login / tokens -----------------------------------------------------

    async def login(
        self,
        email: str,
        password: str,
        device_info: DeviceInfo,
        *,
        mfa_code: str | None = None,
    ) -> tuple[User, TokenPair, uuid.UUID]:
        """Authenticate a user and start a session.

        Returns ``(user, tokens, session_id)``.

        If the account has MFA enabled (``User.mfa_enabled``) and
        ``mfa_code`` is omitted, raises ``MfaRequiredError`` instead of
        issuing tokens -- the caller retries the same call with
        ``mfa_code`` set (a 6-digit TOTP code, or a recovery code). See
        module docstring's ``PasswordChangeRequiredError`` precedent for
        why this is a single-endpoint retry rather than a separate
        challenge-token flow.
        """
        await AuthSecurity.check_rate_limit(self.redis, email, device_info.ip_address)

        user = await self.repository.get_user_by_email(email)
        if not user:
            await self._record_attempt(
                None, email, device_info, success=False, reason="user_not_found"
            )
            raise InvalidCredentialsError()

        if not user.is_active:
            await self._record_attempt(
                user.id, email, device_info, success=False, reason="account_inactive"
            )
            raise InvalidCredentialsError("Account is inactive")

        AuthSecurity.check_account_lock(user.locked_until)

        if not PasswordManager.verify(password, user.password_hash):
            await self._register_failed_attempt(user)
            await self._record_attempt(
                user.id, email, device_info, success=False, reason="invalid_password"
            )
            raise InvalidCredentialsError()

        if not user.is_verified:
            await self._record_attempt(
                user.id, email, device_info, success=False, reason="email_not_verified"
            )
            raise EmailNotVerifiedError()

        if user.must_change_password:
            await self._record_attempt(
                user.id,
                email,
                device_info,
                success=False,
                reason="password_change_required",
            )
            raise PasswordChangeRequiredError()

        if user.mfa_enabled:
            if not mfa_code:
                await self._record_attempt(
                    user.id,
                    email,
                    device_info,
                    success=False,
                    reason="mfa_code_required",
                )
                raise MfaRequiredError()
            if not await self._verify_mfa_or_recovery_code(user.id, mfa_code):
                await self._record_attempt(
                    user.id,
                    email,
                    device_info,
                    success=False,
                    reason="invalid_mfa_code",
                )
                raise InvalidMfaCodeError()

        await self.repository.update_user(
            user,
            failed_login_attempts=0,
            locked_until=None,
            last_login_at=datetime.now(UTC),
        )

        tokens = JWTManager.create_token_pair(str(user.id), user.email)
        session_row = await self.repository.create_refresh_token(
            user.id,
            tokens["refresh_jti"],
            device_id=device_info.device_id or "unknown",
            device_name=device_info.device_name,
            ip_address=device_info.ip_address,
            user_agent=device_info.user_agent,
            location=device_info.location,
            expires_at=datetime.now(UTC)
            + timedelta(days=get_settings().refresh_token_expire_days),
        )

        await AuthSecurity.record_login_attempt(
            self.redis, email, device_info.ip_address, success=True
        )
        await self._record_attempt(user.id, email, device_info, success=True)

        logger.info("user_logged_in", extra={"email": user.email})
        return user, _token_pair_from_dict(tokens), session_row.id

    async def refresh(self, refresh_token: str) -> TokenPair:
        """Validate a refresh token and issue a new (rotated) token pair."""
        try:
            payload = JWTManager.validate_token(refresh_token, expected_type="refresh")
        except (JWTInvalidTokenError, JWTTokenExpiredError) as exc:
            raise InvalidTokenError(str(exc)) from exc

        jti = payload["jti"]
        session_row = await self.repository.get_session_by_refresh_token(jti)
        if session_row is None or not session_row.is_active or session_row.is_expired():
            logger.warning(
                "invalid_refresh_token_attempt", extra={"user_id": payload.get("sub")}
            )
            raise InvalidTokenError("Refresh token is invalid or has been revoked")

        user = await self.repository.get_user_by_id(uuid.UUID(str(payload["sub"])))
        if not user or not user.is_active:
            raise InvalidCredentialsError("User is not active")

        tokens = JWTManager.create_token_pair(str(user.id), user.email)
        await self.repository.rotate_refresh_token(session_row, tokens["refresh_jti"])

        logger.info("access_token_refreshed", extra={"user_id": str(user.id)})
        return _token_pair_from_dict(tokens)

    async def get_user(self, user_id: str) -> AuthUser | None:
        user = await self.repository.get_user_by_id(uuid.UUID(user_id))
        return AuthUser.from_model(user) if user else None

    async def logout(self, session_id: uuid.UUID) -> None:
        await self.repository.revoke_session(session_id)
        logger.info("user_logged_out", extra={"session_id": str(session_id)})

    async def logout_all(self, user_id: uuid.UUID) -> int:
        revoked = await self.repository.revoke_all_sessions(user_id)
        logger.info(
            "user_logged_out_all_devices",
            extra={"user_id": str(user_id), "revoked": revoked},
        )
        return revoked

    # -- password management -------------------------------------------------

    async def change_password(
        self, user_id: uuid.UUID, current_password: str, new_password: str
    ) -> None:
        user = await self.repository.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        if not PasswordManager.verify(current_password, user.password_hash):
            raise InvalidCredentialsError("Current password is incorrect")
        if PasswordManager.verify(new_password, user.password_hash):
            raise PasswordReuseError(
                "New password must be different from the current password"
            )

        await self._reject_recent_passwords(user_id, new_password)

        new_hash = PasswordManager.hash(new_password)
        await self.repository.update_user(
            user,
            password_hash=new_hash,
            password_changed_at=datetime.now(UTC),
            must_change_password=False,
        )
        await self.repository.add_password_history(user_id, new_hash)
        await self.repository.revoke_all_sessions(user_id)

        logger.info("password_changed", extra={"user_id": str(user_id)})

    async def initiate_password_reset(self, email: str) -> None:
        """Issue a reset token if the email exists. Never reveals whether it does."""
        user = await self.repository.get_user_by_email(email)
        if user:
            reset_token = await self._issue_cache_token(
                _RESET_TOKEN_KEY, user.id, ttl=timedelta(hours=1)
            )
            await self.notification_service.enqueue(
                event_type=NotificationEventType.PASSWORD_RESET,
                channel=NotificationChannelType.EMAIL,
                recipient=user.email,
                subject="Reset your CloudGuest password",
                body=(
                    "Use this code to reset your password: "
                    f"{reset_token} (expires in 1 hour)."
                ),
                organization_id=None,
            )
            logger.info("password_reset_initiated", extra={"user_id": str(user.id)})
        else:
            logger.info(
                "password_reset_requested_unknown_email", extra={"email": email}
            )

    async def reset_password(self, reset_token: str, new_password: str) -> None:
        user_id = await self._consume_cache_token(_RESET_TOKEN_KEY, reset_token)
        if not user_id:
            raise InvalidTokenError("Reset token is invalid or expired")

        user = await self.repository.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        await self._reject_recent_passwords(user_id, new_password)

        new_hash = PasswordManager.hash(new_password)
        await self.repository.update_user(
            user,
            password_hash=new_hash,
            password_changed_at=datetime.now(UTC),
            must_change_password=False,
        )
        await self.repository.add_password_history(user_id, new_hash)
        await self.repository.revoke_all_sessions(user_id)

        logger.info("password_reset_completed", extra={"user_id": str(user_id)})

    # -- email verification -------------------------------------------------

    async def verify_email(self, token: str) -> User:
        user_id = await self._consume_cache_token(_VERIFICATION_TOKEN_KEY, token)
        if not user_id:
            raise InvalidTokenError("Verification token is invalid or expired")

        user = await self.repository.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        await self.repository.update_user(
            user, is_verified=True, email_verified_at=datetime.now(UTC)
        )
        logger.info("email_verified", extra={"user_id": str(user_id)})
        return user

    async def resend_verification(self, email: str) -> None:
        user = await self.repository.get_user_by_email(email)
        if user and not user.is_verified:
            verification_token = await self._issue_cache_token(
                _VERIFICATION_TOKEN_KEY, user.id, ttl=timedelta(hours=24)
            )
            await self.notification_service.enqueue(
                event_type=NotificationEventType.EMAIL_VERIFICATION,
                channel=NotificationChannelType.EMAIL,
                recipient=user.email,
                subject="Verify your CloudGuest account",
                body=(
                    "Use this code to verify your account: "
                    f"{verification_token}"
                ),
                organization_id=None,
            )

    # -- MFA ------------------------------------------------------------------

    async def _verify_mfa_or_recovery_code(self, user_id: uuid.UUID, code: str) -> bool:
        """Tries a real TOTP code first, then falls back to a single-use
        recovery code -- either satisfies ``login``'s own ``mfa_code``
        check."""
        credential = await self.repository.get_mfa_credential(user_id)
        if credential is not None:
            secret = mfa.decrypt_secret(credential.secret_encrypted)
            if mfa.verify_code(secret, code):
                await self.repository.update_mfa_credential(
                    credential, {"last_verified_at": datetime.now(UTC)}
                )
                return True

        recovery_code = await self.repository.get_active_recovery_code(
            user_id, mfa.hash_recovery_code(code)
        )
        if recovery_code is not None:
            await self.repository.mark_recovery_code_used(recovery_code)
            return True

        return False

    async def enroll_mfa(self, user_id: uuid.UUID) -> tuple[str, str]:
        """Starts (or restarts, if not yet verified) MFA enrollment.
        Returns ``(secret, provisioning_uri)`` -- the secret is shown once
        here so a user without an authenticator app handy can type it in
        manually; ``provisioning_uri`` is what a QR code would encode.
        ``User.mfa_enabled`` stays ``False`` until :meth:`verify_and_enable_mfa`
        succeeds."""
        user = await self.repository.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError()
        if user.mfa_enabled:
            raise MfaAlreadyEnabledError()

        secret = mfa.generate_secret()
        encrypted = mfa.encrypt_secret(secret)
        existing = await self.repository.get_mfa_credential(user_id)
        if existing is not None:
            await self.repository.update_mfa_credential(
                existing, {"secret_encrypted": encrypted, "enrolled_at": None}
            )
        else:
            await self.repository.create_mfa_credential(
                user_id=user_id,
                secret_encrypted=encrypted,
                enrolled_at=None,
                last_verified_at=None,
            )
        uri = mfa.get_provisioning_uri(secret, account_name=user.email)
        logger.info("mfa_enrollment_started", extra={"user_id": str(user_id)})
        return secret, uri

    async def verify_and_enable_mfa(self, user_id: uuid.UUID, code: str) -> list[str]:
        """Completes enrollment: verifies ``code`` against the pending
        secret, flips ``User.mfa_enabled``, and returns a fresh set of
        recovery codes (plaintext, shown exactly once)."""
        user = await self.repository.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        credential = await self.repository.get_mfa_credential(user_id)
        if credential is None:
            raise MfaNotEnrolledError()

        secret = mfa.decrypt_secret(credential.secret_encrypted)
        if not mfa.verify_code(secret, code):
            raise InvalidMfaCodeError()

        now = datetime.now(UTC)
        await self.repository.update_mfa_credential(
            credential,
            {"enrolled_at": credential.enrolled_at or now, "last_verified_at": now},
        )
        await self.repository.update_user(user, mfa_enabled=True)

        recovery_codes = mfa.generate_recovery_codes(
            get_settings().mfa_recovery_code_count
        )
        await self.repository.replace_recovery_codes(
            user_id, [mfa.hash_recovery_code(c) for c in recovery_codes]
        )
        logger.info("mfa_enabled", extra={"user_id": str(user_id)})
        return recovery_codes

    async def disable_mfa(
        self, user_id: uuid.UUID, *, password: str, code: str
    ) -> None:
        """Disables MFA -- requires both the current password (proves this
        is the account owner, not a hijacked session) and a valid MFA/
        recovery code (proves the second factor itself, not just the
        first, is under the caller's control)."""
        user = await self.repository.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError()
        if not user.mfa_enabled:
            raise MfaNotEnabledError()
        if not PasswordManager.verify(password, user.password_hash):
            raise InvalidCredentialsError()
        if not await self._verify_mfa_or_recovery_code(user_id, code):
            raise InvalidMfaCodeError()

        credential = await self.repository.get_mfa_credential(user_id)
        await self.repository.update_user(user, mfa_enabled=False)
        if credential is not None:
            await self.repository.delete_mfa_credential(credential)
        await self.repository.replace_recovery_codes(user_id, [])
        logger.info("mfa_disabled", extra={"user_id": str(user_id)})

    async def regenerate_recovery_codes(
        self, user_id: uuid.UUID, *, code: str
    ) -> list[str]:
        """Invalidates every existing recovery code and issues a fresh
        set -- requires a valid MFA/recovery code first."""
        user = await self.repository.get_user_by_id(user_id)
        if not user or not user.mfa_enabled:
            raise MfaNotEnabledError()
        if not await self._verify_mfa_or_recovery_code(user_id, code):
            raise InvalidMfaCodeError()

        recovery_codes = mfa.generate_recovery_codes(
            get_settings().mfa_recovery_code_count
        )
        await self.repository.replace_recovery_codes(
            user_id, [mfa.hash_recovery_code(c) for c in recovery_codes]
        )
        logger.info("mfa_recovery_codes_regenerated", extra={"user_id": str(user_id)})
        return recovery_codes

    # -- sessions -------------------------------------------------------------

    async def list_sessions(self, user_id: uuid.UUID):
        return await self.repository.get_active_sessions(user_id)

    async def revoke_session(self, session_id: uuid.UUID) -> None:
        await self.repository.revoke_session(session_id)

    # -- login attempts (real history read, for app.domains.controller_logs) ---

    async def list_login_attempts(
        self,
        *,
        email: str | None = None,
        success: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        return await self.repository.list_login_attempts(
            email=email, success=success, page=page, page_size=page_size
        )

    # -- internal helpers -------------------------------------------------------

    async def _register_failed_attempt(self, user: User) -> None:
        settings = get_settings()
        failed = user.failed_login_attempts + 1
        locked_until = user.locked_until
        if failed >= settings.max_login_attempts:
            locked_until = datetime.now(UTC) + timedelta(
                minutes=settings.account_lockout_minutes
            )
            logger.warning("account_locked", extra={"user_id": str(user.id)})
        await self.repository.update_user(
            user, failed_login_attempts=failed, locked_until=locked_until
        )

    async def _record_attempt(
        self,
        user_id: uuid.UUID | None,
        email: str,
        device_info: DeviceInfo,
        *,
        success: bool,
        reason: str | None = None,
    ) -> None:
        await self.repository.record_login_attempt(
            user_id=user_id,
            email=email,
            ip_address=device_info.ip_address,
            user_agent=device_info.user_agent,
            success=success,
            failure_reason=reason,
        )
        if not success:
            await AuthSecurity.record_login_attempt(
                self.redis, email, device_info.ip_address, success=False
            )

    async def _reject_recent_passwords(
        self, user_id: uuid.UUID, new_password: str
    ) -> None:
        settings = get_settings()
        if settings.password_history_limit <= 0:
            return
        recent_hashes = await self.repository.get_recent_password_hashes(
            user_id, settings.password_history_limit
        )
        for old_hash in recent_hashes:
            if PasswordManager.verify(new_password, old_hash):
                raise PasswordReuseError(
                    "This password was used recently. Please choose a different one."
                )

    async def _issue_cache_token(
        self, key_template: str, user_id: uuid.UUID, *, ttl: timedelta
    ) -> str:
        token = str(uuid4())
        await self.redis.set(
            key_template.format(token=token), str(user_id), ex=int(ttl.total_seconds())
        )
        return token

    async def _consume_cache_token(
        self, key_template: str, token: str
    ) -> uuid.UUID | None:
        key = key_template.format(token=token)
        raw_user_id = await self.redis.get(key)
        if not raw_user_id:
            return None
        await self.redis.delete(key)
        return uuid.UUID(raw_user_id)


def _token_pair_from_dict(tokens: dict) -> TokenPair:
    return TokenPair(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_type=tokens.get("token_type", "bearer"),
        expires_in=tokens["expires_in"],
        refresh_expires_in=tokens["refresh_expires_in"],
    )
