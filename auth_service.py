"""
Authentication service implementing core business logic.

Handles login, registration, password reset, email verification, and token management.

Architecture: Application Layer - Service
"""

import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class AuthServiceError(Exception):
    """Base exception for auth service errors."""

    pass


class UserNotFoundError(AuthServiceError):
    """User not found error."""

    pass


class InvalidCredentialsError(AuthServiceError):
    """Invalid credentials error."""

    pass


class EmailAlreadyExistsError(AuthServiceError):
    """Email already registered error."""

    pass


class UsernameAlreadyExistsError(AuthServiceError):
    """Username already taken error."""

    pass


class EmailNotVerifiedError(AuthServiceError):
    """Email not verified error."""

    pass


class PasswordNotMatchError(AuthServiceError):
    """Passwords don't match error."""

    pass


class AuthService:
    """
    Core authentication business logic service.

    Manages:
    - User registration and login
    - Token generation and refresh
    - Password management
    - Email verification
    - Session management
    """

    def __init__(
        self,
        user_repository,
        session_repository,
        password_history_repository,
        password_hasher,
        jwt_handler,
        security_service,
        cache_service,
    ) -> None:
        """
        Initialize auth service with dependencies.

        Args:
            user_repository: User data access layer
            session_repository: Session data access layer
            password_history_repository: Password history repository
            password_hasher: Password hashing service
            jwt_handler: JWT token handler
            security_service: Security service (rate limit, account lock)
            cache_service: Cache service for tokens and verification codes
        """
        self.user_repo = user_repository
        self.session_repo = session_repository
        self.password_history_repo = password_history_repository
        self.password_hasher = password_hasher
        self.jwt_handler = jwt_handler
        self.security_service = security_service
        self.cache_service = cache_service

    async def register(
        self,
        db: AsyncSession,
        first_name: str,
        last_name: str,
        email: str,
        username: str,
        password: str,
        phone: Optional[str] = None,
        timezone: str = "UTC",
        language: str = "en",
    ) -> dict:
        """
        Register a new user.

        Args:
            db: Database session
            first_name: User's first name
            last_name: User's last name
            email: User's email
            username: User's username
            password: User's password (plain text)
            phone: Optional phone number
            timezone: User's timezone
            language: Preferred language

        Returns:
            Dictionary with user info and email verification status

        Raises:
            EmailAlreadyExistsError: If email already registered
            UsernameAlreadyExistsError: If username already taken
        """
        # Check if email already exists
        existing_user = await self.user_repo.get_by_email(db, email)
        if existing_user:
            logger.warning(f"Registration attempt with existing email: {email}")
            raise EmailAlreadyExistsError(f"Email {email} is already registered")

        # Check if username already exists
        existing_user = await self.user_repo.get_by_username(db, username)
        if existing_user:
            logger.warning(f"Registration attempt with existing username: {username}")
            raise UsernameAlreadyExistsError(f"Username {username} is already taken")

        # Hash password
        password_hash = self.password_hasher.hash_password(password)

        # Create user
        user = await self.user_repo.create(
            db,
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

        # Store password in history
        await self.password_history_repo.create(
            db, user_id=user.id, password_hash=password_hash
        )

        # Generate email verification token
        verification_token = await self._generate_verification_token(user.id)

        logger.info(f"User registered successfully: {email}")

        return {
            "user_id": user.id,
            "email": user.email,
            "username": user.username,
            "is_verified": user.is_verified,
            "verification_token": verification_token,
        }

    async def login(
        self,
        db: AsyncSession,
        email: str,
        password: str,
        device_info,  # DeviceInfo object
    ) -> dict:
        """
        Authenticate user and create session.

        Args:
            db: Database session
            email: User email
            password: User password (plain text)
            device_info: Device information object

        Returns:
            Dictionary with user info, tokens, and session ID

        Raises:
            InvalidCredentialsError: If email/password invalid
            EmailNotVerifiedError: If email not verified
            AccountLockedError: If account is locked
        """
        # Check rate limiting
        self.security_service.check_rate_limit(email, device_info.ip_address)

        # Get user by email
        user = await self.user_repo.get_by_email(db, email)
        if not user:
            logger.warning(f"Login attempt with non-existent email: {email}")
            self.security_service.record_login_attempt(
                email, device_info.ip_address, success=False, failure_reason="user_not_found"
            )
            raise InvalidCredentialsError("Invalid email or password")

        # Check if account is active
        if not user.is_active:
            logger.warning(f"Login attempt on inactive account: {email}")
            self.security_service.record_login_attempt(
                email, device_info.ip_address, success=False, failure_reason="account_inactive"
            )
            raise InvalidCredentialsError("Account is inactive")

        # Check if account is locked
        self.security_service.check_account_lock(user.locked_until)

        # Verify password
        if not self.password_hasher.verify_password(password, user.password_hash):
            logger.warning(f"Failed login attempt: {email} from {device_info.ip_address}")

            # Update failed login attempts
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                logger.warning(
                    f"Account locked after 5 failed attempts: {email}"
                )

            await self.user_repo.update(db, user)
            self.security_service.record_login_attempt(
                email, device_info.ip_address, success=False, failure_reason="invalid_password"
            )
            raise InvalidCredentialsError("Invalid email or password")

        # Check if email is verified
        if not user.is_verified:
            logger.info(f"Login attempt with unverified email: {email}")
            self.security_service.record_login_attempt(
                email, device_info.ip_address, success=False, failure_reason="email_not_verified"
            )
            raise EmailNotVerifiedError(
                "Email not verified. Please check your email for verification link."
            )

        # Reset failed attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = datetime.utcnow()
        await self.user_repo.update(db, user)

        # Generate tokens
        token_pair = self.jwt_handler.create_token_pair(user.id, user.email)

        # Create session
        session = await self.session_repo.create(
            db,
            user_id=user.id,
            device_id=device_info.device_id,
            device_name=device_info.device_name,
            ip_address=device_info.ip_address,
            user_agent=device_info.user_agent,
            location=device_info.location,
            refresh_token_jti=token_pair["refresh_jti"],
            expires_at=datetime.utcnow() + timedelta(days=7),
        )

        # Cache refresh token
        await self.cache_service.set_refresh_token(
            token_pair["refresh_jti"], user.id, expiry_days=7
        )

        logger.info(f"User logged in successfully: {email}")
        self.security_service.record_login_attempt(
            email, device_info.ip_address, success=True
        )

        return {
            "user_id": user.id,
            "email": user.email,
            "username": user.username,
            "is_verified": user.is_verified,
            "tokens": token_pair,
            "session_id": session.id,
        }

    async def refresh_access_token(
        self, db: AsyncSession, refresh_token: str
    ) -> dict:
        """
        Refresh access token using refresh token.

        Args:
            db: Database session
            refresh_token: Refresh token (JWT)

        Returns:
            Dictionary with new access token and refresh token

        Raises:
            InvalidTokenError: If refresh token is invalid
        """
        # Validate refresh token
        payload = self.jwt_handler.validate_token(refresh_token, expected_type="refresh")

        user_id = payload["sub"]
        jti = payload["jti"]

        # Check if token is blacklisted
        is_valid = await self.cache_service.validate_refresh_token(jti, user_id)
        if not is_valid:
            logger.warning(f"Invalid refresh token attempt for user: {user_id}")
            raise InvalidCredentialsError("Refresh token is invalid or expired")

        # Get user
        user = await self.user_repo.get_by_id(db, user_id)
        if not user or not user.is_active:
            logger.warning(f"Refresh token used by inactive/deleted user: {user_id}")
            raise InvalidCredentialsError("User is not active")

        # Generate new token pair (rotate refresh token)
        new_token_pair = self.jwt_handler.create_token_pair(user.id, user.email)

        # Revoke old refresh token
        await self.cache_service.revoke_refresh_token(jti)

        # Cache new refresh token
        await self.cache_service.set_refresh_token(
            new_token_pair["refresh_jti"], user.id, expiry_days=7
        )

        # Update session
        session = await self.session_repo.get_by_refresh_token_jti(db, jti)
        if session:
            session.refresh_token_jti = new_token_pair["refresh_jti"]
            session.mark_activity()
            await self.session_repo.update(db, session)

        logger.info(f"Access token refreshed for user: {user_id}")

        return {
            "access_token": new_token_pair["access_token"],
            "refresh_token": new_token_pair["refresh_token"],
            "token_type": "Bearer",
            "expires_in": new_token_pair["expires_in"],
            "refresh_expires_in": new_token_pair["refresh_expires_in"],
        }

    async def change_password(
        self,
        db: AsyncSession,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> dict:
        """
        Change user password.

        Args:
            db: Database session
            user_id: User ID
            current_password: Current password (plain text)
            new_password: New password (plain text)

        Returns:
            Success message

        Raises:
            UserNotFoundError: If user not found
            InvalidCredentialsError: If current password is wrong
            PasswordNotMatchError: If new password matches old
        """
        # Get user
        user = await self.user_repo.get_by_id(db, user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")

        # Verify current password
        if not self.password_hasher.verify_password(current_password, user.password_hash):
            logger.warning(f"Failed password change attempt: wrong current password")
            raise InvalidCredentialsError("Current password is incorrect")

        # Check if new password is same as current
        if self.password_hasher.verify_password(new_password, user.password_hash):
            raise PasswordNotMatchError("New password must be different from current password")

        # Check password history (prevent reuse of last 5 passwords)
        recent_history = await self.password_history_repo.get_recent(db, user_id, limit=5)
        for history in recent_history:
            if self.password_hasher.verify_password(new_password, history.password_hash):
                raise PasswordNotMatchError(
                    "Password was used recently. Please choose a different password."
                )

        # Hash new password
        new_hash = self.password_hasher.hash_password(new_password)

        # Update user
        user.password_hash = new_hash
        user.password_changed_at = datetime.utcnow()
        await self.user_repo.update(db, user)

        # Store in password history
        await self.password_history_repo.create(
            db, user_id=user_id, password_hash=new_hash
        )

        # Revoke all sessions (force re-login)
        await self.session_repo.revoke_all(db, user_id)

        logger.info(f"Password changed successfully for user: {user_id}")

        return {"message": "Password changed successfully. Please login again."}

    async def verify_email(self, db: AsyncSession, email_token: str) -> dict:
        """
        Verify user email using verification token.

        Args:
            db: Database session
            email_token: Email verification token

        Returns:
            Success message with user info

        Raises:
            InvalidTokenError: If token invalid/expired
        """
        # Get user from cache
        user_id = await self.cache_service.get_verification_token(email_token)
        if not user_id:
            logger.warning(f"Email verification with invalid/expired token")
            raise InvalidCredentialsError("Verification token is invalid or expired")

        # Get user
        user = await self.user_repo.get_by_id(db, user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")

        # Update user
        user.is_verified = True
        user.email_verified_at = datetime.utcnow()
        await self.user_repo.update(db, user)

        # Delete verification token from cache
        await self.cache_service.delete_verification_token(email_token)

        logger.info(f"Email verified successfully for user: {user_id}")

        return {
            "message": "Email verified successfully",
            "user_id": user_id,
            "email": user.email,
        }

    async def initiate_password_reset(self, db: AsyncSession, email: str) -> dict:
        """
        Initiate password reset by sending email with reset token.

        Args:
            db: Database session
            email: User email

        Returns:
            Success message (never reveals if email exists for security)
        """
        # Get user (don't reveal if exists)
        user = await self.user_repo.get_by_email(db, email)

        if user:
            # Generate reset token
            reset_token = await self._generate_reset_token(user.id)
            logger.info(f"Password reset initiated for user: {user.id}")
        else:
            logger.info(f"Password reset requested for non-existent email: {email}")

        # Always return success (security best practice)
        return {
            "message": "If an account exists with that email, a password reset link has been sent."
        }

    async def reset_password(
        self, db: AsyncSession, reset_token: str, new_password: str
    ) -> dict:
        """
        Reset password using reset token.

        Args:
            db: Database session
            reset_token: Password reset token
            new_password: New password

        Returns:
            Success message

        Raises:
            InvalidTokenError: If token invalid/expired
        """
        # Get user from cache
        user_id = await self.cache_service.get_reset_token(reset_token)
        if not user_id:
            logger.warning(f"Password reset with invalid/expired token")
            raise InvalidCredentialsError("Reset token is invalid or expired")

        # Get user
        user = await self.user_repo.get_by_id(db, user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")

        # Hash new password
        new_hash = self.password_hasher.hash_password(new_password)

        # Update user
        user.password_hash = new_hash
        user.password_changed_at = datetime.utcnow()
        await self.user_repo.update(db, user)

        # Store in password history
        await self.password_history_repo.create(
            db, user_id=user_id, password_hash=new_hash
        )

        # Revoke all sessions
        await self.session_repo.revoke_all(db, user_id)

        # Delete reset token
        await self.cache_service.delete_reset_token(reset_token)

        logger.info(f"Password reset successfully for user: {user_id}")

        return {"message": "Password reset successfully. Please login with new password."}

    async def logout(self, db: AsyncSession, session_id: str, refresh_jti: str) -> dict:
        """
        Logout user by revoking session.

        Args:
            db: Database session
            session_id: Session ID to revoke
            refresh_jti: Refresh token JTI to revoke

        Returns:
            Success message
        """
        # Get and revoke session
        session = await self.session_repo.get_by_id(db, session_id)
        if session:
            session.is_active = False
            await self.session_repo.update(db, session)

        # Revoke refresh token
        await self.cache_service.revoke_refresh_token(refresh_jti)

        logger.info(f"User logged out successfully: session={session_id}")

        return {"message": "Logged out successfully"}

    async def _generate_verification_token(self, user_id: str) -> str:
        """Generate and store email verification token."""
        token = str(uuid4())
        await self.cache_service.set_verification_token(token, user_id, expiry_hours=24)
        return token

    async def _generate_reset_token(self, user_id: str) -> str:
        """Generate and store password reset token."""
        token = str(uuid4())
        await self.cache_service.set_reset_token(token, user_id, expiry_hours=1)
        return token
