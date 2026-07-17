"""
Unit and integration tests for authentication module.

Tests cover:
- Password hashing and verification
- JWT token generation and validation
- Login and registration flows
- Password reset and email verification
- Session management
- Rate limiting and account lockout

Architecture: Testing Layer
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def password_hasher():
    """Create password hasher instance."""
    from password_hasher import SecurePasswordHasher

    return SecurePasswordHasher()


@pytest.fixture
def jwt_handler():
    """Create JWT handler instance."""
    from jwt_handler import JWTHandler

    return JWTHandler(secret_key="test_secret_key_at_least_32_characters_long_for_hs256")


@pytest.fixture
def mock_redis():
    """Create mock Redis client."""
    return MagicMock()


@pytest.fixture
def mock_repositories():
    """Create mock repositories."""
    return {
        "user_repo": AsyncMock(),
        "session_repo": AsyncMock(),
        "password_history_repo": AsyncMock(),
        "login_attempt_repo": AsyncMock(),
    }


@pytest.fixture
def auth_service(
    mock_repositories, password_hasher, jwt_handler, mock_redis
):
    """Create auth service instance."""
    from auth_service import AuthService
    from security_service import SecurityService

    security_service = SecurityService(mock_redis)
    cache_service = AsyncMock()

    return AuthService(
        user_repository=mock_repositories["user_repo"],
        session_repository=mock_repositories["session_repo"],
        password_history_repository=mock_repositories["password_history_repo"],
        password_hasher=password_hasher,
        jwt_handler=jwt_handler,
        security_service=security_service,
        cache_service=cache_service,
    )


# ============================================================================
# PASSWORD HASHING TESTS
# ============================================================================


class TestPasswordHasher:
    """Test password hashing and verification."""

    def test_hash_password_success(self, password_hasher):
        """Test successful password hashing."""
        password = "SecurePass123!@#"
        hash_value = password_hasher.hash_password(password)

        assert hash_value is not None
        assert len(hash_value) > 0
        assert hash_value != password

    def test_hash_password_weak_password(self, password_hasher):
        """Test rejection of weak passwords."""
        from password_hasher import PasswordStrengthError

        weak_passwords = [
            "short",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoDigits!",  # No digits
            "NoSpecial123",  # No special chars
            "password",  # Common password
        ]

        for password in weak_passwords:
            with pytest.raises(PasswordStrengthError):
                password_hasher.hash_password(password)

    def test_verify_password_success(self, password_hasher):
        """Test successful password verification."""
        password = "SecurePass123!@#"
        hash_value = password_hasher.hash_password(password)

        assert password_hasher.verify_password(password, hash_value) is True

    def test_verify_password_failure(self, password_hasher):
        """Test failed password verification."""
        password = "SecurePass123!@#"
        hash_value = password_hasher.hash_password(password)
        wrong_password = "WrongPass123!@#"

        assert password_hasher.verify_password(wrong_password, hash_value) is False

    def test_password_strength_score(self, password_hasher):
        """Test password strength scoring."""
        weak = "Pass123!"  # 8 chars
        medium = "SecurePass123!"  # 13 chars
        strong = "VerySecurePassword123!@#$%"  # 26 chars

        weak_score = password_hasher.get_password_strength_score(weak)
        medium_score = password_hasher.get_password_strength_score(medium)
        strong_score = password_hasher.get_password_strength_score(strong)

        assert weak_score < medium_score < strong_score


# ============================================================================
# JWT TOKEN TESTS
# ============================================================================


class TestJWTHandler:
    """Test JWT token operations."""

    def test_create_access_token(self, jwt_handler):
        """Test access token creation."""
        user_id = str(uuid4())
        email = "test@example.com"

        token, jti = jwt_handler.create_access_token(user_id, email)

        assert token is not None
        assert jti is not None
        assert len(token) > 0

    def test_create_refresh_token(self, jwt_handler):
        """Test refresh token creation."""
        user_id = str(uuid4())
        email = "test@example.com"

        token, jti = jwt_handler.create_refresh_token(user_id, email)

        assert token is not None
        assert jti is not None

    def test_create_token_pair(self, jwt_handler):
        """Test token pair creation."""
        user_id = str(uuid4())
        email = "test@example.com"

        tokens = jwt_handler.create_token_pair(user_id, email)

        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert "token_type" in tokens
        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] == 15 * 60  # 15 minutes

    def test_decode_token_success(self, jwt_handler):
        """Test successful token decoding."""
        user_id = str(uuid4())
        email = "test@example.com"

        token, jti = jwt_handler.create_access_token(user_id, email)
        payload = jwt_handler.decode_token(token)

        assert payload["sub"] == user_id
        assert payload["email"] == email
        assert payload["jti"] == jti
        assert payload["type"] == "access"

    def test_decode_token_expired(self, jwt_handler):
        """Test decoding expired token."""
        from jwt_handler import TokenExpiredError
        import jwt as pyjwt

        # Create expired token
        payload = {
            "sub": str(uuid4()),
            "email": "test@example.com",
            "jti": str(uuid4()),
            "type": "access",
            "iat": int((datetime.utcnow() - timedelta(hours=1)).timestamp()),
            "exp": int((datetime.utcnow() - timedelta(minutes=1)).timestamp()),
        }

        token = pyjwt.encode(
            payload, jwt_handler.secret_key, algorithm=jwt_handler.algorithm
        )

        with pytest.raises(TokenExpiredError):
            jwt_handler.decode_token(token)

    def test_validate_token_type_mismatch(self, jwt_handler):
        """Test token type validation."""
        from jwt_handler import InvalidTokenError

        user_id = str(uuid4())
        email = "test@example.com"

        token, _ = jwt_handler.create_access_token(user_id, email)

        with pytest.raises(InvalidTokenError):
            jwt_handler.validate_token(token, expected_type="refresh")

    def test_check_token_expiry(self, jwt_handler):
        """Test token expiry check."""
        user_id = str(uuid4())
        email = "test@example.com"

        token, _ = jwt_handler.create_access_token(user_id, email)

        assert jwt_handler.is_token_expired(token) is False

    def test_get_expiry_time(self, jwt_handler):
        """Test getting token expiry time."""
        user_id = str(uuid4())
        email = "test@example.com"

        token, _ = jwt_handler.create_access_token(user_id, email)
        expiry = jwt_handler.get_expiry_time(token)

        assert expiry is not None
        assert expiry > datetime.utcnow()


# ============================================================================
# SECURITY SERVICE TESTS
# ============================================================================


class TestSecurityService:
    """Test security features."""

    def test_generate_device_id(self, mock_redis):
        """Test device ID generation."""
        from security_service import SecurityService

        service = SecurityService(mock_redis)
        ip = "192.168.1.1"
        user_agent = "Mozilla/5.0..."

        device_id_1 = service.generate_device_id(ip, user_agent)
        device_id_2 = service.generate_device_id(ip, user_agent)

        # Same inputs should produce same device ID
        assert device_id_1 == device_id_2

        # Different inputs should produce different device ID
        device_id_3 = service.generate_device_id("192.168.1.2", user_agent)
        assert device_id_1 != device_id_3

    def test_record_login_attempt_success(self, mock_redis):
        """Test recording successful login attempt."""
        from security_service import SecurityService

        mock_redis.delete = MagicMock()
        service = SecurityService(mock_redis)

        service.record_login_attempt(
            "user@example.com", "192.168.1.1", success=True
        )

        # Should delete failed attempts on success
        mock_redis.delete.assert_called()

    def test_record_login_attempt_failure(self, mock_redis):
        """Test recording failed login attempt."""
        from security_service import SecurityService

        mock_redis.incr = MagicMock(return_value=1)
        mock_redis.expire = MagicMock()

        service = SecurityService(mock_redis)

        service.record_login_attempt(
            "user@example.com", "192.168.1.1", success=False
        )

        # Should increment failed attempts
        mock_redis.incr.assert_called()
        mock_redis.expire.assert_called()

    def test_rate_limit_check(self, mock_redis):
        """Test rate limit checking."""
        from security_service import SecurityService, RateLimitError

        service = SecurityService(mock_redis)
        mock_redis.get = MagicMock(return_value=None)

        # Should not raise when attempts < limit
        result = service.check_rate_limit("user@example.com", "192.168.1.1")
        assert result is False

    def test_account_lock_check(self, mock_redis):
        """Test account lock checking."""
        from security_service import SecurityService, AccountLockedError

        service = SecurityService(mock_redis)
        locked_until = datetime.utcnow() + timedelta(minutes=30)

        with pytest.raises(AccountLockedError):
            service.check_account_lock(locked_until)


# ============================================================================
# AUTH SERVICE TESTS
# ============================================================================


class TestAuthServiceRegister:
    """Test user registration."""

    @pytest.mark.asyncio
    async def test_register_success(self, auth_service, mock_repositories):
        """Test successful registration."""
        db = AsyncMock()
        mock_repositories["user_repo"].get_by_email.return_value = None
        mock_repositories["user_repo"].get_by_username.return_value = None
        mock_repositories["user_repo"].create.return_value = MagicMock(
            id=str(uuid4()), email="test@example.com", is_verified=False
        )

        auth_service.cache_service.set_verification_token = AsyncMock(
            return_value="token"
        )

        result = await auth_service.register(
            db,
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password="SecurePass123!@#",
        )

        assert result["email"] == "test@example.com"
        assert result["is_verified"] is False
        assert "verification_token" in result

    @pytest.mark.asyncio
    async def test_register_email_exists(self, auth_service, mock_repositories):
        """Test registration with existing email."""
        from auth_service import EmailAlreadyExistsError

        db = AsyncMock()
        mock_repositories["user_repo"].get_by_email.return_value = MagicMock()

        with pytest.raises(EmailAlreadyExistsError):
            await auth_service.register(
                db,
                first_name="Test",
                last_name="User",
                email="existing@example.com",
                username="testuser",
                password="SecurePass123!@#",
            )

    @pytest.mark.asyncio
    async def test_register_username_exists(self, auth_service, mock_repositories):
        """Test registration with existing username."""
        from auth_service import UsernameAlreadyExistsError

        db = AsyncMock()
        mock_repositories["user_repo"].get_by_email.return_value = None
        mock_repositories["user_repo"].get_by_username.return_value = MagicMock()

        with pytest.raises(UsernameAlreadyExistsError):
            await auth_service.register(
                db,
                first_name="Test",
                last_name="User",
                email="new@example.com",
                username="existinguser",
                password="SecurePass123!@#",
            )


class TestAuthServiceLogin:
    """Test user login."""

    @pytest.mark.asyncio
    async def test_login_success(self, auth_service, mock_repositories):
        """Test successful login."""
        db = AsyncMock()
        user_id = str(uuid4())
        user = MagicMock(
            id=user_id,
            email="test@example.com",
            password_hash=auth_service.password_hasher.hash_password(
                "SecurePass123!@#"
            ),
            is_active=True,
            is_verified=True,
            locked_until=None,
            failed_login_attempts=0,
        )

        mock_repositories["user_repo"].get_by_email.return_value = user
        mock_repositories["session_repo"].create.return_value = MagicMock(
            id=str(uuid4())
        )
        auth_service.cache_service.set_refresh_token = AsyncMock()

        device_info = MagicMock(
            device_id="device123",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            device_name="Chrome",
            location="Delhi",
        )

        result = await auth_service.login(
            db, "test@example.com", "SecurePass123!@#", device_info
        )

        assert result["user_id"] == user_id
        assert result["email"] == "test@example.com"
        assert "tokens" in result
        assert "session_id" in result

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, auth_service, mock_repositories):
        """Test login with invalid credentials."""
        from auth_service import InvalidCredentialsError

        db = AsyncMock()
        mock_repositories["user_repo"].get_by_email.return_value = None

        device_info = MagicMock(
            ip_address="192.168.1.1", user_agent="Mozilla/5.0"
        )

        with pytest.raises(InvalidCredentialsError):
            await auth_service.login(
                db, "nonexistent@example.com", "AnyPassword123!@#", device_info
            )

    @pytest.mark.asyncio
    async def test_login_email_not_verified(self, auth_service, mock_repositories):
        """Test login with unverified email."""
        from auth_service import EmailNotVerifiedError

        db = AsyncMock()
        user = MagicMock(
            id=str(uuid4()),
            email="test@example.com",
            password_hash=auth_service.password_hasher.hash_password(
                "SecurePass123!@#"
            ),
            is_active=True,
            is_verified=False,  # Not verified
            locked_until=None,
        )

        mock_repositories["user_repo"].get_by_email.return_value = user

        device_info = MagicMock(
            ip_address="192.168.1.1", user_agent="Mozilla/5.0"
        )

        with pytest.raises(EmailNotVerifiedError):
            await auth_service.login(
                db, "test@example.com", "SecurePass123!@#", device_info
            )


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_complete_auth_flow(auth_service, mock_repositories):
    """Test complete authentication flow: register -> login -> refresh."""
    db = AsyncMock()

    # 1. Register
    mock_repositories["user_repo"].get_by_email.return_value = None
    mock_repositories["user_repo"].get_by_username.return_value = None
    user_id = str(uuid4())
    user = MagicMock(
        id=user_id,
        email="flow@example.com",
        username="flowuser",
        is_verified=False,
    )
    mock_repositories["user_repo"].create.return_value = user

    auth_service.cache_service.set_verification_token = AsyncMock()

    register_result = await auth_service.register(
        db,
        first_name="Flow",
        last_name="Test",
        email="flow@example.com",
        username="flowuser",
        password="SecurePass123!@#",
    )

    assert register_result["email"] == "flow@example.com"

    # 2. Verify email
    auth_service.cache_service.get_verification_token = AsyncMock(
        return_value=user_id
    )
    mock_repositories["user_repo"].get_by_id.return_value = user
    user.is_verified = True

    verify_result = await auth_service.verify_email(db, "verification_token")
    assert verify_result["email"] == "flow@example.com"

    # 3. Login
    user.is_active = True
    user.is_verified = True
    user.locked_until = None
    user.failed_login_attempts = 0
    password_hash = auth_service.password_hasher.hash_password("SecurePass123!@#")
    user.password_hash = password_hash

    mock_repositories["user_repo"].get_by_email.return_value = user
    mock_repositories["session_repo"].create.return_value = MagicMock(
        id=str(uuid4())
    )
    auth_service.cache_service.set_refresh_token = AsyncMock()

    device_info = MagicMock(
        device_id="device123",
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0",
        device_name="Chrome",
        location="Delhi",
    )

    login_result = await auth_service.login(
        db, "flow@example.com", "SecurePass123!@#", device_info
    )

    assert login_result["user_id"] == user_id
    assert "tokens" in login_result

    # 4. Refresh token
    auth_service.cache_service.validate_refresh_token = AsyncMock(return_value=True)
    auth_service.cache_service.revoke_refresh_token = AsyncMock()
    auth_service.cache_service.set_refresh_token = AsyncMock()

    refresh_token = login_result["tokens"]["refresh_token"]

    mock_repositories["user_repo"].get_by_id.return_value = user
    mock_repositories["session_repo"].get_by_refresh_token_jti.return_value = (
        MagicMock()
    )

    refresh_result = await auth_service.refresh_access_token(db, refresh_token)

    assert "access_token" in refresh_result
    assert "refresh_token" in refresh_result


# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================


def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )


pytest_plugins = ("pytest_asyncio",)
