"""
Security service for rate limiting, account lockout, and device tracking.

Implements brute force protection and suspicious activity detection.

Architecture: Application Layer - Service
"""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional
from user_agent import parse

logger = logging.getLogger(__name__)


class SecurityConfig:
    """Configuration for security features."""

    # Rate limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30
    RATE_LIMIT_WINDOW_MINUTES = 15

    # Device tracking
    DEVICE_COOKIE_DURATION_DAYS = 30


class SecurityError(Exception):
    """Base exception for security errors."""

    pass


class AccountLockedError(SecurityError):
    """Exception raised when account is locked."""

    def __init__(self, locked_until: datetime, message: str = "Account is locked"):
        self.locked_until = locked_until
        self.message = message
        super().__init__(message)


class RateLimitError(SecurityError):
    """Exception raised when rate limit is exceeded."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Rate limit exceeded. Try again in {retry_after_seconds}s")


class DeviceInfo:
    """Information about user's device."""

    def __init__(
        self,
        device_id: str,
        ip_address: str,
        user_agent: str,
        device_name: Optional[str] = None,
        location: Optional[str] = None,
    ) -> None:
        self.device_id = device_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.device_name = device_name
        self.location = location

        # Parse user agent for device info
        self._parse_user_agent()

    def _parse_user_agent(self) -> None:
        """Parse user agent to extract device details."""
        try:
            ua = parse(self.user_agent)
            self.browser = f"{ua.browser.family} {ua.browser.version_string}"
            self.os = f"{ua.os.family} {ua.os.version_string}"
            self.device_type = (
                "mobile"
                if ua.is_mobile
                else "tablet"
                if ua.is_tablet
                else "desktop"
            )
        except Exception as e:
            logger.warning(f"Failed to parse user agent: {e}")
            self.browser = "Unknown"
            self.os = "Unknown"
            self.device_type = "unknown"

    def to_dict(self) -> dict:
        """Convert device info to dictionary."""
        return {
            "device_id": self.device_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "device_name": self.device_name,
            "location": self.location,
            "browser": self.browser,
            "os": self.os,
            "device_type": self.device_type,
        }


class SecurityService:
    """
    Service for managing security features.

    Features:
        - Account lockout after failed login attempts
        - Rate limiting on login endpoint
        - Device tracking and fingerprinting
        - Failed login attempt logging
    """

    def __init__(
        self,
        redis_client,  # Redis client instance
        config: Optional[SecurityConfig] = None,
    ) -> None:
        """
        Initialize security service.

        Args:
            redis_client: Redis client for caching
            config: Security configuration
        """
        self.redis = redis_client
        self.config = config or SecurityConfig()

    def generate_device_id(
        self, ip_address: str, user_agent: str, fingerprint_seed: Optional[str] = None
    ) -> str:
        """
        Generate a unique device ID from IP and user agent.

        Args:
            ip_address: Client IP address
            user_agent: Client user agent string
            fingerprint_seed: Additional seed data for fingerprinting

        Returns:
            Generated device ID
        """
        components = [ip_address, user_agent]
        if fingerprint_seed:
            components.append(fingerprint_seed)

        fingerprint = "|".join(components)
        device_id = hashlib.sha256(fingerprint.encode()).hexdigest()[:16]

        return device_id

    def record_login_attempt(
        self,
        email: str,
        ip_address: str,
        success: bool,
        failure_reason: Optional[str] = None,
    ) -> None:
        """
        Record a login attempt for rate limiting and auditing.

        Args:
            email: Email of login attempt
            ip_address: Source IP address
            success: Whether login was successful
            failure_reason: Reason for failure if unsuccessful
        """
        key = f"login_attempt:{email}:{ip_address}"

        try:
            if success:
                # Clear failed attempts on successful login
                self.redis.delete(key)
            else:
                # Increment failed attempts
                current = self.redis.incr(key)
                self.redis.expire(key, self.config.RATE_LIMIT_WINDOW_MINUTES * 60)

                logger.warning(
                    f"Failed login attempt for {email} from {ip_address}: "
                    f"{current}/{self.config.MAX_LOGIN_ATTEMPTS} "
                    f"(reason: {failure_reason})"
                )
        except Exception as e:
            logger.error(f"Failed to record login attempt: {e}")

    def get_failed_attempts(self, email: str, ip_address: str) -> int:
        """
        Get number of failed login attempts.

        Args:
            email: Email address
            ip_address: IP address

        Returns:
            Number of failed attempts
        """
        key = f"login_attempt:{email}:{ip_address}"

        try:
            attempts = self.redis.get(key)
            return int(attempts) if attempts else 0
        except Exception as e:
            logger.error(f"Failed to get login attempts: {e}")
            return 0

    def check_rate_limit(self, email: str, ip_address: str) -> bool:
        """
        Check if login is rate limited for this email/IP combination.

        Args:
            email: Email address
            ip_address: IP address

        Returns:
            True if rate limited, False if allowed

        Raises:
            AccountLockedError: If account is locked
            RateLimitError: If rate limit is exceeded
        """
        attempts = self.get_failed_attempts(email, ip_address)

        if attempts >= self.config.MAX_LOGIN_ATTEMPTS:
            raise RateLimitError(self.config.RATE_LIMIT_WINDOW_MINUTES * 60)

        return False

    def check_account_lock(self, locked_until: Optional[datetime]) -> None:
        """
        Check if account is locked.

        Args:
            locked_until: Lock expiry timestamp

        Raises:
            AccountLockedError: If account is locked
        """
        if locked_until and datetime.utcnow() < locked_until:
            remaining_seconds = int((locked_until - datetime.utcnow()).total_seconds())
            raise AccountLockedError(
                locked_until,
                f"Account is locked for {remaining_seconds} more seconds",
            )

    def lock_account(self, lock_until: datetime) -> None:
        """
        Lock user account until specified time.

        Args:
            lock_until: When to unlock the account
        """
        logger.warning(f"Account locked until {lock_until}")

    def unlock_account(self) -> None:
        """Unlock user account."""
        logger.info("Account unlocked")

    def create_device_info(
        self,
        ip_address: str,
        user_agent: str,
        device_name: Optional[str] = None,
        location: Optional[str] = None,
    ) -> DeviceInfo:
        """
        Create and return device information.

        Args:
            ip_address: Client IP address
            user_agent: Client user agent string
            device_name: Human-readable device name
            location: Inferred location

        Returns:
            DeviceInfo object
        """
        device_id = self.generate_device_id(ip_address, user_agent)

        return DeviceInfo(
            device_id=device_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_name=device_name,
            location=location,
        )

    def detect_suspicious_activity(
        self,
        user_id: str,
        new_device_info: DeviceInfo,
        previous_sessions: list,
    ) -> dict:
        """
        Detect suspicious activity based on new device info.

        Args:
            user_id: User ID
            new_device_info: New device information
            previous_sessions: List of previous sessions

        Returns:
            Dictionary with suspicious activity flags
        """
        suspicious = {
            "new_location": False,
            "new_device": False,
            "rapid_consecutive_login": False,
        }

        if not previous_sessions:
            return suspicious

        # Check if new location
        last_session = previous_sessions[0]
        if (
            last_session.location
            and new_device_info.location
            and last_session.location != new_device_info.location
        ):
            suspicious["new_location"] = True

        # Check if new device
        if last_session.ip_address != new_device_info.ip_address:
            suspicious["new_device"] = True

        # Check for rapid consecutive login (within 30 seconds)
        time_since_last = datetime.utcnow() - last_session.last_activity_at
        if time_since_last.total_seconds() < 30:
            suspicious["rapid_consecutive_login"] = True

        if any(suspicious.values()):
            logger.warning(
                f"Suspicious activity detected for user {user_id}: {suspicious}"
            )

        return suspicious

    def get_security_recommendations(
        self, suspicious_flags: dict
    ) -> list[str]:
        """
        Get security recommendations based on suspicious flags.

        Args:
            suspicious_flags: Dictionary of suspicious activity flags

        Returns:
            List of security recommendations
        """
        recommendations = []

        if suspicious_flags.get("new_location"):
            recommendations.append(
                "Login from a new location detected. "
                "If this wasn't you, consider changing your password."
            )

        if suspicious_flags.get("new_device"):
            recommendations.append(
                "Login from a new device detected. "
                "Review your active sessions."
            )

        if suspicious_flags.get("rapid_consecutive_login"):
            recommendations.append(
                "Rapid login attempts detected. "
                "Verify your account security."
            )

        return recommendations
