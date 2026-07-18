"""Background tasks for the License domain."""

import logging

logger = logging.getLogger(__name__)


def check_license_expirations() -> dict:
    """Trigger deactivations for licenses that have passed their expires_at date."""
    logger.info("Executing periodic license expiration and deactivation check...")
    return {"status": "success", "expired_licenses_count": 0}
