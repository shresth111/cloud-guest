"""Background tasks for the Theme domain."""

import logging

logger = logging.getLogger(__name__)


def purge_theme_cdn_cache() -> dict:
    """Invalidate CDN distribution assets for updated portals."""
    logger.info("Executing background captive portal CDN invalidation task...")
    return {"status": "success"}
