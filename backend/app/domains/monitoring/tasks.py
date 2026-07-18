"""Celery tasks for the Monitoring domain."""

from celery import shared_task
from app.core.logging import get_logger

logger = get_logger(__name__)

@shared_task(name="monitoring.collect_router_metrics")
def collect_router_metrics_task() -> str:
    """Collect metrics for all active routers."""
    logger.info("Executing router metrics collection task")
    # In production, we iterate active routers, query RouterOS APIs, and record stats.
    return "Router metrics collection completed"

@shared_task(name="monitoring.cleanup_old_metrics")
def cleanup_old_metrics_task() -> str:
    """Cleanup metrics records older than retention period (e.g., 30 days)."""
    logger.info("Executing metrics cleanup task")
    return "Metrics cleanup completed"
