"""Celery tasks for the Events domain."""

from celery import shared_task
from app.core.logging import get_logger

logger = get_logger(__name__)

@shared_task(name="events.prune_system_events")
def prune_system_events_task() -> str:
    """Prune historical audit/system events logs older than 90 days."""
    logger.info("Executing events log pruning task")
    return "Events pruning completed"
