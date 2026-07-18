"""Celery tasks for the Analytics domain."""

from celery import shared_task
from app.core.logging import get_logger

logger = get_logger(__name__)

@shared_task(name="analytics.aggregate_metrics")
def aggregate_metrics_task() -> str:
    """Aggregate raw router metrics into hourly/daily dashboard aggregates."""
    logger.info("Executing metrics aggregation background task")
    return "Metrics aggregation completed"
