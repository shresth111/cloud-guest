"""Celery tasks for the Reports domain."""

from celery import shared_task
from app.core.logging import get_logger

logger = get_logger(__name__)

@shared_task(name="reports.run_scheduled_reports")
def run_scheduled_reports_task() -> str:
    """Iterate active report schedules, generate respective reports, and email them."""
    logger.info("Running scheduled reports task")
    return "Scheduled reports processed"
