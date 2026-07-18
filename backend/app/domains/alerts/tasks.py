"""Celery tasks for the Alerts domain."""

from celery import shared_task
from app.core.logging import get_logger

logger = get_logger(__name__)

@shared_task(name="alerts.process_alerts_queue")
def process_alerts_queue_task() -> str:
    logger.info("Processing background alerts queue")
    return "Queue processing completed"

@shared_task(name="alerts.escalate_unresolved_alerts")
def escalate_unresolved_alerts_task() -> str:
    logger.info("Escalating unresolved critical alerts")
    return "Escalation completed"
