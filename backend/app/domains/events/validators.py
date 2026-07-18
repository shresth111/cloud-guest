"""Validators for the Events domain."""

from app.domains.monitoring.exceptions import InvalidMetricValueError

def validate_event_category(category: str) -> None:
    valid_categories = {"router", "provisioning", "configuration", "guest", "otp", "voucher", "auth", "system", "audit"}
    if category not in valid_categories:
        raise InvalidMetricValueError(f"Category must be one of: {valid_categories}")
