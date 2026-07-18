"""Validators for the Alerts domain."""

from app.domains.monitoring.exceptions import InvalidMetricValueError

def validate_rule_condition(condition: str) -> None:
    if condition not in (">", "<", "==", ">=", "<="):
        raise InvalidMetricValueError("Condition must be one of: '>', '<', '==', '>=', '<='")
