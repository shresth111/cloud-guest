"""Validators for the Analytics domain."""

from app.domains.monitoring.exceptions import InvalidMetricValueError

def validate_metric_name(name: str) -> None:
    valid_names = {
        "total_bandwidth",
        "active_sessions",
        "peak_concurrent_users",
        "avg_session_duration",
        "otp_success_rate",
        "voucher_usage",
        "today_guests"
    }
    if name not in valid_names:
        raise InvalidMetricValueError(f"Invalid metric name: {name}")
