"""Input validators for the Monitoring domain."""

from app.domains.monitoring.exceptions import InvalidMetricValueError

def validate_metric_ranges(cpu_usage: float, memory_usage: float, disk_usage: float) -> None:
    """Validate metric usage values are within [0, 100]."""
    if not (0.0 <= cpu_usage <= 100.0):
        raise InvalidMetricValueError("CPU usage must be between 0 and 100%")
    if not (0.0 <= memory_usage <= 100.0):
        raise InvalidMetricValueError("Memory usage must be between 0 and 100%")
    if not (0.0 <= disk_usage <= 100.0):
        raise InvalidMetricValueError("Disk usage must be between 0 and 100%")
