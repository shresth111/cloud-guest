"""Validators for the Reports domain."""

from app.domains.monitoring.exceptions import InvalidMetricValueError

def validate_report_format(file_format: str) -> None:
    if file_format not in ("pdf", "csv", "xlsx"):
        raise InvalidMetricValueError("Report file format must be 'pdf', 'csv', or 'xlsx'")
