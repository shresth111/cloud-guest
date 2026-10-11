import contextvars
import json
import logging
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from app.core.config import Settings

request_id_context: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id",
    default=None,
)
user_id_context: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "user_id",
    default=None,
)
organization_id_context: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "organization_id",
    default=None,
)


class JsonLogFormatter(logging.Formatter):
    reserved_fields = {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_context.get(),
            "user_id": user_id_context.get(),
            "organization_id": organization_id_context.get(),
        }
        for key, value in record.__dict__.items():
            if key not in self.reserved_fields and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


# What Celery itself attaches to a record, on top of the stdlib fields:
# ``TaskFormatter`` injects ``task_name``/``task_id``, and the trace module
# logs with ``extra={"data": ...}`` -- the same context its own format
# string already renders. ``taskName`` is the asyncio task name Python 3.12
# adds to every record.
_CELERY_RECORD_FIELDS = frozenset({"task_name", "task_id", "taskName", "data"})


class ExtrasAppendingFormatter(logging.Formatter):
    """Wraps another formatter and appends a record's ``extra=`` fields.

    The API process logs through :class:`JsonLogFormatter`, which carries
    every ``extra`` field. A Celery worker does not: Celery installs its own
    handlers with a ``%(message)s``-style format, so a call such as
    ``logger.warning("alert_rule_evaluation_failed", extra={"rule_id": ...,
    "error": ...})`` reached the worker log as the bare event name. The rule
    id, the organization and the exception were computed and then dropped,
    for every structured event every task emits.

    This keeps Celery's own line shape -- existing greps over
    ``[timestamp: LEVEL/Process] ...`` keep working -- and appends the
    fields as one compact JSON object on the same line. A traceback, if the
    inner formatter rendered one, stays after it.
    """

    def __init__(self, inner: logging.Formatter) -> None:
        super().__init__()
        self._inner = inner

    def format(self, record: logging.LogRecord) -> str:
        rendered = self._inner.format(record)
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in JsonLogFormatter.reserved_fields
            and key not in _CELERY_RECORD_FIELDS
            and not key.startswith("_")
        }
        if not extras:
            return rendered
        suffix = json.dumps(extras, default=str, separators=(",", ":"))
        first_line, newline, rest = rendered.partition("\n")
        return f"{first_line} {suffix}{newline}{rest}"


def append_extras_to_handlers(logger: logging.Logger) -> None:
    """Wrap each of ``logger``'s handlers' formatters once. Idempotent, so
    it is safe on both of Celery's logger-setup signals."""
    for handler in logger.handlers:
        formatter = handler.formatter
        if formatter is None or isinstance(formatter, ExtrasAppendingFormatter):
            continue
        handler.setFormatter(ExtrasAppendingFormatter(formatter))


def configure_logging(settings: Settings) -> None:
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    formatter = JsonLogFormatter()

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)

    Path(settings.log_dir).mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        filename=settings.log_path,
        maxBytes=settings.log_max_bytes,
        backupCount=settings.log_backup_count,
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(log_level)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    logging.getLogger("uvicorn.access").handlers.clear()
    logging.getLogger("uvicorn.error").propagate = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
