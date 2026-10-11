"""A Celery worker must not drop the ``extra=`` fields of a log call.

``alert_rule_evaluation_failed`` was logged with the rule id, organization
and exception, and reached the production worker log as the bare event
name -- 84 times in 14 minutes, none of them diagnosable.
"""

from __future__ import annotations

import logging

from celery.app.log import TaskFormatter
from celery.signals import after_setup_logger, after_setup_task_logger

from app.core.celery_app import celery_app
from app.core.logging import ExtrasAppendingFormatter, append_extras_to_handlers

WORKER_FORMAT = "[%(asctime)s: %(levelname)s/%(processName)s] %(message)s"


def _record(extra: dict | None = None, exc_info=None) -> logging.LogRecord:
    record = logging.LogRecord(
        "app.domains.monitoring.service",
        logging.WARNING,
        __file__,
        1,
        "alert_rule_evaluation_failed",
        None,
        exc_info,
    )
    record.__dict__.update(extra or {})
    return record


def test_extras_reach_the_rendered_line() -> None:
    formatter = ExtrasAppendingFormatter(logging.Formatter(WORKER_FORMAT))
    line = formatter.format(
        _record(
            {"rule_id": "r-1", "organization_id": None, "error": "KeyError: 'value'"}
        )
    )
    assert "] alert_rule_evaluation_failed {" in line
    assert '"rule_id":"r-1"' in line
    assert '"organization_id":null' in line
    assert '"error":"KeyError: \'value\'"' in line


def test_a_record_without_extras_is_left_exactly_as_celery_rendered_it() -> None:
    inner = logging.Formatter(WORKER_FORMAT)
    record = _record()
    assert ExtrasAppendingFormatter(inner).format(record) == inner.format(record)


def test_celerys_own_fields_are_not_repeated() -> None:
    formatter = ExtrasAppendingFormatter(TaskFormatter(WORKER_FORMAT, use_color=False))
    line = formatter.format(_record({"data": {"id": "x"}, "taskName": "Task-1"}))
    assert line.endswith("alert_rule_evaluation_failed")


def test_extras_sit_on_the_first_line_ahead_of_a_traceback() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        exc_info = sys.exc_info()
    formatter = ExtrasAppendingFormatter(logging.Formatter(WORKER_FORMAT))
    first, _, rest = formatter.format(_record({"rule_id": "r-1"}, exc_info)).partition(
        "\n"
    )
    assert first.endswith('{"rule_id":"r-1"}')
    assert "ValueError: boom" in rest


def test_wrapping_is_idempotent() -> None:
    logger = logging.Logger("probe")
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(WORKER_FORMAT))
    logger.addHandler(handler)
    append_extras_to_handlers(logger)
    first = handler.formatter
    append_extras_to_handlers(logger)
    assert isinstance(first, ExtrasAppendingFormatter)
    assert handler.formatter is first


def test_both_celery_logger_signals_install_it() -> None:
    """The hook is only worth anything if Celery actually calls it: firing
    the two real signals must wrap a plain handler's formatter."""
    assert celery_app is not None
    for signal in (after_setup_logger, after_setup_task_logger):
        logger = logging.Logger("probe")
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(WORKER_FORMAT))
        logger.addHandler(handler)
        signal.send(
            sender=None,
            logger=logger,
            loglevel=logging.INFO,
            logfile=None,
            format=WORKER_FORMAT,
            colorize=False,
        )
        assert isinstance(handler.formatter, ExtrasAppendingFormatter), signal.name
