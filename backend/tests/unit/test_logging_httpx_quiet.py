"""httpx's per-request INFO line carries the full URL, query string included.

Ping4SMS takes its API key and the OTP text as query parameters, so on prod
every guest OTP wrote ``key=<api key>&sms=<code> is your verification code``
into the container and file logs. ``configure_logging`` must keep that line
out while letting httpx warnings through.
"""

import logging

import httpx
import pytest

from app.core.config import Settings
from app.core.logging import configure_logging


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def root_capture(tmp_path):
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    saved = {n: logging.getLogger(n).level for n in ("httpx", "httpcore")}
    configure_logging(Settings(log_dir=tmp_path, log_level="INFO"))
    handler = _ListHandler()
    root.addHandler(handler)
    try:
        yield handler
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
        for name, level in saved.items():
            logging.getLogger(name).setLevel(level)


def test_outbound_request_url_with_credentials_is_not_logged(root_capture) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        client.get(
            "https://site.ping4sms.com/api/smsapi",
            params={"key": "SECRETKEY123", "sms": "482913 is your verification code"},
        )

    logged = " ".join(r.getMessage() for r in root_capture.records)
    assert "SECRETKEY123" not in logged
    assert "482913" not in logged


def test_httpx_warnings_still_reach_the_root_logger(root_capture) -> None:
    logging.getLogger("httpx").warning("upstream misbehaved")

    assert any(r.getMessage() == "upstream misbehaved" for r in root_capture.records)


def test_app_info_logs_are_unaffected(root_capture) -> None:
    logging.getLogger("app.domains.otp.service").info("otp_requested")

    assert any(r.getMessage() == "otp_requested" for r in root_capture.records)
