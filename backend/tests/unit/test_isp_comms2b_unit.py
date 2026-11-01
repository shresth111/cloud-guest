"""COMMS-2b pure pieces: the own-sender PDF attachment, parameter rows, and
the new automation triggers."""

from __future__ import annotations

import email
from types import SimpleNamespace

from app.domains.isp_partner import automation
from app.domains.isp_partner.comms2b import (
    TRIGGER_EVENT,
    own_sender_with_attachment,
    parameter_rows,
)
from app.domains.isp_partner.comms_logic import EVENTS
from app.domains.marketing.providers import encrypt_config

PDF = b"%PDF-1.4 test"


def _row(provider_type: str, cfg: dict) -> SimpleNamespace:
    return SimpleNamespace(
        provider_type=provider_type, config_encrypted=encrypt_config(cfg)
    )


async def test_own_smtp_sender_attaches_the_pdf(monkeypatch) -> None:  # noqa: ANN001
    sent = []

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *a):  # noqa: ANN002
            return False

        def send_message(self, message):  # noqa: ANN001
            sent.append(message)

    sender = own_sender_with_attachment(
        _row(
            "smtp",
            {
                "host": "smtp.example.com",
                "port": 587,
                "username": "u",
                "password": "p",
                "from_address": "billing@isp.example.com",
            },
        ),
        PDF,
        "INV-1.pdf",
    )
    monkeypatch.setattr(sender, "_connect", lambda: _Conn())
    res = await sender.send(
        "to@example.com",
        subject="Invoice",
        html_body="<p>Hi</p>",
        from_name="ISP",
        headers={},
    )
    assert res.message_id
    msg = email.message_from_bytes(sent[0].as_bytes())
    parts = [p for p in msg.walk() if p.get_filename() == "INV-1.pdf"]
    assert len(parts) == 1 and parts[0].get_payload(decode=True) == PDF
    assert msg["To"] == "to@example.com"


async def test_own_ses_sender_attaches_the_pdf() -> None:
    calls = []

    class _Client:
        def send_email(self, **kw):  # noqa: ANN003
            calls.append(kw)
            return {"MessageId": "ses-1"}

    sender = own_sender_with_attachment(
        _row(
            "ses",
            {
                "access_key_id": "a",
                "secret_access_key": "b",
                "region": "ap-south-1",
                "from_address": "billing@isp.example.com",
            },
        ),
        PDF,
        "INV-1.pdf",
    )
    sender._client_factory = lambda _cfg: _Client()
    res = await sender.send(
        "to@example.com",
        subject="Invoice",
        html_body="<p>Hi</p>",
        from_name="ISP",
        headers={},
    )
    assert res.message_id == "ses-1"
    msg = email.message_from_bytes(calls[0]["Content"]["Raw"]["Data"])
    assert any(p.get_filename() == "INV-1.pdf" for p in msg.walk())


def test_parameter_rows_name_each_position() -> None:
    assert (
        TRIGGER_EVENT["overdue"] == "overdue" and TRIGGER_EVENT["welcome"] == "welcome"
    )
    rows = parameter_rows("unpaid", ["A", "INV/1", "Rs 1.00", "https://x/pay/t"])
    assert [r["variable"] for r in rows] == EVENTS["unpaid_invoice"]["vars"]
    assert rows[3] == {
        "position": 4,
        "variable": "pay_link",
        "value": "https://x/pay/t",
    }
    assert parameter_rows("nope", ["x"]) == [
        {"position": 1, "variable": None, "value": "x"}
    ]


def test_new_triggers_are_accepted_and_silent_when_unmapped() -> None:
    assert {"overdue", "welcome"} <= set(automation.TRIGGERS)
    assert set(automation.OPT_IN_TRIGGERS) == {"overdue", "welcome"}
    for event in ("overdue", "welcome"):
        assert EVENTS[event]["trigger"] == event
