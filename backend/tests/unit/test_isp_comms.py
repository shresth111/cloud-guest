"""COMMS-2 pure rules: delivery lifecycle (never delivered without a
receipt), Meta webhook signature + parsing, the template catalogue."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime

import pytest

from app.domains.isp_partner import comms_logic as logic

T = datetime(2026, 11, 1, 5, 0, tzinfo=UTC)


def r(status, err=None):  # noqa: ANN001, ANN201
    return {"status": status, "occurred_at": T, "error_title": err}


def test_sent_without_receipt_is_only_sent() -> None:
    assert logic.lifecycle("sent", [])["status"] == "sent"


def test_delivered_and_read_only_from_receipts() -> None:
    assert logic.lifecycle("sent", [r("sent"), r("delivered")])["status"] == "delivered"
    assert logic.lifecycle("sent", [r("delivered"), r("read")])["status"] == "read"
    # out-of-order webhooks: read still wins
    assert logic.lifecycle("sent", [r("read"), r("sent")])["status"] == "read"


def test_failed_wins_and_carries_the_error() -> None:
    life = logic.lifecycle("sent", [r("sent"), r("failed", "Re-engagement message")])
    assert life == {
        "status": "failed",
        "status_at": T,
        "receipt_error": "Re-engagement message",
    }
    assert logic.lifecycle("failed", [])["status"] == "failed"


def test_queued_and_skipped_never_promoted() -> None:
    assert logic.lifecycle("queued", [r("delivered")])["status"] == "queued"
    assert logic.lifecycle("skipped", [r("delivered")])["status"] == "skipped"


def test_signature() -> None:
    body = b'{"entry":[]}'
    good = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert logic.signature_ok("s3cret", body, good)
    assert not logic.signature_ok("other", body, good)
    assert not logic.signature_ok("s3cret", body + b" ", good)
    assert not logic.signature_ok("s3cret", body, None)
    assert not logic.signature_ok("", body, good)
    assert not logic.signature_ok("s3cret", body, good.replace("sha256=", "sha1="))


def test_parse_statuses() -> None:
    payload = {
        "entry": [
            {
                "changes": [
                    {
                        "value": {
                            "statuses": [
                                {
                                    "id": "wamid.A",
                                    "status": "delivered",
                                    "timestamp": "1761973200",
                                },
                                {
                                    "id": "wamid.B",
                                    "status": "failed",
                                    "timestamp": "1761973260",
                                    "errors": [
                                        {"code": 131047, "title": "Re-engagement"}
                                    ],
                                },
                                {"id": "wamid.C", "status": "deleted"},
                                {"status": "read"},
                            ],
                            "messages": [{"id": "inbound"}],
                        }
                    }
                ]
            }
        ]
    }
    out = logic.parse_statuses(json.loads(json.dumps(payload)))
    assert [(o["provider_message_id"], o["status"]) for o in out] == [
        ("wamid.A", "delivered"),
        ("wamid.B", "failed"),
    ]
    assert out[0]["occurred_at"] == datetime.fromtimestamp(1761973200, tz=UTC)
    assert out[1]["error_code"] == "131047" and out[1]["error_title"] == "Re-engagement"


def test_events_cover_the_addendum_and_match_jaze4_triggers() -> None:
    from app.domains.isp_partner.automation import TRIGGERS

    assert set(logic.EVENTS) == {
        "pre_due",
        "overdue",
        "unpaid_invoice",
        "payment_receipt",
        "renewal",
        "welcome",
    }
    wired = {e["trigger"] for e in logic.EVENTS.values() if e["trigger"]}
    assert wired == set(TRIGGERS)
    assert "pay_link" in logic.EVENTS["unpaid_invoice"]["vars"]


def test_render_and_unknown_placeholders() -> None:
    vals = logic.sample_values("unpaid_invoice", "https://x/partner/pay/T")
    assert logic.render("Hi {{ name }}, pay {{balance}} at {{pay_link}}", vals) == (
        "Hi Customer name, pay ₹ 708.00 at https://x/partner/pay/T"
    )
    assert logic.unknown_placeholders("{{name}} {{iban}}", "unpaid_invoice") == ["iban"]
    assert logic.render("{{iban}}", vals) == "{{iban}}"


def test_find_approved() -> None:
    tpls = [
        {
            "name": "due_soon",
            "language": "en",
            "status": "APPROVED",
            "components": [{"type": "BODY", "text": "Hi {{1}}, due {{2}} for {{3}}"}],
        },
        {"name": "due_soon", "language": "hi", "status": "PENDING", "components": []},
    ]
    assert logic.find_approved(tpls, "due_soon", "en") == ("APPROVED", 3)
    assert logic.find_approved(tpls, "due_soon", "hi") == ("PENDING", 0)
    assert logic.find_approved(tpls, "missing", "en") == (None, None)


def test_routes_flag_gated_and_guarded() -> None:
    from app.domains.isp_partner.comms_router import (
        RequireCommsEnabled,
        comms_public_router,
        comms_router,
    )

    for r_ in comms_router.routes:
        deps = {d.call for d in r_.dependant.dependencies}
        names = {getattr(d, "__name__", type(d).__name__) for d in deps}
        assert RequireCommsEnabled in deps, r_.path
        assert {"RequireIspPartner", "RejectLocationRouterHeaders"} <= names, r_.path
    for r_ in comms_public_router.routes:
        deps = {d.call for d in r_.dependant.dependencies}
        names = {getattr(d, "__name__", type(d).__name__) for d in deps}
        assert RequireCommsEnabled in deps
        assert "RequireIspPartner" not in names  # Meta calls it, no user


def test_template_request_rejects_free_text_names() -> None:
    from pydantic import ValidationError

    from app.domains.isp_partner.comms_router import TemplateRequest

    with pytest.raises(ValidationError):
        TemplateRequest(wa_template_name="Hello {{1}} pay now")
    assert (
        TemplateRequest(wa_template_name="due_soon_v2").wa_template_name
        == "due_soon_v2"
    )
