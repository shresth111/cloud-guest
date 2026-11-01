"""APPS-2 #5: the integrations status cards report only recorded state."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from app.domains.isp_partner.integrations_router import (
    acs_card,
    integrations_router,
    ipdr_card,
    provider_card,
    telegram_card,
)

T = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)


def test_no_provider_row_is_not_configured_with_nothing_invented() -> None:
    card = provider_card(None, {})
    assert card["state"] == "not_configured"
    assert card["configured"] is False
    assert card["last_verified_at"] is None
    assert card["last_sent_at"] is None and card["last_failed_at"] is None


def test_provider_row_passes_its_own_status_through() -> None:
    row = SimpleNamespace(
        enabled=True,
        provider_type="meta_cloud",
        status="verified",
        last_verified_at=T,
        last_error=None,
        config_encrypted="SECRET",
    )
    card = provider_card(row, {"sent": T})
    assert card["configured"] and card["status"] == "verified"
    assert card["last_verified_at"] == T.isoformat()
    assert card["last_sent_at"] == T.isoformat() and card["last_failed_at"] is None
    assert "SECRET" not in repr(card)
    assert "last_sent_at" not in provider_card(row)  # email: no send log


def test_telegram_needs_token_and_chat_and_never_returns_them() -> None:
    st = SimpleNamespace(
        telegram_bot_token_encrypted="ENC",
        telegram_chat_id="-100123",
        telegram_enabled=True,
    )
    card = telegram_card(st, {"failed": T}, True)
    assert card["configured"] and card["last_failed_at"] == T.isoformat()
    assert "ENC" not in repr(card) and "-100123" not in repr(card)
    half = SimpleNamespace(
        telegram_bot_token_encrypted="ENC", telegram_chat_id=None, telegram_enabled=True
    )
    assert telegram_card(half, {}, True)["state"] == "not_configured"
    assert telegram_card(None, {}, False)["configured"] is False


def test_acs_configured_only_with_an_enabled_credential() -> None:
    assert acs_card(True, 1, 0, 0, None)["state"] == "not_configured"
    card = acs_card(True, 2, 1, 5, T)
    assert card["configured"] and card["devices"] == 5
    assert card["last_inform_at"] == T.isoformat()


def test_ipdr_local_store_is_not_set_up_and_exports_never_claim_offsite() -> None:
    local = ipdr_card("local", T, None)
    assert local["state"] == "not_set_up" and local["last_offsite_built_at"] is None
    s3 = ipdr_card("s3", T, T)
    assert s3["state"] == "configured"
    assert local["exports_offsite"] == s3["exports_offsite"] == "not_set_up"


def test_the_router_is_one_read_only_get() -> None:
    routes = [(r.path, sorted(r.methods)) for r in integrations_router.routes]
    assert routes == [("/integrations/status", ["GET"])]
