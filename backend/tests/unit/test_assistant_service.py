"""Unit tests for ``app.domains.assistant.service.LoggingAssistantProvider``
-- the keyword-matched canned-reply engine that is this deployment's real,
live assistant behavior (no ``anthropic_api_key`` is configured anywhere in
this environment; see ``dependencies.build_assistant_provider``).

Covers the intent-specificity ordering fixed after live QA testing surfaced
two real collisions: a generic WiFi keyword ("connect") is a Python
substring of "disconnect", and a single "voucher" bucket previously
conflated the staff-facing creation flow with the guest-facing redemption
flow. See ``service.py``'s keyword-group comment for the full rationale.
"""

from __future__ import annotations

import pytest

from app.domains.assistant.service import (
    _BILLING_REPLY,
    _DEFAULT_REPLY,
    _GUEST_MANAGEMENT_REPLY,
    _LOCATION_REPLY,
    _ROUTER_STATUS_REPLY,
    _TEAM_REPLY,
    _VOUCHER_CREATE_REPLY,
    _VOUCHER_REPLY,
    _WIFI_REPLY,
    LoggingAssistantProvider,
)


@pytest.fixture
def provider() -> LoggingAssistantProvider:
    return LoggingAssistantProvider()


class TestVoucherIntentDisambiguation:
    """A staff/owner caller asking how to *create* a voucher must not be
    told how a *guest redeems* one -- the bug found in live QA testing."""

    @pytest.mark.parametrize(
        "message",
        [
            "How do I create a voucher for a guest?",
            "How do I generate a new voucher?",
            "I need to issue a voucher plan",
            "How do I make a voucher for my cafe?",
        ],
    )
    async def test_creation_intent_returns_creation_reply(
        self, provider: LoggingAssistantProvider, message: str
    ) -> None:
        reply = await provider.reply(conversation_history=[], new_message=message)
        assert reply == _VOUCHER_CREATE_REPLY

    @pytest.mark.parametrize(
        "message",
        [
            "My voucher code says already used",
            "How does a guest redeem a voucher?",
            "The voucher redemption isn't working",
        ],
    )
    async def test_redemption_intent_returns_redemption_reply(
        self, provider: LoggingAssistantProvider, message: str
    ) -> None:
        reply = await provider.reply(conversation_history=[], new_message=message)
        assert reply == _VOUCHER_REPLY


class TestGuestManagementBeatsWifiSubstringCollision:
    """"connect" is a substring of "disconnect" -- guest-management intent
    must win over the generic WiFi-troubleshooting bucket."""

    @pytest.mark.parametrize(
        "message",
        [
            "How do I disconnect a guest device?",
            "How do I block a guest from using WiFi?",
            "I need to ban a guest",
            "How do I kick someone off the network?",
        ],
    )
    async def test_guest_management_wins(
        self, provider: LoggingAssistantProvider, message: str
    ) -> None:
        reply = await provider.reply(conversation_history=[], new_message=message)
        assert reply == _GUEST_MANAGEMENT_REPLY


class TestRouterStatus:
    async def test_offline_router_gets_router_reply(
        self, provider: LoggingAssistantProvider
    ) -> None:
        reply = await provider.reply(
            conversation_history=[], new_message="Why is my router offline?"
        )
        assert reply == _ROUTER_STATUS_REPLY


class TestLocationsAndTeam:
    async def test_location_question_gets_location_reply(
        self, provider: LoggingAssistantProvider
    ) -> None:
        reply = await provider.reply(
            conversation_history=[],
            new_message="How do I add a new location to my account?",
        )
        assert reply == _LOCATION_REPLY

    async def test_team_question_gets_team_reply(
        self, provider: LoggingAssistantProvider
    ) -> None:
        reply = await provider.reply(
            conversation_history=[], new_message="How do I invite a teammate?"
        )
        assert reply == _TEAM_REPLY


class TestBillingAndWifiAndDefault:
    async def test_billing_question(self, provider: LoggingAssistantProvider) -> None:
        reply = await provider.reply(
            conversation_history=[], new_message="I was charged twice this month"
        )
        assert reply == _BILLING_REPLY

    async def test_wifi_connectivity_question(
        self, provider: LoggingAssistantProvider
    ) -> None:
        reply = await provider.reply(
            conversation_history=[], new_message="My wifi password isn't working"
        )
        assert reply == _WIFI_REPLY

    async def test_unmatched_message_gets_default_reply(
        self, provider: LoggingAssistantProvider
    ) -> None:
        reply = await provider.reply(
            conversation_history=[], new_message="What's the meaning of life?"
        )
        assert reply == _DEFAULT_REPLY
