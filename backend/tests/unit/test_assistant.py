"""Unit tests for ``app.domains.assistant``'s real conversation/message
logic and provider selection -- complements ``test_assistant_service.py``,
which only covers ``LoggingAssistantProvider``'s keyword matching.

Follows this project's plain-``assert``/native-``async def`` style and its
"fake the narrow Protocol boundary" precedent (see
``tests/unit/test_api_keys.py``).

Covers three real gaps that weren't previously exercised by any test:

1. ``AssistantService``'s ownership scoping -- a caller must never be able
   to read or send a message into a conversation belonging to another
   organization, or another user within their own organization (this
   domain's self-service-only posture, see ``service.py``'s module
   docstring).
2. ``dependencies.build_assistant_provider``'s "empty key -> logging,
   real key -> real provider" selection -- the actual config-driven wiring
   point a real API key gets dropped into later.
3. ``LiteLLMAssistantProvider.reply``'s actual call shape against the
   ``litellm`` version genuinely pinned in ``requirements.txt`` --
   see ``TestLiteLLMProviderRequestShape`` below for what this guards
   against (previously a real compatibility bug against the ``anthropic``
   SDK directly, before this domain moved onto ``litellm``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.assistant.dependencies import (
    _SARVAM_DEFAULT_MODEL,
    build_assistant_provider,
)
from app.domains.assistant.exceptions import (
    ConversationNotFoundError,
    CrossOrganizationConversationAccessError,
    OrganizationContextRequiredError,
)
from app.domains.assistant.models import AssistantConversation, AssistantMessage
from app.domains.assistant.service import (
    AssistantService,
    LiteLLMAssistantProvider,
    LoggingAssistantProvider,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakeAssistantRepository:
    """Fakes ``AssistantRepositoryProtocol`` in-memory -- no DB/session
    needed to exercise ``AssistantService``'s own scoping/orchestration
    logic."""

    conversations: dict[uuid.UUID, AssistantConversation] = field(default_factory=dict)
    messages: dict[uuid.UUID, list[AssistantMessage]] = field(default_factory=dict)

    async def create_conversation(self, **fields: object) -> AssistantConversation:
        conversation = AssistantConversation(**_base_fields(**fields))
        self.conversations[conversation.id] = conversation
        self.messages[conversation.id] = []
        return conversation

    async def get_conversation_by_id(
        self, conversation_id: uuid.UUID
    ) -> AssistantConversation | None:
        return self.conversations.get(conversation_id)

    async def update_conversation(
        self, conversation: AssistantConversation, data: dict[str, object]
    ) -> AssistantConversation:
        for key, value in data.items():
            setattr(conversation, key, value)
        conversation.updated_at = _now()
        return conversation

    async def list_conversations(
        self,
        *,
        organization_id: uuid.UUID,
        user_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> tuple[list[AssistantConversation], PaginationMeta]:
        matching = [
            c
            for c in self.conversations.values()
            if c.organization_id == organization_id and c.user_id == user_id
        ]
        matching.sort(key=lambda c: c.updated_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        page_items = matching[params.offset : params.offset + params.page_size]
        return page_items, PaginationMeta.from_total(params, len(matching))

    async def create_message(self, **fields: object) -> AssistantMessage:
        message = AssistantMessage(**_base_fields(**fields))
        self.messages.setdefault(message.conversation_id, []).append(message)
        return message

    async def list_messages(self, conversation_id: uuid.UUID) -> list[AssistantMessage]:
        return list(self.messages.get(conversation_id, []))


@dataclass
class FakeAssistantProvider:
    """Records every call it receives instead of matching keywords --
    lets tests assert *what* ``AssistantService`` sends the provider,
    independent of ``LoggingAssistantProvider``'s own reply content
    (already covered by ``test_assistant_service.py``)."""

    fixed_reply: str = "canned reply"
    calls: list[tuple[list[dict[str, str]], str]] = field(default_factory=list)

    async def reply(
        self, *, conversation_history: list[dict[str, str]], new_message: str
    ) -> str:
        self.calls.append((conversation_history, new_message))
        return self.fixed_reply


@pytest.fixture
def repo() -> FakeAssistantRepository:
    return FakeAssistantRepository()


@pytest.fixture
def provider() -> FakeAssistantProvider:
    return FakeAssistantProvider()


@pytest.fixture
def service(
    repo: FakeAssistantRepository, provider: FakeAssistantProvider
) -> AssistantService:
    return AssistantService(repo, provider=provider)


class TestStartConversation:
    async def test_requires_organization_context(
        self, service: AssistantService
    ) -> None:
        with pytest.raises(OrganizationContextRequiredError):
            await service.start_conversation(
                requesting_organization_id=None,
                user_id=uuid.uuid4(),
                initial_message="hello",
            )

    async def test_with_initial_message_persists_both_turns_and_derives_title(
        self, service: AssistantService, provider: FakeAssistantProvider
    ) -> None:
        org_id, user_id = uuid.uuid4(), uuid.uuid4()
        conversation, assistant_message = await service.start_conversation(
            requesting_organization_id=org_id,
            user_id=user_id,
            initial_message="How do I create a voucher?",
        )
        assert conversation.title == "How do I create a voucher?"
        assert assistant_message is not None
        assert assistant_message.content == "canned reply"
        assert assistant_message.role == "assistant"
        # The provider was handed the real user message and no prior history.
        assert provider.calls == [([], "How do I create a voucher?")]

        history = await service.get_messages(
            conversation.id, requesting_organization_id=org_id, user_id=user_id
        )
        assert [m.role for m in history] == ["user", "assistant"]

    async def test_long_initial_message_title_is_truncated(
        self, service: AssistantService
    ) -> None:
        long_message = "x" * 200
        conversation, _ = await service.start_conversation(
            requesting_organization_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            initial_message=long_message,
        )
        assert conversation.title is not None
        assert len(conversation.title) == 60
        assert conversation.title.endswith("…")

    async def test_without_initial_message_no_exchange_happens(
        self, service: AssistantService, provider: FakeAssistantProvider
    ) -> None:
        conversation, assistant_message = await service.start_conversation(
            requesting_organization_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            initial_message=None,
        )
        assert conversation.title is None
        assert assistant_message is None
        assert provider.calls == []


class TestOwnershipScoping:
    """A conversation is strictly self-service -- not even another member
    of the same organization can read or write to it (see
    ``service.py``'s module docstring)."""

    async def test_send_message_denied_for_different_organization(
        self, service: AssistantService
    ) -> None:
        owner_org, owner_user = uuid.uuid4(), uuid.uuid4()
        conversation, _ = await service.start_conversation(
            requesting_organization_id=owner_org,
            user_id=owner_user,
            initial_message=None,
        )
        with pytest.raises(CrossOrganizationConversationAccessError):
            await service.send_message(
                conversation.id,
                requesting_organization_id=uuid.uuid4(),
                user_id=owner_user,
                content="snooping",
            )

    async def test_send_message_denied_for_different_user_same_organization(
        self, service: AssistantService
    ) -> None:
        owner_org, owner_user = uuid.uuid4(), uuid.uuid4()
        conversation, _ = await service.start_conversation(
            requesting_organization_id=owner_org,
            user_id=owner_user,
            initial_message=None,
        )
        with pytest.raises(CrossOrganizationConversationAccessError):
            await service.send_message(
                conversation.id,
                requesting_organization_id=owner_org,
                user_id=uuid.uuid4(),
                content="snooping",
            )

    async def test_get_messages_missing_conversation_raises_not_found(
        self, service: AssistantService
    ) -> None:
        with pytest.raises(ConversationNotFoundError):
            await service.get_messages(
                uuid.uuid4(),
                requesting_organization_id=uuid.uuid4(),
                user_id=uuid.uuid4(),
            )

    async def test_list_conversations_never_leaks_other_scopes(
        self, service: AssistantService
    ) -> None:
        org_a, user_a = uuid.uuid4(), uuid.uuid4()
        org_b, user_b = uuid.uuid4(), uuid.uuid4()
        await service.start_conversation(
            requesting_organization_id=org_a, user_id=user_a, initial_message=None
        )
        await service.start_conversation(
            requesting_organization_id=org_b, user_id=user_b, initial_message=None
        )

        result = await service.list_conversations(
            requesting_organization_id=org_a, user_id=user_a
        )
        assert len(result.items) == 1
        assert result.items[0].organization_id == org_a


class TestSendMessage:
    async def test_send_message_includes_prior_history_in_provider_call(
        self, service: AssistantService, provider: FakeAssistantProvider
    ) -> None:
        org_id, user_id = uuid.uuid4(), uuid.uuid4()
        conversation, _ = await service.start_conversation(
            requesting_organization_id=org_id,
            user_id=user_id,
            initial_message="first message",
        )
        provider.calls.clear()

        await service.send_message(
            conversation.id,
            requesting_organization_id=org_id,
            user_id=user_id,
            content="second message",
        )

        assert len(provider.calls) == 1
        history, new_message = provider.calls[0]
        assert new_message == "second message"
        assert [entry["content"] for entry in history] == [
            "first message",
            "canned reply",
        ]


class TestBuildAssistantProvider:
    """``build_assistant_provider`` is the single place that decides real
    vs. logging -- mirrors
    ``app.domains.billing.dependencies.build_payment_gateway``. This is
    the actual config-driven wiring point a real ``anthropic_api_key``
    gets dropped into later."""

    def test_no_api_key_selects_logging_provider(self) -> None:
        settings = Settings(anthropic_api_key="")
        provider = build_assistant_provider(settings=settings)
        assert isinstance(provider, LoggingAssistantProvider)

    def test_configured_api_key_selects_litellm_provider(self) -> None:
        settings = Settings(anthropic_api_key="sk-ant-test-key")
        provider = build_assistant_provider(settings=settings)
        assert isinstance(provider, LiteLLMAssistantProvider)

    def test_sarvam_provider_without_key_falls_back_to_logging(self) -> None:
        """Selecting 'sarvam' with sarvam_api_key still empty must fall
        back to Logging, not silently reuse a configured Anthropic key --
        see build_assistant_provider's own docstring."""
        settings = Settings(
            assistant_provider="sarvam",
            sarvam_api_key="",
            anthropic_api_key="sk-ant-test-key",
        )
        provider = build_assistant_provider(settings=settings)
        assert isinstance(provider, LoggingAssistantProvider)

    def test_sarvam_api_key_without_provider_selection_stays_logging(self) -> None:
        """A configured sarvam_api_key alone (assistant_provider left at
        its 'logging' default) must not activate Sarvam -- explicit
        selection is required, mirroring email_delivery_provider et al."""
        settings = Settings(sarvam_api_key="sarvam-test-key")
        provider = build_assistant_provider(settings=settings)
        assert isinstance(provider, LoggingAssistantProvider)

    def test_sarvam_provider_with_key_selects_litellm_provider(self) -> None:
        settings = Settings(
            assistant_provider="sarvam", sarvam_api_key="sarvam-test-key"
        )
        provider = build_assistant_provider(settings=settings)
        assert isinstance(provider, LiteLLMAssistantProvider)


class TestLiteLLMProviderRequestShape:
    """Regression test guarding the call shape
    ``LiteLLMAssistantProvider.reply`` sends to ``litellm.acompletion`` --
    this domain moved off the ``anthropic`` SDK directly and onto
    ``litellm`` so any future provider switch/fallback routing is a config
    change here rather than a rewrite (see ``service.py``'s docstring on
    the class). ``litellm.acompletion``'s own request-building/transport
    correctness is litellm's concern, not this domain's -- what this test
    actually verifies is *our* call site: the right model string (prefixed
    for the anthropic integration), the system prompt correctly folded
    into ``messages`` as a leading ``system``-role entry (litellm's
    OpenAI-shaped ``messages``, not the anthropic SDK's separate ``system=``
    kwarg), and the final user message appended last.

    Monkeypatches ``litellm.acompletion`` directly (not the HTTP
    transport) -- that's the actual, documented public entry point our
    code calls, and monkeypatching it here works because
    ``LiteLLMAssistantProvider.__init__``'s lazy ``import litellm`` binds
    to the same module object already patched by this test.
    """

    async def test_reply_calls_litellm_acompletion_with_expected_shape(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import litellm

        captured: dict[str, object] = {}

        async def fake_acompletion(**kwargs: object) -> SimpleNamespace:
            captured.update(kwargs)
            message = SimpleNamespace(content="test reply")
            choice = SimpleNamespace(message=message)
            return SimpleNamespace(choices=[choice])

        monkeypatch.setattr(litellm, "acompletion", fake_acompletion)

        provider = LiteLLMAssistantProvider(api_key="sk-ant-test-key")
        reply = await provider.reply(
            conversation_history=[{"role": "user", "content": "earlier message"}],
            new_message="How do I create a voucher?",
        )

        assert reply == "test reply"
        assert captured["model"] == "anthropic/claude-opus-4-8"
        assert captured["api_key"] == "sk-ant-test-key"
        assert captured["max_tokens"] == 1024
        assert captured["reasoning_effort"] == "low"
        messages = captured["messages"]
        assert isinstance(messages, list)
        assert messages[0]["role"] == "system"
        assert "Wyfy Guest" in messages[0]["content"]
        assert messages[-1] == {
            "role": "user",
            "content": "How do I create a voucher?",
        }

    async def test_reply_calls_litellm_acompletion_for_sarvam(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same call-shape guard as the Anthropic test above, for the
        Sarvam branch build_assistant_provider wires up -- confirms the
        'sarvam/<model>' prefix and sarvam_api_key actually reach
        litellm.acompletion untouched (LiteLLMAssistantProvider.__init__
        leaves any model string already containing '/' as-is rather than
        applying its 'anthropic/' default-prefix fallback)."""
        import litellm

        captured: dict[str, object] = {}

        async def fake_acompletion(**kwargs: object) -> SimpleNamespace:
            captured.update(kwargs)
            message = SimpleNamespace(content="namaste reply")
            choice = SimpleNamespace(message=message)
            return SimpleNamespace(choices=[choice])

        monkeypatch.setattr(litellm, "acompletion", fake_acompletion)

        settings = Settings(
            assistant_provider="sarvam", sarvam_api_key="sarvam-test-key"
        )
        provider = build_assistant_provider(settings=settings)
        assert isinstance(provider, LiteLLMAssistantProvider)

        reply = await provider.reply(
            conversation_history=[], new_message="Mera router offline hai"
        )

        assert reply == "namaste reply"
        assert captured["model"] == _SARVAM_DEFAULT_MODEL
        assert captured["model"] == "sarvam/sarvam-105b"
        assert captured["api_key"] == "sarvam-test-key"
