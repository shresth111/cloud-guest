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
   real key -> Anthropic" selection -- the actual config-driven wiring
   point a real API key gets dropped into later.
3. ``AnthropicAssistantProvider.reply``'s actual request shape against the
   ``anthropic`` SDK version genuinely pinned in ``requirements.txt`` --
   see ``TestAnthropicProviderRequestShape`` below for a real compatibility
   bug this caught.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
import pytest

from app.core.config import Settings
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.assistant.dependencies import build_assistant_provider
from app.domains.assistant.exceptions import (
    ConversationNotFoundError,
    CrossOrganizationConversationAccessError,
    OrganizationContextRequiredError,
)
from app.domains.assistant.models import AssistantConversation, AssistantMessage
from app.domains.assistant.service import (
    AnthropicAssistantProvider,
    AssistantService,
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
    async def test_requires_organization_context(self, service: AssistantService) -> None:
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

    def test_configured_api_key_selects_anthropic_provider(self) -> None:
        settings = Settings(anthropic_api_key="sk-ant-test-key")
        provider = build_assistant_provider(settings=settings)
        assert isinstance(provider, AnthropicAssistantProvider)


class TestAnthropicProviderRequestShape:
    """Regression test for a real compatibility bug found while verifying
    this domain's "ready to just work the moment a real key is added"
    claim: the ``anthropic`` SDK version genuinely pinned in
    ``requirements.txt`` at the time (``0.75.0`` -- the version actually
    running in the deployed Docker image) does not accept the
    ``output_config`` keyword argument ``AnthropicAssistantProvider.reply``
    passes to ``messages.create``. Calling it would raise
    ``TypeError: create() got an unexpected keyword argument
    'output_config'`` the instant ``Settings.anthropic_api_key`` was ever
    set -- the exact "code is real but doesn't actually work" failure mode
    this domain's own docstrings claim *not* to have. Fixed by bumping
    ``anthropic`` to ``0.120.2`` in ``requirements.txt``.

    This test never needs a real API key or network access: it monkeypatches
    ``httpx.AsyncClient.send`` (the transport ``anthropic``'s SDK calls
    internally) to return a synthetic success response, so the *entire* real
    call path through ``messages.create`` executes -- including Python's own
    keyword-argument binding, which is exactly where the incompatibility
    surfaced. A future downgrade/repin that reintroduces the mismatch fails
    this test immediately, with no network dependency.
    """

    async def test_reply_request_shape_is_accepted_by_installed_sdk(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}

        async def fake_send(
            self: httpx.AsyncClient, request: httpx.Request, **kwargs: object
        ) -> httpx.Response:
            captured["json"] = json.loads(request.content)
            return httpx.Response(
                200,
                request=request,
                json={
                    "id": "msg_test",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-opus-4-8",
                    "content": [{"type": "text", "text": "test reply"}],
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            )

        monkeypatch.setattr(httpx.AsyncClient, "send", fake_send)

        provider = AnthropicAssistantProvider(api_key="sk-ant-test-key")
        reply = await provider.reply(
            conversation_history=[{"role": "user", "content": "earlier message"}],
            new_message="How do I create a voucher?",
        )

        assert reply == "test reply"
        sent = captured["json"]
        assert isinstance(sent, dict)
        # The exact parameter whose absence in 0.75.0 caused the bug.
        assert sent["output_config"] == {"effort": "low"}
        assert sent["model"] == "claude-opus-4-8"
        assert sent["messages"][-1] == {
            "role": "user",
            "content": "How do I create a voucher?",
        }
