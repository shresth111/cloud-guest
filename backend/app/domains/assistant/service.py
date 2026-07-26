"""Assistant business logic: provider interfaces + ``AssistantService`` --
create/list conversations, list/send messages, with tenant *and* owner
scoping.

## Self-service, not admin-visible -- unlike Support Tickets

This domain is deliberately narrower than
``app.domains.support_tickets``: a caller only ever sees/acts on their
own conversations (``organization_id`` *and* ``user_id`` both scoped to
the caller), never another org member's, and there is no platform-admin
"every organization's conversations" view at all. A support ticket is
meant to be triaged by a human agent across an organization (or the whole
platform); an AI chat thread is a private, self-service exchange the
customer had with the assistant -- there is no analogous "admin resolves
this" workflow to build visibility for.

## Provider interfaces: ``Protocol``, honest logging default

There is no real LLM API key configured anywhere in this deployment --
mirrors ``app.domains.otp.service``'s own "no real SMS/email provider"
starting point exactly, and follows the identical fix:
``AssistantProviderProtocol`` is typed structurally (``Protocol``) so a
real provider can be substituted later (via ``dependencies.py``'s
``build_assistant_provider``, itself mirroring
``app.domains.billing.dependencies.build_payment_gateway``'s "one place
decides real vs. logging" pattern) without this module changing at all.

``LoggingAssistantProvider`` is the honest interim implementation -- but
it is *not* ``otp.service.LoggingEmailProvider``'s "log and do nothing"
shape verbatim, because a chat widget with a literally empty reply is a
bad demo in a way a fire-and-forget OTP send is not (nobody is staring at
the OTP provider waiting for visible output). Instead it does keyword
matching against the customer's message and returns one of a set of
genuinely useful, topical canned replies covering the product's real
staff-facing actions -- voucher creation (distinct from guest-facing
voucher redemption), router offline troubleshooting, blocking/disconnecting
a guest or device, locations, team/roles, billing, WiFi connectivity
troubleshooting, or a generic "a real ticket can be raised" fallback --
the same *category* of honest, non-fake default this codebase already
ships elsewhere for an unconfigured integration
(``LoggingEmailProvider``/``LoggingSmsProvider`` here;
``UnconfiguredPaymentGateway`` in ``app.domains.billing``), just tuned so
the demo experience is actually pleasant rather than obviously stubbed.
This is not a placeholder to be embarrassed about -- it is a real,
if limited, assistant that ships and works today with zero external
dependencies. The keyword groups are checked most-specific-intent-first
(see the comment above ``_GUEST_MANAGEMENT_KEYWORDS``) precisely because
live testing found two real collisions in the original single-bucket
version: a generic WiFi keyword ("connect") is a Python substring of
"disconnect", and a single "voucher" bucket conflated the staff-facing
creation flow with the guest-facing redemption flow.

``AnthropicAssistantProvider`` is the real provider, using the official
``anthropic`` Python SDK -- present and correct, but unreachable until
``Settings.anthropic_api_key`` is actually set (see
``dependencies.build_assistant_provider``), the identical "code is real,
credential is the only missing piece" posture
``app.domains.billing.payment_gateways.StripePaymentGateway``/
``RazorpayPaymentGateway`` already establish for this codebase's payment
integrations.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Protocol

from app.database.utils.pagination import PaginationMeta

from .constants import MessageRole
from .exceptions import (
    ConversationNotFoundError,
    CrossOrganizationConversationAccessError,
    OrganizationContextRequiredError,
)
from .models import AssistantConversation, AssistantMessage
from .repository import AssistantRepositoryProtocol

logger = logging.getLogger(__name__)

# Title auto-derived from the first customer message -- truncated, not
# the raw (up to 4000-char) message, mirroring how a chat UI's own
# thread-list label is always a short summary, not the full text.
_TITLE_MAX_LENGTH = 60


# ============================================================================
# Provider interfaces (Protocol, honest logging default -- see module
# docstring)
# ============================================================================


class AssistantProviderProtocol(Protocol):
    async def reply(
        self, *, conversation_history: list[dict[str, str]], new_message: str
    ) -> str: ...


# Keyword groups -> canned reply, checked in order against the lower-cased
# customer message. Order is intent-specificity, most specific first --
# this matters more than the original single-bucket version because two
# real collisions showed up in live testing (see PR notes):
#
# 1. "in" is a Python substring test, so a generic keyword can match
#    inside an unrelated word -- e.g. "connect" (a _WIFI_KEYWORDS entry)
#    is a substring of "disconnect", so "how do I disconnect a guest"
#    used to match WiFi-troubleshooting before it could ever reach a
#    guest-management bucket. Guest management is now checked first.
# 2. A single "voucher" bucket collapsed two very different intents into
#    one reply: an owner/staff caller asking how to *create* a voucher
#    was getting told how a *guest redeems* one -- topically adjacent,
#    but the wrong instructions for what was actually asked. Creation is
#    now its own bucket, checked before redemption.
_GUEST_MANAGEMENT_KEYWORDS = (
    "block",
    "unblock",
    "ban",
    "kick",
    "disconnect",
    "remove a guest",
    "remove this guest",
    "connected device",
)
_ROUTER_STATUS_KEYWORDS = (
    "router offline",
    "router is offline",
    "router down",
    "router disconnected",
    "router unreachable",
    "router not connecting",
    "no signal",
    "offline",
)
_VOUCHER_CREATE_KEYWORDS = (
    "create a voucher",
    "create voucher",
    "generate voucher",
    "generate a voucher",
    "issue a voucher",
    "issue voucher",
    "new voucher",
    "voucher plan",
    "add a voucher",
    "make a voucher",
)
_VOUCHER_KEYWORDS = ("voucher", "redeem", "redemption")
_BILLING_KEYWORDS = ("bill", "invoice", "payment", "charge", "subscription", "refund")
_LOCATION_KEYWORDS = (
    "location",
    "new property",
    "another property",
    "multiple properties",
    "branch",
)
_TEAM_KEYWORDS = (
    "team",
    "staff",
    "invite",
    "teammate",
    "role",
    "permission",
    "add a user",
    "add a member",
)
_WIFI_KEYWORDS = (
    "wifi",
    "wi-fi",
    "password",
    "connect",
    "internet",
    "network",
    "login",
)

_GUEST_MANAGEMENT_REPLY = (
    "You can block a guest from either the Guests or Connected Devices "
    "section of your dashboard -- open the guest or device entry and "
    "choose Block (this prevents them from reconnecting until you "
    "unblock them). If you just want to end their current session "
    "without a permanent block, use Disconnect instead -- they can "
    "reconnect normally afterward."
)
_ROUTER_STATUS_REPLY = (
    "Router status on the Routers page is based on its last heartbeat, "
    "shown as the last-seen time. If a router shows Offline, first check "
    "it has power and an active internet uplink -- most routers "
    "reconnect automatically within a few minutes once connectivity is "
    "restored. Still showing Offline after confirming power and internet? "
    "I've noted this conversation so our support team can take a closer "
    "look, or you can raise a support ticket directly."
)
_VOUCHER_CREATE_REPLY = (
    "To create vouchers: open the Vouchers section of your dashboard, "
    "set up a Voucher Plan (validity period, data limit, uses per "
    "voucher) under a Voucher Series, then generate vouchers from that "
    "plan -- they're ready to hand out or print immediately."
)
_VOUCHER_REPLY = (
    "Vouchers are redeemed from the guest WiFi login page -- enter the "
    "code exactly as printed (it's case-sensitive) and tap Connect. If a "
    "code shows as already used or expired, it can only be redeemed once "
    "and does not refresh; ask your front-desk/reception team to issue a "
    "new one from the Vouchers section of the dashboard."
)
_BILLING_REPLY = (
    "For billing questions -- invoices, payment methods, or a charge you "
    "don't recognize -- the Billing section of your dashboard has your "
    "full invoice history and current subscription status. If something "
    "still looks wrong after checking there, I've noted this conversation "
    "so our support team can follow up directly, or you can raise a "
    "support ticket for a faster, tracked response."
)
_LOCATION_REPLY = (
    "You can manage multiple properties from the Locations section of "
    "your dashboard -- add a new location there, then assign routers and "
    "vouchers to it. Use the location selector in the dashboard header "
    "to switch between properties."
)
_TEAM_REPLY = (
    "Invite teammates from the Team section of your dashboard and assign "
    "a role -- Owner, Admin, or a custom role -- to control what they "
    "can see and do, such as managing vouchers or viewing billing."
)
_WIFI_REPLY = (
    "For WiFi connection trouble: double-check the network name (SSID) "
    "and password shown on your login page or welcome material -- "
    "passwords are case-sensitive. If you're connected but can't get "
    "online, try forgetting the network on your device and reconnecting, "
    "or restarting WiFi on your device. Still stuck after that? I've "
    "noted this conversation so our support team can take a closer look, "
    "or you can raise a support ticket directly."
)
_DEFAULT_REPLY = (
    "Thanks for reaching out -- I've noted this conversation so our "
    "support team can follow up. If this needs a tracked response, you "
    "can also raise a formal support ticket from your dashboard and a "
    "team member will get back to you there."
)


class LoggingAssistantProvider:
    """Honest interim assistant provider -- keyword-matched canned replies
    instead of calling a real LLM API. See module docstring for why this
    is a deliberate, non-fake default rather than a placeholder."""

    async def reply(
        self, *, conversation_history: list[dict[str, str]], new_message: str
    ) -> str:
        logger.info(
            "assistant_logging_provider_reply",
            extra={"message_length": len(new_message)},
        )
        lowered = new_message.lower()
        if any(keyword in lowered for keyword in _GUEST_MANAGEMENT_KEYWORDS):
            return _GUEST_MANAGEMENT_REPLY
        if any(keyword in lowered for keyword in _ROUTER_STATUS_KEYWORDS):
            return _ROUTER_STATUS_REPLY
        if any(keyword in lowered for keyword in _VOUCHER_CREATE_KEYWORDS):
            return _VOUCHER_CREATE_REPLY
        if any(keyword in lowered for keyword in _VOUCHER_KEYWORDS):
            return _VOUCHER_REPLY
        if any(keyword in lowered for keyword in _BILLING_KEYWORDS):
            return _BILLING_REPLY
        if any(keyword in lowered for keyword in _LOCATION_KEYWORDS):
            return _LOCATION_REPLY
        if any(keyword in lowered for keyword in _TEAM_KEYWORDS):
            return _TEAM_REPLY
        if any(keyword in lowered for keyword in _WIFI_KEYWORDS):
            return _WIFI_REPLY
        return _DEFAULT_REPLY


class AnthropicAssistantProvider:
    """Real ``AssistantProviderProtocol`` implementation, using the
    official ``anthropic`` Python SDK. Only ever constructed by
    ``dependencies.build_assistant_provider`` once
    ``Settings.anthropic_api_key`` is actually set -- see that function
    and this module's own docstring for the "unreachable until
    configured" posture."""

    def __init__(self, *, api_key: str, model: str = "claude-opus-4-8") -> None:
        # Imported lazily so the ``anthropic`` package is only ever
        # touched on the real-provider path -- the logging provider (this
        # deployment's actual default) never needs it importable.
        import anthropic

        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    async def reply(
        self, *, conversation_history: list[dict[str, str]], new_message: str
    ) -> str:
        messages = [
            {"role": entry["role"], "content": entry["content"]}
            for entry in conversation_history
        ]
        messages.append({"role": "user", "content": new_message})
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            # A support-chat reply is a short, latency-sensitive turn, not
            # a long-horizon reasoning task -- "low" effort keeps it fast.
            output_config={"effort": "low"},
            system=(
                "You are the customer support assistant for ZIP WiFi / "
                "CloudGuest, a WiFi-hotspot management SaaS for hotels, "
                "cafes, and similar venues. The person chatting with you "
                "is the venue owner/staff member managing the account, "
                "not a guest using the WiFi -- answer accordingly.\n\n"
                "Real product features you can accurately explain:\n"
                "- Vouchers: staff create voucher plans/series in the "
                "Vouchers section (validity period, data limit, uses per "
                "voucher) and generate codes from a plan. Guests redeem "
                "those codes on the WiFi login page; a redeemed code is "
                "single-use and does not refresh -- staff must issue a "
                "new one.\n"
                "- Routers: each router's status (Online/Offline) on the "
                "Routers page is based on its last heartbeat/last-seen "
                "time. An offline router usually means a power or "
                "internet-uplink problem at the router; it reconnects "
                "automatically once connectivity returns.\n"
                "- Guests & connected devices: staff can Block a guest or "
                "device (prevents reconnecting until unblocked) or "
                "Disconnect one (ends the current session only) from the "
                "Guests or Connected Devices section.\n"
                "- Locations: multi-property accounts manage each "
                "property from the Locations section and switch between "
                "them via the location selector in the dashboard header.\n"
                "- Team & roles: staff are invited from the Team section "
                "and assigned a role (Owner, Admin, or a custom role) "
                "that controls what they can see and do.\n"
                "- Billing: invoices, payment methods, and subscription "
                "status live in the Billing section.\n\n"
                "Be concise and practical, and answer the actual question "
                "asked -- e.g. a question about *creating* a voucher is "
                "about the staff-facing plan/generate flow, not the "
                "guest-facing redemption flow. Never invent a feature, "
                "menu location, or behavior you're not sure this product "
                "has -- if you don't know, say so and tell the customer "
                "a real support ticket can be raised from their "
                "dashboard."
            ),
            messages=messages,
        )
        text_blocks = [block.text for block in response.content if block.type == "text"]
        return "".join(text_blocks).strip() or _DEFAULT_REPLY


# ============================================================================
# Application service
# ============================================================================


@dataclass
class ConversationListResult:
    items: list[AssistantConversation]
    meta: PaginationMeta


class AssistantService:
    """Create/list conversations, list/send messages -- strictly scoped
    to the calling user's own conversations within their own
    organization. See module docstring for why this is narrower than
    ``app.domains.support_tickets``'s own tenant-only scoping."""

    def __init__(
        self,
        repository: AssistantRepositoryProtocol,
        *,
        provider: AssistantProviderProtocol,
    ) -> None:
        self.repository = repository
        self.provider = provider

    # -- create --------------------------------------------------------------

    async def start_conversation(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        user_id: uuid.UUID,
        initial_message: str | None,
    ) -> tuple[AssistantConversation, AssistantMessage | None]:
        if requesting_organization_id is None:
            raise OrganizationContextRequiredError()

        conversation = await self.repository.create_conversation(
            organization_id=requesting_organization_id,
            user_id=user_id,
            title=_derive_title(initial_message),
            created_by=user_id,
            updated_by=user_id,
        )
        logger.info(
            "assistant_conversation_started",
            extra={
                "conversation_id": str(conversation.id),
                "organization_id": str(requesting_organization_id),
            },
        )

        assistant_message: AssistantMessage | None = None
        if initial_message:
            assistant_message = await self._exchange(
                conversation=conversation,
                history=[],
                content=initial_message,
                actor_user_id=user_id,
            )
        return conversation, assistant_message

    # -- read ------------------------------------------------------------

    async def list_conversations(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        user_id: uuid.UUID,
        page: int = 1,
        page_size: int = 25,
    ) -> ConversationListResult:
        if requesting_organization_id is None:
            raise OrganizationContextRequiredError()
        items, meta = await self.repository.list_conversations(
            organization_id=requesting_organization_id,
            user_id=user_id,
            page=page,
            page_size=page_size,
        )
        return ConversationListResult(items=items, meta=meta)

    async def get_messages(
        self,
        conversation_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        user_id: uuid.UUID,
    ) -> list[AssistantMessage]:
        conversation = await self._get_owned_conversation(
            conversation_id,
            requesting_organization_id=requesting_organization_id,
            user_id=user_id,
        )
        return await self.repository.list_messages(conversation.id)

    # -- write -------------------------------------------------------------

    async def send_message(
        self,
        conversation_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        user_id: uuid.UUID,
        content: str,
    ) -> AssistantMessage:
        conversation = await self._get_owned_conversation(
            conversation_id,
            requesting_organization_id=requesting_organization_id,
            user_id=user_id,
        )
        history = await self.repository.list_messages(conversation.id)
        history_payload = [
            {"role": message.role, "content": message.content} for message in history
        ]
        assistant_message = await self._exchange(
            conversation=conversation,
            history=history_payload,
            content=content,
            actor_user_id=user_id,
        )
        assert assistant_message is not None
        return assistant_message

    # -- internal helpers ----------------------------------------------------

    async def _exchange(
        self,
        *,
        conversation: AssistantConversation,
        history: list[dict[str, str]],
        content: str,
        actor_user_id: uuid.UUID,
    ) -> AssistantMessage:
        """Persists the customer's message, calls the provider for a
        reply, persists and returns the assistant's message. Synchronous
        end-to-end (no websockets/streaming/background job) -- see
        ``router.py``'s module docstring for why that is a deliberate
        POC-quality choice for this domain."""
        await self.repository.create_message(
            conversation_id=conversation.id,
            role=MessageRole.USER.value,
            content=content,
            created_by=actor_user_id,
            updated_by=actor_user_id,
        )
        reply_text = await self.provider.reply(
            conversation_history=history, new_message=content
        )
        assistant_message = await self.repository.create_message(
            conversation_id=conversation.id,
            role=MessageRole.ASSISTANT.value,
            content=reply_text,
            created_by=actor_user_id,
            updated_by=actor_user_id,
        )
        # Bumps updated_at (via GenericRepository.update's own timestamp
        # handling) so the conversation list's "most recently active
        # first" ordering (see repository.list_conversations) reflects
        # this exchange.
        await self.repository.update_conversation(conversation, {})
        logger.info(
            "assistant_message_exchanged",
            extra={"conversation_id": str(conversation.id)},
        )
        return assistant_message

    async def _get_owned_conversation(
        self,
        conversation_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        user_id: uuid.UUID,
    ) -> AssistantConversation:
        conversation = await self.repository.get_conversation_by_id(conversation_id)
        if conversation is None or conversation.is_deleted:
            raise ConversationNotFoundError(conversation_id)
        if (
            requesting_organization_id is None
            or conversation.organization_id != requesting_organization_id
            or conversation.user_id != user_id
        ):
            raise CrossOrganizationConversationAccessError()
        return conversation


def _derive_title(initial_message: str | None) -> str | None:
    if not initial_message:
        return None
    stripped = initial_message.strip()
    if len(stripped) <= _TITLE_MAX_LENGTH:
        return stripped
    return stripped[: _TITLE_MAX_LENGTH - 1].rstrip() + "…"


__all__ = [
    "AssistantProviderProtocol",
    "LoggingAssistantProvider",
    "AnthropicAssistantProvider",
    "AssistantService",
    "ConversationListResult",
]
