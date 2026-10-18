"""Login messaging: which account sends a venue's guest login codes.

Resolution, per organization and channel (WhatsApp, SMS):

    the venue's own provider  iff  a row exists (purpose='otp'), it is
                                    verified and enabled, and the
                                    organization is entitled to
                                    ``guest_login_byo``
    otherwise                       the platform default (Wyfy Guest's own
                                    providers, ``Settings.*_delivery_provider``)

Nobody has to do anything for the default: an organization with no row, or
without the add-on, sends through Wyfy exactly as before.

Login never breaks on a venue's vendor. :class:`OrgOtpDispatcher` is what
``OtpService`` calls first; if the venue's provider raises, times out, or
anything about resolving it fails (including the database), it records the
fallback (counter on the row, a throttled audit row) and returns ``False``,
and ``OtpService`` sends the same code through the platform provider.

Two callers manage rows through the same :class:`LoginMessagingService`:

* the venue, from its own dashboard -- the organization is the caller's
  (``RequireOrganization``), never a path or body value;
* the Wyfy team, from the Master console -- the organization is the path id,
  the permission is pinned GLOBAL, and every write records who did it and
  sets ``configured_by_platform`` (the venue's card then says "Set up by Wyfy
  Guest team").

"Verify" is the same for every adapter: send a code through the venue's
account to a number the operator types, and mark the account verified only
when that code is typed back. Acceptance by a vendor is not delivery; the
typed-back code is.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import secrets
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings
from app.domains.rbac.enums import AuditAction

from .adapters import REGISTRY
from .exceptions import (
    ByoNotAllowedError,
    InvalidPhoneError,
    LoginProviderNotFoundError,
    OrganizationNotFoundError,
    ProviderConfigInvalidError,
    ProviderEncryptionUnavailableHttpError,
    ProviderSendFailedError,
    ProviderTypeNotSupportedError,
    VerificationCodeInvalidError,
    VerificationNotStartedError,
    VerificationRateLimitedError,
)
from .http_guard import UrlNotAllowedError, check_url_shape, system_resolver, vet_host
from .registry import (
    CHANNELS,
    AdapterContext,
    AdapterSpec,
    ConfigError,
    OtpMessage,
    ProviderSendError,
    build_display,
    normalize_config,
    scrub,
)

logger = logging.getLogger(__name__)

VERIFY_TTL_SECONDS = 600
VERIFY_MAX_ATTEMPTS = 5
VERIFY_MAX_SENDS = 5  # per organization+channel per VERIFY_TTL_SECONDS
FALLBACK_AUDIT_EVERY_SECONDS = 900
SEND_DEADLINE_SECONDS = 10.0
BREAKER_SECONDS = 120
ENTITY_TYPE = "org_login_provider"


def normalize_phone(raw: str) -> str | None:
    """E.164 from what a guest or operator typed. A bare 10-digit number is
    Indian (+91), as on the captive portal."""
    digits = re.sub(r"[\s\-().]", "", raw or "")
    if digits.startswith("+"):
        body = digits[1:]
    elif len(digits) == 10:
        body = "91" + digits
    elif digits.startswith("00"):
        body = digits[2:]
    else:
        body = digits
    if not re.fullmatch(r"[1-9]\d{7,14}", body):
        return None
    return "+" + body


def mask_phone(phone_e164: str) -> str:
    return phone_e164[:3] + "•" * max(len(phone_e164) - 7, 0) + phone_e164[-4:]


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Actor:
    user_id: uuid.UUID
    via_platform: bool  # True = Wyfy team from the Master console


@dataclass
class ResolvedSender:
    organization_id: uuid.UUID
    channel: str
    provider_id: uuid.UUID
    provider_type: str
    adapter: Any
    config: dict[str, Any]


def platform_default_label(settings: Settings, channel: str) -> tuple[bool, str]:
    """(configured, provider) for the platform's own sender of ``channel``."""
    value = (
        settings.whatsapp_delivery_provider
        if channel == "whatsapp"
        else settings.sms_delivery_provider
    ).lower()
    return value not in ("", "logging"), value or "logging"


class LoginMessagingService:
    def __init__(
        self,
        repository: Any,
        *,
        settings: Settings,
        redis: Any,
        audit_writer: Any | None = None,
        byo_entitlement_check: Callable[[uuid.UUID], Awaitable[bool]] | None = None,
        adapter_context: AdapterContext | None = None,
        now: Callable[[], datetime] | None = None,
        code_factory: Callable[[], str] | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.redis = redis
        self.audit_writer = audit_writer
        self.byo_entitlement_check = byo_entitlement_check
        self.adapter_context = adapter_context or AdapterContext(settings=settings)
        self._now = now or (lambda: datetime.now(UTC))
        self._code = code_factory or (lambda: f"{secrets.randbelow(10**6):06d}")

    # -- entitlement ---------------------------------------------------------

    async def byo_allowed(self, organization_id: uuid.UUID) -> bool:
        if self.byo_entitlement_check is None:
            return False
        try:
            return bool(await self.byo_entitlement_check(organization_id))
        except Exception:  # noqa: BLE001 - no licence row etc. = not allowed
            logger.info("guest_login_byo_entitlement_check_failed", exc_info=True)
            return False

    async def _require_org(self, organization_id: uuid.UUID) -> None:
        if not await self.repository.organization_exists(organization_id):
            raise OrganizationNotFoundError("Organization not found")

    # -- views ----------------------------------------------------------------

    @staticmethod
    def _spec(channel: str, provider_type: str) -> AdapterSpec | None:
        return REGISTRY.get(channel, provider_type)

    async def provider_view(
        self, row: Any, *, effective: bool, for_platform: bool
    ) -> dict[str, Any]:
        spec = self._spec(row.channel, row.provider_type)
        names = (
            await self.repository.get_user_names([row.updated_by_user_id])
            if for_platform and row.updated_by_user_id
            else {}
        )
        display = dict(row.display or {})
        sender = display.get(spec.sender_field) if spec and spec.sender_field else None
        updated_by: dict[str, Any] | None = None
        if row.updated_by_user_id:
            if for_platform:
                updated_by = {
                    "id": str(row.updated_by_user_id),
                    "name": names.get(row.updated_by_user_id),
                }
            else:
                # A venue sees "Wyfy Guest team", never a staff member's name.
                updated_by = {
                    "id": None
                    if row.configured_by_platform
                    else str(row.updated_by_user_id),
                    "name": "Wyfy Guest team" if row.configured_by_platform else None,
                }
        return {
            "channel": row.channel,
            "provider_type": row.provider_type,
            "display_name": spec.display_name if spec else row.provider_type,
            "sender_label": sender if isinstance(sender, str) else None,
            "enabled": bool(row.enabled),
            "status": row.status,
            "effective": effective,
            "last_verified_at": _iso(row.last_verified_at),
            "last_error": row.last_error,
            "display": display,
            "configured_by_platform": bool(row.configured_by_platform),
            "set_up_by": "wyfy_team" if row.configured_by_platform else "venue",
            "fallback": {
                "count": int(row.fallback_count or 0),
                "last_at": _iso(row.last_fallback_at),
                "last_error": row.last_fallback_error,
            },
            "updated_at": _iso(row.updated_at),
            "updated_by": updated_by,
        }

    async def overview(
        self, organization_id: uuid.UUID, *, for_platform: bool
    ) -> dict[str, Any]:
        if for_platform:
            await self._require_org(organization_id)
        rows = await self.repository.list_providers(organization_id)
        allowed = await self.byo_allowed(organization_id)
        channels = []
        for channel in CHANNELS:
            row = rows.get(channel)
            effective = bool(
                row is not None and allowed and row.enabled and row.status == "verified"
            )
            configured, provider = platform_default_label(self.settings, channel)
            channels.append(
                {
                    "channel": channel,
                    "effective_source": "own" if effective else "wyfy",
                    "own": await self.provider_view(
                        row, effective=effective, for_platform=for_platform
                    )
                    if row is not None
                    else None,
                    "platform_default": {"configured": configured, "provider": provider}
                    if for_platform
                    else {"configured": configured},
                }
            )
        return {
            "organization_id": str(organization_id),
            "byo_allowed": allowed,
            "channels": channels,
            "adapters": REGISTRY.schema(),
        }

    async def _require_row(self, organization_id: uuid.UUID, channel: str) -> Any:
        row = await self.repository.get_provider(organization_id, channel)
        if row is None:
            raise LoginProviderNotFoundError(
                "No own provider is set up for this channel; "
                "Wyfy Guest's default is used"
            )
        return row

    async def _effective(self, organization_id: uuid.UUID, row: Any) -> bool:
        return bool(
            row.enabled
            and row.status == "verified"
            and await self.byo_allowed(organization_id)
        )

    # -- write ---------------------------------------------------------------

    async def put_provider(
        self,
        organization_id: uuid.UUID,
        channel: str,
        actor: Actor,
        *,
        provider_type: str | None,
        config: dict[str, Any],
        enabled: bool | None,
    ) -> tuple[dict[str, Any], bool]:
        if actor.via_platform:
            await self._require_org(organization_id)
        elif not await self.byo_allowed(organization_id):
            raise ByoNotAllowedError(
                "Your own login messaging provider is not enabled for this account. "
                "Ask the Wyfy Guest team to turn it on."
            )
        existing = await self.repository.get_provider(organization_id, channel)
        if existing is None and not provider_type:
            raise ProviderConfigInvalidError(
                "provider_type is required", fields={"provider_type": "required"}
            )
        new_type = provider_type or existing.provider_type
        spec = self._spec(channel, new_type)
        if spec is None:
            raise ProviderTypeNotSupportedError(
                f"'{new_type}' is not a supported {channel} provider"
            )
        from app.domains.marketing.providers import (
            ProviderEncryptionUnavailableError,
            decrypt_config,
            encrypt_config,
        )

        same_type = existing is not None and existing.provider_type == new_type
        stored = (
            decrypt_config(existing.config_encrypted, settings=self.settings)
            if same_type
            else {}
        )
        merged = {**stored, **config}
        for name in spec.secret_fields:
            if name in config and config[name] in (None, ""):
                merged[name] = stored.get(name)  # write-only: blank keeps it
        try:
            normalized = normalize_config(spec, merged, stored=stored)
        except ConfigError as exc:
            raise ProviderConfigInvalidError(
                "The provider settings are not valid", fields=exc.fields
            ) from exc
        await self._vet_urls(spec, normalized)
        changed = not same_type or normalized != stored
        status = "unverified" if changed else existing.status
        if enabled is True and status != "verified":
            raise ProviderConfigInvalidError(
                "Verify the provider before turning it on",
                fields={"enabled": "verify first"},
            )
        fields: dict[str, Any] = {
            "updated_by_user_id": actor.user_id,
            "configured_by_platform": actor.via_platform,
        }
        if enabled is not None:
            fields["enabled"] = enabled
        elif existing is None:
            fields["enabled"] = False
        changed_fields: list[str] = []
        if changed:
            try:
                ciphertext = encrypt_config(normalized, settings=self.settings)
            except ProviderEncryptionUnavailableError as exc:
                raise ProviderEncryptionUnavailableHttpError(
                    "Provider credentials cannot be stored until the platform "
                    "encryption key is configured"
                ) from exc
            fields.update(
                {
                    "provider_type": new_type,
                    "config_encrypted": ciphertext,
                    "display": build_display(spec, normalized),
                    "status": "unverified",
                    "enabled": False,
                    "last_error": None,
                    "last_verified_at": None,
                }
            )
            changed_fields = sorted(
                name
                for name in set(normalized) | set(stored)
                if normalized.get(name) != stored.get(name)
            )
        created = existing is None
        if created:
            row = await self.repository.create_provider(
                organization_id=organization_id,
                channel=channel,
                created_by=actor.user_id,
                **fields,
            )
        else:
            row = await self.repository.update_provider(existing, fields)
        await self._audit(
            actor,
            organization_id,
            AuditAction.GUEST_LOGIN_PROVIDER_UPDATED,
            row,
            f"Login-code {channel} provider {'connected' if created else 'updated'}"
            + (" by the Wyfy Guest team" if actor.via_platform else ""),
            {
                "provider_type": new_type,
                "changed_fields": changed_fields,  # names only, never values
                "enabled": bool(row.enabled),
            },
        )
        view = await self.provider_view(
            row,
            effective=await self._effective(organization_id, row),
            for_platform=actor.via_platform,
        )
        return view, created

    async def _vet_urls(self, spec: AdapterSpec, config: dict[str, Any]) -> None:
        """Customer-supplied URLs are resolved and checked on save too, so a
        private address is refused up front, not only at send time."""
        url_field = {"custom_http": "url", "wati": "api_endpoint"}.get(spec.key)
        if not url_field or not config.get(url_field):
            return
        url = config[url_field]
        if (
            spec.key == "custom_http"
            and "{" in url.split("?", 1)[0].split("//", 1)[-1].split("/", 1)[0]
        ):  # noqa: E501
            raise ProviderConfigInvalidError(
                "The provider settings are not valid",
                fields={url_field: "placeholders are not allowed in the host"},
            )
        try:
            host = check_url_shape(url)
            await asyncio.to_thread(
                vet_host,
                host,
                443,
                resolver=self.adapter_context.resolver or system_resolver,
                settings=self.settings,
            )
        except UrlNotAllowedError as exc:
            raise ProviderConfigInvalidError(
                "The provider settings are not valid", fields={url_field: exc.reason}
            ) from exc

    async def delete_provider(
        self, organization_id: uuid.UUID, channel: str, actor: Actor
    ) -> dict[str, Any]:
        if actor.via_platform:
            await self._require_org(organization_id)
        row = await self._require_row(organization_id, channel)
        await self.repository.soft_delete_provider(row)
        await self._clear_challenge(organization_id, channel)
        await self._audit(
            actor,
            organization_id,
            AuditAction.GUEST_LOGIN_PROVIDER_DELETED,
            row,
            f"Login-code {channel} provider removed; Wyfy Guest's default is used"
            + (" (by the Wyfy Guest team)" if actor.via_platform else ""),
            {"provider_type": row.provider_type},
        )
        return {"channel": channel, "effective_source": "wyfy"}

    # -- verify --------------------------------------------------------------

    def _challenge_key(self, organization_id: uuid.UUID, channel: str) -> str:
        return f"guest_messaging:verify:{organization_id}:{channel}"

    async def _clear_challenge(self, organization_id: uuid.UUID, channel: str) -> None:
        try:
            await self.redis.delete(self._challenge_key(organization_id, channel))
        except Exception:  # noqa: BLE001
            logger.warning("guest_messaging_challenge_clear_failed", exc_info=True)

    def _build(self, row: Any) -> tuple[Any, dict[str, Any]]:
        from app.domains.marketing.providers import decrypt_config

        config = decrypt_config(row.config_encrypted, settings=self.settings)
        spec = self._spec(row.channel, row.provider_type)
        if spec is None:
            raise ProviderTypeNotSupportedError(
                f"'{row.provider_type}' is no longer a supported provider"
            )
        return spec.factory(config, self.adapter_context), config

    async def start_verification(
        self, organization_id: uuid.UUID, channel: str, actor: Actor, *, to: str
    ) -> dict[str, Any]:
        if actor.via_platform:
            await self._require_org(organization_id)
        elif not await self.byo_allowed(organization_id):
            raise ByoNotAllowedError(
                "Your own login messaging provider is not enabled for this account."
            )
        phone = normalize_phone(to)
        if phone is None:
            raise InvalidPhoneError(
                "Enter a mobile number with country code, e.g. +91 98765 43210"
            )
        row = await self._require_row(organization_id, channel)
        sends_key = f"guest_messaging:verify-sends:{organization_id}:{channel}"
        sends = await self.redis.incr(sends_key)
        if sends == 1:
            await self.redis.expire(sends_key, VERIFY_TTL_SECONDS)
        if sends > VERIFY_MAX_SENDS:
            raise VerificationRateLimitedError(
                "Too many verification codes; wait ten minutes and try again"
            )
        adapter, config = self._build(row)
        checks: list[dict[str, Any]] = []
        code = self._code()
        organization_name = await self.repository.organization_name(organization_id)
        text = (
            f"{code} is your verification code to connect "
            f"{organization_name or 'your venue'} to Wyfy Guest."
        )
        try:
            preflight = getattr(adapter, "preflight", None)
            if preflight is not None:
                for detail in await preflight():
                    checks.append({"name": "template", "ok": True, "detail": detail})
            result = await adapter.send_otp(OtpMessage(phone, code, text))
        except ProviderSendError as exc:
            detail = scrub(f"{exc.code}: {exc.message}", config) or exc.code
            await self.repository.update_provider(
                row,
                {
                    "status": "failed",
                    "enabled": False,
                    "last_error": detail,
                    "updated_by_user_id": actor.user_id,
                },
            )
            await self._audit(
                actor,
                organization_id,
                AuditAction.GUEST_LOGIN_PROVIDER_VERIFY_FAILED,
                row,
                f"Login-code {channel} provider could not send the verification code",
                {"provider_type": row.provider_type, "error_code": exc.code},
            )
            raise ProviderSendFailedError(
                "Your provider did not accept the verification code", detail=detail
            ) from exc
        challenge = {
            "hash": _hash(code),
            "version": int(row.version or 1),
            "provider_type": row.provider_type,
            "attempts": 0,
            "to": mask_phone(phone),
        }
        await self.redis.set(
            self._challenge_key(organization_id, channel),
            json.dumps(challenge),
            ex=VERIFY_TTL_SECONDS,
        )
        checks.append(
            {
                "name": "send",
                "ok": True,
                "detail": "Accepted by your provider"
                + (f" (id {result.message_id})" if result.message_id else "")
                + ". Enter the code that arrives to finish.",
            }
        )
        return {
            "sent_to": mask_phone(phone),
            "expires_in_seconds": VERIFY_TTL_SECONDS,
            "checks": checks,
        }

    async def confirm_verification(
        self, organization_id: uuid.UUID, channel: str, actor: Actor, *, code: str
    ) -> dict[str, Any]:
        if actor.via_platform:
            await self._require_org(organization_id)
        row = await self._require_row(organization_id, channel)
        key = self._challenge_key(organization_id, channel)
        raw = await self.redis.get(key)
        challenge = json.loads(raw) if raw else None
        if (
            not challenge
            or challenge.get("version") != int(row.version or 1)
            or challenge.get("provider_type") != row.provider_type
        ):
            raise VerificationNotStartedError(
                "Send a verification code first (or again, if the settings changed)"
            )
        if challenge.get("attempts", 0) >= VERIFY_MAX_ATTEMPTS:
            await self._clear_challenge(organization_id, channel)
            raise VerificationRateLimitedError("Too many wrong codes; send a new one")
        if not hmac.compare_digest(_hash((code or "").strip()), challenge["hash"]):
            challenge["attempts"] = challenge.get("attempts", 0) + 1
            ttl = await self.redis.ttl(key)
            await self.redis.set(
                key,
                json.dumps(challenge),
                ex=ttl if ttl and ttl > 0 else VERIFY_TTL_SECONDS,
            )
            raise VerificationCodeInvalidError("That code is not the one we sent")
        await self._clear_challenge(organization_id, channel)
        row = await self.repository.update_provider(
            row,
            {
                "status": "verified",
                "enabled": True,
                "last_verified_at": self._now(),
                "last_error": None,
                "verified_by_user_id": actor.user_id,
                "updated_by_user_id": actor.user_id,
                "configured_by_platform": actor.via_platform
                or bool(row.configured_by_platform),
                "fallback_count": 0,
                "last_fallback_at": None,
                "last_fallback_error": None,
            },
        )
        await self._audit(
            actor,
            organization_id,
            AuditAction.GUEST_LOGIN_PROVIDER_VERIFIED,
            row,
            f"Login-code {channel} provider verified; guest codes now go through it"
            + (" (by the Wyfy Guest team)" if actor.via_platform else ""),
            {"provider_type": row.provider_type, "sent_to": challenge.get("to")},
        )
        return await self.provider_view(
            row,
            effective=await self._effective(organization_id, row),
            for_platform=actor.via_platform,
        )

    # -- send-time resolution --------------------------------------------------

    async def resolve_sender(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        channel: str,
    ) -> ResolvedSender | None:
        """The venue's own sender for a guest login code, or ``None`` for the
        platform default. The organization comes from the location when one
        is named (the portal's request body is not trusted to pair them); a
        body naming a location of another organization gets the default."""
        org = organization_id
        if location_id is not None:
            location_org = await self.repository.location_organization(location_id)
            if location_org is None:
                return None
            if organization_id is not None and organization_id != location_org:
                return None
            org = location_org
        if org is None:
            return None
        row = await self.repository.get_provider(org, channel)
        if row is None or not row.enabled or row.status != "verified":
            return None
        if not await self.byo_allowed(org):
            return None
        adapter, config = self._build(row)
        return ResolvedSender(org, channel, row.id, row.provider_type, adapter, config)

    def _breaker_key(self, organization_id: uuid.UUID, channel: str) -> str:
        return f"guest_messaging:breaker:{organization_id}:{channel}"

    async def breaker_open(self, organization_id: uuid.UUID, channel: str) -> bool:
        """After a failure the venue's provider is skipped for a short while,
        so a dead vendor does not make every guest wait for its timeout."""
        try:
            return bool(
                await self.redis.get(self._breaker_key(organization_id, channel))
            )
        except Exception:  # noqa: BLE001
            return False

    async def record_fallback(
        self, sender: ResolvedSender, error: str, *, auth: bool = False
    ) -> None:
        now = self._now()
        detail = scrub(error, sender.config) or "error"
        try:
            await self.redis.set(
                self._breaker_key(sender.organization_id, sender.channel),
                "1",
                ex=BREAKER_SECONDS,
            )
        except Exception:  # noqa: BLE001
            logger.warning("guest_login_byo_breaker_set_failed", exc_info=True)
        await self.repository.record_fallback(sender.provider_id, at=now, error=detail)
        if auth:
            # Wrong or revoked credentials will not fix themselves: stop
            # trying until someone re-verifies, and say so on the card.
            row = await self.repository.get_provider(
                sender.organization_id, sender.channel
            )
            if row is not None and row.id == sender.provider_id:
                await self.repository.update_provider(
                    row, {"status": "failed", "enabled": False, "last_error": detail}
                )
        throttle = (
            f"guest_messaging:fallback-audit:{sender.organization_id}:{sender.channel}"
        )
        try:
            first = await self.redis.set(
                throttle, "1", ex=FALLBACK_AUDIT_EVERY_SECONDS, nx=True
            )
        except Exception:  # noqa: BLE001
            first = True
        if first and self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=None,
                action=AuditAction.GUEST_LOGIN_PROVIDER_FALLBACK.value,
                entity_type=ENTITY_TYPE,
                entity_id=sender.provider_id,
                organization_id=sender.organization_id,
                description=(
                    f"A guest login code could not go through the venue's own "
                    f"{sender.channel} provider and was sent by Wyfy Guest's default"
                ),
                event_metadata={
                    "channel": sender.channel,
                    "provider_type": sender.provider_type,
                    "error": detail,
                    "throttled_for_seconds": FALLBACK_AUDIT_EVERY_SECONDS,
                },
            )

    # -- audit -----------------------------------------------------------------

    async def _audit(
        self,
        actor: Actor,
        organization_id: uuid.UUID,
        action: AuditAction,
        row: Any,
        description: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor.user_id,
            action=action.value,
            entity_type=ENTITY_TYPE,
            entity_id=row.id,
            organization_id=organization_id,
            description=description,
            event_metadata={
                "channel": row.channel,
                "via": "master_console" if actor.via_platform else "customer_dashboard",
                **(metadata or {}),
            },
        )


class OrgOtpDispatcher:
    """What ``OtpService`` calls before its platform provider. Never raises:
    ``True`` = the venue's own provider accepted the code; ``False`` = use the
    platform default (no own provider, or it failed -- recorded)."""

    def __init__(self, service: LoginMessagingService, session: Any | None) -> None:
        self.service = service
        self.session = session

    def _savepoint(self):  # noqa: ANN202
        if self.session is None:
            from contextlib import nullcontext

            return _AsyncNull(nullcontext())
        return self.session.begin_nested()

    async def try_send(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        channel: str,
        phone: str,
        code: str,
        message: str,
    ) -> bool:
        if organization_id is None and location_id is None:
            return False
        try:
            async with self._savepoint():
                sender = await self.service.resolve_sender(
                    organization_id=organization_id,
                    location_id=location_id,
                    channel=channel,
                )
        except Exception:  # noqa: BLE001 - resolving must never fail a login
            logger.warning("guest_login_byo_resolve_failed", exc_info=True)
            return False
        if sender is None:
            return False
        if await self.service.breaker_open(sender.organization_id, channel):
            return False
        e164 = normalize_phone(phone) or phone
        try:
            result = await asyncio.wait_for(
                sender.adapter.send_otp(OtpMessage(e164, code, message)),
                timeout=SEND_DEADLINE_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 - any failure falls back
            if isinstance(exc, ProviderSendError):
                error = f"{exc.code}: {exc.message}"
            elif isinstance(exc, TimeoutError):
                error = "provider_timeout: no answer in time"
            else:
                error = f"provider_error: {type(exc).__name__}"
            logger.warning(
                "guest_login_byo_send_failed_falling_back",
                extra={
                    "organization_id": str(sender.organization_id),
                    "channel": channel,
                    "provider_type": sender.provider_type,
                    "error_code": getattr(exc, "code", type(exc).__name__),
                },
            )
            try:
                async with self._savepoint():
                    await self.service.record_fallback(
                        sender, error, auth=bool(getattr(exc, "auth", False))
                    )
            except Exception:  # noqa: BLE001
                logger.warning("guest_login_byo_fallback_record_failed", exc_info=True)
            return False
        logger.info(
            "guest_login_byo_sent",
            extra={
                "organization_id": str(sender.organization_id),
                "channel": channel,
                "provider_type": sender.provider_type,
                "provider_message_id": result.message_id,
            },
        )
        return True


class _AsyncNull:
    def __init__(self, inner: Any) -> None:
        self.inner = inner

    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc: object) -> bool:
        return False


__all__ = [
    "Actor",
    "LoginMessagingService",
    "OrgOtpDispatcher",
    "ResolvedSender",
    "mask_phone",
    "normalize_phone",
]
