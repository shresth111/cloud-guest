"""Own-provider CRUD, verify, WABA template sync and the Master read-only
view (spec §12.4).

Every public method takes the organization from the caller's scope (never a
path or body) and returns :func:`provider_view` output -- the only shape any
endpoint emits. It carries the ``display`` stub (non-secret fields plus
``{set, hint}`` per secret) and never the decrypted config or the ciphertext.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings
from app.domains.rbac.enums import AuditAction

from .constants import (
    CHANNEL_ORDER,
    SAMPLE_GUEST_NAME,
    SAMPLE_UNSUBSCRIBE_TOKEN,
    Channel,
)
from .exceptions import (
    InvalidAddressError,
    MarketingNotFoundError,
    MarketingValidationError,
    OrganizationNotFoundForMarketingError,
    ProviderConfigInvalidError,
    ProviderEncryptionUnavailableHttpError,
    ProviderNotVerifiedError,
    ProviderSenderConflictError,
    ProviderTypeNotSupportedError,
    SmtpHostNotAllowedHttpError,
    TemplateNotFoundError,
)
from .providers import (
    OwnSenders,
    ProviderConfigError,
    ProviderEncryptionUnavailableError,
    Resolver,
    SmtpHostNotAllowedError,
    build_display,
    build_own_senders,
    decrypt_config,
    encrypt_config,
    normalize_config,
    placeholder_count,
    scrub,
    spec_for,
    system_resolver,
    verify_provider,
    vet_smtp_host,
)
from .repository import MarketingRepository
from .service import (
    CallerScope,
    MarketingService,
    provider_display_name,
    provider_sender_label,
)
from .validators import normalize_address, render, utc_iso

logger = logging.getLogger(__name__)


def _wyfy_senders(settings: Settings) -> set[str]:
    """Every sender identity Wyfy itself uses (OTP and marketing): a venue's
    own provider may not claim one (409 ``provider_sender_conflict``)."""
    values = {
        settings.ping4sms_sender_id,
        settings.exotel_from_number,
        settings.marketing_sms_sender_id,
        settings.twilio_from_number,
        settings.whatsapp_twilio_from_number,
        settings.marketing_whatsapp_from_number,
        settings.smtp_from_address,
        settings.smtp_username,
        settings.admin_smtp_from_address,
        settings.admin_smtp_username,
        settings.marketing_email_from_address,
        settings.marketing_smtp_from_address,
        settings.marketing_smtp_username,
        settings.ses_from_address,
    }
    return {str(v).strip().lower() for v in values if v}


class ProviderService:
    def __init__(
        self,
        repository: MarketingRepository,
        *,
        settings: Settings,
        marketing: MarketingService,
        audit_writer: Any | None = None,
        resolver: Resolver = system_resolver,
        own_sender_builder: Callable[[str, dict[str, Any]], OwnSenders] | None = None,
        organization_exists: Callable[[uuid.UUID], Awaitable[bool]] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.marketing = marketing
        self.audit_writer = audit_writer
        self.resolver = resolver
        self.own_sender_builder = own_sender_builder or (
            lambda provider_type, config: build_own_senders(
                provider_type, config, settings=settings, resolver=resolver
            )
        )
        self.organization_exists = organization_exists
        self._now = now or (lambda: datetime.now(UTC))

    # -- views -------------------------------------------------------------

    async def provider_view(self, row: Any, *, effective: bool) -> dict[str, Any]:
        names = (
            await self.repository.get_user_names([row.updated_by_user_id])
            if row.updated_by_user_id
            else {}
        )
        return {
            "channel": row.channel,
            "provider_type": row.provider_type,
            "enabled": bool(row.enabled),
            "status": row.status,
            "last_verified_at": utc_iso(row.last_verified_at),
            "last_error": row.last_error,
            "effective": effective,
            "display": dict(row.display or {}),
            "updated_at": utc_iso(row.updated_at),
            "updated_by": {
                "id": str(row.updated_by_user_id),
                "name": names.get(row.updated_by_user_id),
            }
            if row.updated_by_user_id
            else None,
        }

    async def _effective(self, organization_id: uuid.UUID, channel: Channel) -> bool:
        resolution = (await self.marketing.resolve_providers(organization_id))[channel]
        return resolution.own

    async def list_providers(self, scope: CallerScope) -> dict[str, Any]:
        resolutions = await self.marketing.resolve_providers(scope.organization_id)
        channels = []
        for channel in CHANNEL_ORDER:
            resolution = resolutions[channel]
            channels.append(
                {
                    "channel": channel.value,
                    "effective_source": resolution.source,
                    "own": await self.provider_view(
                        resolution.row, effective=resolution.own
                    )
                    if resolution.row is not None
                    else None,
                }
            )
        return {"channels": channels}

    async def _require_row(self, scope: CallerScope, channel: Channel) -> Any:
        row = await self.repository.get_provider(scope.organization_id, channel.value)
        if row is None:
            raise MarketingNotFoundError("No own provider is set up for this channel")
        return row

    async def get_provider(
        self, scope: CallerScope, channel: Channel
    ) -> dict[str, Any]:
        row = await self._require_row(scope, channel)
        return await self.provider_view(
            row, effective=await self._effective(scope.organization_id, channel)
        )

    # -- PUT ---------------------------------------------------------------

    async def put_provider(
        self,
        scope: CallerScope,
        channel: Channel,
        *,
        provider_type: str | None,
        config: dict[str, Any],
        enabled: bool | None,
    ) -> tuple[dict[str, Any], bool]:
        existing = await self.repository.get_provider(
            scope.organization_id, channel.value
        )
        if existing is None and not provider_type:
            raise ProviderConfigInvalidError(
                "provider_type is required", fields={"provider_type": "required"}
            )
        new_type = provider_type or existing.provider_type
        spec = spec_for(channel, new_type)
        if spec is None:
            raise ProviderTypeNotSupportedError(
                f"'{new_type}' is not a supported {channel.value} provider"
            )
        cleared = [
            name
            for name in spec.secrets
            if name in config and config[name] in (None, "")
        ]
        if cleared:
            raise ProviderConfigInvalidError(
                "A secret cannot be blanked; send it only to change it, or "
                "DELETE the provider to remove it",
                fields={name: "cannot be empty" for name in cleared},
            )
        replace = existing is None or existing.provider_type != new_type
        stored: dict[str, Any] = {}
        if replace:
            merged = dict(config)
        else:
            stored = decrypt_config(existing.config_encrypted, settings=self.settings)
            merged = {**stored, **config}
            for name, value in config.items():
                if value is None:
                    merged.pop(name, None)
        try:
            normalized = normalize_config(spec, merged)
        except ProviderConfigError as exc:
            raise ProviderConfigInvalidError(
                "The provider settings are not valid", fields=exc.fields
            ) from exc
        if spec.provider_type == "smtp":
            try:
                await asyncio.to_thread(
                    vet_smtp_host,
                    normalized["host"],
                    normalized["port"],
                    resolver=self.resolver,
                    settings=self.settings,
                )
            except SmtpHostNotAllowedError as exc:
                raise SmtpHostNotAllowedHttpError(
                    f"SMTP host not allowed: {exc.reason}", host=exc.host
                ) from exc
        sender_value = normalized.get(spec.sender_field or "")
        if sender_value and str(sender_value).strip().lower() in _wyfy_senders(
            self.settings
        ):
            raise ProviderSenderConflictError(
                "This sender belongs to Wyfy's own platform account"
            )
        changed = replace or normalized != stored
        status = "unverified" if changed else existing.status
        if enabled is True and status != "verified":
            raise ProviderNotVerifiedError(
                "Verify the provider before enabling it", status=status
            )
        if enabled is not None:
            new_enabled = enabled
        else:
            new_enabled = bool(existing.enabled) if existing is not None else False
        fields: dict[str, Any] = {
            "enabled": new_enabled,
            "updated_by_user_id": scope.actor_user_id,
        }
        changed_fields: list[str] = []
        if changed:
            try:
                ciphertext = encrypt_config(normalized, settings=self.settings)
            except ProviderEncryptionUnavailableError as exc:
                raise ProviderEncryptionUnavailableHttpError(
                    "Own-provider credentials cannot be stored until the platform "
                    "encryption key is configured"
                ) from exc
            display = build_display(spec, normalized)
            if (
                existing is not None
                and not replace
                and spec.provider_type == "meta_cloud"
                and (existing.display or {}).get("display_phone_number")
            ):
                display["display_phone_number"] = existing.display[
                    "display_phone_number"
                ]
            fields.update(
                {
                    "provider_type": new_type,
                    "config_encrypted": ciphertext,
                    "display": display,
                    "status": "unverified",
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
                organization_id=scope.organization_id,
                channel=channel.value,
                created_by=scope.actor_user_id,
                **fields,
            )
        else:
            was_enabled = bool(existing.enabled)
            row = await self.repository.update_provider(existing, fields)
            if new_enabled and not was_enabled:
                await self._audit(
                    scope,
                    AuditAction.MARKETING_PROVIDER_ENABLED,
                    row,
                    "Own provider enabled; the venue accepted responsibility "
                    "for registration and compliance of messages sent through "
                    "its own account",
                )
        await self._audit(
            scope,
            AuditAction.MARKETING_PROVIDER_UPDATED,
            row,
            f"Own {channel.value} provider {'created' if created else 'updated'}",
            {
                "provider_type": new_type,
                # Names only -- never values.
                "changed_fields": changed_fields,
                "enabled": new_enabled,
            },
        )
        view = await self.provider_view(
            row, effective=await self._effective(scope.organization_id, channel)
        )
        return view, created

    # -- DELETE ------------------------------------------------------------

    async def delete_provider(
        self, scope: CallerScope, channel: Channel
    ) -> dict[str, Any]:
        row = await self._require_row(scope, channel)
        affected = await self.repository.count_active_campaigns_for(
            scope.organization_id, org_provider_id=row.id
        )
        await self.repository.soft_delete_provider(row)
        await self._audit(
            scope,
            AuditAction.MARKETING_PROVIDER_DELETED,
            row,
            f"Own {channel.value} provider removed",
            {"affected_campaign_count": affected},
        )
        return {
            "channel": channel.value,
            "effective_source": "wyfy",
            "affected_campaign_count": affected,
        }

    # -- verify ------------------------------------------------------------

    async def verify(
        self,
        scope: CallerScope,
        channel: Channel,
        *,
        test_to: str | None,
        template_id: uuid.UUID | None,
    ) -> dict[str, Any]:
        row = await self._require_row(scope, channel)
        config = decrypt_config(row.config_encrypted, settings=self.settings)
        senders = self.own_sender_builder(row.provider_type, config)
        test_send = await self._test_send_for(
            scope, channel, row, senders, test_to, template_id
        )
        result = await verify_provider(
            row.provider_type, config, senders, test_send=test_send
        )
        now = self._now()
        data: dict[str, Any] = {
            "status": "verified" if result.ok else "failed",
            "last_error": None if result.ok else scrub(result.first_error(), config),
            "verified_by_user_id": scope.actor_user_id,
            "updated_by_user_id": scope.actor_user_id,
        }
        if result.ok:
            data["last_verified_at"] = now
        if result.display_phone_number:
            data["display"] = {
                **(row.display or {}),
                "display_phone_number": result.display_phone_number,
            }
        row = await self.repository.update_provider(row, data)
        await self._audit(
            scope,
            AuditAction.MARKETING_PROVIDER_VERIFIED,
            row,
            f"Own {channel.value} provider verification: {row.status}",
            {"checks": [{"name": c.name, "ok": c.ok} for c in result.checks]},
        )
        return {
            "provider": await self.provider_view(
                row, effective=await self._effective(scope.organization_id, channel)
            ),
            "checks": [check.as_dict() for check in result.checks],
        }

    async def _test_send_for(
        self,
        scope: CallerScope,
        channel: Channel,
        row: Any,
        senders: OwnSenders,
        test_to: str | None,
        template_id: uuid.UUID | None,
    ):
        if channel in (Channel.SMS, Channel.EMAIL) and not test_to:
            raise MarketingValidationError("test_to is required for this channel")
        if channel is Channel.SMS and template_id is None:
            raise MarketingValidationError(
                "template_id is required: an org template with its own DLT id "
                "(a free-text SMS would be dropped by carriers)"
            )
        if not test_to:
            return None
        address = normalize_address(channel, test_to)
        if address is None:
            raise InvalidAddressError("test_to is not valid for this channel")
        organization = await self.marketing._organization(scope.organization_id)
        values = self.marketing._values(
            {"venue_name": organization.name, "location_name": organization.name},
            {},
            guest_name=SAMPLE_GUEST_NAME,
            token=SAMPLE_UNSUBSCRIBE_TOKEN,
        )
        template = None
        if template_id is not None:
            template = await self.repository.get_template(
                scope.organization_id, template_id
            )
            if template is None or template.organization_id is None:
                raise TemplateNotFoundError(
                    "Template not found among your own templates"
                )
        if channel is Channel.SMS:
            if not template.sms_body or not template.sms_dlt_template_id:
                raise MarketingValidationError(
                    "The template needs an SMS body and its own DLT template id"
                )
            body = "[TEST] " + render(template.sms_body, values)
            dlt = template.sms_dlt_template_id

            async def send():
                return await senders.sms.send(address, body, dlt_template_id=dlt)

        elif channel is Channel.EMAIL:

            async def send():
                return await senders.email.send(
                    address,
                    subject=f"[TEST] {organization.name}: your email provider works",
                    html_body=(
                        "<p>This is a test message from Wyfy Guest, sent through "
                        "your own email account.</p>"
                    ),
                    from_name=organization.name,
                    headers={},
                )

        else:
            if template is None:
                return None
            if template.whatsapp_source != "own_waba":
                raise MarketingValidationError(
                    "Pick a template synced from your WhatsApp Business Account"
                )
            order = list(template.whatsapp_variable_order or [])
            if len(order) != placeholder_count(template.whatsapp_body):
                raise MarketingValidationError("Map every {{n}} placeholder first")
            parameters = [values.get(name, "") for name in order]

            async def send():
                return await senders.whatsapp.send_waba_template(
                    address,
                    template_name=template.whatsapp_provider_template_name,
                    language=template.whatsapp_provider_language or "en",
                    parameters=parameters,
                )

        await self.marketing._consume_test_quota(scope.organization_id, 1)
        return send

    # -- Master (platform, read-only) --------------------------------------

    async def platform_view(self, organization_id: uuid.UUID) -> dict[str, Any]:
        if self.organization_exists is not None and not await self.organization_exists(
            organization_id
        ):
            raise OrganizationNotFoundForMarketingError("Organization not found")
        resolutions = await self.marketing.resolve_providers(organization_id)
        channels = []
        for channel in CHANNEL_ORDER:
            resolution = resolutions[channel]
            row = resolution.row
            channels.append(
                {
                    "channel": channel.value,
                    "effective_source": resolution.source,
                    # No display hints, no secrets: Master support needs neither.
                    "own": {
                        "provider_type": row.provider_type,
                        "enabled": bool(row.enabled),
                        "status": row.status,
                        "last_verified_at": utc_iso(row.last_verified_at),
                        "last_error": row.last_error,
                        "sender_label": provider_sender_label(row),
                        "display_name": provider_display_name(row),
                    }
                    if row is not None
                    else None,
                }
            )
        return {"organization_id": str(organization_id), "channels": channels}

    # -- audit -------------------------------------------------------------

    async def _audit(
        self,
        scope: CallerScope,
        action: AuditAction,
        row: Any,
        description: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=scope.actor_user_id,
            action=action.value,
            entity_type="org_marketing_provider",
            entity_id=row.id,
            organization_id=scope.organization_id,
            description=description,
            event_metadata={"channel": row.channel, **(metadata or {})},
        )


__all__ = ["ProviderService"]
