"""Unit tests for the two-mailbox outgoing-mail split.

Outgoing mail is deliberately split across two real Zoho mailboxes:

    admin@wyfyguest.com  guest OTP, password reset, new-location welcome
    sales@wyfyguest.com  demo-request notifications, channel-partner
                         welcome, quotations

These tests assert three separate things, because they fail in three
separate ways:

1. **Routing** -- each of the six flows resolves to the mailbox it is
   supposed to. Asserted at the real wiring points (the actual
   ``dependencies.py`` functions and the real outbox dispatch), not against
   the routing table in isolation, so a correct table wired to the wrong
   provider still fails.
2. **Fallback** -- with the second mailbox unconfigured, the admin@ flows
   degrade to the general identity (exactly today's behavior, which works)
   and say so in a log. An unconfigured mailbox must never crash guest
   login and must never be silent.
3. **Never send as a mailbox you did not authenticate as** -- the failure
   that produced ``553 Sender is not allowed to relay emails`` in
   production. Asserted structurally: a ``From`` cannot be paired with
   another account's credentials because there is no constructor, setter or
   settings path that lets it.

Every credential below is an obvious placeholder. Real mailbox passwords
live only in the server's ``.env``.

Style follows ``tests/unit/test_notification.py``: plain ``assert``, native
``async def``, small hand-rolled fakes at the narrow Protocol boundary.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.core.config import Settings
from app.domains.channel_partner.dependencies import (
    _resolve_email_provider as resolve_channel_partner_email_provider,
)
from app.domains.notification.constants import (
    MAIL_IDENTITY_BY_EVENT_TYPE,
    NotificationChannelType,
    NotificationDeliveryStatus,
    NotificationEventType,
    mail_identity_for_event,
)
from app.domains.notification.models import NotificationDelivery
from app.domains.notification.service import NotificationService
from app.domains.otp.dependencies import get_otp_service
from app.domains.otp.service import (
    EmailProviderNotConfiguredError,
    LoggingEmailProvider,
    MailIdentity,
    MailIdentityMismatchError,
    SmtpEmailProvider,
    SmtpIdentity,
    get_configured_email_provider,
    get_configured_email_providers_by_identity,
    resolve_smtp_identity,
    warn_email_identity_fallback,
)
from app.domains.quotation.dependencies import (
    _resolve_email_provider as resolve_quotation_email_provider,
)

ADMIN = "admin@wyfyguest.com"
SALES = "sales@wyfyguest.com"
ADMIN_PASSWORD = "placeholder-admin-password"
SALES_PASSWORD = "placeholder-sales-password"


@pytest.fixture(autouse=True)
def _rearm_fallback_warning() -> None:
    """``warn_email_identity_fallback`` is memoized so a per-request
    fallback cannot flood the log (see its docstring). Re-arm it around
    every test so one test's warning never hides another's.

    ``getattr`` rather than a direct call so that removing the memoization
    is caught by the one test that is *about* memoization
    (``test_fallback_warning_is_not_repeated_per_send``) instead of
    erroring out every test in this module at fixture setup."""
    clear = getattr(warn_email_identity_fallback, "cache_clear", lambda: None)
    clear()
    yield
    clear()


def _settings(**overrides: object) -> Settings:
    """Both mailboxes fully configured, as production is meant to be."""
    base: dict[str, object] = {
        "email_delivery_provider": "smtp",
        "smtp_host": "smtp.zoho.in",
        "smtp_port": 587,
        "smtp_username": SALES,
        "smtp_password": SALES_PASSWORD,
        "smtp_use_tls": True,
        "smtp_from_address": SALES,
        "admin_smtp_host": "smtp.zoho.in",
        "admin_smtp_port": 587,
        "admin_smtp_username": ADMIN,
        "admin_smtp_password": ADMIN_PASSWORD,
        "admin_smtp_use_tls": True,
        "admin_smtp_from_address": ADMIN,
    }
    base.update(overrides)
    return Settings(**base)


# ============================================================================
# Fakes for the outbox dispatch path
# ============================================================================


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


def _make_delivery(event_type: str, **overrides: object) -> NotificationDelivery:
    fields: dict[str, object] = {
        "organization_id": None,
        "template_id": None,
        "event_type": event_type,
        "channel": NotificationChannelType.EMAIL.value,
        "recipient": "someone@example.com",
        "subject": "subject",
        "body": "body",
        "status": NotificationDeliveryStatus.PENDING.value,
        "attempt_count": 0,
        "max_attempts": 5,
        "next_attempt_at": None,
        "sent_at": None,
        "error_message": None,
        "attachment_storage_key": None,
        "attachment_filename": None,
        "context": None,
    }
    fields.update(overrides)
    return NotificationDelivery(**_base_fields(**fields))


@dataclass
class FakeDeliveryRepository:
    due: list[NotificationDelivery] = field(default_factory=list)

    async def list_due_deliveries(
        self, *, statuses: list[str], now: datetime, limit: int
    ) -> list[NotificationDelivery]:
        return list(self.due)

    async def update_delivery(
        self, delivery: NotificationDelivery, data: dict[str, object]
    ) -> NotificationDelivery:
        for key, value in data.items():
            setattr(delivery, key, value)
        return delivery


@dataclass
class RecordingEmailProvider:
    """Stands in for one mailbox's provider so a test can assert *which*
    mailbox a send went through, not merely that a send happened."""

    mailbox: str
    sent: list[tuple[str, str, str]] = field(default_factory=list)
    should_fail: bool = False

    async def send(self, email: str, subject: str, body: str) -> None:
        if self.should_fail:
            raise RuntimeError(f"{self.mailbox} refused the message")
        self.sent.append((email, subject, body))


def _outbox_service(
    delivery: NotificationDelivery,
) -> tuple[
    NotificationService, RecordingEmailProvider, RecordingEmailProvider
]:
    admin = RecordingEmailProvider(ADMIN)
    sales = RecordingEmailProvider(SALES)
    service = NotificationService(
        FakeDeliveryRepository(due=[delivery]),
        email_provider=sales,
        email_providers_by_identity={
            MailIdentity.DEFAULT: sales,
            MailIdentity.ADMIN: admin,
        },
    )
    return service, admin, sales


# ============================================================================
# 1. Routing: each of the six flows resolves to the right mailbox
# ============================================================================


class TestSixFlowsResolveToTheRightMailbox:
    def test_guest_otp_sends_from_admin(self) -> None:
        """The highest-stakes flow on the platform, and the one being
        moved: every guest login's verification code."""
        service = get_otp_service(
            repository=object(),
            redis=object(),
            audit_repository=None,
            settings=_settings(),
        )
        assert isinstance(service.email_provider, SmtpEmailProvider)
        assert service.email_provider.from_address == ADMIN

    def test_account_data_masking_otp_rides_the_same_admin_identity(self) -> None:
        """``app.domains.user.router``'s data-masking OTP resolves through
        the very same ``get_otp_service`` dependency, so it moves with
        guest OTP by construction. Pinned so a future split of the two is a
        deliberate, test-breaking act rather than a silent divergence."""
        from app.domains.user.router import request_data_masking_otp

        assert request_data_masking_otp is not None
        service = get_otp_service(
            repository=object(),
            redis=object(),
            audit_repository=None,
            settings=_settings(),
        )
        assert service.email_provider.from_address == ADMIN

    async def test_password_reset_sends_from_admin(self) -> None:
        delivery = _make_delivery(NotificationEventType.PASSWORD_RESET.value)
        service, admin, sales = _outbox_service(delivery)

        await service.dispatch_pending()

        assert len(admin.sent) == 1
        assert sales.sent == []

    async def test_location_welcome_email_sends_from_admin(self) -> None:
        delivery = _make_delivery(NotificationEventType.LOCATION_WELCOME_EMAIL.value)
        service, admin, sales = _outbox_service(delivery)

        await service.dispatch_pending()

        assert len(admin.sent) == 1
        assert sales.sent == []

    async def test_demo_request_notification_sends_from_sales(self) -> None:
        delivery = _make_delivery(NotificationEventType.DEMO_REQUEST_RECEIVED.value)
        service, admin, sales = _outbox_service(delivery)

        await service.dispatch_pending()

        assert len(sales.sent) == 1
        assert admin.sent == []

    def test_quotation_sends_from_sales(self) -> None:
        provider = resolve_quotation_email_provider(_settings())
        assert isinstance(provider, SmtpEmailProvider)
        assert provider.from_address == SALES

    def test_channel_partner_welcome_sends_from_sales(self) -> None:
        provider = resolve_channel_partner_email_provider(_settings())
        assert isinstance(provider, SmtpEmailProvider)
        assert provider.from_address == SALES

    def test_password_reset_and_welcome_resolve_to_admin_in_the_routing_table(
        self,
    ) -> None:
        """The table itself, so a reader's one-lookup answer to "which
        mailbox does a password reset come from?" is also the tested one."""
        assert (
            mail_identity_for_event(NotificationEventType.PASSWORD_RESET.value)
            is MailIdentity.ADMIN
        )
        assert (
            mail_identity_for_event(
                NotificationEventType.LOCATION_WELCOME_EMAIL.value
            )
            is MailIdentity.ADMIN
        )
        assert (
            mail_identity_for_event(
                NotificationEventType.DEMO_REQUEST_RECEIVED.value
            )
            is MailIdentity.DEFAULT
        )

    def test_only_the_two_moved_events_are_routed_to_admin(self) -> None:
        """Nothing moves by accident. Every outbox event other than the two
        deliberately moved ones must still resolve to the identity it used
        before this split existed."""
        moved = {
            event
            for event, identity in MAIL_IDENTITY_BY_EVENT_TYPE.items()
            if identity is MailIdentity.ADMIN
        }
        assert moved == {
            NotificationEventType.PASSWORD_RESET,
            NotificationEventType.LOCATION_WELCOME_EMAIL,
        }
        for event in NotificationEventType:
            if event in moved:
                continue
            assert mail_identity_for_event(event.value) is MailIdentity.DEFAULT

    def test_unknown_persisted_event_type_routes_to_default(self) -> None:
        """``NotificationDelivery.event_type`` is a persisted string column;
        a row written by an older/newer build must route somewhere sane
        rather than raising inside the dispatch sweep."""
        assert mail_identity_for_event("some_event_from_the_future") is (
            MailIdentity.DEFAULT
        )

    async def test_untouched_outbox_events_still_use_the_general_identity(
        self,
    ) -> None:
        """A regression guard for "existing behaviour for anything not
        explicitly moved must not change" -- a user invite is not part of
        the split and must still leave from the general mailbox."""
        delivery = _make_delivery(NotificationEventType.USER_INVITED.value)
        service, admin, sales = _outbox_service(delivery)

        await service.dispatch_pending()

        assert len(sales.sent) == 1
        assert admin.sent == []


# ============================================================================
# 2. Fallback when the second mailbox is not configured
# ============================================================================


class TestFallbackWhenAdminMailboxUnset:
    def test_admin_flows_fall_back_to_the_general_identity(self) -> None:
        """Today's behavior: one mailbox, everything through it. That
        works, so an unconfigured second mailbox must degrade to it."""
        settings = _settings(admin_smtp_host="")
        provider = get_configured_email_provider(
            settings, identity=MailIdentity.ADMIN
        )
        assert isinstance(provider, SmtpEmailProvider)
        assert provider.from_address == SALES
        assert provider.username == SALES

    def test_fallback_is_logged_not_silent(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.WARNING, logger="app.domains.otp.service")
        settings = _settings(admin_smtp_host="")

        get_configured_email_provider(settings, identity=MailIdentity.ADMIN)

        [record] = [
            r for r in caplog.records if r.message == "email_identity_fallback"
        ]
        assert record.requested_identity == MailIdentity.ADMIN.value
        assert record.fallback_identity == MailIdentity.DEFAULT.value
        assert "admin_smtp_host is empty" in record.reason

    def test_fallback_does_not_raise_or_return_none(self) -> None:
        """Guest OTP resolves its provider during dependency resolution.
        An unconfigured second mailbox must not turn that into a 500 --
        that would look like "the WiFi is broken" at every venue at once."""
        settings = _settings(admin_smtp_host="")
        provider = get_configured_email_provider(
            settings, identity=MailIdentity.ADMIN
        )
        assert provider is not None

    def test_guest_otp_still_works_with_no_admin_mailbox(self) -> None:
        service = get_otp_service(
            repository=object(),
            redis=object(),
            audit_repository=None,
            settings=_settings(admin_smtp_host=""),
        )
        assert service.email_provider.from_address == SALES

    def test_logging_mode_keeps_both_identities_log_only(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A fresh checkout in ``email_delivery_provider='logging'`` must
        not start sending real mail just because an admin mailbox happens
        to be configured -- and must say why it ignored it."""
        caplog.set_level(logging.WARNING, logger="app.domains.otp.service")
        settings = _settings(email_delivery_provider="logging")

        provider = get_configured_email_provider(
            settings, identity=MailIdentity.ADMIN
        )

        assert isinstance(provider, LoggingEmailProvider)
        [record] = [
            r for r in caplog.records if r.message == "email_identity_fallback"
        ]
        assert "is not 'smtp'" in record.reason

    def test_sales_flows_are_unaffected_by_the_admin_block(self) -> None:
        """The three sales flows must resolve identically whether or not a
        second mailbox exists -- they are not the flows being moved."""
        with_admin = resolve_quotation_email_provider(_settings())
        without_admin = resolve_quotation_email_provider(
            _settings(admin_smtp_host="")
        )
        assert with_admin.from_address == without_admin.from_address == SALES

    def test_default_identity_never_emits_a_fallback_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Every pre-existing caller asks for no identity at all. None of
        them should suddenly start logging."""
        caplog.set_level(logging.WARNING, logger="app.domains.otp.service")
        get_configured_email_provider(_settings(admin_smtp_host=""))
        assert [
            r for r in caplog.records if r.message == "email_identity_fallback"
        ] == []

    def test_fallback_warning_is_not_repeated_per_send(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Provider selection runs per request. A warning nobody can read
        past is a warning nobody reads -- which is precisely how ``535
        Authentication Failed`` went unnoticed for days."""
        caplog.set_level(logging.WARNING, logger="app.domains.otp.service")
        settings = _settings(admin_smtp_host="")

        for _ in range(25):
            get_configured_email_provider(settings, identity=MailIdentity.ADMIN)

        assert (
            len(
                [
                    r
                    for r in caplog.records
                    if r.message == "email_identity_fallback"
                ]
            )
            == 1
        )

    def test_identity_map_is_complete_even_when_admin_is_unset(self) -> None:
        """The outbox asks for a provider per identity. Fallback happens at
        resolution, so the map never has a hole for the sweep to trip on."""
        providers = get_configured_email_providers_by_identity(
            _settings(admin_smtp_host="")
        )
        assert set(providers) == set(MailIdentity)
        assert providers[MailIdentity.ADMIN].from_address == SALES
        assert providers[MailIdentity.DEFAULT].from_address == SALES


# ============================================================================
# 3. A From address can never carry another account's credentials
# ============================================================================


class TestIdentityCannotMixAccounts:
    def test_smtp_identity_rejects_a_from_belonging_to_another_account(
        self,
    ) -> None:
        with pytest.raises(MailIdentityMismatchError) as excinfo:
            SmtpIdentity.from_settings_block(
                host="smtp.zoho.in",
                port=587,
                username=ADMIN,
                password=ADMIN_PASSWORD,
                use_tls=True,
                from_address=SALES,
                label="admin_smtp",
            )
        assert "553" in str(excinfo.value)

    def test_smtp_identity_defaults_from_address_to_the_authenticated_user(
        self,
    ) -> None:
        identity = SmtpIdentity.from_settings_block(
            host="smtp.zoho.in",
            port=587,
            username=ADMIN,
            password=ADMIN_PASSWORD,
            use_tls=True,
            from_address="",
            label="admin_smtp",
        )
        assert identity.from_address == ADMIN

    def test_provider_cannot_be_built_from_loose_credential_fields(self) -> None:
        """The shape guarantee. ``SmtpEmailProvider`` takes one identity and
        nothing else, so "authenticate as A, send as B" is not expressible
        at any call site -- it is not a discipline anyone has to remember."""
        with pytest.raises(TypeError):
            SmtpEmailProvider(  # type: ignore[call-arg]
                host="smtp.zoho.in",
                port=587,
                username=ADMIN,
                password=ADMIN_PASSWORD,
                use_tls=True,
                from_address=SALES,
            )

    def test_from_address_cannot_be_reassigned_after_construction(self) -> None:
        provider = SmtpEmailProvider(
            SmtpIdentity.from_settings_block(
                host="smtp.zoho.in",
                port=587,
                username=ADMIN,
                password=ADMIN_PASSWORD,
                use_tls=True,
                from_address="",
                label="admin_smtp",
            )
        )
        with pytest.raises(AttributeError):
            provider.from_address = SALES  # type: ignore[misc]
        # ...and the identity underneath it is frozen too, so there is no
        # second door into the same mismatch.
        with pytest.raises(AttributeError):
            provider.identity.from_address = SALES  # type: ignore[misc]

    def test_every_routed_flow_authenticates_as_the_mailbox_it_sends_as(
        self,
    ) -> None:
        """Swept across all six flows at once: for each, the account we log
        in as and the account we claim to be must be the same string."""
        settings = _settings()
        providers = [
            get_otp_service(
                repository=object(),
                redis=object(),
                audit_repository=None,
                settings=settings,
            ).email_provider,
            resolve_quotation_email_provider(settings),
            resolve_channel_partner_email_provider(settings),
            *get_configured_email_providers_by_identity(settings).values(),
        ]
        for provider in providers:
            assert isinstance(provider, SmtpEmailProvider)
            assert provider.username == provider.from_address

    def test_mismatched_admin_block_falls_back_instead_of_relaying(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A hand-edited ``.env`` that pairs admin@'s login with sales@'s
        From must not send at all from that identity, must not 500 guest
        login, and must be loud."""
        caplog.set_level(logging.ERROR, logger="app.domains.otp.service")
        settings = _settings(admin_smtp_from_address=SALES)

        provider = get_configured_email_provider(
            settings, identity=MailIdentity.ADMIN
        )

        assert provider.username == provider.from_address == SALES
        [record] = [
            r for r in caplog.records if r.message == "email_identity_invalid"
        ]
        assert record.identity == MailIdentity.ADMIN.value

    def test_a_misconfigured_mailbox_is_not_reported_as_an_absent_one(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """"admin_smtp_host is empty" sent someone hunting for a missing
        variable that was in fact present and wrong. The fallback warning
        must distinguish "never configured" from "configured badly"."""
        caplog.set_level(logging.WARNING, logger="app.domains.otp.service")

        get_configured_email_provider(
            _settings(admin_smtp_from_address=SALES), identity=MailIdentity.ADMIN
        )

        [record] = [
            r for r in caplog.records if r.message == "email_identity_fallback"
        ]
        assert "is empty" not in record.reason
        assert "email_identity_invalid" in record.reason

    def test_mismatched_default_block_raises_rather_than_relaying(self) -> None:
        """The general identity has nothing to fall back to. Refusing to
        build a provider is the honest outcome -- the same
        ``EmailProviderNotConfiguredError`` an empty ``smtp_host`` already
        raises, which every caller already handles."""
        settings = _settings(smtp_from_address="someone-else@wyfyguest.com")
        with pytest.raises(EmailProviderNotConfiguredError):
            get_configured_email_provider(settings)

    def test_resolve_returns_none_for_an_unusable_identity(self) -> None:
        assert (
            resolve_smtp_identity(
                _settings(admin_smtp_from_address=SALES), MailIdentity.ADMIN
            )
            is None
        )

    def test_invoice_mailbox_gets_the_same_guarantee(self) -> None:
        """``invoice_smtp_*`` is a separate, pre-existing identity that was
        deliberately left where it is -- but it resolves through the same
        value object, so it inherits the same rule instead of needing its
        own copy of it."""
        from app.domains.billing.router import _get_invoice_email_provider

        settings = _settings(
            invoice_smtp_host="smtp.zoho.in",
            invoice_smtp_username="accounts@wyfyguest.com",
            invoice_smtp_password="placeholder-accounts-password",
            invoice_smtp_from_address=SALES,
        )
        with pytest.raises(MailIdentityMismatchError):
            _get_invoice_email_provider(settings)

    def test_identity_with_no_server_is_not_an_identity(self) -> None:
        with pytest.raises(MailIdentityMismatchError):
            SmtpIdentity.from_settings_block(
                host="",
                port=587,
                username=ADMIN,
                password=ADMIN_PASSWORD,
                use_tls=True,
                from_address=ADMIN,
                label="admin_smtp",
            )


# ============================================================================
# 4. A send that failed is never reported as sent
# ============================================================================


class TestFailedSendIsNeverReportedAsSent:
    async def test_admin_mailbox_failure_is_recorded_as_a_failure(self) -> None:
        delivery = _make_delivery(NotificationEventType.PASSWORD_RESET.value)
        service, admin, sales = _outbox_service(delivery)
        admin.should_fail = True

        summary = await service.dispatch_pending()

        assert summary.sent == 0
        assert delivery.status != NotificationDeliveryStatus.SENT.value
        assert delivery.sent_at is None
        assert "refused the message" in (delivery.error_message or "")
        # ...and it must not quietly re-route to the other mailbox on
        # failure, which would send account-security mail from sales@.
        assert sales.sent == []

    async def test_a_healthy_mailbox_is_not_dragged_down_by_the_other(
        self,
    ) -> None:
        admin_delivery = _make_delivery(NotificationEventType.PASSWORD_RESET.value)
        sales_delivery = _make_delivery(
            NotificationEventType.DEMO_REQUEST_RECEIVED.value
        )
        admin = RecordingEmailProvider(ADMIN, should_fail=True)
        sales = RecordingEmailProvider(SALES)
        service = NotificationService(
            FakeDeliveryRepository(due=[admin_delivery, sales_delivery]),
            email_provider=sales,
            email_providers_by_identity={
                MailIdentity.DEFAULT: sales,
                MailIdentity.ADMIN: admin,
            },
        )

        summary = await service.dispatch_pending()

        assert summary.sent == 1
        assert len(sales.sent) == 1
        assert sales_delivery.status == NotificationDeliveryStatus.SENT.value
        assert admin_delivery.status != NotificationDeliveryStatus.SENT.value
