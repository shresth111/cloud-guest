"""Guest Marketing bring-your-own providers (spec §12, BE-11a/BE-11b).

Security properties under test, each revert-checked while building:

* no endpoint output (list, get, put, delete, verify, sync, Master) ever
  contains a secret, any part of one except the 4-char hint, or the
  ciphertext -- for every provider type (the Omada ``securityKey`` lesson);
* the SMTP SSRF guard refuses internal addresses on save AND on every
  connect (DNS rebinding);
* a campaign snapshotted to an own provider NEVER sends through Wyfy: an
  auth error trips the row and fails the remaining recipients with
  ``own_provider_failed``; the Wyfy fake sender is never called;
* scheduling through Wyfy while an own provider exists but is unusable needs
  ``acknowledge_wyfy_fallback`` (Q11 = Option A);
* BYO is its own paid add-on: locking it cancels own-snapshotted campaigns
  only, and it is off whenever Guest Marketing itself is off;
* the permission is ORGANIZATION-pinned: a location grant cannot satisfy it,
  and an org caller without ``marketing_providers.manage`` is refused.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.domains.marketing.constants import CampaignStatus, Channel, RecipientStatus
from app.domains.marketing.exceptions import (
    OwnProviderUnacknowledgedError,
    ProviderConfigInvalidError,
    ProviderEncryptionUnavailableHttpError,
    ProviderNotVerifiedError,
    ProviderSenderConflictError,
    ProviderTypeNotSupportedError,
    SmtpHostNotAllowedHttpError,
    SyncedTemplateReadOnlyError,
)
from app.domains.marketing.provider_service import ProviderService
from app.domains.marketing.providers import (
    PROVIDER_SPECS,
    GuardedSMTP,
    MetaCloudWhatsAppSender,
    OwnSenders,
    SmtpHostNotAllowedError,
    VerifyCheck,
    assert_provider_key_safe,
    ip_is_blocked,
    secret_hint,
    vet_smtp_host,
    waba_template_body,
)
from app.domains.marketing.schemas import TemplateUpdate
from app.domains.marketing.senders import ProviderResult, SendError
from app.domains.marketing.service import MarketingService
from tests.unit.test_guest_marketing import (
    NOW,
    ORG_A,
    ORG_B,
    FakeEmailSender,
    FakeRepo,
    _campaign,
    _row,
    _scope,
    _senders,
    _settings,
    _world,
)

PUBLIC_IP = "93.184.216.34"

SECRETS = {
    "ping4sms": {"api_key": "Zq7Kx9Pw2Lm4Vb8Nc0001"},
    "exotel": {
        "api_key": "Hj3Rt6Yu1Io5Pa9Sd0002",
        "api_token": "Fg2Hk7Jl4Zx8Cv1Bn0003",
    },
    "smtp": {"password": "Qw5Er8Ty2Ui6Op3As0004"},
    "ses": {
        "access_key_id": "Dk9Fj2Gh5Lz8Xc3Vb0005",
        "secret_access_key": "Nm4Qa7Ws1Ed6Rf9Tg0006",
    },
    "meta_cloud": {"access_token": "Yh3Uj8Ik2Ol5Pz9Mx0007"},
}
PLAIN = {
    "ping4sms": {"route": "2", "sender_id": "CAFEXY", "dlt_entity_id": "1101001"},
    "exotel": {
        "account_sid": "cafe1",
        "subdomain": "api.in.exotel.com",
        "sender_id": "CAFEEX",
        "dlt_entity_id": "1101002",
    },
    "smtp": {
        "host": "mail.cafe.example",
        "port": 587,
        "username": "offers@cafe.example",
        "from_address": "offers@cafe.example",
    },
    "ses": {"region": "ap-south-1", "from_address": "offers@cafe.example"},
    "meta_cloud": {"phone_number_id": "1234567890", "waba_id": "9876543210"},
}
CHANNEL_OF = {
    "ping4sms": Channel.SMS,
    "exotel": Channel.SMS,
    "smtp": Channel.EMAIL,
    "ses": Channel.EMAIL,
    "meta_cloud": Channel.WHATSAPP,
}


# ============================================================================
# Fakes
# ============================================================================


class ByoRepo(FakeRepo):
    async def get_provider(self, organization_id, channel):
        return (await self.list_providers(organization_id)).get(channel)

    async def create_provider(self, **fields):
        fields.setdefault("last_verified_at", None)
        fields.setdefault("last_error", None)
        fields.setdefault("verified_by_user_id", None)
        row = _row(**fields)
        self.providers[(fields["organization_id"], fields["channel"])] = row
        return row

    async def update_provider(self, row, data):
        for key, value in data.items():
            setattr(row, key, value)
        return row

    async def soft_delete_provider(self, row):
        row.is_deleted = True
        del self.providers[(row.organization_id, row.channel)]
        self.deleted_providers = [*getattr(self, "deleted_providers", []), row]

    async def get_provider_by_id(self, organization_id, provider_id):
        for row in [*self.providers.values(), *getattr(self, "deleted_providers", [])]:
            if row.organization_id == organization_id and row.id == provider_id:
                return row
        return None

    async def trip_provider(self, provider_id, last_error):
        for row in self.providers.values():
            if row.id == provider_id and row.status == "verified":
                row.status = "failed"
                row.last_error = last_error
                return True
        return False

    async def fail_unsent_recipients(
        self, campaign_id, *, error_code, error_message, claimed_ids=()
    ):
        count = 0
        for r in self.recipients.values():
            if r.campaign_id != campaign_id:
                continue
            if r.status == RecipientStatus.PENDING.value or (
                r.id in claimed_ids and r.status == RecipientStatus.SENDING.value
            ):
                r.status = RecipientStatus.FAILED.value
                r.error_code = error_code
                r.error_message = error_message
                count += 1
        if count:
            await self.adjust_counters(campaign_id, pending=-count, failed=count)
        return count

    async def count_active_campaigns_for(
        self, organization_id, *, own_only=False, org_provider_id=None
    ):
        return sum(
            1
            for c in self.campaigns.values()
            if c.organization_id == organization_id
            and c.status in ("scheduled", "sending")
            and (not own_only or getattr(c, "provider_source", "wyfy") == "own")
            and (
                org_provider_id is None
                or getattr(c, "org_provider_id", None) == org_provider_id
            )
        )

    async def list_synced_templates(self, organization_id):
        return [
            t
            for t in self.templates.values()
            if t.organization_id == organization_id
            and getattr(t, "whatsapp_source", None) == "own_waba"
            and not t.is_deleted
        ]

    async def update_template(self, template, data):
        for key, value in data.items():
            setattr(template, key, value)
        return template

    async def update_template_cas(self, template, *, expected_version, data):
        if template.version != expected_version:
            return False
        for key, value in data.items():
            setattr(template, key, value)
        template.version += 1
        return True


class FakeSms:
    provider = "ping4sms"

    def __init__(self, *, fail_auth: bool = False) -> None:
        self.sent: list[str] = []
        self.fail_auth = fail_auth

    async def send(self, phone, body, *, dlt_template_id):
        if self.fail_auth:
            raise SendError(
                "invalid_user",
                "ping4sms error 101 for key Zq7Kx9Pw2Lm4Vb8Nc0001",
                permanent=True,
                auth=True,
            )
        self.sent.append(phone)
        return ProviderResult("ping4sms", f"m{len(self.sent)}")


class OwnEmail(FakeEmailSender):
    provider = "smtp"

    def __init__(self, *, fail_auth_after: int | None = None) -> None:
        super().__init__()
        self.fail_auth_after = fail_auth_after

    async def send(self, email, *, subject, html_body, from_name, headers):
        if self.fail_auth_after is not None and len(self.sent) >= self.fail_auth_after:
            raise SendError(
                "provider_auth_failed",
                "535 auth failed for Qw5Er8Ty2Ui6Op3As0004",
                permanent=True,
                auth=True,
            )
        self.sent.append(email)
        return ProviderResult("smtp", f"own-{len(self.sent)}")


def _public_resolver(host, port):
    return [PUBLIC_IP]


def _byo_world(*, byo: bool = True, own_email: OwnEmail | None = None):
    world = _world()
    repo = ByoRepo(
        **{k: getattr(world.repo, k) for k in world.repo.__dataclass_fields__}
    )
    world.repo = repo
    own_email = own_email or OwnEmail()

    async def _byo(org):
        return byo

    def factory(row):
        return OwnSenders(
            row.provider_type,
            email=own_email,
            sms=FakeSms(),
            scrubber=lambda m: (m or "").replace("Qw5Er8Ty2Ui6Op3As0004", "***"),
        )

    async def _entitled(org):
        return True

    def service(**kwargs):
        return MarketingService(
            repo,
            settings=_settings(),
            senders=_senders(world.email),
            now=lambda: NOW,
            entitlement_check=_entitled,
            byo_entitlement_check=_byo,
            own_sender_factory=factory,
            **kwargs,
        )

    world.service = service  # type: ignore[method-assign]
    return world, own_email


def _provider_service(world, **kwargs) -> ProviderService:
    marketing = world.service()
    return ProviderService(
        world.repo,
        settings=_settings(),
        marketing=marketing,
        resolver=_public_resolver,
        now=lambda: NOW,
        **kwargs,
    )


async def _add_verified_smtp(world, *, enabled=True):
    service = _provider_service(world)
    await service.put_provider(
        _scope(),
        Channel.EMAIL,
        provider_type="smtp",
        config={**PLAIN["smtp"], **SECRETS["smtp"]},
        enabled=None,
    )
    row = await world.repo.get_provider(ORG_A, "email")
    row.status = "verified"
    row.enabled = enabled
    return row


# ============================================================================
# Masking: no secret or ciphertext in any output, for every provider type
# ============================================================================


def _assert_clean(payload: Any, provider_type: str, ciphertext: str) -> None:
    text = json.dumps(payload, default=str)
    for secret in SECRETS[provider_type].values():
        assert secret not in text, f"{provider_type}: full secret leaked"
        # No fragment longer than the 4-char hint.
        for i in range(len(secret) - 5):
            assert secret[i : i + 6] not in text, f"{provider_type}: fragment leaked"
    assert ciphertext not in text
    assert "config_encrypted" not in text


class TestNoSecretEverLeaves:
    @pytest.mark.parametrize("provider_type", sorted(SECRETS))
    async def test_every_endpoint_output_is_masked(self, provider_type: str) -> None:
        world, _ = _byo_world()
        channel = CHANNEL_OF[provider_type]
        verify_senders = OwnSenders(provider_type)

        async def _fake_verify(*args, **kwargs):
            raise AssertionError("not used")

        service = _provider_service(
            world, own_sender_builder=lambda t, c: verify_senders
        )
        put_view, created = await service.put_provider(
            _scope(),
            channel,
            provider_type=provider_type,
            config={**PLAIN[provider_type], **SECRETS[provider_type]},
            enabled=None,
        )
        assert created
        row = await world.repo.get_provider(ORG_A, channel.value)
        outputs = [
            put_view,
            await service.get_provider(_scope(), channel),
            await service.list_providers(_scope()),
            await service.platform_view(ORG_A),
        ]
        # Partial update keeps the secret and still leaks nothing.
        updated, _ = await service.put_provider(
            _scope(), channel, provider_type=None, config={}, enabled=None
        )
        outputs.append(updated)
        # Verify path, with a provider error that echoes the credential.
        import app.domains.marketing.provider_service as ps

        async def _verify(pt, config, senders, *, test_send):
            from app.domains.marketing.providers import VerifyResult, scrub

            secret = next(iter(SECRETS[provider_type].values()))
            result = VerifyResult(
                checks=[VerifyCheck("credentials", False, f"bad key {secret}")]
            )
            for check in result.checks:
                check.detail = scrub(check.detail, config)
            return result

        original = ps.verify_provider
        ps.verify_provider = _verify
        try:
            test_to = "+919876543210" if channel is Channel.SMS else "o@cafe.in"
            if channel is Channel.SMS:
                template = await world.repo.create_template(
                    organization_id=ORG_A,
                    name="Own SMS",
                    category="offer",
                    description=None,
                    sms_body="Hi {{unsubscribe_link}}",
                    sms_dlt_template_id="1107000000000000001",
                    whatsapp_approval_status="not_submitted",
                    system_key=None,
                )
                outputs.append(
                    await service.verify(
                        _scope(), channel, test_to=test_to, template_id=template.id
                    )
                )
            else:
                outputs.append(
                    await service.verify(
                        _scope(),
                        channel,
                        test_to=None if channel is Channel.WHATSAPP else test_to,
                        template_id=None,
                    )
                )
        finally:
            ps.verify_provider = original
        outputs.append(await service.delete_provider(_scope(), channel))
        for payload in outputs:
            _assert_clean(payload, provider_type, row.config_encrypted)
        # And the stored last_error is scrubbed too.
        assert all(
            s not in (row.last_error or "") for s in SECRETS[provider_type].values()
        )

    def test_hint_reveals_nothing_for_short_secrets(self) -> None:
        assert secret_hint("short-secret") == "…cret"  # exactly 12
        assert secret_hint("elevenchars") == "…"
        assert secret_hint(None) == "…"

    async def test_master_view_has_no_hints(self) -> None:
        world, _ = _byo_world()
        await _add_verified_smtp(world)
        view = await _provider_service(world).platform_view(ORG_A)
        own = next(c for c in view["channels"] if c["channel"] == "email")["own"]
        assert "display" not in own
        assert own["sender_label"] == "offers@cafe.example"
        assert "…" not in json.dumps(view)


# ============================================================================
# PUT semantics
# ============================================================================


class TestProviderPut:
    async def test_omitted_secret_is_kept_and_blank_secret_refused(self) -> None:
        world, _ = _byo_world()
        service = _provider_service(world)
        await service.put_provider(
            _scope(),
            Channel.SMS,
            provider_type="ping4sms",
            config={**PLAIN["ping4sms"], **SECRETS["ping4sms"]},
            enabled=None,
        )
        view, _ = await service.put_provider(
            _scope(),
            Channel.SMS,
            provider_type=None,
            config={"route": "3"},
            enabled=None,
        )
        assert view["display"]["api_key"] == {"set": True, "hint": "…0001"}
        assert view["display"]["route"] == "3"
        for blank in ("", None):
            with pytest.raises(ProviderConfigInvalidError):
                await service.put_provider(
                    _scope(),
                    Channel.SMS,
                    provider_type=None,
                    config={"api_key": blank},
                    enabled=None,
                )

    async def test_config_change_unverifies_and_enable_needs_verified(self) -> None:
        world, _ = _byo_world()
        row = await _add_verified_smtp(world, enabled=True)
        service = _provider_service(world)
        view, _ = await service.put_provider(
            _scope(),
            Channel.EMAIL,
            provider_type=None,
            config={"from_name": "Cafe"},
            enabled=None,
        )
        assert view["status"] == "unverified" and view["enabled"] is True
        assert view["effective"] is False  # §12.1: Wyfy until re-verified
        with pytest.raises(ProviderNotVerifiedError):
            await service.put_provider(
                _scope(), Channel.EMAIL, provider_type=None, config={}, enabled=True
            )
        assert row.status == "unverified"

    async def test_type_change_is_a_full_replace(self) -> None:
        world, _ = _byo_world()
        await _add_verified_smtp(world)
        service = _provider_service(world)
        with pytest.raises(ProviderConfigInvalidError) as excinfo:
            await service.put_provider(
                _scope(),
                Channel.EMAIL,
                provider_type="ses",
                config={"region": "ap-south-1"},
                enabled=None,
            )
        assert "secret_access_key" in excinfo.value.data["fields"]

    async def test_unsupported_pairs_and_bad_fields(self) -> None:
        world, _ = _byo_world()
        service = _provider_service(world)
        with pytest.raises(ProviderTypeNotSupportedError):
            await service.put_provider(
                _scope(), Channel.SMS, provider_type="smtp", config={}, enabled=None
            )
        with pytest.raises(ProviderConfigInvalidError) as excinfo:
            await service.put_provider(
                _scope(),
                Channel.EMAIL,
                provider_type="smtp",
                config={**PLAIN["smtp"], **SECRETS["smtp"], "port": 22, "evil": "x"},
                enabled=None,
            )
        assert excinfo.value.data["fields"]["port"] == "must be one of 25,465,587,2525"
        assert "evil" in excinfo.value.data["fields"]

    async def test_wyfy_sender_is_refused(self) -> None:
        world, _ = _byo_world()
        service = ProviderService(
            world.repo,
            settings=_settings(ping4sms_sender_id="CAFEXY"),
            marketing=world.service(),
            resolver=_public_resolver,
        )
        with pytest.raises(ProviderSenderConflictError):
            await service.put_provider(
                _scope(),
                Channel.SMS,
                provider_type="ping4sms",
                config={**PLAIN["ping4sms"], **SECRETS["ping4sms"]},
                enabled=None,
            )

    async def test_public_encryption_key_refuses_writes(self) -> None:
        world, _ = _byo_world()
        settings = _settings(environment="production")
        service = ProviderService(
            world.repo,
            settings=settings,
            marketing=world.service(),
            resolver=_public_resolver,
        )
        with pytest.raises(ProviderEncryptionUnavailableHttpError):
            await service.put_provider(
                _scope(),
                Channel.EMAIL,
                provider_type="smtp",
                config={**PLAIN["smtp"], **SECRETS["smtp"]},
                enabled=None,
            )
        assert await world.repo.get_provider(ORG_A, "email") is None
        assert assert_provider_key_safe(settings) is False
        assert assert_provider_key_safe(_settings()) is True  # local env

    async def test_org_b_cannot_see_org_a_provider(self) -> None:
        world, _ = _byo_world()
        await _add_verified_smtp(world)
        listed = await _provider_service(world).list_providers(_scope(ORG_B))
        assert all(c["own"] is None for c in listed["channels"])


# ============================================================================
# SSRF guard
# ============================================================================


class TestSsrfGuard:
    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ],
    )
    def test_internal_addresses_are_blocked(self, ip: str) -> None:
        assert ip_is_blocked(ip)

    def test_public_address_and_extra_cidr(self) -> None:
        assert not ip_is_blocked(PUBLIC_IP)
        assert ip_is_blocked(
            PUBLIC_IP,
            settings=_settings(marketing_smtp_blocked_cidrs="93.184.216.0/24"),
        )

    def test_mixed_answer_is_refused(self) -> None:
        with pytest.raises(SmtpHostNotAllowedError):
            vet_smtp_host("mail.x", 587, resolver=lambda h, p: [PUBLIC_IP, "10.0.0.5"])

    async def test_put_refuses_internal_smtp_host(self) -> None:
        world, _ = _byo_world()
        service = ProviderService(
            world.repo,
            settings=_settings(),
            marketing=world.service(),
            resolver=lambda h, p: ["169.254.169.254"],
        )
        with pytest.raises(SmtpHostNotAllowedHttpError):
            await service.put_provider(
                _scope(),
                Channel.EMAIL,
                provider_type="smtp",
                config={**PLAIN["smtp"], **SECRETS["smtp"]},
                enabled=None,
            )

    def test_every_connect_re_resolves_dns_rebinding(self) -> None:
        answers = iter([[PUBLIC_IP], ["127.0.0.1"]])

        def resolver(host, port):
            return next(answers)

        def vet(host, port):
            return vet_smtp_host(host, port, resolver=resolver)

        vet("mail.cafe.example", 587)  # save-time check passes
        with pytest.raises(SmtpHostNotAllowedError):
            GuardedSMTP("mail.cafe.example", 587, timeout=1, vet=vet)


# ============================================================================
# Resolution, status fields, schedule acknowledgement and snapshot
# ============================================================================


class TestResolution:
    async def test_effective_requires_enabled_verified_and_byo(self) -> None:
        for byo, enabled, status, expected in [
            (True, True, "verified", "own"),
            (False, True, "verified", "wyfy"),
            (True, False, "verified", "wyfy"),
            (True, True, "failed", "wyfy"),
        ]:
            world, _ = _byo_world(byo=byo)
            row = await _add_verified_smtp(world, enabled=enabled)
            row.status = status
            status_payload = await world.service().status(_scope())
            email = next(
                c for c in status_payload["channels"] if c["channel"] == "email"
            )
            assert email["provider_source"] == expected
            assert email["own_provider_status"] == status
            assert email["byo_entitled"] is byo
            assert email["own_provider_enabled"] is enabled
            assert email["requires_fallback_ack"] is (expected == "wyfy" and enabled)
            if expected == "own":
                assert (
                    email["provider_display_name"] == "Your SMTP (offers@cafe.example)"
                )
                assert email["configured"] is True

    async def test_status_without_own_row_reports_nulls(self) -> None:
        world, _ = _byo_world()
        payload = await world.service().status(_scope())
        for channel in payload["channels"]:
            assert channel["own_provider_enabled"] is None
            assert channel["own_provider_status"] is None
            assert channel["requires_fallback_ack"] is False
            assert channel["provider_source"] == "wyfy"

    async def test_unusable_own_provider_needs_acknowledgement(self) -> None:
        world, own_email = _byo_world()
        row = await _add_verified_smtp(world, enabled=True)
        row.status = "failed"
        service = world.service()
        created = await _campaign(world, _scope())
        with pytest.raises(OwnProviderUnacknowledgedError):
            await service.schedule(
                _scope(),
                uuid.UUID(created["id"]),
                scheduled_at=None,
                idempotency_key="ack-1234",
            )
        result = await service.schedule(
            _scope(),
            uuid.UUID(created["id"]),
            scheduled_at=None,
            idempotency_key="ack-5678",
            acknowledge_wyfy_fallback=True,
        )
        assert result["provider"] == {
            "source": "wyfy",
            "type": None,
            "display_name": "Wyfy default",
        }
        await service.send_batch(uuid.UUID(result["id"]))
        assert own_email.sent == [] and len(world.email.sent) == 2

    async def test_own_snapshot_sends_only_through_own(self) -> None:
        world, own_email = _byo_world()
        row = await _add_verified_smtp(world)
        service = world.service()
        created = await _campaign(world, _scope())
        result = await service.schedule(
            _scope(),
            uuid.UUID(created["id"]),
            scheduled_at=None,
            idempotency_key="own-1234",
        )
        campaign = world.repo.campaigns[uuid.UUID(result["id"])]
        assert (
            campaign.provider_source,
            campaign.provider_type,
            campaign.org_provider_id,
        ) == (
            "own",
            "smtp",
            row.id,
        )
        await service.send_batch(campaign.id)
        assert sorted(own_email.sent) == ["a1_in@guest.in", "a2_in@guest.in"]
        assert world.email.sent == []
        assert {r.provider_source for r in world.repo.recipients.values()} == {"own"}

    async def test_system_sms_template_not_sendable_through_own_sms(self) -> None:
        world, _ = _byo_world()
        service = _provider_service(world)
        await service.put_provider(
            _scope(),
            Channel.SMS,
            provider_type="ping4sms",
            config={**PLAIN["ping4sms"], **SECRETS["ping4sms"]},
            enabled=None,
        )
        row = await world.repo.get_provider(ORG_A, "sms")
        row.status, row.enabled = "verified", True
        world.system_template.sms_dlt_template_id = "1107000000000000009"
        resource = await world.service().get_template(
            _scope(), world.system_template.id
        )
        assert resource["sendable"]["sms"] == {
            "ok": False,
            "reason": "own_provider_requires_own_template",
        }


# ============================================================================
# No fallback: auth trip, unavailable row
# ============================================================================


class TestNoFallback:
    async def _scheduled_own(self, world):
        service = world.service()
        created = await _campaign(world, _scope())
        result = await service.schedule(
            _scope(),
            uuid.UUID(created["id"]),
            scheduled_at=None,
            idempotency_key="trip-" + uuid.uuid4().hex,
        )
        return service, world.repo.campaigns[uuid.UUID(result["id"])]

    async def test_auth_error_trips_row_and_fails_the_rest_never_wyfy(self) -> None:
        world, own_email = _byo_world(own_email=OwnEmail(fail_auth_after=0))
        row = await _add_verified_smtp(world)
        service, campaign = await self._scheduled_own(world)
        await service.send_batch(campaign.id)
        assert row.status == "failed"
        assert "Qw5Er8Ty2Ui6Op3As0004" not in (row.last_error or "")
        statuses = {(r.status, r.error_code) for r in world.repo.recipients.values()}
        assert statuses == {("failed", "own_provider_failed")}
        assert campaign.status == CampaignStatus.FAILED.value
        assert campaign.last_error.startswith("own_provider_failed: ")
        assert world.email.sent == [] and own_email.sent == []

    async def test_partial_send_then_trip_finalizes_sent(self) -> None:
        world, own_email = _byo_world(own_email=OwnEmail(fail_auth_after=1))
        await _add_verified_smtp(world)
        service, campaign = await self._scheduled_own(world)
        await service.send_batch(campaign.id)
        assert len(own_email.sent) == 1 and world.email.sent == []
        assert campaign.status == CampaignStatus.SENT.value
        assert campaign.last_error.startswith("own_provider_failed")
        assert campaign.count_failed == 1 and campaign.count_submitted == 1

    async def test_other_campaign_on_tripped_row_fails_at_next_batch(self) -> None:
        world, own_email = _byo_world()
        row = await _add_verified_smtp(world)
        service, campaign = await self._scheduled_own(world)
        row.status = "failed"  # tripped by another campaign
        await service.send_batch(campaign.id)
        assert own_email.sent == [] and world.email.sent == []
        assert campaign.last_error.startswith("own_provider_failed")

    async def test_dispatch_fails_when_row_removed(self) -> None:
        world, own_email = _byo_world()
        row = await _add_verified_smtp(world)
        service = world.service()
        created = await _campaign(world, _scope())
        await service.schedule(
            _scope(),
            uuid.UUID(created["id"]),
            scheduled_at=NOW + timedelta(hours=2),
            idempotency_key="deleted-1234",
        )
        campaign = world.repo.campaigns[uuid.UUID(created["id"])]
        await world.repo.soft_delete_provider(row)

        async def due(now, limit=20):
            return [campaign.id]

        world.repo.due_campaign_ids = due
        world.repo.sending_campaigns_without_progress = lambda before: _empty()
        service._now = lambda: NOW + timedelta(hours=3)
        await service.dispatch_due()
        assert campaign.status == CampaignStatus.FAILED.value
        assert campaign.last_error == "own_provider_unavailable: provider removed"
        assert own_email.sent == [] and world.email.sent == []


async def _empty():
    return []


# ============================================================================
# BYO add-on: lock cancels own campaigns only; requires guest_marketing
# ============================================================================


class TestByoAddon:
    async def test_lock_hook_cancels_only_own_snapshotted(self) -> None:
        from app.domains.marketing.repository import ByoCampaignLockHook

        calls = {}

        class Repo:
            async def count_active_campaigns_for(self, org, **kw):
                calls["count"] = kw
                return 1

            async def cancel_active_campaigns_for_lock(self, org, **kw):
                calls["cancel"] = kw
                return 1

        hook = ByoCampaignLockHook(Repo())
        assert await hook.cancel_active_campaigns_for_lock(ORG_A) == 1
        assert calls["cancel"]["own_only"] is True
        assert calls["cancel"]["cancel_reason"] == "byo_locked"
        await hook.count_active_campaigns(ORG_A)
        assert calls["count"] == {"own_only": True}

    async def test_byo_blocked_by_guest_marketing(self) -> None:
        from app.domains.feature_entitlement.addons import AddonService

        overrides = {
            "guest_marketing_byo": SimpleNamespace(
                organization_id=ORG_A,
                feature_key="guest_marketing_byo",
                is_enabled=True,
                reason=None,
                set_by_user_id=None,
                updated_at=NOW,
                created_at=NOW,
            )
        }

        class Overrides:
            async def get_live(self, org, key):
                return overrides.get(key)

        class Plans:
            async def get_plan_feature_enabled(self, org, key):
                return False

        class Orgs:
            async def get_organization(self, org):
                return object()

        service = AddonService(
            organizations=Orgs(),
            plan_features=Plans(),
            overrides=Overrides(),
            campaign_hooks={},
            user_names=SimpleNamespace(get_user_names=lambda ids: _empty_dict()),
            audit_writer=None,
            entitlement_cache=None,
            committer=None,
        )
        views = {v.key: v for v in await service.list_addons(ORG_A)}
        assert views["guest_marketing_byo"].enabled is False
        assert views["guest_marketing_byo"].blocked_by == "guest_marketing"
        assert views["guest_marketing"].blocked_by is None

    async def test_snapshot_drops_byo_without_guest_marketing(self) -> None:
        from app.domains.billing.service import LicenseService

        class Licenses:
            async def get_by_organization_id(self, org):
                return SimpleNamespace(
                    plan_id=uuid.uuid4(), status="active", expires_at=None
                )

        class Plans:
            async def list_plan_features(self, pid):
                return []

        def overrides(*keys):
            class _Overrides:
                async def list_for_organization(self, org):
                    return [
                        SimpleNamespace(feature_key=k, is_enabled=True) for k in keys
                    ]

            return _Overrides()

        only_byo = LicenseService(
            Licenses(), Plans(), feature_overrides=overrides("guest_marketing_byo")
        )
        assert (
            "guest_marketing_byo"
            not in (await only_byo.get_entitlement_snapshot(ORG_A)).enabled_features
        )
        both = LicenseService(
            Licenses(),
            Plans(),
            feature_overrides=overrides("guest_marketing", "guest_marketing_byo"),
        )
        assert {"guest_marketing", "guest_marketing_byo"} <= (
            await both.get_entitlement_snapshot(ORG_A)
        ).enabled_features


async def _empty_dict():
    return {}


# ============================================================================
# RBAC
# ============================================================================


class TestProviderRbac:
    def _grants(self, slug: str) -> set[str]:
        from app.domains.rbac.enums import PermissionModule
        from app.domains.rbac.seed import (
            MODULE_ACTIONS,
            SYSTEM_ROLES,
            expand_grant_level,
        )

        role = next(r for r in SYSTEM_ROLES if r.slug == slug)
        level = role.overrides.get(
            PermissionModule.MARKETING_PROVIDERS, role.default_level
        )
        return {
            a.value
            for a in expand_grant_level(
                level, MODULE_ACTIONS[PermissionModule.MARKETING_PROVIDERS]
            )
        }

    def test_module_and_grants(self) -> None:
        from app.domains.rbac.enums import PermissionModule, ScopeType
        from app.domains.rbac.seed import MODULE_NARROWEST_SCOPE, SYSTEM_ROLES

        assert (
            MODULE_NARROWEST_SCOPE[PermissionModule.MARKETING_PROVIDERS]
            == ScopeType.ORGANIZATION
        )
        assert self._grants("organization-owner") == {"read", "manage"}
        assert self._grants("organization-admin") == {"read", "manage"}
        assert self._grants("read-only") == {"read"}
        assert self._grants("auditor") == {"read"}
        assert self._grants("msp-owner") == set() and self._grants("msp-admin") == set()
        for role in SYSTEM_ROLES:
            if role.scope_type == ScopeType.LOCATION:
                assert self._grants(role.slug) == set(), role.slug

    def test_location_grant_cannot_satisfy_organization_pin(self) -> None:
        from app.domains.rbac.authorization import ScopeResolver
        from app.domains.rbac.context import GrantScope, ScopeContext
        from app.domains.rbac.enums import ScopeType

        requested = ScopeContext(organization_id=ORG_A, location_id=uuid.uuid4())
        location_grant = GrantScope(
            scope_type=ScopeType.LOCATION,
            organization_id=ORG_A,
            location_id=requested.location_id,
        )
        assert not ScopeResolver.satisfies(
            location_grant, ScopeType.ORGANIZATION, requested
        )

    def test_org_caller_without_manage_is_refused(self) -> None:
        from fastapi.testclient import TestClient

        from app.database.session import get_db_session
        from app.domains.auth.models import AuthUser
        from app.domains.billing.dependencies import get_entitlement_checker
        from app.domains.billing.service import EntitlementSnapshot
        from app.domains.rbac.authorization import AccessValidator
        from app.domains.rbac.dependencies import (
            CurrentOrganizationScope,
            CurrentUser,
            get_access_validator,
        )
        from app.domains.rbac.enums import ScopeType
        from app.domains.rbac.exceptions import PermissionDeniedError
        from app.domains.rbac.organization_scope import OrganizationScope
        from tests.unit.test_guest_marketing import _app

        seen: list[tuple[str, ScopeType]] = []

        class ReadOnly(AccessValidator):
            def __init__(self) -> None:
                pass

            async def check(self, user_id, key, *, scope_type, scope_context):
                seen.append((key, scope_type))
                if key != "marketing_providers.read":
                    raise PermissionDeniedError(key, str(scope_type))

        class Unlocked:
            async def get_snapshot(self, org):
                return EntitlementSnapshot(
                    organization_id=org,
                    plan_id=uuid.uuid4(),
                    license_status="active",
                    expires_at=None,
                    enabled_features=frozenset(
                        {"guest_marketing", "guest_marketing_byo"}
                    ),
                    limits={},
                    tiers={},
                )

        async def _no_db():
            yield None

        app = _app()
        app.dependency_overrides[get_entitlement_checker] = lambda: Unlocked()
        app.dependency_overrides[CurrentOrganizationScope] = lambda: (
            OrganizationScope.for_organization(ORG_A)
        )
        app.dependency_overrides[CurrentUser] = lambda: AuthUser(
            id=str(uuid.uuid4()), email="ro@a.in"
        )
        app.dependency_overrides[get_access_validator] = lambda: ReadOnly()
        app.dependency_overrides[get_db_session] = _no_db
        client = TestClient(app, raise_server_exceptions=False)
        response = client.put(
            "/api/v1/marketing/providers/sms",
            json={"provider_type": "ping4sms", "config": {}},
            # A location header would make an unpinned check infer LOCATION
            # scope; the pin keeps it at ORGANIZATION regardless.
            headers={
                "X-Organization-Id": str(ORG_A),
                "X-Location-Id": str(uuid.uuid4()),
            },
        )
        assert response.status_code == 403, response.text
        assert response.json()["data"]["error_code"] == "permission_denied"
        assert seen == [("marketing_providers.manage", ScopeType.ORGANIZATION)]

    def test_byo_locked_is_402_with_feature_key(self) -> None:
        from fastapi.testclient import TestClient

        from app.domains.auth.models import AuthUser
        from app.domains.billing.dependencies import get_entitlement_checker
        from app.domains.billing.service import EntitlementSnapshot
        from app.domains.rbac.dependencies import CurrentOrganizationScope, CurrentUser
        from app.domains.rbac.organization_scope import OrganizationScope
        from tests.unit.test_guest_marketing import _app

        class GmOnly:
            async def get_snapshot(self, org):
                return EntitlementSnapshot(
                    organization_id=org,
                    plan_id=uuid.uuid4(),
                    license_status="active",
                    expires_at=None,
                    enabled_features=frozenset({"guest_marketing"}),
                    limits={},
                    tiers={},
                )

        app = _app()
        app.dependency_overrides[get_entitlement_checker] = lambda: GmOnly()
        app.dependency_overrides[CurrentOrganizationScope] = lambda: (
            OrganizationScope.for_organization(ORG_A)
        )
        app.dependency_overrides[CurrentUser] = lambda: AuthUser(
            id=str(uuid.uuid4()), email="o@a.in"
        )
        client = TestClient(app, raise_server_exceptions=False)
        for method, path in [
            ("GET", "/api/v1/marketing/providers"),
            ("GET", "/api/v1/marketing/providers/sms"),
            ("PUT", "/api/v1/marketing/providers/sms"),
            ("DELETE", "/api/v1/marketing/providers/sms"),
            ("POST", "/api/v1/marketing/providers/sms/verify"),
            ("POST", "/api/v1/marketing/providers/whatsapp/sync-templates"),
        ]:
            response = client.request(
                method, path, json={}, headers={"X-Organization-Id": str(ORG_A)}
            )
            assert response.status_code == 402, (method, path, response.text)
            assert response.json()["data"] == {
                "error_code": "feature_not_entitled",
                "feature_key": "guest_marketing_byo",
            }

    def test_master_providers_route_is_pinned_global(self) -> None:
        from tests.unit.test_guest_marketing import _app

        app = _app()
        route = next(
            r
            for r in app.routes
            if getattr(r, "path", "")
            == "/api/v1/platform/organizations/{organization_id}/marketing-providers"
        )
        permission = next(
            d.call
            for d in route.dependant.dependencies
            if getattr(d.call, "__qualname__", "").startswith("RequirePermission")
        )
        closure = {str(c.cell_contents) for c in permission.__closure__}
        assert {"organizations.read", "global"} <= closure


# ============================================================================
# Rate limit bucket
# ============================================================================


class TestOwnRateBucket:
    async def test_own_provider_uses_per_org_bucket(self) -> None:
        from app.domains.marketing.service import RateLimiter

        keys: list[str] = []

        class Redis:
            async def incr(self, key):
                keys.append(key)
                return 1

            async def expire(self, key, seconds):
                return True

        limiter = RateLimiter(Redis(), {Channel.EMAIL: 10.0})
        await limiter.acquire(Channel.EMAIL)
        await limiter.acquire(Channel.EMAIL, own_organization_id=ORG_A, own_rate=5.0)
        assert keys[0].startswith("marketing:rate:email:") and ":org:" not in keys[0]
        assert keys[1].startswith(f"marketing:rate:email:org:{ORG_A}:")


# ============================================================================
# Senders: recorded provider responses (BE-11a/BE-11b)
# ============================================================================


def _mock_client(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(**kwargs):
        kwargs.pop("transport", None)
        return real(transport=httpx.MockTransport(handler), **kwargs)

    import app.domains.marketing.providers as providers_module

    monkeypatch.setattr(providers_module.httpx, "AsyncClient", factory)


class TestMetaCloud:
    CONFIG = {
        "phone_number_id": "111",
        "waba_id": "222",
        "access_token": "Yh3Uj8Ik2Ol5Pz9Mx0007",
    }

    async def test_template_send_payload_and_message_id(self, monkeypatch) -> None:
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["auth"] = request.headers["authorization"]
            seen["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "messaging_product": "whatsapp",
                    "messages": [{"id": "wamid.ABC"}],
                },
            )

        _mock_client(monkeypatch, handler)
        sender = MetaCloudWhatsAppSender(self.CONFIG)
        result = await sender.send_waba_template(
            "+919876543210",
            template_name="weekend",
            language="en_US",
            parameters=["Riya", "u"],
        )
        assert result.message_id == "wamid.ABC"
        assert seen["url"].endswith("/111/messages")
        assert seen["body"]["to"] == "919876543210"
        assert seen["body"]["template"]["components"][0]["parameters"][1] == {
            "type": "text",
            "text": "u",
        }

    async def test_error_190_is_an_auth_failure(self, monkeypatch) -> None:
        _mock_client(
            monkeypatch,
            lambda r: httpx.Response(
                401,
                json={
                    "error": {"message": "Error validating access token", "code": 190}
                },
            ),
        )
        with pytest.raises(SendError) as excinfo:
            await MetaCloudWhatsAppSender(self.CONFIG).send_waba_template(
                "+919876543210", template_name="t", language="en", parameters=[]
            )
        assert excinfo.value.auth and excinfo.value.permanent

    async def test_list_templates_follows_paging(self, monkeypatch) -> None:
        pages = {
            "first": {
                "data": [{"name": "a"}],
                "paging": {"next": "https://graph.facebook.com/next-page"},
            },
            "second": {"data": [{"name": "b"}], "paging": {}},
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=pages["second"]
                if "next-page" in str(request.url)
                else pages["first"],
            )

        _mock_client(monkeypatch, handler)
        names = [
            t["name"]
            for t in await MetaCloudWhatsAppSender(self.CONFIG).list_templates()
        ]
        assert names == ["a", "b"]

    def test_unsupported_template_shapes_are_skipped(self) -> None:
        assert (
            waba_template_body({"components": [{"type": "BODY", "text": "Hi {{1}}"}]})[
                0
            ]
            == "Hi {{1}}"
        )
        assert (
            waba_template_body({"parameter_format": "NAMED", "components": []})[0]
            is None
        )
        assert (
            waba_template_body(
                {
                    "components": [
                        {"type": "HEADER", "format": "IMAGE"},
                        {"type": "BODY", "text": "x"},
                    ]
                }
            )[0]
            is None
        )


class TestWabaSync:
    async def _world_with_meta(self, remote):
        world, _ = _byo_world()

        class FakeMeta:
            async def list_templates(self):
                return remote

        service = _provider_service(
            world, own_sender_builder=lambda t, c: OwnSenders(t, whatsapp=FakeMeta())
        )
        await service.put_provider(
            _scope(),
            Channel.WHATSAPP,
            provider_type="meta_cloud",
            config={**PLAIN["meta_cloud"], **SECRETS["meta_cloud"]},
            enabled=None,
        )
        row = await world.repo.get_provider(ORG_A, "whatsapp")
        row.status, row.enabled = "verified", True
        return world, service

    async def test_sync_upserts_approved_marketing_templates(self) -> None:
        remote = [
            {
                "name": "weekend",
                "language": "en",
                "status": "APPROVED",
                "category": "MARKETING",
                "components": [{"type": "BODY", "text": "Hi {{1}}, stop: {{2}}"}],
            },
            {
                "name": "otp",
                "language": "en",
                "status": "APPROVED",
                "category": "AUTHENTICATION",
                "components": [{"type": "BODY", "text": "{{1}}"}],
            },
            {
                "name": "pending",
                "language": "en",
                "status": "PENDING",
                "category": "MARKETING",
            },
        ]
        world, service = await self._world_with_meta(remote)
        result = await service.sync_whatsapp_templates(_scope())
        assert (result["created"], result["updated"], result["marked_unavailable"]) == (
            1,
            0,
            0,
        )
        template = result["templates"][0]
        assert template["whatsapp"]["source"] == "own_waba"
        assert template["whatsapp"]["provider_template_name"] == "weekend"
        assert template["sendable"]["whatsapp"] == {
            "ok": False,
            "reason": "unsubscribe_link_missing",
        }
        # Map the placeholders; now sendable through the own number.
        row = world.repo.templates[uuid.UUID(template["id"])]
        mapped = await world.service().update_template(
            _scope(),
            row.id,
            TemplateUpdate(
                version=row.version,
                whatsapp={"variable_order": ["guest_name", "unsubscribe_link"]},
            ),
        )
        assert mapped["sendable"]["whatsapp"] == {"ok": True, "reason": None}
        with pytest.raises(SyncedTemplateReadOnlyError):
            await world.service().update_template(
                _scope(), row.id, TemplateUpdate(version=row.version, description="x")
            )
        # Removed from the WABA -> marked unavailable on the next sync.
        remote.clear()
        again = await service.sync_whatsapp_templates(_scope())
        assert again["marked_unavailable"] == 1
        assert row.whatsapp_approval_status == "rejected"

    async def test_sync_requires_verified_meta_row(self) -> None:
        world, service = await self._world_with_meta([])
        row = await world.repo.get_provider(ORG_A, "whatsapp")
        row.status = "unverified"
        with pytest.raises(ProviderNotVerifiedError):
            await service.sync_whatsapp_templates(_scope())


def test_every_provider_type_has_a_secret_spec() -> None:
    for (_channel, provider_type), spec in PROVIDER_SPECS.items():
        assert spec.secrets, provider_type
        assert set(spec.secrets) <= set(spec.required)
        assert provider_type in SECRETS
