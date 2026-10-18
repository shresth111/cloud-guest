"""Login messaging service, OTP fallback, tenancy and routes.

* resolution: the venue's verified, enabled provider is used only while the
  org holds ``guest_login_byo``; anything else is the platform default, and a
  portal request naming a location of another org gets the default;
* login never breaks: when the venue's provider fails, the SAME code goes out
  through the platform provider, the fallback is counted on the row, an
  audit row is written (throttled), a breaker skips the vendor for a while,
  and an auth error turns the row off until it is verified again;
* secrets: no view (customer or Master) contains a secret or the ciphertext;
* verify: a code goes to the number typed, and only that code typed back
  marks the provider verified (Master: number Master typed, audited as the
  Wyfy team, card shows "Set up by Wyfy Guest team");
* tenancy: every venue route takes the org from RequireOrganization (no org in
  path or body) and pins ORGANIZATION; every Master route takes the org from
  the path and pins GLOBAL -- checked structurally, through ScopeResolver and
  over HTTP, where an org-scoped grant is refused on a foreign org's path.
"""

from __future__ import annotations

import functools
import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.core.config import Settings
from app.domains.guest_messaging.exceptions import (
    ByoNotAllowedError,
    LoginProviderNotFoundError,
    OrganizationNotFoundError,
    ProviderConfigInvalidError,
    ProviderSendFailedError,
    VerificationCodeInvalidError,
    VerificationNotStartedError,
)
from app.domains.guest_messaging.registry import AdapterContext
from app.domains.guest_messaging.service import (
    Actor,
    LoginMessagingService,
    OrgOtpDispatcher,
    normalize_phone,
)
from app.domains.otp.constants import OtpChannel, OtpPurpose
from app.domains.rbac.enums import AuditAction, ScopeType
from tests.unit.test_otp import FakeAuditLogWriter, make_service

ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
ORG_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
LOC_A = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
LOC_B = uuid.UUID("00000000-0000-0000-0000-0000000000b1")
VENUE_ADMIN = uuid.UUID("00000000-0000-0000-0000-0000000000f1")
WYFY_STAFF = uuid.UUID("00000000-0000-0000-0000-0000000000f2")
NOW = datetime(2026, 10, 18, 9, 0, tzinfo=UTC)
TOKEN = "EAAG-secret-token-value-0001"
META = {
    "phone_number_id": "1234567890",
    "waba_id": "9876543210",
    "access_token": TOKEN,
    "template_name": "wifi_login_code",
}
SMS = {
    "api_key": "p4s-key-secret-00001",
    "sender_id": "CAFEWF",
    "dlt_template_id": "1107000000000001",
    "message_template": "{otp} is your Wi-Fi code",
}


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.counts: dict[str, int] = {}

    async def get(self, key):  # noqa: ANN001
        return self.store.get(key)

    async def set(self, key, value, ex=None, nx=False):  # noqa: ANN001
        if nx and key in self.store:
            return None
        self.store[key] = str(value)
        return True

    async def delete(self, key):  # noqa: ANN001
        self.store.pop(key, None)

    async def incr(self, key):  # noqa: ANN001
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def expire(self, key, seconds):  # noqa: ANN001
        return True

    async def ttl(self, key):  # noqa: ANN001
        return 300


class FakeRepo:
    """Mirrors LoginProviderRepository: every read is keyed on organization
    (and, in SQL, purpose='otp')."""

    def __init__(self) -> None:
        self.rows: dict[tuple[uuid.UUID, str], Any] = {}
        self.orgs = {ORG_A: "Cafe A", ORG_B: "Hotel B"}
        self.locations = {LOC_A: ORG_A, LOC_B: ORG_B}

    async def list_providers(self, organization_id):  # noqa: ANN001
        return {c: r for (o, c), r in self.rows.items() if o == organization_id}

    async def get_provider(self, organization_id, channel):  # noqa: ANN001
        return self.rows.get((organization_id, channel))

    async def create_provider(self, **fields):  # noqa: ANN003
        base = {
            "id": uuid.uuid4(),
            "version": 1,
            "updated_at": NOW,
            "last_verified_at": None,
            "last_error": None,
            "verified_by_user_id": None,
            "fallback_count": 0,
            "last_fallback_at": None,
            "last_fallback_error": None,
            "purpose": "otp",
        }
        row = SimpleNamespace(**{**base, **fields})
        self.rows[(fields["organization_id"], fields["channel"])] = row
        return row

    async def update_provider(self, row, data):  # noqa: ANN001
        for key, value in data.items():
            setattr(row, key, value)
        row.version += 1
        return row

    async def soft_delete_provider(self, row):  # noqa: ANN001
        del self.rows[(row.organization_id, row.channel)]

    async def record_fallback(self, provider_id, *, at, error):  # noqa: ANN001
        for row in self.rows.values():
            if row.id == provider_id:
                row.fallback_count += 1
                row.last_fallback_at = at
                row.last_fallback_error = error

    async def organization_exists(self, organization_id):  # noqa: ANN001
        return organization_id in self.orgs

    async def organization_name(self, organization_id):  # noqa: ANN001
        return self.orgs.get(organization_id)

    async def location_organization(self, location_id):  # noqa: ANN001
        return self.locations.get(location_id)

    async def get_user_names(self, ids):  # noqa: ANN001
        return {i: "Staff Member" for i in ids if i}


class Vendor:
    """MockTransport handler standing in for every vendor."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.fail: int | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail:
            code = 190 if self.fail == 401 else 131000
            return httpx.Response(self.fail, json={"error": {"code": code}})
        if "graph.facebook.com" in str(request.url):
            if request.method == "GET":
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {
                                "name": "wifi_login_code",
                                "language": "en",
                                "status": "APPROVED",
                                "category": "AUTHENTICATION",
                            }
                        ]
                    },
                )
            return httpx.Response(200, json={"messages": [{"id": "wamid.1"}]})
        return httpx.Response(200, text="5512345")

    def codes(self) -> list[str]:
        out = []
        for r in self.requests:
            if r.method == "POST" and "graph.facebook.com" in str(r.url):
                out.append(json.loads(r.content)["template"]["components"][0]["parameters"][0]["text"])  # noqa: E501
        return out


def _world(*, allowed: set[uuid.UUID] | None = None):
    repo = FakeRepo()
    redis = FakeRedis()
    audit = FakeAuditLogWriter()
    vendor = Vendor()
    allowed = {ORG_A} if allowed is None else allowed

    async def entitled(org):  # noqa: ANN001
        return org in allowed

    service = LoginMessagingService(
        repo,
        settings=Settings(),
        redis=redis,
        audit_writer=audit,
        byo_entitlement_check=entitled,
        adapter_context=AdapterContext(
            transport=httpx.MockTransport(vendor), resolver=lambda h, p: ["93.184.216.34"]
        ),
        now=lambda: NOW,
        code_factory=lambda: "246810",
    )
    return SimpleNamespace(repo=repo, redis=redis, audit=audit, vendor=vendor, service=service)


VENUE = Actor(VENUE_ADMIN, via_platform=False)
MASTER = Actor(WYFY_STAFF, via_platform=True)


async def _connect_and_verify(w, org=ORG_A, actor=VENUE, channel="whatsapp", config=META):  # noqa: ANN001, E501
    provider_type = "meta_cloud" if channel == "whatsapp" else "ping4sms"
    await w.service.put_provider(
        org, channel, actor, provider_type=provider_type, config=config, enabled=None
    )
    await w.service.start_verification(org, channel, actor, to="+91 98765 43210")
    return await w.service.confirm_verification(org, channel, actor, code="246810")


# ============================================================================
# Resolution order
# ============================================================================


class TestResolution:
    async def test_no_row_means_platform_default(self) -> None:
        w = _world()
        assert (
            await w.service.resolve_sender(
                organization_id=ORG_A, location_id=None, channel="whatsapp"
            )
            is None
        )

    async def test_unverified_row_is_not_used(self) -> None:
        w = _world()
        await w.service.put_provider(
            ORG_A, "whatsapp", VENUE, provider_type="meta_cloud", config=META, enabled=None
        )
        assert (
            await w.service.resolve_sender(
                organization_id=ORG_A, location_id=None, channel="whatsapp"
            )
            is None
        )

    async def test_verified_and_entitled_is_used(self) -> None:
        w = _world()
        await _connect_and_verify(w)
        sender = await w.service.resolve_sender(
            organization_id=None, location_id=LOC_A, channel="whatsapp"
        )
        assert sender is not None and sender.organization_id == ORG_A
        # SMS is independent: still the default.
        assert (
            await w.service.resolve_sender(
                organization_id=ORG_A, location_id=None, channel="sms"
            )
            is None
        )

    async def test_add_on_locked_means_default_even_when_verified(self) -> None:
        w = _world(allowed=set())
        await _connect_and_verify(w, actor=MASTER)
        assert (
            await w.service.resolve_sender(
                organization_id=ORG_A, location_id=None, channel="whatsapp"
            )
            is None
        )
        overview = await w.service.overview(ORG_A, for_platform=True)
        whatsapp = overview["channels"][0]
        assert overview["byo_allowed"] is False
        assert whatsapp["effective_source"] == "wyfy"
        assert whatsapp["own"]["status"] == "verified"

    async def test_disabled_row_is_not_used(self) -> None:
        w = _world()
        await _connect_and_verify(w)
        await w.service.put_provider(
            ORG_A, "whatsapp", VENUE, provider_type=None, config={}, enabled=False
        )
        assert (
            await w.service.resolve_sender(
                organization_id=ORG_A, location_id=None, channel="whatsapp"
            )
            is None
        )

    async def test_portal_body_pairing_a_foreign_location_gets_the_default(
        self,
    ) -> None:
        w = _world(allowed={ORG_A, ORG_B})
        await _connect_and_verify(w, org=ORG_A)
        assert (
            await w.service.resolve_sender(
                organization_id=ORG_B, location_id=LOC_A, channel="whatsapp"
            )
            is None
        )
        assert (
            await w.service.resolve_sender(
                organization_id=None, location_id=LOC_B, channel="whatsapp"
            )
            is None
        )


# ============================================================================
# Login never breaks: fallback
# ============================================================================


async def _otp_with_dispatcher(w):  # noqa: ANN001
    fx = make_service()
    fx.service.org_dispatcher = OrgOtpDispatcher(w.service, session=None)
    return fx


class TestFallback:
    async def test_own_provider_sends_and_platform_does_not(self) -> None:
        w = _world()
        await _connect_and_verify(w)
        fx = await _otp_with_dispatcher(w)
        await fx.service.request_otp(
            identifier="+919876543210",
            channel=OtpChannel.WHATSAPP,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=ORG_A,
            location_id=LOC_A,
        )
        assert fx.whatsapp_provider.sent == []
        assert len(w.vendor.codes()) == 2  # the verify code, then the login code

    async def test_failure_falls_back_with_the_same_code_and_is_recorded(self) -> None:
        w = _world()
        await _connect_and_verify(w)
        w.vendor.fail = 503
        fx = await _otp_with_dispatcher(w)
        await fx.service.request_otp(
            identifier="+919876543210",
            channel=OtpChannel.WHATSAPP,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=ORG_A,
            location_id=LOC_A,
        )
        assert len(fx.whatsapp_provider.sent) == 1
        phone, code, _ = fx.whatsapp_provider.sent[0]
        assert phone == "+919876543210"
        sent_body = json.loads(w.vendor.requests[-1].content)
        assert sent_body["template"]["components"][0]["parameters"][0]["text"] == code
        row = w.repo.rows[(ORG_A, "whatsapp")]
        assert row.fallback_count == 1
        assert row.last_fallback_error.startswith("provider_rejected")
        fallback_audits = [
            e
            for e in w.audit.entries
            if e["action"] == AuditAction.GUEST_LOGIN_PROVIDER_FALLBACK.value
        ]
        assert len(fallback_audits) == 1
        assert fallback_audits[0]["organization_id"] == ORG_A
        assert TOKEN not in json.dumps(fallback_audits[0], default=str)
        # A 5xx is not an auth error: the row stays verified.
        assert row.status == "verified"

    async def test_breaker_skips_the_vendor_after_a_failure(self) -> None:
        w = _world()
        await _connect_and_verify(w)
        w.vendor.fail = 503
        fx = await _otp_with_dispatcher(w)
        for _ in range(3):
            await fx.service.request_otp(
                identifier="+919876543210",
                channel=OtpChannel.WHATSAPP,
                purpose=OtpPurpose.GUEST_LOGIN,
                organization_id=ORG_A,
                location_id=None,
            )
        vendor_posts = [r for r in w.vendor.requests if r.method == "POST"]
        assert len(vendor_posts) == 2  # verify + the first login only
        assert len(fx.whatsapp_provider.sent) == 3
        audits = [
            e
            for e in w.audit.entries
            if e["action"] == AuditAction.GUEST_LOGIN_PROVIDER_FALLBACK.value
        ]
        assert len(audits) == 1

    async def test_auth_error_turns_the_row_off_until_verified_again(self) -> None:
        w = _world()
        await _connect_and_verify(w)
        w.vendor.fail = 401
        fx = await _otp_with_dispatcher(w)
        await fx.service.request_otp(
            identifier="+919876543210",
            channel=OtpChannel.WHATSAPP,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=ORG_A,
            location_id=None,
        )
        row = w.repo.rows[(ORG_A, "whatsapp")]
        assert row.status == "failed" and row.enabled is False
        assert len(fx.whatsapp_provider.sent) == 1

    async def test_a_broken_resolver_still_lets_the_guest_in(self) -> None:
        w = _world()

        async def boom(**kwargs):  # noqa: ANN003
            raise RuntimeError("database is down")

        w.service.resolve_sender = boom
        fx = await _otp_with_dispatcher(w)
        await fx.service.request_otp(
            identifier="+919876543210",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=ORG_A,
            location_id=None,
        )
        assert len(fx.sms_provider.sent) == 1

    async def test_account_codes_never_use_the_venue_provider(self) -> None:
        w = _world()
        await _connect_and_verify(w, channel="sms", config=SMS)
        fx = await _otp_with_dispatcher(w)
        await fx.service.request_otp(
            identifier="+919876543210",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.ACCOUNT_DATA_MASKING,
            organization_id=ORG_A,
            location_id=None,
        )
        assert len(fx.sms_provider.sent) == 1

    async def test_sms_through_the_venue_uses_its_dlt_text(self) -> None:
        w = _world()
        await _connect_and_verify(w, channel="sms", config=SMS)
        fx = await _otp_with_dispatcher(w)
        await fx.service.request_otp(
            identifier="9876543210",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
            organization_id=ORG_A,
            location_id=None,
        )
        assert fx.sms_provider.sent == []
        params = w.vendor.requests[-1].url.params
        assert params["number"] == "919876543210"
        assert params["sms"].endswith(" is your Wi-Fi code")


# ============================================================================
# Secrets never leave
# ============================================================================


class TestSecretMasking:
    async def test_no_view_contains_the_secret_or_ciphertext(self) -> None:
        w = _world()
        view, created = await w.service.put_provider(
            ORG_A, "whatsapp", VENUE, provider_type="meta_cloud", config=META, enabled=None
        )
        assert created
        row = w.repo.rows[(ORG_A, "whatsapp")]
        outputs = [
            view,
            await w.service.overview(ORG_A, for_platform=False),
            await w.service.overview(ORG_A, for_platform=True),
            await _connect_and_verify(w),
        ]
        for output in outputs:
            text = json.dumps(output, default=str)
            assert TOKEN not in text
            assert row.config_encrypted not in text
            assert "TOKEN" not in text
        assert view["display"]["access_token"] == {"set": True, "hint": "…0001"}

    async def test_omitting_the_secret_keeps_it_and_changing_settings_unverifies(
        self,
    ) -> None:
        w = _world()
        await _connect_and_verify(w)
        view, _ = await w.service.put_provider(
            ORG_A,
            "whatsapp",
            VENUE,
            provider_type=None,
            config={"template_name": "wifi_login_v2"},
            enabled=None,
        )
        assert view["status"] == "unverified" and view["enabled"] is False
        from app.domains.marketing.providers import decrypt_config

        stored = decrypt_config(w.repo.rows[(ORG_A, "whatsapp")].config_encrypted)
        assert stored["access_token"] == TOKEN
        assert stored["template_name"] == "wifi_login_v2"

    async def test_enabling_requires_verification(self) -> None:
        w = _world()
        with pytest.raises(ProviderConfigInvalidError):
            await w.service.put_provider(
                ORG_A, "whatsapp", VENUE, provider_type="meta_cloud", config=META, enabled=True
            )


# ============================================================================
# Verify
# ============================================================================


class TestVerify:
    async def test_wrong_code_then_right_code(self) -> None:
        w = _world()
        await w.service.put_provider(
            ORG_A, "whatsapp", VENUE, provider_type="meta_cloud", config=META, enabled=None
        )
        started = await w.service.start_verification(
            ORG_A, "whatsapp", VENUE, to="+91 98765 43210"
        )
        assert started["sent_to"].endswith("3210") and "98765" not in started["sent_to"]
        assert json.loads(w.vendor.requests[-1].content)["to"] == "919876543210"
        with pytest.raises(VerificationCodeInvalidError):
            await w.service.confirm_verification(ORG_A, "whatsapp", VENUE, code="111111")
        view = await w.service.confirm_verification(ORG_A, "whatsapp", VENUE, code="246810")
        assert view["status"] == "verified" and view["enabled"] is True
        assert view["effective"] is True
        assert view["set_up_by"] == "venue"

    async def test_changing_settings_after_sending_voids_the_code(self) -> None:
        w = _world()
        await w.service.put_provider(
            ORG_A, "whatsapp", VENUE, provider_type="meta_cloud", config=META, enabled=None
        )
        await w.service.start_verification(ORG_A, "whatsapp", VENUE, to="+919876543210")
        await w.service.put_provider(
            ORG_A,
            "whatsapp",
            VENUE,
            provider_type=None,
            config={"template_name": "other"},
            enabled=None,
        )
        with pytest.raises(VerificationNotStartedError):
            await w.service.confirm_verification(ORG_A, "whatsapp", VENUE, code="246810")

    async def test_vendor_refusal_marks_failed_and_scrubs_the_error(self) -> None:
        w = _world()
        await w.service.put_provider(
            ORG_A, "whatsapp", VENUE, provider_type="meta_cloud", config=META, enabled=None
        )
        w.vendor.fail = 400
        with pytest.raises(ProviderSendFailedError) as caught:
            await w.service.start_verification(
                ORG_A, "whatsapp", VENUE, to="+919876543210"
            )
        assert TOKEN not in json.dumps(caught.value.data, default=str)
        assert w.repo.rows[(ORG_A, "whatsapp")].status == "failed"

    async def test_customer_needs_the_add_on_to_connect(self) -> None:
        w = _world(allowed=set())
        with pytest.raises(ByoNotAllowedError):
            await w.service.put_provider(
                ORG_A, "whatsapp", VENUE, provider_type="meta_cloud", config=META, enabled=None
            )


# ============================================================================
# Master acting for a venue
# ============================================================================


class TestMaster:
    async def test_master_sets_up_and_verifies_with_its_own_number(self) -> None:
        w = _world()
        view = await _connect_and_verify(w, actor=MASTER)
        assert view["configured_by_platform"] is True
        assert view["set_up_by"] == "wyfy_team"
        assert view["updated_by"]["name"] == "Staff Member"
        venue_view = (await w.service.overview(ORG_A, for_platform=False))["channels"][0]
        assert venue_view["own"]["set_up_by"] == "wyfy_team"
        # The venue sees the team, never the staff member.
        assert venue_view["own"]["updated_by"] == {"id": None, "name": "Wyfy Guest team"}
        audits = [e for e in w.audit.entries if e["organization_id"] == ORG_A]
        assert audits and all(e["actor_user_id"] == WYFY_STAFF for e in audits)
        assert all(e["event_metadata"]["via"] == "master_console" for e in audits)
        assert {e["action"] for e in audits} >= {
            AuditAction.GUEST_LOGIN_PROVIDER_UPDATED.value,
            AuditAction.GUEST_LOGIN_PROVIDER_VERIFIED.value,
        }

    async def test_master_acts_on_the_path_org_only(self) -> None:
        w = _world(allowed={ORG_A, ORG_B})
        await _connect_and_verify(w, org=ORG_B, actor=MASTER)
        assert (ORG_B, "whatsapp") in w.repo.rows
        assert (ORG_A, "whatsapp") not in w.repo.rows
        assert (await w.service.overview(ORG_A, for_platform=True))["channels"][0][
            "own"
        ] is None

    async def test_unknown_org_is_404_for_master(self) -> None:
        w = _world()
        with pytest.raises(OrganizationNotFoundError):
            await w.service.overview(uuid.uuid4(), for_platform=True)

    async def test_disconnect_reverts_to_default(self) -> None:
        w = _world()
        await _connect_and_verify(w, actor=MASTER)
        out = await w.service.delete_provider(ORG_A, "whatsapp", MASTER)
        assert out["effective_source"] == "wyfy"
        with pytest.raises(LoginProviderNotFoundError):
            await w.service.delete_provider(ORG_A, "whatsapp", MASTER)

    async def test_a_venue_cannot_reach_another_venues_row(self) -> None:
        w = _world(allowed={ORG_A, ORG_B})
        await _connect_and_verify(w, org=ORG_B)
        with pytest.raises(LoginProviderNotFoundError):
            await w.service.delete_provider(ORG_A, "whatsapp", VENUE)
        with pytest.raises(LoginProviderNotFoundError):
            await w.service.start_verification(
                ORG_A, "whatsapp", VENUE, to="+919876543210"
            )
        assert (await w.service.overview(ORG_A, for_platform=False))["channels"][0][
            "own"
        ] is None


def test_normalize_phone() -> None:
    assert normalize_phone("98765 43210") == "+919876543210"
    assert normalize_phone("+44 7700 900123") == "+447700900123"
    assert normalize_phone("0044 7700 900123") == "+447700900123"
    assert normalize_phone("abc") is None


# ============================================================================
# Tenancy at the route layer
# ============================================================================


@functools.cache
def _routes():
    from app.main import create_app

    return tuple(
        r for r in create_app().routes if "guest-messaging" in getattr(r, "path", "")
    )


def _closure_values(route, kind):  # noqa: ANN001
    out = []
    for dependency in route.dependant.dependencies:
        for cell in dependency.call.__closure__ or ():
            if isinstance(cell.cell_contents, kind):
                out.append(cell.cell_contents)
    return out


class TestRouteTenancy:
    def test_venue_routes_take_the_org_from_scope_and_pin_organization(self) -> None:
        from app.domains.rbac.dependencies import RequireOrganization

        venue = [r for r in _routes() if not r.path.startswith("/api/v1/platform")]
        assert len(venue) == 5
        for route in venue:
            assert "{organization_id}" not in route.path
            assert "organization_id" not in [p.name for p in route.dependant.path_params]
            calls = [d.call for d in route.dependant.dependencies]
            assert RequireOrganization in calls, route.path
            assert _closure_values(route, ScopeType) == [ScopeType.ORGANIZATION], route.path

    def test_master_routes_take_the_org_from_the_path_and_pin_global(self) -> None:
        master = [r for r in _routes() if r.path.startswith("/api/v1/platform")]
        assert len(master) == 5
        for route in master:
            assert "{organization_id}" in route.path
            assert _closure_values(route, ScopeType) == [ScopeType.GLOBAL], route.path
            keys = [
                k for k in _closure_values(route, str) if not isinstance(k, ScopeType)
            ]
            assert keys and set(keys) <= {"organizations.read", "organizations.update"}

    def test_an_org_scoped_grant_cannot_satisfy_the_master_check(self) -> None:
        from app.domains.rbac.authorization import (
            GrantScope,
            ScopeContext,
            ScopeResolver,
        )

        requested = ScopeContext(organization_id=ORG_B)
        org_grant = GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=ORG_B)
        assert ScopeResolver.satisfies(org_grant, ScopeType.GLOBAL, requested) is False
        assert (
            ScopeResolver.satisfies(
                GrantScope(scope_type=ScopeType.GLOBAL), ScopeType.GLOBAL, requested
            )
            is True
        )


class _HttpWorld:
    """The two routers on a bare app, with the RBAC engine stubbed to a fixed
    set of grants. The service is real (fakes underneath)."""

    def __init__(self, grants) -> None:  # noqa: ANN001
        from fastapi import FastAPI

        from app.common.exceptions import register_exception_handlers
        from app.database.session import get_db_session
        from app.domains.auth.dependencies import get_current_user
        from app.domains.auth.models import AuthUser
        from app.domains.guest_messaging.dependencies import (
            get_login_messaging_service,
        )
        from app.domains.guest_messaging.router import platform_router, router
        from app.domains.rbac.authorization import AccessValidator, ScopeResolver
        from app.domains.rbac.dependencies import (
            RequireOrganization,
            get_access_validator,
        )

        self.world = _world(allowed={ORG_A, ORG_B})

        class _Validator(AccessValidator):
            def __init__(self) -> None:
                self.cache = None
                self.denial_audit_repository = None
                self.scope_resolver = ScopeResolver()

            async def get_effective_grants(self, _user_id):  # noqa: ANN001
                return grants

            async def _record_denial_out_of_band(self, **kwargs):  # noqa: ANN003
                return None

        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(router, prefix="/api/v1")
        app.include_router(platform_router, prefix="/api/v1")

        async def _db():
            yield None

        app.dependency_overrides[get_db_session] = _db
        app.dependency_overrides[get_current_user] = lambda: AuthUser(
            id=str(VENUE_ADMIN), email="owner@cafe-a.example"
        )
        app.dependency_overrides[get_access_validator] = _Validator
        app.dependency_overrides[RequireOrganization] = lambda: ORG_A
        app.dependency_overrides[get_login_messaging_service] = lambda: self.world.service
        self.app = app

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return await c.request(method, path, **kwargs)


def _grants(*pairs):  # noqa: ANN002
    from app.domains.rbac.authorization import EffectiveGrant, EffectiveGrants

    return EffectiveGrants(
        allow=tuple(
            EffectiveGrant(permission_key=k, effect="allow", scope=s, source="test")
            for k, s in pairs
        ),
        deny=(),
    )


class TestHttpCrossTenant:
    async def test_venue_owner_cannot_use_master_routes_on_a_foreign_org(self) -> None:
        from app.domains.rbac.authorization import GrantScope

        own = GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=ORG_A)
        foreign = GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=ORG_B)
        http = _HttpWorld(
            _grants(
                ("organizations.read", own),
                ("organizations.update", own),
                ("organizations.update", foreign),
                ("marketing_providers.manage", own),
            )
        )
        base = f"/api/v1/platform/organizations/{ORG_B}/guest-messaging/providers"
        for method, path, body in (
            ("GET", base, None),
            ("PUT", f"{base}/whatsapp", {"provider_type": "meta_cloud", "config": META}),
            ("DELETE", f"{base}/whatsapp", None),
            ("POST", f"{base}/whatsapp/verify", {"to": "+919876543210"}),
        ):
            response = await http.request(
                method, path, json=body, headers={"X-Organization-Id": str(ORG_B)}
            )
            assert response.status_code == 403, (method, path, response.text)
        assert http.world.repo.rows == {}

    async def test_global_operator_writes_to_the_path_org(self) -> None:
        from app.domains.rbac.authorization import GrantScope

        http = _HttpWorld(
            _grants(("organizations.update", GrantScope(scope_type=ScopeType.GLOBAL)))
        )
        response = await http.request(
            "PUT",
            f"/api/v1/platform/organizations/{ORG_B}/guest-messaging/providers/whatsapp",
            json={"provider_type": "meta_cloud", "config": META},
            # A header naming another org changes nothing: the path decides.
            headers={"X-Organization-Id": str(ORG_A)},
        )
        assert response.status_code == 201, response.text
        assert set(http.world.repo.rows) == {(ORG_B, "whatsapp")}
        assert TOKEN not in response.text
        assert http.world.repo.rows[(ORG_B, "whatsapp")].configured_by_platform is True

    async def test_venue_route_acts_on_the_callers_org_only(self) -> None:
        from app.domains.rbac.authorization import GrantScope

        own = GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=ORG_A)
        http = _HttpWorld(
            _grants(("marketing_providers.manage", own), ("marketing_providers.read", own))
        )
        response = await http.request(
            "PUT",
            "/api/v1/guest-messaging/providers/whatsapp",
            json={
                "provider_type": "meta_cloud",
                "config": META,
                "organization_id": str(ORG_B),
            },
            headers={"X-Organization-Id": str(ORG_A)},
        )
        assert response.status_code == 422  # unknown body keys are refused
        response = await http.request(
            "PUT",
            "/api/v1/guest-messaging/providers/whatsapp",
            json={"provider_type": "meta_cloud", "config": META},
            headers={"X-Organization-Id": str(ORG_A)},
        )
        assert response.status_code == 201, response.text
        assert set(http.world.repo.rows) == {(ORG_A, "whatsapp")}
        # Naming another org in the header does not move the write: the
        # permission check then runs against ORG_B, where this caller holds
        # nothing.
        response = await http.request(
            "DELETE",
            "/api/v1/guest-messaging/providers/whatsapp",
            headers={"X-Organization-Id": str(ORG_B)},
        )
        assert response.status_code == 403
        assert set(http.world.repo.rows) == {(ORG_A, "whatsapp")}

    async def test_location_grant_cannot_manage_the_venue_provider(self) -> None:
        from app.domains.rbac.authorization import GrantScope

        http = _HttpWorld(
            _grants(
                (
                    "marketing_providers.manage",
                    GrantScope(scope_type=ScopeType.LOCATION, location_id=LOC_A),
                )
            )
        )
        response = await http.request(
            "PUT",
            "/api/v1/guest-messaging/providers/sms",
            json={"provider_type": "ping4sms", "config": SMS},
            headers={"X-Location-Id": str(LOC_A)},
        )
        assert response.status_code == 403, response.text
