"""Name required at sign-in (``captive_portal_configs.require_guest_name``).

The behaviour these tests pin, end to end through the real services:

* The OTP login still issues the session (the code is spent and must not be
  asked for twice), but reports ``name_required`` when the venue requires a
  name and the guest has none on file.
* Until a name is stored, EVERY step that opens the network refuses that
  session: RADIUS Authorize (Access-Reject), the router agent's
  ``/agent/authorized-macs`` bypass list (MAC left out), and the
  network-integration portal authorize routes (403,
  ``data.code == "guest_name_required"``).
* ``POST /guest/sign-in-name`` (``GuestService.submit_sign_in_name``) stores
  a cleaned name for the just-verified OTP session, rejecting an empty or
  whitespace-only one with ``data.code == "guest_name_invalid"``; after it
  the same session is admitted.
* A venue that turned the requirement off behaves exactly as before.
* The config is resolved by the SESSION's location, never the guest's home.
* The production default is ON (owner decision), and required implies
  collected.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from app.common.exceptions import CloudGuestError
from app.domains.captive_portal.models import CaptivePortalConfig
from app.domains.captive_portal.schemas import (
    CaptivePortalConfigCreateRequest,
    CaptivePortalConfigResponse,
)
from app.domains.captive_portal.service import ResolvedPortalConfig
from app.domains.guest.constants import (
    GUEST_DISPLAY_NAME_MAX_LENGTH,
    GuestAuthMethod,
)
from app.domains.guest.exceptions import (
    GuestNameInvalidError,
    GuestNameRequiredError,
    GuestProfileFieldNotCollectedError,
    GuestProfileUpdateNotAuthorizedError,
)
from app.domains.guest.validators import (
    normalize_guest_display_name,
    session_awaits_required_name,
)
from app.domains.router_agent.dependencies import AgentIdentity
from app.domains.router_agent.router import agent_authorized_macs

from .test_captive_portal import _create_config, make_service
from .test_guest import FakeAccessControlHook, Fixture, make_fixture
from .test_omada_authorization_duration import _authorize
from .test_omada_authorization_duration import _fixture as omada_fixture

PHONE = "+15551234567"
MAC = "aa:bb:cc:dd:ee:ff"


async def _otp_login(fx: Fixture, *, identifier: str = PHONE, mac: str = MAC):
    return await fx.guest_service.login_via_otp(
        identifier=identifier,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
    )


async def _nas(fx: Fixture):
    await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier="nas-1",
        shared_secret="supersecret123",
    )
    return await fx.radius_service.authenticate_nas(
        nas_identifier="nas-1", shared_secret="supersecret123"
    )


@dataclass
class _NoTrustedDevices:
    async def list_active_entries_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[object]:
        return []


async def _authorized_macs(fx: Fixture) -> list[str]:
    identity = AgentIdentity(router=fx.router, credential=None)  # type: ignore[arg-type]
    response = await agent_authorized_macs(
        identity=identity,
        guest_repository=fx.repository,
        mac_authorization_service=_NoTrustedDevices(),  # type: ignore[arg-type]
        access_decision_service=FakeAccessControlHook(),  # type: ignore[arg-type]
        captive_portal_service=fx.captive_portal_service,  # type: ignore[arg-type]
    )
    return response.mac_addresses


# ============================================================================
# Validation
# ============================================================================


class TestNormalizeDisplayName:
    def test_trims_and_collapses_whitespace(self) -> None:
        assert normalize_guest_display_name("  Asha \t  Rao \n") == "Asha Rao"

    @pytest.mark.parametrize("raw", [None, "", "   ", "\t\n "])
    def test_empty_or_whitespace_is_rejected_with_the_stable_code(
        self, raw: str | None
    ) -> None:
        with pytest.raises(GuestNameInvalidError) as exc:
            normalize_guest_display_name(raw)
        assert exc.value.status_code == 400
        assert exc.value.data == {"code": "guest_name_invalid"}

    def test_matches_the_column_width(self) -> None:
        ok = "a" * GUEST_DISPLAY_NAME_MAX_LENGTH
        assert normalize_guest_display_name(ok) == ok
        with pytest.raises(GuestNameInvalidError):
            normalize_guest_display_name(ok + "a")
        # Measured AFTER cleaning: padding does not count against the limit.
        assert normalize_guest_display_name(f"   {ok}   ") == ok

    def test_control_characters_are_rejected(self) -> None:
        with pytest.raises(GuestNameInvalidError):
            normalize_guest_display_name("Asha\x00Rao")

    def test_the_column_width_is_the_models(self) -> None:
        from app.domains.guest.models import Guest

        assert Guest.__table__.c.display_name.type.length == (
            GUEST_DISPLAY_NAME_MAX_LENGTH
        )


class TestThePredicate:
    def _session(self, method: str):  # noqa: ANN202
        return type("S", (), {"auth_method": method})()

    def _guest(self, name: str | None):  # noqa: ANN202
        return type("G", (), {"display_name": name})()

    @pytest.mark.parametrize("method", ["otp_sms", "otp_email", "otp_whatsapp"])
    def test_held_for_every_otp_method(self, method: str) -> None:
        assert session_awaits_required_name(
            session=self._session(method),
            guest=self._guest(None),
            require_guest_name=True,
        )

    @pytest.mark.parametrize(
        "method", ["voucher", "username_password", "pin", "mac_whitelist"]
    )
    def test_other_methods_are_out_of_scope(self, method: str) -> None:
        assert not session_awaits_required_name(
            session=self._session(method),
            guest=self._guest(None),
            require_guest_name=True,
        )

    def test_a_name_on_file_satisfies_it(self) -> None:
        assert not session_awaits_required_name(
            session=self._session("otp_sms"),
            guest=self._guest("Asha"),
            require_guest_name=True,
        )

    def test_a_blank_stored_name_does_not(self) -> None:
        assert session_awaits_required_name(
            session=self._session("otp_sms"),
            guest=self._guest("   "),
            require_guest_name=True,
        )

    def test_off_means_off(self) -> None:
        assert not session_awaits_required_name(
            session=self._session("otp_sms"),
            guest=self._guest(None),
            require_guest_name=False,
        )


# ============================================================================
# Required + missing -> refused at every gate, with the code
# ============================================================================


class TestRequiredAndMissing:
    async def test_login_succeeds_but_reports_name_required(self) -> None:
        from app.domains.guest.router import _login_response

        fx = make_fixture(require_guest_name=True)
        result = await _otp_login(fx)

        assert result.name_required is True
        assert _login_response(result).name_required is True
        # The session exists -- the OTP is spent and must not be re-asked.
        assert result.session.status == "active"

    async def test_radius_authorize_rejects_until_the_name_is_stored(self) -> None:
        fx = make_fixture(require_guest_name=True)
        login = await _otp_login(fx)
        nas = await _nas(fx)

        before = await fx.radius_service.authorize(nas_client=nas, username=PHONE)
        assert before.authorized is False

        await fx.guest_service.submit_sign_in_name(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name="Asha Rao",
        )
        after = await fx.radius_service.authorize(nas_client=nas, username=PHONE)
        assert after.authorized is True

    async def test_agent_bypass_list_leaves_the_mac_out_until_named(self) -> None:
        fx = make_fixture(require_guest_name=True)
        login = await _otp_login(fx)

        assert await _authorized_macs(fx) == []

        await fx.guest_service.submit_sign_in_name(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name="Asha",
        )
        assert await _authorized_macs(fx) == ["AA:BB:CC:DD:EE:FF"]

    async def test_require_session_name_raises_the_stable_code(self) -> None:
        fx = make_fixture(require_guest_name=True)
        login = await _otp_login(fx)

        with pytest.raises(GuestNameRequiredError) as exc:
            await fx.guest_service.require_session_name(session_id=login.session.id)
        assert exc.value.status_code == 403
        assert exc.value.data == {"code": "guest_name_required"}

    async def test_unknown_session_is_not_answered_by_the_name_gate(self) -> None:
        """The portal-authorize proof-of-session check owns the opaque
        refusal for a session that does not exist; the name gate must not
        become a second, distinguishable oracle for it."""
        fx = make_fixture(require_guest_name=True)
        await fx.guest_service.require_session_name(session_id=uuid.uuid4())

    async def test_omada_portal_authorize_is_refused_before_the_controller(
        self,
    ) -> None:
        service, provider, session_id, org, location = omada_fixture(
            session_timeout_minutes=30
        )

        @dataclass
        class _Gate:
            asked: list[uuid.UUID] = field(default_factory=list)

            async def require_session_name(self, *, session_id: uuid.UUID) -> None:
                self.asked.append(session_id)
                raise GuestNameRequiredError()

        gate = _Gate()
        service.guest_name_gate = gate
        with pytest.raises(GuestNameRequiredError):
            await _authorize(service, session_id, org, location)
        # Asked AFTER the session was proven, and the controller never was.
        assert gate.asked == [session_id]
        assert provider.authorize_durations == []

    async def test_missing_name_on_sign_in_name_endpoint_is_400_with_code(
        self,
    ) -> None:
        fx = make_fixture(require_guest_name=True)
        login = await _otp_login(fx)
        with pytest.raises(GuestNameInvalidError) as exc:
            await fx.guest_service.submit_sign_in_name(
                guest_id=login.guest.id,
                session_id=login.session.id,
                display_name="   ",
            )
        assert exc.value.data == {"code": "guest_name_invalid"}
        stored = await fx.repository.get_guest_by_id(login.guest.id)
        assert stored is not None and stored.display_name is None

    async def test_reload_reports_the_bit_on_the_active_session_lookup(self) -> None:
        """A guest who reloads on the name screen must land back on it."""
        fx = make_fixture(require_guest_name=True)
        await _otp_login(fx)
        found = await fx.guest_service.get_active_session_for_device(
            router_id=fx.router.id, device_mac=MAC
        )
        assert found is not None and found.name_required is True


# ============================================================================
# Required + present -> stored, admitted
# ============================================================================


class TestRequiredAndPresent:
    async def test_name_is_stored_cleaned_on_the_guest(self) -> None:
        fx = make_fixture(require_guest_name=True)
        login = await _otp_login(fx)

        guest = await fx.guest_service.submit_sign_in_name(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name="  Asha   Rao ",
        )

        assert guest.display_name == "Asha Rao"
        assert not await fx.guest_service.session_awaits_required_name(login.session)

    async def test_returning_guest_with_a_name_is_not_held(self) -> None:
        fx = make_fixture(require_guest_name=True)
        first = await _otp_login(fx)
        await fx.guest_service.submit_sign_in_name(
            guest_id=first.guest.id,
            session_id=first.session.id,
            display_name="Asha",
        )
        again = await _otp_login(fx)
        assert again.name_required is False

    async def test_latest_typed_name_wins(self) -> None:
        """Documented semantics: last write wins, the same rule the
        post-connect profile write already applies to display_name."""
        fx = make_fixture(require_guest_name=True)
        login = await _otp_login(fx)
        await fx.guest_service.submit_sign_in_name(
            guest_id=login.guest.id, session_id=login.session.id, display_name="Asha"
        )
        guest = await fx.guest_service.submit_sign_in_name(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name="Asha Rao",
        )
        assert guest.display_name == "Asha Rao"

    async def test_a_session_belonging_to_someone_else_cannot_write(self) -> None:
        fx = make_fixture(require_guest_name=True)
        mine = await _otp_login(fx)
        theirs = await _otp_login(
            fx, identifier="+15557654321", mac="11:22:33:44:55:66"
        )
        with pytest.raises(GuestProfileUpdateNotAuthorizedError):
            await fx.guest_service.submit_sign_in_name(
                guest_id=mine.guest.id,
                session_id=theirs.session.id,
                display_name="Mallory",
            )

    async def test_a_non_otp_session_cannot_use_the_sign_in_name_path(self) -> None:
        fx = make_fixture(require_guest_name=True)
        fx.voucher_service.register("VOUCHER1", data_limit_mb=None, validity_minutes=60)
        voucher = await fx.guest_service.login_via_voucher(
            code="VOUCHER1",
            identifier=PHONE,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac=MAC,
        )
        assert voucher.name_required is False
        with pytest.raises(GuestProfileUpdateNotAuthorizedError):
            await fx.guest_service.submit_sign_in_name(
                guest_id=voucher.guest.id,
                session_id=voucher.session.id,
                display_name="Asha",
            )


# ============================================================================
# Not required -> unchanged behaviour
# ============================================================================


class TestNotRequired:
    async def test_venue_that_turned_it_off_is_never_held(self) -> None:
        fx = make_fixture(require_guest_name=False)
        login = await _otp_login(fx)
        nas = await _nas(fx)

        assert login.name_required is False
        assert (
            await fx.radius_service.authorize(nas_client=nas, username=PHONE)
        ).authorized is True
        assert await _authorized_macs(fx) == ["AA:BB:CC:DD:EE:FF"]
        await fx.guest_service.require_session_name(session_id=login.session.id)

    async def test_off_and_not_collecting_refuses_the_write(self) -> None:
        """DPDP: with neither flag on, the venue has not agreed to hold a
        name, so even this path refuses it -- the same rule as the
        post-connect profile write."""
        fx = make_fixture(require_guest_name=False, collect_guest_name=False)
        login = await _otp_login(fx)
        with pytest.raises(GuestProfileFieldNotCollectedError):
            await fx.guest_service.submit_sign_in_name(
                guest_id=login.guest.id,
                session_id=login.session.id,
                display_name="Asha",
            )

    async def test_post_connect_profile_endpoint_is_untouched(self) -> None:
        fx = make_fixture(require_guest_name=False)
        login = await _otp_login(fx)
        guest = await fx.guest_service.update_guest_profile(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name="Priya",
            email=None,
        )
        assert guest.display_name == "Priya"

    async def test_an_unresolvable_config_fails_open(self) -> None:
        fx = make_fixture(require_guest_name=True)
        login = await _otp_login(fx)

        async def _boom(**_: object) -> ResolvedPortalConfig:
            raise CloudGuestError("config gone", status_code=404)

        fx.captive_portal_service.resolve_portal_config = _boom  # type: ignore[method-assign]
        assert not await fx.guest_service.session_awaits_required_name(login.session)


# ============================================================================
# Config resolution by the SESSION's location
# ============================================================================


class TestResolvedBySessionLocation:
    """``Guest.location_id`` is the guest's home venue and is never
    constrained to match the session's. At a multi-location chain the
    requirement must follow the venue the guest is standing in."""

    def _per_location(self, fx: Fixture, overrides: dict[uuid.UUID, bool]) -> None:
        base = fx.captive_portal_service.configs_by_org[fx.organization_id]
        configs: dict[uuid.UUID, CaptivePortalConfig] = {
            loc: _copy_config(base, require_guest_name=flag)
            for loc, flag in overrides.items()
        }

        async def resolve(
            *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
        ) -> ResolvedPortalConfig:
            assert location_id is not None
            return ResolvedPortalConfig(
                config=configs[location_id], resolved_via_location_override=True
            )

        fx.captive_portal_service.resolve_portal_config = resolve  # type: ignore[method-assign]

    async def test_session_venue_requires_guest_home_venue_does_not(self) -> None:
        fx = make_fixture()
        home = uuid.uuid4()
        self._per_location(fx, {fx.location_id: True, home: False})
        login = await _otp_login(fx)
        # Pretend the guest was first seen at another venue of the chain.
        await fx.repository.update_guest(login.guest, {"location_id": home})

        assert login.name_required is True
        assert await fx.guest_service.session_awaits_required_name(login.session)

    async def test_guest_home_venue_requires_session_venue_does_not(self) -> None:
        fx = make_fixture()
        home = uuid.uuid4()
        self._per_location(fx, {fx.location_id: False, home: True})
        login = await _otp_login(fx)
        await fx.repository.update_guest(login.guest, {"location_id": home})

        assert login.name_required is False
        assert not await fx.guest_service.session_awaits_required_name(login.session)


def _copy_config(base: CaptivePortalConfig, **changes: object) -> CaptivePortalConfig:
    clone = CaptivePortalConfig(
        **{
            c.key: getattr(base, c.key)
            for c in CaptivePortalConfig.__table__.columns
            if c.key in base.__dict__
        }
    )
    for k, v in changes.items():
        setattr(clone, k, v)
    return clone


# ============================================================================
# Defaults (owner decision: ON for every venue) and required => collected
# ============================================================================


class TestDefaults:
    def test_model_column_defaults_on_with_a_server_default(self) -> None:
        column = CaptivePortalConfig.__table__.c.require_guest_name
        assert column.default.arg is True
        assert str(column.server_default.arg) == "true"
        assert column.nullable is False

    def test_create_schema_defaults_on(self) -> None:
        field_info = CaptivePortalConfigCreateRequest.model_fields["require_guest_name"]
        assert field_info.default is True

    def test_response_schemas_carry_the_field(self) -> None:
        assert "require_guest_name" in CaptivePortalConfigResponse.model_fields

    def test_migration_backfills_on_and_implies_collection(self) -> None:
        versions = Path(__file__).resolve().parents[2] / "alembic" / "versions"
        text = (
            versions / "0143_add_require_guest_name_to_captive_portal_configs.py"
        ).read_text()
        assert 'server_default=sa.text("true")' in text
        assert "SET collect_guest_name = true" in text
        assert 'down_revision = "0142_create_instant_on_poller_tables"' in text

    async def test_created_config_defaults_on_and_collects(self) -> None:
        fx = make_service()
        config = await _create_config(fx, collect_guest_name=False)
        assert config.require_guest_name is True
        assert config.collect_guest_name is True

    async def test_a_venue_can_turn_it_off(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"require_guest_name": False, "collect_guest_name": False},
        )
        assert updated.require_guest_name is False
        assert updated.collect_guest_name is False

    async def test_required_wins_over_an_explicit_collect_false(self) -> None:
        """The dashboard PUTs its whole form; a bundle that predates the
        toggle must still be able to save, and must not leave a venue
        requiring a name it does not collect."""
        fx = make_service()
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"collect_guest_name": False},
        )
        assert updated.require_guest_name is True
        assert updated.collect_guest_name is True

    async def test_turning_it_back_on_turns_collection_on(self) -> None:
        fx = make_service()
        config = await _create_config(
            fx, require_guest_name=False, collect_guest_name=False
        )
        assert config.collect_guest_name is False
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"require_guest_name": True},
        )
        assert updated.collect_guest_name is True



class TestNoConfigResolvesToRequired:
    """Owner decision: the default is ON, including when no config row
    resolves at all (e.g. the venue's config was deleted after this
    session's login). The name screen must still be able to clear it."""

    def _no_config(self, fx: Fixture) -> None:
        from app.domains.captive_portal.exceptions import (
            CaptivePortalConfigNotConfiguredError,
        )

        async def resolve(
            *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
        ) -> ResolvedPortalConfig:
            raise CaptivePortalConfigNotConfiguredError(fx.organization_id)

        fx.captive_portal_service.resolve_portal_config = resolve  # type: ignore[method-assign]

    async def test_gate_holds_and_the_name_screen_clears_it(self) -> None:
        fx = make_fixture(require_guest_name=False)
        login = await _otp_login(fx)
        assert login.name_required is False
        self._no_config(fx)

        assert await fx.guest_service.session_awaits_required_name(login.session)
        with pytest.raises(GuestNameRequiredError):
            await fx.guest_service.require_session_name(session_id=login.session.id)

        await fx.guest_service.submit_sign_in_name(
            guest_id=login.guest.id,
            session_id=login.session.id,
            display_name="Asha",
        )
        assert not await fx.guest_service.session_awaits_required_name(login.session)

    async def test_agent_bypass_list_reads_no_config_as_required(self) -> None:
        fx = make_fixture(require_guest_name=False)
        await _otp_login(fx)
        assert await _authorized_macs(fx) == ["AA:BB:CC:DD:EE:FF"]
        self._no_config(fx)
        assert await _authorized_macs(fx) == []

    def test_a_config_without_the_attribute_reads_as_required(self) -> None:
        from app.domains.guest.service import _venue_requires_name

        assert _venue_requires_name(object()) is True
