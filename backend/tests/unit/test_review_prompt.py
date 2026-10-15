"""The "Rate us on Google" page after portal login (SPEC google-review).

Covers: Place ID normalisation and the link allowlist on write; the
server-side ``review_prompt_due`` rule (per location, 30-day cooldown,
never after a tap); ``POST /guest/review-prompt-shown``; the session-level
stamp on ``/guest/review-link-opened``; and ``GET
/captive-portal/review-stats`` (explicit scope, org check, required
location).
"""

from __future__ import annotations

import inspect
import types
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.domains.captive_portal.constants import (
    REVIEW_PROMPT_COOLDOWN,
    REVIEW_URL_PLACE_ID_TEMPLATE,
)
from app.domains.captive_portal.exceptions import (
    CrossOrganizationCaptivePortalConfigAccessError,
    InvalidReviewUrlError,
    ReviewStatsCrossLocationError,
    ReviewStatsLocationNotFoundError,
)
from app.domains.captive_portal.validators import (
    normalize_review_url,
    validate_review_url,
)
from app.domains.guest.constants import GuestAuthMethod, GuestSessionStatus
from app.domains.guest.exceptions import GuestReviewPromptNotAuthorizedError
from app.domains.guest.repository import GuestRepository
from app.domains.rbac.enums import ScopeType

from .test_captive_portal import _create_config, make_service
from .test_guest import Fixture as GuestFixture
from .test_guest import make_fixture

PLACE_ID = "ChIJN1t_tDeuEmsRUsoyG83frY4"
GOOD_URL = "https://g.page/r/CabcXYZ123/review"


# ============================================================================
# Normalisation + allowlist (AC 2-3)
# ============================================================================


class TestNormalizeReviewUrl:
    def test_a_bare_place_id_becomes_a_writereview_link(self) -> None:
        assert normalize_review_url(PLACE_ID) == REVIEW_URL_PLACE_ID_TEMPLATE.format(
            place_id=PLACE_ID
        )
        assert normalize_review_url(f"  {PLACE_ID}  ").endswith(f"placeid={PLACE_ID}")

    def test_the_normalised_link_passes_the_allowlist(self) -> None:
        validate_review_url(normalize_review_url(PLACE_ID))

    @pytest.mark.parametrize(
        "value",
        [
            GOOD_URL,
            "https://search.google.com/local/writereview?placeid=abc",
            "https://maps.app.goo.gl/AbCdEf",
            "https://goo.gl/maps/AbCdEf",
        ],
    )
    def test_a_pasted_link_is_left_verbatim(self, value: str) -> None:
        assert normalize_review_url(value) == value

    @pytest.mark.parametrize(
        "value",
        ["short", "has.a.dot.in.it.and.long.enough", "a/b/c/d/e/f/g/h/i/j/k/l"],
    )
    def test_anything_that_is_not_a_place_id_is_not_rewritten(self, value: str) -> None:
        assert normalize_review_url(value) == value

    def test_none_and_blank_pass_through(self) -> None:
        assert normalize_review_url(None) is None
        assert normalize_review_url("") == ""
        assert normalize_review_url("   ") == "   "


class TestReviewUrlNegatives:
    @pytest.mark.parametrize(
        "value",
        [
            "http://g.page/r/x",
            "https://google.evil.com/x",
            "https://evil.com\\@google.com/",
            "https://user@google.com/",
            "https://notgoogle.com/",
            "javascript:alert(1)",
        ],
    )
    def test_rejected_after_normalisation(self, value: str) -> None:
        with pytest.raises(InvalidReviewUrlError):
            validate_review_url(normalize_review_url(value))


class TestPlaceIdThroughTheService:
    async def test_create_stores_the_normalised_link(self) -> None:
        fx = make_service()
        config = await _create_config(fx, review_url=PLACE_ID)
        assert config.review_url == REVIEW_URL_PLACE_ID_TEMPLATE.format(
            place_id=PLACE_ID
        )

    async def test_update_stores_the_normalised_link(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"review_url": PLACE_ID, "review_card_enabled": True},
        )
        assert updated.review_url.endswith(f"placeid={PLACE_ID}")

    async def test_update_still_rejects_a_bad_link(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        with pytest.raises(InvalidReviewUrlError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"review_url": "https://google.evil.com/x"},
            )

    async def test_blank_clears_the_link(self) -> None:
        fx = make_service()
        config = await _create_config(fx, review_url=GOOD_URL)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"review_url": None},
        )
        assert updated.review_url is None

    async def test_another_organization_cannot_edit_the_link(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        with pytest.raises(CrossOrganizationCaptivePortalConfigAccessError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=uuid.uuid4(),
                data={"review_url": PLACE_ID},
            )


# ============================================================================
# review_prompt_due (AC 6) and the two guest endpoints (AC 7-8)
# ============================================================================


async def _login(fx: GuestFixture, mac: str = "aa:bb:cc:dd:ee:ff"):
    return await fx.guest_service.login_via_otp(
        identifier="+15551234567",
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
    )


def _enable(fx: GuestFixture, *, enabled: bool = True, url: str | None = GOOD_URL):
    config = fx.captive_portal_service.configs_by_org[fx.organization_id]
    config.review_card_enabled = enabled
    config.review_url = url


def _other_session(session: Any, *, location_id: uuid.UUID | None = None) -> Any:
    """A fresh session for the same guest, as a later visit would have."""
    return types.SimpleNamespace(
        id=uuid.uuid4(),
        guest_id=session.guest_id,
        organization_id=session.organization_id,
        location_id=location_id or session.location_id,
        started_at=datetime.now(UTC),
        review_prompt_shown_at=None,
        review_link_opened_at=None,
    )


class TestReviewPromptDue:
    async def test_due_when_enabled_with_a_valid_link(self) -> None:
        fx = make_fixture()
        _enable(fx)
        login = await _login(fx)
        assert await fx.guest_service.review_prompt_due(login.guest, login.session)

    async def test_not_due_when_switched_off(self) -> None:
        fx = make_fixture()
        _enable(fx, enabled=False)
        login = await _login(fx)
        assert not await fx.guest_service.review_prompt_due(login.guest, login.session)

    @pytest.mark.parametrize("url", [None, "", "   ", "https://example.com/r"])
    async def test_not_due_without_a_valid_link(self, url: str | None) -> None:
        fx = make_fixture()
        _enable(fx, url=url)
        login = await _login(fx)
        assert not await fx.guest_service.review_prompt_due(login.guest, login.session)

    async def test_never_again_at_this_location_after_a_tap(self) -> None:
        fx = make_fixture()
        _enable(fx)
        login = await _login(fx)
        await fx.guest_service.record_review_link_opened(
            guest_id=login.guest.id, session_id=login.session.id
        )
        # Clear the org-level stamp so only the session-level rule is tested.
        login.guest.review_link_opened_at = None
        later = _other_session(login.session)
        later.started_at = datetime.now(UTC) + 2 * REVIEW_PROMPT_COOLDOWN
        assert not await fx.guest_service.review_prompt_due(login.guest, later)

    async def test_not_due_within_the_cooldown_at_this_location(self) -> None:
        fx = make_fixture()
        _enable(fx)
        login = await _login(fx)
        await fx.guest_service.record_review_prompt_shown(
            guest_id=login.guest.id, session_id=login.session.id
        )
        assert not await fx.guest_service.review_prompt_due(
            login.guest, _other_session(login.session)
        )

    async def test_due_again_after_the_cooldown(self) -> None:
        fx = make_fixture()
        _enable(fx)
        login = await _login(fx)
        login.session.review_prompt_shown_at = (
            datetime.now(UTC) - REVIEW_PROMPT_COOLDOWN - timedelta(minutes=1)
        )
        assert await fx.guest_service.review_prompt_due(
            login.guest, _other_session(login.session)
        )

    async def test_not_due_again_in_the_session_that_showed_it(self) -> None:
        fx = make_fixture()
        _enable(fx)
        login = await _login(fx)
        await fx.guest_service.record_review_prompt_shown(
            guest_id=login.guest.id, session_id=login.session.id
        )
        assert not await fx.guest_service.review_prompt_due(login.guest, login.session)

    async def test_legacy_org_level_tap_means_never(self) -> None:
        fx = make_fixture()
        _enable(fx)
        login = await _login(fx)
        login.guest.review_link_opened_at = datetime.now(UTC) - timedelta(days=400)
        assert not await fx.guest_service.review_prompt_due(login.guest, login.session)

    async def test_due_at_a_different_location_of_the_same_org(self) -> None:
        fx = make_fixture()
        _enable(fx)
        login = await _login(fx)
        await fx.guest_service.record_review_prompt_shown(
            guest_id=login.guest.id, session_id=login.session.id
        )
        branch_b = uuid.uuid4()
        fx.captive_portal_service.add_location(branch_b, fx.organization_id)
        assert await fx.guest_service.review_prompt_due(
            login.guest, _other_session(login.session, location_id=branch_b)
        )

    async def test_never_raises(self) -> None:
        fx = make_fixture()
        _enable(fx)
        login = await _login(fx)

        async def boom(**_: object) -> bool:
            raise RuntimeError("db down")

        fx.repository.has_blocking_review_activity = boom  # type: ignore[method-assign]
        assert not await fx.guest_service.review_prompt_due(login.guest, login.session)

    async def test_the_bits_reach_the_login_payload(self) -> None:
        from app.domains.guest.router import _login_payload

        class _NoOffer:
            async def offer_for(self, _result: object) -> None:
                return None

        fx = make_fixture()
        _enable(fx)
        login = await _login(fx)
        payload = await _login_payload(login, _NoOffer(), fx.guest_service)
        assert payload["review_prompt_due"] is True
        assert payload["review_shown_this_session"] is False

        await fx.guest_service.record_review_prompt_shown(
            guest_id=login.guest.id, session_id=login.session.id
        )
        payload = await _login_payload(login, _NoOffer(), fx.guest_service)
        assert payload["review_prompt_due"] is False
        assert payload["review_shown_this_session"] is True
        # The deprecated bit still goes out for older portals.
        assert payload["has_opened_review_link"] is False


class TestReviewPromptShown:
    async def test_stamps_the_session(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        updated = await fx.guest_service.record_review_prompt_shown(
            guest_id=login.guest.id, session_id=login.session.id
        )
        assert updated.review_prompt_shown_at is not None
        assert fx.guest_service.review_shown_this_session(updated)

    async def test_idempotent(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        first = await fx.guest_service.record_review_prompt_shown(
            guest_id=login.guest.id, session_id=login.session.id
        )
        stamp = first.review_prompt_shown_at
        second = await fx.guest_service.record_review_prompt_shown(
            guest_id=login.guest.id, session_id=login.session.id
        )
        assert second.review_prompt_shown_at >= stamp

    async def test_unknown_session_is_refused(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        with pytest.raises(GuestReviewPromptNotAuthorizedError):
            await fx.guest_service.record_review_prompt_shown(
                guest_id=login.guest.id, session_id=uuid.uuid4()
            )

    async def test_another_guests_session_is_refused(self) -> None:
        fx = make_fixture()
        mine = await _login(fx)
        theirs = await fx.guest_service.login_via_otp(
            identifier="+15557654321",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="11:22:33:44:55:66",
        )
        with pytest.raises(GuestReviewPromptNotAuthorizedError):
            await fx.guest_service.record_review_prompt_shown(
                guest_id=mine.guest.id, session_id=theirs.session.id
            )

    async def test_an_ended_session_is_refused(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        login.session.status = GuestSessionStatus.DISCONNECTED.value
        with pytest.raises(GuestReviewPromptNotAuthorizedError):
            await fx.guest_service.record_review_prompt_shown(
                guest_id=login.guest.id, session_id=login.session.id
            )

    def test_the_403_shape(self) -> None:
        assert GuestReviewPromptNotAuthorizedError().status_code == 403

    def test_shown_before_the_session_started_does_not_count(self) -> None:
        from app.domains.guest.service import GuestService

        now = datetime.now(UTC)
        session = types.SimpleNamespace(
            started_at=now, review_prompt_shown_at=now - timedelta(seconds=1)
        )
        assert GuestService.review_shown_this_session(session) is False  # type: ignore[arg-type]


class TestReviewLinkOpenedStampsTheSession:
    async def test_both_stamps(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        guest = await fx.guest_service.record_review_link_opened(
            guest_id=login.guest.id, session_id=login.session.id
        )
        assert guest.review_link_opened_at is not None
        assert login.session.review_link_opened_at is not None


# ============================================================================
# GET /captive-portal/review-stats (AC 4-5)
# ============================================================================


def _stats_route() -> Any:
    from app.domains.captive_portal.router import router

    return next(r for r in router.routes if r.path == "/captive-portal/review-stats")


class _Result:
    def __init__(self, row: tuple[int, int]) -> None:
        self._row = row

    def one(self) -> tuple[int, int]:
        return self._row


class _FakeDb:
    def __init__(self, location: Any | None, row: tuple[int, int] = (412, 57)) -> None:
        self.location = location
        self.row = row
        self.statements: list[Any] = []

    async def get(self, _model: Any, ident: uuid.UUID) -> Any:
        if self.location is not None and self.location.id == ident:
            return self.location
        return None

    async def execute(self, statement: Any) -> _Result:
        self.statements.append(statement)
        return _Result(self.row)


def _location(org: uuid.UUID) -> Any:
    return types.SimpleNamespace(id=uuid.uuid4(), organization_id=org, is_deleted=False)


def _request() -> Any:
    return types.SimpleNamespace(state=types.SimpleNamespace(request_id="rid"))


class TestReviewStatsRoute:
    def test_scope_is_declared_explicitly(self) -> None:
        route = _stats_route()
        cells = [
            c.cell_contents
            for d in route.dependencies
            for c in (getattr(d.dependency, "__closure__", None) or ())
        ]
        assert "captive_portal.read" in cells
        assert ScopeType.LOCATION in cells

    def test_location_id_is_required(self) -> None:
        route = _stats_route()
        params = {p.name: p for p in route.dependant.query_params}
        assert params["location_id"].required is True
        assert params["days"].required is False

    async def test_returns_counts_for_the_callers_location(self) -> None:
        from app.domains.captive_portal.router import get_review_stats

        org = uuid.uuid4()
        loc = _location(org)
        db = _FakeDb(loc)
        out = await get_review_stats(
            request=_request(),
            location_id=loc.id,
            days=30,
            requesting_organization_id=org,
            header_location_id=None,
            db=db,
        )
        assert out["success"] is True
        assert out["data"]["shown"] == 412
        assert out["data"]["opened"] == 57
        assert out["data"]["days"] == 30
        assert out["data"]["location_id"] == str(loc.id)

    async def test_another_orgs_location_is_a_404(self) -> None:
        from app.domains.captive_portal.router import get_review_stats

        loc = _location(uuid.uuid4())
        with pytest.raises(ReviewStatsLocationNotFoundError) as exc:
            await get_review_stats(
                request=_request(),
                location_id=loc.id,
                days=30,
                requesting_organization_id=uuid.uuid4(),
                header_location_id=None,
                db=_FakeDb(loc),
            )
        assert exc.value.status_code == 404

    async def test_missing_location_is_a_404(self) -> None:
        from app.domains.captive_portal.router import get_review_stats

        with pytest.raises(ReviewStatsLocationNotFoundError):
            await get_review_stats(
                request=_request(),
                location_id=uuid.uuid4(),
                days=30,
                requesting_organization_id=uuid.uuid4(),
                header_location_id=None,
                db=_FakeDb(None),
            )

    async def test_a_mismatched_location_header_is_refused(self) -> None:
        from app.domains.captive_portal.router import get_review_stats

        org = uuid.uuid4()
        loc = _location(org)
        with pytest.raises(ReviewStatsCrossLocationError):
            await get_review_stats(
                request=_request(),
                location_id=loc.id,
                days=30,
                requesting_organization_id=org,
                header_location_id=uuid.uuid4(),
                db=_FakeDb(loc),
            )

    async def test_global_admin_reads_one_location_only(self) -> None:
        from app.domains.captive_portal.router import get_review_stats

        loc = _location(uuid.uuid4())
        db = _FakeDb(loc)
        await get_review_stats(
            request=_request(),
            location_id=loc.id,
            days=7,
            requesting_organization_id=None,
            header_location_id=None,
            db=db,
        )
        sql = str(
            db.statements[0].compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
        assert "guest_sessions.location_id = " in sql
        assert loc.id.hex in sql.replace("-", "")


class TestRepositoryQueries:
    async def test_blocking_query_compiles_and_is_location_scoped(self) -> None:
        db = _FakeDb(None)

        class _Scalar:
            def scalar_one(self) -> bool:
                return False

        async def execute(statement: Any) -> _Scalar:
            db.statements.append(statement)
            return _Scalar()

        db.execute = execute  # type: ignore[method-assign]
        repo = GuestRepository(db)  # type: ignore[arg-type]
        assert not await repo.has_blocking_review_activity(
            guest_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            shown_since=datetime.now(UTC),
        )
        sql = str(db.statements[0].compile(dialect=postgresql.dialect()))
        assert "guest_sessions.location_id" in sql
        assert "review_link_opened_at IS NOT NULL" in sql

    def test_cooldown_is_thirty_days(self) -> None:
        assert timedelta(days=30) == REVIEW_PROMPT_COOLDOWN

    def test_stats_signature_has_no_all_locations_form(self) -> None:
        from app.domains.captive_portal.router import get_review_stats

        sig = inspect.signature(get_review_stats)
        assert sig.parameters["location_id"].default is not None


class TestMigration:
    def test_0166_is_the_single_head(self) -> None:
        import pathlib

        versions = list(pathlib.Path("alembic/versions").glob("*.py"))
        name = "0166_add_review_prompt_columns_to_guest_sessions"
        text = pathlib.Path(f"alembic/versions/{name}.py").read_text()
        assert f'revision = "{name}"' in text
        assert 'down_revision = "0165_traffic_flow_platform_hosts"' in text
        children = [
            p.name for p in versions if f'down_revision = "{name}"' in p.read_text()
        ]
        assert not children
