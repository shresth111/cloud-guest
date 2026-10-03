"""WISPr-Bandwidth-Max-Down/-Up on an Aruba Instant On Access-Accept.

An EXPERIMENT, not a feature. Instant On has no router API, no controller
API and no CoA, so the RADIUS reply is the only way a speed could reach a
guest there -- and no Aruba document says Instant On honours any per-user
rate attribute. These attributes are therefore sent only to NAS-only routers
named in ``Settings.radius_bandwidth_attribute_router_ids`` (empty by
default), so a hardware measurement on staging can decide. The customer
dashboard's Bandwidth control stays greyed until it does.

What is pinned here:

* a gated Aruba router gets the guest's BANDWIDTH policy rate in bits/s;
* an un-gated Aruba router, a rejected request, an unlimited (0/0) policy and
  a failing policy lookup get nothing -- and the failure never rejects;
* MikroTik and Omada replies are byte-identical whether or not their own id
  is in the gate (it is ignored for them).
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.common.exceptions import register_exception_handlers
from app.core.config import Settings
from app.domains.guest.constants import (
    RADIUS_NAS_IDENTIFIER_HEADER,
    RADIUS_SHARED_SECRET_HEADER,
)
from app.domains.guest.dependencies import get_radius_service
from app.domains.guest.router import radius_router
from app.domains.policy.constants import PolicyType
from tests.unit.test_aruba_access_rules import (
    _ARUBA_CSID,
    _PHONE,
    _authorize,
    _fixture,
    _PolicyLookup,
    _register_nas,
    _sign_in,
)

_NAS_ID = "cg-aruba-test"
_NAS_SECRET = "supersecret123"
_WISPR_KEYS = ("WISPr-Bandwidth-Max-Down", "WISPr-Bandwidth-Max-Up")


def _bandwidth(download_kbps: int, upload_kbps: int) -> _PolicyLookup:
    return _PolicyLookup(
        rules={
            PolicyType.BANDWIDTH: {
                "download_rate_kbps": download_kbps,
                "upload_rate_kbps": upload_kbps,
            }
        }
    )


def _gate(fx) -> None:  # noqa: ANN001
    fx.radius_service.bandwidth_attribute_router_ids = frozenset({fx.router.id})


class _RecordingLookup(_PolicyLookup):
    calls: list[dict]

    def __init__(self, **kwargs) -> None:  # noqa: ANN003
        super().__init__(**kwargs)
        self.calls = []

    async def resolve_effective_policy(self, **kwargs):  # noqa: ANN003, ANN201
        self.calls.append(kwargs)
        return await super().resolve_effective_policy(**kwargs)


class _FakeQueueLookup:
    async def get_rate_limit_reply_for_session(self, session_id: uuid.UUID) -> str:
        return "512k/2048k"


# ============================================================================
# RadiusService.authorize
# ============================================================================


class TestGatedArubaRouter:
    async def test_the_bandwidth_policy_rate_is_sent_in_bits_per_second(self) -> None:
        fx = _fixture(policy_lookup=_bandwidth(2048, 512))
        _gate(fx)
        nas = await _register_nas(fx)
        await _sign_in(fx)

        result = await _authorize(fx, nas)

        assert result.authorized is True
        # kbps * 1000 -- the same "k" format_mikrotik_rate_limit uses.
        assert result.bandwidth_max_down_bps == 2_048_000
        assert result.bandwidth_max_up_bps == 512_000
        # Still no MikroTik VSA at an Aruba venue (PR #339's rule).
        assert result.rate_limit is None

    async def test_a_guest_mapped_group_is_resolved_for_this_guest(self) -> None:
        """Same resolution queue_management uses: org + location + guest_id,
        so a Group Policies "Map users" override wins for the mapped guest."""
        lookup = _RecordingLookup(
            rules={
                PolicyType.BANDWIDTH: {
                    "download_rate_kbps": 2000,
                    "upload_rate_kbps": 1000,
                }
            }
        )
        fx = _fixture(policy_lookup=lookup)
        _gate(fx)
        nas = await _register_nas(fx)
        login = await _sign_in(fx)

        await _authorize(fx, nas)

        bandwidth_calls = [
            c for c in lookup.calls if c["policy_type"] == PolicyType.BANDWIDTH
        ]
        assert bandwidth_calls, "the BANDWIDTH policy was never resolved"
        call = bandwidth_calls[-1]
        assert call["guest_id"] == login.session.guest_id
        assert call["location_id"] == login.session.location_id
        assert call["organization_id"] == login.session.organization_id

    async def test_an_unlimited_policy_sends_nothing(self) -> None:
        fx = _fixture(policy_lookup=_bandwidth(0, 0))
        _gate(fx)
        nas = await _register_nas(fx)
        await _sign_in(fx)

        result = await _authorize(fx, nas)

        assert result.authorized is True
        assert result.bandwidth_max_down_bps is None
        assert result.bandwidth_max_up_bps is None

    async def test_a_direction_at_zero_is_omitted_not_sent_as_zero(self) -> None:
        """0 bits/s is not "unlimited" on the wire; absence is."""
        fx = _fixture(policy_lookup=_bandwidth(2048, 0))
        _gate(fx)
        nas = await _register_nas(fx)
        await _sign_in(fx)

        result = await _authorize(fx, nas)

        assert result.bandwidth_max_down_bps == 2_048_000
        assert result.bandwidth_max_up_bps is None

    async def test_no_bandwidth_policy_sends_nothing(self) -> None:
        fx = _fixture(policy_lookup=_PolicyLookup())
        _gate(fx)
        nas = await _register_nas(fx)
        await _sign_in(fx)

        result = await _authorize(fx, nas)

        assert result.authorized is True
        assert result.bandwidth_max_down_bps is None
        assert result.bandwidth_max_up_bps is None

    async def test_a_failing_policy_lookup_still_accepts_and_sends_nothing(
        self,
    ) -> None:
        fx = _fixture(policy_lookup=_bandwidth(2048, 512))
        _gate(fx)
        nas = await _register_nas(fx)
        await _sign_in(fx)
        fx.guest_service.policy_lookup = _PolicyLookup(raises=RuntimeError("db"))

        result = await _authorize(fx, nas)

        assert result.authorized is True
        assert result.bandwidth_max_down_bps is None
        assert result.bandwidth_max_up_bps is None

    async def test_a_rejected_request_carries_nothing(self) -> None:
        fx = _fixture(policy_lookup=_bandwidth(2048, 512))
        _gate(fx)
        nas = await _register_nas(fx)

        result = await _authorize(fx, nas, identifier="+910000000000")

        assert result.authorized is False
        assert result.bandwidth_max_down_bps is None
        assert result.bandwidth_max_up_bps is None


class TestUngatedRouters:
    async def test_an_aruba_router_outside_the_gate_gets_nothing(self) -> None:
        """The default: prod is unchanged until a router is named."""
        fx = _fixture(policy_lookup=_bandwidth(2048, 512))
        assert fx.radius_service.bandwidth_attribute_router_ids == frozenset()
        nas = await _register_nas(fx)
        await _sign_in(fx)

        result = await _authorize(fx, nas)

        assert result.authorized is True
        assert result.bandwidth_max_down_bps is None
        assert result.bandwidth_max_up_bps is None

    async def test_another_routers_id_in_the_gate_does_not_open_it(self) -> None:
        fx = _fixture(policy_lookup=_bandwidth(2048, 512))
        fx.radius_service.bandwidth_attribute_router_ids = frozenset({uuid.uuid4()})
        nas = await _register_nas(fx)
        await _sign_in(fx)

        result = await _authorize(fx, nas)

        assert result.bandwidth_max_down_bps is None

    @pytest.mark.parametrize("vendor", ["mikrotik", "omada"])
    async def test_a_non_nas_only_router_in_the_gate_is_ignored(
        self, vendor: str
    ) -> None:
        fx = _fixture(
            vendor=vendor,
            policy_lookup=_bandwidth(2048, 512),
            queue_lookup=_FakeQueueLookup(),
        )
        _gate(fx)
        nas = await _register_nas(fx)
        await _sign_in(fx)

        result = await _authorize(fx, nas)

        assert result.authorized is True
        assert result.bandwidth_max_down_bps is None
        assert result.bandwidth_max_up_bps is None
        # Their own speed path is untouched.
        assert result.rate_limit == "512k/2048k"


# ============================================================================
# The wire (POST /api/v1/radius/authorize through the real route)
# ============================================================================


def _app(fx) -> FastAPI:  # noqa: ANN001
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(radius_router, prefix="/api/v1")
    app.dependency_overrides[get_radius_service] = lambda: fx.radius_service
    return app


async def _post_authorize(app: FastAPI) -> dict:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/radius/authorize",
            json={"username": _PHONE, "calling_station_id": _ARUBA_CSID},
            headers={
                RADIUS_NAS_IDENTIFIER_HEADER: _NAS_ID,
                RADIUS_SHARED_SECRET_HEADER: _NAS_SECRET,
            },
        )
    assert resp.status_code == 200
    return resp.json()


class TestWire:
    async def test_a_gated_aruba_accept_names_the_wispr_attributes(self) -> None:
        fx = _fixture(policy_lookup=_bandwidth(2048, 512))
        _gate(fx)
        await _register_nas(fx)
        await _sign_in(fx)

        body = await _post_authorize(_app(fx))

        assert body["control:Auth-Type"] == "Accept"
        # rlm_rest attribute names (dictionary.wispr), integer bits/s.
        assert body["WISPr-Bandwidth-Max-Down"] == 2_048_000
        assert body["WISPr-Bandwidth-Max-Up"] == 512_000
        assert "Mikrotik-Rate-Limit" not in body

    async def test_an_ungated_aruba_accept_has_no_wispr_key(self) -> None:
        fx = _fixture(policy_lookup=_bandwidth(2048, 512))
        await _register_nas(fx)
        await _sign_in(fx)

        body = await _post_authorize(_app(fx))

        assert body["control:Auth-Type"] == "Accept"
        assert not set(_WISPR_KEYS) & set(body)

    @pytest.mark.parametrize("vendor", ["mikrotik", "omada"])
    async def test_mikrotik_and_omada_replies_are_identical_with_the_gate_on(
        self, vendor: str
    ) -> None:
        """Same fixture, same guest, one call with the gate empty and one with
        this router's own id in it: the reply must not change by a key or a
        value. ``Session-Timeout`` is the remaining allowance, so it may tick
        by one second between the calls; everything else is exact."""
        fx = _fixture(
            vendor=vendor,
            policy_lookup=_bandwidth(2048, 512),
            queue_lookup=_FakeQueueLookup(),
        )
        await _register_nas(fx)
        await _sign_in(fx)
        app = _app(fx)

        before = await _post_authorize(app)
        _gate(fx)
        after = await _post_authorize(app)

        assert before["Mikrotik-Rate-Limit"] == "512k/2048k"
        assert abs(before.pop("Session-Timeout") - after.pop("Session-Timeout")) <= 1
        assert before == after
        assert list(before) == list(after)
        assert not set(_WISPR_KEYS) & set(after)


# ============================================================================
# The gate itself
# ============================================================================


class TestGateSetting:
    def test_defaults_to_no_router(self) -> None:
        s = Settings(radius_bandwidth_attribute_router_ids="")
        assert s.radius_bandwidth_attribute_router_id_set == frozenset()

    def test_parses_normalises_and_dedupes(self) -> None:
        rid = uuid.UUID("9e6069de-f7a7-409f-8e4e-68d1cba75687")
        s = Settings(
            radius_bandwidth_attribute_router_ids=(f" {str(rid).upper()} ,{rid},,")
        )
        assert s.radius_bandwidth_attribute_router_ids == str(rid)
        assert s.radius_bandwidth_attribute_router_id_set == frozenset({rid})

    def test_a_typo_stops_startup_naming_the_token(self) -> None:
        with pytest.raises(ValueError, match="not-a-uuid"):
            Settings(radius_bandwidth_attribute_router_ids="not-a-uuid")
