"""Unit tests for ``app.domains.feature_entitlement``.

This domain had no test file, no ``models.py`` and no ``repository.py``, and
both of its customer-facing methods were fictional:

* ``get_customer_features`` ignored ``customer_id`` entirely and returned the
  same constant list for every customer -- every ``PlanFeatureKey`` enabled
  except ``AI_FEATURES``/``WHITE_LABEL``, ``limits={}`` -- under the comment
  "In a real implementation, this would check the customer's plan features
  from the billing domain."
* ``update_customer_features`` echoed the caller's payload back with
  ``"Customer features updated"`` and persisted nothing, behind a
  ``billing.manage`` permission gate.

The read is now an adapter over ``EntitlementChecker.get_snapshot`` -- the very
object ``RequireFeature`` gates live requests against -- so what this endpoint
reports and what the platform enforces cannot diverge. The write refuses,
because no per-customer override model exists to write to.

Plain-``assert``/native-``async def`` style, in-memory fakes, no live
Postgres -- same convention as the rest of this suite.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

import pytest

from app.domains.billing.constants import PlanFeatureKey
from app.domains.feature_entitlement.exceptions import (
    PerCustomerFeatureOverrideNotSupportedError,
)
from app.domains.feature_entitlement.schemas import CustomerFeatureValue
from app.domains.feature_entitlement.service import FeatureEntitlementService


class _FakeSnapshot:
    """Mirrors ``billing.service.EntitlementSnapshot``'s real surface."""

    def __init__(
        self,
        *,
        enabled: set[str] | None = None,
        limits: dict[str, Decimal] | None = None,
        tiers: dict[str, str] | None = None,
    ) -> None:
        self.enabled_features = frozenset(enabled or set())
        self.limits = limits or {}
        self.tiers = tiers or {}

    def has_feature(self, feature_key: PlanFeatureKey) -> bool:
        return feature_key.value in self.enabled_features


class _FakeEntitlementChecker:
    def __init__(self, snapshot: _FakeSnapshot) -> None:
        self._snapshot = snapshot
        self.asked_for: list[uuid.UUID] = []

    async def get_snapshot(self, organization_id: uuid.UUID) -> _FakeSnapshot:
        self.asked_for.append(organization_id)
        return self._snapshot


def _service(snapshot: _FakeSnapshot) -> tuple[FeatureEntitlementService, object]:
    checker = _FakeEntitlementChecker(snapshot)
    return (
        FeatureEntitlementService(
            billing_dashboard=None, entitlement_checker=checker
        ),
        checker,
    )


class TestCustomerFeaturesAreRead:
    async def test_the_customer_id_is_actually_used(self) -> None:
        """The old implementation never looked at it. Two different customers
        could not possibly have differed."""
        service, checker = _service(_FakeSnapshot())
        customer_id = uuid.uuid4()

        await service.get_customer_features(customer_id)

        assert checker.asked_for == [customer_id]

    async def test_a_feature_on_the_plan_reads_as_enabled(self) -> None:
        service, _ = _service(
            _FakeSnapshot(enabled={PlanFeatureKey.WHITE_LABEL.value})
        )

        response = await service.get_customer_features(uuid.uuid4())

        by_key = {f.feature_key: f for f in response.features}
        assert by_key[PlanFeatureKey.WHITE_LABEL.value].enabled is True

    async def test_a_feature_absent_from_the_plan_reads_as_disabled(self) -> None:
        """The old constant reported almost everything enabled for everyone,
        including ``CAMPAIGNS`` and ``API_ACCESS`` for a customer whose plan
        carried neither."""
        service, _ = _service(_FakeSnapshot(enabled=set()))

        response = await service.get_customer_features(uuid.uuid4())

        by_key = {f.feature_key: f for f in response.features}
        assert by_key[PlanFeatureKey.CAMPAIGNS.value].enabled is False
        assert by_key[PlanFeatureKey.API_ACCESS.value].enabled is False

    async def test_reported_entitlement_matches_what_require_feature_enforces(
        self,
    ) -> None:
        """The whole point of the rewrite: this endpoint and the live gate now
        read the same snapshot, so a customer cannot be told they have a
        feature that ``RequireFeature`` will 402 them for."""
        snapshot = _FakeSnapshot(enabled={PlanFeatureKey.ANALYTICS.value})
        service, _ = _service(snapshot)

        response = await service.get_customer_features(uuid.uuid4())

        for feature in response.features:
            key = PlanFeatureKey(feature.feature_key)
            if key.value in snapshot.limits or key.value in snapshot.tiers:
                continue
            assert feature.enabled == snapshot.has_feature(key)

    async def test_plan_limits_are_reported_not_flattened_away(self) -> None:
        """``limits={}`` was hardcoded, so a plan's actual ceilings -- the
        thing /pricing sells -- were invisible."""
        service, _ = _service(
            _FakeSnapshot(limits={PlanFeatureKey.MAX_LOCATIONS.value: Decimal(3)})
        )

        response = await service.get_customer_features(uuid.uuid4())

        by_key = {f.feature_key: f for f in response.features}
        assert by_key[PlanFeatureKey.MAX_LOCATIONS.value].limits["value"] == Decimal(3)

    async def test_tier_values_are_reported(self) -> None:
        service, _ = _service(
            _FakeSnapshot(tiers={PlanFeatureKey.SUPPORT_LEVEL.value: "priority"})
        )

        response = await service.get_customer_features(uuid.uuid4())

        by_key = {f.feature_key: f for f in response.features}
        assert (
            by_key[PlanFeatureKey.SUPPORT_LEVEL.value].limits["tier_value"]
            == "priority"
        )


class TestCustomerFeatureWritesAreRefused:
    async def test_update_raises_instead_of_silently_doing_nothing(self) -> None:
        """It used to return "Customer features updated" having written
        nothing at all."""
        service, _ = _service(_FakeSnapshot())

        with pytest.raises(PerCustomerFeatureOverrideNotSupportedError):
            await service.update_customer_features(
                uuid.uuid4(),
                [
                    CustomerFeatureValue(
                        feature_key=PlanFeatureKey.WHITE_LABEL.value, enabled=True
                    )
                ],
            )

    async def test_refusal_is_a_501_so_a_client_can_tell_it_is_unbuilt(self) -> None:
        service, _ = _service(_FakeSnapshot())

        try:
            await service.update_customer_features(uuid.uuid4(), [])
        except PerCustomerFeatureOverrideNotSupportedError as exc:
            assert exc.status_code == 501
        else:  # pragma: no cover - the call above must raise
            raise AssertionError("update_customer_features silently succeeded")
