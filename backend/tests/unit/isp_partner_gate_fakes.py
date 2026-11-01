"""Fake entitlement checkers for the ISP twin gate tests (ADDENDUM_04 §1)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field


@dataclass
class FakeSnapshot:
    license_status: str = "active"
    enabled_features: frozenset[str] = frozenset()

    @property
    def is_active(self) -> bool:
        return self.license_status == "active"

    def has_feature(self, key) -> bool:
        return key.value in self.enabled_features


@dataclass
class FakeChecker:
    """Answers ``get_snapshot`` from a per-org map; records which org it saw."""

    snapshots: dict[uuid.UUID, FakeSnapshot] = field(default_factory=dict)
    default: FakeSnapshot | None = None
    seen: list[uuid.UUID] = field(default_factory=list)

    async def get_snapshot(self, organization_id: uuid.UUID) -> FakeSnapshot:
        self.seen.append(organization_id)
        snap = self.snapshots.get(organization_id, self.default)
        if snap is None:
            from app.domains.billing.exceptions import LicenseNotFoundError

            raise LicenseNotFoundError(organization_id)
        return snap


def entitled_everything() -> FakeChecker:
    """Active licence and every feature: lets non-gate tests reach the handler."""
    from app.domains.billing.constants import PlanFeatureKey

    return FakeChecker(
        default=FakeSnapshot(
            enabled_features=frozenset(k.value for k in PlanFeatureKey)
        )
    )
