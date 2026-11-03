"""POST /alerts/rules takes its owner from the caller's scope, not the body."""

from __future__ import annotations

import contextlib
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.monitoring import router as monitoring_router
from app.domains.monitoring.exceptions import AlertRuleNotFoundError
from app.domains.monitoring.schemas import AlertRuleCreateRequest

OWN = uuid.uuid4()
OTHER = uuid.uuid4()


class _Service:
    def __init__(self) -> None:
        self.created: list[dict[str, Any]] = []

    async def create_alert_rule(self, **kw: Any) -> Any:
        self.created.append(kw)
        raise _Stop


class _Stop(Exception):
    pass


async def _create(body_org: uuid.UUID | None, caller_org: uuid.UUID | None) -> _Service:
    service = _Service()
    payload = AlertRuleCreateRequest(
        name="r",
        organization_id=body_org,
        trigger_type="threshold",
        severity="info",
    )
    with contextlib.suppress(_Stop):
        await monitoring_router.create_alert_rule(
            SimpleNamespace(state=SimpleNamespace(request_id="t"), headers={}),
            payload,
            requesting_organization_id=caller_org,
            service=service,
        )
    return service


@pytest.mark.asyncio
async def test_org_caller_cannot_create_a_rule_for_another_org() -> None:
    service = _Service()
    with pytest.raises(AlertRuleNotFoundError):
        await monitoring_router.create_alert_rule(
            SimpleNamespace(state=SimpleNamespace(request_id="t"), headers={}),
            AlertRuleCreateRequest(
                name="r",
                organization_id=OTHER,
                trigger_type="threshold",
                severity="info",
            ),
            requesting_organization_id=OWN,
            service=service,
        )
    assert service.created == []


@pytest.mark.asyncio
async def test_org_caller_without_a_body_org_gets_their_own_not_a_global_rule() -> None:
    assert (await _create(None, OWN)).created[0]["organization_id"] == OWN


@pytest.mark.asyncio
async def test_org_caller_naming_their_own_org_is_unchanged() -> None:
    assert (await _create(OWN, OWN)).created[0]["organization_id"] == OWN


@pytest.mark.asyncio
@pytest.mark.parametrize("body_org", [OTHER, None])
async def test_platform_caller_keeps_choosing(body_org: uuid.UUID | None) -> None:
    assert (await _create(body_org, None)).created[0]["organization_id"] == body_org
