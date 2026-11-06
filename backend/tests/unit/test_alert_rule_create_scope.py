"""POST /alerts/rules takes its owner from the caller's scope, not the body."""

from __future__ import annotations

import contextlib
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.monitoring import router as monitoring_router
from app.domains.monitoring.constants import AlertTriggerType
from app.domains.monitoring.exceptions import (
    AlertRuleNotFoundError,
    NotificationChannelNotFoundError,
)
from app.domains.monitoring.schemas import AlertRuleCreateRequest
from app.domains.monitoring.service import AlertService
from app.domains.organization.exceptions import CrossOrganizationAccessError

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


_THRESHOLD_CONFIG = {
    "metric": "cpu_usage_percent",
    "operator": "gt",
    "value": 90,
}


class _ChannelRepo:
    """Enough of the repository to reach the channel check, and to prove that a
    refused link wrote nothing."""

    def __init__(self, *channels: SimpleNamespace) -> None:
        self.channels = {c.id: c for c in channels}
        self.rule = SimpleNamespace(
            id=uuid.uuid4(),
            organization_id=OWN,
            trigger_type="threshold",
            target_component=None,
            condition_config=_THRESHOLD_CONFIG,
        )
        self.links: list[list[uuid.UUID]] = []
        self.created = 0

    async def get_notification_channels_by_ids(self, ids: list[uuid.UUID]) -> list[Any]:
        return [self.channels[i] for i in ids if i in self.channels]

    async def create_alert_rule(self, **_: Any) -> Any:
        self.created += 1
        return self.rule

    async def get_alert_rule(self, _id: uuid.UUID) -> Any:
        return self.rule

    async def update_alert_rule(self, rule: Any, _data: Any) -> Any:
        return rule

    async def replace_alert_rule_notification_channels(
        self, _rule_id: uuid.UUID, ids: list[uuid.UUID]
    ) -> None:
        self.links.append(ids)


def _channel(org: uuid.UUID | None) -> SimpleNamespace:
    return SimpleNamespace(id=uuid.uuid4(), organization_id=org)


async def _create_with_channel(
    repo: _ChannelRepo,
    channel_id: uuid.UUID,
    *,
    rule_org: uuid.UUID | None,
    caller_org: uuid.UUID | None,
) -> None:
    await AlertService(repo).create_alert_rule(
        name="r",
        description=None,
        organization_id=rule_org,
        trigger_type=AlertTriggerType.THRESHOLD,
        target_component=None,
        condition_config=_THRESHOLD_CONFIG,
        severity="info",
        notification_channel_ids=[channel_id],
        requesting_organization_id=caller_org,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("channel_org", [OTHER, None])
async def test_org_caller_cannot_link_a_channel_that_is_not_theirs(
    channel_org: uuid.UUID | None,
) -> None:
    channel = _channel(channel_org)
    repo = _ChannelRepo(channel)
    with pytest.raises(CrossOrganizationAccessError):
        await _create_with_channel(repo, channel.id, rule_org=OWN, caller_org=OWN)
    assert repo.created == 0
    assert repo.links == []


@pytest.mark.asyncio
async def test_org_caller_links_their_own_channel() -> None:
    channel = _channel(OWN)
    repo = _ChannelRepo(channel)
    await _create_with_channel(repo, channel.id, rule_org=OWN, caller_org=OWN)
    assert repo.links == [[channel.id]]


@pytest.mark.asyncio
async def test_a_channel_that_does_not_exist_is_refused() -> None:
    repo = _ChannelRepo()
    with pytest.raises(NotificationChannelNotFoundError):
        await _create_with_channel(repo, uuid.uuid4(), rule_org=OWN, caller_org=OWN)
    assert repo.created == 0


@pytest.mark.asyncio
async def test_platform_caller_cannot_send_one_orgs_alerts_to_another_org() -> None:
    channel = _channel(OTHER)
    repo = _ChannelRepo(channel)
    with pytest.raises(CrossOrganizationAccessError):
        await _create_with_channel(repo, channel.id, rule_org=OWN, caller_org=None)
    assert repo.created == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rule_org", "channel_org"), [(OWN, None), (None, OTHER), (None, None)]
)
async def test_platform_caller_keeps_the_other_links(
    rule_org: uuid.UUID | None, channel_org: uuid.UUID | None
) -> None:
    channel = _channel(channel_org)
    repo = _ChannelRepo(channel)
    await _create_with_channel(repo, channel.id, rule_org=rule_org, caller_org=None)
    assert repo.links == [[channel.id]]


@pytest.mark.asyncio
async def test_update_cannot_link_a_foreign_channel() -> None:
    channel = _channel(OTHER)
    repo = _ChannelRepo(channel)
    with pytest.raises(CrossOrganizationAccessError):
        await AlertService(repo).update_alert_rule(
            repo.rule.id,
            data={},
            notification_channel_ids=[channel.id],
            requesting_organization_id=OWN,
        )
    assert repo.links == []
