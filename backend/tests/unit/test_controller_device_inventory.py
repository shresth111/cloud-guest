"""Unit tests for the customer-facing, org-scoped controller device read
(``NetworkIntegrationService.list_controller_devices_for_location``).

Read-only surface: the venue owner sees the devices their Omada controller
manages (the controller + adopted APs). The three ``status`` values are the
contract that matters -- "you have no controller", "your controller didn't
answer", and "here is what it manages (possibly nothing)" must never collapse
into each other.
"""

from __future__ import annotations

import uuid

from app.domains.network_integration.exceptions import ProviderConnectionFailedError
from app.domains.network_integration.providers.base import ProviderDevice
from app.domains.network_integration.service import (
    ControllerInventoryResult,
    NetworkIntegrationService,
)


class _Repo:
    """Only the one method the read touches."""

    def __init__(self, integration: object | None) -> None:
        self._integration = integration
        self.calls: list[tuple[uuid.UUID, uuid.UUID]] = []

    async def get_omada_openapi_integration_for_location(
        self, *, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> object | None:
        self.calls.append((location_id, organization_id))
        return self._integration


def _service(repo: _Repo) -> NetworkIntegrationService:
    # The read only ever touches self.repository and self.list_devices; build a
    # bare service and stub list_devices per test.
    svc = NetworkIntegrationService.__new__(NetworkIntegrationService)
    svc.repository = repo  # type: ignore[attr-defined]
    return svc


async def test_no_integration_for_location_is_no_controller() -> None:
    repo = _Repo(integration=None)
    svc = _service(repo)
    org = uuid.uuid4()
    loc = uuid.uuid4()

    result = await svc.list_controller_devices_for_location(
        location_id=loc, organization_id=org
    )

    assert result == ControllerInventoryResult(status="no_controller", devices=())
    # The org and location are both handed to the org-scoped query.
    assert repo.calls == [(loc, org)]


async def test_no_org_short_circuits_without_a_query() -> None:
    repo = _Repo(integration=object())
    svc = _service(repo)

    result = await svc.list_controller_devices_for_location(
        location_id=uuid.uuid4(), organization_id=None
    )

    assert result.status == "no_controller"
    assert repo.calls == []  # a global caller never reaches the org query


async def test_reachable_controller_returns_its_devices() -> None:
    integration = type("I", (), {"id": uuid.uuid4()})()
    repo = _Repo(integration=integration)
    svc = _service(repo)
    devices = [
        ProviderDevice(
            mac="AA-BB-CC-DD-EE-01", name="Controller", device_type="controller"
        ),
        ProviderDevice(
            mac="AA-BB-CC-DD-EE-02", name="EAP245", device_type="ap", client_count=3
        ),
    ]
    seen: dict[str, object] = {}

    async def _list_devices(integration_id, *, requesting_organization_id):
        seen["integration_id"] = integration_id
        seen["org"] = requesting_organization_id
        return devices

    svc.list_devices = _list_devices  # type: ignore[assignment]
    org = uuid.uuid4()

    result = await svc.list_controller_devices_for_location(
        location_id=uuid.uuid4(), organization_id=org
    )

    assert result.status == "ok"
    assert result.devices == tuple(devices)
    # Resolved integration id is used, and the org is carried through for the
    # tenant check inside list_devices.
    assert seen == {"integration_id": integration.id, "org": org}


async def test_empty_ok_is_distinct_from_no_controller() -> None:
    integration = type("I", (), {"id": uuid.uuid4()})()
    svc = _service(_Repo(integration=integration))

    async def _list_devices(integration_id, *, requesting_organization_id):
        return []

    svc.list_devices = _list_devices  # type: ignore[assignment]

    result = await svc.list_controller_devices_for_location(
        location_id=uuid.uuid4(), organization_id=uuid.uuid4()
    )

    # A controller that manages nothing yet is "ok" with no devices -- NOT
    # "no_controller". The dashboard must be able to tell them apart.
    assert result.status == "ok"
    assert result.devices == ()


async def test_provider_error_becomes_unreachable_not_a_raise() -> None:
    integration = type("I", (), {"id": uuid.uuid4()})()
    svc = _service(_Repo(integration=integration))

    async def _list_devices(integration_id, *, requesting_organization_id):
        raise ProviderConnectionFailedError("controller unreachable")

    svc.list_devices = _list_devices  # type: ignore[assignment]

    result = await svc.list_controller_devices_for_location(
        location_id=uuid.uuid4(), organization_id=uuid.uuid4()
    )

    assert result == ControllerInventoryResult(status="unreachable", devices=())
