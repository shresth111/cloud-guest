"""Traffic Lens must never file one venue's flows under another tenant.

The exporter map turns a flow's source (the router's tunnel address) into a
router. It used to be a last-wins dict over every non-revoked peer, soft
deleted ones included: an address held by two routers silently went to
whichever row the database returned last, and with it the IPDR join.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.domains.traffic_flow.service import (
    ExporterRouter,
    TrafficFlowRepository,
    exporter_map_from_rows,
)

ORG_A, LOC_A, ROUTER_A = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
ORG_B, LOC_B, ROUTER_B = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()


def test_unique_address_maps_to_its_router() -> None:
    out = exporter_map_from_rows([("10.20.0.53", ROUTER_A, ORG_A, LOC_A)])
    assert out == {"10.20.0.53": ExporterRouter(ROUTER_A, ORG_A, LOC_A)}


def test_address_held_by_two_tenants_is_refused() -> None:
    out = exporter_map_from_rows(
        [
            ("10.20.0.40", ROUTER_A, ORG_A, LOC_A),
            ("10.20.0.40", ROUTER_B, ORG_B, LOC_B),
            ("10.20.0.33", ROUTER_B, ORG_B, LOC_B),
        ]
    )
    assert "10.20.0.40" not in out
    assert out["10.20.0.33"].organization_id == ORG_B


def test_same_router_listed_twice_is_not_ambiguous() -> None:
    out = exporter_map_from_rows(
        [
            ("10.20.0.53", ROUTER_A, ORG_A, LOC_A),
            ("10.20.0.53", ROUTER_A, ORG_A, LOC_A),
        ]
    )
    assert out["10.20.0.53"].router_id == ROUTER_A


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Session:
    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows
        self.statements: list[Any] = []

    async def execute(self, stmt: Any) -> _Result:
        self.statements.append(stmt)
        return _Result(self.rows)


@pytest.mark.asyncio
async def test_repository_skips_deleted_peers_and_refuses_ambiguity() -> None:
    session = _Session(
        [
            ("10.20.0.40", ROUTER_A, ORG_A, LOC_A),
            ("10.20.0.40", ROUTER_B, ORG_B, LOC_B),
        ]
    )
    repository = TrafficFlowRepository(session)  # type: ignore[arg-type]
    out = await repository.exporter_router_map()
    assert out == {}
    sql = str(
        session.statements[0].compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    assert "wireguard_peers.is_deleted IS false" in sql
    assert "routers.is_deleted IS false" in sql
