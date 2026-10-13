"""The traffic-flow revisions must be no-ops on a database that already has
the tables (staging got them from its own 0153). Checked without a database
server: every DDL statement the revision issues is captured and must be
guarded, and the revision must create exactly what the models declare."""

from __future__ import annotations

import importlib.util
import pathlib
import re
from typing import Any

import pytest

from app.domains.traffic_flow.models import TrafficFlowIngestState, TrafficFlowWindow

VERSIONS = pathlib.Path("alembic/versions")


def _load(filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(
        filename.removesuffix(".py"), VERSIONS / filename
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _captured(module: Any, monkeypatch: pytest.MonkeyPatch, fn: str) -> list[str]:
    statements: list[str] = []

    class _Op:
        def execute(self, sql: Any) -> None:
            statements.append(" ".join(str(sql).split()))

        def __getattr__(self, name: str) -> Any:
            raise AssertionError(
                f"op.{name} is not idempotent; use guarded SQL via op.execute"
            )

    monkeypatch.setattr(module, "op", _Op())
    getattr(module, fn)()
    return statements


def _columns(statement: str) -> set[str]:
    body = statement[statement.index("(") + 1 : statement.rindex(")")]
    names = set()
    for part in re.split(r",\s*(?![^()]*\))", body):
        first = part.split()[0]
        if first.upper() != "CONSTRAINT":
            names.add(first)
    return names


class TestCreateRevision:
    FILE = "0156_create_traffic_flow_tables.py"

    def test_chains_on_mains_head(self) -> None:
        module = _load(self.FILE)
        assert module.revision == "0156_create_traffic_flow_tables"
        assert module.down_revision == "0154_create_guest_device_events"
        assert len(module.revision) <= 32  # alembic_version.version_num

    def test_every_upgrade_statement_is_guarded(self, monkeypatch) -> None:
        statements = _captured(_load(self.FILE), monkeypatch, "upgrade")
        assert len(statements) == 3
        for statement in statements:
            assert "IF NOT EXISTS" in statement, statement

    def test_downgrade_is_guarded(self, monkeypatch) -> None:
        for statement in _captured(_load(self.FILE), monkeypatch, "downgrade"):
            assert "IF EXISTS" in statement, statement

    def test_creates_the_columns_the_models_declare_at_this_revision(
        self, monkeypatch
    ) -> None:
        statements = _captured(_load(self.FILE), monkeypatch, "upgrade")
        created = {
            re.search(r"CREATE TABLE IF NOT EXISTS (\w+)", s).group(1): _columns(s)
            for s in statements
            if s.startswith("CREATE TABLE")
        }
        assert set(created) == {"traffic_flow_windows", "traffic_flow_ingest_state"}
        for model in (TrafficFlowWindow, TrafficFlowIngestState):
            declared = {c.name for c in model.__table__.columns}
            assert created[model.__tablename__] <= declared
            assert declared - created[model.__tablename__] <= LATER_COLUMNS.get(
                model.__tablename__, set()
            )


#: Columns added by later revisions (0157_traffic_flow_services_export).
LATER_COLUMNS: dict[str, set[str]] = {
    "traffic_flow_windows": {
        "bytes_up",
        "bytes_down",
        "services_measured",
        # 0164_traffic_flow_window_overhead
        "bytes_overhead_up",
        "bytes_overhead_down",
    },
}
