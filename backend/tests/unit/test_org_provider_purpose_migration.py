"""Migration 0167: ``org_marketing_providers`` gains ``purpose`` (+ the
fallback/Master columns) and its unique index moves to
(organization, purpose, channel).

Two layers:

* offline -- the revision chains on main's head and issues exactly the
  operations the model declares (captured through a fake ``op``);
* against a real Postgres (gated on ``CLOUDGUEST_TEST_POSTGRES_URL``, like
  ``test_marketing_credits_postgres.py``) -- in a throwaway schema, 0135's
  table is built, 0167 upgrade runs, a marketing and an otp row coexist for
  the same channel, the new index refuses a second otp row, and downgrade
  refuses while otp rows exist and then restores the old shape.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import uuid
from typing import Any

import pytest

from app.domains.marketing.models import OrgMarketingProvider

VERSIONS = pathlib.Path(__file__).resolve().parents[2] / "alembic" / "versions"
FILE = "0167_org_provider_purpose.py"


def _load(filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(
        "_m_" + filename.removesuffix(".py"), VERSIONS / filename
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Op:
    def __init__(self, otp_rows: int = 0) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []
        self._otp_rows = otp_rows

    def get_bind(self):  # noqa: ANN201
        rows = self._otp_rows

        class _Bind:
            def execute(self, statement):  # noqa: ANN001, ANN201
                class _R:
                    def scalar(self):  # noqa: ANN201
                        return rows

                return _R()

        return _Bind()

    def __getattr__(self, name: str):  # noqa: ANN204
        def _record(*args, **kwargs):  # noqa: ANN002, ANN003
            self.calls.append((name, args, kwargs))

        return _record


class TestOffline:
    def test_chains_on_mains_head(self) -> None:
        module = _load(FILE)
        assert module.revision == "0167_org_provider_purpose"
        assert module.down_revision == "0166_add_review_prompt_columns_to_guest_sessions"
        assert len(module.revision) <= 32

    def test_is_the_only_head(self) -> None:
        downs = {
            _load(p.name).down_revision
            for p in VERSIONS.glob("0*.py")
            if p.name != FILE
        }
        assert "0167_org_provider_purpose" not in downs

    def test_upgrade_adds_what_the_model_declares(self, monkeypatch) -> None:
        module = _load(FILE)
        op = _Op()
        monkeypatch.setattr(module, "op", op)
        module.upgrade()
        added = {args[1].name for name, args, _ in op.calls if name == "add_column"}
        assert added == {
            "purpose",
            "configured_by_platform",
            "fallback_count",
            "last_fallback_at",
            "last_fallback_error",
        }
        declared = {c.name for c in OrgMarketingProvider.__table__.columns}
        assert added <= declared
        purpose = next(
            args[1] for name, args, _ in op.calls
            if name == "add_column" and args[1].name == "purpose"
        )  # fmt: skip
        assert purpose.nullable is False
        assert purpose.server_default.arg == "marketing"
        assert ("drop_index", ("uq_omp_org_channel",), {"table_name": module.TABLE}) in [
            (n, a, k) for n, a, k in op.calls
        ]
        created = [a for n, a, k in op.calls if n == "create_index"]
        assert created == [
            ("uq_omp_org_purpose_channel", module.TABLE, ["organization_id", "purpose", "channel"])  # noqa: E501
        ]
        index = next(
            i for i in OrgMarketingProvider.__table__.indexes
            if i.name == "uq_omp_org_purpose_channel"
        )  # fmt: skip
        assert [c.name for c in index.columns] == ["organization_id", "purpose", "channel"]

    def test_downgrade_reverses_and_refuses_with_otp_rows(self, monkeypatch) -> None:
        module = _load(FILE)
        op = _Op(otp_rows=0)
        monkeypatch.setattr(module, "op", op)
        module.downgrade()
        dropped = {a[1] for n, a, _ in op.calls if n == "drop_column"}
        assert "purpose" in dropped and len(dropped) == 5
        assert ("uq_omp_org_channel", module.TABLE, ["organization_id", "channel"]) in [
            a for n, a, _ in op.calls if n == "create_index"
        ]
        monkeypatch.setattr(module, "op", _Op(otp_rows=2))
        with pytest.raises(RuntimeError, match="login-code"):
            module.downgrade()


# ---------------------------------------------------------------------------
# Real Postgres
# ---------------------------------------------------------------------------

_PG_URL = os.environ.get("CLOUDGUEST_TEST_POSTGRES_URL")


@pytest.mark.skipif(not _PG_URL, reason="CLOUDGUEST_TEST_POSTGRES_URL not set")
def test_upgrade_and_downgrade_on_postgres() -> None:
    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy.exc import IntegrityError

    sync_url = _PG_URL.replace("+asyncpg", "+psycopg2") if _PG_URL else ""
    try:
        engine = sa.create_engine(sync_url)
        engine.connect().close()
    except Exception:  # noqa: BLE001
        engine = sa.create_engine(_PG_URL.replace("+asyncpg", "+psycopg"))
    schema = f"t_{uuid.uuid4().hex[:10]}"
    m0135, m0167 = _load("0135_create_org_marketing_providers.py"), _load(FILE)
    with engine.begin() as conn:
        conn.execute(sa.text(f"CREATE SCHEMA {schema}"))
    try:
        with engine.begin() as conn:
            conn.execute(sa.text(f"SET search_path TO {schema}"))
            conn.execute(sa.text("CREATE TABLE organizations (id uuid PRIMARY KEY)"))
            for table in ("marketing_campaigns", "marketing_campaign_recipients",
                          "marketing_templates"):  # fmt: skip
                conn.execute(
                    sa.text(
                        f"CREATE TABLE {table} (id uuid PRIMARY KEY, "
                        "organization_id uuid, whatsapp_body text, "
                        "deleted_at timestamptz)"
                    )
                )
            ops = Operations(MigrationContext.configure(conn))
            m0135.op = ops
            m0135.upgrade()
            org = uuid.uuid4()
            conn.execute(sa.text("INSERT INTO organizations VALUES (:o)"), {"o": org})
            insert = sa.text(
                "INSERT INTO org_marketing_providers "
                "(organization_id, channel, provider_type, config_encrypted, display"
                "{cols}) VALUES (:o, 'sms', 'ping4sms', 'x', '{{}}'{vals})"
            )
            conn.execute(sa.text(insert.text.format(cols="", vals="")), {"o": org})
            m0167.op = ops
            m0167.upgrade()
            purpose = conn.execute(
                sa.text("SELECT purpose FROM org_marketing_providers")
            ).scalar()
            assert purpose == "marketing"  # backfilled
            otp = sa.text(insert.text.format(cols=", purpose", vals=", 'otp'"))
            conn.execute(otp, {"o": org})  # same channel, other purpose: allowed
        with pytest.raises(IntegrityError):
            with engine.begin() as conn:
                conn.execute(sa.text(f"SET search_path TO {schema}"))
                conn.execute(otp, {"o": org})
        with engine.begin() as conn:
            conn.execute(sa.text(f"SET search_path TO {schema}"))
            m0167.op = Operations(MigrationContext.configure(conn))
            with pytest.raises(RuntimeError):
                m0167.downgrade()
        with engine.begin() as conn:
            conn.execute(sa.text(f"SET search_path TO {schema}"))
            conn.execute(
                sa.text("DELETE FROM org_marketing_providers WHERE purpose = 'otp'")
            )
            m0167.op = Operations(MigrationContext.configure(conn))
            m0167.downgrade()
            columns = {
                r[0]
                for r in conn.execute(
                    sa.text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = :s AND table_name = "
                        "'org_marketing_providers'"
                    ),
                    {"s": schema},
                )
            }
            assert "purpose" not in columns and "fallback_count" not in columns
            indexes = {
                r[0]
                for r in conn.execute(
                    sa.text("SELECT indexname FROM pg_indexes WHERE schemaname = :s"),
                    {"s": schema},
                )
            }
            assert "uq_omp_org_channel" in indexes
            assert "uq_omp_org_purpose_channel" not in indexes
    finally:
        with engine.begin() as conn:
            conn.execute(sa.text(f"DROP SCHEMA {schema} CASCADE"))
