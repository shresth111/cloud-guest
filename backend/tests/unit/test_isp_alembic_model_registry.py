"""Every ISP-partner / TR-069 table is visible to alembic.

``alembic/env.py`` imports only ``app.domains.isp_partner.models`` and
``app.domains.tr069.models``. A model module that nothing in that import chain
reaches is still created by its migration, and still works at runtime (the API
imports it through a router), but alembic's ``target_metadata`` never sees it:
``alembic check`` / autogenerate then report the table as one to DROP. That is
how ``addon_models`` (isp_addon_allowances, isp_parity_settings,
isp_customer_messaging) went missing until RELEASE (2026-11-02).

The check runs in a fresh interpreter so nothing else this test session
imported can register the tables by accident.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]
DOMAINS = ("isp_partner", "tr069")
_TABLENAME = re.compile(r'^\s+__tablename__\s*=\s*["\']([a-z0-9_]+)["\']', re.M)

_PROBE = """
import json
from app.database.base import Base
import app.domains.isp_partner.models  # noqa: F401  (what alembic/env.py imports)
import app.domains.tr069.models  # noqa: F401
print(json.dumps(sorted(Base.metadata.tables)))
"""


def _declared_tables() -> dict[str, str]:
    found: dict[str, str] = {}
    for domain in DOMAINS:
        for path in sorted((BACKEND / "app" / "domains" / domain).rglob("*.py")):
            for name in _TABLENAME.findall(path.read_text()):
                found[name] = str(path.relative_to(BACKEND))
    return found


def _registered_tables() -> set[str]:
    out = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return set(json.loads(out.strip().splitlines()[-1]))


def test_env_py_imports_both_model_packages() -> None:
    env = (BACKEND / "alembic" / "env.py").read_text()
    for domain in DOMAINS:
        assert f"from app.domains.{domain} import models" in env, domain


def test_every_isp_model_module_is_reached_from_the_alembic_imports() -> None:
    declared = _declared_tables()
    assert len(declared) > 50, "the table scan found almost nothing; fix the regex"
    registered = _registered_tables()
    missing = {t: where for t, where in declared.items() if t not in registered}
    assert not missing, (
        "These tables are declared in a model module that alembic/env.py never "
        "imports, so `alembic check` would report them as tables to drop. "
        "Import the module from app/domains/<domain>/models.py: "
        + json.dumps(missing, indent=2)
    )


def test_the_scan_sees_the_addon_tables() -> None:
    # The three tables that were missing; the scan must keep finding them.
    declared = _declared_tables()
    addon = ("isp_addon_allowances", "isp_parity_settings", "isp_customer_messaging")
    for table in addon:
        assert table in declared, table
