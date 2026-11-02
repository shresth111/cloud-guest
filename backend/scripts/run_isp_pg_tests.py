"""Run every ISP partner PostgreSQL test file, one file per pytest process.

CI-INTEG (2026-11-01). The ``tests/unit/test_isp*_postgres.py`` files (plus
``test_isp_pppoe.py`` and ``test_isp_service_control.py``, gated the same way)
skip unless ``ISP_TEST_PG_DSN`` is set, so the default suite never runs them.
They cannot share one process (the shared async engine's event loop is bound
to the first test's loop) and several count every row of a table, so each
file gets:

* a fresh database cloned from one template migrated to ``alembic head``;
* an empty Redis (``FLUSHDB``);
* the base env below plus the ``VAR=value`` pairs written in its own module
  docstring (the lanes document their run command there), minus the
  database / Redis URLs, which always point at the throwaway services.

Usage (from ``backend/``)::

    ISP_PG_ADMIN_URL=postgresql://postgres:postgres@localhost:5432/postgres \\
    ISP_PG_REDIS_URL=redis://localhost:6379/0 \\
    python scripts/run_isp_pg_tests.py [test file ...]

``ISP_PG_SHARD=i/n`` (1-based) runs every n-th file starting at the i-th, so
CI can split the files across a matrix. Exit status is non-zero if any file
failed. Never point it at a real
database: it creates and drops ``isppg_*`` databases on that server.
"""

from __future__ import annotations

import ast
import asyncio
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse

BACKEND = Path(__file__).resolve().parent.parent
TEMPLATE = "isppg_template"

BASE_ENV = {
    "ISP_TEST_PG_DSN": "1",
    "ISP_PARTNER_ENABLED": "true",
    "TR069_ENABLED": "true",
}
# Never taken from a docstring: these always point at the CI services.
_FORCED = {"CLOUDGUEST_DATABASE_URL", "CLOUDGUEST_REDIS_URL", "ISP_TEST_PG_DSN"}
_PAIR = re.compile(r"\b([A-Z][A-Z0-9_]+)=([^\s\\]+)")


def discover() -> list[Path]:
    unit = BACKEND / "tests" / "unit"
    files = sorted(unit.glob("test_isp*_postgres.py"))
    for extra in ("test_isp_pppoe.py", "test_isp_service_control.py"):
        p = unit / extra
        if p.exists() and "ISP_TEST_PG_DSN" in p.read_text():
            files.append(p)
    return files


def docstring_env(path: Path) -> dict[str, str]:
    doc = ast.get_docstring(ast.parse(path.read_text())) or ""
    return {k: v for k, v in _PAIR.findall(doc) if k not in _FORCED}


def _with_db(url: str, db: str, *, driver: str | None = None) -> str:
    u = urlparse(url)
    scheme = u.scheme if driver is None else driver
    return urlunparse(u._replace(scheme=scheme, path=f"/{db}"))


async def _admin(sql: list[str]) -> None:
    import asyncpg

    conn = await asyncpg.connect(os.environ["ISP_PG_ADMIN_URL"])
    try:
        for s in sql:
            await conn.execute(s)
    finally:
        await conn.close()


def _drop_create(db: str, template: str | None = None) -> None:
    tpl = f" TEMPLATE {template}" if template else ""
    asyncio.run(
        _admin(
            [
                f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)',
                f'CREATE DATABASE "{db}"{tpl}',
            ]
        )
    )


def _flush_redis() -> None:
    import redis

    redis.Redis.from_url(os.environ["ISP_PG_REDIS_URL"]).flushdb()


def _ensure_bucket(env: dict[str, str]) -> None:
    endpoint = env.get("CLOUDGUEST_S3_ENDPOINT_URL")
    if not endpoint:
        return
    import boto3

    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=env.get("CLOUDGUEST_S3_ACCESS_KEY_ID", "cloudguest"),
        aws_secret_access_key=env.get(
            "CLOUDGUEST_S3_SECRET_ACCESS_KEY", "cloudguest12345"
        ),
        region_name=env.get("CLOUDGUEST_S3_REGION", "us-east-1"),
    )
    bucket = env.get("CLOUDGUEST_S3_BUCKET_NAME", "cloudguest")
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception:  # noqa: BLE001 -- create on any miss
        s3.create_bucket(Bucket=bucket)


def migrate_template(base: dict[str, str]) -> None:
    _drop_create(TEMPLATE)
    env = {**base, "CLOUDGUEST_DATABASE_URL": _db_url(TEMPLATE)}
    t = time.monotonic()
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND,
        env=env,
        check=True,
    )
    print(f"template migrated to head in {time.monotonic() - t:.0f}s", flush=True)


def _db_url(db: str) -> str:
    return _with_db(os.environ["ISP_PG_ADMIN_URL"], db, driver="postgresql+asyncpg")


def main(argv: list[str]) -> int:
    for var in ("ISP_PG_ADMIN_URL", "ISP_PG_REDIS_URL"):
        if not os.environ.get(var):
            print(f"{var} is not set", file=sys.stderr)
            return 2
    shard = os.environ.get("ISP_PG_SHARD", "")  # "i/n", 1-based
    files = [Path(a).resolve() for a in argv] or discover()
    if shard:
        i, n = (int(x) for x in shard.split("/"))
        files = files[i - 1 :: n]
        print(f"shard {i}/{n}: {len(files)} files", flush=True)
    base = {
        **os.environ,
        **BASE_ENV,
        "CLOUDGUEST_REDIS_URL": os.environ["ISP_PG_REDIS_URL"],
        "PYTHONPATH": os.pathsep.join(
            [str(BACKEND), str(BACKEND / "vendor" / "wyfy-device-gateway")]
        ),
    }
    _ensure_bucket(base)
    migrate_template(base)

    results: list[tuple[str, int, float]] = []
    for i, f in enumerate(files):
        db = f"isppg_{i:02d}"
        _drop_create(db, TEMPLATE)
        _flush_redis()
        env = {**base, **docstring_env(f), "CLOUDGUEST_DATABASE_URL": _db_url(db)}
        rel = f.relative_to(BACKEND)
        print(f"\n::group::{rel}", flush=True)
        t = time.monotonic()
        rc = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-p",
                "no:cacheprovider",
                "-q",
                "-rfEs",
                str(rel),
            ],
            cwd=BACKEND,
            env=env,
        ).returncode
        dt = time.monotonic() - t
        print("::endgroup::", flush=True)
        # 5 = no tests collected; anything else non-zero is a failure.
        results.append((str(rel), rc, dt))
        if rc not in (0,):
            print(f"::error file=backend/{rel}::{rel} exited {rc}", flush=True)
        asyncio.run(_admin([f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)']))

    print("\nISP PostgreSQL tests:")
    for rel, rc, dt in results:
        print(f"  {'PASS' if rc == 0 else 'FAIL'}  {dt:6.0f}s  {rel}")
    failed = [r for r in results if r[1] != 0]
    print(f"{len(results) - len(failed)}/{len(results)} files passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
