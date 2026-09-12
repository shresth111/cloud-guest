"""Read-only: the router's RADIUS client rows and its `/radius incoming`
(CoA / Disconnect-Request listener) settings.

Writes nothing. Exists because the platform believes it configures
`/radius incoming accept=yes` and the lab router was observed reading
`accept=false` -- so either the write never ran, ran against a different
router, or something reset half of it. Read before concluding which.
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402


async def load_router(host_filter: str):
    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        return await conn.fetchrow(
            """
            SELECT management_ip_address, api_username,
                   api_credentials_encrypted, name
            FROM routers
            WHERE management_ip_address = $1
            LIMIT 1
            """,
            host_filter,
        )
    finally:
        await conn.close()


def dump(api, segments, redact=()):
    print(f"\n=== /{'/'.join(segments)} ===")
    try:
        rows = list(api.path(*segments))
    except Exception as exc:  # noqa: BLE001
        print(f"  <unreadable: {type(exc).__name__}: {exc}>")
        return
    if not rows:
        print("  (empty)")
        return
    for i, row in enumerate(rows):
        shown = {
            k: ("<redacted>" if k in redact else v)
            for k, v in row.items()
            if v not in (None, "")
        }
        print(f"  {i}: {shown}")


def main():
    row = asyncio.run(load_router(sys.argv[1] if len(sys.argv) > 1 else "10.20.0.14"))
    if row is None:
        print("NO ROUTER ROW")
        return 2
    password = decrypt_secret(row["api_credentials_encrypted"])
    print(f"router={row['name']} host={row['management_ip_address']}")

    api = librouteros.connect(
        host=row["management_ip_address"],
        username=row["api_username"],
        password=password,
        port=8728,
        timeout=15,
    )
    try:
        dump(api, ("radius", "incoming"))
        dump(api, ("radius",), redact=("secret",))
        dump(api, ("ip", "hotspot", "profile"), redact=("radius-secret",))
        return 0
    finally:
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())
