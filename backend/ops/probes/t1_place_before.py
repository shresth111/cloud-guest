"""T1 from docs/mikrotik/TRUSTED_DEVICES_AND_ACCESS_RULES.md 1098.

Does librouteros' Path.add() accept `place-before` on RouterOS 7.23.3, and
does it take a `.id` rather than an ordinal?

Everything this writes is `action=passthrough` in `forward`, commented
`cg-test-*`. Passthrough counts the packet and continues down the chain, so
none of these rules can accept, drop or reorder anything. All three are
removed in a `finally`, and only rules carrying the `cg-test-` comment are
ever touched.
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

MARK = "cg-test-"


async def load_router(host_filter: str):
    # Read the DSN the way the app itself does rather than off the
    # environment: the container does not export DATABASE_URL under that
    # name, and get_settings() is the one source that is always right.
    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix):]
    conn = await asyncpg.connect(url)
    try:
        return await conn.fetchrow(
            """
            -- No api_port column exists: the API port is a code-side
            -- constant (vlan/device_adapters._DEFAULT_API_PORT = 8728),
            -- which is also the only port that reaches a fleet router.
            SELECT management_ip_address, api_username, api_credentials_encrypted,
                   name
            FROM routers
            WHERE management_ip_address = $1
            LIMIT 1
            """,
            host_filter,
        )
    finally:
        await conn.close()


def comments(api):
    return [
        (r.get("comment"), r.get(".id"))
        for r in api.path("ip", "firewall", "filter")
        if str(r.get("comment", "")).startswith(MARK)
    ]


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
    menu = api.path("ip", "firewall", "filter")
    created = []
    try:
        pre_existing = comments(api)
        if pre_existing:
            print("REFUSING: cg-test- rules already present:", pre_existing)
            return 3

        a = menu.add(chain="forward", action="passthrough", comment=MARK + "a")
        created.append(a)
        b = menu.add(chain="forward", action="passthrough", comment=MARK + "b")
        created.append(b)
        print(f"a={a} b={b}")

        # The actual question: does add() take place-before, and is it a .id?
        try:
            c = menu.add(
                chain="forward",
                action="passthrough",
                comment=MARK + "c",
                **{"place-before": b},
            )
            created.append(c)
            print(f"c={c}  (place-before accepted a .id)")
        except Exception as exc:  # noqa: BLE001 -- this IS the result
            print(
                "T1 RESULT: place-before with a .id REJECTED -> "
                f"{type(exc).__name__}: {exc}"
            )
            return 0

        order = [c for c, _ in comments(api)]
        print("ORDER:", order)
        expected = [MARK + "a", MARK + "c", MARK + "b"]
        verdict = "PASS" if order == expected else f"UNEXPECTED (wanted {expected})"
        print("T1 RESULT:", verdict)
        return 0
    finally:
        for rid in reversed(created):
            try:
                menu.remove(rid)
            except Exception as exc:  # noqa: BLE001
                print(f"CLEANUP FAILED for {rid}: {exc}")
        left = comments(api)
        print("cleanup leftover:", left if left else "none")
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())
