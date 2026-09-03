"""T2 from docs/mikrotik/TRUSTED_DEVICES_AND_ACCESS_RULES.md.

Can a static rule be placed ABOVE hotspot's dynamic rules in `forward`?
That decides whether the ordered band of §5.2 can sit above the hotspot
chains at all, or has to sit below them.

Same safety envelope as T1: one `action=passthrough` rule in `forward`,
commented `cg-test-top`. Passthrough counts the packet and continues, so it
cannot accept, drop, or reorder anything. It is removed in a `finally`, and
nothing that is not commented `cg-test-` is ever written or removed.
"""

import asyncio
import sys

import asyncpg
import librouteros

sys.path.insert(0, "/app")
from app.domains.router.crypto import decrypt_secret  # noqa: E402

MARK = "cg-test-"
TOP = MARK + "top"


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


def is_dynamic(row) -> bool:
    v = row.get("dynamic")
    return v is True or str(v).lower() in ("true", "yes")


def forward_rows(api):
    return [
        r for r in api.path("ip", "firewall", "filter")
        if str(r.get("chain", "")) == "forward"
    ]


def describe(rows):
    out = []
    for i, r in enumerate(rows):
        flag = "D" if is_dynamic(r) else " "
        action = str(r.get("action", "?"))
        comment = r.get("comment", "") or ""
        out.append(f"  {i:>3} {flag} {action:<12} {comment}")
    return "\n".join(out)


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
    created = None
    try:
        before = forward_rows(api)
        if any(str(r.get("comment", "")).startswith(MARK) for r in before):
            print("REFUSING: cg-test- rules already present")
            return 3

        dyn_idx = next((i for i, r in enumerate(before) if is_dynamic(r)), None)
        print(f"forward chain: {len(before)} rules, first dynamic at index {dyn_idx}")
        print("BEFORE:")
        print(describe(before))

        if dyn_idx is None:
            print("T2 RESULT: no dynamic rules in forward -- nothing to sit above")
            return 0

        target = before[dyn_idx][".id"]
        try:
            created = menu.add(
                chain="forward",
                action="passthrough",
                comment=TOP,
                **{"place-before": target},
            )
        except Exception as exc:  # noqa: BLE001 -- this IS the result
            print(f"T2 RESULT: REFUSED to place above a dynamic rule -> "
                  f"{type(exc).__name__}: {exc}")
            return 0

        after = forward_rows(api)
        print("AFTER:")
        print(describe(after))
        top_idx = next(
            (i for i, r in enumerate(after) if str(r.get("comment", "")) == TOP), None
        )
        new_dyn_idx = next((i for i, r in enumerate(after) if is_dynamic(r)), None)
        print(f"cg-test-top at {top_idx}; first dynamic at {new_dyn_idx}")
        if top_idx is not None and new_dyn_idx is not None and top_idx < new_dyn_idx:
            print("T2 RESULT: PASS -- a static rule CAN sit above the dynamic rules")
        else:
            print("T2 RESULT: FAIL -- it landed below the first dynamic rule")
        return 0
    finally:
        if created is not None:
            try:
                menu.remove(created)
            except Exception as exc:  # noqa: BLE001
                print(f"CLEANUP FAILED for {created}: {exc}")
        left = [
            r.get("comment") for r in forward_rows(api)
            if str(r.get("comment", "")).startswith(MARK)
        ]
        print("cleanup leftover:", left if left else "none")
        api.close()


if __name__ == "__main__":
    raise SystemExit(main())
