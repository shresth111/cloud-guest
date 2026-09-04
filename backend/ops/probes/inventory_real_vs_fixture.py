"""Read-only: which tenants, locations and routers are real, and which are
left-over test data.

Every platform-wide number an operator reads -- TENANTS, MRR, ACTIVE
LOCATIONS, ROUTERS ONLINE -- counts rows, and this database contains a
large amount of test data that has never been distinguished from customer
data. On 2026-09-04 the Master console read **14 tenants** and
**8 routers**; of those routers, six belonged to one demo organization and
one to a post-deploy check fixture, leaving a single genuine production
router. "ROUTERS ONLINE 7/8" is a true count of rows and a badly
misleading description of the fleet.

This prints the breakdown so a human can decide what, if anything, to
remove. It is deliberately a *report*, not a cleanup:

  * some of these rows are load-bearing for someone's demo;
  * `deadbeef-` fixtures span organizations, locations, routers, users,
    roles and members, and their generator is not in version control
    (recorded in commit 2c37f1a), so nothing here can be regenerated if it
    turns out to be wanted;
  * and an organization is the root of a cascade -- deleting one reaches
    guests, sessions, invoices and audit rows.

So: no writes, no suggestions to pipe into anything. Read it, then decide.

The classification is a heuristic and says so per row. `suspect` means
"looks like test data by id prefix or name"; it is never proof, and a real
customer is perfectly entitled to be called "QA Test Co".

Writes nothing.
"""

import asyncio
import sys

sys.path.insert(0, "/app")

# `deadbeef-<kind>-4000-8000-<counter>` is the id scheme of a ~576-row
# fixture set spanning six tables. See ops/probes/read_demo_fixtures.py.
FIXTURE_ID_PREFIX = "deadbeef"

# Names used by this project's own test and deploy-verification runs.
FIXTURE_NAME_PATTERNS = (
    "zz ",
    "hub cutover verify",
    "wyfy demo",
    "demo ",
    "qa ",
    "test",
    "postdeploy",
)


def _looks_like_fixture(org_id: str, name: str) -> str | None:
    if org_id.startswith(FIXTURE_ID_PREFIX):
        return "id is a seeded fixture UUID"
    lowered = name.lower()
    for pattern in FIXTURE_NAME_PATTERNS:
        if lowered.startswith(pattern) or pattern in lowered:
            return f"name matches {pattern!r}"
    return None


async def main() -> int:
    import asyncpg

    from app.core.config import get_settings

    url = str(get_settings().database_url)
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            url = "postgresql://" + url[len(prefix) :]
    conn = await asyncpg.connect(url)
    try:
        orgs = await conn.fetch(
            "SELECT id, name, created_at, is_deleted FROM organizations "
            "ORDER BY created_at"
        )
        rows = []
        for org in orgs:
            locations = await conn.fetch(
                "SELECT id, name, is_deleted FROM locations "
                "WHERE organization_id = $1",
                org["id"],
            )
            routers = await conn.fetch(
                "SELECT id, name, is_deleted, location_id FROM routers "
                "WHERE organization_id = $1",
                org["id"],
            )
            rows.append((org, locations, routers))

        live_orgs = [r for r in rows if not r[0]["is_deleted"]]
        print(f"organizations: {len(rows)} total, {len(live_orgs)} not archived\n")

        suspect_orgs = 0
        suspect_routers = 0
        real_routers = 0
        for org, locations, routers in rows:
            reason = _looks_like_fixture(str(org["id"]), org["name"])
            live_locations = [x for x in locations if not x["is_deleted"]]
            live_routers = [x for x in routers if not x["is_deleted"]]
            tag = "SUSPECT" if reason else "real   "
            if reason:
                suspect_orgs += 1
                suspect_routers += len(live_routers)
            else:
                real_routers += len(live_routers)
            archived = " [ARCHIVED]" if org["is_deleted"] else ""
            print(
                f"  {tag} {org['name']!r}{archived}  id={str(org['id'])[:8]}  "
                f"created={org['created_at']:%Y-%m-%d}  "
                f"locations={len(live_locations)}/{len(locations)}  "
                f"routers={len(live_routers)}/{len(routers)}"
                + (f"  -- {reason}" if reason else "")
            )

        print(
            f"\nrouters at live organizations: {real_routers} not-suspect, "
            f"{suspect_routers} suspect"
        )

        # The orphans: a router whose parent location or organization was
        # archived keeps `is_deleted = False`, so it is counted
        # platform-wide and is unreachable from the fleet screen, which
        # walks the live tree. cloud-guest#134 excluded them from the
        # aggregate; they still exist.
        orphans = await conn.fetch(
            "SELECT r.id, r.name FROM routers r "
            "JOIN locations l ON l.id = r.location_id "
            "JOIN organizations o ON o.id = r.organization_id "
            "WHERE r.is_deleted = false "
            "AND (l.is_deleted = true OR o.is_deleted = true)"
        )
        print(f"\nrouters under an archived location or organization: {len(orphans)}")
        for row in orphans:
            print(f"  {row['name']!r}  id={str(row['id'])[:8]}")

        print(
            "\nNothing was modified. An organization is the root of a cascade "
            "reaching guests,\nsessions, invoices and audit rows, and the "
            "`deadbeef-` fixture generator is not in\nversion control -- "
            "removed rows cannot be regenerated."
        )
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
