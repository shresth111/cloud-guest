"""Generates a FreeRADIUS clients.conf block per active RadiusNasClient row
-- run *inside* the deploy-api-1 container (needs its Python environment,
DB session, and Fernet key to call app.domains.router.crypto.decrypt_secret)
via sync_radius_clients.sh, never invoked directly on the host. See
../README.md's "Dynamic NAS clients" section for the full design.

**2026-08-18 incident fix.** Every client block used to be emitted with a
blanket ``ipaddr = 0.0.0.0/0`` -- documented at the time (README, 2026-08-10)
as "correct with today's single real NAS, wrong once there are several."
The fleet grew past one NAS by 2026-08-15 and that gap went live: FreeRADIUS
indexes clients by IP/CIDR, so only the *first* ``0.0.0.0/0`` stanza it
parses in a given ``clients.wyfy.conf`` ever loads -- every other NAS's
block, regardless of its own shortname, is rejected outright as
``Failed to add duplicate client`` (confirmed via
``journalctl -u freeradius`` on cloudguest-vm: the rejected shortname
rotated across reloads because the un-ordered ``SELECT`` below has no
stable row order, not because of any duplicate *row* -- there was never
more than one ``radius_nas_clients`` row per router_id, and
``0061_fix_radius_nas_soft_delete_uniqueness``'s partial unique indexes
plus ``RadiusService.register_nas``'s own
``RadiusNasAlreadyRegisteredError`` guard already prevent that at both the
DB and service layer). Each client's ``ipaddr`` is now scoped to that
router's real WireGuard tunnel address (``wireguard_peers.tunnel_ip_address``,
``/32``) instead, so distinct NAS clients no longer share one IP/CIDR key
and can all load simultaneously. **2026-09-11 follow-up: that fallback is now gone entirely.** Emitting
``ipaddr = 0.0.0.0/0`` for a NAS row with no tunnel peer did not merely widen
one stanza -- it minted a *catch-all client carrying that router's real
``shortname`` and ``backend_secret``*. FreeRADIUS matches clients by longest
prefix, so such a stanza answers every source address no other stanza claims,
and ``sites-enabled/default`` then sends the platform API
``X-RADIUS-NAS-Identifier``/``X-RADIUS-Shared-Secret`` for a genuine router.
Any host that could reach UDP 1812 and knew the stanza's ``secret`` would
authenticate to the backend *as that venue* and could both authorize guests on
it and post accounting against it.

The fallback could never have served a real router either, which is why
removing it cannot break a working venue: the hub's security group admits
1812/1813 only from ``10.20.0.0/24`` (the WireGuard peer range) and the VPC,
so a NAS with no ``wireguard_peers`` row has no network path to FreeRADIUS at
all. A stanza for it can only ever match somebody else. Such rows are now
skipped, named on stderr, and named in a comment in the generated file.

The one genuinely dangerous case -- *every* row skipped -- would otherwise
hand ``sync_radius_clients.sh`` a comments-only file that is still non-empty,
passing its ``[ ! -s ]`` guard and replacing every live stanza. :func:`main`
exits non-zero instead, so the script's ``set -e`` aborts and the last good
``clients.wyfy.conf`` stays exactly where it is."""

import asyncio
import sys

sys.path.insert(0, "/app")
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.domains.router.crypto import decrypt_secret

# LEFT JOINed against wireguard_peers so a NAS with no tunnel peer yet
# still renders (falling back to 0.0.0.0/0 below) instead of silently
# vanishing from clients.wyfy.conf. No ORDER BY is needed now that each
# row's ipaddr is unique -- FreeRADIUS's parse order no longer determines
# which clients survive.
QUERY = text(
    "SELECT n.id, n.nas_identifier, n.shared_secret_encrypted, "
    "w.tunnel_ip_address "
    "FROM radius_nas_clients n "
    "LEFT JOIN wireguard_peers w ON w.router_id = n.router_id "
    "WHERE n.is_deleted = false AND n.status = 'active'"
)


def render_client_block(
    nas_id: object, identifier: str, secret: str, tunnel_ip: str | None
) -> str | None:
    """Renders one FreeRADIUS ``client { }`` stanza for a single
    ``RadiusNasClient`` row. ``ipaddr`` is scoped to ``tunnel_ip`` (that
    router's real WireGuard tunnel address) as a ``/32`` whenever it is
    known -- the fix for the "Failed to add duplicate client" incident
    (see module docstring): FreeRADIUS keys its client table by IP/CIDR,
    so two clients both left on the old blanket ``0.0.0.0/0`` collide and
    only the first-parsed one ever loads, regardless of shortname.

    Returns ``None`` -- rendering no stanza at all -- when ``tunnel_ip``
    is ``None`` (an active NAS registered before its ``wireguard_peers``
    row exists). This used to emit ``ipaddr = 0.0.0.0/0``, which is the
    catch-all defect described in the module docstring: the stanza carries
    this router's real ``shortname`` and ``backend_secret``, and
    FreeRADIUS's longest-prefix client matching then points it at every
    source address no other stanza claims.

    Dropping the row costs nothing a working venue depends on. RADIUS is
    reachable only from ``10.20.0.0/24`` and the VPC, so a NAS with no
    tunnel address cannot send FreeRADIUS a packet in the first place --
    the stanza could only ever have matched a *different* host. ``main()``
    names every skipped row on stderr and in the generated file so the
    condition stays visible instead of being silently papered over with a
    credential-bearing wildcard."""
    if not tunnel_ip:
        return None
    safe_name = f"nas_{str(nas_id).replace('-', '_')}"
    ipaddr = f"{tunnel_ip}/32"
    return (
        f"client {safe_name} {{\n"
        f"    ipaddr = {ipaddr}\n"
        f'    secret = "{secret}"\n'
        # `backend_secret` is NOT a FreeRADIUS built-in -- it is a custom
        # per-client item that `sites-enabled/default` reads back out as
        # `%{client:backend_secret}` when it builds each `rlm_rest` call,
        # so that a router authenticates to the platform API as ITSELF
        # rather than as whichever router happened to be hardcoded into
        # the snippet. `ops/hub-agents/radius_agent.py`'s `add_client()`
        # has always emitted it; this generator never did.
        #
        # That asymmetry is a live, silent divergence, not a cosmetic one:
        # a NAS whose stanza comes from THIS file (every row the 60s
        # `wyfy-radius-sync.timer` regenerates) resolves
        # `%{client:backend_secret}` to the empty string, and the REST
        # call it authenticates goes out with no credential at all. The
        # router does not 401 -- it gets an `Auth-Type: Reject` over HTTP
        # 200, with nothing logged anywhere. Emitting the same item the
        # agent emits is what keeps the two write paths interchangeable.
        f'    backend_secret = "{secret}"\n'
        f"    nas_type = other\n"
        f'    shortname = "{identifier}"\n'
        f"}}\n"
    )


def build_client_config(
    rows: list[tuple[object, str, str, str | None]],
) -> tuple[str, list[str]]:
    """Turn already-decrypted NAS rows into the exact bytes of
    ``clients.wyfy.conf``, plus the warnings to put on stderr.

    Split out of :func:`main` so the three outcomes below can be tested
    without a database, a Fernet key, or a container. They are the whole
    safety contract of this script, and two of the three are states that have
    really occurred on this hub.

    Returns ``(stdout_text, warnings)``. An **empty** ``stdout_text`` means
    "emit nothing at all", which is what makes ``sync_radius_clients.sh``'s
    ``[ ! -s "$TMP" ]`` guard fire and keep the existing file. Raises
    ``SystemExit(1)`` for the one case that must abort the sync outright.
    """
    lines: list[str] = []
    skipped: list[str] = []
    for nas_id, identifier, secret, tunnel_ip in rows:
        block = render_client_block(nas_id, identifier, secret, tunnel_ip)
        if block is None:
            skipped.append(str(identifier))
            continue
        lines.append(block)

    #  Case 1: we have active NAS rows and not one is renderable. This is the
    #  case that must NOT reach sync_radius_clients.sh. Its emptiness guard is
    #  `[ ! -s "$TMP" ]`, and a file of nothing but comments is not empty -- it
    #  would be copied over clients.wyfy.conf and take every live stanza with
    #  it. Exiting non-zero lets that script's `set -e` abort with the last
    #  good file untouched, and is loud because this state is anomalous.
    if rows and not lines:
        print(
            f"REFUSING to emit: all {len(rows)} active NAS client(s) lack a "
            "wireguard_peers tunnel address "
            f"({', '.join(skipped)}). Writing a stanza-less clients.wyfy.conf "
            "would deauthenticate the entire fleet; keeping the existing file.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    #  Case 2: no active NAS rows at all -- a state that has really happened
    #  (on 2026-08-22 every NAS client was deleted through the master console).
    #
    #  Emit NOTHING, not even a newline. `test -s` is "size > 0", so the bare
    #  `print("\n".join([]))` this used to fall through to wrote one byte, the
    #  guard did not fire, and the near-empty file was copied over
    #  clients.wyfy.conf and the server reloaded. Zero rows from a 60-second
    #  cron is far more often a transient or misconfigured read than a real
    #  "this platform has no venues", and removing every NAS stanza fleet-wide
    #  is not a decision to take silently on that evidence.
    if not lines:
        return "", [
            "0 active NAS client(s); emitting nothing so the existing "
            "clients.wyfy.conf is kept rather than replaced with an empty file."
        ]

    #  Case 3: the normal path. Skipped rows are named in the file itself as
    #  well as on stderr, so an operator reading clients.wyfy.conf sees why a
    #  NAS they registered is absent without having to find the log.
    body = "\n".join(lines)
    for identifier in skipped:
        body += (
            f"\n# SKIPPED nas {identifier}: no wireguard_peers tunnel address. "
            "No stanza is emitted -- a 0.0.0.0/0 stanza would carry this "
            "router's real shortname/backend_secret to every unmatched source."
        )
    warnings = [
        f"generated {len(lines)} client(s) from {len(rows)} active NAS row(s); "
        f"{len(skipped)} skipped (no known wireguard tunnel IP)"
    ]
    warnings += [
        f"WARNING nas {identifier} has no tunnel address and was skipped"
        for identifier in skipped
    ]
    return body + "\n", warnings


async def main() -> None:
    settings = get_settings()
    engine = create_async_engine(str(settings.database_url))
    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        rows = (await session.execute(QUERY)).all()

    decrypted = [
        (nas_id, identifier, decrypt_secret(enc), tunnel_ip)
        for nas_id, identifier, enc, tunnel_ip in rows
    ]
    body, warnings = build_client_config(decrypted)
    #  `sys.stdout.write`, not `print`: an empty body must produce zero bytes,
    #  and `print("")` produces one.
    sys.stdout.write(body)
    for warning in warnings:
        print(warning, file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
