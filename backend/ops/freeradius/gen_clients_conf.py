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
and can all load simultaneously. ``0.0.0.0/0`` remains as an explicit,
logged fallback for the edge case of an active NAS with no tunnel peer row
yet -- see :func:`render_client_block`'s own docstring."""

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
) -> str:
    """Renders one FreeRADIUS ``client { }`` stanza for a single
    ``RadiusNasClient`` row. ``ipaddr`` is scoped to ``tunnel_ip`` (that
    router's real WireGuard tunnel address) as a ``/32`` whenever it is
    known -- the fix for the "Failed to add duplicate client" incident
    (see module docstring): FreeRADIUS keys its client table by IP/CIDR,
    so two clients both left on the old blanket ``0.0.0.0/0`` collide and
    only the first-parsed one ever loads, regardless of shortname.

    Falls back to ``0.0.0.0/0`` only when ``tunnel_ip`` is ``None`` (an
    active NAS somehow registered before its ``wireguard_peers`` row
    exists) -- kept as an explicit fallback, not silently dropped from the
    generated file, since a NAS that can't yet be scoped to a real IP
    still needs to authenticate; ``main()`` counts and logs how many rows
    hit this fallback so a recurrence is visible in
    ``/var/log/wyfy-radius-sync.log`` rather than silently repeating this
    same incident once a second such NAS exists.

    **2026-08-22: ``backend_secret`` is mandatory, do not remove it.** The
    live ``sites-enabled/default`` on the hub identifies the calling NAS to
    the backend with

        REST-HTTP-Header += "X-RADIUS-NAS-Identifier: %{client:shortname}"
        REST-HTTP-Header += "X-RADIUS-Shared-Secret: %{client:backend_secret}"

    ``%{client:ATTR}`` reads arbitrary named items back off whichever
    ``client { }`` stanza matched this packet's source IP -- but *only*
    items that stanza actually declares. This generator emitted no
    ``backend_secret``, so the xlat expanded to the empty string, the
    backend saw a blank ``X-RADIUS-Shared-Secret`` and 401'd **every**
    authorize call: a total fleet outage, and precisely the 2026-08-18
    incident's signature. Verified live on wyfy-prod-hub-vm 2026-08-22 with
    ``freeradius -X`` + ``radclient``: with the field present the header
    arrives populated; with it absent the header arrives empty and the
    request is rejected. The live ``/usr/local/sbin/radius_agent.py`` (the
    only thing writing NAS stanzas in production today, and whose source
    lives in ``ops/hub-agents/``) has always emitted it -- this generator
    was the odd one out.

    Note this file writes ``clients.wyfy.conf``, which is a DIFFERENT file
    from the ``clients.conf`` the live agent appends to, and which nothing
    currently ``$INCLUDE``s. See ``ops/hub-agents/README.md``."""
    safe_name = f"nas_{str(nas_id).replace('-', '_')}"
    ipaddr = f"{tunnel_ip}/32" if tunnel_ip else "0.0.0.0/0"
    return (
        f"client {safe_name} {{\n"
        f"    ipaddr = {ipaddr}\n"
        f'    secret = "{secret}"\n'
        f'    backend_secret = "{secret}"\n'
        f"    nas_type = other\n"
        f'    shortname = "{identifier}"\n'
        f"}}\n"
    )


async def main() -> None:
    settings = get_settings()
    engine = create_async_engine(str(settings.database_url))
    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        rows = (await session.execute(QUERY)).all()

    lines = []
    fallback_count = 0
    for nas_id, identifier, enc, tunnel_ip in rows:
        if tunnel_ip is None:
            fallback_count += 1
        secret = decrypt_secret(enc)
        lines.append(render_client_block(nas_id, identifier, secret, tunnel_ip))

    print("\n".join(lines))
    print(
        f"# generated {len(rows)} client(s), {fallback_count} on 0.0.0.0/0 fallback "
        "(no known wireguard tunnel IP)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    asyncio.run(main())
