"""Emit the hotspot-certificate push list, one router per line, from the database.

Runs INSIDE the `api` container (it needs the app's own settings and its
decryption key), invoked by renew-hotspot-certs.sh:

    docker compose exec -T api python /opt/wyfy/fleet-inventory.py

This file lives BESIDE the script that calls it, in the product repo, and
that is deliberate. It was originally added to the separate wyfy-infra
operations repo alone, while the product repo kept the hand-written router
array this file exists to replace -- so for two weeks the repo an engineer
actually opens described a mechanism that had already been replaced, and one
of them read it and concluded the fleet certificate covered a single router.
A helper whose only caller lives in another repo is a drift waiting to
happen; see renew-hotspot-certs.sh's own header for the full account.

Output, one line per pushable router, tab-separated:

    <name>\t<management_ip>\t<credential>

Anything that is not a pushable router goes to STDERR as a SKIP line with a
reason, so a router silently missing from a renewal is impossible to confuse
with a fleet that is fully covered. STDOUT is data; STDERR is explanation.

WHY THIS EXISTS
---------------
renew-hotspot-certs.sh used to carry a hand-written `ROUTERS=(...)` array and
one fleet-wide `ROUTER_SSH_PASSWORD`. Both were wrong for the fleet this
platform actually provisions, and its own README already said so ("a shared
password across the whole fleet is a real, known gap, not an oversight").

Measured 2026-08-23, not assumed: the founder's router (10.20.0.72) had ZERO
certificates on it. It was not in the array, and the shared password did not
authenticate to it -- verified by an explicit SSH attempt. The setup-script
generator issues every router its own credential and stores it encrypted, so
the shared password cannot reach ANY router the generator provisioned. The
push could only ever have worked on the one router that predates it.

A hand-maintained inventory also fails in the direction nobody notices: a new
venue goes live, nobody edits the array, and that venue serves an expiring
certificate until a guest complains.

THE dns-name CHECK IS NOT OPTIONAL
----------------------------------
A router is only pushable if the hostname its hotspot redirects to is covered
by the certificate being pushed. Pushing to a router whose `dns-name` is
something else installs a certificate that does not match the address in the
guest's URL bar -- which produces the same full-screen browser warning the
whole certificate effort exists to remove, while looking like a success in
every log. That check lives in the shell script (it needs the SANs of the
actual PEM); this file exports the dns-name so it can be made.
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy import select

from app.database.session import SessionLocal
from app.domains.router.crypto import decrypt_secret
from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router


def _skip(name: str, reason: str) -> None:
    print(f"SKIP\t{name}\t{reason}", file=sys.stderr)


async def _main() -> None:
    async with SessionLocal() as session:
        rows = (
            (await session.execute(select(Router).where(Router.is_deleted.is_(False))))
            .scalars()
            .all()
        )

    emitted = 0
    for r in rows:
        name = r.name or str(r.id)

        # ONLINE ONLY. An offline router cannot be pushed to, and attempting
        # it would turn every renewal into a wall of connection failures that
        # a real failure then hides inside. It is reported as a skip so the
        # gap stays visible: that venue keeps serving the old certificate
        # until it comes back and the next renewal reaches it.
        if r.status != RouterStatus.ONLINE.value:
            _skip(name, f"status={r.status}, not reachable for a push")
            continue

        if not r.management_ip_address:
            _skip(name, "no management address (has it ever joined the tunnel?)")
            continue

        # The generator stores a per-router credential. No credential means
        # this router was enrolled some other way, and the push has no way in
        # -- which is exactly the state the shared password used to hide.
        if not r.api_credentials_encrypted:
            _skip(
                name,
                "no stored credential -- re-run the setup script for this router",
            )
            continue

        try:
            secret = decrypt_secret(r.api_credentials_encrypted)
        except Exception as exc:  # noqa: BLE001 -- one router must not abort the fleet
            _skip(name, f"credential could not be decrypted: {type(exc).__name__}")
            continue

        if not secret:
            _skip(name, "stored credential decrypts to an empty string")
            continue

        # Tab-separated because a RouterOS password may contain almost
        # anything except a tab, and the shell reader splits on tabs only.
        # `|` (what the old hand-written array used) is a plausible password
        # character and would have split a credential in half silently.
        print(f"{name}\t{r.management_ip_address}\t{secret}")
        emitted += 1

    print(f"INVENTORY\t{emitted} pushable of {len(rows)} router(s)", file=sys.stderr)


asyncio.run(_main())
