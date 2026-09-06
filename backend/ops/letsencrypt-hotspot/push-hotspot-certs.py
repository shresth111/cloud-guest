"""Push a renewed hotspot certificate to the whole fleet over the RouterOS API.

This is the replacement for the ``scp`` + ``ssh`` half of
``renew-hotspot-certs.sh``. That script still owns certbot, the renewal
window, the DNS-01 hooks and the deploy-hook marker; none of that is broken.
What it can no longer do is reach a router: measured against the live fleet on
2026-09-06, ports 21/22/23/80/443/8291 all *time out* on the only reachable
router -- filtered by a firewall drop, not refused -- and only 8728/8729
answer. So the transport is inverted. The router pulls both PEMs itself with
``/tool fetch`` (an ordinary API command on 8728) from a listener that exists
only for the seconds this run takes, and the re-import and rebind are issued
over the same API session.

Runs INSIDE the ``api`` container, because it needs the app's own settings and
its Fernet key to decrypt each router's own API credential -- and because the
router's fetch URL must be minted on a host that is actually on the WireGuard
tunnel.

    docker compose exec -T api python /opt/wyfy/push-hotspot-certs.py \\
        --fullchain /etc/letsencrypt/live/wyfy-hotspot-fleet/fullchain.pem \\
        --privkey   /etc/letsencrypt/live/wyfy-hotspot-fleet/privkey.pem \\
        --bind-host <this host's WireGuard tunnel address>

``--bind-host`` is not optional and is not guessed. It decides which interface
the fleet private key is briefly readable on, and that must be a decision
somebody made and can read back out of the command that ran, not a default.
A wildcard address is refused outright.

``--dry-run`` prints the inventory and the skips and pushes to nothing. Run it
first: it is the cheapest way to see which venues this renewal will and will
not cover, and the skip lines are the ones worth reading.

STDOUT is the per-router result; STDERR is explanation. Exit status is 0 only
if every pushable router was pushed to *and verified* -- the adapter reads the
device back and refuses to call an unverified push a success.

## Before the first unattended run

Two things in this path have never touched hardware and both should be watched
once, on one router, by a human:

1. whether ``/certificate import`` behaves over the API on this firmware;
2. whether a router can reach an HTTP URL on the app server *at all* -- every
   use of the WireGuard tunnel so far has been app-server-to-router, and this
   is the first thing to ask a router to originate a connection back.

Both fail closed. If the fetch fails, nothing on the router is touched. If the
import silently does nothing, the router is left on its current, working
certificate -- see ``MikroTikAdapter._push_hotspot_certificate_sync``'s
docstring for the ordering that guarantees it.

And one deployment fact that is not a test's to prove. ``--bind-host`` must be
an address this process can actually bind AND the router can actually route
to. Inside a bridged docker container neither is true of the host's WireGuard
address, so ``docker compose exec api`` alone is not enough: either give that
run host networking, or publish a fixed ``--bind-port`` bound to the tunnel
address. This is a sibling of the two blockers tracked elsewhere (the GoDaddy
API credential, and ``/opt/wyfy`` not being mounted into the api container) and
like them it is a deployment decision, not a code change.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from sqlalchemy import select

from app.database.session import SessionLocal
from app.domains.router.hotspot_cert_push import (
    DEFAULT_CERT_NAME,
    DEFAULT_HOTSPOT_PROFILE,
    certificate_san_names,
    push_certificate_to_routers,
    select_push_targets,
)
from app.domains.router.models import Router


def _err(message: str) -> None:
    print(message, file=sys.stderr)


async def _load_routers() -> list[Router]:
    async with SessionLocal() as session:
        rows = await session.execute(select(Router).where(Router.is_deleted.is_(False)))
        return list(rows.scalars().all())


async def _main(args: argparse.Namespace) -> int:
    fullchain = Path(args.fullchain).read_bytes()
    privkey = Path(args.privkey).read_bytes()

    san_names = certificate_san_names(fullchain)
    _err(f"CERT\t{args.cert_name}\tSANs: {', '.join(san_names) or '(none)'}")

    routers = await _load_routers()
    targets, skipped = select_push_targets(
        routers, cert_name=args.cert_name, hotspot_profile=args.hotspot_profile
    )
    for skip in skipped:
        _err(f"SKIP\t{skip.name}\t{skip.reason}")
    _err(f"INVENTORY\t{len(targets)} pushable of {len(routers)} router(s)")

    if args.dry_run:
        for target in targets:
            print(f"DRY-RUN\t{target.name}\t{target.host}")
        return 0
    if not targets:
        _err("FATAL: no router is pushable -- see the SKIP lines above")
        return 1

    outcomes = await push_certificate_to_routers(
        targets,
        fullchain_pem=fullchain,
        privkey_pem=privkey,
        bind_host=args.bind_host,
        bind_port=args.bind_port,
    )

    failures = 0
    for outcome in outcomes:
        if outcome.ok and outcome.result is not None:
            result = outcome.result
            print(
                f"OK\t{outcome.name}\t{outcome.host}\t"
                f"bound={result.bound_ssl_certificate}\t"
                f"expires={result.leaf_invalid_after}\t"
                f"chain={','.join(result.chain_cert_names) or '(deduped)'}"
            )
        else:
            failures += 1
            print(f"FAIL\t{outcome.name}\t{outcome.host}\t{outcome.error}")

    if failures:
        _err(
            f"FINISHED WITH {failures} FAILURE(S) -- those venues are still on "
            "their previous certificate; this is safe until it expires and "
            "then it is not. Needs a human."
        )
        return 1
    _err(f"all {len(outcomes)} router(s) verified on the renewed certificate")
    return 0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--fullchain", required=True)
    parser.add_argument("--privkey", required=True)
    parser.add_argument(
        "--bind-host",
        required=True,
        help=(
            "this host's own WireGuard tunnel address. The PEM listener binds "
            "here and nowhere else; a wildcard address is refused."
        ),
    )
    parser.add_argument(
        "--bind-port",
        type=int,
        default=0,
        help=(
            "port for that listener. 0 (the default) picks an ephemeral one, "
            "which is right when this runs somewhere that already holds the "
            "tunnel address. Pass a fixed port when the listener has to be "
            "published out of a bridged container -- see the module docstring."
        ),
    )
    parser.add_argument("--cert-name", default=DEFAULT_CERT_NAME)
    parser.add_argument("--hotspot-profile", default=DEFAULT_HOTSPOT_PROFILE)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the inventory and the skips, push to nothing",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main(_parse_args())))
