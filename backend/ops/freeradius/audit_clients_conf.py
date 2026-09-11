#!/usr/bin/env python3
"""Read-only audit of a FreeRADIUS ``clients.conf``: which ``client{}``
stanzas are backed by a real, active NAS, which are orphans left behind by
re-provisioning, and which are catch-alls that answer for source addresses
nobody registered.

**Why this exists.** Two separate write paths create stanzas on the hub --
``ops/hub-agents/radius_agent.py``'s ``add_client`` (into ``clients.conf``)
and ``gen_clients_conf.py`` (into ``clients.wyfy.conf``) -- and until
2026-08-22 the agent had no ``DELETE`` at all, so deleting a NAS through the
console removed the database row and left the credential live on the RADIUS
server. The 2026-08-22 capture of the hub shows the result: 19 stanzas, of
which 12 are duplicates for two routers (7 x ``cg-11462682``, 5 x
``cg-04f81868``), one per tunnel address each router was ever reallocated.
Nothing on the box reports that, and the hub has no shell to go looking.

This script is the missing report. It **never writes to the file it is
given**. ``--emit-pruned`` writes a *new* file for a human to diff and apply
deliberately; there is no in-place mode, and applying anything to the live
hub is a separate, manual step.

It is deliberately stdlib-only and takes the set of legitimate NAS
identifiers as an argument rather than opening a database, so it can be run
against a captured tree off-box -- which, while the hub has no shell, is the
only way it can be run at all.

Usage::

    # what is in this file, and what backs it
    audit_clients_conf.py clients.conf --active-nas cg-bfc7ed1c

    # machine-readable, for a checklist or a test
    audit_clients_conf.py clients.conf --active-nas cg-bfc7ed1c --format json

    # write a cleaned copy NEXT TO the original -- never over it
    audit_clients_conf.py clients.conf --active-nas cg-bfc7ed1c \\
        --emit-pruned clients.conf.pruned

Exit status is ``0`` when the file is clean, ``1`` when anything would be
removed, so it can gate a checklist step.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable

#  FreeRADIUS ships ~290 lines of commented-out examples at the top of its
#  stock clients.conf, several of them `#client foo {`. Matching without
#  anchoring past leading `#` classifies those as real stanzas and produces a
#  removal plan that deletes comments -- so the opening `#` is excluded here
#  rather than stripped later.
_CLIENT_OPEN_RE = re.compile(r"^[ \t]*client[ \t]+([^\s{]+)[ \t]*\{")
_SHORTNAME_RE = re.compile(r"^[ \t]*shortname[ \t]*=[ \t]*\"?([^\"\s]+)\"?[ \t]*$")
_IPADDR_RE = re.compile(r"^[ \t]*(?:ipaddr|ipv4addr|ipv6addr)[ \t]*=[ \t]*(\S+)[ \t]*$")
_BACKEND_SECRET_RE = re.compile(r"^[ \t]*backend_secret[ \t]*=")

#  A stanza with either of these as its address answers for every source the
#  more specific stanzas do not claim. FreeRADIUS matches clients by longest
#  prefix, so a catch-all is never shadowed into harmlessness by the specific
#  stanzas around it -- it is strictly the fallback for everything else.
_CATCH_ALL_ADDRESSES = frozenset(
    {"0.0.0.0/0", "0.0.0.0", "*", "::/0", "::", "0.0.0.0/0.0.0.0"}
)

#  Shipped by the distribution in every stock clients.conf. Present on a
#  healthy hub, not evidence of drift, and removing them is not this script's
#  business.
_STOCK_NAMES = frozenset({"localhost", "localhost_ipv6"})

CLEAN = "clean"
CATCH_ALL = "catch-all"
ORPHAN = "orphan"
ACTIVE = "active"
STOCK = "stock"
UNKNOWN = "unknown"


@dataclass
class Stanza:
    """One ``client { ... }`` block, with the source line span that would
    have to be deleted to remove it."""

    label: str
    start: int  # 0-based, inclusive
    end: int  # 0-based, exclusive
    shortname: str | None = None
    ipaddr: str | None = None
    has_backend_secret: bool = False
    classification: str = UNKNOWN
    reasons: list[str] = field(default_factory=list)

    @property
    def identity(self) -> str:
        """What the platform actually knows this NAS by.

        ``shortname`` -- not the ``client <label>`` -- is the value
        ``%{client:shortname}`` sends to the backend's ``CurrentNas``, and the
        live labels are both doubled (``cg-cg-5d3a509e``) and non-unique
        (seven stanzas share ``cg-cg-11462682``). Keying anything on the label
        matches the wrong stanzas."""
        return self.shortname or self.label


def parse_clients_conf(text: str) -> list[Stanza]:
    """Split ``text`` into its ``client{}`` stanzas.

    Brace counting, not a line-per-stanza assumption: a real clients.conf
    nests (``limit { ... }`` inside a client is stock, and ``coa_server``
    blocks nest too), so a naive "until the next ``}``" scan closes the first
    stanza early and mis-attributes every line after it."""
    lines = text.splitlines()
    stanzas: list[Stanza] = []
    i = 0
    while i < len(lines):
        match = _CLIENT_OPEN_RE.match(lines[i])
        if not match:
            i += 1
            continue
        start = i
        depth = lines[i].count("{") - lines[i].count("}")
        shortname: str | None = None
        ipaddr: str | None = None
        has_backend_secret = False
        i += 1
        while i < len(lines) and depth > 0:
            line = lines[i]
            stripped = line.lstrip()
            if not stripped.startswith("#"):
                if (m := _SHORTNAME_RE.match(line)) is not None:
                    shortname = m.group(1)
                elif (m := _IPADDR_RE.match(line)) is not None:
                    ipaddr = m.group(1)
                elif _BACKEND_SECRET_RE.match(line):
                    has_backend_secret = True
            depth += line.count("{") - line.count("}")
            i += 1
        if depth > 0:
            raise ValueError(
                f"unterminated client block opened at line {start + 1} "
                f"({match.group(1)})"
            )
        stanzas.append(
            Stanza(
                label=match.group(1),
                start=start,
                end=i,
                shortname=shortname,
                ipaddr=ipaddr,
                has_backend_secret=has_backend_secret,
            )
        )
    return stanzas


def classify(stanzas: Iterable[Stanza], active_nas: set[str]) -> list[Stanza]:
    """Tag each stanza and record, in prose, why.

    ``active_nas`` is the set of ``nas_identifier`` values with a live
    ``radius_nas_clients`` row (``is_deleted = false AND status = 'active'``)
    -- the same predicate ``gen_clients_conf.py`` selects on."""
    result = []
    seen_identities: dict[str, int] = {}
    for stanza in stanzas:
        stanza.reasons = []
        if stanza.ipaddr in _CATCH_ALL_ADDRESSES:
            stanza.classification = CATCH_ALL
            stanza.reasons.append(
                f"ipaddr {stanza.ipaddr} answers every source address no other "
                "stanza claims (FreeRADIUS matches clients by longest prefix)"
            )
            if stanza.has_backend_secret:
                #  The severe variant. Without backend_secret the stanza is a
                #  dead end -- `%{client:backend_secret}` expands to empty, the
                #  REST call goes out with no credential and `CurrentNas`
                #  refuses it. WITH one, an unregistered source authenticates
                #  to the platform API as a genuine venue.
                stanza.reasons.append(
                    "and it carries backend_secret, so a request from any "
                    "unmatched source authenticates to the platform API as "
                    f"NAS {stanza.identity!r}"
                )
            else:
                stanza.reasons.append(
                    "it carries no backend_secret, so the REST call it "
                    "produces has no credential and CurrentNas rejects it -- "
                    "inert today, but it silently swallows packets from "
                    "unenrolled sources and must go before RADIUS is ever "
                    "exposed more widely"
                )
        elif stanza.label in _STOCK_NAMES:
            stanza.classification = STOCK
            stanza.reasons.append("distribution default, present on a healthy hub")
        elif stanza.identity in active_nas:
            stanza.classification = ACTIVE
            stanza.reasons.append(
                f"shortname {stanza.identity!r} has a live radius_nas_clients row"
            )
            previous = seen_identities.get(stanza.identity)
            if previous is not None:
                #  Same NAS, two addresses. Only one can be the current tunnel
                #  IP; the other is a stale allocation the router no longer
                #  holds. Both still authenticate, which is the problem.
                stanza.classification = ORPHAN
                stanza.reasons = [
                    f"duplicate stanza for active NAS {stanza.identity!r} "
                    f"(already defined at line {previous + 1}) -- a router has "
                    "one current tunnel address; the rest are stale "
                    "allocations that still authenticate"
                ]
            else:
                seen_identities[stanza.identity] = stanza.start
        else:
            stanza.classification = ORPHAN
            stanza.reasons.append(
                f"shortname {stanza.identity!r} has no active radius_nas_clients "
                "row -- the NAS was deleted or was never registered, but this "
                "credential is still live on the RADIUS server"
            )
        result.append(stanza)
    return result


def removable(stanzas: Iterable[Stanza]) -> list[Stanza]:
    """Stanzas the plan proposes deleting: orphans and catch-alls.

    ``stock`` and ``active`` are never proposed. That asymmetry is the whole
    safety property -- a bug in the classifier can leave rubbish behind, but
    it cannot be talked into deauthenticating a live venue."""
    return [s for s in stanzas if s.classification in (ORPHAN, CATCH_ALL)]


def prune(text: str, stanzas: Iterable[Stanza]) -> str:
    """Return ``text`` with ``stanzas`` removed. Deleted back-to-front so an
    earlier removal cannot shift the line numbers of a later one."""
    lines = text.splitlines(keepends=True)
    for stanza in sorted(stanzas, key=lambda s: s.start, reverse=True):
        del lines[stanza.start : stanza.end]
    return "".join(lines)


def render_text(stanzas: list[Stanza], active_nas: set[str]) -> str:
    out: list[str] = []
    counts: dict[str, int] = {}
    for stanza in stanzas:
        counts[stanza.classification] = counts.get(stanza.classification, 0) + 1
    out.append(
        f"{len(stanzas)} client stanza(s); "
        + ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    )
    out.append(f"active NAS identifiers supplied: {', '.join(sorted(active_nas)) or '(none)'}")
    out.append("")
    for stanza in stanzas:
        out.append(
            f"  [{stanza.classification:9}] line {stanza.start + 1:>5}-{stanza.end:<5} "
            f"client {stanza.label}  shortname={stanza.shortname or '(unset)'}  "
            f"ipaddr={stanza.ipaddr or '(unset)'}"
        )
        for reason in stanza.reasons:
            out.append(f"              {reason}")
    doomed = removable(stanzas)
    out.append("")
    if not doomed:
        out.append("PLAN: nothing to remove.")
    else:
        out.append(f"PLAN: remove {len(doomed)} stanza(s):")
        for stanza in doomed:
            out.append(
                f"  - client {stanza.label} (shortname="
                f"{stanza.shortname or '(unset)'}, ipaddr={stanza.ipaddr or '(unset)'}) "
                f"at line {stanza.start + 1}-{stanza.end}"
            )
        out.append("")
        out.append(
            "Nothing has been changed. Re-run with --emit-pruned <newfile> to "
            "write a cleaned copy for review."
        )
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("path", help="clients.conf to read (never modified)")
    parser.add_argument(
        "--active-nas",
        default="",
        help="comma-separated nas_identifier values with a live "
        "radius_nas_clients row (is_deleted=false AND status='active')",
    )
    parser.add_argument(
        "--active-nas-file",
        help="file with one nas_identifier per line; merged with --active-nas",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--emit-pruned",
        metavar="PATH",
        help="write a cleaned copy to PATH for review. Refuses to overwrite "
        "the input, and never edits in place.",
    )
    args = parser.parse_args(argv)

    active: set[str] = {n.strip() for n in args.active_nas.split(",") if n.strip()}
    if args.active_nas_file:
        with open(args.active_nas_file, encoding="utf-8") as handle:
            active |= {line.strip() for line in handle if line.strip()}

    with open(args.path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()

    stanzas = classify(parse_clients_conf(text), active)

    if args.emit_pruned:
        #  Guarding on the string is not enough -- `./clients.conf` and
        #  `clients.conf` are the same file by two names, and a symlinked
        #  sites-enabled-style path is a third.
        import os

        if os.path.realpath(args.emit_pruned) == os.path.realpath(args.path):
            print(
                "--emit-pruned must name a different file; this script never "
                "edits clients.conf in place.",
                file=sys.stderr,
            )
            return 2
        with open(args.emit_pruned, "w", encoding="utf-8") as handle:
            handle.write(prune(text, removable(stanzas)))

    if args.format == "json":
        print(
            json.dumps(
                {
                    "path": args.path,
                    "active_nas": sorted(active),
                    "stanzas": [
                        {
                            "label": s.label,
                            "shortname": s.shortname,
                            "ipaddr": s.ipaddr,
                            "has_backend_secret": s.has_backend_secret,
                            "classification": s.classification,
                            "reasons": s.reasons,
                            "line_start": s.start + 1,
                            "line_end": s.end,
                        }
                        for s in stanzas
                    ],
                    "removable": [s.label for s in removable(stanzas)],
                },
                indent=2,
            )
        )
    else:
        print(render_text(stanzas, active))

    return 1 if removable(stanzas) else 0


if __name__ == "__main__":
    raise SystemExit(main())
