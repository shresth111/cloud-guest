#!/usr/bin/env python3
"""Read-only conformance check for a FreeRADIUS tree, run against a copy of
the hub's ``/etc/freeradius/3.0``.

**Why this exists.** Every RADIUS outage this platform has had was a silent
config divergence that nothing reported, and the hub has no shell -- so the
only way anyone has ever learned the running config was wrong is by a venue
failing. The checks below are not hypothetical: each one is a defect that
actually shipped, named with the date it bit.

+---+------------------------------------------+---------------------------+
| # | invariant                                | what breaks without it    |
+===+==========================================+===========================+
| 1 | ``sites-enabled/default`` is the same    | 2026-08-18 root cause #1: |
|   | file as ``sites-available/default``      | every edit to the         |
|   | (symlink, or byte-identical)             | "obvious" file was inert  |
|   |                                          | for three weeks           |
+---+------------------------------------------+---------------------------+
| 2 | ``mods-enabled/rest`` likewise           | same trap, same tree; the |
|   |                                          | live one is a real file   |
+---+------------------------------------------+---------------------------+
| 3 | ``authorize{}`` sends the per-NAS REST   | 2026-08-18 root cause #2: |
|   | headers via ``%{client:shortname}`` /    | a hardcoded identifier    |
|   | ``%{client:backend_secret}``             | 401'd every router but    |
|   |                                          | the first                 |
+---+------------------------------------------+---------------------------+
| 4 | ``authorize{}`` forces                   | 2026-08-18 root cause #4: |
|   | ``Message-Authenticator`` after ``rest`` | RouterOS silently         |
|   |                                          | discards the Accept as a  |
|   |                                          | "bad-reply"               |
+---+------------------------------------------+---------------------------+
| 5 | ``accounting{}`` calls ``rest``          | no byte data at all, so   |
|   |                                          | data caps and FUP quotas  |
|   |                                          | never enforce             |
+---+------------------------------------------+---------------------------+
| 6 | the accounting payload sends             | totals fed into the       |
|   | ``bytes_uploaded_total`` (not ``_delta``)| backend's additive delta  |
|   |                                          | field make usage grow     |
|   |                                          | quadratically with uptime |
+---+------------------------------------------+---------------------------+
| 7 | the octet counters are reassembled with  | every session past 4 GiB  |
|   | ``Acct-*-Gigawords``                     | truncates to near zero,   |
|   |                                          | exactly when a guest has  |
|   |                                          | used the most             |
+---+------------------------------------------+---------------------------+
| 8 | no ``client{}`` stanza is a catch-all    | any host that reaches     |
|   |                                          | 1812 and knows one secret |
|   |                                          | is a trusted NAS          |
+---+------------------------------------------+---------------------------+
| 9 | ``connect_uri`` points somewhere this    | the estate moved from     |
|   | estate can actually reach                | Azure to AWS on           |
|   |                                          | 2026-08-27 and this repo's|
|   |                                          | copy still named an Azure |
|   |                                          | VNet address              |
+---+------------------------------------------+---------------------------+

This reads files and nothing else. It opens no sockets, runs no FreeRADIUS
binary, and writes nothing -- so it is safe to point at a production capture,
and it is the only form of verification available while the hub has no shell.
It is **not** a substitute for ``radiusd -XC``, which is the only thing that
can prove the config parses; it checks the things ``-XC`` is happy to accept.

Usage::

    verify_hub_config.py /path/to/etc/freeradius/3.0
    verify_hub_config.py /path/to/tree --format json
    verify_hub_config.py /path/to/tree --expect-api-cidr 172.31.0.0/16

Exit status is ``0`` when every check passes, ``1`` when any FAILs.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"


@dataclass
class Finding:
    check: str
    status: str
    detail: str


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _section(text: str, name: str) -> str | None:
    """Extract one top-level unlang section (``authorize {`` ... matching
    ``}``) by brace counting.

    A regex stopping at the first ``}`` is wrong here for the same reason it
    is wrong in ``clients.conf``: ``accounting{}`` legitimately contains
    nested ``if (...) { }`` and ``update { }`` blocks, and ``rest { ... }``
    with an rcode body nests too. Stopping early reports "accounting does not
    call rest" on a file where it plainly does."""
    match = re.search(rf"^{re.escape(name)}\s*\{{", text, re.MULTILINE)
    if not match:
        return None
    start = match.end() - 1
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _strip_comments(text: str) -> str:
    """Drop ``#`` comment lines.

    Load-bearing for every "does this section call rest" check: the repo's own
    ``sites-default.snippets.conf`` discusses ``rest`` at length in prose, and
    a commented-out block is exactly how one of these invariants was lost in
    the first place. A commented ``rest`` is not a call."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def _same_file(enabled: Path, available: Path) -> tuple[bool, str]:
    """Whether ``enabled`` is genuinely the same config as ``available``.

    A symlink is the intended arrangement. A byte-identical regular file is
    *currently* correct but is the trap itself -- they drift the moment
    someone edits one of them, which is precisely what happened on
    2026-08-18 -- so it is reported as a pass with a warning rather than
    silently accepted."""
    if not enabled.exists():
        return False, f"{enabled} does not exist"
    if enabled.is_symlink():
        target = (enabled.parent / enabled.readlink()).resolve()
        if target == available.resolve():
            return True, f"symlink -> {enabled.readlink()}"
        return False, f"symlink points at {enabled.readlink()}, not {available.name}"
    if not available.exists():
        return False, f"{enabled} is a regular file and {available} does not exist"
    if enabled.read_bytes() == available.read_bytes():
        return (
            True,
            "regular file, currently byte-identical to sites-available -- but "
            "NOT a symlink, so the two will drift on the next edit (this is "
            "the 2026-08-18 root cause #1 trap, still armed)",
        )
    return False, (
        f"{enabled} is a regular file that DIFFERS from {available} -- edits "
        "to the sites-available copy are inert"
    )


def check_tree(root: Path, expect_api_cidr: str | None = None) -> list[Finding]:
    findings: list[Finding] = []

    def add(check: str, ok: bool, detail: str) -> None:
        findings.append(Finding(check, PASS if ok else FAIL, detail))

    # 1 + 2 -- enabled vs available
    for enabled_rel, available_rel in (
        ("sites-enabled/default", "sites-available/default"),
        ("mods-enabled/rest", "mods-available/rest"),
    ):
        ok, detail = _same_file(root / enabled_rel, root / available_rel)
        add(f"{enabled_rel} tracks {available_rel}", ok, detail)

    site = _read(root / "sites-enabled/default")
    if site is None:
        findings.append(
            Finding("sites-enabled/default readable", FAIL, "file not found")
        )
        site = ""
    site = _strip_comments(site)

    authorize = _section(site, "authorize") or ""
    accounting = _section(site, "accounting") or ""

    # 3 -- per-NAS REST headers
    has_shortname = "%{client:shortname}" in authorize
    has_backend_secret = "%{client:backend_secret}" in authorize
    add(
        "authorize{} sends per-NAS REST headers",
        has_shortname and has_backend_secret,
        "found %{client:shortname} and %{client:backend_secret}"
        if has_shortname and has_backend_secret
        else (
            f"shortname xlat: {has_shortname}, backend_secret xlat: "
            f"{has_backend_secret} -- a hardcoded NAS identifier 401s every "
            "router but the one it names"
        ),
    )

    # 4 -- Message-Authenticator on the accept path
    mauth = re.search(
        r"update\s+reply\s*\{[^}]*Message-Authenticator\s*:=", authorize, re.DOTALL
    )
    add(
        "authorize{} forces Message-Authenticator on the reply",
        mauth is not None,
        "found `update reply { Message-Authenticator := ... }`"
        if mauth
        else "absent -- RouterOS with require-message-auth discards the "
        "rlm_rest-built Access-Accept as a bad-reply, which is neither a "
        "reject nor a timeout and shows up in no obvious counter",
    )

    # 5 -- accounting actually calls rest
    if not accounting:
        add("accounting{} calls rest", False, "no accounting{} section found")
    else:
        calls_rest = re.search(r"^\s*rest\b", accounting, re.MULTILINE) is not None
        add(
            "accounting{} calls rest",
            calls_rest,
            "accounting{} invokes the rest module"
            if calls_rest
            else "accounting{} is stock (detail/unix/-sql/exec/attr_filter) "
            "and never calls rest -- no byte data reaches the backend, so "
            "data caps and FUP quotas cannot enforce",
        )

    # 6 + 7 -- the accounting payload shape
    rest_conf = _read(root / "mods-enabled/rest") or _read(root / "mods-available/rest")
    if rest_conf is None:
        findings.append(Finding("mods-enabled/rest readable", FAIL, "file not found"))
    else:
        rest_acct = _section(_strip_comments(rest_conf), "\taccounting") or _section(
            _strip_comments(rest_conf), "accounting"
        )
        body = rest_acct or ""
        sends_totals = "bytes_uploaded_total" in body
        sends_deltas = "bytes_uploaded_delta" in body
        add(
            "rest accounting sends totals, not deltas",
            sends_totals and not sends_deltas,
            "payload carries bytes_uploaded_total"
            if sends_totals and not sends_deltas
            else (
                "payload carries bytes_uploaded_delta -- Acct-Input-Octets is "
                "a running TOTAL (RFC 2866 s5.3), and the backend ADDS a "
                "delta, so every interim update re-adds the whole session to "
                "date and usage grows quadratically with uptime"
            ),
        )
        #  Gigawords may be reassembled in rest.conf's data template or, on
        #  this build, in the unlang that precedes it (nested %{...} inside
        #  `data` does not expand). Accept either.
        gigawords = "Gigawords" in (rest_conf + site)
        add(
            "octet counters reassembled with Acct-*-Gigawords",
            gigawords,
            "Gigawords reassembly present"
            if gigawords
            else "absent -- Acct-Input-Octets is the low 32 bits and wraps "
            "every 4 GiB (RFC 2869 s5.1-5.2), so a session past 4 GiB "
            "truncates to near zero exactly when a guest used the most",
        )

        # 9 -- connect_uri
        uri = re.search(r'connect_uri\s*=\s*"([^"]+)"', rest_conf)
        if not uri:
            add("rest connect_uri present", False, "no connect_uri found")
        elif expect_api_cidr:
            host = re.sub(r"^https?://", "", uri.group(1)).split(":")[0].split("/")[0]
            try:
                in_cidr = ipaddress.ip_address(host) in ipaddress.ip_network(
                    expect_api_cidr
                )
            except ValueError:
                #  A hostname rather than a literal. Not checkable here, and
                #  not wrong -- say so instead of failing.
                findings.append(
                    Finding(
                        "rest connect_uri is reachable from this estate",
                        SKIP,
                        f"{host!r} is not an IP literal; cannot check against "
                        f"{expect_api_cidr} without resolving it",
                    )
                )
            else:
                add(
                    "rest connect_uri is reachable from this estate",
                    in_cidr,
                    f"{host} is inside {expect_api_cidr}"
                    if in_cidr
                    else (
                        f"{host} is OUTSIDE {expect_api_cidr} -- a stale "
                        "address here means rlm_rest cannot reach the API at "
                        "all, and both authorize and accounting fail"
                    ),
                )
        else:
            findings.append(
                Finding(
                    "rest connect_uri is reachable from this estate",
                    SKIP,
                    f"{uri.group(1)} -- pass --expect-api-cidr to check it",
                )
            )

    # 8 -- catch-all clients
    clients = _read(root / "clients.conf")
    if clients is None:
        findings.append(Finding("clients.conf readable", SKIP, "file not found"))
    else:
        wildcards = [
            line.strip()
            for line in clients.splitlines()
            if not line.lstrip().startswith("#")
            and re.match(r"^\s*ipaddr\s*=\s*(0\.0\.0\.0(/0)?|\*|::/0)\s*$", line)
        ]
        add(
            "no catch-all client stanza",
            not wildcards,
            "every client stanza is scoped to a specific address"
            if not wildcards
            else (
                f"{len(wildcards)} wildcard address line(s) -- FreeRADIUS "
                "matches clients by longest prefix, so a catch-all answers "
                "every source no other stanza claims. Run "
                "audit_clients_conf.py for the per-stanza breakdown."
            ),
        )

    return findings


def render_text(findings: list[Finding]) -> str:
    out = []
    for f in findings:
        out.append(f"[{f.status}] {f.check}")
        out.append(f"       {f.detail}")
    failed = sum(1 for f in findings if f.status == FAIL)
    out.append("")
    out.append(
        f"{len(findings)} check(s): "
        f"{sum(1 for f in findings if f.status == PASS)} pass, "
        f"{failed} fail, "
        f"{sum(1 for f in findings if f.status == SKIP)} skipped"
    )
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a FreeRADIUS tree (read-only)")
    parser.add_argument("root", help="path to a copy of /etc/freeradius/3.0")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--expect-api-cidr",
        help="CIDR the platform API should live in, e.g. 172.31.0.0/16 for the "
        "AWS VPC. Omitted, connect_uri is reported but not judged.",
    )
    args = parser.parse_args(argv)

    findings = check_tree(Path(args.root), args.expect_api_cidr)
    if args.format == "json":
        print(
            json.dumps(
                [
                    {"check": f.check, "status": f.status, "detail": f.detail}
                    for f in findings
                ],
                indent=2,
            )
        )
    else:
        print(render_text(findings))
    return 1 if any(f.status == FAIL for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
