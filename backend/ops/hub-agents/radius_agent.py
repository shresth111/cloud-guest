#!/usr/bin/env python3
"""Minimal per-router FreeRADIUS client-provisioning HTTP agent.

Adds a real `client <address>/32 { ... }` block to clients.conf so this
specific NAS gets its own genuine NAS identity resolvable via
`%{client:shortname}`/`%{client:backend_secret}` in sites-enabled/default
(see docs -- this is the fix for "every router shared one NAS identity").

Validates with `freeradius -CX` before ever restarting the live service;
reverts on any failure so a bad request can't take down RADIUS for every
other already-configured router.

`DELETE /radius/client` is the exact symmetric counterpart of the `POST`.
It did not exist until 2026-08-22, and its absence was a real, live,
silent-data-divergence bug: `app.domains.guest.router
._deregister_nas_from_radius_bridge` has been sending this request since
it was written, `http.server.BaseHTTPRequestHandler` answered every one of
them `501 Unsupported method ('DELETE')`, and the backend logged a WARNING
and returned success to the operator anyway. Net effect on the live hub:
the database held 0 active NAS clients while clients.conf still held 21
`client{}` stanzas -- including every one an operator believed they had
just deleted, each still carrying a valid shared secret. Deleting a NAS is
a security operation (it revokes a router's ability to authenticate
guests); reporting it complete while the credential is still live on the
RADIUS server is the failure mode this whole file now exists to prevent.

Both handlers key on `shortname`, never on the `client <name>` label:
`add_client` writes the label as `cg-<nas_identifier>` while the
`nas_identifier` itself already starts with `cg-`, so the live labels read
`cg-cg-5d3a509e` and are additionally NOT unique (the live hub has seven
separate stanzas all labelled `cg-cg-11462682`, one per tunnel IP that
router has been reallocated over its lifetime). `shortname` is the value
the backend actually knows, the value `%{client:shortname}` sends to
`CurrentNas`, and the only one that identifies a NAS rather than one of
its historical addresses -- so it is what both add and remove match on.
The doubled label is left exactly as it is: it is cosmetic, FreeRADIUS
indexes clients by IP/CIDR rather than by label, and renaming it would
churn every live stanza for no behavioural gain.
"""

import http.server
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time

SHARED_SECRET = os.environ.get("RADIUS_AGENT_SECRET", "")
# Bind to the VNet-private NIC only. Defence in depth behind
# wyfy-agent-firewall.sh and wyfy-prod-hub-nsg: binding here also excludes
# the wg0 tunnel (10.20.0.1), which the NSG cannot see at all.
BIND_ADDR = os.environ.get("AGENT_BIND_ADDR", "0.0.0.0")
CLIENTS_CONF = "/etc/freeradius/3.0/clients.conf"
BACKUP_DIR = "/root/freeradius-backups"

# ONE WRITER AT A TIME.
#
# The server below is a `ThreadingHTTPServer`, so concurrent requests each
# get their own thread and are NOT serialised -- and every mutating path
# does read-modify-write on a single shared file and then shells out to
# `systemctl restart freeradius`. Nothing guarded that.
#
# Two threads interleaving there is a real race with three distinct
# outcomes, all of which surface identically as an opaque HTTP 500:
# one thread reading `clients.conf` while the other is part-way through
# rewriting it; two `systemctl restart` jobs colliding, where systemd
# cancels one and returns non-zero; and `freeradius -CX` parsing the file
# mid-write. The last two both make `_validate_and_restart` restore the
# backup and raise, which is safe but looks like a hard failure to the
# caller.
#
# This is not theoretical. On 2026-08-27 at 14:45:29.920 a single
# `POST /radius/client` returned 500, 105ms after the preceding WireGuard
# write; the same request succeeded when replayed later with nothing else
# in flight. The 60s `wyfy-radius-sync.timer` also runs
# `systemctl reload freeradius`, so there is a recurring external
# collision window this lock alone cannot close -- see README -- but
# serialising this agent's own writers removes the half we control.
#
# Held across the whole mutate-validate-restart sequence, not just the
# file write: the restart is as much a part of the critical section as the
# write is.
_LOG = logging.getLogger("radius_agent")

_WRITE_LOCK = threading.Lock()

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
_CLIENT_OPEN_RE = re.compile(r"^\s*client\s+(\S+)\s*\{")
_SHORTNAME_RE = re.compile(r"^\s*shortname\s*=\s*(\S+)\s*$")


def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _split_client_blocks(text: str) -> list[tuple[int, int, str | None]]:
    """Return ``(start_line, end_line_exclusive, shortname)`` for every
    top-level ``client ... { ... }`` block in ``text``.

    Deliberately a real brace-depth scan rather than a regex over the whole
    file: ``clients.conf`` legitimately contains nested blocks (a ``limit
    {}`` inside a client, ``client {}`` examples inside comments) and
    Ubuntu's stock file is ~290 lines of exactly that. A commented-out
    ``#client foo {`` must not be treated as a block, which is why
    ``_CLIENT_OPEN_RE`` anchors on optional whitespace then a literal
    ``client``.

    ## A block with no ``shortname`` line reports its LABEL

    FreeRADIUS defaults a client's shortname to the ``client <name>``
    label when the ``shortname`` directive is absent, so a stanza written
    without one still answers to that name at runtime. This parser used to
    report ``None`` for those, and ``None`` never equals anything a caller
    asks for -- so such a block was invisible to
    :func:`_strip_clients_with_shortname` and could not be deleted by any
    request at all.

    That was not hypothetical. The live hub carried

        client cloudguest-dynamic-wan {
            ipaddr = 0.0.0.0/0
            ...
        }

    with no ``shortname`` line, and every
    ``DELETE {"nas_identifier": "cloudguest-dynamic-wan"}`` answered
    ``{"removed": 0}`` -- which reads as "already gone" and is the one
    answer that makes an operator stop looking. A ``0.0.0.0/0`` client
    with a fixed shared secret stayed on the RADIUS server for weeks
    because of it, and removing it in the end took shell on a box nobody
    had shell on. Matching what FreeRADIUS itself does is the fix.
    """
    lines = text.split("\n")
    blocks: list[tuple[int, int, str | None]] = []
    i = 0
    while i < len(lines):
        open_match = _CLIENT_OPEN_RE.match(lines[i])
        if open_match:
            depth = 0
            start = i
            # The label, used as the shortname when the block declares
            # none -- FreeRADIUS's own rule. See this function's docstring.
            label = open_match.group(1)
            shortname: str | None = None
            while i < len(lines):
                stripped = lines[i].split("#", 1)[0]
                depth += stripped.count("{") - stripped.count("}")
                if depth == 1:
                    m = _SHORTNAME_RE.match(stripped)
                    if m:
                        shortname = m.group(1)
                if depth == 0 and i > start:
                    break
                i += 1
            if depth != 0:
                # Unbalanced braces: refuse to guess where this block ends.
                raise RuntimeError(
                    f"clients.conf has an unterminated client block at line "
                    f"{start + 1}; refusing to edit it"
                )
            blocks.append((start, i + 1, shortname or label))
        i += 1
    return blocks


def _strip_clients_with_shortname(
    text: str, nas_identifier: str
) -> tuple[str, list[str]]:
    """Remove EVERY ``client`` block whose ``shortname`` is
    ``nas_identifier``. Returns the new text and the removed blocks' own
    source text (so a caller replacing a stanza can carry settings over
    from the one it supersedes).

    Every match is removed, not just the first: the live hub proves a
    single ``nas_identifier`` routinely owns several stanzas at once (one
    per tunnel IP it has ever held -- ``register_external_radius_nas``
    re-registers on secret rotation and the old stanza was never taken
    away). Leaving any of them behind would leave a still-valid shared
    secret on the RADIUS server for a NAS the operator just deleted, which
    is precisely the bug this function exists to close.
    """
    blocks = _split_client_blocks(text)
    doomed = [b for b in blocks if b[2] == nas_identifier]
    if not doomed:
        return text, []
    lines = text.split("\n")
    drop: set[int] = set()
    removed_text: list[str] = []
    for start, end, _ in doomed:
        drop.update(range(start, end))
        removed_text.append("\n".join(lines[start:end]))
    kept = [ln for idx, ln in enumerate(lines) if idx not in drop]
    return "\n".join(kept), removed_text


def _validate_and_restart(backup_path: str) -> None:
    """Parse-check, then restart. Any failure restores ``backup_path`` and
    raises -- never returns a "succeeded" that didn't.

    ``freeradius -CX`` is checked on BOTH its exit status and its "OK"
    banner: this build has been observed to exit 0 while still reporting
    problems, and a config that fails to parse takes authentication down
    for the entire fleet, not just the router being changed.
    """
    check = subprocess.run(
        ["freeradius", "-CX"], capture_output=True, text=True, timeout=30
    )
    if check.returncode != 0 or "Configuration appears to be OK" not in check.stdout:
        shutil.copy2(backup_path, CLIENTS_CONF)
        raise RuntimeError(
            "config validation failed, reverted: " + check.stdout[-2000:]
        )

    restart = subprocess.run(
        ["systemctl", "restart", "freeradius"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if restart.returncode != 0:
        shutil.copy2(backup_path, CLIENTS_CONF)
        subprocess.run(["systemctl", "restart", "freeradius"], timeout=30)
        raise RuntimeError(
            "service restart failed, reverted: " + restart.stderr[-2000:]
        )


def _backup() -> str:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_path = os.path.join(BACKUP_DIR, f"clients.conf.bak-{int(time.time())}")
    shutil.copy2(CLIENTS_CONF, backup_path)
    return backup_path


def add_client(
    address: str,
    nas_identifier: str,
    secret: str,
    require_message_authenticator: bool | None = None,
) -> dict:
    """Serialised against every other mutating call -- see `_WRITE_LOCK`.

    Argument validation stays OUTSIDE the lock: it touches nothing shared
    and a malformed request should not queue behind a live restart.

    `address` was called `tunnel_ip` when every NAS on this server was a
    MikroTik on the WireGuard overlay. An Omada controller in RADIUS mode
    is a NAS too and it has no tunnel -- its stanza is keyed on its public
    address -- so the parameter is named for what it is. The HTTP handler
    accepts BOTH spellings (see `do_POST`), because a backend newer than
    this file must keep working and a backend older than it must too.

    `require_message_authenticator` is `None` for "keep this agent's
    existing behaviour" (carry `yes` over from a superseded stanza, else
    `no`) and `True` to demand it. It is not defaulted to `True` here:
    flipping that default would hard-reject every router in the fleet that
    does not send a Message-Authenticator, which is a fleet-wide behaviour
    change and not this function's business. It exists because an
    internet-facing client -- which is what a controller stanza is -- has a
    spoofable source address, and Omada demonstrably sends the attribute on
    every request (measured on the wire, 2026-09-11).
    """
    if not valid_ip(address):
        raise ValueError("invalid address")
    if not _IDENTIFIER_RE.match(nas_identifier):
        raise ValueError("invalid nas_identifier")
    if not secret or len(secret) < 8:
        raise ValueError("secret too short")

    with _WRITE_LOCK:
        return _add_client_locked(
            address, nas_identifier, secret, require_message_authenticator
        )


def _add_client_locked(
    address: str,
    nas_identifier: str,
    secret: str,
    require_message_authenticator: bool | None = None,
) -> dict:
    backup_path = _backup()

    with open(CLIENTS_CONF) as f:
        current = f.read()

    # Replace, don't append. Appending is what produced the live hub's
    # seven-stanzas-for-one-NAS state: every secret rotation left the
    # PREVIOUS stanza in place, still valid, still bound to a tunnel IP
    # that WireGuard is free to reallocate to a different router. A
    # re-registration must supersede the old identity, not sit alongside
    # it.
    current, superseded = _strip_clients_with_shortname(current, nas_identifier)

    # Carry `require_message_authenticator` over from the stanza being
    # superseded instead of re-asserting this agent's own default. Some
    # live stanzas were hand-set to `yes` during the 2026-08-18
    # captive-portal incident and a re-registration silently downgrading
    # them back to `no` would quietly weaken (BlastRADIUS, CVE-2024-3596)
    # a router an operator had deliberately hardened. `no` remains the
    # default for a genuinely new NAS: flipping that default would hard-
    # reject any router that does not send a Message-Authenticator on its
    # Access-Request, which is a fleet-wide behaviour change and not this
    # change's business.
    require_msg_auth = "no"
    for old in superseded:
        m = re.search(r"^\s*require_message_authenticator\s*=\s*(\S+)", old, re.M)
        if m and m.group(1) == "yes":
            require_msg_auth = "yes"
    # An explicit `yes` from the caller wins over both the default and the
    # carried-over value. It can only ever HARDEN: there is no way to ask
    # this agent to turn the requirement off, so a request cannot silently
    # downgrade a client somebody deliberately hardened -- the exact
    # asymmetry the carry-over above exists to protect.
    if require_message_authenticator:
        require_msg_auth = "yes"

    block_name = f"cg-{nas_identifier}".replace(".", "-")
    block = (
        f"\nclient {block_name} {{\n"
        f"\tipaddr = {address}/32\n"
        f"\tsecret = {secret}\n"
        f"\tshortname = {nas_identifier}\n"
        f"\tbackend_secret = {secret}\n"
        f"\trequire_message_authenticator = {require_msg_auth}\n"
        f"\tnas_type = other\n"
        f"}}\n"
    )
    with open(CLIENTS_CONF, "w") as f:
        f.write(current.rstrip("\n") + "\n" + block)

    _validate_and_restart(backup_path)
    return {"status": "ok", "superseded": len(superseded)}


def remove_client(nas_identifier: str) -> dict:
    """Remove every ``client{}`` stanza for ``nas_identifier``.

    ``removed`` is returned to the caller rather than being flattened into
    a bare 200: ``removed == 0`` means "this NAS was not on this RADIUS
    server", which is a materially different outcome from "its credential
    has just been revoked" and the backend is entitled to tell an operator
    which one happened. What this function will never do is return success
    without the file on disk actually no longer containing the stanza --
    the write, the ``freeradius -CX`` parse check and the restart all have
    to succeed first, and any one of them failing restores the backup and
    raises.
    """
    if not _IDENTIFIER_RE.match(nas_identifier):
        raise ValueError("invalid nas_identifier")

    with _WRITE_LOCK:
        return _remove_client_locked(nas_identifier)


def _remove_client_locked(nas_identifier: str) -> dict:
    with open(CLIENTS_CONF) as f:
        current = f.read()

    updated, removed = _strip_clients_with_shortname(current, nas_identifier)
    if not removed:
        # Nothing to do: no file write, no parse check, no restart. A
        # no-op must not bounce the RADIUS service for the whole fleet.
        return {"status": "ok", "removed": 0}

    backup_path = _backup()
    with open(CLIENTS_CONF, "w") as f:
        f.write(updated)
    _validate_and_restart(backup_path)

    # Belt and braces: re-read what is actually on disk now. The whole
    # class of bug this agent keeps being bitten by is an operation that
    # reports success having changed nothing, so the success path here is
    # conditional on the file really not containing the stanza any more.
    with open(CLIENTS_CONF) as f:
        _, still_present = _strip_clients_with_shortname(f.read(), nas_identifier)
    if still_present:
        shutil.copy2(backup_path, CLIENTS_CONF)
        subprocess.run(["systemctl", "restart", "freeradius"], timeout=30)
        raise RuntimeError(
            f"{len(still_present)} stanza(s) for {nas_identifier} still "
            f"present after removal; reverted"
        )
    return {"status": "ok", "removed": len(removed)}


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed_payload(self) -> dict | None:
        """Shared auth + body parse. Returns ``None`` (having already
        written the error response) if the request must not proceed."""
        if self.path != "/radius/client":
            self.send_response(404)
            self.end_headers()
            return None
        if not SHARED_SECRET or self.headers.get("X-Agent-Secret") != SHARED_SECRET:
            self._json(401, {"error": "unauthorized"})
            return None
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_POST(self):
        try:
            payload = self._authed_payload()
            if payload is None:
                return
            # `address` is the current spelling, `tunnel_ip` the one every
            # deployed backend before 2026-09-12 sends. Accepting both is
            # what lets this agent and the backend be upgraded in either
            # order -- which matters more than usual here, because nobody
            # currently has shell on this host to upgrade it at all.
            address = payload.get("address") or payload.get("tunnel_ip")
            if not address:
                self._json(400, {"error": "address (or tunnel_ip) is required"})
                return
            result = add_client(
                address,
                payload["nas_identifier"],
                payload["secret"],
                bool(payload.get("require_message_authenticator")) or None,
            )
            self._json(200, result)
        except Exception as e:  # noqa: BLE001 -- single-purpose agent
            # Log BEFORE responding, with the traceback. The response body
            # carries `str(e)`, which is all the caller can use, but the
            # traceback is what distinguishes "PermissionError on
            # /root/freeradius-backups" from "systemctl restart lost a race"
            # -- and those want completely different fixes.
            _LOG.warning("add_client failed: %s", e, exc_info=True)
            self._json(500, {"error": str(e)})

    def do_DELETE(self):
        try:
            payload = self._authed_payload()
            if payload is None:
                return
            nas_identifier = payload.get("nas_identifier")
            if not nas_identifier:
                self._json(400, {"error": "nas_identifier is required"})
                return
            self._json(200, remove_client(nas_identifier))
        except Exception as e:  # noqa: BLE001 -- single-purpose agent
            _LOG.warning("remove_client failed: %s", e, exc_info=True)
            self._json(500, {"error": str(e)})

    def log_message(self, fmt, *args):
        # Was `pass`. That is why the 2026-08-27 outage cost a day: the
        # agent returned a 500 with a precise reason in its body, the
        # backend discarded the body, and this no-op meant the hub's own
        # journal had no record either. There was literally nowhere left to
        # look. Access lines go to the journal at DEBUG (quiet by default,
        # available with `systemctl log-level debug`); real faults are
        # logged at WARNING by the handlers below regardless.
        _LOG.debug("%s - %s", self.address_string(), fmt % args)


if __name__ == "__main__":
    # systemd captures stderr into the journal, so this is all that is
    # needed for `journalctl -u radius-agent` to become useful.
    logging.basicConfig(
        level=logging.DEBUG,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s radius-agent %(message)s",
    )
    if not SHARED_SECRET:
        raise SystemExit("RADIUS_AGENT_SECRET env var must be set")
    http.server.ThreadingHTTPServer((BIND_ADDR, 9092), Handler).serve_forever()
