#!/usr/bin/env python3
"""Minimal WireGuard peer-provisioning HTTP agent for radius-wg-vm.

Runs as root (systemd service) so it can shell out to `wg`/wg-quick config
persistence. Auth is a single shared secret header -- this host has no
other HTTP service exposed except FreeRADIUS (UDP) and this agent, and the
secret is never logged.

POST /wg/peer  { }  (empty body)  -> allocates the next free /32 in
  10.20.0.0/24 (scanning `wg show wg0 allowed-ips`), generates a fresh
  keypair with `wg genkey`/`wg pubkey`, adds it live via `wg set` AND
  appends it to /etc/wireguard/wg0.conf so it survives a reboot, and
  returns everything the caller needs to configure the far end.

GET /wg/peers -> the hub's own ground truth of who is actually tunneled in
  right now, straight from `wg show wg0 dump` -- public key, tunnel IP,
  last handshake, bytes transferred. Exists because the app's own
  `wireguard_peers` table can drift from what the hub is really doing (a
  peer added directly on the box, or a DB row that never got created,
  never shows up in a DB-only view) -- this endpoint is what lets the
  backend build a fleet-status view against reality instead of trusting
  the database alone.
"""

import http.server
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys

SHARED_SECRET = os.environ.get("WG_AGENT_SECRET", "")
# Bind to the VNet-private NIC only. Defence in depth behind
# wyfy-agent-firewall.sh and wyfy-prod-hub-nsg: binding here also excludes
# the wg0 tunnel (10.20.0.1), which the NSG cannot see at all.
BIND_ADDR = os.environ.get("AGENT_BIND_ADDR", "0.0.0.0")
WG_IFACE = "wg0"
WG_SUBNET = ipaddress.ip_network("10.20.0.0/24")
SERVER_ENDPOINT_HOST = "hub.wyfyguest.com"
SERVER_ENDPOINT_PORT = "51820"
WG_CONF_PATH = "/etc/wireguard/wg0.conf"


def run(cmd: list[str]) -> str:
    return subprocess.run(
        cmd, check=True, capture_output=True, text=True
    ).stdout.strip()


def server_public_key() -> str:
    return run(["wg", "show", WG_IFACE, "public-key"])


def used_ips() -> set[str]:
    out = run(["wg", "show", WG_IFACE, "allowed-ips"])
    used = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            cidr = parts[1]
            ip = cidr.split("/")[0]
            used.add(ip)
    return used


# WireGuard public keys are 32 bytes, base64 -- 44 chars ending in "=".
# Validated before ever reaching a subprocess argument list.
_PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]=$")

_LOG = logging.getLogger("wg_agent")


def next_free_ip() -> str:
    taken = used_ips()
    for host in WG_SUBNET.hosts():
        s = str(host)
        if s.endswith(".1"):
            continue  # server's own address
        if s not in taken:
            return s
    raise RuntimeError("WireGuard subnet exhausted")


def list_peers() -> list[dict]:
    """One entry per line of `wg show wg0 dump` (the header/server line is
    skipped -- it has only 4 fields where a real peer line has 8, so the
    split-length check below is what tells them apart, the same way
    `wg`'s own `--help` documents the two line shapes).

    Field order per WireGuard's own dump format: public-key, preshared-key,
    endpoint, allowed-ips, latest-handshake (unix epoch seconds, "0" if
    never), transfer-rx, transfer-tx, persistent-keepalive."""
    out = run(["wg", "show", WG_IFACE, "dump"])
    peers = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 8:
            continue  # the one 4-field line is the interface/server itself
        (
            public_key,
            _psk,
            endpoint,
            allowed_ips,
            latest_handshake,
            rx,
            tx,
            _keepalive,
        ) = parts
        peers.append(
            {
                "public_key": public_key,
                "endpoint": endpoint if endpoint != "(none)" else None,
                "allowed_ips": allowed_ips,
                "latest_handshake_epoch": int(latest_handshake),
                "transfer_rx_bytes": int(rx),
                "transfer_tx_bytes": int(tx),
            }
        )
    return peers


def allocate_peer() -> dict:
    private_key = run(["wg", "genkey"])
    public_key = subprocess.run(
        ["wg", "pubkey"], input=private_key, check=True, capture_output=True, text=True
    ).stdout.strip()
    tunnel_ip = next_free_ip()

    subprocess.run(
        ["wg", "set", WG_IFACE, "peer", public_key, "allowed-ips", f"{tunnel_ip}/32"],
        check=True,
    )
    with open(WG_CONF_PATH, "a") as f:
        f.write(f"\n[Peer]\nPublicKey = {public_key}\nAllowedIPs = {tunnel_ip}/32\n")

    return {
        "router_private_key": private_key,
        "router_public_key": public_key,
        "router_tunnel_ip": tunnel_ip,
        "server_public_key": server_public_key(),
        "server_endpoint_host": SERVER_ENDPOINT_HOST,
        "server_endpoint_port": SERVER_ENDPOINT_PORT,
        "tunnel_subnet": str(WG_SUBNET),
    }


def remove_peer(public_key: str) -> dict:
    """Remove one peer from the live interface AND from ``wg0.conf``.

    !! NOT YET DEPLOYED. !! Written 2026-08-27; the running agent on the
    hub has no DELETE handler at all, and there is currently no shell
    access to that host (no key, EC2 Instance Connect is unavailable on
    its Debian AMI, no SSM agent) to install this. Committed so it is ready
    the moment access exists, and so the gap is on the record rather than
    in someone's head.

    Why it has to exist: ``allocate_peer()`` above always allocates and
    there is no update path, so before this every re-provision of a router
    left its previous peer on the hub permanently. Confirmed live -- one
    router accumulated 10.20.0.2/.3/.4/.5, and the orphans outlived the
    deletion of the router's own database rows. Nothing in the platform
    could reclaim them, because this verb did not exist.

    Both halves matter and they fail differently. ``wg set ... remove``
    alone leaves the stanza in ``wg0.conf``, so the peer returns on the
    next ``wg-quick`` restart or reboot. Editing the file alone leaves the
    peer live in the kernel until then. So: kernel first (so the peer stops
    routing immediately even if the rewrite then fails), file second.

    Idempotent: removing a peer the interface does not have is reported as
    ``removed: 0`` rather than an error, matching ``radius_agent.py``'s
    ``remove_client`` -- "this peer was not here" is a materially different
    outcome from "it has just been revoked", and the caller is entitled to
    tell them apart.
    """
    if not _PUBKEY_RE.match(public_key):
        raise ValueError("invalid public_key")

    present = public_key in {p["public_key"] for p in list_peers()}
    if not present:
        return {"status": "ok", "removed": 0}

    subprocess.run(
        ["wg", "set", WG_IFACE, "peer", public_key, "remove"],
        check=True,
    )

    # Rewrite wg0.conf without this peer's [Peer] stanza. A real
    # block-boundary scan, not a regex over the whole file: an [Interface]
    # section precedes the peers and must survive untouched, and a
    # PublicKey line only identifies the stanza it sits inside.
    with open(WG_CONF_PATH) as f:
        lines = f.read().split("\n")
    out: list[str] = []
    i = 0
    dropped = 0
    while i < len(lines):
        if lines[i].strip().lower() == "[peer]":
            end = i + 1
            while end < len(lines) and not lines[end].strip().startswith("["):
                end += 1
            block = lines[i:end]
            if any(
                ln.split("=", 1)[1].strip() == public_key
                for ln in block
                if ln.strip().lower().startswith("publickey") and "=" in ln
            ):
                dropped += 1
                i = end
                continue
            out.extend(block)
            i = end
            continue
        out.append(lines[i])
        i += 1

    with open(WG_CONF_PATH, "w") as f:
        f.write("\n".join(out).rstrip("\n") + "\n")

    return {"status": "ok", "removed": 1, "config_stanzas_dropped": dropped}


class Handler(http.server.BaseHTTPRequestHandler):
    def _unauthorized(self):
        self.send_response(401)
        self.end_headers()
        self.wfile.write(b'{"error":"unauthorized"}')

    def do_POST(self):
        if self.path != "/wg/peer":
            self.send_response(404)
            self.end_headers()
            return
        if not SHARED_SECRET or self.headers.get("X-Agent-Secret") != SHARED_SECRET:
            self._unauthorized()
            return
        try:
            result = allocate_peer()
            body = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:  # noqa: BLE001 -- single-purpose agent, log and 500
            body = json.dumps({"error": str(e)}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_GET(self):
        if self.path != "/wg/peers":
            self.send_response(404)
            self.end_headers()
            return
        if not SHARED_SECRET or self.headers.get("X-Agent-Secret") != SHARED_SECRET:
            self._unauthorized()
            return
        try:
            body = json.dumps({"peers": list_peers()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:  # noqa: BLE001 -- single-purpose agent, log and 500
            body = json.dumps({"error": str(e)}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_DELETE(self):
        """!! NOT YET DEPLOYED -- see `remove_peer`. !!

        The backend has been sending this request since
        `make_hub_peer_deregistrar` was written; the running agent answers
        every one of them `501 Unsupported method ('DELETE')`, which is
        why `revoke_tunnel` cannot actually revoke and why superseded peers
        accumulate. Same request shape as the POST: JSON body, same header
        auth, same path.
        """
        if self.path != "/wg/peer":
            self.send_response(404)
            self.end_headers()
            return
        if not SHARED_SECRET or self.headers.get("X-Agent-Secret") != SHARED_SECRET:
            self._unauthorized()
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            public_key = payload.get("public_key")
            if not public_key:
                body = json.dumps({"error": "public_key is required"}).encode()
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = json.dumps(remove_peer(public_key)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:  # noqa: BLE001 -- single-purpose agent
            _LOG.warning("remove_peer failed: %s", e, exc_info=True)
            body = json.dumps({"error": str(e)}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Was `pass`, identically to radius_agent.py's. Between the two
        # agents that meant a failure on either left no trace anywhere: the
        # response body was discarded by the backend and the journal had
        # nothing. That is what made the 2026-08-27 fault take a day to
        # place. See radius_agent.py's own note.
        _LOG.debug("%s - %s", self.address_string(), fmt % args)


if __name__ == "__main__":
    # systemd captures stderr into the journal, so this is all that is
    # needed for `journalctl -u wg-agent` to become useful.
    logging.basicConfig(
        level=logging.DEBUG,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s wg-agent %(message)s",
    )
    if not SHARED_SECRET:
        raise SystemExit("WG_AGENT_SECRET env var must be set")
    http.server.ThreadingHTTPServer((BIND_ADDR, 9091), Handler).serve_forever()
