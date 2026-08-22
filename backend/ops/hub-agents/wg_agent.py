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
"""

import http.server
import ipaddress
import json
import os
import subprocess

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
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()


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


def next_free_ip() -> str:
    taken = used_ips()
    for host in WG_SUBNET.hosts():
        s = str(host)
        if s.endswith(".1"):
            continue  # server's own address
        if s not in taken:
            return s
    raise RuntimeError("WireGuard subnet exhausted")


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

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    if not SHARED_SECRET:
        raise SystemExit("WG_AGENT_SECRET env var must be set")
    http.server.ThreadingHTTPServer((BIND_ADDR, 9091), Handler).serve_forever()
