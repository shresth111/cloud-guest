#!/usr/bin/env python3
"""Minimal per-router FreeRADIUS client-provisioning HTTP agent.

Adds a real `client <tunnel_ip>/32 { ... }` block to clients.conf so this
specific router gets its own genuine NAS identity resolvable via
`%{client:shortname}`/`%{client:backend_secret}` in sites-enabled/default
(see docs -- this is the fix for "every router shared one NAS identity").

Validates with `freeradius -CX` before ever restarting the live service;
reverts on any failure so a bad request can't take down RADIUS for every
other already-configured router.
"""

import http.server
import ipaddress
import json
import os
import re
import shutil
import subprocess
import time

SHARED_SECRET = os.environ.get("RADIUS_AGENT_SECRET", "")
CLIENTS_CONF = "/etc/freeradius/3.0/clients.conf"
BACKUP_DIR = "/root/freeradius-backups"

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")


def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def add_client(tunnel_ip: str, nas_identifier: str, secret: str) -> None:
    if not valid_ip(tunnel_ip):
        raise ValueError("invalid tunnel_ip")
    if not _IDENTIFIER_RE.match(nas_identifier):
        raise ValueError("invalid nas_identifier")
    if not secret or len(secret) < 8:
        raise ValueError("secret too short")

    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_path = os.path.join(BACKUP_DIR, f"clients.conf.bak-{int(time.time())}")
    shutil.copy2(CLIENTS_CONF, backup_path)

    block_name = f"cg-{nas_identifier}".replace(".", "-")
    block = (
        f"\nclient {block_name} {{\n"
        f"\tipaddr = {tunnel_ip}/32\n"
        f"\tsecret = {secret}\n"
        f"\tshortname = {nas_identifier}\n"
        f"\tbackend_secret = {secret}\n"
        f"\trequire_message_authenticator = no\n"
        f"\tnas_type = other\n"
        f"}}\n"
    )
    with open(CLIENTS_CONF, "a") as f:
        f.write(block)

    check = subprocess.run(
        ["freeradius", "-CX"], capture_output=True, text=True, timeout=30
    )
    if check.returncode != 0 or "Configuration appears to be OK" not in check.stdout:
        shutil.copy2(backup_path, CLIENTS_CONF)
        raise RuntimeError(
            "config validation failed, reverted: " + check.stdout[-2000:]
        )

    restart = subprocess.run(
        ["systemctl", "restart", "freeradius"], capture_output=True, text=True, timeout=30
    )
    if restart.returncode != 0:
        shutil.copy2(backup_path, CLIENTS_CONF)
        subprocess.run(["systemctl", "restart", "freeradius"], timeout=30)
        raise RuntimeError("service restart failed, reverted: " + restart.stderr[-2000:])


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/radius/client":
            self.send_response(404)
            self.end_headers()
            return
        if not SHARED_SECRET or self.headers.get("X-Agent-Secret") != SHARED_SECRET:
            self._json(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            add_client(
                payload["tunnel_ip"], payload["nas_identifier"], payload["secret"]
            )
            self._json(200, {"status": "ok"})
        except Exception as e:  # noqa: BLE001 -- single-purpose agent
            self._json(500, {"error": str(e)})

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    if not SHARED_SECRET:
        raise SystemExit("RADIUS_AGENT_SECRET env var must be set")
    http.server.ThreadingHTTPServer(("0.0.0.0", 9092), Handler).serve_forever()
