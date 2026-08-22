#!/usr/bin/env python3
"""Frontend-callable config-push agent: applies a rendered RouterOS script
to a real device over SSH, through the WireGuard tunnel this host already
terminates. Called directly from the dashboard (browser) after it renders
a config preview -- no backend Celery task involved, matching the
"frontend drives it" design: the browser already has the rendered script
text and the router's real connection info from existing platform APIs;
this agent is just the SSH-capable bridge a browser can't be.

Uses `scp`/`ssh` via subprocess + sshpass (already proven against the real
router tonight) rather than a Python SSH library, to reuse the exact
tooling already verified working end-to-end.
"""

import http.server
import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time

SHARED_SECRET = os.environ.get("CONFIG_AGENT_SECRET", "")
_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def apply_config(tunnel_ip: str, username: str, password: str, script: str) -> dict:
    if not valid_ip(tunnel_ip):
        raise ValueError("invalid tunnel_ip")
    if not _USER_RE.match(username):
        raise ValueError("invalid username")
    if not script.strip():
        raise ValueError("empty script")

    remote_name = f"cloudguest-push-{int(time.time())}.rsc"
    with tempfile.NamedTemporaryFile("w", suffix=".rsc", delete=False) as f:
        f.write(script)
        local_path = f.name

    try:
        scp = subprocess.run(
            [
                "sshpass", "-p", password,
                "scp", "-O",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=25",
                local_path, f"{username}@{tunnel_ip}:{remote_name}",
            ],
            capture_output=True, text=True, timeout=45,
        )
        if scp.returncode != 0:
            return {"applied": False, "stage": "upload", "detail": scp.stderr[-2000:]}

        ssh = subprocess.run(
            [
                "sshpass", "-p", password,
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=25",
                f"{username}@{tunnel_ip}",
                f"/import file-name={remote_name}",
            ],
            capture_output=True, text=True, timeout=45,
        )
        return {
            "applied": ssh.returncode == 0,
            "stage": "import",
            "detail": (ssh.stdout + ssh.stderr)[-3000:],
        }
    finally:
        os.unlink(local_path)


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Agent-Secret")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.end_headers()

    def do_POST(self):
        if self.path != "/config/apply":
            self.send_response(404)
            self.end_headers()
            return
        if not SHARED_SECRET or self.headers.get("X-Agent-Secret") != SHARED_SECRET:
            self._json(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            result = apply_config(
                payload["tunnel_ip"], payload["username"], payload["password"], payload["script"]
            )
            self._json(200 if result["applied"] else 502, result)
        except Exception as e:  # noqa: BLE001 -- single-purpose agent
            self._json(500, {"error": str(e)})

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    if not SHARED_SECRET:
        raise SystemExit("CONFIG_AGENT_SECRET env var must be set")
    http.server.ThreadingHTTPServer(("0.0.0.0", 9093), Handler).serve_forever()
