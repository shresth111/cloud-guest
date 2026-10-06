#!/usr/bin/env python3
"""Hub flow agent: serves nfacctd's 5-minute window files to the app server.

NOT DEPLOYED. Design: ~/wyfy-ops/netflow/DESIGN.md §4. Stdlib only, same
shape as wg_agent.py / radius_agent.py: one shared secret in X-Agent-Secret,
bound to the hub's private address, firewalled to the app server.

    GET /flows/windows?after=<epoch>&limit=<n>
        -> {"windows": [{"window_start", "window_seconds", "rows": [...]}],
            "agent_time", "oldest_spooled"}
    GET /flows/health
        -> {"spooled_windows", "newest_window_start", "oldest_spooled"}

Only COMPLETE windows are served: the window has ended plus a grace period,
and the file has not been modified for a few seconds (nfacctd writes it at
the end of the bin). Files older than SPOOL_HOURS are deleted -- the hub
keeps no long-lived flow data (DESIGN.md §7).

Unlike the other two agents, failures are LOGGED (to stderr / journald) and
returned with a reason; a silent agent cost a day once already.
"""

from __future__ import annotations

import calendar
import hmac
import http.server
import json
import logging
import os
import re
import sys
import time
import urllib.parse

SHARED_SECRET = os.environ.get("FLOW_AGENT_SECRET", "")
BIND_ADDR = os.environ.get("AGENT_BIND_ADDR", "127.0.0.1")
PORT = int(os.environ.get("FLOW_AGENT_PORT", "9094"))
SPOOL_DIR = os.environ.get("FLOW_SPOOL_DIR", "/var/spool/wyfy-flows")
WINDOW_SECONDS = 300
GRACE_SECONDS = 60
QUIET_SECONDS = 5
SPOOL_HOURS = 2
MAX_LIMIT = 24

_NAME = re.compile(r"^(\d{8})-(\d{4})\.json$")

logging.basicConfig(
    stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(message)s"
)
log = logging.getLogger("flow_agent")


def window_start_of(name: str) -> int | None:
    match = _NAME.match(name)
    if not match:
        return None
    try:
        parsed = time.strptime(match.group(1) + match.group(2), "%Y%m%d%H%M")
    except ValueError:
        return None
    return calendar.timegm(parsed)  # nfacctd writes UTC on the hub


def spooled() -> list[tuple[int, str]]:
    try:
        names = os.listdir(SPOOL_DIR)
    except FileNotFoundError:
        return []
    out = []
    for name in names:
        start = window_start_of(name)
        if start is not None:
            out.append((start, os.path.join(SPOOL_DIR, name)))
    return sorted(out)


def prune(now: float) -> None:
    cutoff = now - SPOOL_HOURS * 3600
    for start, path in spooled():
        if start + WINDOW_SECONDS < cutoff:
            try:
                os.remove(path)
            except OSError as exc:
                log.warning("prune failed %s: %s", path, exc)


def read_rows(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                log.warning("skipping malformed line in %s", path)
                continue
            rows.append(
                {
                    "peer_ip_src": record.get("peer_ip_src"),
                    "ip_src": record.get("ip_src"),
                    "ip_dst": record.get("ip_dst"),
                    "bytes": record.get("bytes", 0),
                    "packets": record.get("packets", 0),
                    "flows": record.get("flows", 0),
                }
            )
    return rows


def complete_windows(after: int, limit: int, now: float) -> list[dict]:
    windows = []
    for start, path in spooled():
        if start <= after:
            continue
        if start + WINDOW_SECONDS + GRACE_SECONDS > now:
            continue
        try:
            if now - os.path.getmtime(path) < QUIET_SECONDS:
                continue
            rows = read_rows(path)
        except OSError as exc:
            log.warning("read failed %s: %s", path, exc)
            continue
        windows.append(
            {"window_start": start, "window_seconds": WINDOW_SECONDS, "rows": rows}
        )
        if len(windows) >= limit:
            break
    return windows


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        supplied = self.headers.get("X-Agent-Secret", "")
        if not SHARED_SECRET or not hmac.compare_digest(supplied, SHARED_SECRET):
            self._send(401, {"error": "unauthorized"})
            return
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        now = time.time()
        try:
            prune(now)
            files = spooled()
            oldest = files[0][0] if files else None
            if parsed.path == "/flows/windows":
                after = int(query.get("after", ["0"])[0])
                limit = max(1, min(int(query.get("limit", ["12"])[0]), MAX_LIMIT))
                self._send(
                    200,
                    {
                        "windows": complete_windows(after, limit, now),
                        "agent_time": int(now),
                        "oldest_spooled": oldest,
                    },
                )
            elif parsed.path == "/flows/health":
                self._send(
                    200,
                    {
                        "spooled_windows": len(files),
                        "newest_window_start": files[-1][0] if files else None,
                        "oldest_spooled": oldest,
                    },
                )
            else:
                self._send(404, {"error": "not found"})
        except ValueError as exc:
            self._send(400, {"error": f"bad query: {exc}"})
        except Exception as exc:  # noqa: BLE001 -- logged AND returned
            log.exception("handler failed")
            self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

    def log_message(self, fmt: str, *args) -> None:  # noqa: ANN002
        log.info("%s %s", self.address_string(), fmt % args)


def main() -> None:
    if not SHARED_SECRET:
        log.error("FLOW_AGENT_SECRET is empty; refusing to start")
        sys.exit(1)
    server = http.server.ThreadingHTTPServer((BIND_ADDR, PORT), Handler)
    log.info("flow_agent listening on %s:%s, spool %s", BIND_ADDR, PORT, SPOOL_DIR)
    server.serve_forever()


if __name__ == "__main__":
    main()
