#!/usr/bin/env python3
"""Hub flow agent: serves nfacctd's 5-minute window files to the app server.

NOT DEPLOYED. Design: ~/wyfy-ops/netflow/DESIGN.md §4. Stdlib only, same
shape as wg_agent.py / radius_agent.py: one shared secret in X-Agent-Secret,
bound to the hub's private address, firewalled to the app server.

    GET /flows/windows?after=<epoch>&limit=<n>
        -> {"windows": [{"window_start", "window_seconds", "rows": [...],
                         "flow_rows": [...], "flow_rows_total",
                         "flow_rows_truncated"}],
            "agent_time", "oldest_spooled"}
    GET /flows/health
        -> {"spooled_windows", "spooled_flow_windows",
            "newest_window_start", "oldest_spooled"}

Two files per window (ops/netflow/nfacctd.conf): ``<stamp>.json`` holds the
rollup rows and is served as ``rows``, exactly as before. ``records-
<stamp>.json`` holds one row per exported flow record (start, end, NAT) and
is served as ``flow_rows``.

Compatibility, in both directions:

* An app that does not know ``flow_rows`` reads ``window_start``,
  ``window_seconds`` and ``rows`` and ignores the rest; those three are
  byte-for-byte what they were.
* A collector that does not write ``records-*.json`` (the older config)
  gives windows with no ``flow_rows`` key at all. The key is absent, not an
  empty list: absent means "the hub has no per-flow rows", an empty list
  means "it has, and there were none".

Only COMPLETE windows are served: the window has ended plus a grace period,
and neither file has been modified for a few seconds (nfacctd writes them at
the end of the bin, the per-flow one in several parts when its cache fills).
Files older than SPOOL_HOURS are deleted -- the hub keeps no long-lived flow
data (DESIGN.md §7). That is the only place per-flow rows live on the hub.

Per-flow rows are bounded on the way out: at most FLOW_ROWS_PER_WINDOW rows
of a window are served, the largest by bytes, with the true count beside
them, and a response stops adding windows once it carries FLOW_ROWS_PER_
RESPONSE of them. Both are stated in the response, never silent.

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

#: Most per-flow rows served for one window, largest by bytes first. A busy
#: venue can export tens of thousands a window; at about 300 bytes a row that
#: is tens of megabytes to build here and to parse in the app.
FLOW_ROWS_PER_WINDOW = int(os.environ.get("FLOW_ROWS_PER_WINDOW", "20000"))
#: Once a response carries this many per-flow rows, no further window is
#: added to it; the app's next pull continues from its cursor.
FLOW_ROWS_PER_RESPONSE = int(os.environ.get("FLOW_ROWS_PER_RESPONSE", "60000"))
#: When earlier windows had a per-flow file and this one does not yet, wait
#: this much longer before serving the window without one. A window is
#: ingested once; served too early, its flow rows would never be stored.
FLOW_FILE_EXTRA_GRACE_SECONDS = 120

FLOW_FILE_PREFIX = "records-"
_NAME = re.compile(r"^(\d{8})-(\d{4})\.json$")
_FLOW_NAME = re.compile(r"^records-(\d{8})-(\d{4})\.json$")

#: Rollup row keys. The first three and the last three are always present in
#: the served row; the middle three only when the collector printed them.
ROLLUP_OPTIONAL_KEYS = ("ip_proto", "port_src", "port_dst")
ROLLUP_KEYS = (
    "peer_ip_src",
    "ip_src",
    "ip_dst",
    *ROLLUP_OPTIONAL_KEYS,
    "bytes",
    "packets",
    "flows",
)
#: Per-flow row keys, as pmacct prints them and as the app's flow-record
#: ingest reads them. A key the collector did not print is left out of the
#: served row: absent is "not recorded", and must not arrive as 0 or "".
FLOW_ROW_KEYS = (
    "peer_ip_src",
    "ip_src",
    "ip_dst",
    "ip_proto",
    "port_src",
    "port_dst",
    "post_nat_ip_src",
    "post_nat_ip_dst",
    "post_nat_port_src",
    "post_nat_port_dst",
    "timestamp_start",
    "timestamp_end",
    "timestamp_arrival",
    "bytes",
    "packets",
    "flows",
)

logging.basicConfig(
    stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(message)s"
)
log = logging.getLogger("flow_agent")


def _stamp(match: re.Match | None) -> int | None:
    if not match:
        return None
    try:
        parsed = time.strptime(match.group(1) + match.group(2), "%Y%m%d%H%M")
    except ValueError:
        return None
    return calendar.timegm(parsed)  # nfacctd writes UTC on the hub


def window_start_of(name: str) -> int | None:
    """Window start of a ROLLUP file name, else None."""
    return _stamp(_NAME.match(name))


def flow_window_start_of(name: str) -> int | None:
    """Window start of a PER-FLOW file name, else None."""
    return _stamp(_FLOW_NAME.match(name))


def _listed(start_of) -> list[tuple[int, str]]:  # noqa: ANN001
    try:
        names = os.listdir(SPOOL_DIR)
    except FileNotFoundError:
        return []
    out = []
    for name in names:
        start = start_of(name)
        if start is not None:
            out.append((start, os.path.join(SPOOL_DIR, name)))
    return sorted(out)


def spooled() -> list[tuple[int, str]]:
    """Rollup files, oldest first."""
    return _listed(window_start_of)


def spooled_flows() -> list[tuple[int, str]]:
    """Per-flow files, oldest first."""
    return _listed(flow_window_start_of)


def prune(now: float) -> None:
    """Delete both kinds of file once their window is SPOOL_HOURS old."""
    cutoff = now - SPOOL_HOURS * 3600
    for start, path in [*spooled(), *spooled_flows()]:
        if start + WINDOW_SECONDS < cutoff:
            try:
                os.remove(path)
            except OSError as exc:
                log.warning("prune failed %s: %s", path, exc)


def _records(path: str):  # noqa: ANN202
    """JSON objects of a spool file, one per line; malformed lines skipped."""
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
            if isinstance(record, dict):
                yield record


def _bytes_of(row: dict) -> int:
    try:
        return int(row.get("bytes") or 0)
    except (TypeError, ValueError):
        return 0


def read_flow_rows(path: str, limit: int | None = None) -> tuple[list[dict], int]:
    """Per-flow rows of one window file and how many the file holds.

    Each row keeps exactly the FLOW_ROW_KEYS the collector printed -- no key
    is invented and no value is rewritten. With ``limit``, only the largest
    rows by bytes are kept (ties in file order), and the second value still
    counts them all."""
    limit = FLOW_ROWS_PER_WINDOW if limit is None else limit
    rows = []
    for record in _records(path):
        rows.append({key: record[key] for key in FLOW_ROW_KEYS if key in record})
    total = len(rows)
    if total > limit:
        # Stable: equal rows stay in file order.
        rows.sort(key=_bytes_of, reverse=True)
        del rows[limit:]
    return rows, total


def read_rows(path: str) -> list[dict]:
    """Rollup rows of one window file. The served shape is unchanged since
    the first version of this agent: an app that predates ``flow_rows``
    depends on it."""
    rows = []
    for record in _records(path):
        rows.append(
            {
                "peer_ip_src": record.get("peer_ip_src"),
                "ip_src": record.get("ip_src"),
                "ip_dst": record.get("ip_dst"),
                # Present once nfacctd aggregates on proto/ports (see
                # ops/netflow/nfacctd.conf). Passed through as printed;
                # the app decides which port is the remote one. Absent
                # keys stay absent so the app can tell "not measured".
                **{key: record[key] for key in ROLLUP_OPTIONAL_KEYS if key in record},
                "bytes": record.get("bytes", 0),
                "packets": record.get("packets", 0),
                "flows": record.get("flows", 0),
            }
        )
    return rows


def _quiet(path: str, now: float) -> bool:
    return now - os.path.getmtime(path) >= QUIET_SECONDS


def complete_windows(after: int, limit: int, now: float) -> list[dict]:
    flow_files = dict(spooled_flows())
    windows = []
    flow_rows_served = 0
    for start, path in spooled():
        if start <= after:
            continue
        if start + WINDOW_SECONDS + GRACE_SECONDS > now:
            continue
        flow_path = flow_files.get(start)
        try:
            if not _quiet(path, now):
                continue
            if flow_path is not None and not _quiet(flow_path, now):
                # Still being written (a busy window is written in parts).
                # Stop here rather than skip: the app's cursor is the newest
                # window it ingested, so a later window served now would
                # leave this one behind for good.
                break
            if (
                flow_path is None
                and flow_files
                and start
                + WINDOW_SECONDS
                + GRACE_SECONDS
                + FLOW_FILE_EXTRA_GRACE_SECONDS
                > now
            ):
                # The collector writes per-flow files and this window's has
                # not appeared yet: give it a little longer, in order.
                break
            window = {
                "window_start": start,
                "window_seconds": WINDOW_SECONDS,
                "rows": read_rows(path),
            }
            if flow_path is not None:
                flow_rows, total = read_flow_rows(flow_path)
                window["flow_rows"] = flow_rows
                window["flow_rows_total"] = total
                window["flow_rows_truncated"] = total > len(flow_rows)
                if total > len(flow_rows):
                    log.warning(
                        "window %s: serving %s of %s flow rows (FLOW_ROWS_PER_WINDOW)",
                        start,
                        len(flow_rows),
                        total,
                    )
                flow_rows_served += len(flow_rows)
        except OSError as exc:
            log.warning("read failed %s: %s", path, exc)
            continue
        windows.append(window)
        if len(windows) >= limit or flow_rows_served >= FLOW_ROWS_PER_RESPONSE:
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
                        "spooled_flow_windows": len(spooled_flows()),
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
