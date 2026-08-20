#!/usr/bin/env python3
"""Phase A live-venue adoption: read-only discover for a router manifest.

Calls ``POST /api/v1/routers/{id}/discover?trigger=manual`` for each entry.
Never applies configuration. See ``LIVE_VENUE_ADOPTION.md`` §3.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def _api_request(
    *,
    base_url: str,
    token: str,
    method: str,
    path: str,
    query: dict[str, str] | None = None,
    organization_id: str | None = None,
) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if organization_id:
        headers["X-Organization-Id"] = organization_id
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} -> HTTP {exc.code}: {detail}") from exc
    payload = json.loads(body)
    if not payload.get("success"):
        raise RuntimeError(f"{method} {path} failed: {payload.get('message')}")
    return payload["data"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        required=True,
        help="JSON file with {venues: [{router_id, venue_name, organization_id?}]}",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("CLOUDGUEST_API_BASE_URL", ""),
        help="API base including /api/v1 (or set CLOUDGUEST_API_BASE_URL)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("CLOUDGUEST_BEARER_TOKEN", ""),
        help="Bearer token (or set CLOUDGUEST_BEARER_TOKEN)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print manifest only; do not call the API",
    )
    args = parser.parse_args()

    with open(args.manifest, encoding="utf-8") as handle:
        manifest = json.load(handle)
    venues = manifest.get("venues") or []
    if not venues:
        print("manifest has no venues", file=sys.stderr)
        return 1

    if args.dry_run:
        print("venue_name\trouter_id\torganization_id")
        for entry in venues:
            print(
                f"{entry.get('venue_name', '')}\t{entry.get('router_id', '')}\t"
                f"{entry.get('organization_id') or ''}"
            )
        return 0

    if not args.base_url or not args.token:
        print(
            "Set --base-url/--token or CLOUDGUEST_API_BASE_URL/CLOUDGUEST_BEARER_TOKEN",
            file=sys.stderr,
        )
        return 1

    print(
        "venue_name\trouter_id\tsnapshot_status\tcompatibility_overall\tsnapshot_id\terror"
    )
    exit_code = 0
    for entry in venues:
        router_id = str(entry["router_id"])
        venue_name = str(entry.get("venue_name") or router_id)
        org_id = entry.get("organization_id")
        org_header = str(org_id) if org_id else None
        try:
            data = _api_request(
                base_url=args.base_url,
                token=args.token,
                method="POST",
                path=f"/routers/{router_id}/discover",
                query={"trigger": "manual"},
                organization_id=org_header,
            )
            snapshot = data.get("snapshot") or {}
            compatibility = data.get("compatibility") or {}
            print(
                f"{venue_name}\t{router_id}\t{snapshot.get('status', '')}\t"
                f"{compatibility.get('overall', '')}\t{snapshot.get('id', '')}\t"
            )
        except Exception as exc:  # noqa: BLE001 — operator script
            exit_code = 1
            print(f"{venue_name}\t{router_id}\t\t\t\t{exc}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
