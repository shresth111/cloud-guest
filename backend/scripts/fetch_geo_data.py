#!/usr/bin/env python3
"""Download the DB-IP Lite country and ASN databases for Traffic Lens Geo
Location (``app/domains/traffic_flow/geo.py``).

    python scripts/fetch_geo_data.py                 # into <backend>/data/geo
    python scripts/fetch_geo_data.py --dest /some/dir
    python scripts/fetch_geo_data.py --month 2026-10

Run at image build (see the Dockerfile). Standard library only, needs no
account and no token.

Licence: DB-IP Lite is CC BY 4.0 (https://db-ip.com/db/lite.php). The data
is NOT committed to this repository; the application shows the required
"IP Geolocation by DB-IP" link wherever results appear.

The application works without these files (it answers
``geo_available: false``), so a failure here exits non-zero and leaves any
existing files untouched -- it is the caller's choice whether that stops a
build. Each file is downloaded to a temporary name, checked by actually
opening it and looking an address up, and only then moved into place.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import os
import sys
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.domains.traffic_flow.mmdb import MMDBError, MMDBReader  # noqa: E402

BASE_URL = "https://download.db-ip.com/free"
#: (edition in the URL, file name the application opens, key every record has)
EDITIONS = (
    ("dbip-country-lite", "dbip-country-lite.mmdb", "country"),
    ("dbip-asn-lite", "dbip-asn-lite.mmdb", "autonomous_system_number"),
)
#: A well-known public address both databases must know.
PROBE_ADDRESS = ipaddress.ip_address("8.8.8.8")
MAX_BYTES = 200 * 1024 * 1024
TIMEOUT_SECONDS = 60
USER_AGENT = "wyfy-guest-geo-fetch/1"


def candidate_months(explicit: str | None) -> list[str]:
    """This month, then the previous one: early in a month the new release
    may not be published yet."""
    if explicit:
        return [explicit]
    today = datetime.now(UTC).date().replace(day=1)
    previous = (today - timedelta(days=1)).replace(day=1)
    return [today.strftime("%Y-%m"), previous.strftime("%Y-%m")]


def download(url: str, target: Path) -> str:
    """Fetch ``url`` (gzip) and write the decompressed bytes to ``target``.
    Returns the SHA-256 of the decompressed file."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    digest = hashlib.sha256()
    written = 0
    with (
        urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response,  # noqa: S310
        gzip.GzipFile(fileobj=response) as unpacked,
        target.open("wb") as out,
    ):
        while chunk := unpacked.read(1 << 20):
            written += len(chunk)
            if written > MAX_BYTES:
                raise RuntimeError(f"{url}: larger than {MAX_BYTES} bytes, refused")
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest()


def check(path: Path, key: str) -> int | None:
    """Open the file with the application's own reader and look one address
    up. Returns the build epoch."""
    reader = MMDBReader(path)
    try:
        record = reader.get(PROBE_ADDRESS)
        if not isinstance(record, dict) or key not in record:
            raise MMDBError(f"{path.name}: no usable record for {PROBE_ADDRESS}")
        return reader.build_epoch
    finally:
        reader.close()


def fetch(dest: Path, month: str) -> dict[str, object]:
    dest.mkdir(parents=True, exist_ok=True)
    staged: list[tuple[Path, Path]] = []
    files: dict[str, object] = {}
    try:
        for edition, filename, key in EDITIONS:
            url = f"{BASE_URL}/{edition}-{month}.mmdb.gz"
            temporary = dest / f".{filename}.part"
            sha256 = download(url, temporary)
            staged.append((temporary, dest / filename))
            files[filename] = {
                "url": url,
                "sha256": sha256,
                "bytes": temporary.stat().st_size,
                "build_epoch": check(temporary, key),
            }
        # Both are good: only now replace what the application reads.
        for temporary, final in staged:
            os.replace(temporary, final)
    finally:
        for temporary, _final in staged:
            temporary.unlink(missing_ok=True)
        for _edition, filename, _key in EDITIONS:
            (dest / f".{filename}.part").unlink(missing_ok=True)
    manifest = {
        "source": "DB-IP Lite",
        "license": "CC BY 4.0",
        "attribution": "IP Geolocation by DB-IP (https://db-ip.com)",
        "release": month,
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "files": files,
    }
    (dest / "SOURCE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dest", type=Path, default=BACKEND / "data" / "geo")
    parser.add_argument("--month", help="release to fetch, YYYY-MM (default: newest)")
    args = parser.parse_args()
    last_error: Exception | None = None
    for month in candidate_months(args.month):
        try:
            manifest = fetch(args.dest, month)
        except Exception as exc:  # noqa: BLE001 -- reported, next month tried
            last_error = exc
            print(f"geo data {month}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        print(f"geo data {manifest['release']} written to {args.dest}")
        return 0
    print(f"geo data NOT fetched: {last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
