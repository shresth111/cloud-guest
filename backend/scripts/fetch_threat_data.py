#!/usr/bin/env python3
"""Download the Spamhaus DROP lists (IPv4 and IPv6) for the Traffic Lens
"known-bad destinations" finding (``app/domains/traffic_flow/threat_list.py``).

    python scripts/fetch_threat_data.py                 # into <backend>/data/threat
    python scripts/fetch_threat_data.py --dest /some/dir

Run at image build (see the Dockerfile). Standard library only, needs no
account and no token.

Terms (https://www.spamhaus.org/drop/terms/ and the DROP page, read
2026-10-13): free of charge "regardless of size or business type"; "when
used in a product, credit must be given to Spamhaus Project, and the date
and (c) text should remain with the file and data"; no licence to
redistribute. So the files are NOT committed to this repository, and they
are written here byte for byte as published -- the date and copyright line
are inside them and stay there.

The application works without these files (the finding answers
``could_not_check``), so a failure here exits non-zero and leaves any
existing files untouched -- it is the caller's choice whether that stops a
build. Every file is downloaded to a temporary name, checked by loading the
whole set with the application's own reader, and only then moved into place.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.domains.traffic_flow.threat_list import (  # noqa: E402
    MANIFEST_FILENAME,
    THREAT_LIST_FILENAMES,
    THREAT_LIST_NAME,
    ThreatList,
)

BASE_URL = "https://www.spamhaus.org/drop"
#: A list this small is a broken download, not a quiet day (DROP v4 has
#: held over a thousand net-blocks for years).
MIN_ENTRIES = 100
MAX_BYTES = 20 * 1024 * 1024
TIMEOUT_SECONDS = 60
USER_AGENT = "wyfy-guest-threat-list-fetch/1"


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise RuntimeError(f"{url}: larger than {MAX_BYTES} bytes, refused")
    return body


def fetch(dest: Path) -> dict[str, object]:
    dest.mkdir(parents=True, exist_ok=True)
    files: dict[str, object] = {}
    # Staged in a directory of their own so the set can be loaded exactly as
    # the application will load it before anything it reads is replaced.
    with tempfile.TemporaryDirectory(dir=dest, prefix=".staging-") as staging:
        stage = Path(staging)
        for filename in THREAT_LIST_FILENAMES:
            url = f"{BASE_URL}/{filename}"
            body = download(url)
            (stage / filename).write_bytes(body)
            files[filename] = {
                "url": url,
                "sha256": hashlib.sha256(body).hexdigest(),
                "bytes": len(body),
            }
        loaded = ThreatList(stage)
        if not loaded.available:
            raise RuntimeError(f"not a usable list: {loaded.unavailable_reason}")
        if loaded.entries < MIN_ENTRIES:
            raise RuntimeError(f"only {loaded.entries} entries, refused")
        # The set is good: only now replace what the application reads.
        for filename in THREAT_LIST_FILENAMES:
            os.replace(stage / filename, dest / filename)
    manifest = {
        "source": THREAT_LIST_NAME,
        "terms": "https://www.spamhaus.org/drop/terms/",
        "copyright": loaded.copyright,
        "list_date": loaded.list_date.isoformat() if loaded.list_date else None,
        "entries": loaded.entries,
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "files": files,
    }
    (dest / MANIFEST_FILENAME).write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dest", type=Path, default=BACKEND / "data" / "threat")
    args = parser.parse_args()
    try:
        manifest = fetch(args.dest)
    except Exception as exc:  # noqa: BLE001 -- reported; the build decides
        print(f"threat list NOT fetched: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(
        f"{manifest['source']} {manifest['list_date']} "
        f"({manifest['entries']} entries) written to {args.dest}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
