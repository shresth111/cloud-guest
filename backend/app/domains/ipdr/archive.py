"""Where IPDR day files live: S3 (``ipdr/`` prefix of the 2-year
Object-Locked netlogs archive bucket) or, when no bucket is configured, a
local directory. One gzip NDJSON object per (organization, location, IST
day), a new key per build -- Object Lock never has to overwrite anything.

The S3 client uses boto3's default credential chain (the instance role via
IMDSv2), **not** the MinIO keys of ``app.core.storage``. The role needs
``s3:PutObject`` + ``s3:GetObject`` on ``ipdr/*`` (DESIGN.md section 3; the
owner runs that command). No delete is ever issued.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Protocol

from app.core.config import Settings

from .constants import ARCHIVE_FORMAT_VERSION, STORE_LOCAL, STORE_S3


class IpdrArchiveError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class StoredDay:
    store: str
    key: str
    sha256: str
    size: int


def encode_day(records: list[dict[str, Any]]) -> bytes:
    lines = "".join(
        json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in records
    )
    # mtime=0: the same rows always give the same bytes (and sha256).
    return gzip.compress(lines.encode(), mtime=0)


def decode_day(blob: bytes) -> list[dict[str, Any]]:
    text = gzip.decompress(blob).decode()
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def object_key(
    prefix: str,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    day: date,
    built_at: datetime,
) -> str:
    stamp = built_at.strftime("%Y%m%dT%H%M%SZ")
    base = prefix.strip("/")
    return (
        f"{base}/{ARCHIVE_FORMAT_VERSION}/org={organization_id}/"
        f"loc={location_id}/date={day.isoformat()}/ipdr-{stamp}.ndjson.gz"
    )


class IpdrArchive(Protocol):
    store: str

    async def put(self, key: str, blob: bytes) -> StoredDay: ...

    async def get(self, key: str) -> bytes: ...


class LocalIpdrArchive:
    store = STORE_LOCAL

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if self.root.resolve() not in path.parents:
            raise IpdrArchiveError(f"Key outside the archive: {key}")
        return path

    async def put(self, key: str, blob: bytes) -> StoredDay:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        return StoredDay(self.store, key, hashlib.sha256(blob).hexdigest(), len(blob))

    async def get(self, key: str) -> bytes:
        try:
            return self._path(key).read_bytes()
        except FileNotFoundError as exc:
            raise IpdrArchiveError(f"Missing archive object: {key}") from exc


class S3IpdrArchive:
    store = STORE_S3

    def __init__(self, bucket: str, *, region: str, client: Any = None) -> None:
        self.bucket = bucket
        if client is None:
            import boto3

            client = boto3.client("s3", region_name=region)
        self._client = client

    def _put(self, key: str, blob: bytes) -> StoredDay:
        try:
            # Object Lock buckets refuse a PUT without an integrity checksum.
            self._client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=blob,
                ContentType="application/x-ndjson",
                ContentEncoding="gzip",
                ChecksumAlgorithm="SHA256",
            )
        except Exception as exc:
            raise IpdrArchiveError(f"Upload of {key} failed: {exc}") from exc
        return StoredDay(self.store, key, hashlib.sha256(blob).hexdigest(), len(blob))

    def _get(self, key: str) -> bytes:
        try:
            response = self._client.get_object(Bucket=self.bucket, Key=key)
            return response["Body"].read()
        except Exception as exc:
            raise IpdrArchiveError(f"Download of {key} failed: {exc}") from exc

    async def put(self, key: str, blob: bytes) -> StoredDay:
        return await asyncio.to_thread(self._put, key, blob)

    async def get(self, key: str) -> bytes:
        return await asyncio.to_thread(self._get, key)


def archive_from_settings(settings: Settings) -> IpdrArchive:
    bucket = (settings.ipdr_archive_bucket or "").strip()
    if bucket:
        return S3IpdrArchive(bucket, region=settings.ipdr_archive_region)
    return LocalIpdrArchive(settings.ipdr_local_dir)


class ArchiveReader:
    """Reads a day file by its index row, checking the stored sha256."""

    def __init__(self, archives: dict[str, IpdrArchive]) -> None:
        self._archives = archives

    async def read(self, store: str, key: str, sha256: str) -> list[dict[str, Any]]:
        archive = self._archives.get(store)
        if archive is None:
            raise IpdrArchiveError(f"No {store} archive configured for {key}")
        blob = await archive.get(key)
        if hashlib.sha256(blob).hexdigest() != sha256:
            raise IpdrArchiveError(f"Checksum mismatch for {key}")
        return decode_day(blob)
