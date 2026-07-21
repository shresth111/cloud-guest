"""S3-compatible object storage for durable, attachable binary artifacts.

Before this module, voucher batch PDFs (``app.domains.voucher.voucher_pdf``),
invoice PDFs (``app.domains.billing.invoice_pdf``), and analytics scheduled
report exports (``app.domains.analytics.report_tasks``) were all generated
as real bytes and then thrown away -- returned directly in an HTTP response
or measured for an email body and discarded. This module gives every
domain that generates such bytes a place to persist them, so
``app.domains.notification`` can attach a stored key/URL to an outbox
email instead of re-generating (or simply losing) the file.

Works against any S3-compatible endpoint: MinIO in ``docker-compose.yml``
locally (the default `Settings.s3_endpoint_url`), real AWS S3 in any other
deployment (set `s3_endpoint_url` to an empty string to fall back to
boto3's own AWS endpoint resolution). Object storage is treated as
required local infrastructure -- like Postgres/Redis, not like Stripe/
Razorpay's genuinely-optional-paid-integration posture -- because voucher/
invoice/report generation is core, not optional, functionality.

boto3's S3 client is synchronous. Every call here bridges it through
``asyncio.to_thread``, the same sync-in-async bridge direction
``app.core.celery_app``'s own module docstring documents in reverse (an
async Celery task body bridging to a sync worker context via
``asyncio.run``) -- here it is a sync client called from otherwise-async
service code.
"""

from __future__ import annotations

import asyncio
import logging
from functools import lru_cache
from typing import Protocol

import boto3
from botocore.exceptions import ClientError

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class ObjectStorageError(Exception):
    """Raised when a real upload/presigned-URL request to the configured
    object storage backend fails. Never swallowed silently -- callers
    (e.g. ``app.domains.notification.service.NotificationService``) must
    decide how to handle a genuine storage-layer failure themselves."""


class ObjectStorageProtocol(Protocol):
    async def upload(self, *, key: str, content: bytes, content_type: str) -> str:
        """Persists ``content`` under ``key``. Returns the storage key
        (unchanged) so callers can store it as a plain reference column."""
        ...

    async def generate_presigned_url(
        self, *, key: str, expires_in_seconds: int = 3600
    ) -> str: ...


class S3ObjectStorage:
    """Real, boto3-backed :class:`ObjectStorageProtocol` implementation."""

    def __init__(
        self,
        *,
        bucket_name: str,
        endpoint_url: str | None,
        access_key_id: str,
        secret_access_key: str,
        region_name: str,
    ) -> None:
        self.bucket_name = bucket_name
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url or None,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region_name,
        )
        self._bucket_ensured = False

    def _ensure_bucket_sync(self) -> None:
        if self._bucket_ensured:
            return
        try:
            self._client.head_bucket(Bucket=self.bucket_name)
        except ClientError:
            try:
                self._client.create_bucket(Bucket=self.bucket_name)
            except ClientError as exc:
                raise ObjectStorageError(
                    f"Could not create or access bucket '{self.bucket_name}': {exc}"
                ) from exc
        self._bucket_ensured = True

    def _upload_sync(self, *, key: str, content: bytes, content_type: str) -> str:
        self._ensure_bucket_sync()
        try:
            self._client.put_object(
                Bucket=self.bucket_name, Key=key, Body=content, ContentType=content_type
            )
        except ClientError as exc:
            raise ObjectStorageError(f"Upload of '{key}' failed: {exc}") from exc
        return key

    def _generate_presigned_url_sync(self, *, key: str, expires_in_seconds: int) -> str:
        try:
            return self._client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket_name, "Key": key},
                ExpiresIn=expires_in_seconds,
            )
        except ClientError as exc:
            raise ObjectStorageError(
                f"Could not generate a presigned URL for '{key}': {exc}"
            ) from exc

    async def upload(self, *, key: str, content: bytes, content_type: str) -> str:
        return await asyncio.to_thread(
            self._upload_sync, key=key, content=content, content_type=content_type
        )

    async def generate_presigned_url(
        self, *, key: str, expires_in_seconds: int = 3600
    ) -> str:
        return await asyncio.to_thread(
            self._generate_presigned_url_sync,
            key=key,
            expires_in_seconds=expires_in_seconds,
        )


@lru_cache
def get_object_storage() -> ObjectStorageProtocol:
    """Process-wide singleton, mirroring ``app.core.config.get_settings``'s
    own ``@lru_cache`` no-argument singleton pattern."""
    settings = get_settings()
    return S3ObjectStorage(
        bucket_name=settings.s3_bucket_name,
        endpoint_url=settings.s3_endpoint_url or None,
        access_key_id=settings.s3_access_key_id,
        secret_access_key=settings.s3_secret_access_key,
        region_name=settings.s3_region,
    )


__all__ = [
    "ObjectStorageError",
    "ObjectStorageProtocol",
    "S3ObjectStorage",
    "get_object_storage",
]
