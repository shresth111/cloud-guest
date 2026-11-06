from __future__ import annotations

from functools import lru_cache

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.session import get_db_session

from .archive import (
    ArchiveReader,
    IpdrArchive,
    LocalIpdrArchive,
    S3IpdrArchive,
    archive_from_settings,
)
from .builder import IpdrBuilder
from .constants import STORE_LOCAL, STORE_S3
from .repository import IpdrRepository
from .service import IpdrService


@lru_cache(maxsize=4)
def _s3(bucket: str, region: str) -> S3IpdrArchive:
    return S3IpdrArchive(bucket, region=region)


def archive_for(settings: Settings) -> IpdrArchive:
    bucket = (settings.ipdr_archive_bucket or "").strip()
    if bucket:
        return _s3(bucket, settings.ipdr_archive_region)
    return archive_from_settings(settings)


def reader_for(settings: Settings) -> ArchiveReader:
    """Both stores, so a day written locally before a bucket was configured
    stays readable."""
    archives: dict[str, IpdrArchive] = {
        STORE_LOCAL: LocalIpdrArchive(settings.ipdr_local_dir)
    }
    bucket = (settings.ipdr_archive_bucket or "").strip()
    if bucket:
        archives[STORE_S3] = _s3(bucket, settings.ipdr_archive_region)
    return ArchiveReader(archives)


def ipdr_service_for(session: AsyncSession, settings: Settings) -> IpdrService:
    repository = IpdrRepository(session)
    return IpdrService(
        repository,
        settings,
        IpdrBuilder(repository, settings),
        reader_for(settings),
    )


def get_ipdr_service(
    db: AsyncSession = Depends(get_db_session),
) -> IpdrService:
    return ipdr_service_for(db, get_settings())
