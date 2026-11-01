"""COLLECTIONS-1 feature flag and permission keys.

``ISP_COLLECTIONS_ENABLED`` (default OFF): while off every ``/isp/collections``
route answers 404 ``ISP_COLLECTIONS_DISABLED`` and the daily pass does nothing.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import _err

ISP_COLLECTIONS_READ = "isp_collections.read"
#: notes and promises-to-pay
ISP_COLLECTIONS_UPDATE = "isp_collections.update"
#: record cash in the field (+ the receipt slip, + own handover)
ISP_COLLECTIONS_COLLECT = "isp_collections.collect"
#: approve / reject another collector's end-of-day cash handover
ISP_COLLECTIONS_APPROVE = "isp_collections.approve"


class IspCollectionsSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    collections_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_collections_settings() -> IspCollectionsSettings:
    return IspCollectionsSettings()


IspCollectionsDisabledError = _err(
    "IspCollectionsDisabledError", "ISP_COLLECTIONS_DISABLED", 404, "Not Found"
)
IspPromiseNotFoundError = _err(
    "IspPromiseNotFoundError",
    "ISP_COLLECTION_PROMISE_NOT_FOUND",
    404,
    "Promise not found",
)
IspHandoverNotFoundError = _err(
    "IspHandoverNotFoundError",
    "ISP_COLLECTION_HANDOVER_NOT_FOUND",
    404,
    "Handover not found",
)
IspHandoverStateError = _err(
    "IspHandoverStateError",
    "ISP_COLLECTION_HANDOVER_STATE",
    409,
    "This handover has already been decided",
)
IspHandoverSelfApprovalError = _err(
    "IspHandoverSelfApprovalError",
    "ISP_COLLECTION_SELF_APPROVAL",
    409,
    "A collector cannot approve their own handover",
)
IspHandoverEmptyError = _err(
    "IspHandoverEmptyError",
    "ISP_COLLECTION_NOTHING_TO_HAND_OVER",
    422,
    "No cash recorded by you on that day is waiting for a handover",
)


async def RequireCollectionsEnabled() -> None:
    if not get_collections_settings().collections_enabled:
        raise IspCollectionsDisabledError()
