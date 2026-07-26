"""Unit tests for the Branding domain's background-image upload/delete/
read flow -- ``BrandingService.upload_background_image``/
``delete_background_image``/``get_background_image_bytes``, and the proxy
path (``BrandingService._resolve_background_image_url``) that
``background_image_url`` resolves to, exercised indirectly through
``get_branding``.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_dns.py``) and ``tests/unit/test_voucher.py``'s own
``FakeObjectStorage`` precedent for faking
``app.core.storage.ObjectStorageProtocol`` -- reused here (extended with
``download``) rather than re-invented.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.common.responses import ApiResponse
from app.core.storage import ObjectStorageError
from app.domains.branding.exceptions import (
    BackgroundImageNotFoundError,
    BrandingStorageNotConfiguredError,
    InvalidBackgroundImageError,
    InvalidLogoError,
    LogoNotFoundError,
)
from app.domains.branding.models import Branding
from app.domains.branding.router import router as branding_router
from app.domains.branding.schemas import BrandingResponse, DefaultBrandingResponse
from app.domains.branding.service import (
    BACKGROUND_IMAGE_MAX_BYTES,
    BACKGROUND_IMAGE_RAW_PATH,
    DEFAULT_BRANDING,
    LOGO_MAX_BYTES,
    LOGO_RAW_PATH,
    BrandingService,
)

# ============================================================================
# Shared fakes
# ============================================================================


@dataclass
class FakeObjectStorage:
    """In-memory stand-in for ``app.core.storage.ObjectStorageProtocol`` --
    mirrors ``tests/unit/test_voucher.py``'s own ``FakeObjectStorage``,
    extended with ``download`` for the background-image proxy read path."""

    uploaded: dict[str, bytes] = field(default_factory=dict)
    fail_download: bool = False

    async def upload(self, *, key: str, content: bytes, content_type: str) -> str:
        self.uploaded[key] = content
        return key

    async def generate_presigned_url(
        self, *, key: str, expires_in_seconds: int = 3600
    ) -> str:
        return f"https://minio.example.com/{key}?expires={expires_in_seconds}"

    async def download(self, *, key: str) -> bytes:
        if self.fail_download:
            raise ObjectStorageError("download failed")
        return self.uploaded[key]


class FakeBrandingRepository:
    """In-memory stand-in for ``BrandingRepositoryProtocol``."""

    def __init__(self) -> None:
        self._by_org: dict[uuid.UUID, Branding] = {}

    async def get_by_organization(self, organization_id: uuid.UUID) -> Branding | None:
        return self._by_org.get(organization_id)

    async def upsert(
        self,
        organization_id: uuid.UUID,
        data: dict,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> Branding:
        existing = self._by_org.get(organization_id)
        if existing:
            for k, v in data.items():
                if v is not None:
                    setattr(existing, k, v)
            existing.updated_by = actor_user_id
            return existing
        branding = Branding(
            id=uuid.uuid4(),
            organization_id=organization_id,
            company_name=data.get("company_name"),
            logo_url=data.get("logo_url"),
            favicon_url=data.get("favicon_url"),
            primary_color=data.get("primary_color"),
            secondary_color=data.get("secondary_color"),
            accent_color=data.get("accent_color"),
            theme=data.get("theme", "light"),
            background_image_key=None,
            created_by=actor_user_id,
            updated_by=actor_user_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        self._by_org[organization_id] = branding
        return branding

    async def set_background_image_key(
        self,
        organization_id: uuid.UUID,
        key: str | None,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> Branding:
        existing = self._by_org.get(organization_id)
        if existing:
            existing.background_image_key = key
            existing.updated_by = actor_user_id
            return existing
        branding = Branding(
            id=uuid.uuid4(),
            organization_id=organization_id,
            background_image_key=key,
            created_by=actor_user_id,
            updated_by=actor_user_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        self._by_org[organization_id] = branding
        return branding

    async def set_logo_key(
        self,
        organization_id: uuid.UUID,
        key: str | None,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> Branding:
        existing = self._by_org.get(organization_id)
        if existing:
            existing.logo_key = key
            existing.updated_by = actor_user_id
            return existing
        branding = Branding(
            id=uuid.uuid4(),
            organization_id=organization_id,
            logo_key=key,
            created_by=actor_user_id,
            updated_by=actor_user_id,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        self._by_org[organization_id] = branding
        return branding


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> object:
        self.entries.append(fields)
        return None


def make_service(
    *, with_storage: bool = True
) -> tuple[
    BrandingService,
    FakeBrandingRepository,
    FakeObjectStorage | None,
    FakeAuditLogWriter,
]:
    repository = FakeBrandingRepository()
    audit_writer = FakeAuditLogWriter()
    storage = FakeObjectStorage() if with_storage else None
    service = BrandingService(
        repository, audit_writer=audit_writer, object_storage=storage
    )
    return service, repository, storage, audit_writer


PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"0" * 100


# ============================================================================
# upload_background_image
# ============================================================================


class TestUploadBackgroundImage:
    async def test_upload_persists_key_and_returns_proxy_url(self) -> None:
        service, repository, storage, audit_writer = make_service()
        org_id = uuid.uuid4()

        result = await service.upload_background_image(
            org_id,
            filename="bg.png",
            content_type="image/png",
            content=PNG_BYTES,
            actor_user_id=uuid.uuid4(),
        )

        # A stable proxy path, not a direct object-storage link -- see
        # BACKGROUND_IMAGE_RAW_PATH's own docstring for why.
        assert result.background_image_url == BACKGROUND_IMAGE_RAW_PATH
        stored = repository._by_org[org_id]
        assert stored.background_image_key is not None
        assert stored.background_image_key.startswith(f"branding/{org_id}/background/")
        assert stored.background_image_key.endswith(".png")
        assert storage.uploaded[stored.background_image_key] == PNG_BYTES
        assert any(
            e["action"] == "branding_background_image_updated"
            for e in audit_writer.entries
        )

    async def test_upload_replaces_existing_key(self) -> None:
        service, repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()

        first = await service.upload_background_image(
            org_id, filename="a.png", content_type="image/png", content=PNG_BYTES
        )
        second = await service.upload_background_image(
            org_id, filename="b.jpg", content_type="image/jpeg", content=PNG_BYTES
        )

        # Same stable proxy path both times -- the underlying key changed,
        # not the URL callers see.
        assert first.background_image_url == second.background_image_url
        assert repository._by_org[org_id].background_image_key.endswith(".jpg")

    async def test_rejects_unsupported_content_type(self) -> None:
        service, _repository, _storage, _audit = make_service()
        with pytest.raises(InvalidBackgroundImageError):
            await service.upload_background_image(
                uuid.uuid4(),
                filename="script.svg",
                content_type="image/svg+xml",
                content=b"<svg></svg>",
            )

    async def test_rejects_empty_file(self) -> None:
        service, _repository, _storage, _audit = make_service()
        with pytest.raises(InvalidBackgroundImageError):
            await service.upload_background_image(
                uuid.uuid4(),
                filename="empty.png",
                content_type="image/png",
                content=b"",
            )

    async def test_rejects_oversized_file(self) -> None:
        service, _repository, _storage, _audit = make_service()
        oversized = b"0" * (BACKGROUND_IMAGE_MAX_BYTES + 1)
        with pytest.raises(InvalidBackgroundImageError):
            await service.upload_background_image(
                uuid.uuid4(),
                filename="huge.png",
                content_type="image/png",
                content=oversized,
            )

    async def test_raises_when_storage_not_configured(self) -> None:
        service, _repository, _storage, _audit = make_service(with_storage=False)
        with pytest.raises(BrandingStorageNotConfiguredError):
            await service.upload_background_image(
                uuid.uuid4(),
                filename="bg.png",
                content_type="image/png",
                content=PNG_BYTES,
            )


# ============================================================================
# delete_background_image
# ============================================================================


class TestDeleteBackgroundImage:
    async def test_delete_clears_key(self) -> None:
        service, repository, _storage, audit_writer = make_service()
        org_id = uuid.uuid4()
        await service.upload_background_image(
            org_id, filename="bg.png", content_type="image/png", content=PNG_BYTES
        )
        assert repository._by_org[org_id].background_image_key is not None

        result = await service.delete_background_image(org_id)

        assert result.background_image_url is None
        assert repository._by_org[org_id].background_image_key is None
        assert any(
            e["action"] == "branding_background_image_removed"
            for e in audit_writer.entries
        )

    async def test_raises_when_storage_not_configured(self) -> None:
        service, _repository, _storage, _audit = make_service(with_storage=False)
        with pytest.raises(BrandingStorageNotConfiguredError):
            await service.delete_background_image(uuid.uuid4())


# ============================================================================
# get_branding / round trip
# ============================================================================


class TestGetBrandingBackgroundImage:
    async def test_get_branding_with_no_row_returns_platform_default(self) -> None:
        # DefaultBrandingResponse (the platform fallback) has no
        # background_image_url field at all -- it's a fixed public
        # default, not per-organization data.
        service, _repository, _storage, _audit = make_service()
        result = await service.get_branding(uuid.uuid4())
        assert result is DEFAULT_BRANDING

    async def test_get_branding_returns_the_proxy_path_when_image_set(self) -> None:
        service, _repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()
        await service.upload_background_image(
            org_id, filename="bg.png", content_type="image/png", content=PNG_BYTES
        )

        first = await service.get_branding(org_id)
        second = await service.get_branding(org_id)

        # Deterministic and stable across calls -- no expiring link to
        # regenerate, so both reads return the exact same value.
        assert first.background_image_url == BACKGROUND_IMAGE_RAW_PATH
        assert second.background_image_url == BACKGROUND_IMAGE_RAW_PATH

    async def test_get_branding_returns_no_url_after_delete(self) -> None:
        service, _repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()
        await service.upload_background_image(
            org_id, filename="bg.png", content_type="image/png", content=PNG_BYTES
        )
        await service.delete_background_image(org_id)

        result = await service.get_branding(org_id)

        assert result.background_image_url is None


# ============================================================================
# get_background_image_bytes (backs GET /branding/background-image/raw)
# ============================================================================


class TestGetBackgroundImageBytes:
    async def test_returns_bytes_and_content_type_for_uploaded_image(self) -> None:
        service, _repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()
        await service.upload_background_image(
            org_id, filename="bg.jpg", content_type="image/jpeg", content=PNG_BYTES
        )

        content, content_type = await service.get_background_image_bytes(org_id)

        assert content == PNG_BYTES
        assert content_type == "image/jpeg"

    async def test_raises_not_found_when_no_image_set(self) -> None:
        service, _repository, _storage, _audit = make_service()
        with pytest.raises(BackgroundImageNotFoundError):
            await service.get_background_image_bytes(uuid.uuid4())

    async def test_raises_not_found_when_no_branding_row_at_all(self) -> None:
        service, _repository, _storage, _audit = make_service()
        with pytest.raises(BackgroundImageNotFoundError):
            await service.get_background_image_bytes(uuid.uuid4())

    async def test_raises_when_storage_not_configured(self) -> None:
        service, _repository, _storage, _audit = make_service(with_storage=False)
        with pytest.raises(BrandingStorageNotConfiguredError):
            await service.get_background_image_bytes(uuid.uuid4())

    async def test_propagates_storage_download_failure(self) -> None:
        service, _repository, storage, _audit = make_service()
        org_id = uuid.uuid4()
        await service.upload_background_image(
            org_id, filename="bg.png", content_type="image/png", content=PNG_BYTES
        )
        storage.fail_download = True

        with pytest.raises(ObjectStorageError):
            await service.get_background_image_bytes(org_id)


# ============================================================================
# upload_logo / delete_logo / get_logo_bytes -- mirrors the
# background-image test classes above exactly.
# ============================================================================


class TestUploadLogo:
    async def test_upload_persists_key_and_returns_proxy_url(self) -> None:
        service, repository, storage, audit_writer = make_service()
        org_id = uuid.uuid4()

        result = await service.upload_logo(
            org_id,
            filename="logo.png",
            content_type="image/png",
            content=PNG_BYTES,
            actor_user_id=uuid.uuid4(),
        )

        assert result.logo_url == LOGO_RAW_PATH
        assert result.logo_is_uploaded is True
        stored = repository._by_org[org_id]
        assert stored.logo_key is not None
        assert stored.logo_key.startswith(f"branding/{org_id}/logo/")
        assert stored.logo_key.endswith(".png")
        assert storage.uploaded[stored.logo_key] == PNG_BYTES
        assert any(
            e["action"] == "branding_logo_updated" for e in audit_writer.entries
        )

    async def test_upload_wins_over_plain_text_logo_url(self) -> None:
        service, repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()
        repository._by_org[org_id] = Branding(
            id=uuid.uuid4(),
            organization_id=org_id,
            logo_url="https://example.com/manually-typed-logo.png",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        result = await service.upload_logo(
            org_id, filename="logo.png", content_type="image/png", content=PNG_BYTES
        )

        assert result.logo_url == LOGO_RAW_PATH
        assert result.logo_is_uploaded is True

    async def test_rejects_unsupported_content_type(self) -> None:
        service, _repository, _storage, _audit = make_service()
        with pytest.raises(InvalidLogoError):
            await service.upload_logo(
                uuid.uuid4(),
                filename="script.svg",
                content_type="image/svg+xml",
                content=b"<svg></svg>",
            )

    async def test_rejects_empty_file(self) -> None:
        service, _repository, _storage, _audit = make_service()
        with pytest.raises(InvalidLogoError):
            await service.upload_logo(
                uuid.uuid4(),
                filename="empty.png",
                content_type="image/png",
                content=b"",
            )

    async def test_rejects_oversized_file(self) -> None:
        service, _repository, _storage, _audit = make_service()
        oversized = b"0" * (LOGO_MAX_BYTES + 1)
        with pytest.raises(InvalidLogoError):
            await service.upload_logo(
                uuid.uuid4(),
                filename="huge.png",
                content_type="image/png",
                content=oversized,
            )

    async def test_raises_when_storage_not_configured(self) -> None:
        service, _repository, _storage, _audit = make_service(with_storage=False)
        with pytest.raises(BrandingStorageNotConfiguredError):
            await service.upload_logo(
                uuid.uuid4(),
                filename="logo.png",
                content_type="image/png",
                content=PNG_BYTES,
            )


class TestDeleteLogo:
    async def test_delete_clears_key_and_falls_back_to_plain_url(self) -> None:
        service, repository, _storage, audit_writer = make_service()
        org_id = uuid.uuid4()
        repository._by_org[org_id] = Branding(
            id=uuid.uuid4(),
            organization_id=org_id,
            logo_url="https://example.com/fallback-logo.png",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        await service.upload_logo(
            org_id, filename="logo.png", content_type="image/png", content=PNG_BYTES
        )
        assert repository._by_org[org_id].logo_key is not None

        result = await service.delete_logo(org_id)

        assert repository._by_org[org_id].logo_key is None
        # Deleting the *uploaded* logo reveals the plain-text URL again,
        # exactly the same "clear only this layer" semantics
        # set_background_image_key/set_logo_key both implement.
        assert result.logo_url == "https://example.com/fallback-logo.png"
        assert result.logo_is_uploaded is False
        assert any(
            e["action"] == "branding_logo_removed" for e in audit_writer.entries
        )

    async def test_raises_when_storage_not_configured(self) -> None:
        service, _repository, _storage, _audit = make_service(with_storage=False)
        with pytest.raises(BrandingStorageNotConfiguredError):
            await service.delete_logo(uuid.uuid4())


class TestGetLogoBytes:
    async def test_returns_bytes_and_content_type_for_uploaded_logo(self) -> None:
        service, _repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()
        await service.upload_logo(
            org_id, filename="logo.jpg", content_type="image/jpeg", content=PNG_BYTES
        )

        content, content_type = await service.get_logo_bytes(org_id)

        assert content == PNG_BYTES
        assert content_type == "image/jpeg"

    async def test_raises_not_found_when_no_logo_uploaded(self) -> None:
        service, _repository, _storage, _audit = make_service()
        with pytest.raises(LogoNotFoundError):
            await service.get_logo_bytes(uuid.uuid4())

    async def test_raises_not_found_when_only_plain_text_url_set(self) -> None:
        # A manually-typed logo_url with no upload doesn't count -- that's
        # rendered by hotlinking the URL directly, never through this
        # authenticated proxy.
        service, repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()
        repository._by_org[org_id] = Branding(
            id=uuid.uuid4(),
            organization_id=org_id,
            logo_url="https://example.com/logo.png",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        with pytest.raises(LogoNotFoundError):
            await service.get_logo_bytes(org_id)

    async def test_raises_when_storage_not_configured(self) -> None:
        service, _repository, _storage, _audit = make_service(with_storage=False)
        with pytest.raises(BrandingStorageNotConfiguredError):
            await service.get_logo_bytes(uuid.uuid4())


# ============================================================================
# GET /branding response_model regression: this endpoint can genuinely
# return either shape (see router.py's own comment on this), so the
# declared response_model must accept both -- this is exactly the
# validation FastAPI itself runs on every response, exercised directly
# here rather than through a full HTTP round trip.
# ============================================================================


class TestGetBrandingResponseModelAcceptsBothShapes:
    def test_accepts_default_branding_with_no_organization_row(self) -> None:
        envelope = ApiResponse[BrandingResponse | DefaultBrandingResponse](
            success=True,
            message="Branding retrieved",
            data=DEFAULT_BRANDING.model_dump(mode="json"),
            request_id="req-1",
        )
        assert isinstance(envelope.data, DefaultBrandingResponse)

    async def test_accepts_real_organization_branding(self) -> None:
        service, _repository, _storage, _audit = make_service()
        result = await service.upload_background_image(
            uuid.uuid4(), filename="bg.png", content_type="image/png", content=PNG_BYTES
        )
        envelope = ApiResponse[BrandingResponse | DefaultBrandingResponse](
            success=True,
            message="Branding retrieved",
            data=result.model_dump(mode="json"),
            request_id="req-2",
        )
        assert isinstance(envelope.data, BrandingResponse)
        assert envelope.data.background_image_url == result.background_image_url


# ============================================================================
# Structural RBAC check
# ============================================================================


_PUBLIC_BRANDING_ROUTES = {
    "/branding/default",
    "/branding/{organization_id}/logo/public",
    "/branding/{organization_id}/background-image/public",
}


class TestEveryRouteRequiresPermission:
    def test_every_branding_route_has_a_permission_dependency_or_is_public(
        self,
    ) -> None:
        # See tests/unit/test_route_permission_coverage.py's own allowlist
        # entries for these exact three routes -- each documents its own
        # "no platform identity exists at this point" reason there.
        for route in branding_router.routes:
            if getattr(route, "path", "") in _PUBLIC_BRANDING_ROUTES:
                continue
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
