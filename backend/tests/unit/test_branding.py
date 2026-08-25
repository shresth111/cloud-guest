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

import hashlib
import inspect
import io
import random
import uuid
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from PIL import Image
from starlette.requests import Request

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
from app.domains.branding.router import _asset_response
from app.domains.branding.router import router as branding_router
from app.domains.branding.schemas import BrandingResponse, DefaultBrandingResponse
from app.domains.branding.service import (
    _BACKGROUND_MAX_PROCESS_DIM,
    _BACKGROUND_MAX_PROCESS_PIXELS,
    _BACKGROUND_TARGET_LONG_EDGE,
    _EXTENSION_TO_CONTENT_TYPE,
    BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES,
    BACKGROUND_IMAGE_MAX_BYTES,
    BACKGROUND_IMAGE_MIN_LONG_EDGE,
    BACKGROUND_IMAGE_RAW_PATH,
    DEFAULT_BRANDING,
    LOGO_MAX_BYTES,
    LOGO_RAW_PATH,
    BrandingService,
    _process_background_image,
    _process_logo,
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
        luminance: int | None = None,
        top_luminance: int | None = None,
        entropy: int | None = None,
        actor_user_id: uuid.UUID | None = None,
    ) -> Branding:
        existing = self._by_org.get(organization_id)
        if existing:
            existing.background_image_key = key
            existing.background_luminance = luminance
            existing.background_top_luminance = top_luminance
            existing.background_entropy = entropy
            existing.updated_by = actor_user_id
            return existing
        branding = Branding(
            id=uuid.uuid4(),
            organization_id=organization_id,
            background_image_key=key,
            background_luminance=luminance,
            background_top_luminance=top_luminance,
            background_entropy=entropy,
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


# ============================================================================
# Image-serving cache headers (_asset_response) -- see that helper's own
# docstring: get_logo_public/get_background_image_public are exactly what a
# guest's browser fetches on every WiFi join via GET /captive-portal/resolve,
# and previously shipped with zero cache headers at all.
# ============================================================================


def _make_request(*, if_none_match: str | None = None) -> Request:
    headers = (
        [] if if_none_match is None else [(b"if-none-match", if_none_match.encode())]
    )
    return Request(
        {"type": "http", "method": "GET", "path": "/branding/x", "headers": headers}
    )


class TestAssetResponseCacheHeaders:
    def test_sets_etag_and_cache_control(self) -> None:
        response = _asset_response(
            _make_request(),
            content=b"fake-image-bytes",
            content_type="image/png",
            visibility="public",
        )
        assert response.status_code == 200
        assert response.body == b"fake-image-bytes"
        etag = response.headers["etag"]
        assert etag == f'"{hashlib.sha256(b"fake-image-bytes").hexdigest()}"'
        cache_control = response.headers["cache-control"]
        assert "public" in cache_control
        assert "max-age=" in cache_control
        assert "must-revalidate" in cache_control

    def test_private_visibility_for_authenticated_endpoints(self) -> None:
        response = _asset_response(
            _make_request(),
            content=b"fake-image-bytes",
            content_type="image/png",
            visibility="private",
        )
        assert "private" in response.headers["cache-control"]
        assert "public" not in response.headers["cache-control"]

    def test_matching_if_none_match_returns_304_with_no_body(self) -> None:
        content = b"fake-image-bytes"
        etag = f'"{hashlib.sha256(content).hexdigest()}"'
        response = _asset_response(
            _make_request(if_none_match=etag),
            content=content,
            content_type="image/png",
            visibility="public",
        )
        assert response.status_code == 304
        assert response.body == b""
        # A 304 still needs to carry the cache directives so the client
        # refreshes its cache entry's freshness lifetime, not just its
        # validator.
        assert response.headers["etag"] == etag
        assert "cache-control" in response.headers

    def test_mismatched_if_none_match_returns_full_body(self) -> None:
        response = _asset_response(
            _make_request(if_none_match='"some-other-etag"'),
            content=b"fake-image-bytes",
            content_type="image/png",
            visibility="public",
        )
        assert response.status_code == 200
        assert response.body == b"fake-image-bytes"

    def test_changed_content_changes_etag(self) -> None:
        """Content-addressed correctness: a re-upload writes new bytes
        under a fresh object-storage key (BrandingService's own upload_*
        methods), but the URL a browser has cached never changes -- the
        ETag must actually reflect *these* bytes on every real request, or
        a stale cached image could otherwise look validated forever."""
        etag_v1 = _asset_response(
            _make_request(),
            content=b"version-1",
            content_type="image/png",
            visibility="public",
        ).headers["etag"]
        etag_v2 = _asset_response(
            _make_request(),
            content=b"version-2",
            content_type="image/png",
            visibility="public",
        ).headers["etag"]
        assert etag_v1 != etag_v2

    def test_wildcard_if_none_match_matches(self) -> None:
        response = _asset_response(
            _make_request(if_none_match="*"),
            content=b"fake-image-bytes",
            content_type="image/png",
            visibility="public",
        )
        # RFC 7232: "*" matches any current representation -- not handled
        # specially here (only exact-etag matching is implemented), so this
        # documents the actual, narrower behavior rather than asserting an
        # unimplemented spec nicety.
        assert response.status_code == 200


# ============================================================================
# Background image pipeline -- captive-portal v7 design spec, Part 4
#
# Note the deliberate difference from every test above this line:
# ``PNG_BYTES`` is a PNG magic header followed by 100 ASCII zeros, which
# Pillow cannot decode. That is *why* the tests above still pass
# unchanged after v7 -- every one of them takes ``_process_background_
# image``'s graceful "return None, store the original unchanged" path,
# so their ``.png``/``.jpg`` key assertions still hold. It also means
# not one of them exercises the pipeline. Everything below builds a real
# image with ``Image.new(...)``.
# ============================================================================


def _png(size: tuple[int, int], color: tuple[int, int, int] = (120, 130, 140)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="PNG")
    return buf.getvalue()


def _two_tone_png(
    size: tuple[int, int],
    top: tuple[int, int, int],
    bottom: tuple[int, int, int],
) -> bytes:
    """A image whose top band differs from the rest -- the only way to
    tell ``background_top_luminance`` apart from ``background_luminance``
    and prove it really measures the headline zone."""
    img = Image.new("RGB", size, bottom)
    img.paste(top, (0, 0, size[0], size[1] // 3))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _animated_gif(size: tuple[int, int]) -> bytes:
    first = Image.new("RGB", size, (220, 20, 20))
    second = Image.new("RGB", size, (20, 20, 220))
    buf = io.BytesIO()
    first.save(buf, format="GIF", save_all=True, append_images=[second], duration=100)
    return buf.getvalue()


def _decoded(content: bytes) -> Image.Image:
    return Image.open(io.BytesIO(content))


class TestProcessBackgroundImage:
    def test_returns_webp_bytes_content_type_and_extension(self) -> None:
        result = _process_background_image(_png((1600, 1200)))

        assert result is not None
        content, content_type, extension, metrics = result
        assert content_type == "image/webp"
        assert extension == "webp"
        assert _decoded(content).format == "WEBP"
        # Part 4's whole economic argument: a correctly-sized WebP is a
        # fraction of what a camera upload weighs.
        assert len(content) < len(_png((1600, 1200)))
        assert 0 <= metrics.luminance <= 100

    def test_serving_map_already_knows_webp(self) -> None:
        """Part 4's "WebP is safe" claim, asserted rather than assumed:
        the serving path resolves content type from the stored key's
        extension, so a ``.webp`` key must already map without any
        change to that path."""
        assert _EXTENSION_TO_CONTENT_TYPE["webp"] == "image/webp"

    def test_exif_orientation_is_applied(self) -> None:
        """The single most consequential line in the pipeline. Browsers
        auto-rotate a JPEG by its EXIF Orientation tag, Pillow does not,
        and re-encoding to WebP drops the tag -- so without
        ``ImageOps.exif_transpose`` every portrait phone photo would
        ship sideways the day v7 deploys. Here: a 1600x900 *landscape*
        JPEG carrying Orientation=6 ("rotate 90 CW"), which a browser
        renders as 900x1600 portrait."""
        img = Image.new("RGB", (1600, 900), (200, 60, 60))
        exif = img.getexif()
        exif[274] = 6
        buf = io.BytesIO()
        img.save(buf, format="JPEG", exif=exif)

        result = _process_background_image(buf.getvalue())

        assert result is not None
        out = _decoded(result[0])
        # Rotated, i.e. portrait -- not the 1600x900 Pillow would have
        # produced had the tag been ignored.
        assert out.size == (900, 1600)

    def test_exif_free_image_is_unrotated(self) -> None:
        result = _process_background_image(_png((1600, 900)))
        assert result is not None
        assert _decoded(result[0]).size == (1600, 900)

    def test_downscales_to_the_target_long_edge(self) -> None:
        result = _process_background_image(_png((4000, 3000)))

        assert result is not None
        out = _decoded(result[0])
        assert max(out.size) == _BACKGROUND_TARGET_LONG_EDGE
        # Aspect ratio preserved.
        assert out.size == (2560, 1920)

    def test_does_not_upscale_a_smaller_image(self) -> None:
        """Only ever downscales. Upscaling here would manufacture bytes
        and detail that were never in the file -- the exact thing CSS
        `cover` already does badly and that Part 4 exists to stop."""
        result = _process_background_image(_png((1400, 1050)))
        assert result is not None
        assert _decoded(result[0]).size == (1400, 1050)

    def test_animated_gif_flattens_to_frame_zero(self) -> None:
        """Correct for a background -- nobody wants a loop behind a
        sign-in form -- and frame 0 specifically, not some other frame."""
        result = _process_background_image(_animated_gif((1600, 1200)))

        assert result is not None
        out = _decoded(result[0]).convert("RGB")
        assert getattr(out, "n_frames", 1) == 1
        r, g, b = out.resize((1, 1)).getpixel((0, 0))
        # Frame 0 is red, frame 1 is blue.
        assert r > b, f"flattened to the wrong frame: {(r, g, b)}"

    def test_gif_is_still_an_accepted_upload_type(self) -> None:
        """Part 4's first trap. Removing ``image/gif`` from the ingress
        allowlist used to also remove ``gif`` from the *derived* serving
        map, and every already-stored ``.gif`` key would begin serving as
        ``application/octet-stream`` -- which a browser will not paint as
        a background-image. The two dicts are now independent (see
        ``_EXTENSION_TO_CONTENT_TYPE``'s comment); this asserts the
        second half of that, so a future ingress restriction cannot take
        the serving map with it."""
        assert "image/gif" in BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES
        assert _EXTENSION_TO_CONTENT_TYPE["gif"] == "image/gif"

    def test_every_ingress_extension_is_servable(self) -> None:
        for extension in BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES.values():
            assert extension in _EXTENSION_TO_CONTENT_TYPE

    def test_undecodable_bytes_return_none(self) -> None:
        """The graceful fallback the whole contract rests on -- the
        caller stores the original unchanged rather than failing the
        upload."""
        assert _process_background_image(PNG_BYTES) is None
        assert _process_background_image(b"not an image at all") is None

    def test_decompression_bomb_returns_none(self) -> None:
        """``Image.DecompressionBombError`` subclasses bare ``Exception``,
        so it is caught by none of UnidentifiedImageError / OSError /
        SyntaxError / ValueError, and Pillow raises it from inside
        ``load()`` -- before any size guard in this module can run.
        Simulated by lowering Pillow's own threshold rather than
        allocating a real 400-megapixel image."""
        content = _png((1600, 1200))
        original = Image.MAX_IMAGE_PIXELS
        try:
            Image.MAX_IMAGE_PIXELS = 10
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                assert _process_background_image(content) is None
        finally:
            Image.MAX_IMAGE_PIXELS = original

    def test_rejects_an_image_past_the_per_edge_ceiling(self) -> None:
        # 20000 x 4 is only 80k pixels -- it passes any total-pixel test
        # but is absurd on one edge.
        assert _process_background_image(_png((20000, 4))) is None

    def test_total_pixel_guard_catches_what_a_per_edge_guard_misses(self) -> None:
        """A 1 x 200000000 aspect passes a per-edge check while decoding
        to 200 megapixels, which is why both guards exist. Asserted
        against the constants rather than by building such a file, since
        constructing it would itself allocate the memory the guard is
        there to prevent."""
        assert (
            _BACKGROUND_MAX_PROCESS_DIM * _BACKGROUND_MAX_PROCESS_DIM
            > _BACKGROUND_MAX_PROCESS_PIXELS
        ), "the total-pixel guard must be reachable, not dead code"
        assert _BACKGROUND_MAX_PROCESS_DIM > 4096, (
            "must sit far above the logo ceiling -- a 24MP phone photo is "
            "6000x4000, and a 4096 ceiling would make the fallback fire on "
            "exactly the uploads that most need downscaling"
        )

    def test_flattens_transparency_rather_than_carrying_alpha(self) -> None:
        img = Image.new("RGBA", (1600, 1200), (255, 0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="PNG")

        result = _process_background_image(buf.getvalue())

        assert result is not None
        out = _decoded(result[0]).convert("RGB")
        r, g, b = out.resize((1, 1)).getpixel((0, 0))
        # Fully transparent red composited onto white -- white, and
        # specifically *not* red.
        assert r > 180 and g > 180 and b > 180, (r, g, b)


class TestBackgroundImageMetrics:
    def test_dark_and_bright_images_measure_apart(self) -> None:
        dark = _process_background_image(_png((1600, 1200), (10, 10, 10)))
        bright = _process_background_image(_png((1600, 1200), (245, 245, 245)))

        assert dark is not None and bright is not None
        assert dark[3].luminance < 15
        assert bright[3].luminance > 85

    def test_top_luminance_measures_the_top_band_not_the_whole_image(self) -> None:
        """The distinction C3 actually needs: an image can be dark
        overall while the band the headline sits over is blown-out sky."""
        result = _process_background_image(
            _two_tone_png((1600, 1200), top=(250, 250, 250), bottom=(15, 15, 15))
        )

        assert result is not None
        metrics = result[3]
        assert metrics.top_luminance > 85
        assert metrics.luminance < 60
        assert metrics.top_luminance > metrics.luminance

    def test_flat_image_is_low_entropy_and_noise_is_high(self) -> None:
        """C5's "busyness" measure. A flat colour has a one-bucket
        histogram; random noise fills every bucket."""
        flat = _process_background_image(_png((1600, 1200), (128, 128, 128)))

        noise = Image.frombytes(
            "RGB",
            (1600, 1200),
            bytes(random.randbytes(1600 * 1200 * 3)),
        )
        buf = io.BytesIO()
        noise.save(buf, format="PNG")
        busy = _process_background_image(buf.getvalue())

        assert flat is not None and busy is not None
        assert flat[3].entropy < 10
        assert busy[3].entropy > flat[3].entropy

    def test_all_metrics_are_ints_in_range(self) -> None:
        result = _process_background_image(
            _two_tone_png((1600, 1200), (200, 0, 0), (0, 0, 90))
        )
        assert result is not None
        metrics = result[3]
        for value in (metrics.luminance, metrics.top_luminance, metrics.entropy):
            assert isinstance(value, int)
            assert 0 <= value <= 100


class TestUploadBackgroundImageThroughThePipeline:
    async def test_real_image_is_stored_as_webp_with_metrics(self) -> None:
        service, repository, storage, _audit = make_service()
        org_id = uuid.uuid4()

        result = await service.upload_background_image(
            org_id,
            filename="lobby.png",
            content_type="image/png",
            content=_png((1600, 1200), (30, 40, 50)),
        )

        stored = repository._by_org[org_id]
        assert stored.background_image_key.endswith(".webp")
        assert _decoded(storage.uploaded[stored.background_image_key]).format == "WEBP"
        assert stored.background_luminance is not None
        assert stored.background_top_luminance is not None
        assert stored.background_entropy is not None
        # And they come back out on the read model the dashboard uses.
        assert result.background_luminance == stored.background_luminance
        assert result.background_entropy == stored.background_entropy

    async def test_jpeg_upload_is_normalized_to_webp(self) -> None:
        service, repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()
        buf = io.BytesIO()
        Image.new("RGB", (2000, 1500), (90, 100, 110)).save(buf, format="JPEG")

        await service.upload_background_image(
            org_id, filename="a.jpg", content_type="image/jpeg", content=buf.getvalue()
        )

        assert repository._by_org[org_id].background_image_key.endswith(".webp")

    async def test_unprocessable_upload_still_stores_the_original_unchanged(
        self,
    ) -> None:
        """The contract ``_process_logo`` established and this function
        mirrors: an image we cannot process is stored as-is, not
        rejected. Metrics stay ``None`` -- "not measured", which the
        frontend must be able to tell apart from "measured 0"."""
        service, repository, storage, _audit = make_service()
        org_id = uuid.uuid4()

        await service.upload_background_image(
            org_id, filename="bg.png", content_type="image/png", content=PNG_BYTES
        )

        stored = repository._by_org[org_id]
        assert stored.background_image_key.endswith(".png")
        assert storage.uploaded[stored.background_image_key] == PNG_BYTES
        assert stored.background_luminance is None
        assert stored.background_top_luminance is None
        assert stored.background_entropy is None

    async def test_rejects_an_image_below_the_resolution_floor(self) -> None:
        """Part 4 item 8: below ~1200px on the long edge, `cover` on a
        phone is upscaling by 2x or more and no processing recovers the
        detail. Refused with a reason, never silently accepted."""
        service, _repository, _storage, _audit = make_service()

        with pytest.raises(InvalidBackgroundImageError) as exc:
            await service.upload_background_image(
                uuid.uuid4(),
                filename="tiny.png",
                content_type="image/png",
                content=_png((800, 600)),
            )
        assert str(BACKGROUND_IMAGE_MIN_LONG_EDGE) in str(exc.value)

    async def test_accepts_exactly_the_resolution_floor(self) -> None:
        service, repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()
        await service.upload_background_image(
            org_id,
            filename="ok.png",
            content_type="image/png",
            content=_png((BACKGROUND_IMAGE_MIN_LONG_EDGE, 700)),
        )
        assert repository._by_org[org_id].background_image_key.endswith(".webp")

    async def test_undecodable_upload_skips_the_resolution_floor(self) -> None:
        """Refusing a file for being too small when we could not measure
        it at all would be worse than storing it -- and would break every
        pre-v7 test that uploads undecodable bytes."""
        service, repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()
        await service.upload_background_image(
            org_id, filename="bg.png", content_type="image/png", content=PNG_BYTES
        )
        assert repository._by_org[org_id].background_image_key is not None

    async def test_size_cap_still_applies_to_ingress_bytes(self) -> None:
        """The 5 MiB cap must be checked *before* processing. Checking it
        after would let a 40 MB upload through on the grounds that it
        compresses well -- having already paid the bandwidth, the decode
        and the memory."""
        service, _repository, _storage, _audit = make_service()
        oversized = _png((3000, 2000)) + b"\x00" * BACKGROUND_IMAGE_MAX_BYTES

        with pytest.raises(InvalidBackgroundImageError) as exc:
            await service.upload_background_image(
                uuid.uuid4(),
                filename="huge.png",
                content_type="image/png",
                content=oversized,
            )
        assert "limit" in str(exc.value)

    async def test_delete_clears_the_metrics_too(self) -> None:
        service, repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()
        await service.upload_background_image(
            org_id,
            filename="bg.png",
            content_type="image/png",
            content=_png((1600, 1200)),
        )
        assert repository._by_org[org_id].background_luminance is not None

        await service.delete_background_image(org_id)

        stored = repository._by_org[org_id]
        assert stored.background_image_key is None
        assert stored.background_luminance is None
        assert stored.background_top_luminance is None
        assert stored.background_entropy is None

    async def test_stored_webp_serves_with_the_right_content_type(self) -> None:
        """End to end: the pipeline writes a ``.webp`` key and the read
        path resolves its content type from that extension, with no
        change to the serving path at all."""
        service, _repository, _storage, _audit = make_service()
        org_id = uuid.uuid4()
        await service.upload_background_image(
            org_id,
            filename="bg.png",
            content_type="image/png",
            content=_png((1600, 1200)),
        )

        content, content_type = await service.get_background_image_bytes(org_id)

        assert content_type == "image/webp"
        assert _decoded(content).format == "WEBP"


# ============================================================================
# _process_logo -- the DecompressionBombError fix
#
# A live 500 today, independent of v7: the class subclasses bare
# ``Exception`` so none of the enumerated handlers catch it, and Pillow
# raises it from ``load()`` -- which runs *before* the
# ``_LOGO_MAX_PROCESS_DIM`` guard. A ~20000x20000 mostly-flat PNG (what
# "export at maximum size" produces) compresses to well under the 5 MiB
# ingress cap and crashes the logo upload.
# ============================================================================


class TestProcessLogoDecompressionBomb:
    def test_process_logo_returns_none_instead_of_raising(self) -> None:
        content = _png((400, 400))
        original = Image.MAX_IMAGE_PIXELS
        try:
            Image.MAX_IMAGE_PIXELS = 10
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                assert _process_logo(content) is None
        finally:
            Image.MAX_IMAGE_PIXELS = original

    async def test_upload_logo_falls_back_instead_of_500ing(self) -> None:
        service, repository, storage, _audit = make_service()
        org_id = uuid.uuid4()
        content = _png((400, 400))

        original = Image.MAX_IMAGE_PIXELS
        try:
            Image.MAX_IMAGE_PIXELS = 10
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                await service.upload_logo(
                    org_id,
                    filename="logo.png",
                    content_type="image/png",
                    content=content,
                )
        finally:
            Image.MAX_IMAGE_PIXELS = original

        # The original bytes, stored unchanged -- the documented
        # fallback, not an exception.
        key = repository._by_org[org_id].logo_key
        assert key is not None
        assert storage.uploaded[key] == content

    def test_the_enumerated_except_list_was_not_widened_to_bare_exception(
        self,
    ) -> None:
        """The list is deliberate and auditable: every entry names a
        real, reproduced failure. Catching bare ``Exception`` would make
        the next genuine bug in this function invisible."""
        for fn in (_process_logo, _process_background_image):
            # Comments stripped first -- both functions *discuss* why
            # they are not `except Exception`, and matching that prose
            # would make this assertion pass for the wrong reason.
            code = "\n".join(
                line
                for line in inspect.getsource(fn).splitlines()
                if not line.lstrip().startswith("#")
            )
            assert "except Exception" not in code
            assert "DecompressionBombError" in code
