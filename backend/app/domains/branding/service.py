"""Branding business logic: get/update per-organization branding, with
default fallback."""

from __future__ import annotations

import asyncio
import io
import logging
import uuid
from dataclasses import dataclass
from typing import Protocol

from PIL import (
    Image,
    ImageDraw,
    ImageFilter,
    ImageOps,
    ImageStat,
    UnidentifiedImageError,
)

from app.core.storage import ObjectStorageError, ObjectStorageProtocol

from .exceptions import (
    BackgroundImageNotFoundError,
    BrandingStorageNotConfiguredError,
    InvalidBackgroundImageError,
    InvalidLogoError,
    LogoNotFoundError,
)
from .models import Branding
from .repository import BrandingRepositoryProtocol
from .schemas import BrandingResponse, BrandingUpdateRequest, DefaultBrandingResponse

logger = logging.getLogger(__name__)

DEFAULT_BRANDING = DefaultBrandingResponse()

# Background image upload constraints for the customer dashboard's
# Background Image page (login-screen background). This is the *ingress*
# allowlist only -- what a dashboard user is allowed to hand us. What
# actually gets stored is decided by ``_process_background_image``
# (captive-portal v7 design spec Part 4), which normalizes every
# successful upload to WebP regardless of what came in; the extension
# mapped here only survives on the graceful fallback path where
# processing returned ``None`` and the original bytes are stored
# unchanged.
BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES: dict[str, str] = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "image/gif": "gif",
}
BACKGROUND_IMAGE_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB

# The path BrandingResponse.background_image_url points browsers at --
# proxied through this API (see get_background_image_bytes / the router's
# GET /branding/background-image/raw) rather than a direct object-storage
# link. A presigned MinIO/S3 URL would need that storage endpoint itself
# reachable from the browser, which on this platform's actual single-VM
# deployment it deliberately isn't (only the API's own port is opened) --
# real AWS S3 in another deployment would make a direct link *possible*,
# but routing every deployment through the already-authenticated,
# already-public API is simpler than conditioning behavior on which one
# this happens to be.
BACKGROUND_IMAGE_RAW_PATH = "/branding/background-image/raw"

# The *serving* map: stored-key extension -> Content-Type, for
# get_background_image_bytes/get_logo_bytes. Deliberately spelled out
# rather than derived (by inversion) from
# BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES, which is what it used to be.
# The two dicts answer genuinely different questions -- "what may a user
# upload *today*" versus "what extensions exist in the
# ``brandings.background_image_key``/``logo_key`` columns *already*" --
# and coupling them made the second silently shrink whenever the first
# did. Concretely: dropping ``image/gif`` from the ingress allowlist (a
# one-line change someone will eventually want, since v7's pipeline
# normalizes everything to WebP anyway) also dropped ``gif`` from *this*
# map, and every already-stored ``.gif`` key would start serving as
# ``application/octet-stream`` -- a browser refuses to paint that as a
# background-image, so the guest-facing captive portal for those
# organizations would simply lose its background with nothing in the
# logs. **This map may gain entries but must never lose one**, for as
# long as a key with that extension can still be in the database.
_EXTENSION_TO_CONTENT_TYPE: dict[str, str] = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
    "gif": "image/gif",
}

# Logo upload constraints -- same allowed types/size ceiling as the
# background image (no image-processing pipeline exists here either), a
# separate constant only so the two can diverge later without coupling.
LOGO_ALLOWED_CONTENT_TYPES: dict[str, str] = dict(
    BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES
)
LOGO_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB

# See BACKGROUND_IMAGE_RAW_PATH's own comment -- same reasoning, same
# same-API-proxy-not-direct-object-storage-link approach.
LOGO_RAW_PATH = "/branding/logo/raw"

# Unauthenticated counterparts (see GET /branding/{organization_id}/logo/public
# and .../background-image/public's own docstrings) -- what
# app.domains.captive_portal's guest-facing resolve endpoint points a
# real guest's browser at when a location's own captive_portal_configs
# row has no logo_url/background_image_url of its own set, falling back
# to the organization's branding upload. `{organization_id}` is filled in
# by the caller (there is no session to derive it from at that call site
# either).
PUBLIC_LOGO_PATH_TEMPLATE = "/branding/{organization_id}/logo/public"
PUBLIC_BACKGROUND_IMAGE_PATH_TEMPLATE = (
    "/branding/{organization_id}/background-image/public"
)


# Logos most customers export "as-is" from a design tool ship on a
# solid-color (usually white) square canvas with heavy padding -- the
# mark itself only fills a small fraction of it. Rendered at any fixed
# display size, that padding is what makes the logo look tiny even
# though the box around it is large. This makes uploads robust to that
# by hand: flood-fill the padding transparent (seeded from every border
# pixel, so only background connected to the edge is removed -- a same-
# colored shape fully enclosed *inside* the mark, e.g. a letterform's
# counter, is left alone), then crop tight to the remaining content
# with a small transparent margin re-added. Always outputs PNG (the
# whole point is real alpha), regardless of what was uploaded.
_LOGO_MAX_PROCESS_DIM = 4096
_LOGO_FLOODFILL_THRESHOLD = 24
_LOGO_MARGIN_FRACTION = 0.06


def _process_logo(content: bytes) -> tuple[bytes, str, str] | None:
    """Returns (processed_bytes, content_type, extension), or ``None`` if
    the image couldn't be safely processed (unreadable, too large, or
    already blank) -- callers should fall back to storing the original
    upload unchanged in that case rather than failing it."""
    try:
        img = Image.open(io.BytesIO(content))
        img.load()
    # Pillow's own decoders raise more than just UnidentifiedImageError/
    # OSError for a corrupt file -- confirmed live: a malformed PNG chunk
    # raises a bare SyntaxError ("broken PNG file (chunk ...)"), which
    # isn't a subclass of either and was propagating uncaught out of this
    # function, crashing the whole upload request with a 500 instead of
    # the graceful "fall back to storing the original bytes unchanged"
    # this function's own docstring already promises. ValueError covers
    # a couple of other known corrupt-data decode paths (e.g. truncated
    # palette data) for the same reason.
    #
    # Image.DecompressionBombError is the same class of bug, found later:
    # it subclasses bare ``Exception`` (not OSError/ValueError), and
    # Pillow raises it from inside ``open``/``load`` as soon as
    # width*height exceeds 2x ``Image.MAX_IMAGE_PIXELS`` (~89.5 MP by
    # default). The ``_LOGO_MAX_PROCESS_DIM`` guard below cannot save us
    # -- it runs *after* ``img.load()``. So a ~20000x20000 PNG, which
    # compresses to well under the 5 MiB ingress cap when it is mostly
    # flat colour (exactly what an "export at maximum size" logo is),
    # 500s the logo upload today instead of taking this function's own
    # documented "store the original unchanged" fallback. Enumerated
    # here rather than widening any of this to a bare ``except
    # Exception``: the point of the list is that every entry names a
    # real, reproduced failure, which is what makes it auditable.
    except (
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        ValueError,
        Image.DecompressionBombError,
    ):
        return None

    width, height = img.size
    if (
        width == 0
        or height == 0
        or width > _LOGO_MAX_PROCESS_DIM
        or height > _LOGO_MAX_PROCESS_DIM
    ):
        return None

    img = img.convert("RGBA")
    alpha_min, _alpha_max = img.split()[3].getextrema()
    already_has_transparency = alpha_min < 250

    if not already_has_transparency:
        for x in range(width):
            for y in (0, height - 1):
                if img.getpixel((x, y))[3] != 0:
                    ImageDraw.floodfill(
                        img, (x, y), (0, 0, 0, 0), thresh=_LOGO_FLOODFILL_THRESHOLD
                    )
        for y in range(height):
            for x in (0, width - 1):
                if img.getpixel((x, y))[3] != 0:
                    ImageDraw.floodfill(
                        img, (x, y), (0, 0, 0, 0), thresh=_LOGO_FLOODFILL_THRESHOLD
                    )

    bbox = img.getbbox()
    if bbox is None:
        return None

    cropped = img.crop(bbox)
    content_w, content_h = cropped.size
    margin = max(4, round(max(content_w, content_h) * _LOGO_MARGIN_FRACTION))
    canvas = Image.new(
        "RGBA", (content_w + margin * 2, content_h + margin * 2), (0, 0, 0, 0)
    )
    canvas.paste(cropped, (margin, margin), cropped)

    buf = io.BytesIO()
    canvas.save(buf, format="PNG", optimize=True)
    return buf.getvalue(), "image/png", "png"


# ============================================================================
# Background image pipeline (captive-portal v7 design spec, Part 4)
# ============================================================================
#
# Before v7 there was no image processing for backgrounds at all: content
# type and a 5 MiB cap were validated and the raw bytes were stored and
# served. That is why venue photos look soft on a phone -- a
# heavily-compressed upload gets *upscaled* by CSS `cover` to fill the
# viewport -- and why a 1-5 MB gallery photo is downloaded in full over
# the venue's own uplink when a correctly-sized WebP for a 1170x2532
# screen is 80-150 KB (spec §5 S4: 10-40x overhead).
#
# Ceiling for a single edge. Deliberately far above the logo's 4096: a
# 24 MP phone photo is 6000x4000, and reusing 4096 would make the
# graceful fallback fire on exactly the uploads that most need
# downscaling -- the fallback stores the original bytes, so the "too big
# to process" branch would ship the *largest* files through untouched.
_BACKGROUND_MAX_PROCESS_DIM = 12000
# ...and a total-pixel ceiling, because a per-edge check alone is not a
# memory bound: 1 x 200000000 passes any per-edge test you care to write
# while decoding to 200 M pixels. 80 MP sits deliberately *below*
# Pillow's own default ``Image.MAX_IMAGE_PIXELS`` (~89.5 MP) so this
# guard is what normally answers, with DecompressionBombError as the
# backstop for anything that trips Pillow first.
_BACKGROUND_MAX_PROCESS_PIXELS = 80_000_000
# Long edge of what we actually store. 2560 covers a 1440p desktop
# viewport and is ~2x the longest phone edge in real use, so `cover`
# never upscales.
_BACKGROUND_TARGET_LONG_EDGE = 2560
# Blur radius as a fraction of the long edge, so a 6000px upload and a
# 2560px upload come out looking the *same* rather than the 6000px one
# looking sharper after the downscale. 0.0094 * 2560 ~= 24px, the middle
# of the spec's "~20-28px equivalent" (§1.4 C2). Blur runs before the
# downscale (spec order) -- that is also the higher-quality order, since
# LANCZOS then resamples an already band-limited image.
_BACKGROUND_BLUR_FRACTION = 0.0094
_BACKGROUND_BLUR_MIN_RADIUS = 12.0
_BACKGROUND_BLUR_MAX_RADIUS = 64.0
# Baked-in neutral tint, composited under the frontend's own scrim.
#
# The spec (§1.4 C2) asks for "a base tint at alpha >= 0.45". Implemented
# deliberately lower, and this is the one place this module knowingly
# departs from the letter of Part 4 -- three reasons, all of them from
# the spec's own text:
#   * It double-counts. The frontend already ships a scrim whose peak
#     opacity is `background_overlay_strength`, default 55 (PR #36).
#     0.45 baked in *under* 0.55 composites to 1-(0.55*0.45) = 0.75
#     effective darkening at the text zones. §1.3's own derivation puts
#     the AA floor for white body text over *any* image at 0.535, so
#     0.75 buys no compliance at all.
#   * §0.1 item 1 records what that looks like shipped: PR #81's single
#     heavy wash "reduced a real venue's photo to a ghost" and was
#     reverted by #82. Baking it into the stored bytes makes that
#     version irreversible -- there is no revert, only a re-upload.
#   * It contradicts C3. C3 wants the scrim's *polarity* chosen at
#     render time from `background_luminance` (light scrim over a dark
#     photo, dark scrim over a light one). A dark tint burned in at
#     upload removes that choice permanently, and skews the very
#     luminance value C3 reads.
# What the tint is genuinely for is unifying an image so the blur reads
# as a deliberate surface rather than a smeared photo. 0.18 does that
# and leaves the photo recognisably the venue's. Safety comes from the
# §1.3 floor at render time, which this does not and should not replace.
_BACKGROUND_TINT_ALPHA = 0.18
_BACKGROUND_TINT_RGB = (17, 24, 39)
# WebP quality. ~82 is the standard "visually lossless for photographic
# content" point, and the image is pre-blurred by the time it is encoded,
# so there is very little high-frequency detail left for a higher
# quality to preserve.
_BACKGROUND_WEBP_QUALITY = 82
# Fraction of the image height treated as "the top band" for
# ``background_top_luminance`` -- the zone the portal's headline sits
# over (spec §1.4 C3).
_BACKGROUND_TOP_BAND_FRACTION = 0.35
# Metrics are computed on a bounded working copy rather than the full
# decode, so their cost is O(1) in upload size. A mean is invariant
# under area-averaging resize, and entropy measured here is entropy at
# roughly display scale, which is the scale C5's "busyness" question is
# actually about.
_BACKGROUND_METRICS_SAMPLE_EDGE = 512
# Shannon entropy of an 8-bit histogram maxes out at 8 bits; scaled to
# the same 0-100 range as the luminances so all three metrics read
# alike.
_MAX_HISTOGRAM_ENTROPY_BITS = 8.0

# Hard resolution floor for an *accepted* upload (spec Part 4 item 8).
# Below this, `cover` on a 1170x2532 phone is upscaling by 2x or more
# and no amount of processing recovers the detail -- the founder's
# "photos look soft" complaint in physical form. Rejected loudly with a
# reason the dashboard renders, never silently accepted-and-degraded.
BACKGROUND_IMAGE_MIN_LONG_EDGE = 1200


@dataclass(frozen=True, slots=True)
class BackgroundImageMetrics:
    """What ``_process_background_image`` measured about the image, for
    the frontend's scrim decisions (v7 spec §1.4 C3 and C5).

    All three are integers on a 0-100 scale, and all three describe the
    **source** image as uploaded (post-EXIF-rotation, pre-blur,
    pre-tint), per Part 4's own step ordering. That is the useful
    definition: it stays correct if the blur radius or the tint constant
    is ever retuned, whereas a measurement of the final bytes would
    silently become wrong on the day someone changes
    ``_BACKGROUND_TINT_ALPHA`` and would need a full backfill to fix.

    ``luminance``/``top_luminance`` are ITU-R BT.601 luma
    (``Image.convert("L")``), **not** WCAG relative luminance -- no
    sRGB linearization. That is deliberate and safe: these values only
    ever choose scrim *polarity* and let a already-dark photo use *less*
    scrim than the floor. Nothing about AA compliance rests on them
    (§1.3 consequence 2: "image analysis is not required for compliance
    -- only for beauty"), so a monotonic, cheap approximation is the
    right tool and pretending to WCAG precision here would be the
    misleading choice.
    """

    luminance: int
    top_luminance: int
    entropy: int


def _luminance_percent(image: Image.Image) -> int:
    if image.width == 0 or image.height == 0:
        return 0
    mean = ImageStat.Stat(image).mean[0]
    return max(0, min(100, round(mean / 255 * 100)))


def _measure_background(image: Image.Image) -> BackgroundImageMetrics:
    """Computes the three C3/C5 metrics off an already-decoded,
    already-EXIF-rotated image. Works on a bounded grayscale copy -- see
    ``_BACKGROUND_METRICS_SAMPLE_EDGE``."""
    sample = image.convert("L")
    long_edge = max(sample.size)
    if long_edge > _BACKGROUND_METRICS_SAMPLE_EDGE:
        scale = _BACKGROUND_METRICS_SAMPLE_EDGE / long_edge
        sample = sample.resize(
            (
                max(1, round(sample.width * scale)),
                max(1, round(sample.height * scale)),
            ),
            Image.Resampling.LANCZOS,
        )

    top_height = max(1, round(sample.height * _BACKGROUND_TOP_BAND_FRACTION))
    top_band = sample.crop((0, 0, sample.width, top_height))

    entropy_bits = sample.entropy()
    entropy = max(
        0, min(100, round(entropy_bits / _MAX_HISTOGRAM_ENTROPY_BITS * 100))
    )
    return BackgroundImageMetrics(
        luminance=_luminance_percent(sample),
        top_luminance=_luminance_percent(top_band),
        entropy=entropy,
    )


def _background_image_long_edge(content: bytes) -> int | None:
    """Reads just the header of ``content`` to get its long edge, without
    decoding any pixels -- so the ``BACKGROUND_IMAGE_MIN_LONG_EDGE``
    rejection is answered before the (comparatively expensive) real
    processing pass runs.

    Returns ``None`` when the header cannot be read at all. That is not
    an error here: an undecodable upload takes the same graceful
    "store the original unchanged" path ``_process_background_image``
    documents, and rejecting a file for being too small when we could
    not measure it would be worse than storing it. Same enumerated
    ``except`` list, same reasoning, as ``_process_logo``."""
    try:
        with Image.open(io.BytesIO(content)) as img:
            return max(img.size)
    except (
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        ValueError,
        Image.DecompressionBombError,
    ):
        return None


def _process_background_image(
    content: bytes,
) -> tuple[bytes, str, str, BackgroundImageMetrics] | None:
    """Returns ``(processed_bytes, content_type, extension, metrics)``, or
    ``None`` if the image couldn't be safely processed (unreadable,
    decompression bomb, or beyond the size guards) -- callers should fall
    back to storing the original upload unchanged in that case rather
    than failing it, exactly as ``_process_logo`` does.

    Mirrors ``_process_logo``'s contract with one addition: the fourth
    tuple element carries the C3/C5 measurements out, because they are
    computed from the same decode and there is no second point in the
    request where the pixels are still in hand.

    Always outputs WebP, whatever came in. Safe with **zero** changes to
    the serving path: ``_EXTENSION_TO_CONTENT_TYPE`` already maps
    ``webp``, and the URL a browser is handed
    (``BACKGROUND_IMAGE_RAW_PATH`` / the public template) carries no
    extension at all, so nothing downstream can branch on format.
    Support is Safari 14 / iOS 14 and every Android WebView.
    """
    try:
        img = Image.open(io.BytesIO(content))
        img.load()
    # Same enumerated list as _process_logo -- see its own comment for
    # why each entry is here and why this is not `except Exception` --
    # plus Image.DecompressionBombError, which matters far more on this
    # path than on the logo one: backgrounds are where real camera
    # uploads land.
    except (
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        ValueError,
        Image.DecompressionBombError,
    ):
        return None

    # An animated GIF flattens to frame 0. Correct for a background --
    # a looping animation behind a sign-in form is not what anyone
    # wants, and CSS `background-image` would animate it forever on a
    # phone -- but logged, because the venue chose an animation and is
    # getting a still, which is worth being able to explain when they
    # ask.
    if getattr(img, "n_frames", 1) > 1:
        logger.info(
            "background_image_animation_flattened",
            extra={"frames": getattr(img, "n_frames", 1), "format": img.format},
        )

    # Size guards before any pixel work. Both are needed: a per-edge
    # ceiling alone lets a 1 x 200000000 strip through, and a
    # total-pixel ceiling alone lets a 200000 x 300 strip through into
    # resize/blur paths that allocate per-row.
    width, height = img.size
    if width == 0 or height == 0:
        return None
    if width > _BACKGROUND_MAX_PROCESS_DIM or height > _BACKGROUND_MAX_PROCESS_DIM:
        return None
    if width * height > _BACKGROUND_MAX_PROCESS_PIXELS:
        return None

    # MANDATORY, and it must happen before anything reads or rewrites
    # the pixels. Browsers auto-rotate a JPEG by its EXIF Orientation
    # tag; Pillow does not, and re-encoding (to WebP, here) drops the
    # tag entirely. Without this line every portrait photo taken on a
    # phone -- which is most of what a venue owner uploads -- ships
    # sideways the day this pipeline goes live. It is a regression that
    # does not exist today *precisely* because today the bytes are
    # stored untouched and the browser still sees the tag.
    img = ImageOps.exif_transpose(img) or img

    metrics = _measure_background(img)

    # Flatten onto white rather than keeping alpha: a PNG with
    # transparency used as a full-bleed background would composite
    # against whatever the portal's canvas happens to be, which is not
    # something the venue can see or control at upload time. White
    # matches the portal's own light canvas.
    if img.mode in ("RGBA", "LA", "P"):
        rgba = img.convert("RGBA")
        flattened = Image.new("RGB", rgba.size, (255, 255, 255))
        flattened.paste(rgba, mask=rgba.split()[3])
        img = flattened
    else:
        img = img.convert("RGB")

    radius = min(
        _BACKGROUND_BLUR_MAX_RADIUS,
        max(_BACKGROUND_BLUR_MIN_RADIUS, max(img.size) * _BACKGROUND_BLUR_FRACTION),
    )
    img = img.filter(ImageFilter.GaussianBlur(radius=radius))

    if _BACKGROUND_TINT_ALPHA > 0:
        tint = Image.new("RGB", img.size, _BACKGROUND_TINT_RGB)
        img = Image.blend(img, tint, _BACKGROUND_TINT_ALPHA)

    long_edge = max(img.size)
    if long_edge > _BACKGROUND_TARGET_LONG_EDGE:
        scale = _BACKGROUND_TARGET_LONG_EDGE / long_edge
        img = img.resize(
            (max(1, round(img.width * scale)), max(1, round(img.height * scale))),
            Image.Resampling.LANCZOS,
        )

    buf = io.BytesIO()
    img.save(buf, format="WEBP", quality=_BACKGROUND_WEBP_QUALITY)
    return buf.getvalue(), "image/webp", "webp", metrics


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class PortalResolveCacheProtocol(Protocol):
    """The single method this service needs from
    ``app.domains.captive_portal.cache.CaptivePortalResolveCache`` --
    structural, so the branding domain never imports that concrete class.

    Design spec §5 S7 folds this organization's ``brandings`` row into
    the guest-facing captive-portal resolve cache. That cache is keyed
    per ``(organization_id, location_id)`` pair, so a *single* branding
    row now backs an arbitrary number of cached entries -- one per
    location that falls back to it. Without this fan-out an admin
    uploading a new logo would stay invisible to every already-cached
    location for up to a full TTL, which would be a real regression
    against the per-request, uncached fetch S7 replaces.
    """

    async def invalidate_organization(self, organization_id: uuid.UUID) -> None: ...


class BrandingService:
    def __init__(
        self,
        repository: BrandingRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        object_storage: ObjectStorageProtocol | None = None,
        portal_resolve_cache: PortalResolveCacheProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer
        self.object_storage = object_storage
        self.portal_resolve_cache = portal_resolve_cache

    async def get_branding(self, organization_id: uuid.UUID) -> BrandingResponse:
        branding = await self.repository.get_by_organization(organization_id)
        if branding is None:
            return DEFAULT_BRANDING
        return await self._to_response(branding)

    async def update_branding(
        self,
        organization_id: uuid.UUID,
        data: BrandingUpdateRequest,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> BrandingResponse:
        update_data = data.model_dump(exclude_unset=True, exclude_none=True)
        branding = await self.repository.upsert(
            organization_id, update_data, actor_user_id=actor_user_id
        )
        await self._audit(
            actor_user_id,
            "branding_updated",
            entity_type="branding",
            entity_id=branding.id,
            description=f"Branding updated for organization {organization_id}",
            organization_id=organization_id,
        )
        await self._invalidate_portal_resolve_cache(organization_id)
        return await self._to_response(branding)

    async def upload_background_image(
        self,
        organization_id: uuid.UUID,
        *,
        filename: str,
        content_type: str,
        content: bytes,
        actor_user_id: uuid.UUID | None = None,
    ) -> BrandingResponse:
        """Uploads a new login-screen background image for ``organization_id``,
        replacing any existing one, and persists the storage key.

        Reuses ``app.core.storage`` -- the same object storage
        ``app.domains.voucher``/``app.domains.analytics`` already write
        through -- rather than inventing a new storage mechanism.
        """
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError()

        extension = BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES.get(content_type)
        if extension is None:
            raise InvalidBackgroundImageError(
                f"unsupported content type '{content_type}' -- allowed: "
                f"{', '.join(sorted(BACKGROUND_IMAGE_ALLOWED_CONTENT_TYPES))}"
            )
        if not content:
            raise InvalidBackgroundImageError("uploaded file is empty")
        if len(content) > BACKGROUND_IMAGE_MAX_BYTES:
            max_mb = BACKGROUND_IMAGE_MAX_BYTES // (1024 * 1024)
            raise InvalidBackgroundImageError(f"file exceeds the {max_mb}MB limit")

        # Hard resolution floor (v7 spec Part 4 item 8), checked off the
        # header only so we reject before doing any real work. Skipped
        # when the header can't be read -- that upload takes the
        # graceful fallback below instead, and refusing a file we could
        # not even measure would be strictly worse.
        source_long_edge = await asyncio.to_thread(
            _background_image_long_edge, content
        )
        if (
            source_long_edge is not None
            and source_long_edge < BACKGROUND_IMAGE_MIN_LONG_EDGE
        ):
            raise InvalidBackgroundImageError(
                f"image is only {source_long_edge}px on its longest edge -- a "
                f"background needs at least {BACKGROUND_IMAGE_MIN_LONG_EDGE}px, "
                "otherwise it is upscaled to fill a phone screen and looks "
                "blurry"
            )

        # Deliberately *after* the 5 MiB check: that cap is on ingress
        # bytes, not on post-compression bytes. Checking it afterwards
        # would let a 40 MB upload through on the grounds that it
        # compresses to 200 KB, having already paid the bandwidth, the
        # decode and the memory.
        # Bridged through asyncio.to_thread rather than called inline:
        # the pipeline is pure CPU, and a 6000x4000 photo (an ordinary
        # 24 MP phone upload, and one that fits comfortably under the
        # 5 MiB ingress cap) measures ~1.4s of blur/resample. Inline,
        # that is 1.4s during which this worker serves nobody -- not
        # just this uploader, every concurrent request on the process.
        # Same sync-in-async bridge direction, and the same reasoning,
        # as app.core.storage's boto3 calls.
        metrics: BackgroundImageMetrics | None = None
        processed = await asyncio.to_thread(_process_background_image, content)
        if processed is not None:
            content, content_type, extension, metrics = processed
        else:
            logger.warning(
                "background_image_processing_skipped",
                extra={"organization_id": str(organization_id)},
            )

        key = f"branding/{organization_id}/background/{uuid.uuid4()}.{extension}"
        try:
            await self.object_storage.upload(
                key=key, content=content, content_type=content_type
            )
        except ObjectStorageError:
            logger.exception(
                "background_image_upload_failed",
                extra={"organization_id": str(organization_id)},
            )
            raise

        branding = await self.repository.set_background_image_key(
            organization_id,
            key,
            luminance=metrics.luminance if metrics else None,
            top_luminance=metrics.top_luminance if metrics else None,
            entropy=metrics.entropy if metrics else None,
            actor_user_id=actor_user_id,
        )
        await self._audit(
            actor_user_id,
            "branding_background_image_updated",
            entity_type="branding",
            entity_id=branding.id,
            description=(
                f"Background image updated for organization {organization_id} "
                f"(original filename: {filename})"
            ),
            organization_id=organization_id,
        )
        await self._invalidate_portal_resolve_cache(organization_id)
        return await self._to_response(branding)

    async def delete_background_image(
        self,
        organization_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> BrandingResponse:
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError()

        # Metrics describe an image that no longer exists -- cleared with
        # it, so nothing downstream can size a scrim against a deleted
        # photo.
        branding = await self.repository.set_background_image_key(
            organization_id,
            None,
            luminance=None,
            top_luminance=None,
            entropy=None,
            actor_user_id=actor_user_id,
        )
        await self._audit(
            actor_user_id,
            "branding_background_image_removed",
            entity_type="branding",
            entity_id=branding.id,
            description=f"Background image removed for organization {organization_id}",
            organization_id=organization_id,
        )
        await self._invalidate_portal_resolve_cache(organization_id)
        return await self._to_response(branding)

    async def upload_logo(
        self,
        organization_id: uuid.UUID,
        *,
        filename: str,
        content_type: str,
        content: bytes,
        actor_user_id: uuid.UUID | None = None,
    ) -> BrandingResponse:
        """Uploads a new logo for ``organization_id``, replacing any
        existing one, and persists the storage key. Mirrors
        upload_background_image exactly -- same object storage, same
        validation shape."""
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError("Logo")

        extension = LOGO_ALLOWED_CONTENT_TYPES.get(content_type)
        if extension is None:
            raise InvalidLogoError(
                f"unsupported content type '{content_type}' -- allowed: "
                f"{', '.join(sorted(LOGO_ALLOWED_CONTENT_TYPES))}"
            )
        if not content:
            raise InvalidLogoError("uploaded file is empty")
        if len(content) > LOGO_MAX_BYTES:
            max_mb = LOGO_MAX_BYTES // (1024 * 1024)
            raise InvalidLogoError(f"file exceeds the {max_mb}MB limit")

        processed = _process_logo(content)
        if processed is not None:
            content, content_type, extension = processed
        else:
            logger.warning(
                "logo_autocrop_skipped",
                extra={"organization_id": str(organization_id)},
            )

        key = f"branding/{organization_id}/logo/{uuid.uuid4()}.{extension}"
        try:
            await self.object_storage.upload(
                key=key, content=content, content_type=content_type
            )
        except ObjectStorageError:
            logger.exception(
                "logo_upload_failed",
                extra={"organization_id": str(organization_id)},
            )
            raise

        branding = await self.repository.set_logo_key(
            organization_id, key, actor_user_id=actor_user_id
        )
        await self._audit(
            actor_user_id,
            "branding_logo_updated",
            entity_type="branding",
            entity_id=branding.id,
            description=(
                f"Logo updated for organization {organization_id} "
                f"(original filename: {filename})"
            ),
            organization_id=organization_id,
        )
        await self._invalidate_portal_resolve_cache(organization_id)
        return await self._to_response(branding)

    async def delete_logo(
        self,
        organization_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> BrandingResponse:
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError("Logo")

        branding = await self.repository.set_logo_key(
            organization_id, None, actor_user_id=actor_user_id
        )
        await self._audit(
            actor_user_id,
            "branding_logo_removed",
            entity_type="branding",
            entity_id=branding.id,
            description=f"Logo removed for organization {organization_id}",
            organization_id=organization_id,
        )
        await self._invalidate_portal_resolve_cache(organization_id)
        return await self._to_response(branding)

    async def get_default_branding(self) -> DefaultBrandingResponse:
        return DEFAULT_BRANDING

    async def get_background_image_bytes(
        self, organization_id: uuid.UUID
    ) -> tuple[bytes, str]:
        """Streams the current background image's raw bytes + content
        type -- backs ``GET /branding/background-image/raw``, the proxy
        endpoint ``background_image_url`` actually points at.

        Raises ``BackgroundImageNotFoundError`` if the organization has
        no background image set, ``BrandingStorageNotConfiguredError`` if
        this service instance has no object storage backend.
        """
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError()

        branding = await self.repository.get_by_organization(organization_id)
        key = branding.background_image_key if branding else None
        if not key:
            raise BackgroundImageNotFoundError(organization_id)

        content = await self.object_storage.download(key=key)
        extension = key.rsplit(".", 1)[-1].lower() if "." in key else ""
        content_type = _EXTENSION_TO_CONTENT_TYPE.get(
            extension, "application/octet-stream"
        )
        return content, content_type

    async def get_logo_bytes(self, organization_id: uuid.UUID) -> tuple[bytes, str]:
        """Streams the current uploaded logo's raw bytes + content type --
        backs ``GET /branding/logo/raw``. Mirrors get_background_image_bytes
        exactly. Raises ``LogoNotFoundError`` if the organization has no
        *uploaded* logo (a plain-text ``logo_url`` with no ``logo_key``
        doesn't count -- that's rendered by hotlinking the URL directly,
        never through this proxy)."""
        if self.object_storage is None:
            raise BrandingStorageNotConfiguredError("Logo")

        branding = await self.repository.get_by_organization(organization_id)
        key = branding.logo_key if branding else None
        if not key:
            raise LogoNotFoundError(organization_id)

        content = await self.object_storage.download(key=key)
        extension = key.rsplit(".", 1)[-1].lower() if "." in key else ""
        content_type = _EXTENSION_TO_CONTENT_TYPE.get(
            extension, "application/octet-stream"
        )
        return content, content_type

    async def _to_response(self, branding: Branding) -> BrandingResponse:
        logo_url, logo_is_uploaded = self._resolve_logo_url(branding)
        return BrandingResponse(
            id=str(branding.id),
            organization_id=str(branding.organization_id),
            company_name=branding.company_name,
            logo_url=logo_url,
            logo_is_uploaded=logo_is_uploaded,
            favicon_url=branding.favicon_url,
            primary_color=branding.primary_color,
            secondary_color=branding.secondary_color,
            accent_color=branding.accent_color,
            theme=branding.theme or "light",
            background_image_url=await self._resolve_background_image_url(branding),
            background_luminance=branding.background_luminance,
            background_top_luminance=branding.background_top_luminance,
            background_entropy=branding.background_entropy,
            created_at=branding.created_at,
            updated_at=branding.updated_at,
        )

    async def _resolve_background_image_url(self, branding: Branding) -> str | None:
        """Turns the durable, persisted ``background_image_key`` into the
        stable proxy path the frontend fetches (authenticated, same as
        every other branding call) to render the actual image -- see
        ``BACKGROUND_IMAGE_RAW_PATH``'s own docstring for why this is a
        same-API proxy path rather than a direct object-storage link."""
        if not branding.background_image_key:
            return None
        return BACKGROUND_IMAGE_RAW_PATH

    def _resolve_logo_url(self, branding: Branding) -> tuple[str | None, bool]:
        """An uploaded logo (``logo_key`` set) always wins over the plain
        text ``logo_url`` column -- returns the stable proxy path and
        ``True`` for that case, or the plain text URL as-is and ``False``
        when there's no upload. See ``BrandingResponse.logo_is_uploaded``'s
        own docstring for why the frontend needs to tell these apart."""
        if branding.logo_key:
            return LOGO_RAW_PATH, True
        return branding.logo_url, False

    async def _invalidate_portal_resolve_cache(
        self, organization_id: uuid.UUID
    ) -> None:
        """Best-effort fan-out to the guest-facing captive-portal resolve
        cache -- see ``PortalResolveCacheProtocol``'s own docstring.

        Never raises. A branding upload must not fail because Redis is
        momentarily unreachable; the resolve cache's own TTL is the
        backstop, exactly as it already is for every other missed
        invalidation this platform tolerates."""
        if self.portal_resolve_cache is None:
            return
        try:
            await self.portal_resolve_cache.invalidate_organization(organization_id)
        except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
            logger.warning(
                "branding_portal_resolve_cache_invalidation_failed",
                extra={"organization_id": str(organization_id), "error": str(exc)},
            )

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: str,
        *,
        entity_type: str,
        entity_id: uuid.UUID | None = None,
        description: str = "",
        organization_id: uuid.UUID | None = None,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )
