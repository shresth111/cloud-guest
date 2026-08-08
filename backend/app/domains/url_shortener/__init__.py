"""The URL Shortener domain.

A small, self-contained "shorten a URL, redirect on visit" utility, callable
from three distinct surfaces (see ``constants.ShortLinkSource``):

* The public, unauthenticated marketing-site tool
  (``POST /api/v1/public/short-links``, ``source=public_site``).
* The authenticated customer dashboard, org-scoped
  (``POST/GET/PATCH/DELETE /api/v1/short-links``, ``source=customer``).
* The Master (platform-admin) console, cross-tenant moderation
  (``GET/PATCH /api/v1/master/short-links``).

Plus one guest-facing, no-auth redirect endpoint (``GET /api/v1/s/{code}``)
that every generated short link ultimately resolves through.

See ``models.py``/``service.py``/``router.py`` module docstrings for the
full design write-up -- this module mirrors ``app.domains.voucher``'s and
``app.domains.otp``'s established shape (models/repository/service/router/
schemas/dependencies/exceptions/constants/validators) throughout.
"""

from __future__ import annotations
