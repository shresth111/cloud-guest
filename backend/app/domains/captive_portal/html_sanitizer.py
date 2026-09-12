"""Allowlist sanitizer for venue-authored ``post_login_html``.

``captive_portal_configs.post_login_html`` is HTML a venue admin writes in
the customer dashboard and that a *guest* is then shown, on the same
origin that handles their OTP code and phone number. The author is
semi-trusted at best -- a venue admin, or whoever has taken over a venue
admin's session -- so the bytes are treated as hostile input, not as
content.

**Sanitized on write, never on read.** ``GET /captive-portal/resolve`` is
the single hottest unauthenticated request in the product (every guest
device, every WiFi join -- see ``cache.py``'s own module docstring), and
the write path is a rare, always-authenticated admin save. Sanitizing on
read would put an HTML parse on that hot path *and* leave hostile bytes
sitting in the database for any other consumer -- a future preview
endpoint, an export, a support tool -- to find and trust. Sanitizing on
write costs one parse per admin save and makes the stored bytes safe for
every reader, present and future.

**This is defence in depth, not the only defence.** The guest frontend
renders this HTML inside an iframe sandboxed with neither
``allow-scripts`` nor ``allow-same-origin``, so script cannot execute
there even if it survived. That is the primary control; this module is
the one that has to keep holding when someone builds a second renderer
and forgets the sandbox.

**Why ``nh3``.** ``nh3`` is the Python binding for Rust's ``ammonia``:
an allowlist sanitizer built on ``html5ever``, the same parser Firefox's
engine grew out of -- so what it sanitizes is the tree a browser would
actually build, not the tree a regex thinks the markup describes. That
parser-fidelity property is the whole game for a sanitizer, and it is
exactly what hand-rolled tag stripping gets wrong. The obvious
alternative, ``bleach``, is in maintenance mode upstream and explicitly
points new users at ``nh3``; neither was already a dependency here, so
there was no incumbent to defer to and ``nh3`` is the one added.

**What ``nh3`` deliberately does not do: CSS.** ``ammonia`` filters tags,
attributes and URL schemes. It does not look inside a ``style``
attribute's value or a ``<style>`` element's text -- if you allow them,
their contents pass through byte-for-byte. Inline styling and ``<style>``
blocks are genuinely wanted for a custom page (that is most of what
"author your own page" means), so they are allowed here and the CSS is
sanitized by this module's own :func:`sanitize_declarations` /
:func:`sanitize_stylesheet`, which strip the constructs that can execute
or phone home.
"""

from __future__ import annotations

import re
from copy import deepcopy

import nh3

from .constants import POST_LOGIN_HTML_MAX_BYTES
from .exceptions import PostLoginHtmlTooLargeError

__all__ = [
    "sanitize_post_login_html",
    "sanitize_declarations",
    "sanitize_stylesheet",
]


# ---------------------------------------------------------------------------
# HTML allowlist
# ---------------------------------------------------------------------------

# ``nh3.ALLOWED_TAGS`` is already a formatting/layout allowlist with no
# script-bearing element in it (no ``script``/``iframe``/``object``/
# ``embed``/``form``/``base``/``meta``/``link``/``svg``/``math``), so it is
# the right starting point rather than something to re-derive. Added on
# top: ``style`` (see the module docstring -- a custom page needs a
# stylesheet, and its contents are sanitized separately), the three
# sectioning elements a hand-written page reaches for that the default set
# happens to omit, and ``tfoot``, which ``nh3.ALLOWED_ATTRIBUTES`` already
# has an entry for while ``ALLOWED_TAGS`` does not.
ALLOWED_TAGS: frozenset[str] = frozenset(
    nh3.ALLOWED_TAGS | {"style", "section", "main", "tfoot"}
)

# Removed *with their text content*, not merely unwrapped. Everything here
# is an element whose children are a program, a document, or a form
# submission rather than prose -- unwrapping a ``<script>`` would paste its
# source into the page as visible text, which is worse than useless.
#
# ``style`` is deliberately NOT in this set (ammonia's own default puts it
# here). It must not be: ammonia panics outright if a tag appears in both
# ``tags`` and ``clean_content_tags``, and we want the stylesheet kept.
CLEAN_CONTENT_TAGS: frozenset[str] = frozenset(
    {
        "script",
        "iframe",
        "object",
        "embed",
        "form",
        "base",
        "meta",
        "link",
        "noscript",
        "template",
        "svg",
        "math",
        "frame",
        "frameset",
        "applet",
        "textarea",
        "select",
        "option",
        "button",
        "input",
    }
)


def _build_allowed_attributes() -> dict[str, set[str]]:
    """``nh3.ALLOWED_ATTRIBUTES`` plus the presentational attributes a
    venue-authored page actually needs.

    Note what is *not* here and cannot be: ``nh3`` allowlists attributes by
    name, and no ``on*`` handler name is in this dict, so every event
    handler attribute -- ``onclick``, ``onerror``, ``onload``, and the
    hundred others including any the HTML spec adds tomorrow -- is dropped
    by construction rather than by a blocklist that has to be kept current.

    ``target`` is also deliberately absent: whatever the author wrote is
    dropped, and ``set_tag_attribute_values`` below then sets exactly
    ``target="_blank"`` on every anchor. That is stricter than allowing the
    attribute through, because it makes ``target="_top"`` -- a frame-busting
    move against any future renderer that is not the sandboxed iframe --
    unexpressible rather than merely discouraged.
    """
    attributes: dict[str, set[str]] = {
        tag: set(values) for tag, values in deepcopy(nh3.ALLOWED_ATTRIBUTES).items()
    }
    attributes["*"] = {"style", "class", "title", "lang", "dir"}
    attributes.setdefault("style", set()).update({"media"})
    return attributes


ALLOWED_ATTRIBUTES: dict[str, set[str]] = _build_allowed_attributes()

# ``http``/``https`` are what the brief for this field asks for on ``href``
# and ``src``. ``mailto``/``tel`` are the two additions: a "call us" or
# "email us" link is an ordinary thing for a venue page to want, neither
# scheme can express code, and both are already in ``nh3``'s own default
# set. Every other default scheme is dropped -- ``ftp``, ``magnet``,
# ``bitcoin`` and friends have no business on a guest WiFi splash page,
# and ``javascript:``/``data:`` were never in the default set to begin
# with, which is what makes those two impossible here.
ALLOWED_URL_SCHEMES: frozenset[str] = frozenset({"http", "https", "mailto", "tel"})

# Relative URLs are stripped rather than passed through. The page is
# rendered from a ``srcdoc`` iframe with no meaningful base URL, so a
# relative ``src`` resolves to nothing useful anyway; and against a future
# renderer that *does* have a base, a relative URL is one that silently
# points at whatever origin is hosting the page, which for this field is
# the origin handling guest OTP codes.
_URL_RELATIVE = "deny"

# Anchors are forced open in a new browsing context and given the full
# ``rel`` hardening, rather than either being trusted or having the
# attribute merely allowed -- see ``_build_allowed_attributes``.
_SET_TAG_ATTRIBUTE_VALUES: dict[str, dict[str, str]] = {"a": {"target": "_blank"}}
_LINK_REL = "noopener noreferrer"


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

# Matched against a *normalized* probe of each declaration -- lowercased,
# CSS backslash escapes removed, all whitespace removed (see
# ``_css_probe``) -- so ``expr\ession(``, ``behavior :`` and
# ``EXPRESSION(`` all reduce to the same needle. Historic IE-era
# script-from-CSS vectors plus the two remote-load vectors:
#
# * ``expression(`` / ``-moz-binding`` / ``behavior`` / ``progid:`` --
#   CSS that runs code. Dead in every shipping browser, kept because a
#   sanitizer's job is not to bet on which renderer sees the bytes.
# * ``javascript:`` / ``vbscript:`` -- a script URL anywhere in a value.
# * ``@import`` -- pulls in a stylesheet from a third party. Not in the
#   brief's list, and added deliberately: it is a remote load whose
#   *contents* this sanitizer never sees and whose owner can change them
#   after the fact, which is the one thing an on-write sanitizer cannot
#   defend against. Inline CSS plus ``url()`` (still allowed, for
#   ``@font-face`` and background images) covers what a venue actually
#   needs from it.
_BANNED_CSS_SUBSTRINGS: tuple[str, ...] = (
    "expression(",
    "-moz-binding",
    "behavior:",
    "progid:",
    "javascript:",
    "vbscript:",
    "livescript:",
    "@import",
)

_CSS_COMMENT_RE = re.compile(r"/\*.*?(?:\*/|$)", re.DOTALL)
_CSS_ESCAPE_RE = re.compile(r"\\")
_CSS_WHITESPACE_RE = re.compile(r"\s+")
_CSS_URL_RE = re.compile(r"url\s*\(([^)]*)\)", re.IGNORECASE)
# Anything of the form ``scheme:`` at the very start of a URL token.
_URL_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")


def _strip_css_comments(css: str) -> str:
    """Removes ``/* ... */`` comments, including an unterminated trailing
    one.

    Runs *before* any banned-substring check, and that ordering is the
    point: ``expr/**/ession(`` is a real, historic way of smuggling a
    needle past a naive scanner, and it only works if the scanner looks at
    the bytes before the comments come out.
    """
    return _CSS_COMMENT_RE.sub("", css)


def _css_probe(text: str) -> str:
    """The normalized form :data:`_BANNED_CSS_SUBSTRINGS` is matched
    against: lowercased, CSS backslash escapes dropped, whitespace
    removed.

    Dropping backslashes rather than resolving them is deliberate.
    Resolving CSS escapes properly means implementing a chunk of the CSS
    tokenizer; dropping them turns ``expr\\ession(`` into
    ``expression(`` -- which is what the renderer would have resolved it
    to -- and can only ever make the probe match *more* readily, never
    less. A false positive here costs one dropped declaration.
    """
    return _CSS_WHITESPACE_RE.sub("", _CSS_ESCAPE_RE.sub("", text.lower()))


def _has_banned_css(text: str) -> bool:
    probe = _css_probe(text)
    return any(needle in probe for needle in _BANNED_CSS_SUBSTRINGS)


def _url_token_is_safe(token: str) -> bool:
    """Whether one ``url(...)`` payload points somewhere a stylesheet may
    point.

    Absolute ``http``/``https`` only. A scheme-relative ``//host/x`` or a
    path-relative ``/x`` is rejected for the same reason
    :data:`_URL_RELATIVE` denies relative URLs in markup -- it resolves
    against whatever origin ends up rendering the page. ``data:`` is
    rejected too, even though ``data:image/png`` would be harmless,
    because ``data:image/svg+xml`` is not: an SVG is a document that can
    carry script, and telling the two apart by sniffing a MIME label the
    author also controls is not a distinction worth trusting.
    """
    value = token.strip().strip("\"'").strip()
    if not value:
        return False
    match = _URL_SCHEME_RE.match(value)
    if match is None:
        return False
    return match.group(1).lower() in {"http", "https"}


def _split_css_declarations(text: str) -> list[str]:
    """Splits a declaration list on ``;``, ignoring separators inside
    quoted strings (``content: "a;b"`` is one declaration, not two)."""
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    escaped = False
    for char in text:
        if quote is not None:
            buf.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            buf.append(char)
            continue
        if char == ";":
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(char)
    parts.append("".join(buf))
    return parts


def sanitize_declarations(css: str) -> str:
    """Sanitizes a CSS *declaration list* -- the value of a ``style``
    attribute, or the body of one rule inside a ``<style>`` block.

    Drops the offending declaration and keeps the rest, rather than
    discarding the whole attribute: a venue whose ten-property inline
    style contains one typo that happens to look like a needle should lose
    that one property, not their layout.

    Comments are stripped first even though the caller may already have
    done so -- ``style`` attributes reach this function directly from
    ``nh3``'s attribute hook, with nothing between them and the author's
    bytes, and ``expr/**/ession(`` has to die on that path too.
    """
    kept: list[str] = []
    for declaration in _split_css_declarations(_strip_css_comments(css)):
        if not declaration.strip():
            continue
        if _has_banned_css(declaration):
            continue
        urls = _CSS_URL_RE.findall(declaration)
        if any(not _url_token_is_safe(url) for url in urls):
            continue
        kept.append(declaration.strip())
    return "; ".join(kept)


def sanitize_stylesheet(css: str) -> str:
    """Sanitizes the text content of a ``<style>`` element.

    Walks the sheet tracking brace depth and quoting, splitting it into
    three kinds of run: a *prelude* (the text before a ``{`` -- a selector,
    or an at-rule's condition), a *declaration list* (the text before a
    ``}``, handed to :func:`sanitize_declarations`), and a top-level
    *statement* (the text before a ``;`` outside any block -- ``@import
    url(...);`` and friends, also handed to :func:`sanitize_declarations`,
    which is what drops them). Nested blocks
    (``@media { .a { ... } }``) fall out of that naturally: the inner ``}``
    flushes the declarations and the outer one flushes an empty string.

    A prelude is never rewritten, only checked -- a selector cannot carry
    a value, so the only way one trips the banned-substring check is a
    deliberate ``expression(``-style payload, and in that case the whole
    sheet is dropped. That is the one place this module fails closed
    rather than surgically, because a prelude that has been tampered with
    tells you nothing reliable about the block it introduces. Flushing
    top-level statements on ``;`` is what keeps that from over-firing:
    without it, an ``@import`` at the top of the sheet would still be
    sitting in the buffer when the *first real rule's* selector was
    flushed, and the entire stylesheet would be discarded over one line.

    ``<style>`` text needs no protection against ``</style>`` smuggling:
    ``html5ever`` tokenizes the element as RAWTEXT, so its content is by
    construction everything up to the first ``</style``, and the
    serializer writes back exactly what the parser accepted.
    """
    css = _strip_css_comments(css)
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    for char in css:
        if quote is not None:
            buf.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            buf.append(char)
            continue
        if char == "{":
            prelude = "".join(buf)
            buf = []
            if _has_banned_css(prelude):
                return ""
            out.append(prelude)
            out.append("{")
            depth += 1
            continue
        if char == "}":
            if depth == 0:
                # A stray closer with nothing open. Drop it rather than
                # emit unbalanced CSS.
                buf = []
                continue
            out.append(sanitize_declarations("".join(buf)))
            buf = []
            out.append("}")
            depth -= 1
            continue
        if char == ";" and depth == 0:
            statement = sanitize_declarations("".join(buf))
            buf = []
            if statement:
                out.append(statement)
                out.append(";")
            continue
        buf.append(char)
    # Whatever is left when the input runs out: a truncated final rule, or
    # a last statement with no terminating ``;``.
    tail = sanitize_declarations("".join(buf))
    if tail:
        out.append(tail)
        out.append(";" if depth == 0 else "")
    # Close anything the author left open, so this never emits CSS that
    # swallows whatever a future renderer concatenates after it.
    out.append("}" * depth)
    return "".join(out)


_STYLE_BLOCK_RE = re.compile(
    r"(<style\b[^>]*>)(.*?)(</style>)", re.IGNORECASE | re.DOTALL
)


def _sanitize_style_blocks(html: str) -> str:
    """Second pass over ``nh3``'s own output, sanitizing the CSS inside
    each surviving ``<style>`` element.

    Regex over HTML is normally a mistake; it is safe *here* specifically
    because the input is not author markup but ``html5ever``'s
    re-serialization of the tree it parsed. Every ``<style>`` in that
    output is a real, balanced element, its content is RAWTEXT that
    provably cannot contain ``</style``, and its attributes have already
    been filtered and re-quoted. Doing this before ``nh3`` instead would
    mean running the regex over exactly the hostile, malformed markup that
    makes regex-over-HTML a bad idea.
    """

    def _replace(match: re.Match[str]) -> str:
        body = sanitize_stylesheet(match.group(2))
        if not body.strip():
            return ""
        return f"{match.group(1)}{body}{match.group(3)}"

    return _STYLE_BLOCK_RE.sub(_replace, html)


def _attribute_filter(tag: str, attribute: str, value: str) -> str | None:
    """``nh3`` attribute hook. Returns the value to keep, or ``None`` to
    drop the attribute.

    Only ``style`` is rewritten -- it is the one allowed attribute whose
    value ``ammonia`` does not itself understand. Everything else has
    already survived the name allowlist and, for ``href``/``src``, the URL
    scheme check, so it is passed through untouched.

    Called for the ``target``/``rel`` values this module *adds* as well as
    the ones the author wrote, which is why this must be a pass-through by
    default rather than an allowlist of its own.
    """
    if attribute != "style":
        return value
    cleaned = sanitize_declarations(value)
    return cleaned or None


def sanitize_post_login_html(html: str | None) -> str | None:
    """The one entry point the service layer calls. Returns the exact
    bytes to store.

    ``None`` and blank-after-sanitizing both come back as ``None``, not
    ``""``: the column's contract is "null/empty means the pre-existing
    redirect/success behaviour", and storing two different values that
    both mean "nothing" invites a renderer to eventually treat them
    differently.

    Raises :class:`~.exceptions.PostLoginHtmlTooLargeError` (400) when the
    *submitted* value exceeds
    :data:`~.constants.POST_LOGIN_HTML_MAX_BYTES`. The check is on the
    input rather than the output on purpose -- the number in the error has
    to be the number the venue can see in their own editor, and the
    sanitizer is not required to be size-monotonic anyway (it appends
    ``rel``/``target`` to anchors, so a link-dense page can come out a
    little larger than it went in).
    """
    if html is None:
        return None
    actual_bytes = len(html.encode("utf-8"))
    if actual_bytes > POST_LOGIN_HTML_MAX_BYTES:
        raise PostLoginHtmlTooLargeError(actual_bytes, POST_LOGIN_HTML_MAX_BYTES)
    if not html.strip():
        return None
    cleaned = nh3.clean(
        html,
        tags=set(ALLOWED_TAGS),
        clean_content_tags=set(CLEAN_CONTENT_TAGS),
        attributes={tag: set(values) for tag, values in ALLOWED_ATTRIBUTES.items()},
        attribute_filter=_attribute_filter,
        url_schemes=set(ALLOWED_URL_SCHEMES),
        url_relative=_URL_RELATIVE,
        link_rel=_LINK_REL,
        set_tag_attribute_values={
            tag: dict(values) for tag, values in _SET_TAG_ATTRIBUTE_VALUES.items()
        },
        strip_comments=True,
    )
    cleaned = _sanitize_style_blocks(cleaned)
    return cleaned or None
