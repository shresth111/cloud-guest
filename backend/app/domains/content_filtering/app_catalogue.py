"""The curated app catalogue behind "Block Websites -> Apps".

One toggle per app. Switching an app off creates one ordinary
``ContentFilterRule`` per name (and, where an app is reachable by a stable
published address range, per range) below, tagged with ``app_key``, and
pushes each through the existing per-rule push -- so every name gets the
same DNS sinkhole and ``tls-host`` drops a hand-blocked website gets, and
every range the same address-list drop. Nothing here is a new enforcement
mechanism.

## What this is, and what it is not

It matches **the names an app's own servers use**, nothing more. It is not
application identification: there is no deep packet inspection on this
platform and none is pretended. Concretely:

* An app that already has a connection open, or that connects to a
  hard-coded address, is not stopped by a name block. Telegram is the
  extreme case -- its apps connect to built-in addresses -- which is why it
  also carries Telegram's own published IPv4 ranges.
* Apps that share infrastructure with something a venue still wants are
  deliberately under-blocked rather than over-blocked: ``googleapis.com``,
  ``ggpht.com``, ``fbcdn.net``, ``akamaized.net`` and ``dailyhunt.in`` are
  never listed, because blocking them breaks Google sign-in, Maps,
  Instagram, every Akamai customer, or a news app.
* Torrent clients find peers without trackers (DHT, peer exchange); this
  blocks the popular sites and trackers, not BitTorrent.

The UI says so in plain words ("matches the app's website names; some apps
may still get through"), and the security catalogue's
``application_control`` row carries the same limits.

## Sources (researched 2026-10-01)

* YouTube, Instagram, Facebook, Messenger, WhatsApp, TikTok, Netflix,
  Telegram, Snapchat: the NextDNS "services" catalogue
  (github.com/nextdns/services), trimmed to the registrable names and the
  app-specific hosts, without its CNAME/CDN aliases.
* Telegram IPv4 ranges: core.telegram.org/resources/cidr.txt (IPv6 ranges
  omitted -- ``/ip firewall address-list`` is IPv4).
* JioHotstar: hotstar.com (incl. ``service.hotstar.com``, which a public
  blocklist issue showed is needed for playback), jiohotstar.com,
  jiocinema.com.
* PUBG Mobile / BGMI and Free Fire: Netify's application pages (pubgmobile,
  gpubgm, freefiremobile, freefireind, ff.garena) plus the game-service
  hosts their clients resolve (igamecj.com, ggblueshark.com).
* Moj: mojapp.in and sharechat.com (Moj is ShareChat's app and uses its
  API hosts, so ShareChat goes with it). Josh: myjosh.in.

## Invariants (tested)

Every value passes this domain's own validators; no name appears under two
apps (so ownership on unblock is never ambiguous); no app lists a shared
platform name from the exclusion list above; keys are short, stable and
safe to put in a URL.
"""

from __future__ import annotations

from dataclasses import dataclass

from .constants import ContentFilterCategory


@dataclass(frozen=True, slots=True)
class CatalogueApp:
    key: str
    name: str
    category: ContentFilterCategory
    domains: tuple[str, ...]
    #: Published IPv4 ranges, for an app whose clients connect by address.
    cidrs: tuple[str, ...] = ()
    #: One plain sentence for the venue owner when this app is known to get
    #: through more than most. ``None`` when the generic caveat is enough.
    note: str | None = None


APP_CATALOGUE: tuple[CatalogueApp, ...] = (
    CatalogueApp(
        key="youtube",
        name="YouTube",
        category=ContentFilterCategory.STREAMING,
        domains=(
            "youtube.com",
            "youtu.be",
            "youtube-nocookie.com",
            "youtubekids.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "googlevideo.com",
            "ytimg.com",
        ),
    ),
    CatalogueApp(
        key="instagram",
        name="Instagram",
        category=ContentFilterCategory.SOCIAL_MEDIA,
        domains=("instagram.com", "cdninstagram.com", "ig.me", "instagr.am"),
    ),
    CatalogueApp(
        key="facebook",
        name="Facebook and Messenger",
        category=ContentFilterCategory.SOCIAL_MEDIA,
        domains=(
            "facebook.com",
            "fb.com",
            "fb.me",
            "facebook.net",
            "fbsbx.com",
            "messenger.com",
            "m.me",
        ),
    ),
    CatalogueApp(
        key="whatsapp",
        name="WhatsApp",
        category=ContentFilterCategory.SOCIAL_MEDIA,
        domains=("whatsapp.com", "whatsapp.net", "wa.me"),
        note="WhatsApp can reconnect through its own built-in addresses.",
    ),
    CatalogueApp(
        key="short_video",
        name="TikTok, Moj and Josh",
        category=ContentFilterCategory.SOCIAL_MEDIA,
        domains=(
            "tiktok.com",
            "tiktokv.com",
            "tiktokcdn.com",
            "tiktokcdn-in.com",
            "musical.ly",
            "byteoversea.com",
            "ibytedtos.com",
            "mojapp.in",
            "sharechat.com",
            "myjosh.in",
        ),
        note="This also blocks ShareChat, which runs Moj.",
    ),
    CatalogueApp(
        key="netflix",
        name="Netflix",
        category=ContentFilterCategory.STREAMING,
        domains=(
            "netflix.com",
            "netflix.net",
            "nflxvideo.net",
            "nflximg.net",
            "nflxext.com",
            "nflxso.net",
        ),
    ),
    CatalogueApp(
        key="jiohotstar",
        name="JioHotstar",
        category=ContentFilterCategory.STREAMING,
        domains=("hotstar.com", "jiohotstar.com", "jiocinema.com"),
    ),
    CatalogueApp(
        key="battle_royale",
        name="BGMI, PUBG Mobile and Free Fire",
        category=ContentFilterCategory.GAMING,
        domains=(
            "battlegroundsmobileindia.com",
            "pubgmobile.com",
            "gpubgm.com",
            "igamecj.com",
            "freefiremobile.com",
            "freefireind.in",
            "ff.garena.com",
            "ggblueshark.com",
        ),
        note="A match already in progress is not cut off.",
    ),
    CatalogueApp(
        key="telegram",
        name="Telegram",
        category=ContentFilterCategory.SOCIAL_MEDIA,
        domains=(
            "telegram.org",
            "telegram.me",
            "t.me",
            "telesco.pe",
            "tdesktop.com",
            "telegra.ph",
        ),
        cidrs=(
            "91.108.4.0/22",
            "91.108.8.0/22",
            "91.108.12.0/22",
            "91.108.16.0/22",
            "91.108.20.0/22",
            "91.108.56.0/22",
            "91.105.192.0/23",
            "149.154.160.0/20",
            "185.76.151.0/24",
        ),
    ),
    CatalogueApp(
        key="snapchat",
        name="Snapchat",
        category=ContentFilterCategory.SOCIAL_MEDIA,
        domains=(
            "snapchat.com",
            "sc-cdn.net",
            "sc-static.net",
            "sc-prod.net",
            "sc-gw.com",
            "snapkit.com",
            "snapads.com",
            "feelinsonice-hrd.appspot.com",
        ),
    ),
    CatalogueApp(
        key="torrents",
        name="Torrent sites and trackers",
        category=ContentFilterCategory.CUSTOM,
        domains=(
            "thepiratebay.org",
            "1337x.to",
            "yts.mx",
            "nyaa.si",
            "torrentgalaxy.to",
            "opentrackr.org",
            "openbittorrent.com",
            "open.stealth.si",
            "tracker.torrent.eu.org",
            "exodus.desync.com",
        ),
        note="Torrent apps can still find each other without these sites.",
    ),
)

#: Names that must never appear in the catalogue: shared platform
#: infrastructure whose block would break something a venue still wants.
SHARED_INFRASTRUCTURE_NAMES: frozenset[str] = frozenset(
    {
        "googleapis.com",
        "google.com",
        "gstatic.com",
        "ggpht.com",
        "googleusercontent.com",
        "fbcdn.net",
        "akamaized.net",
        "akamaihd.net",
        "cloudfront.net",
        "amazonaws.com",
        "appspot.com",
        "garena.com",
        "dailyhunt.in",
        "apple.com",
        "icloud.com",
    }
)


def app_by_key(key: str) -> CatalogueApp | None:
    return next((app for app in APP_CATALOGUE if app.key == key), None)


__all__ = [
    "APP_CATALOGUE",
    "SHARED_INFRASTRUCTURE_NAMES",
    "CatalogueApp",
    "app_by_key",
]
