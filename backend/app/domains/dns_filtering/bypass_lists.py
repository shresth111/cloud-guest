"""The platform's public DoH lists: fetch, validate, keep the last good copy.

## Source

``github.com/dibdot/DoH-IP-blocklists`` -- ``doh-ipv4.txt``,
``doh-ipv6.txt`` and ``doh-domains.txt``. Licence GPL-3.0 (we consume the
published data files at runtime; nothing from the repository is vendored or
redistributed). Its README: the domain list is curated by hand "usually once
a month", and ``doh-lookup.sh`` "runs automatically every hour via GitHub
actions" to regenerate the address files -- the commit log on 2026-09-24
showed several regenerations a day. Line format, observed: one literal per
line, optionally followed by whitespace and a ``# comment`` naming the
hostnames the address belongs to.

## Trust

The source is a third party's GitHub file. It is trusted for exactly one
thing: *which IP literals and hostnames look like DoH servers*. So:

* only the first whitespace-separated token of each line is read, and only
  if it parses as an IP address of the expected version (or a plain
  hostname) -- comments, CIDRs, ranges, wildcards and anything else are
  dropped and counted;
* only globally routable unicast addresses are kept -- a private,
  loopback, link-local or multicast entry would black-hole something at the
  venue itself;
* platform exclusions are removed (Cloudflare Gateway's resolver ranges,
  ``cloudflare-gateway.com``): the source list really does carry Gateway
  resolver addresses;
* a list over the entry cap, empty, or less than ``min_keep_ratio`` of the
  last good list is **refused whole** and the last good copy stays in force.

## Hostnames: subdomains only, plus a curated set

The domain file lists ~1,360 names, ~180 of them bare apex domains
(``cleanbrowsing.org``, ``ahoj.email``). An apex is usually also its
operator's website and mail domain, so sinkholing it breaks more than DoH.
Only names with at least three labels are taken from the source; the
curated :data:`~.constants.CURATED_DOH_HOSTNAMES` (which does include a few
deliberate two-label names like ``dns.google``) is always added.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlparse

import httpx
from wyfy_device_gateway.mikrotik_dns_filtering import normalize_hostname

from .constants import CURATED_DOH_HOSTNAMES, BlocklistKind, BlocklistRefreshStatus

#: A list file larger than this is not a DoH list. Read no further.
MAX_LIST_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ParsedList:
    entries: list[str]
    rejected: int = 0
    excluded: int = 0


def list_sha(entries: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(entries)).encode()).hexdigest()


def _first_token(line: str) -> str | None:
    body = line.split("#", 1)[0].strip()
    return body.split()[0] if body else None


def parse_ip_list(
    text: str, *, version: int, exclusions: Iterable[str] = ()
) -> ParsedList:
    """Globally routable unicast literals of IP ``version`` only, deduped,
    sorted, minus anything inside an ``exclusions`` network."""
    networks = [ipaddress.ip_network(n, strict=False) for n in exclusions]
    kept: set[str] = set()
    rejected = excluded = 0
    for line in text.splitlines():
        token = _first_token(line)
        if token is None:
            continue
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            rejected += 1
            continue
        if address.version != version or not address.is_global or address.is_multicast:
            rejected += 1
            continue
        if any(address.version == n.version and address in n for n in networks):
            excluded += 1
            continue
        kept.add(str(address))
    return ParsedList(
        sorted(kept, key=lambda a: ipaddress.ip_address(a)), rejected, excluded
    )


def _excluded_name(name: str, suffixes: Iterable[str]) -> bool:
    return any(name == s or name.endswith("." + s) for s in suffixes if s)


def parse_hostname_list(text: str, *, exclusions: Iterable[str] = ()) -> ParsedList:
    """Plain hostnames with at least three labels, lower-cased, deduped,
    sorted, minus any name at or under an ``exclusions`` suffix."""
    suffixes = [s.strip().lower().rstrip(".") for s in exclusions]
    kept: set[str] = set()
    rejected = excluded = 0
    for line in text.splitlines():
        token = _first_token(line)
        if token is None:
            continue
        name = normalize_hostname(token)
        if name is None or name.count(".") < 2:
            rejected += 1
            continue
        if _excluded_name(name, suffixes):
            excluded += 1
            continue
        kept.add(name)
    return ParsedList(sorted(kept), rejected, excluded)


def refusal_reason(
    parsed: ParsedList,
    *,
    last_good_count: int | None,
    max_entries: int,
    min_keep_ratio: float,
) -> str | None:
    """Why a freshly parsed list must NOT replace the last good one, or
    ``None`` when it may."""
    count = len(parsed.entries)
    if count == 0:
        return f"no valid entries ({parsed.rejected} lines rejected)"
    if count > max_entries:
        return f"{count} entries exceeds the cap of {max_entries}"
    if last_good_count and count < last_good_count * min_keep_ratio:
        return (
            f"{count} entries is under {min_keep_ratio:.0%} of the last good "
            f"list's {last_good_count}; keeping the last good list"
        )
    return None


def hostnames_to_push(
    source: Iterable[str],
    *,
    exclusions: Iterable[str],
    probe_hostname: str,
    max_entries: int,
) -> list[str]:
    """Curated names first (always kept), then the source's, excluding the
    router's own upstream suffixes and the name the DoH switch probes."""
    suffixes = [s.strip().lower() for s in exclusions]
    never = {probe_hostname.strip().lower().rstrip(".")}
    out: list[str] = []
    for name in (*CURATED_DOH_HOSTNAMES, *source):
        if name in never or _excluded_name(name, suffixes):
            continue
        out.append(name)
    return list(dict.fromkeys(out))[:max_entries]


class ListFetcher(Protocol):
    async def fetch(self, url: str) -> str: ...


class ListFetchError(Exception):
    pass


@dataclass
class HttpxListFetcher:
    """https only, no redirects followed, at most :data:`MAX_LIST_BYTES`.
    ``transport`` exists for tests."""

    timeout_seconds: float = 20.0
    transport: httpx.AsyncBaseTransport | None = None

    async def fetch(self, url: str) -> str:
        if urlparse(url).scheme != "https":
            raise ListFetchError(f"refusing a non-https list URL: {url!r}")
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            try:
                async with client.stream("GET", url) as response:
                    if response.status_code != 200:
                        raise ListFetchError(f"HTTP {response.status_code} from {url}")
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_LIST_BYTES:
                            raise ListFetchError(
                                f"{url} is larger than {MAX_LIST_BYTES} bytes"
                            )
                        chunks.append(chunk)
            except httpx.HTTPError as exc:
                raise ListFetchError(f"{type(exc).__name__} fetching {url}") from exc
        return b"".join(chunks).decode("utf-8", errors="replace")


class BlocklistStore(Protocol):
    async def get_blocklist(self, kind: str): ...  # noqa: ANN201
    async def save_blocklist(self, kind: str, data: dict[str, object]): ...  # noqa: ANN201
    async def commit(self) -> None: ...


@dataclass(frozen=True, slots=True)
class RefreshSettings:
    ipv4_url: str
    ipv6_url: str
    domains_url: str
    max_entries: int = 5000
    min_keep_ratio: float = 0.5
    ip_exclusions: tuple[str, ...] = ()
    hostname_exclusions: tuple[str, ...] = ()


@dataclass
class RefreshOutcome:
    statuses: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


async def refresh_blocklists(
    store: BlocklistStore,
    fetcher: ListFetcher,
    settings: RefreshSettings,
    *,
    now: datetime | None = None,
) -> RefreshOutcome:
    """Fetch, validate and store each list. A failure or refusal on one
    list never touches another's, and never replaces a last good copy."""
    now = now or datetime.now(UTC)
    outcome = RefreshOutcome()
    plan = (
        (
            BlocklistKind.DOH_IPV4,
            settings.ipv4_url,
            lambda t: parse_ip_list(t, version=4, exclusions=settings.ip_exclusions),
        ),
        (
            BlocklistKind.DOH_IPV6,
            settings.ipv6_url,
            lambda t: parse_ip_list(t, version=6, exclusions=settings.ip_exclusions),
        ),
        (
            BlocklistKind.DOH_DOMAINS,
            settings.domains_url,
            lambda t: parse_hostname_list(t, exclusions=settings.hostname_exclusions),
        ),
    )
    for kind, url, parse in plan:
        existing = await store.get_blocklist(kind.value)
        try:
            text = await fetcher.fetch(url)
        except ListFetchError as exc:
            status, error, parsed = BlocklistRefreshStatus.ERROR, str(exc), None
        else:
            parsed = parse(text)
            error = refusal_reason(
                parsed,
                last_good_count=existing.entry_count if existing is not None else None,
                max_entries=settings.max_entries,
                min_keep_ratio=settings.min_keep_ratio,
            )
            status = (
                BlocklistRefreshStatus.REFUSED if error else BlocklistRefreshStatus.OK
            )
        data: dict[str, object] = {
            "source_url": url,
            "last_attempt_at": now,
            "last_status": status.value,
            "last_error": error,
        }
        if status is BlocklistRefreshStatus.OK and parsed is not None:
            data.update(
                entries=parsed.entries,
                entry_count=len(parsed.entries),
                sha256=list_sha(parsed.entries),
                fetched_at=now,
            )
            await store.save_blocklist(kind.value, data)
        elif existing is not None:
            await store.save_blocklist(kind.value, data)
        # No last good copy and nothing valid: nothing to store.
        outcome.statuses[kind.value] = status.value
        if error:
            outcome.errors[kind.value] = error
    await store.commit()
    return outcome


__all__ = [
    "HttpxListFetcher",
    "ListFetchError",
    "ListFetcher",
    "MAX_LIST_BYTES",
    "ParsedList",
    "RefreshOutcome",
    "RefreshSettings",
    "hostnames_to_push",
    "list_sha",
    "parse_hostname_list",
    "parse_ip_list",
    "refresh_blocklists",
    "refusal_reason",
]
