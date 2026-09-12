"""Pure validation helpers for the Network Diagnostics domain -- no I/O,
easy to unit-test in isolation (mirrors every other domain's own
``validators.py`` convention, e.g. ``app.domains.content_filtering
.validators``).

## What this can and cannot enforce, honestly

``target`` was previously validated as ``str(min_length=1, max_length=255)``
and nothing else, then handed to RouterOS as ``address=<target>``. That is
the input to a tool that sends real packets at a caller-chosen destination
from the customer's own router, so it deserves more than a length check.

What :func:`normalize_target` genuinely enforces:

* the value is a real IPv4/IPv6 address or a syntactically real DNS
  hostname, and nothing else -- no URLs, no ``:port``, no ``/path``, no
  whitespace, no shell- or RouterOS-shaped punctuation;
* the value is not an address that is meaningless or abuse-shaped to
  probe: loopback, unspecified (``0.0.0.0``/``::``), link-local
  (including the ``169.254.169.254`` cloud metadata address), multicast,
  the IPv4 limited broadcast address, or an otherwise IETF-reserved
  block. Pinging these from a router either tells the operator nothing or
  is a packet-amplification shape, never a diagnostic.

**Private/RFC1918 addresses are deliberately allowed.** "Can this router
reach its own gateway / its own DNS server / that access point" is the
single most useful thing this tool does, and every one of those targets is
private. Blocking them would remove the feature's actual value.

What this **cannot** enforce, and no amount of validation here could:

* **that a public target is "the customer's own to probe".** The platform
  does not store any customer's WAN allocation or upstream prefixes --
  ``Router.public_ip_address`` is a single address the device reported, not
  a delegation, and there is no ASN/prefix record anywhere in the schema.
  There is therefore no honest way to distinguish "my own ISP's gateway"
  from "a stranger's server" for a public destination, and pretending
  otherwise with a heuristic would block real diagnostics while stopping no
  determined abuser. The real control on that risk is volume, not
  destination: see ``constants.py``'s per-organization window, which is
  what actually bounds how much traffic one tenant can point anywhere.
* **that a hostname does not resolve to a rejected address.** Resolution
  happens on the router, not here; a name could resolve to 127.0.0.1 or to
  a multicast group. Doing our own lookup would prove nothing (the router
  may use different DNS servers, and the answer can change between our
  lookup and the device's) and would add a blocking DNS call to a request
  path. The address rules below therefore catch the literal form only, and
  are honestly a speed bump rather than a boundary.
"""

from __future__ import annotations

import ipaddress
import re

from .exceptions import InvalidDiagnosticTargetError

# One or more dot-separated labels, each 1-63 chars, alphanumeric with
# interior hyphens only -- the real DNS hostname-label grammar (RFC 1035
# section 2.3.1). Unlike app.domains.content_filtering.validators's own
# DOMAIN_PATTERN this accepts a SINGLE label, because a venue's own
# internal names ("gateway", "nvr", a router's /ip dns static entry) are
# real, legitimate diagnostic targets and are single-label by nature.
_DNS_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
HOSTNAME_PATTERN = re.compile(rf"^{_DNS_LABEL}(\.{_DNS_LABEL})*$")

# The longest a fully-qualified DNS name may be, and also the column width
# of DiagnosticRun.target.
MAX_TARGET_LENGTH = 255

_IPV4_BROADCAST = ipaddress.IPv4Address("255.255.255.255")


def _reject(value: str, reason: str) -> InvalidDiagnosticTargetError:
    return InvalidDiagnosticTargetError(value, reason)


def _check_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address, raw: str) -> None:
    """Rejects addresses that are meaningless or abuse-shaped to probe.

    Deliberately does NOT reject ``is_private``: see the module docstring
    -- the venue's own gateway, DNS server and access points are all
    private, and they are the targets this tool exists for.
    """
    if address.is_loopback:
        raise _reject(raw, "a loopback address is not reachable from the router")
    if address.is_unspecified:
        raise _reject(raw, "the unspecified address is not a real destination")
    if address.is_multicast:
        raise _reject(raw, "multicast addresses cannot be diagnosed this way")
    if address.is_link_local:
        # Covers 169.254.0.0/16 (and so the 169.254.169.254 cloud metadata
        # address) and fe80::/10.
        raise _reject(raw, "link-local addresses are not a valid diagnostic target")
    if isinstance(address, ipaddress.IPv4Address) and address == _IPV4_BROADCAST:
        raise _reject(raw, "the broadcast address cannot be diagnosed this way")
    if address.is_reserved:
        raise _reject(raw, "reserved addresses are not a valid diagnostic target")


def normalize_target(value: str) -> str:
    """Returns the canonical form of a real diagnostic target, or raises
    :class:`~.exceptions.InvalidDiagnosticTargetError`.

    An IP is returned in Python's own canonical ``str()`` form (so
    ``::ffff:1.2.3.4`` and mixed-case IPv6 normalize); a hostname is
    returned lowercased with any trailing root dot stripped, so the same
    target is one string in the history rather than several.
    """
    candidate = value.strip()
    if not candidate:
        raise _reject(value, "a target is required")
    if len(candidate) > MAX_TARGET_LENGTH:
        raise _reject(value, f"a target may be at most {MAX_TARGET_LENGTH} characters")

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        _check_ip(address, value)
        return str(address)

    hostname = candidate.rstrip(".").lower()
    if not hostname or HOSTNAME_PATTERN.match(hostname) is None:
        raise _reject(value, "a target must be an IP address or a plain hostname")
    return hostname


__all__ = ["normalize_target", "HOSTNAME_PATTERN", "MAX_TARGET_LENGTH"]
