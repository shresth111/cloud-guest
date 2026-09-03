"""Content Filtering domain: per-router, real MikroTik RouterOS
content-filtering rule CRUD -- a genuinely sellable feature for the
colleges/PGs/hostels segment of this product's customer base (parents/
wardens routinely want basic content restriction on guest WiFi).

## Scope decision: DNS sinkhole + address-list/firewall-filter -- not
Layer7, not a web-proxy, never TLS interception

RouterOS offers several real mechanisms for blocking guest traffic to
specific destinations. This domain deliberately implements the two that
are honestly practical on the low-power hardware this platform actually
deploys (the documented real test device across this codebase is a
MikroTik hEX lite):

* **DNS sinkhole** (``/ip dns static``) for a blocked *domain* -- guest
  devices already receive this router's own address as their DNS server
  (see ``app.domains.network_config.renderers``'s own "Hotspot dns-name"
  section for where that's established), so answering a blocked domain's
  lookup with an address that goes nowhere useful (this platform's own
  loopback, ``127.0.0.1``) stops the connection before it starts, with
  effectively zero per-packet CPU cost -- RouterOS answers the query
  once, from a small static table, the same mechanism ``app.domains.dns``
  already uses for ordinary local DNS records.
* **Address-list + one shared firewall-filter DROP rule**
  (``/ip firewall address-list`` + ``/ip firewall filter``) for a blocked
  *IP/CIDR* -- the simplest, most commonly real-world-deployed approach
  for blocking a known-bad destination by address, and RouterOS's own
  address-list membership check is a cheap hash lookup, not a per-rule
  linear scan.

**Deliberately not implemented, and why:**

* **Layer7 protocol matching** (``/ip firewall layer7-protocol`` + regex
  matching against every packet's payload) is real, but expensive on
  exactly this hardware class -- the same honest performance concern this
  codebase already documents elsewhere (e.g. the ISP health-check
  sweep's own sequential-load reasoning). A hEX lite's CPU budget is not
  where per-packet regex matching belongs for a "block guest social
  media" feature that DNS-level blocking already covers for the
  overwhelming majority of real guest devices.
* **Web-proxy** (``/ip proxy`` + ``/ip proxy access``) only sees
  unencrypted HTTP content -- essentially none of the real, popular sites
  a college/PG/hostel customer actually wants blocked (social media,
  streaming, gambling, adult content) are served over plain HTTP today,
  so a transparent proxy would filter almost nothing a real deployment
  cares about.
* **TLS interception (HTTPS MITM) is a hard, non-negotiable exclusion.**
  Decrypting guest HTTPS traffic to inspect it is a real security/privacy/
  trust problem this product must never build, regardless of how it would
  extend this feature's coverage -- see this module's own task brief for
  the explicit scope boundary.

**The one real, honest limitation of DNS-based blocking, stated plainly
rather than glossed over:** a guest device that manually configures a
different DNS resolver (a public one, or DNS-over-HTTPS/TLS) bypasses the
sinkhole entirely. This is a known, real limitation of DNS-based content
filtering everywhere it is deployed, not unique to this implementation --
and it is still the honest, practical mechanism for the overwhelming
majority of real guest devices, which use whatever DNS server DHCP hands
them. An admin who additionally wants to force all guest DNS traffic
through the router (blocking outbound port 53 to anything else) already
has the general-purpose tool to do that -- ``app.domains.firewall`` -- and
this domain deliberately does not duplicate that capability itself.

## Live device push

``POST /content-filter-rules/{id}/push`` realizes one rule on its own
router over the RouterOS API, per rule -- see ``service.py``'s own module
docstring for why per-rule and not per-router, and
``wyfy_device_gateway.mikrotik_adapter.configure_content_filter_rule``
for the exact objects each mechanism above becomes. This section
previously said the opposite ("no live device push in this pass ... real
RouterOS provisioning happens through ``app.domains.network_config``'s
existing push pipeline"), and that pipeline had no caller for these rules
at all. The result was a feature that reported a security property it did
not have: a customer blocked a site, the dashboard said blocked, and
every guest on that router kept reaching it.
"""

from __future__ import annotations
