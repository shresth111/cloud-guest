"""DNS filtering: web-category blocking through Cloudflare Gateway.

The honest path PRD §11.1 option A and §17 recommend: category filtering
needs a maintained category database and a resolver that applies it, and
RouterOS has neither. So the venue's router forwards its DNS to a
Cloudflare Gateway DoH endpoint -- one per distinct category selection,
shared by every venue that chose it -- and the categories are enforced by
Gateway DNS policies this platform manages.

* ``cloudflare_client`` -- the Gateway API (categories, locations, rules).
* ``service`` -- profiles shared across venues (one Gateway location and
  one rule per distinct category set, not per router or venue), the
  configurable location cap, moving routers between sets, and the
  enable/disable lifecycle.
* ``device_adapters`` -> ``wyfy_device_gateway.mikrotik_dns_filtering`` --
  the whole-router resolver switch with snapshot, read-back, probe and
  rollback, and the opt-in DoT/DoH bypass hardening.

MikroTik only. A controller-managed venue (TP-Link Omada) is refused, as
every other device-security feature refuses it.

Static DNS (``/ip dns static``, where ``content_filtering``'s sinkhole
lives) is never touched and keeps answering first: the platform's own
domain blocks and Gateway's categories stack.
"""
