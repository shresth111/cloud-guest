"""DNS Management domain: per-router static DNS record inventory (A/AAAA/
CNAME entries RouterOS's own ``/ip dns static`` serves).

A pure inventory/rules domain -- no ``device_adapters.py``, no live device
push. Mirrors ``app.domains.dhcp``/``app.domains.vlan``'s own "config
resource, realized onto a device later by a provisioning pass" precedent
(real RouterOS static-DNS provisioning happens through
``app.domains.network_config``'s existing push pipeline, not this one).
"""

from __future__ import annotations
