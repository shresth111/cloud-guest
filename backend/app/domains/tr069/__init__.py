"""TR-069 / CWMP control plane over GenieACS (API_CONTRACT §5-6).

GenieACS 1.2.x runs unmodified as a separate process; this domain is the
multi-tenant layer over its NBI. CPE authentication happens at the nginx edge
through ``internal_router`` (``/internal/tr069/acs-auth``). Isolation lives
only in ``tr069_devices``: tags in GenieACS are written for ops and never
trusted for authorization.

* ``config`` -- ``TR069_*`` settings (own BaseSettings);
* ``credentials`` -- minting, hashing and encrypting ACS credentials;
* ``nbi_client`` -- httpx client, timeouts, 502 mapping;
* ``params`` -- curated TR-181/TR-098 paths with a password denylist;
* ``sync`` -- sync-on-read of an ISP's devices;
* ``script`` -- the MikroTik ``/tr069-client`` script;
* ``service`` / ``router`` / ``internal_router`` -- the HTTP surface.
"""
