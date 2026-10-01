"""Security activity -- what a venue's protections actually did.

Split from ``app.domains.security`` on purpose. That domain is read-only by
construction and a test enforces it (no session writes, no device I/O in its
package). Counting what protections did needs both: an hourly Celery
collector reads each router's own rule hit counters over 8728 and stores them
here. The read uses ``wyfy_device_gateway.read_only_reader
.ReadOnlyDeviceReader``, which can only issue ``print`` reads of an allowlist
of paths -- **nothing in this domain writes to a router**.

* ``classify`` -- which router rows belong to which protection (pure).
* ``service.SecurityCounterCollector`` -- one router's read, diffed into
  hourly deltas.
* ``service.SecurityActivityService`` -- the ``GET /security/activity`` view.
* ``tasks`` -- the staggered hourly sweep.
"""

__all__: list[str] = []
