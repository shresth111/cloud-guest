"""Device Logs: syslog that venue devices send to the platform.

Design: ``~/wyfy-ops/syslog/DESIGN.md`` (decisions, sizing, retention,
privacy, hardware test plan). In one paragraph:

MikroTik routers send RFC 3164 syslog over UDP **inside their WireGuard
tunnel** to the hub's tunnel address; the hub DNATs it to a Vector collector
on the app server, which (a) archives every raw line and (b) posts throttled
batches to ``POST /internal/device-logs/ingest``. This domain parses each
line, attributes it to a router by **source tunnel IP** (unforgeable inside
WireGuard, because ``AllowedIPs`` is a cryptographic filter), masks phone
numbers and e-mail addresses, and stores it in ``device_log_events`` for the
Master-console viewer. The per-router ``wyfy-<tag>`` prefix only cross-checks
attribution; it never establishes it.

Everything is gated on ``Settings.device_logs_enabled`` (default False).
Omada and Aruba Instant On are deliberately not built yet; the event model
carries ``vendor``/``source`` so they land in the same table later. Aruba
Instant On cannot send syslog at all -- never label its feed as syslog.
"""
