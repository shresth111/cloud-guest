"""IPDR: per-connection records in the Indian ISP / CERT-In IPDR column
format (minus Address), built from Traffic Lens flow records joined to guest
sessions, archived per (organization, location, IST day) for 2 years.

Read ``~/wyfy-ops/ipdr/DESIGN.md`` before changing anything here. In short:

* ``join`` -- pure: stitch flow records into connections, match the session
  that held the address, mark ambiguous translations;
* ``translation`` -- where Translated IP/Port come from (observed NAT event,
  derived from the router's public address, ambiguous, none);
* ``builder`` -- one location's records for a window, the nightly archive
  of closed IST days;
* ``archive`` -- gzip NDJSON in S3 (``ipdr/``) or a local directory;
* ``service`` / ``router`` -- the masked Connections list (``ipdr.read``)
  and the unmasked CSV (``ipdr.export``), both ORGANIZATION-scoped and
  audited.

This is PII for law-enforcement requests. The CSV is the only place a full
phone number or email appears.
"""
