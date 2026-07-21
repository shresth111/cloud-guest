"""Device Synchronization domain: an honest orchestrator over every
*real* per-router sync mechanism this codebase already has, plus an
immutable Sync History log of each orchestrated attempt.

## Honest scope -- composes what's real, never fabricates the rest

This domain triggers/reports exactly three real, already-existing
mechanisms, never re-implementing any of them:

* ``app.domains.connected_devices.service.ConnectedDeviceService
  .sync_router`` -- real DHCP-lease/ARP/wireless-registration-table sync.
* ``app.domains.queue_management.service.QueueManagementService
  .reapply_assignments_for_router`` -- a new bulk method added to that
  domain specifically for this orchestrator, itself composing that
  domain's own real, pre-existing ``reset_queue`` per assignment.
* ``app.domains.provisioning_engine.service.ProvisioningEngineService
  .list_jobs`` -- a read-only status check against the real
  ``ProvisionJob`` history for this router.

DHCP/VLAN/Port Forwarding have **no** real device push anywhere in this
codebase today (confirmed: no ``device_adapters.py`` in any of those
three domains) -- their own docs already document this as deliberately
deferred to the not-yet-built Network Configuration Management domain
(roadmap item #11), which will own real config-versioning/rollback
provisioning for exactly those domains. This orchestrator therefore
reports those three components as ``not_provisioned`` -- a real,
accurate status -- rather than fabricating a device push that doesn't
exist, and never preempts or duplicates that future domain's own scope.

See ``docs/device_sync/FLOW.md`` for the full design write-up.
"""

from __future__ import annotations
