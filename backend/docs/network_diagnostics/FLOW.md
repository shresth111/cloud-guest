# Network Diagnostics -- Design Notes

## 0. A genuinely different shape from the other 12 roadmap domains

Before writing any code, research confirmed this domain is not another
"config resource" (DHCP/VLAN/Port Forwarding/Hotspot/QoS -- a static
inventory table, realized onto a device later). "Network Diagnostics" is
a real-time **execution** domain: an admin asks for a `ping`/
`traceroute` right now and expects a real result in the same HTTP
response. This changes which existing mechanism is the right one to
compose.

## 1. Why `app.domains.router_agent`'s job queue was rejected

`router_agent`'s `GET /agent/actions`/`POST /agent/actions/{id}/complete`
is a real, working **pull-model** queue -- but it exists entirely to
drain `app.domains.router_provisioning.models.ProvisioningJob` rows
(`job_type` is a closed enum: `initial_config`/`config_push`/`backup`/
`restore`/`factory_reset`), with a retry/`max_attempts`/terminal-status
state machine built for idempotent, retryable, config-mutating
operations. Two real mismatches rule it out for this domain:

1. **Timing.** A device polls `GET /agent/actions` on its own cadence;
   nothing in that module drives a synchronous "wait for this specific
   job to finish" flow. An admin clicking "ping this router" cannot be
   satisfied by "whenever the device's agent next happens to poll."
2. **Semantics.** A `ping`/`traceroute` is not a retryable, durable,
   config-mutating action -- forcing it into `ProvisioningJobType` would
   mean editing that already-complete domain's closed enum and status
   transitions for a concept (an ephemeral read, not a device-state
   change) that doesn't actually fit its model.

## 2. Ping: mirrored from `app.domains.isp`, not imported at runtime

A full-tree grep found exactly one pre-existing ping-shaped capability
anywhere in this codebase: `app.domains.isp.device_adapters
.MikroTikIspHealthAdapter.ping` (used for WAN-uplink health checks, real
`/tool/ping` command, real reply parsing). Its command string and
reply-parsing logic (read the *last* cumulative reply row for `sent`/
`received`/`packet-loss`/`avg-rtt`; a small real parser for RouterOS's
own duration-string format, e.g. `"1ms200us"`) is exactly correct and is
**mirrored** into this domain's own `device_adapters.py` rather than
imported at runtime. Depending on `app.domains.isp` at runtime for a
capability that has nothing to do with ISP links would itself be a real
architectural mismatch -- this domain would need to construct/inject
ISP's own credential and adapter types for a concept (a generic,
any-router diagnostic) it doesn't actually share with WAN-link health
monitoring. Mirroring the already-correct logic once, and explaining why
here, was judged better than either duplicating it silently or coupling
two unrelated domains.

## 3. Traceroute: genuinely new, honestly described as an interpretation

A full-tree grep confirmed zero existing traceroute/bandwidth-test
implementation anywhere in this codebase. RouterOS's own
`/tool/traceroute` streams reply rows the same way `/tool/ping` does --
repeated, cumulative updates for one hop before moving to the next --
but there is no verified, documented reply-field name in this codebase
for an explicit hop number. `_parse_traceroute_rows` therefore collapses
consecutive same-`address` rows into one final `TracerouteHop` each,
numbering hops by their position in the reply stream (the same order a
real traceroute discovers them in) -- a defensible, honestly-described
interpretation of the real reply shape, not a fabricated one. This is
called out explicitly in `device_adapters.py`'s own module docstring
rather than presented as verified fact.

## 4. Every attempt is recorded -- a device failure is a real outcome, not an error

`run_ping`/`run_traceroute` catch
`DiagnosticsDeviceConnectionError`/`DiagnosticsDeviceOperationError` and
record a `FAILED` `DiagnosticRun` with the real error message, rather
than letting the exception propagate as a bare HTTP 502 that discards
the attempt. "This router could not be reached" *is* the diagnostic
result an admin asked for -- losing it to an unhandled exception would
defeat the domain's own purpose. `MissingDiagnosticsCredentialsError` (a
configuration problem -- the router has no stored management IP/
username/secret at all) is the one exception that still raises directly,
mirroring `app.domains.isp.exceptions.IspMissingCredentialsError`'s
identical posture: a missing credential is not a diagnostic outcome to
record, it is a setup problem to fix first.

## 5. `status`: did the diagnostic execute, not "was the target reachable"

`DiagnosticRun.status` is `SUCCESS` whenever a real result was obtained
from the device -- including a ping with 100% packet loss, or a
traceroute where every hop timed out. Reachability itself is a property
of the *result* (`result.packet_loss_percentage`, `result.hops`), not of
whether the diagnostic could execute. Conflating "target unreachable"
with "diagnostic failed" would require inventing a reachability
threshold this domain has no real basis for (unlike
`app.domains.isp.validators.classify_health_status`, which has a real,
documented threshold *for WAN-link failover decisions specifically* --
a concern this domain does not share).

## 6. RBAC: a genuinely new permission module, no unclaimed fit

No pre-existing, unclaimed `PermissionModule` fits "run a live diagnostic
against one router" -- confirmed by grepping `rbac/enums.py` before
adding one, per this session's own established discipline.
`PermissionModule.NETWORK_DIAGNOSTICS` was minted fresh, mirroring
`PermissionModule.DEVICE_SYNC`'s exact `(READ, EXECUTE, MANAGE)` shape
(no `CREATE`/`UPDATE`/`DELETE`, since `DiagnosticRun` rows are immutable
and only ever created by running a diagnostic itself). The pre-existing
"Network Administrator" role gains a `FULL` override.

## 7. Not composed into Network Configuration Management

Unlike Hotspot Settings/QoS (composed into `app.domains.network_config`
as rendered categories the moment they were built), this domain owns no
config to render -- there is nothing here that becomes part of a
router's desired-state `ConfigVersion`. It is therefore never composed
into that pipeline; its own history table is the complete picture.
