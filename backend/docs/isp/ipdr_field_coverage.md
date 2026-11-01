# IPDR field coverage (DoT parameter list)

Generated from `app/domains/isp_partner/ipdr_lea.py::FIELD_COVERAGE` (IPDR-2, ADDENDUM_06).
The API serves the same list at `GET /isp/compliance/ipdr-field-coverage`. Fields that are
partial or not collected are reported as missing in every export; nothing is filled in or inferred.

| Field | Status | Source / note |
|---|---|---|
| Subscriber user id / login | available | guest session identifier; isp_subscribers.identifier |
| Subscriber name, address, phone, email | available | isp_subscribers + JAZE-3 KYC (installation / permanent address) |
| ID proof type and number | partial | KYC: type + masked number only. Aadhaar is stored as last 4 digits; the full number is never held, so it can never be produced. |
| Gender / date of birth | partial | KYC gender / date_of_birth, only when the ISP collected them; empty otherwise (never inferred). |
| Device MAC address | available | guest device MAC; DHCP lease MAC when the session has none |
| Private (source) IP and port | available | traffic_flow_records.src_address / src_port |
| Public (translated) IP and port | partial | router NAT events (nat_source=nat_event). When the router exports flows without NAT fields the port is derived or ambiguous, and the report says so. |
| Destination IP and port | available | traffic_flow_records.dst_address / dst_port |
| Protocol | available | traffic_flow_records.protocol |
| Connection start / end time (event) | partial | flow_start / flow_end from the router. Not every exporter sends them; when absent the event time is reported as missing, never replaced by receipt time. |
| Record receipt time | available | traffic_flow_records.arrived_at (collector window as fallback, labelled) |
| IP lease allocate / release time | partial | guest session start / end, or the DHCP lease window where synced |
| NAS / router identity | available | router name and id; NAS client for PPPoE |
| NAS port / interface | partial | PPPoE NAS-Port-Id (JAZE-6). Hotspot sessions do not record one. |
| IPv6 delegated prefix | partial | PPPoE Delegated-IPv6-Prefix when the NAS sends it; hotspot is IPv4 only |
| Bytes up / down | available | flow bytes; session byte counters |
| Router clock skew (NTP) | not_collected | No per-router NTP offset is polled today; compare event and receipt times (gap flag) instead. |
| Cell / tower / location of the user | not_applicable | Fixed-line and hotspot service; the installation address is the location. |

## Time

- **Event time** = the router's own timestamp (`traffic_flow_records.flow_start`). When the router did not send one, it is reported as missing.
- **Receipt time** = `traffic_flow_records.arrived_at` (the collector window only when `arrived_at` is missing, labelled `collector_window`).
- Both are shown in IST. Receipt time never stands in for event time. Rows where receipt lags the event by more than N minutes (default 5) are flagged.

## Retention

Target: 730 days. `GET /isp/compliance/retention` reports, per router, the oldest NAT row, the oldest session row, and the days in the window with zero NAT rows while the router was up (it sent a health snapshot).

Never pruned: `guest_sessions`, `guest_login_history`, `otp_requests`, `audit_log_entries`, `login_attempts`, `traffic_flow_records`.

## Identity

Aadhaar: only the last 4 digits are stored (J6). The LEA report prints the masked number only, because the full number is never held.
