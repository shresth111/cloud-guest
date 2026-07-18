# RBAC Permission Matrix

Generated directly from `app/domains/rbac/seed.py` (`SYSTEM_ROLES` x `MODULE_ACTIONS`) -- do not hand-edit the table below. Regenerate with:

```bash
cd backend
python -c "from app.domains.rbac.seed import generate_permission_matrix_markdown as g; print(g())" > docs/rbac/PERMISSION_MATRIX.md
```

Cell values are the *default grant level* for that role x module pair: `-` (none), `R` (read-only), `O` (operate: applicable actions minus Manage/Delete), or `F` (full: every applicable action for that module). See `RBAC_ARCHITECTURE.md` for what each level expands to.

| Role | Scope | Dashboard | Users | Roles | Permissions | Organizations | Locations | Routers | Router Provisioning | Templates | Captive Portal | Guest WiFi | Guest Users | Guest Sessions | OTP | Voucher | Campaigns | Radius | WireGuard | Firewall | DHCP | DNS | Hotspot | Bandwidth | Analytics | Reports | Monitoring | Alerts | Notifications | Billing | Invoices | Subscriptions | White Label | API Keys | Audit Logs | System Settings | AI Assistant |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Super Admin | global | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F |
| Platform Admin | global | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | O | F | F | O | F |
| Platform Support | global | R | O | R | R | R | R | R | R | R | R | R | O | O | R | R | R | R | R | R | R | R | R | R | R | R | O | O | O | R | R | R | R | R | R | R | R |
| Billing Manager | global | R | - | - | - | R | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | R | - | - | - | F | F | F | - | - | - | - | - |
| MSP Owner | organization | O | F | F | O | F | F | F | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | - | O | - | O |
| MSP Admin | organization | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | R | O | O | O | - | O | - | O |
| Organization Owner | organization | F | F | O | R | R | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | O | O | R | O | O | F | - | F |
| Organization Admin | organization | O | O | R | R | R | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | O | R | R | R | R | - | O | - | O |
| Network Administrator | location | R | - | - | - | - | R | F | F | O | O | - | - | - | - | - | - | F | F | F | F | F | F | F | R | R | F | O | - | - | - | - | - | - | - | - | - |
| Location Manager | location | R | - | - | - | - | O | - | - | - | O | O | O | O | O | O | O | - | - | - | - | - | R | - | R | R | R | R | O | - | - | - | - | - | - | - | - |
| Reception Staff | location | R | - | - | - | - | - | - | - | - | - | - | O | O | O | O | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| Helpdesk | location | R | - | - | - | - | - | - | - | - | - | - | R | O | - | R | - | - | - | - | - | - | - | - | - | - | R | R | R | - | - | - | - | - | - | - | - |
| Read Only | organization | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | - | R |
| Auditor | organization | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | F | - | R |
| Guest Operator | location | R | - | - | - | - | - | - | - | - | - | O | O | O | O | O | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |

## Module -> Applicable Actions

| Module | Applicable actions |
|---|---|
| Dashboard | view |
| Users | create, read, update, delete, export, import, assign, manage |
| Roles | create, read, update, delete, assign, manage |
| Permissions | read, assign, manage |
| Organizations | create, read, update, delete, manage |
| Locations | create, read, update, delete, manage |
| Routers | create, read, update, delete, manage, execute |
| Router Provisioning | create, read, update, delete, execute, approve, manage |
| Templates | create, read, update, delete, export, import, manage |
| Captive Portal | create, read, update, delete, manage |
| Guest WiFi | create, read, update, delete, manage |
| Guest Users | create, read, update, delete, export, manage |
| Guest Sessions | read, delete, export, execute, manage |
| OTP | create, read, execute, manage |
| Voucher | create, read, update, delete, export, import, approve, manage |
| Campaigns | create, read, update, delete, approve, export, manage |
| Radius | create, read, update, delete, manage |
| WireGuard | create, read, update, delete, execute, manage |
| Firewall | create, read, update, delete, execute, manage |
| DHCP | create, read, update, delete, manage |
| DNS | create, read, update, delete, manage |
| Hotspot | create, read, update, delete, manage, execute |
| Bandwidth | read, update, manage |
| Analytics | read, export, view |
| Reports | read, export, view, manage |
| Monitoring | read, view, manage |
| Alerts | read, update, delete, view, manage |
| Notifications | read, update, delete, manage |
| Billing | read, update, export, manage |
| Invoices | create, read, update, delete, export, approve, manage |
| Subscriptions | create, read, update, delete, manage |
| White Label | read, update, manage |
| API Keys | create, read, delete, manage |
| Audit Logs | read, export, view |
| System Settings | read, update, manage |
| AI Assistant | read, execute, view, manage |

