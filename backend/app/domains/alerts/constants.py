"""Constants for the Alerts domain."""

# Alert Severities
SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

# Alert Statuses
STATUS_ACTIVE = "active"
STATUS_ACKNOWLEDGED = "acknowledged"
STATUS_RESOLVED = "resolved"

# Alert Categories
CATEGORY_SYSTEM = "system"
CATEGORY_ROUTER = "router"
CATEGORY_NETWORK = "network"
CATEGORY_SECURITY = "security"

# Alert Types
TYPE_ROUTER_OFFLINE = "router_offline"
TYPE_ROUTER_ONLINE = "router_online"
TYPE_HEARTBEAT_MISSING = "heartbeat_missing"
TYPE_HIGH_CPU = "high_cpu"
TYPE_HIGH_MEMORY = "high_memory"
TYPE_HIGH_DISK = "high_disk"
TYPE_HIGH_TEMP = "high_temperature"
TYPE_HIGH_BANDWIDTH = "high_bandwidth"
TYPE_VPN_DOWN = "vpn_down"
TYPE_FREERADIUS_DOWN = "freeradius_down"
TYPE_DATABASE_DOWN = "database_down"
TYPE_REDIS_DOWN = "redis_down"
TYPE_API_FAILURE = "api_failure"
