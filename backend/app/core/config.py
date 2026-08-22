from functools import lru_cache
from pathlib import Path

from pydantic import Field, PostgresDsn, RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="CLOUDGUEST_",
        case_sensitive=False,
        extra="ignore",
    )

    environment: str = Field(default="local", min_length=2)
    debug: bool = False
    service_name: str = "cloudguest-backend"
    api_v1_prefix: str = "/api/v1"
    allowed_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "https://wyfyguest.com",
            "https://www.wyfyguest.com",
            "https://app.wyfyguest.com",
            "https://portal.wyfyguest.com",
        ]
    )

    database_url: PostgresDsn = Field(
        default="postgresql+asyncpg://cloudguest:cloudguest@localhost:5432/cloudguest"
    )
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=100)
    database_pool_timeout: int = Field(default=30, ge=1, le=120)

    pagination_default_page_size: int = Field(
        default=25,
        ge=1,
        le=1000,
        description=(
            "Default page_size for app.database.utils.pagination.PageParams "
            "when a caller doesn't specify one. Enterprise SaaS Phase G: "
            "was previously a hardcoded app.database.constants.DEFAULT_PAGE_SIZE "
            "module constant -- moved to Settings per this codebase's own "
            "'every tunable is a documented Settings field' convention."
        ),
    )
    pagination_max_page_size: int = Field(
        default=100,
        ge=1,
        le=1000,
        description=(
            "Hard ceiling PageParams clamps page_size to, regardless of what "
            "a caller requests. Was previously app.database.constants"
            ".MAX_PAGE_SIZE -- see pagination_default_page_size's own note."
        ),
    )

    redis_url: RedisDsn = Field(default="redis://localhost:6379/0")
    redis_health_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    jwt_secret_key: str = Field(
        default="insecure-local-dev-secret-key-change-me-32chars",
        min_length=32,
        description=(
            "Secret key used to sign auth JWTs. Must be overridden in every "
            "non-local environment."
        ),
    )
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=15, ge=1, le=1440)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=90)
    max_login_attempts: int = Field(default=5, ge=1, le=100)
    account_lockout_minutes: int = Field(default=30, ge=1, le=1440)
    password_history_limit: int = Field(default=5, ge=0, le=50)

    log_level: str = "INFO"
    log_dir: Path = Path("logs")
    log_file: str = "cloudguest.log"
    log_max_bytes: int = Field(default=10_485_760, ge=1_048_576)
    log_backup_count: int = Field(default=10, ge=1, le=100)

    request_timeout_seconds: int = Field(default=30, ge=1, le=300)

    rbac_permission_cache_ttl_seconds: int = Field(
        default=300,
        ge=1,
        le=86_400,
        description=(
            "TTL for the Redis-backed effective-permission cache "
            "(app.domains.rbac.cache.PermissionCache). Real invalidation "
            "happens on every role/permission/override mutation; this TTL "
            "is only a backstop against a missed invalidation."
        ),
    )
    billing_entitlement_cache_ttl_seconds: int = Field(
        default=120,
        ge=1,
        le=86_400,
        description=(
            "TTL for the Redis-backed entitlement-snapshot cache "
            "(app.domains.billing.cache.EntitlementCache). Real invalidation "
            "happens on every License mutation (assign/activate/suspend/"
            "cancel/expire/upgrade/downgrade); this TTL is only a backstop "
            "against a missed invalidation and against a Plan/PlanFeature "
            "catalog edit (which does not fan out to affected organizations)."
        ),
    )
    captive_portal_resolve_cache_ttl_seconds: int = Field(
        default=60,
        ge=1,
        le=86_400,
        description=(
            "TTL for the Redis-backed captive-portal resolve cache "
            "(app.domains.captive_portal.cache.CaptivePortalResolveCache). "
            "GET /captive-portal/resolve is guest-device-facing, unauthenticated, "
            "hit-on-every-WiFi-join traffic against config that changes rarely "
            "(an admin editing branding/login-method toggles) -- caching it is a "
            "clear win. Real invalidation happens on every "
            "create/update/activate/deactivate/delete of the exact "
            "(organization_id, location_id) captive-portal config mutated; this "
            "TTL is only a backstop against a missed invalidation and against an "
            "organization-level default change (which does not fan out to every "
            "location under that org lacking its own override), mirroring "
            "billing_entitlement_cache_ttl_seconds's identical documented "
            "trade-off."
        ),
    )
    captive_portal_resolve_negative_cache_ttl_seconds: int = Field(
        default=10,
        ge=1,
        le=3_600,
        description=(
            "TTL for a *negative* captive-portal resolve result -- a "
            "location/organization that resolved to "
            "CaptivePortalConfigNotConfiguredError (design spec §5 S10). "
            "Deliberately far shorter than "
            "captive_portal_resolve_cache_ttl_seconds: a negative result "
            "is almost always an admin mid-setup, and the cost of being "
            "wrong is asymmetric. Caching it too long means an operator "
            "who just configured a venue watches the portal keep saying "
            "'not configured'; caching it briefly means a misconfigured "
            "location stops replaying the full resolution walk on every "
            "guest device that joins. Real invalidation still happens on "
            "config create, so this TTL only backstops the window before "
            "that write."
        ),
    )
    branding_asset_cache_ttl_seconds: int = Field(
        default=3600,
        ge=1,
        le=604_800,
        description=(
            "Browser Cache-Control max-age for the branding logo/background-"
            "image serving endpoints (app.domains.branding.router's raw/"
            "public GET endpoints) -- notably the unauthenticated "
            ".../logo/public and .../background-image/public paths "
            "GET /captive-portal/resolve points a guest's browser at on "
            "every WiFi join. These bytes are content-addressed (a fresh "
            "object-storage key is written on every re-upload, the row's "
            "own *_key column repointed to it -- the old key's bytes never "
            "mutate in place), so every response also carries a strong "
            "ETag hashed from the real bytes returned; a client revisiting "
            "after this TTL expires still gets a cheap 304 instead of a "
            "full re-download whenever the underlying image hasn't "
            "actually changed. This TTL only bounds how long a re-upload "
            "can take to reach a browser that cached the *previous* image "
            "and hasn't revisited since -- not correctness, since the "
            "ETag always reflects the real current bytes on any request "
            "that does reach the server."
        ),
    )
    rbac_max_parent_role_depth: int = Field(
        default=10,
        ge=1,
        le=50,
        description=(
            "Maximum number of parent_role_id hops walked when resolving "
            "recursive role-permission inheritance. A defensive backstop "
            "against any cycle that slips past the service-layer check."
        ),
    )

    router_encryption_key: str = Field(
        default="aW5zZWN1cmUtbG9jYWwtZGV2LWZlcm5ldC1rZXkzMiE=",
        min_length=32,
        description=(
            "App-level symmetric key (Fernet, urlsafe-base64) used by "
            "app.domains.router.crypto to encrypt/decrypt RouterOS API "
            "connection credentials at rest. Must be overridden with a real "
            "Fernet key (Fernet.generate_key()) in every non-local "
            "environment -- this is an interim design pending a real "
            "secrets-manager/KMS integration (see "
            "docs/router/ROUTER_ARCHITECTURE.md)."
        ),
    )
    router_provisioning_token_expire_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description=(
            "How long a generated zero-touch-provisioning bearer token "
            "remains valid before a device must have it regenerated."
        ),
    )
    wireguard_handshake_stale_after_minutes: int = Field(
        default=5,
        ge=1,
        le=1440,
        description=(
            "How long since a WireGuard peer's last device-reported "
            "handshake (app.domains.wireguard) before its computed "
            "health status flips from 'healthy' to 'stale'. There is no "
            "live 'wg show' integration in this sandbox -- this is a "
            "DB-tracked, device-reported signal, the same honest interim "
            "posture app.domains.router.models.Router.health_status "
            "already documents. Five minutes is roughly double WireGuard's "
            "own ~2-minute keepalive/handshake-renegotiation cadence, so a "
            "single missed report does not immediately read as unhealthy."
        ),
    )

    hub_wg_agent_url: str = Field(
        default="http://10.30.2.10:9091/wg/peer",
        description=(
            "Absolute URL of the hub's WireGuard peer-provisioning agent "
            "(ops/hub-agents/wg_agent.py, port 9091), called by "
            "app.domains.wireguard.router.allocate_external_wireguard_peer. "
            "Was a module-level constant hardcoded to the OLD hub's public "
            "IP (20.219.72.235); that host was deleted with its subscription "
            "and every venue provisioning hung to timeout until this moved "
            "here. Defaults to the hub's VNET-PRIVATE address so the call "
            "and its shared secret never leave the VNet -- the transport is "
            "plain HTTP. Do not point this at a public IP or hostname."
        ),
    )
    hub_wg_agent_secret: str = Field(
        default="",
        description=(
            "Shared secret sent as the X-Agent-Secret header to "
            "hub_wg_agent_url. Must equal WG_AGENT_SECRET in the hub's "
            "/etc/wyfy/hub-agents.env -- the agent compares with !=, so any "
            "skew is a hard 401, never a degraded mode; rotate both sides "
            "together. Empty = unconfigured: the agent also rejects an empty "
            "secret, so a blank value fails closed rather than open. The "
            "previous value was committed in cleartext in this repo and has "
            "been rotated."
        ),
    )
    hub_radius_agent_url: str = Field(
        default="http://10.30.2.10:9092/radius/client",
        description=(
            "Absolute URL of the hub's FreeRADIUS client-provisioning agent "
            "(ops/hub-agents/radius_agent.py, port 9092), called by "
            "app.domains.guest.router.register_external_radius_nas. See "
            "hub_wg_agent_url for why this is private-address-by-default and "
            "why it stopped being a constant."
        ),
    )
    hub_radius_agent_secret: str = Field(
        default="",
        description=(
            "Shared secret sent as the X-Agent-Secret header to "
            "hub_radius_agent_url. See hub_wg_agent_secret -- same rotation "
            "and fail-closed rules."
        ),
    )

    snmp_default_community: str = Field(
        default="",
        description=(
            "Platform-wide default SNMP community string -- used by "
            "app.domains.provisioning_engine.service"
            ".run_router_snmp_metrics_poll_sweep for a router that has "
            "snmp_enabled=True but no per-router "
            "Router.snmp_community_encrypted override configured (mirrors "
            "stripe_secret_key/razorpay_key_id's own 'empty = "
            "unconfigured' posture). Empty = unconfigured: a router with "
            "snmp_enabled and no community anywhere (neither per-router "
            "nor this default) is honestly skipped by the sweep, never "
            "guessed at a fabricated default like the well-known "
            "'public'. Override via CLOUDGUEST_SNMP_DEFAULT_COMMUNITY in "
            "any real deployment that wants a single shared community "
            "across its fleet rather than configuring one per router."
        ),
    )
    snmp_default_version: str = Field(
        default="2c",
        description=(
            'Platform-wide default SNMP protocol version ("1" or '
            '"2c" -- see wyfy_device_gateway.snmp_poller\'s own module '
            "docstring for why SNMPv3 is out of scope), used when a "
            "router has no per-router Router.snmp_version override."
        ),
    )
    snmp_default_port: int = Field(
        default=161,
        ge=1,
        le=65535,
        description=(
            "Platform-wide default SNMP agent UDP port (161 is the real "
            "IANA-assigned SNMP port), used when a router has no "
            "per-router Router.snmp_port override."
        ),
    )
    snmp_poll_timeout_seconds: int = Field(
        default=5,
        ge=1,
        le=60,
        description=(
            "Per-request UDP timeout for "
            "wyfy_device_gateway.snmp_poller.SnmpPoller -- an SNMP "
            "request has no TCP connection-level timeout to fall back on "
            "(it's a connectionless UDP request/reply), so this is the "
            "one real, honest bound on how long the SNMP metrics-poll "
            "sweep waits for a single router's reply before treating it "
            "as unreachable."
        ),
    )

    otp_code_length: int = Field(
        default=6,
        ge=4,
        le=10,
        description=(
            "Number of digits in a generated OTP code "
            "(app.domains.otp.service.generate_numeric_code)."
        ),
    )
    otp_expiry_seconds: int = Field(
        default=300,
        ge=30,
        le=3600,
        description=(
            "How long a generated OTP code remains valid "
            "(app.domains.otp.models.OtpRequest.expires_at) before "
            "app.domains.otp.exceptions.OtpExpiredError is raised."
        ),
    )
    otp_max_verification_attempts: int = Field(
        default=5,
        ge=1,
        le=20,
        description=(
            "Maximum times a single OTP code may be guessed "
            "(OtpRequest.attempt_count vs. max_attempts) before it locks "
            "itself out (OtpAttemptsExceededError) -- mirrors "
            "max_login_attempts's identical per-secret brute-force cap, "
            "distinct from the request-level throttle below."
        ),
    )
    otp_max_requests_per_window: int = Field(
        default=5,
        ge=1,
        le=100,
        description=(
            "Maximum number of new OTP codes a single identifier "
            "(phone/email) may request within otp_request_window_minutes "
            "(app.domains.otp.service.OtpRateLimiter, Redis-backed) -- "
            "protects the delivery channel from spam, distinct from "
            "otp_max_verification_attempts's per-code brute-force cap."
        ),
    )
    otp_request_window_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description=(
            "Rolling window (minutes) otp_max_requests_per_window is "
            "measured over -- mirrors account_lockout_minutes's identical "
            "naming/style for a Redis-backed rate window."
        ),
    )

    # ========================================================================
    # BE-012 Part 4: Forecast Engine + Insight Engine thresholds
    #
    # Every number the Forecast Engine (app.domains.analytics.forecast) and
    # Insight Engine (app.domains.analytics.insights) compare a real,
    # computed value against lives here, following this file's own
    # established pattern (a plain, documented Settings field, never a
    # hardcoded magic number inline in analytics code) -- see
    # docs/analytics/FLOW.md for the exact rule/threshold cross-reference.
    # None of these change what data is real; they only tune when a real
    # linear-regression trend or rule-engine comparison is judged
    # "significant enough to report".
    # ========================================================================

    analytics_forecast_history_days: int = Field(
        default=30,
        ge=3,
        le=365,
        description=(
            "How many trailing days of ORG_DAILY_SUMMARY/LOCATION_DAILY_"
            "SUMMARY AnalyticsSnapshot history feed the Forecast Engine's "
            "linear-trend fit (bandwidth/guest-growth/network-load/capacity "
            "forecasts) -- app.domains.analytics.forecast_service."
            "ForecastService."
        ),
    )
    analytics_forecast_default_days: int = Field(
        default=7,
        ge=1,
        le=90,
        description=(
            "Default number of days a Forecast Engine endpoint projects "
            "forward when the caller omits the forecast_days query "
            "parameter."
        ),
    )
    analytics_forecast_min_history_points: int = Field(
        default=3,
        ge=2,
        le=90,
        description=(
            "Minimum number of real historical data points required before "
            "app.domains.analytics.forecast.fit_linear_trend is even "
            "attempted (bandwidth/guest-growth/network-load/capacity "
            "forecasts, and the Router Failure Risk heuristic's own CPU/"
            "memory trend fits) -- fewer points than this reports "
            "available=false rather than fabricating a line through too "
            "little data."
        ),
    )
    analytics_forecast_capacity_router_count_threshold: int = Field(
        default=50,
        ge=1,
        le=100_000,
        description=(
            "The router-count 'capacity ceiling' app.domains.analytics."
            "forecast_service.ForecastService.get_capacity_forecast "
            "projects an organization's real router_count_total trend "
            "against. This is an operator-set planning assumption, not "
            "data derived from any real infrastructure-capacity record "
            "(no such record exists anywhere in this codebase) -- override "
            "per-deployment via CLOUDGUEST_ANALYTICS_FORECAST_CAPACITY_"
            "ROUTER_COUNT_THRESHOLD."
        ),
    )
    analytics_forecast_router_health_lookback_days: int = Field(
        default=14,
        ge=1,
        le=90,
        description=(
            "How many trailing days of RouterHealthSnapshot history feed "
            "the Router Failure Risk heuristic's CPU/memory trend fits and "
            "unhealthy-ratio signal."
        ),
    )
    analytics_forecast_router_cpu_rising_slope_threshold: float = Field(
        default=1.0,
        ge=0,
        le=100,
        description=(
            "CPU usage percentage-points-per-day slope (from a real "
            "ordinary-least-squares fit over RouterHealthSnapshot history) "
            "above which the Router Failure Risk heuristic's "
            "'rising_cpu_usage' signal fires for a router."
        ),
    )
    analytics_forecast_router_memory_rising_slope_threshold: float = Field(
        default=1.0,
        ge=0,
        le=100,
        description=(
            "Same as analytics_forecast_router_cpu_rising_slope_threshold, "
            "for memory_usage_percent."
        ),
    )
    analytics_forecast_router_unhealthy_ratio_threshold: float = Field(
        default=0.3,
        ge=0,
        le=1,
        description=(
            "Fraction of a router's recent RouterHealthSnapshot readings "
            "reporting health_status='unhealthy' at/above which the Router "
            "Failure Risk heuristic's 'degrading_health_status' signal "
            "fires -- health_status is categorical, not numeric, so a "
            "'sustained negative trend' is operationalized as this ratio "
            "rather than a regression slope."
        ),
    )
    analytics_forecast_router_alert_count_threshold: int = Field(
        default=2,
        ge=1,
        le=1000,
        description=(
            "Number of monitoring Alerts recorded against one router within "
            "analytics_forecast_router_alert_lookback_days at/above which "
            "the Router Failure Risk heuristic's 'repeated_alerts' signal "
            "fires."
        ),
    )
    analytics_forecast_router_alert_lookback_days: int = Field(
        default=7,
        ge=1,
        le=90,
        description=(
            "Lookback window (days) the Router Failure Risk heuristic's "
            "'repeated_alerts' signal counts app.domains.monitoring.models."
            "Alert rows within, per router."
        ),
    )
    analytics_insight_customer_growth_significant_percent: float = Field(
        default=10.0,
        ge=0,
        le=1000,
        description=(
            "Minimum absolute organization-count growth percentage (over "
            "DEFAULT_GROWTH_LOOKBACK_DAYS) before the Business Insight "
            "Engine's 'customer_growth' rule fires."
        ),
    )
    analytics_insight_guest_growth_significant_percent: float = Field(
        default=15.0,
        ge=0,
        le=1000,
        description=(
            "Same as analytics_insight_customer_growth_significant_percent, "
            "for platform-wide unique-guest-count growth."
        ),
    )
    analytics_insight_plan_distribution_min_coverage_percent: float = Field(
        default=50.0,
        ge=0,
        le=100,
        description=(
            "Minimum percentage of organizations with a populated "
            "Organization.subscription_tier before the Business Insight "
            "Engine's 'plan_distribution_coverage' rule stops flagging the "
            "figure as too sparse to be meaningful."
        ),
    )
    analytics_insight_offline_router_hours_threshold: int = Field(
        default=24,
        ge=1,
        le=720,
        description=(
            "How many consecutive hours a router's last_seen_at heartbeat "
            "must be stale (with Router.status == OFFLINE) before the "
            "Operational Recommendations Engine's 'offline_routers' rule "
            "counts it."
        ),
    )
    analytics_insight_offline_router_count_threshold: int = Field(
        default=1,
        ge=1,
        le=1000,
        description=(
            "Minimum number of qualifying offline routers within one "
            "organization before the 'offline_routers' rule fires "
            "(WARNING severity)."
        ),
    )
    analytics_insight_offline_router_critical_count_threshold: int = Field(
        default=3,
        ge=1,
        le=1000,
        description=(
            "Minimum number of qualifying offline routers within one "
            "organization at/above which the 'offline_routers' rule "
            "escalates to CRITICAL severity instead of WARNING."
        ),
    )
    analytics_insight_location_volume_lookback_days: int = Field(
        default=7,
        ge=1,
        le=90,
        description=(
            "The 'week' in the Operational Recommendations Engine's "
            "'location_guest_volume_drop' week-over-week comparison."
        ),
    )
    analytics_insight_location_volume_drop_percent: float = Field(
        default=20.0,
        ge=0,
        le=100,
        description=(
            "Minimum percentage drop in a location's session_count_total "
            "(this lookback period vs. the immediately preceding one of "
            "equal length) before the 'location_guest_volume_drop' rule "
            "fires."
        ),
    )
    analytics_insight_router_cpu_lookback_days: int = Field(
        default=7,
        ge=1,
        le=90,
        description=(
            "How many trailing days of RouterHealthSnapshot history feed "
            "the Operational Recommendations Engine's 'rising_router_cpu' "
            "consecutive-increase check."
        ),
    )
    analytics_insight_router_cpu_consecutive_threshold: int = Field(
        default=3,
        ge=2,
        le=100,
        description=(
            "Number of consecutive strictly-increasing cpu_usage_percent "
            "readings (chronologically trailing) before the "
            "'rising_router_cpu' rule fires."
        ),
    )
    analytics_insight_critical_alert_count_threshold: int = Field(
        default=2,
        ge=1,
        le=1000,
        description=(
            "Minimum number of currently-open CRITICAL alerts, aged past "
            "analytics_insight_critical_alert_age_hours_threshold, within "
            "one organization before the 'persistent_critical_alerts' rule "
            "fires."
        ),
    )
    analytics_insight_critical_alert_age_hours_threshold: int = Field(
        default=24,
        ge=1,
        le=720,
        description=(
            "How long (hours) a CRITICAL alert must have been open "
            "(non-RESOLVED) before it counts toward the "
            "'persistent_critical_alerts' rule."
        ),
    )

    # ========================================================================
    # BE-013 Part 2: Subscription + Renewal + Coupon Engines
    #
    # Every tunable ``renewal_service.RenewalService`` compares a real,
    # computed date against lives here, following this file's own
    # established pattern (a plain, documented Settings field, never a
    # hardcoded magic number inline in renewal code) -- see
    # docs/billing/FLOW.md for the full write-up.
    # ========================================================================

    subscription_trial_period_days: int = Field(
        default=14,
        ge=1,
        le=365,
        description=(
            "How long a FREE_TRIAL-plan Subscription's trial period lasts "
            "(app.domains.billing.service.SubscriptionService"
            ".create_subscription) before its first real renewal attempt "
            "is due."
        ),
    )
    subscription_renewal_grace_period_days: int = Field(
        default=7,
        ge=0,
        le=90,
        description=(
            "How long a Subscription may remain PAST_DUE (a failed or "
            "not-yet-configured renewal charge) before "
            "app.domains.billing.renewal_service.RenewalService"
            ".expire_lapsed_subscriptions finally calls Part 1's "
            "LicenseService.expire_license -- the real grace-period policy "
            "Part 1's own docs/billing/FLOW.md deferred to this later part."
        ),
    )
    subscription_renewal_reminder_days_before: int = Field(
        default=3,
        ge=0,
        le=90,
        description=(
            "How many days before Subscription.current_period_end "
            "RenewalService.send_renewal_reminders dispatches an upcoming-"
            "renewal reminder email (once per billing period -- see "
            "Subscription.last_renewal_reminder_sent_at)."
        ),
    )
    subscription_expiry_reminder_days_before: int = Field(
        default=3,
        ge=0,
        le=90,
        description=(
            "How many days before a PAST_DUE subscription's grace-period "
            "deadline (past_due_at + subscription_renewal_grace_period_"
            "days) RenewalService.send_expiry_reminders dispatches a "
            "license-expiring-soon reminder email (once per past-due "
            "episode -- see Subscription.last_expiry_reminder_sent_at)."
        ),
    )

    # ========================================================================
    # BE-013 Part 3: Payment Service + real Stripe/Razorpay Integration +
    # Webhooks
    #
    # Every key/secret below defaults to an empty string -- "unconfigured" is
    # the honest, expected state of every field here in this sandbox (there
    # are no real Stripe/Razorpay credentials anywhere in it, and there
    # never will be). app.domains.billing.payment_gateways.StripePaymentGateway/
    # RazorpayPaymentGateway each check their own provider's key(s) before
    # any network attempt and raise a clear
    # app.domains.billing.exceptions.PaymentGatewayNotConfiguredError instead
    # of hanging or failing confusingly. Must be set via a real environment
    # variable (CLOUDGUEST_STRIPE_SECRET_KEY, etc.) in any real deployment.
    # ========================================================================

    stripe_secret_key: str = Field(
        default="",
        description=(
            "Stripe secret API key (sk_live_.../sk_test_...). Empty = "
            "unconfigured -- StripePaymentGateway raises "
            "PaymentGatewayNotConfiguredError for any real charge attempt "
            "rather than making a network call. Must be set via "
            "CLOUDGUEST_STRIPE_SECRET_KEY in any real deployment."
        ),
    )
    stripe_webhook_secret: str = Field(
        default="",
        description=(
            "Stripe webhook signing secret (whsec_...) used to verify the "
            "Stripe-Signature header on POST /api/v1/webhooks/stripe -- see "
            "app.domains.billing.webhooks's module docstring for the exact, "
            "real HMAC-SHA256 verification scheme."
        ),
    )
    stripe_webhook_tolerance_seconds: int = Field(
        default=300,
        ge=1,
        le=3600,
        description=(
            "Replay-protection tolerance window (seconds) for Stripe "
            "webhook signature verification -- a request whose embedded "
            "timestamp is older than this is rejected. 300s (5 minutes) "
            "matches stripe.Webhook.DEFAULT_TOLERANCE in the installed "
            "stripe SDK."
        ),
    )
    razorpay_key_id: str = Field(
        default="",
        description=(
            "Razorpay API key id. Empty = unconfigured (alongside "
            "razorpay_key_secret) -- RazorpayPaymentGateway raises "
            "PaymentGatewayNotConfiguredError for any real charge attempt. "
            "Must be set via CLOUDGUEST_RAZORPAY_KEY_ID in any real "
            "deployment."
        ),
    )
    razorpay_key_secret: str = Field(
        default="",
        description=(
            "Razorpay API key secret. Must be set via "
            "CLOUDGUEST_RAZORPAY_KEY_SECRET in any real deployment."
        ),
    )
    razorpay_webhook_secret: str = Field(
        default="",
        description=(
            "Razorpay webhook secret used to verify the "
            "X-Razorpay-Signature header on POST /api/v1/webhooks/razorpay "
            "-- see app.domains.billing.webhooks's module docstring for the "
            "exact, real HMAC-SHA256 verification scheme (no timestamp/"
            "replay-tolerance component -- Razorpay's own real scheme has "
            "none)."
        ),
    )
    payment_default_provider: str = Field(
        default="stripe",
        description=(
            "The single, platform-wide default payment provider "
            "('stripe'/'razorpay') app.domains.billing.dependencies"
            ".build_payment_gateway selects when no other signal is given -- "
            "see docs/billing/FLOW.md for why a single platform default "
            "(rather than a per-organization/per-plan choice) was judged the "
            "right model for this part."
        ),
    )

    # ========================================================================
    # Assistant domain: AI customer-support chatbot
    # ========================================================================

    assistant_provider: str = Field(
        default="logging",
        description=(
            "Which real LLM provider app.domains.assistant.dependencies"
            ".build_assistant_provider routes 'sarvam' selection through -- "
            "'logging' (default) or 'sarvam'. Mirrors email_delivery_"
            "provider/sms_delivery_provider/whatsapp_delivery_provider's "
            "identical selector pattern (app.domains.otp.service"
            ".get_configured_email_provider et al.): 'sarvam' with "
            "sarvam_api_key still empty falls back to LoggingAssistant"
            "Provider rather than making a network call with no "
            "credential. Deliberately does *not* gate the Anthropic path -- "
            "that one still activates purely off anthropic_api_key being "
            "non-empty (see that field's own docstring), the original "
            "single-provider behavior this codebase shipped with before "
            "Sarvam existed as an option, preserved unchanged so existing "
            "deployments that already set only CLOUDGUEST_ANTHROPIC_API_KEY "
            "keep working with zero migration. Override via "
            "CLOUDGUEST_ASSISTANT_PROVIDER in any real deployment that "
            "wants Sarvam instead."
        ),
    )
    anthropic_api_key: str = Field(
        default="",
        description=(
            "Anthropic API key (sk-ant-...) used by "
            "app.domains.assistant.service.LiteLLMAssistantProvider "
            "(routed through litellm, not the anthropic SDK directly). "
            "Empty = unconfigured -- app.domains.assistant.dependencies"
            ".build_assistant_provider falls back to "
            "LoggingAssistantProvider (keyword-matched canned replies, no "
            "network call) rather than making a network call, mirroring "
            "the identical 'empty key = honest logging default' posture "
            "stripe_secret_key/razorpay_key_id already establish for "
            "payments. Override via CLOUDGUEST_ANTHROPIC_API_KEY in any "
            "real deployment -- the default is a placeholder, not a real "
            "key. See sarvam_api_key/assistant_provider for the other "
            "supported provider."
        ),
    )
    sarvam_api_key: str = Field(
        default="",
        description=(
            "Sarvam AI API key used by app.domains.assistant.service"
            ".LiteLLMAssistantProvider when assistant_provider='sarvam' "
            "(routed through litellm's 'sarvam/<model>' provider prefix, "
            "the same generic litellm.acompletion wrapper the Anthropic "
            "path already uses -- not a Sarvam SDK). Empty = unconfigured "
            "-- build_assistant_provider falls back to "
            "LoggingAssistantProvider even when assistant_provider='sarvam' "
            "is set, the identical 'empty key = honest logging default' "
            "posture anthropic_api_key/stripe_secret_key/razorpay_key_id "
            "already establish. Override via CLOUDGUEST_SARVAM_API_KEY in "
            "any real deployment -- the default is a placeholder, not a "
            "real key."
        ),
    )
    payment_webhook_event_dedup_ttl_seconds: int = Field(
        default=604_800,
        ge=60,
        le=2_592_000,
        description=(
            "TTL (seconds) for the Redis-backed webhook event-id dedup set "
            "(app.domains.billing.webhooks.RedisWebhookEventDedup) -- "
            "default 7 days, comfortably longer than either provider's own "
            "real webhook redelivery/retry window."
        ),
    )

    # ========================================================================
    # BE-013 Part 4: Invoice Engine + Tax/GST
    #
    # Platform-level tax jurisdiction config -- what state/country/GSTIN the
    # platform itself is registered in, needed to determine intra-state
    # (CGST+SGST) vs. inter-state (IGST) for every GST invoice
    # (app.domains.billing.validators.compute_tax_breakdown). Modeled as
    # plain Settings fields (a real business config, not a per-deployment
    # secret) rather than a config table -- there is exactly one "home
    # jurisdiction" for this platform at any given time, the same "a plain,
    # documented Settings field, never a hardcoded magic number" pattern
    # every other tunable in this file already follows. See
    # docs/billing/FLOW.md for the full write-up.
    # ========================================================================

    frontend_base_url: str = Field(
        default="https://app.cloudguest.example",
        description=(
            "The deployed frontend's public origin, used to build the "
            "login_url a newly-provisioned location owner's welcome email "
            "points at (see app.domains.location.provisioning_service). "
            "Override via CLOUDGUEST_FRONTEND_BASE_URL in any real "
            "deployment -- the default is a placeholder, not a real host."
        ),
    )
    api_public_base_url: str = Field(
        default="https://api.wyfyguest.com",
        description=(
            "This backend's own public origin, used to render every "
            "RouterOS script that calls back to this platform over the "
            "open internet -- app.domains.network_config.renderers"
            ".render_bootstrap_script/render_agent_heartbeat_scheduler/"
            "render_isp_netwatch_entry all take an api_base_url parameter "
            "a real caller should source from here rather than a literal. "
            "Must be a real https:// origin (RouterOS 7 verifies TLS "
            "certificates by default -- see _require_https in that "
            "module). Override via CLOUDGUEST_API_PUBLIC_BASE_URL in any "
            "real deployment -- the default points at this platform's own "
            "real, registered production domain (see app/main.py's CORS "
            "allowlist), not a placeholder, but it still needs to resolve "
            "to wherever this backend is actually reachable in a given "
            "deployment."
        ),
    )
    platform_gst_state: str = Field(
        default="Maharashtra",
        description=(
            "The Indian state this platform's own business is GST-"
            "registered in. Compared (case-insensitively) against an "
            "organization's own BillingProfile.billing_state to decide "
            "intra-state (CGST+SGST split) vs. inter-state (IGST) GST -- "
            "see app.domains.billing.validators.compute_tax_breakdown. "
            "Override via CLOUDGUEST_PLATFORM_GST_STATE in any real "
            "deployment to the platform's actual registered state."
        ),
    )
    platform_gst_country: str = Field(
        default="IN",
        description=(
            "ISO 3166-1 alpha-2 country code this platform's GST "
            "registration applies to. An organization whose BillingProfile"
            ".billing_country differs from this is always inter-state "
            "(IGST) by definition, regardless of billing_state."
        ),
    )
    platform_gstin: str = Field(
        default="",
        description=(
            "This platform's own GSTIN (GST identification number), shown "
            "on the seller line of every generated GST invoice PDF. Empty "
            "= unconfigured -- an honest, cosmetic-only gap (invoice PDFs "
            "still generate correctly, just without a seller GSTIN line); "
            "does not gate any tax computation. Override via "
            "CLOUDGUEST_PLATFORM_GSTIN in any real deployment."
        ),
    )
    platform_legal_business_name: str = Field(
        default="CloudGuest",
        description=(
            "This platform's own legal/business name, printed as the "
            "seller on every generated invoice PDF header."
        ),
    )
    invoice_due_days: int = Field(
        default=15,
        ge=0,
        le=365,
        description=(
            "Default payment-terms window -- app.domains.billing.service"
            ".InvoiceService.generate_invoice_for_subscription sets "
            "Invoice.due_date to issue_date + this many days."
        ),
    )
    invoice_overdue_sweep_interval_seconds: float = Field(
        default=3600.0,
        ge=60.0,
        le=86_400.0,
        description=(
            "Beat interval for app.domains.billing.tasks"
            ".run_invoice_overdue_sweep, which transitions every ISSUED "
            "invoice whose due_date has passed to OVERDUE -- mirrors "
            "subscription_renewal_grace_period_days's own hourly-sweep "
            "granularity reasoning (invoice due dates are day-granularity, "
            "so hourly checking has no freshness cost)."
        ),
    )

    otel_exporter_otlp_endpoint: str | None = Field(
        default=None,
        description=(
            "OTLP/HTTP collector endpoint (e.g. "
            "'http://localhost:4318/v1/traces') that "
            "app.core.tracing.configure_tracing exports spans to. There is "
            "no real OpenTelemetry Collector/Jaeger/Tempo instance in this "
            "sandbox, so leaving this unset is the honest default: spans "
            "are still generated by a real OpenTelemetry SDK "
            "TracerProvider (app.core.tracing), just exported to the "
            "console (ConsoleSpanExporter) instead of a network collector. "
            "Setting this to a real collector's OTLP/HTTP endpoint in any "
            "non-local environment switches to the real OTLPSpanExporter "
            "with zero code changes."
        ),
    )

    # ========================================================================
    # Notification domain: real email/SMS/WhatsApp providers + object
    # storage + outbox dispatch
    #
    # Mirrors the Stripe/Razorpay section's own "empty/'logging' = honest
    # unconfigured default" pattern: every real-provider setting below is
    # inert until explicitly selected via `email_delivery_provider`/
    # `sms_delivery_provider`/`whatsapp_delivery_provider`, so a fresh
    # local checkout keeps today's log-only behavior with zero
    # configuration. See app.domains.otp.service's `SmtpEmailProvider`/
    # `SesEmailProvider`/`TwilioSmsProvider`/`TwilioWhatsAppProvider` and
    # app.domains.notification for the full write-up.
    # ========================================================================

    email_delivery_provider: str = Field(
        default="logging",
        description=(
            "Which concrete EmailProviderProtocol implementation "
            "app.domains.otp.service.get_configured_email_provider selects: "
            "'logging' (default, no real send), 'smtp', or 'ses'."
        ),
    )
    smtp_host: str = Field(default="", description="SMTP server hostname.")
    smtp_port: int = Field(default=587, ge=1, le=65_535)
    smtp_username: str = Field(default="")
    smtp_password: str = Field(default="")
    smtp_use_tls: bool = Field(default=True)
    smtp_from_address: str = Field(default="noreply@cloudguest.local")

    ses_access_key_id: str = Field(default="")
    ses_secret_access_key: str = Field(default="")
    ses_region: str = Field(default="us-east-1")
    ses_from_address: str = Field(default="")

    # Invoice emails (billing.router's `_send_invoice_email_and_build_response`)
    # deliberately go out from a separate mailbox from every other
    # notification (OTP, password reset, ...) -- finance/accounts wants its
    # own dedicated sending identity regardless of which account the
    # general `smtp_*` settings above end up using. Empty (the default)
    # means "no dedicated invoice mailbox configured yet" -- falls back to
    # the shared `email_delivery_provider`/`smtp_*` config above, so a
    # fresh checkout with only the general SMTP settings configured keeps
    # working exactly as before this field existed.
    invoice_smtp_host: str = Field(
        default="", description="SMTP server hostname for invoice emails specifically."
    )
    invoice_smtp_port: int = Field(default=587, ge=1, le=65_535)
    invoice_smtp_username: str = Field(default="")
    invoice_smtp_password: str = Field(default="")
    invoice_smtp_use_tls: bool = Field(default=True)
    invoice_smtp_from_address: str = Field(default="")

    # ------------------------------------------------------------------
    # Second named sending identity: the admin mailbox
    # ------------------------------------------------------------------
    # Outgoing mail is deliberately split across two real mailboxes:
    #
    #   admin@wyfyguest.com  -- guest OTP, password reset, new-location
    #                           welcome  (this `admin_smtp_*` block,
    #                           `MailIdentity.ADMIN`)
    #   sales@wyfyguest.com  -- demo-request notifications, channel-partner
    #                           welcome, quotations  (the general `smtp_*`
    #                           block above, `MailIdentity.DEFAULT`, which
    #                           is also what every other sender -- alerts,
    #                           invites, voucher exports -- keeps using)
    #
    # The routing table that decides which flow gets which identity is
    # `app.domains.otp.service.MailIdentity` plus
    # `app.domains.notification.constants.MAIL_IDENTITY_BY_EVENT_TYPE`;
    # read those two to answer "which mailbox does X come from?".
    #
    # This is a NEW, separately named block rather than a reuse of
    # `invoice_smtp_*` above on purpose: `invoice_smtp_*` means "the
    # finance/accounts mailbox" and nothing else, so pointing OTP at it
    # would make both settings lie about themselves. Both blocks resolve
    # through the same `SmtpIdentity` value object, so the host/username/
    # password/From pairing rule is written once, not twice.
    #
    # Empty `admin_smtp_host` (the default) means "no second mailbox
    # configured" -- every ADMIN-routed flow then falls back to the
    # general `smtp_*` identity and says so in a log
    # (`email_identity_fallback`), which is exactly today's behavior.
    admin_smtp_host: str = Field(
        default="",
        description=(
            "SMTP server hostname for the admin@ sending identity (guest "
            "OTP, password reset, new-location welcome). Empty = fall back "
            "to the general smtp_* identity."
        ),
    )
    admin_smtp_port: int = Field(default=587, ge=1, le=65_535)
    admin_smtp_username: str = Field(default="")
    admin_smtp_password: str = Field(default="")
    admin_smtp_use_tls: bool = Field(default=True)
    admin_smtp_from_address: str = Field(
        default="",
        description=(
            "From address for the admin@ identity. Empty defaults to "
            "admin_smtp_username -- an identity always sends as the account "
            "it authenticated as unless deliberately told otherwise, and "
            "SmtpIdentity rejects a From that belongs to a different "
            "account (Zoho answers that mismatch with '553 Sender is not "
            "allowed to relay emails')."
        ),
    )

    demo_request_notify_email: str = Field(
        default="",
        description=(
            "Internal-team inbox app.domains.demo_request.service"
            ".DemoRequestService notifies (via app.domains.notification) on "
            "every new public 'Book a Demo' submission. Empty (the "
            "default) is a deliberate no-op -- same 'unconfigured means "
            "silently skip, not fabricate a recipient' posture as "
            "email_delivery_provider='logging' above -- so a fresh "
            "checkout with no team inbox configured yet never fails/spams "
            "an arbitrary address."
        ),
    )

    # ======================================================================
    # Demo booking calendar (app.domains.demo_booking)
    # ======================================================================
    # The availability rules behind the public "pick a time" calendar.
    # Configuration rather than hardcoding, but deliberately NOT a
    # scheduling admin UI -- the founder asked for a booking calendar, not
    # Calendly. Changing the sales team's working week is a deploy-time
    # decision here, which is the right weight for something that happens
    # once a year.
    #
    # EVERY field in this block that names a time, a day or a date is
    # expressed in `demo_booking_timezone`, never in UTC. See
    # app.domains.demo_booking.availability's module docstring for the full
    # convention and why it is written that way round.
    #
    # The list-shaped fields are plain comma-separated strings, not
    # `list[str]`: pydantic-settings parses a list field from the
    # environment as JSON, which would make
    # `CLOUDGUEST_DEMO_BOOKING_BLACKOUT_DATES=2026-10-02` a startup crash
    # instead of the obvious thing. They are parsed -- loudly, naming the
    # offending token -- by `availability.parse_*`.

    demo_booking_timezone: str = Field(
        default="Asia/Kolkata",
        description=(
            "IANA zone every availability rule below is defined in, and "
            "the zone slot times are displayed in. IST: the founder, the "
            "sales team and effectively every visitor are in it. Instants "
            "are always stored and returned in UTC regardless; this "
            "governs which wall-clock hours those instants land on."
        ),
    )
    demo_booking_workday_start: str = Field(
        default="10:00",
        description=(
            "First slot start of the day, HH:MM in demo_booking_timezone."
        ),
    )
    demo_booking_workday_end: str = Field(
        default="18:00",
        description=(
            "Close of business, HH:MM in demo_booking_timezone. A slot must "
            "fit entirely before this, so with a 30-minute slot the last "
            "start is 17:30, not 18:00."
        ),
    )
    demo_booking_slot_minutes: int = Field(
        default=30,
        ge=5,
        le=480,
        description=(
            "Length of one demo. 30 minutes is what the sales team already "
            "books manually. Changing this changes the published grid; it "
            "does NOT move meetings already booked (DemoBooking.ends_at is "
            "stored, not derived) -- see that model's own docstring for the "
            "one overlap case this leaves open."
        ),
    )
    demo_booking_buffer_minutes: int = Field(
        default=0,
        ge=0,
        le=240,
        description=(
            "Gap between the end of one slot and the start of the next. "
            "Default 0 -- back-to-back 30-minute calls on a 30-minute grid "
            "is what sales does today; raise it if calls start running "
            "over."
        ),
    )
    demo_booking_lead_time_minutes: int = Field(
        default=120,
        ge=0,
        le=10_080,
        description=(
            "Minimum notice: a slot starting sooner than this is neither "
            "listed nor bookable. Two hours gives sales time to see the "
            "booking before the call. Even at 0 a slot is never bookable "
            "at or after its own start instant -- see "
            "availability.BookingWindow.is_bookable."
        ),
    )
    demo_booking_horizon_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description=(
            "How far ahead the calendar opens, in local calendar days from "
            "today. 30 keeps the published calendar to something the team "
            "can actually honour."
        ),
    )
    demo_booking_working_days: str = Field(
        default="0,1,2,3,4",
        description=(
            "Comma-separated Python weekday numbers (Monday 0 ... Sunday 6) "
            "the team takes demos on. Default Mon-Fri."
        ),
    )
    demo_booking_blackout_dates: str = Field(
        default="",
        description=(
            "Comma-separated YYYY-MM-DD local dates on which nothing is "
            "bookable -- public holidays, offsites. Reported to the UI as "
            "its own day status ('blackout'), distinct from a weekend, "
            "because 'we're closed for Diwali' and 'it's Sunday' are "
            "different things to tell a visitor."
        ),
    )
    demo_booking_max_active_per_email: int = Field(
        default=2,
        ge=0,
        le=100,
        description=(
            "Hard cap on how many FUTURE confirmed slots one email address "
            "may hold at once, checked against the database. This is the "
            "guard that actually bounds 'someone scripts 500 bookings and "
            "fills the calendar' -- a Redis counter can be flushed or "
            "expire, held rows cannot. 0 disables the cap."
        ),
    )
    demo_booking_max_attempts_per_window: int = Field(
        default=10,
        ge=1,
        le=1000,
        description=(
            "Per-email booking attempts allowed inside "
            "demo_booking_attempt_window_minutes, enforced with the same "
            "Redis INCR+EXPIRE+TTL pattern as otp_max_requests_per_window. "
            "Counts attempts, not successes, so a script losing race after "
            "race is still throttled."
        ),
    )
    demo_booking_attempt_window_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description=(
            "Rolling window demo_booking_max_attempts_per_window applies to."
        ),
    )
    demo_booking_lead_dedupe_minutes: int = Field(
        default=60,
        ge=0,
        le=1440,
        description=(
            "How recently an unbooked lead from the same email may have "
            "been created for a new booking attempt to reuse it instead of "
            "creating a second queue entry. Covers the real case -- a "
            "visitor who lost a slot race and immediately picked another "
            "time. 0 disables reuse (every attempt is its own lead)."
        ),
    )

    sms_delivery_provider: str = Field(
        default="logging",
        description=(
            "Which concrete SmsProviderProtocol implementation "
            "app.domains.otp.service.get_configured_sms_provider selects: "
            "'logging' (default, no real send), 'twilio', or 'exotel'."
        ),
    )
    twilio_account_sid: str = Field(default="")
    twilio_auth_token: str = Field(default="")
    twilio_from_number: str = Field(default="")
    exotel_api_key: str = Field(default="")
    exotel_api_token: str = Field(default="")
    exotel_account_sid: str = Field(default="")
    exotel_from_number: str = Field(
        default="", description="DLT-approved sender ID Exotel sends SMS as."
    )
    exotel_subdomain: str = Field(
        default="api.exotel.com",
        description="'api.exotel.com' or 'api.in.exotel.com' (Mumbai region).",
    )
    exotel_dlt_entity_id: str = Field(
        default="", description="TRAI DLT-registered entity id (India SMS compliance)."
    )
    exotel_dlt_template_id: str = Field(
        default="",
        description=(
            "TRAI DLT-registered template id -- the OTP message body sent "
            "must match this template's approved text exactly, or Indian "
            "carriers silently drop the message."
        ),
    )

    whatsapp_delivery_provider: str = Field(
        default="logging",
        description=(
            "Which concrete WhatsAppProviderProtocol implementation "
            "app.domains.otp.service.get_configured_whatsapp_provider "
            "selects: 'logging' (default, no real send), or 'twilio'."
        ),
    )
    # Deliberately no separate whatsapp_twilio_account_sid/auth_token --
    # Twilio's WhatsApp Business API runs on the exact same Account SID/
    # Auth Token as SMS (twilio_account_sid/twilio_auth_token above), just
    # a different sender identity and message shape. See
    # app.domains.otp.service.TwilioWhatsAppProvider's own docstring.
    whatsapp_twilio_from_number: str = Field(
        default="",
        description=(
            "The Twilio WhatsApp-enabled sender number, e.g. "
            "'+14155238886' (Twilio's own sandbox number) or a real "
            "Meta-approved WhatsApp Business sender once one is "
            "provisioned. Sent as 'whatsapp:{this}' in the From field -- "
            "never include the 'whatsapp:' prefix here."
        ),
    )
    whatsapp_twilio_content_sid: str = Field(
        default="",
        description=(
            "The Twilio-Console SID (e.g. 'HXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx') "
            "of a Meta-approved WhatsApp Content Template -- required "
            "because WhatsApp Business API rejects a freeform message body "
            "for any business-initiated conversation (which every OTP send "
            "is), unlike plain SMS. Create and get this template approved "
            "in the Twilio Console before setting "
            "whatsapp_delivery_provider='twilio' in any real deployment."
        ),
    )
    whatsapp_twilio_content_variable_key: str = Field(
        default="1",
        description=(
            "The approved template's placeholder key the OTP code is "
            'substituted into, e.g. Twilio ContentVariables \'{"1": '
            "\"042817\"}' for a template body reading 'Your code is "
            "{{1}}'. Only needs changing if the approved template numbers "
            "its variables differently."
        ),
    )

    s3_endpoint_url: str = Field(
        default="http://minio:9000",
        description=(
            "S3-compatible endpoint app.core.storage.S3ObjectStorage "
            "connects to -- points at the local docker-compose MinIO "
            "service by default. Override with a real AWS S3 endpoint (or "
            "leave the AWS default) in any non-local deployment."
        ),
    )
    s3_bucket_name: str = Field(default="cloudguest")
    s3_access_key_id: str = Field(default="cloudguest")
    s3_secret_access_key: str = Field(default="cloudguest12345")
    s3_region: str = Field(default="us-east-1")

    notification_dispatch_sweep_interval_seconds: float = Field(
        default=60.0,
        ge=5.0,
        le=3600.0,
        description=(
            "Beat interval for app.domains.notification.tasks"
            ".run_notification_dispatch_sweep, which drains every PENDING/"
            "RETRYING NotificationDelivery row whose next_attempt_at has "
            "passed."
        ),
    )
    notification_max_delivery_attempts: int = Field(
        default=5,
        ge=1,
        le=50,
        description=(
            "How many real send attempts a NotificationDelivery gets "
            "before app.domains.notification.service.NotificationService"
            ".dispatch_pending gives up and leaves it FAILED."
        ),
    )
    notification_retry_backoff_seconds: int = Field(
        default=300,
        ge=1,
        le=86_400,
        description=(
            "Flat backoff before a RETRYING NotificationDelivery's next "
            "send attempt. A flat (not exponential) backoff is the "
            "deliberately simplest defensible choice for this first pass "
            "-- see app.domains.notification.service's own docstring."
        ),
    )

    # ========================================================================
    # Security surface: API keys, MFA/TOTP, rate limiting
    # ========================================================================

    mfa_encryption_key: str = Field(
        default="aW5zZWN1cmUtbG9jYWwtZGV2LWZlcm5ldC1rZXkzMiE=",
        min_length=32,
        description=(
            "App-level symmetric key (Fernet, urlsafe-base64) used by "
            "app.domains.auth.mfa to encrypt/decrypt a user's TOTP secret "
            "at rest. Deliberately a separate key from "
            "router_encryption_key -- an unrelated secret class gets its "
            "own key, never a shared one. Same interim-design posture as "
            "router_encryption_key (see that field's own docstring): must "
            "be overridden with a real Fernet key "
            "(Fernet.generate_key()) in every non-local environment."
        ),
    )
    mfa_recovery_code_count: int = Field(
        default=10,
        ge=1,
        le=50,
        description=(
            "How many single-use recovery codes "
            "app.domains.auth.mfa.generate_recovery_codes issues on MFA "
            "enrollment/regeneration."
        ),
    )

    rate_limit_max_requests: int = Field(
        default=60,
        ge=1,
        le=10_000,
        description=(
            "Requests a single (client IP, path) pair may make within "
            "rate_limit_window_seconds before "
            "app.middleware.rate_limit.RateLimitMiddleware responds "
            "429 -- applied only to the curated auth/public/guest-facing "
            "path prefixes that module's own constants.py lists, not "
            "every route."
        ),
    )
    captive_portal_resolve_rate_limit_max_requests: int = Field(
        default=600,
        ge=1,
        le=100_000,
        description=(
            "Requests GET /captive-portal/resolve may serve per "
            "rate_limit_window_seconds, applied separately to each venue "
            "(organization/location) and to each client IP -- see design "
            "spec §5 S8 and app.middleware.rate_limit's own module "
            "docstring. Sized for a venue, not a device: every guest at a "
            "venue leaves through one NAT egress IP, so the previous "
            "device-sized 60 meant roughly twenty simultaneous arrivals "
            "could 429 each other off the WiFi they were joining. 600 "
            "over the default 60s window is ~10 req/s per venue, which "
            "clears a realistic arrival burst by a wide margin while "
            "still bounding how hard one source can drive an "
            "unauthenticated endpoint."
        ),
    )
    rate_limit_window_seconds: int = Field(
        default=60,
        ge=1,
        le=3600,
        description=(
            "Rolling window (seconds) rate_limit_max_requests is measured "
            "over -- mirrors app.domains.otp.service.OtpRateLimiter's "
            "identical INCR+EXPIRE+TTL Redis pattern."
        ),
    )

    @property
    def log_path(self) -> Path:
        return self.log_dir / self.log_file


@lru_cache
def get_settings() -> Settings:
    return Settings()
