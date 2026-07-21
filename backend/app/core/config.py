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
        default_factory=lambda: ["http://localhost:3000"]
    )

    database_url: PostgresDsn = Field(
        default="postgresql+asyncpg://cloudguest:cloudguest@localhost:5432/cloudguest"
    )
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=100)
    database_pool_timeout: int = Field(default=30, ge=1, le=120)

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
    # Notification domain: real email/SMS providers + object storage +
    # outbox dispatch
    #
    # Mirrors the Stripe/Razorpay section's own "empty/'logging' = honest
    # unconfigured default" pattern: every real-provider setting below is
    # inert until explicitly selected via `email_delivery_provider`/
    # `sms_delivery_provider`, so a fresh local checkout keeps today's
    # log-only behavior with zero configuration. See
    # app.domains.otp.service's `SmtpEmailProvider`/`SesEmailProvider`/
    # `TwilioSmsProvider` and app.domains.notification for the full
    # write-up.
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

    sms_delivery_provider: str = Field(
        default="logging",
        description=(
            "Which concrete SmsProviderProtocol implementation "
            "app.domains.otp.service.get_configured_sms_provider selects: "
            "'logging' (default, no real send) or 'twilio'."
        ),
    )
    twilio_account_sid: str = Field(default="")
    twilio_auth_token: str = Field(default="")
    twilio_from_number: str = Field(default="")

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
