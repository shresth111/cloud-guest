# Billing Domain Architecture

This domain manages subscription plans, tenant subscriptions, licenses, invoices, credit notes, payments, and coupons for the CloudGuest Enterprise Multi-Tenant SaaS platform.

## Architecture & Design Patterns
- **Domain Driven Design (DDD)**: Clear boundary representing the complete financial and subscription lifecycle.
- **Repository Pattern**: Implements protocol-based repositories for decoupled testing using in-memory doubles.
- **Service Layer**: Centrates complex business rules, such as recurring grace periods, GST calculations, and cascading coupon discounts.
- **Gateway Abstraction**: Future-proof structure ready for Stripe and Razorpay webhook handling.

## Components
- **Subscription Engine**: Manages user subscription plans (`starter`, `premium`, `enterprise`) and active periods with grace periods.
- **Billing Profile Engine**: Maintains external gateway customer tokens, default card info, and dynamic organization addresses.
- **License Engine**: Allocates and validates cryptographically structured license keys for active MikroTik routers.
- **Payment & Coupon Engine**: Processes charges, verifies transaction intents, and validates percent/fixed promotional discounts.
- **Invoice Engine**: Compiles dynamic line items, taxes (GST), and prints sequential invoice IDs (`INV-YYYY-XXXXX`).
