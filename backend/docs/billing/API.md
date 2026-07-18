# Billing Domain API Specifications

All routes are prefixed with `/api/v1`.

## Subscriptions

### POST `/subscriptions/plans`
Creates a new subscription plan option.
- **Payload**:
  ```json
  {
    "name": "Enterprise Plus",
    "code": "enterprise-plus",
    "price_monthly": 199.00,
    "price_yearly": 1990.00,
    "currency": "USD",
    "trial_days": 30,
    "limits": { "max_routers": 100 }
  }
  ```

### POST `/subscriptions`
Subscribes an organization to a plan.
- **Payload**:
  ```json
  {
    "organization_id": "uuid",
    "plan_id": "uuid",
    "billing_cycle": "monthly"
  }
  ```

## Payments & Coupons

### POST `/payments/intents`
Prepares a gateway transaction intent.
- **Payload**:
  ```json
  {
    "organization_id": "uuid",
    "amount": 49.00,
    "currency": "USD",
    "gateway": "stripe"
  }
  ```

### POST `/coupons`
Generates a promo code.
- **Payload**:
  ```json
  {
    "code": "SAVE30",
    "discount_type": "percentage",
    "discount_value": 30.0
  }
  ```

## Licenses

### POST `/licenses/generate`
Generates a new software license key.
- **Payload**:
  ```json
  {
    "organization_id": "uuid",
    "tier": "enterprise"
  }
  ```

### POST `/licenses/activate`
Activates an issued key on a physical router.
- **Payload**:
  ```json
  {
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "router_id": "uuid"
  }
  ```
