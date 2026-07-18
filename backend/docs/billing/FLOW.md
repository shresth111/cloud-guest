# Billing Domain Lifecycle Flows

## 1. Subscription & Payment Intent Flow
```
[User App] ---> (POST /payments/intents) ---> [Calculate GST & Coupon]
                                                   |
                                                   v
[User Checkout] <--- [Client Secret] <--- [Record Pending Payment]
      |
      v (Enters Card Info)
[Gateway (Stripe/Razorpay)] ---> [Succeeded Webhook] ---> [Update Payment & Sub Status]
```

## 2. Router License Activation Flow
```
[MikroTik Router (Booting)] ---> (POST /licenses/activate)
                                       |
                                       v
                             [Verify key matches org]
                             [Update Status -> activated]
                                       |
                                       v
[Router Configured] <----------- [Return OK]
```

## 3. Invoice Generation and Credit Note Flow
1. **Periodic Celery Tasks** check active subscriptions nearing current period ends.
2. **Compile Line Items**: Merges base plan rate + active router counts + tax rates.
3. **Draft Generation**: Emits an invoice model with status `draft`.
4. **Trigger Charge**: Initiates a background payment using the stored default gateway payment method.
5. **Success Event**: Marks invoice as `paid` and delivers receipt PDFs automatically.
6. **Failed Event**: Shifts invoice to `open`, launches graceful email notifications, and enters retry periods.
7. **Refund Event**: Emits a `CreditNote` adjusting the ledger state on demand.
