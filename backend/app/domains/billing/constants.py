"""Constants for the Billing domain."""

from enum import Enum

class PaymentGateway(str, Enum):
    STRIPE = "stripe"
    RAZORPAY = "razorpay"
    PAYPAL = "paypal"

class BillingCycle(str, Enum):
    MONTHLY = "monthly"
    YEARLY = "yearly"
