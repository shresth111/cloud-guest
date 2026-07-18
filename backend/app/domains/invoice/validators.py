"""Validators for invoice parameters."""

def validate_invoice_totals(subtotal: float, discount: float, tax: float, total: float) -> bool:
    """Validate that subtotal - discount + tax is mathematically correct."""
    calculated = round(subtotal - discount + tax, 2)
    return abs(calculated - round(total, 2)) < 0.05
