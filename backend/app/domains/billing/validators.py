"""Validators for the Billing domain."""

import re

def validate_tax_id(tax_id: str, tax_id_type: str) -> bool:
    """Validate format of Tax/GST number based on type."""
    if not tax_id:
        return True
    
    # Simple GSTIN check for India
    if tax_id_type.lower() == "gst":
        gst_regex = r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$"
        return bool(re.match(gst_regex, tax_id))
        
    return True
