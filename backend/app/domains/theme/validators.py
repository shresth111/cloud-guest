"""Validators for custom theme CSS/JS codes."""

def sanitize_custom_js(js_code: str) -> bool:
    """Basic sanity check to ensure custom JS doesn't contain simple injection threats."""
    if not js_code:
        return True
    forbidden = ["<script>", "</script>", "document.cookie"]
    return not any(x in js_code.lower() for x in forbidden)
