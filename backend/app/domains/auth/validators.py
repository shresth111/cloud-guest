from __future__ import annotations


def validate_email(email: str) -> bool:
    return "@" in email and "." in email.split("@")[-1]


def validate_password(password: str) -> bool:
    return len(password) >= 8
