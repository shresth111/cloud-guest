"""ACS credentials: one per ISP (devices arrive unassigned) and one per
customer with TR-069 enabled.

The password is stored twice, for two readers: an Argon2id hash
(``PasswordManager.hash_raw``, the existing auth hasher) that ``acs-auth``
verifies, and a Fernet ciphertext (``app.domains.router.crypto``) the ISP UI
decrypts to show it. It is alphanumeric only, so it never needs RouterOS
escaping and never trips a shell.
"""

from __future__ import annotations

import secrets
import string
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.auth.password import PasswordManager
from app.domains.router.crypto import decrypt_secret, encrypt_secret

from .models import Tr069AcsCredential

_ALPHABET = string.ascii_letters + string.digits
PASSWORD_LENGTH = 24


def generate_username(kind: str) -> str:
    """``isp-<8hex>`` or ``cust-<8hex>``."""
    if kind not in {"isp", "cust"}:
        raise ValueError(kind)
    return f"{kind}-{secrets.token_hex(4)}"


def generate_password(length: int = PASSWORD_LENGTH) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def hash_password(password: str) -> str:
    return PasswordManager.hash_raw(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return PasswordManager.verify(password, password_hash)
    except Exception:  # noqa: BLE001 -- a malformed hash is a failed login
        return False


class CredentialStore:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(
        self, isp_org_id: uuid.UUID, customer_org_id: uuid.UUID | None
    ) -> Tr069AcsCredential | None:
        condition = (
            Tr069AcsCredential.customer_organization_id.is_(None)
            if customer_org_id is None
            else Tr069AcsCredential.customer_organization_id == customer_org_id
        )
        return (
            await self.session.execute(
                select(Tr069AcsCredential).where(
                    Tr069AcsCredential.isp_organization_id == isp_org_id,
                    condition,
                    Tr069AcsCredential.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def get_by_username(self, username: str) -> Tr069AcsCredential | None:
        return (
            await self.session.execute(
                select(Tr069AcsCredential).where(
                    Tr069AcsCredential.username == username,
                    Tr069AcsCredential.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def ensure(
        self,
        isp_org_id: uuid.UUID,
        customer_org_id: uuid.UUID | None,
        *,
        actor_user_id: uuid.UUID | None,
        enabled: bool = True,
    ) -> Tr069AcsCredential:
        """Return the credential, minting it on first use. Re-enabling an
        existing one keeps its username and password."""
        existing = await self.get(isp_org_id, customer_org_id)
        if existing is not None:
            if existing.enabled != enabled:
                existing.enabled = enabled
                existing.updated_by = actor_user_id
                await self.session.flush()
            return existing
        password = generate_password()
        row = Tr069AcsCredential(
            isp_organization_id=isp_org_id,
            customer_organization_id=customer_org_id,
            username=generate_username("isp" if customer_org_id is None else "cust"),
            password_hash=hash_password(password),
            password_encrypted=encrypt_secret(password),
            enabled=enabled,
            created_by=actor_user_id,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def set_enabled(
        self,
        isp_org_id: uuid.UUID,
        customer_org_id: uuid.UUID | None,
        enabled: bool,
        *,
        actor_user_id: uuid.UUID | None,
    ) -> Tr069AcsCredential | None:
        """Flip an existing credential; never mints one."""
        existing = await self.get(isp_org_id, customer_org_id)
        if existing is not None and existing.enabled != enabled:
            existing.enabled = enabled
            existing.updated_by = actor_user_id
            await self.session.flush()
        return existing

    async def rotate(
        self, credential: Tr069AcsCredential, *, actor_user_id: uuid.UUID | None
    ) -> Tr069AcsCredential:
        """New password, same username (CPEs keep their identity)."""
        password = generate_password()
        credential.password_hash = hash_password(password)
        credential.password_encrypted = encrypt_secret(password)
        credential.rotated_at = datetime.now(UTC)
        credential.updated_by = actor_user_id
        await self.session.flush()
        return credential

    @staticmethod
    def plaintext(credential: Tr069AcsCredential) -> str:
        return decrypt_secret(credential.password_encrypted)
