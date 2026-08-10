"""Generates a FreeRADIUS clients.conf block per active RadiusNasClient row
-- run *inside* the deploy-api-1 container (needs its Python environment,
DB session, and Fernet key to call app.domains.router.crypto.decrypt_secret)
via sync_radius_clients.sh, never invoked directly on the host. See
../README.md's "Dynamic NAS clients" section for the full design and its
one known scaling gap (every client currently accepts from 0.0.0.0/0,
correct with today's single real NAS, wrong once there are several)."""

import asyncio, sys
sys.path.insert(0, "/app")
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from app.core.config import get_settings
from app.domains.router.crypto import decrypt_secret

async def main():
    settings = get_settings()
    engine = create_async_engine(str(settings.database_url))
    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        rows = (await session.execute(text(
            "SELECT id, nas_identifier, shared_secret_encrypted FROM radius_nas_clients "
            "WHERE is_deleted=false AND status='active'"
        ))).all()

    lines = []
    for row in rows:
        nas_id, identifier, enc = row
        secret = decrypt_secret(enc)
        safe_name = f"nas_{str(nas_id).replace('-', '_')}"
        lines.append(f'client {safe_name} {{\n    ipaddr = 0.0.0.0/0\n    secret = "{secret}"\n    nas_type = other\n    shortname = "{identifier}"\n}}\n')
    print("\n".join(lines))
    print(f"# generated {len(rows)} client(s)", file=sys.stderr)

asyncio.run(main())
