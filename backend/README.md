# CloudGuest Backend

CloudGuest is a commercial SaaS backend for a cloud-managed MikroTik Network
Operating System. Module 001 provides the production foundation only: FastAPI
application wiring, configuration, logging, database and Redis connectivity,
middleware, exception handling, health checks, Docker assets and unit tests.

Authentication, organizations, routers and product domains are intentionally
excluded from this module.

## Stack

- Python 3.13+
- FastAPI
- SQLAlchemy 2
- Alembic
- PostgreSQL
- Redis
- Pydantic v2
- Docker Compose

## Local Development

```bash
cd backend
python3.13 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
pytest
uvicorn app.main:app --reload
```

API docs are available at:

```text
http://localhost:8000/docs
```

## Docker

```bash
cd backend
docker compose up --build
```

Services:

- API: `http://localhost:8000`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

## Health Checks

```bash
curl http://localhost:8000/api/v1/health/live
curl http://localhost:8000/api/v1/health/ready
```

## Module Documentation

- [Module 002: Database Core](docs/database-core/README.md)

## Git Commit Message

```text
feat(module-001): add backend foundation
```
