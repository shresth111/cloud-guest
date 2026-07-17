# Module 002: Database Core

CloudGuest Database Core provides reusable persistence primitives for every
future domain module. It keeps domain behavior out of infrastructure while
standardizing model identity, auditability, soft deletion, optimistic version
tracking and repository access patterns.

## Architecture

- `BaseModel` is the abstract SQLAlchemy parent for future domain entities.
- Mixins are independent and composable: UUID, timestamps, soft delete, audit
  and version columns.
- `GenericRepository` provides async SQLAlchemy 2 CRUD and query operations.
- Utilities centralize pagination, filtering, sorting and UUID generation.
- Database exceptions provide typed failure modes for service-layer handling.
- Pydantic response schemas support pagination and metadata-heavy database
  responses without replacing the global API envelope from Module 001.

## Folder Structure

```text
backend/
  alembic/
    versions/
      .gitkeep
    env.py
    script.py.mako
  app/
    database/
      repositories/
        __init__.py
        generic.py
      schemas/
        __init__.py
        base.py
      utils/
        __init__.py
        filters.py
        pagination.py
        sorting.py
        uuid.py
      __init__.py
      base.py
      constants.py
      exceptions.py
      redis.py
      session.py
  docs/
    database-core/
      FLOW.md
      README.md
      TESTING.md
  tests/
    unit/
      test_database_mixins.py
      test_database_utils.py
      test_generic_repository.py
```

## Base Model Columns

Every model inheriting `BaseModel` receives:

- `id`: PostgreSQL UUID primary key
- `created_at`: timezone-aware creation timestamp
- `updated_at`: timezone-aware update timestamp
- `deleted_at`: nullable soft-delete timestamp
- `is_deleted`: soft-delete flag
- `created_by`: nullable actor UUID
- `updated_by`: nullable actor UUID
- `version`: integer version for service-layer concurrency checks

## Repository Capabilities

`GenericRepository` supports:

- create and bulk create
- update and partial update
- hard delete, soft delete and restore
- get by ID and required get by ID
- get all
- pagination
- search
- sorting and filtering
- exists and count
- explicit commit and rollback helpers

## Alembic Commands

Create a migration after a domain module adds SQLAlchemy models:

```bash
cd backend
alembic revision --autogenerate -m "create module tables"
```

Apply migrations:

```bash
cd backend
alembic upgrade head
```

Rollback one migration:

```bash
cd backend
alembic downgrade -1
```

## Git Commit Message

```text
feat(module-002): add database core foundation
```
