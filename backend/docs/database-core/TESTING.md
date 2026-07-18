# Database Core Testing

## Unit Tests

Run database-core unit tests with:

```bash
cd backend
pytest tests/unit/test_database_mixins.py \
  tests/unit/test_database_utils.py \
  tests/unit/test_generic_repository.py
```

## Full Backend Tests

```bash
cd backend
pytest
```

## Coverage

The Module 002 tests cover:

- BaseModel column composition
- soft-delete and restore behavior
- UUID generation
- pagination normalization and metadata
- filter validation
- sort validation
- repository create, partial update, soft delete and statement construction

## Database Integration Tests

Integration tests should be added with the first domain module that creates
real tables. Those tests should run against PostgreSQL through Docker Compose
so PostgreSQL UUID, index and constraint behavior is verified against the
production database engine.

