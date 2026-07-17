# Database Core Flow

## Read Flow

```text
API handler
  -> service layer
  -> GenericRepository
  -> SQLAlchemy statement utilities
  -> AsyncSession
  -> PostgreSQL
```

The repository excludes soft-deleted records by default. Callers must opt in
with `include_deleted=True` when administrative or recovery workflows need
access to deleted rows.

## Write Flow

```text
API handler
  -> service layer validates command
  -> repository creates or mutates aggregate
  -> AsyncSession flush
  -> service commits transaction
```

Repository methods flush changes and translate SQLAlchemy failures into typed
database exceptions. Transaction ownership remains explicit through `commit`
and `rollback`, allowing service methods to compose several repository calls in
one transaction.

## Filtering

Filtering accepts a mapping of model field names to values. Scalar values use
equality predicates. Lists, tuples and sets use `IN` predicates. Unknown fields
raise `InvalidFilterError`.

## Sorting

Sorting validates the selected field against the model. Invalid fields raise
`InvalidSortError`. Sort order is constrained to `asc` or `desc`.

## Pagination

Pagination normalizes invalid input:

- page numbers below `1` become `1`
- page size is clamped between `1` and `MAX_PAGE_SIZE`
- metadata exposes total items, total pages and navigation booleans

