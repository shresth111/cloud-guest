class DatabaseError(Exception):
    """Base exception for reusable database operations."""


class RecordNotFoundError(DatabaseError):
    def __init__(self, model_name: str, identifier: object) -> None:
        super().__init__(f"{model_name} record was not found: {identifier}")


class DuplicateRecordError(DatabaseError):
    def __init__(self, model_name: str, field: str) -> None:
        super().__init__(f"{model_name} already exists for field: {field}")


class InvalidFilterError(DatabaseError):
    def __init__(self, field: str) -> None:
        super().__init__(f"Invalid filter field: {field}")


class InvalidSortError(DatabaseError):
    def __init__(self, field: str) -> None:
        super().__init__(f"Invalid sort field: {field}")


class ConflictError(DatabaseError):
    def __init__(self, message: str) -> None:
        super().__init__(message)

