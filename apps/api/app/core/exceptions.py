from typing import Any

from fastapi import status


class AegisException(Exception):
    """Base exception for all AEGIS domain and application errors."""

    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_SERVER_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


class ResourceNotFoundException(AegisException):
    def __init__(self, resource: str, identifier: Any) -> None:
        super().__init__(
            message=f"{resource} '{identifier}' not found",
            code="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class UnauthorizedException(AegisException):
    def __init__(self, message: str = "Authentication required") -> None:
        super().__init__(
            message=message,
            code="UNAUTHORIZED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class ForbiddenException(AegisException):
    def __init__(self, message: str = "Permission denied") -> None:
        super().__init__(
            message=message,
            code="FORBIDDEN",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class TenantViolationException(AegisException):
    def __init__(
        self, message: str = "Access across organization boundaries is forbidden"
    ) -> None:
        super().__init__(
            message=message,
            code="TENANT_ACCESS_DENIED",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class ConflictException(AegisException):
    def __init__(self, message: str) -> None:
        super().__init__(
            message=message,
            code="CONFLICT",
            status_code=status.HTTP_409_CONFLICT,
        )


class ValidationException(AegisException):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )
