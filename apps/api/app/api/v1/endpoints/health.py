from fastapi import APIRouter, Depends

from apps.api.app.core.config import settings
from apps.api.app.dependencies.core import get_health_service
from apps.api.app.schemas.domain import (
    HealthResponse,
    ReadinessResponse,
    VersionResponse,
)
from apps.api.app.services.health import HealthService

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Liveness probe confirming that the API process is running."""
    return HealthResponse(
        status="ok",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
    )


@router.get("/ready", response_model=ReadinessResponse)
async def readiness_check(
    health_service: HealthService = Depends(get_health_service),
) -> ReadinessResponse:
    """Readiness probe verifying operational state of dependencies (Postgres, Redis, Storage)."""
    return await health_service.check_readiness()


@router.get("/version", response_model=VersionResponse)
async def version_info() -> VersionResponse:
    """Version and environment metadata endpoint."""
    return VersionResponse(
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        api_version="v1",
    )
