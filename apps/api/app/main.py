from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from apps.api.app.api.v1.router import v1_router
from apps.api.app.core.config import settings
from apps.api.app.core.exceptions import AegisException
from apps.api.app.core.logging import logger
from apps.api.app.middleware.ratelimit import TokenBucketRateLimiter
from apps.api.app.middleware.security import (
    CorrelationIdMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from apps.api.app.services.infrastructure import get_redis_service
from packages.observability.telemetry import init_opentelemetry
from packages.service_runtime.metrics import (
    PrometheusMetricsMiddleware,
    setup_metrics_endpoint,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Startup
    logger.info(
        "Initializing %s (v%s) in environment=%s",
        settings.APP_NAME,
        settings.APP_VERSION,
        settings.ENVIRONMENT,
    )
    init_opentelemetry(
        service_name=settings.OTEL_SERVICE_NAME,
        endpoint=settings.OTEL_ENDPOINT,
        enabled=settings.OTEL_ENABLED,
    )
    yield
    # Shutdown
    logger.info("Shutting down %s", settings.APP_NAME)
    redis_service = get_redis_service(settings)
    await redis_service.close()


def create_application() -> FastAPI:
    app = FastAPI(
        title="LogicFalcon API (Powered by AEGIS AI)",
        description="LogicFalcon is an AI-powered software engineering intelligence platform for evidence-grounded code review, repository analysis, change-impact assessment, root-cause analysis, and safe fix proposals. Powered by AEGIS AI.",
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
        redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    )

    # 1. Base Security & Trust Middlewares
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )

    # 2. Observability & Security Middlewares
    app.add_middleware(TokenBucketRateLimiter, requests_per_minute=300, burst_capacity=50)
    app.add_middleware(
        RequestSizeLimitMiddleware,
        max_size_bytes=settings.MAX_REQUEST_SIZE_BYTES,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(PrometheusMetricsMiddleware, service_name=settings.APP_NAME)  # type: ignore[arg-type]
    setup_metrics_endpoint(app)

    # 3. Safe Exception Handlers (Standardized error envelope, no internal stack traces leaked)
    @app.exception_handler(AegisException)
    async def aegis_exception_handler(
        request: Request, exc: AegisException
    ) -> JSONResponse:
        req_id = getattr(request.state, "request_id", "req_unknown")
        logger.warning(
            "Application error [%s]: %s",
            exc.code,
            exc.message,
            extra={"request_id": req_id, "error_code": exc.code},
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "request_id": req_id,
                    "details": exc.details,
                }
            },
            headers={"X-Request-ID": req_id},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        req_id = getattr(request.state, "request_id", "req_unknown")
        logger.error(
            "Unhandled server exception: %s",
            str(exc),
            exc_info=True,
            extra={"request_id": req_id},
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An internal server error occurred.",
                    "request_id": req_id,
                }
            },
            headers={"X-Request-ID": req_id},
        )

    # 4. Include API Routers
    app.include_router(v1_router, prefix=settings.API_V1_PREFIX)

    return app


app = create_application()
