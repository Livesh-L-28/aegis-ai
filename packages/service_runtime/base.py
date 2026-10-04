from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from packages.logging.logger import get_logger, setup_logging
from packages.observability.telemetry import init_opentelemetry
from packages.service_runtime.metrics import (
    PrometheusMetricsMiddleware,
    setup_metrics_endpoint,
)


class CorrelationAndTracingMiddleware(BaseHTTPMiddleware):
    """Propagates X-Request-ID and trace context across services."""

    def __init__(self, app: FastAPI, service_name: str) -> None:
        super().__init__(app)
        self.service_name = service_name

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        import uuid

        from packages.observability.telemetry import get_current_trace_id

        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        request.state.trace_id = get_current_trace_id()

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


def create_simulated_service(
    service_name: str,
    version: str = "1.0.0",
    environment: str = "production-sim",
) -> FastAPI:
    """Factory creating an instrumented simulated production microservice."""
    setup_logging(service_name=service_name, environment=environment)
    logger = get_logger(f"service.{service_name}")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logger.info("Initializing simulated service: %s v%s", service_name, version)
        init_opentelemetry(service_name=service_name, enabled=False)
        yield
        logger.info("Stopping simulated service: %s", service_name)

    app = FastAPI(
        title=f"Simulated Production: {service_name}",
        version=version,
        lifespan=lifespan,
    )

    # Middlewares
    app.add_middleware(CorrelationAndTracingMiddleware, service_name=service_name)  # type: ignore[arg-type]
    app.add_middleware(PrometheusMetricsMiddleware, service_name=service_name)  # type: ignore[arg-type]

    # Metrics endpoint
    setup_metrics_endpoint(app)

    # Standard Service Metadata & Health Endpoints
    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "service": service_name, "version": version}

    @app.get("/ready")
    async def ready() -> dict[str, Any]:
        return {"status": "ready", "service": service_name}

    @app.get("/metadata")
    async def metadata() -> dict[str, Any]:
        return {
            "service": service_name,
            "version": version,
            "environment": environment,
            "commit": "a1b2c3d4",
            "build": f"build-{version}-release",
        }

    return app
