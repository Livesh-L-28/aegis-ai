import re
import time
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from packages.logging.logger import get_logger
from packages.observability.telemetry import get_current_trace_id

logger = get_logger("aegis.middleware")

SAFE_REQUEST_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Enforces X-Request-ID propagation and contextual structured logging."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        incoming_id = request.headers.get("X-Request-ID")
        if incoming_id and SAFE_REQUEST_ID_REGEX.match(incoming_id):
            request_id = incoming_id
        else:
            request_id = str(uuid4())

        request.state.request_id = request_id
        trace_id = get_current_trace_id()
        request.state.trace_id = trace_id

        start_time = time.perf_counter()

        response = await call_next(request)

        duration_ms = (time.perf_counter() - start_time) * 1000
        response.headers["X-Request-ID"] = request_id

        # Log structured request completion
        logger.info(
            "%s %s completed %s in %.2fms",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            extra={
                "request_id": request_id,
                "trace_id": trace_id,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "path": request.url.path,
                "method": request.method,
            },
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Applies enterprise defense-in-depth security response headers."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Enforces request payload size limits."""

    def __init__(self, app, max_size_bytes: int = 10 * 1024 * 1024) -> None:  # type: ignore
        super().__init__(app)
        self.max_size_bytes = max_size_bytes

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_size_bytes:
            req_id = getattr(request.state, "request_id", str(uuid4()))
            return JSONResponse(
                status_code=413,
                content={
                    "error": {
                        "code": "REQUEST_TOO_LARGE",
                        "message": f"Payload exceeds maximum allowed size of {self.max_size_bytes} bytes",
                        "request_id": req_id,
                    }
                },
                headers={"X-Request-ID": req_id},
            )
        return await call_next(request)
