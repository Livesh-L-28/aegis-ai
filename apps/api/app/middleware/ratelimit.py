import time
from typing import Any
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from packages.logging.logger import get_logger

logger = get_logger("aegis.ratelimit")


class TokenBucketRateLimiter(BaseHTTPMiddleware):
    """Production Redis-compatible in-memory token bucket rate limiter.

    Enforces request limits per client IP / tenant organization to prevent API denial-of-service.
    """

    def __init__(
        self,
        app: Any,
        requests_per_minute: int = 300,
        burst_capacity: int = 50,
    ) -> None:
        super().__init__(app)
        self.rate = requests_per_minute / 60.0  # tokens added per second
        self.capacity = burst_capacity + requests_per_minute
        self.buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_update)

    def _allow_request(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last_update = self.buckets.get(key, (self.capacity, now))

        # Add tokens accrued since last request
        elapsed = now - last_update
        tokens = min(self.capacity, tokens + elapsed * self.rate)

        if tokens >= 1.0:
            self.buckets[key] = (tokens - 1.0, now)
            return True
        else:
            self.buckets[key] = (tokens, now)
            return False

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Exclude internal metrics, health checks, and static files from rate limiting
        path = request.url.path
        if path.startswith(("/health", "/ready", "/metrics", "/docs", "/openapi.json")):
            return await call_next(request)

        # Identify client by Tenant Org ID or Client IP
        client_key = (
            request.headers.get("X-Organization-ID")
            or request.client.host
            if request.client
            else "unknown_client"
        )

        if not self._allow_request(client_key):
            req_id = getattr(request.state, "request_id", str(uuid4()))
            logger.warning("Rate limit exceeded for client: %s", client_key)
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": "Too many requests. Please slow down.",
                        "request_id": req_id,
                    }
                },
                headers={
                    "X-Request-ID": req_id,
                    "Retry-After": "2",
                },
            )

        return await call_next(request)
