import time

from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response as StarletteResponse

# --- Standard HTTP Metrics (Low Cardinality) ---
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP requests handled",
    ["service", "method", "route", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["service", "method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

HTTP_IN_FLIGHT_REQUESTS = Gauge(
    "http_in_flight_requests",
    "Current in-flight HTTP requests",
    ["service"],
)

# --- Dependency Metrics ---
DATABASE_QUERY_DURATION_SECONDS = Histogram(
    "database_query_duration_seconds",
    "Database query latency in seconds",
    ["service", "operation"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 3.0),
)

DATABASE_ERRORS_TOTAL = Counter(
    "database_errors_total",
    "Total database operation errors",
    ["service", "error_type"],
)

REDIS_OPERATION_DURATION_SECONDS = Histogram(
    "redis_operation_duration_seconds",
    "Redis command latency in seconds",
    ["service", "command"],
    buckets=(0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5),
)

REDIS_ERRORS_TOTAL = Counter(
    "redis_errors_total",
    "Total Redis operation errors",
    ["service", "command"],
)

# --- Business Domain Metrics ---
ORDERS_CREATED_TOTAL = Counter(
    "orders_created_total",
    "Total successful orders created",
    ["service"],
)

ORDERS_FAILED_TOTAL = Counter(
    "orders_failed_total",
    "Total failed order attempts",
    ["service", "reason"],
)

PAYMENTS_ATTEMPTED_TOTAL = Counter(
    "payments_attempted_total",
    "Total payment processing attempts",
    ["service"],
)

PAYMENTS_FAILED_TOTAL = Counter(
    "payments_failed_total",
    "Total failed payment operations",
    ["service", "reason"],
)

USER_REQUESTS_TOTAL = Counter(
    "user_requests_total",
    "Total user operations",
    ["service", "operation"],
)

# --- AI Reliability Engine (aireliability) Integration Metrics ---
AIRELIABILITY_ANALYSIS_TOTAL = Counter(
    "aireliability_analysis_total",
    "Total reliability and root cause analysis invocations",
    ["service", "status"],
)

AIRELIABILITY_ANALYSIS_FAILED_TOTAL = Counter(
    "aireliability_analysis_failed_total",
    "Total failed reliability and root cause analysis invocations",
    ["service", "reason"],
)

AIRELIABILITY_ANALYSIS_DURATION_SECONDS = Histogram(
    "aireliability_analysis_duration_seconds",
    "Duration of aireliability trace analysis and diagnosis in seconds",
    ["service"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)

AIRELIABILITY_REGRESSION_TOTAL = Counter(
    "aireliability_regression_total",
    "Total evaluation and regression suite runs",
    ["service", "suite"],
)

AIRELIABILITY_REGRESSION_FAILED_TOTAL = Counter(
    "aireliability_regression_failed_total",
    "Total failed evaluation and regression suite runs",
    ["service", "suite"],
)



# --- Engineering Evidence Graph Metrics ---
AEGIS_EVIDENCE_NODES_TOTAL = Counter(
    "aegis_evidence_nodes_total",
    "Total evidence graph nodes indexed or stored",
    ["node_type"],
)

AEGIS_EVIDENCE_QUERY_DURATION_SECONDS = Histogram(
    "aegis_evidence_query_duration_seconds",
    "Evidence graph query execution latency in seconds",
    ["operation"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)

AEGIS_EVIDENCE_FILES_INDEXED_TOTAL = Counter(
    "aegis_evidence_files_indexed_total",
    "Total source files indexed by language and status",
    ["language", "status"],
)

AEGIS_EVIDENCE_CACHE_HITS_TOTAL = Counter(
    "aegis_evidence_cache_hits_total",
    "Total content-hash cache hits during indexing",
)

AEGIS_EVIDENCE_IMPACT_QUERY_DURATION_SECONDS = Histogram(
    "aegis_evidence_impact_query_duration_seconds",
    "Latency of change-impact analysis queries in seconds",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)


# --- Phase 3 Autonomous Debugging Metrics ---
AEGIS_DEBUGGING_ANALYSES_TOTAL = Counter(
    "aegis_debugging_analyses_total",
    "Total autonomous debugging runs by completion status",
    ["status"],
)

AEGIS_DEBUGGING_ANALYSIS_DURATION_SECONDS = Histogram(
    "aegis_debugging_analysis_duration_seconds",
    "Duration of autonomous debugging investigations in seconds",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

AEGIS_DEBUGGING_HYPOTHESES_TOTAL = Counter(
    "aegis_debugging_hypotheses_total",
    "Total root cause hypotheses evaluated by verdict",
    ["verdict"],
)

AEGIS_DEBUGGING_PROPOSALS_TOTAL = Counter(
    "aegis_debugging_proposals_total",
    "Total fix proposals generated by validation status",
    ["validation_status"],
)




class PrometheusMetricsMiddleware(BaseHTTPMiddleware):
    """Instruments HTTP endpoints and records Prometheus metrics with safe low cardinality."""

    def __init__(self, app: FastAPI, service_name: str) -> None:
        super().__init__(app)
        self.service_name = service_name

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path in ("/metrics", "/health", "/ready"):
            return await call_next(request)

        route = request.url.path
        # Sanitize parameter routes to prevent metric cardinality explosion
        for r in request.app.routes:
            match, _ = r.matches(request.scope)
            if match.name == "FULL":
                route = getattr(r, "path", route)
                break

        method = request.method
        HTTP_IN_FLIGHT_REQUESTS.labels(service=self.service_name).inc()
        start_time = time.perf_counter()

        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            duration = time.perf_counter() - start_time
            HTTP_IN_FLIGHT_REQUESTS.labels(service=self.service_name).dec()
            HTTP_REQUEST_DURATION_SECONDS.labels(
                service=self.service_name, method=method, route=route
            ).observe(duration)
            HTTP_REQUESTS_TOTAL.labels(
                service=self.service_name,
                method=method,
                route=route,
                status_code=str(status_code),
            ).inc()


def setup_metrics_endpoint(app: FastAPI) -> None:
    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint() -> StarletteResponse:
        return StarletteResponse(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )
