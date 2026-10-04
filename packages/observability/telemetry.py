from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Tracer

from packages.logging.logger import get_logger

logger = get_logger("aegis.observability")


def init_opentelemetry(
    service_name: str = "aegis-api",
    endpoint: str = "http://localhost:4317",
    enabled: bool = False,
) -> Tracer:
    """Initialize OpenTelemetry tracer provider safely without breaking local startup."""
    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    if enabled:
        try:
            exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info("OpenTelemetry exporter configured for endpoint: %s", endpoint)
        except Exception as exc:
            logger.warning(
                "Failed to initialize OTLP exporter, falling back to default provider: %s",
                exc,
            )

    trace.set_tracer_provider(provider)
    return trace.get_tracer(service_name)


def get_current_trace_id() -> str | None:
    """Retrieve current trace ID if active span exists."""
    span = trace.get_current_span()
    if span and span.get_span_context().is_valid:
        return format(span.get_span_context().trace_id, "032x")
    return None
