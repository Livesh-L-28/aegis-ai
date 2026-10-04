import logging
import sys
from typing import Any

from pythonjsonlogger import jsonlogger

SENSITIVE_KEYS = {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "secret_key",
    "authorization",
    "api_key",
    "apikey",
    "jwt",
}


def mask_sensitive_data(data: Any) -> Any:
    """Recursively mask sensitive values in logs."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if str(k).lower() in SENSITIVE_KEYS:
                cleaned[k] = "[REDACTED]"
            elif isinstance(v, (dict, list)):
                cleaned[k] = mask_sensitive_data(v)
            else:
                cleaned[k] = v
        return cleaned
    elif isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]
    return data


class StructuredJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with mandatory fields and sensitive key sanitization."""

    def add_fields(
        self,
        log_record: dict[str, Any],
        record: logging.LogRecord,
        message_dict: dict[str, Any],
    ) -> None:
        super().add_fields(log_record, record, message_dict)
        log_record["timestamp"] = self.formatTime(record, self.datefmt)
        log_record["level"] = record.levelname
        log_record["service"] = getattr(record, "service", "aegis-api")
        log_record["environment"] = getattr(record, "environment", "development")

        # Standard context fields
        if hasattr(record, "request_id"):
            log_record["request_id"] = record.request_id
        if hasattr(record, "trace_id"):
            log_record["trace_id"] = record.trace_id
        if hasattr(record, "organization_id"):
            log_record["organization_id"] = record.organization_id
        if hasattr(record, "user_id"):
            log_record["user_id"] = record.user_id
        if hasattr(record, "project_id"):
            log_record["project_id"] = record.project_id

        # Redact sensitive parameters in log record
        for k, v in list(log_record.items()):
            if str(k).lower() in SENSITIVE_KEYS:
                log_record[k] = "[REDACTED]"
            elif isinstance(v, (dict, list)):
                log_record[k] = mask_sensitive_data(v)


def setup_logging(
    service_name: str = "aegis-api",
    environment: str = "development",
    log_level: str = "INFO",
) -> logging.Logger:
    """Configure structured JSON logging for the application."""
    logger = logging.getLogger("aegis")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    formatter = StructuredJsonFormatter(
        "%(timestamp)s %(level)s %(service)s %(environment)s %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False

    # Also route standard uvicorn loggers cleanly
    for uvicorn_logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        u_logger = logging.getLogger(uvicorn_logger_name)
        u_logger.handlers.clear()
        u_logger.addHandler(handler)
        u_logger.propagate = False

    return logger


def get_logger(name: str = "aegis") -> logging.Logger:
    return logging.getLogger(name)
