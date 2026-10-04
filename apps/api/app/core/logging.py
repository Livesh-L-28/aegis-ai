from apps.api.app.core.config import settings
from packages.logging.logger import get_logger, mask_sensitive_data, setup_logging

logger = setup_logging(
    service_name=settings.APP_NAME,
    environment=settings.ENVIRONMENT,
    log_level=settings.LOG_LEVEL,
)

__all__ = ["get_logger", "logger", "mask_sensitive_data"]
