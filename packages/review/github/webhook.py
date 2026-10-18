"""GitHub Webhook signature verification and idempotent event routing."""

import hashlib
import hmac
import os

from packages.logging.logger import get_logger

logger = get_logger("aegis.review.github.webhook")


class WebhookSecurityError(ValueError):
    """Raised when webhook security constraints are violated in production."""
    pass


class GitHubWebhookVerifier:
    """Verifies incoming GitHub webhook payloads using HMAC SHA-256 signature verification."""

    def __init__(self, secret: str | None = None) -> None:
        env_secret = os.environ.get("GITHUB_WEBHOOK_SECRET")
        env_val = os.environ.get("AEGIS_ENV") or os.environ.get("ENVIRONMENT")
        if env_val:
            is_production = env_val.lower() == "production"
        else:
            try:
                from apps.api.app.core.config import settings
                is_production = getattr(settings, "ENVIRONMENT", "development") == "production"
            except Exception:
                is_production = False

        effective_secret = secret or env_secret

        if is_production:
            if not effective_secret:
                raise WebhookSecurityError(
                    "GITHUB_WEBHOOK_SECRET must be explicitly configured in production environments."
                )
            if effective_secret == "default-dev-secret":
                raise WebhookSecurityError(
                    "Predictable development secret 'default-dev-secret' is strictly forbidden in production."
                )
            self.secret = effective_secret
        else:
            self.secret = effective_secret or "default-dev-secret"

    def verify_signature(
        self,
        payload: bytes,
        signature_header: str | None,
        custom_secret: str | None = None,
    ) -> bool:
        """Verifies HMAC SHA-256 signature using constant-time comparison."""
        if not signature_header:
            logger.warning("Missing X-Hub-Signature-256 header")
            return False

        if not signature_header.startswith("sha256="):
            return False

        target_secret = custom_secret or self.secret
        if not target_secret:
            return False

        secret_bytes = target_secret.encode("utf-8")
        expected_sig = hmac.new(secret_bytes, payload, hashlib.sha256).hexdigest()
        received_sig = signature_header.removeprefix("sha256=")

        return hmac.compare_digest(expected_sig, received_sig)


class GitHubEventIdempotencyTracker:
    """In-memory bounded deduplication cache for GitHub webhook delivery IDs."""

    def __init__(self, max_size: int = 1000) -> None:
        self.max_size = max_size
        self._seen: set[str] = set()
        self._order: list[str] = []

    def is_duplicate(self, delivery_id: str) -> bool:
        if delivery_id in self._seen:
            return True
        if len(self._order) >= self.max_size:
            oldest = self._order.pop(0)
            self._seen.discard(oldest)
        self._seen.add(delivery_id)
        self._order.append(delivery_id)
        return False


default_idempotency_tracker = GitHubEventIdempotencyTracker()
