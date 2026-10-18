"""Regression tests for SEC-02: GitHub webhook security and fail-closed secret management."""

import hashlib
import hmac
from collections.abc import Generator

import pytest

from packages.config.settings import get_settings
from packages.review.github.webhook import GitHubWebhookVerifier, WebhookSecurityError


@pytest.fixture(autouse=True)
def reset_settings_cache() -> Generator[None, None, None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()



def test_missing_secret_in_production_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)

    with pytest.raises(WebhookSecurityError, match="GITHUB_WEBHOOK_SECRET must be explicitly configured"):
        GitHubWebhookVerifier()


def test_predictable_dev_secret_rejected_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "default-dev-secret")

    with pytest.raises(WebhookSecurityError, match="strictly forbidden in production"):
        GitHubWebhookVerifier()


def test_configured_production_secret_verifies_correctly(monkeypatch: pytest.MonkeyPatch) -> None:
    prod_secret = "prod-super-secure-webhook-secret-998877"
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", prod_secret)

    verifier = GitHubWebhookVerifier()
    payload = b'{"action": "opened"}'
    expected_sig = "sha256=" + hmac.new(prod_secret.encode(), payload, hashlib.sha256).hexdigest()

    assert verifier.verify_signature(payload, expected_sig) is True
    assert verifier.verify_signature(payload, "sha256=wrong_sig") is False
    assert verifier.verify_signature(payload, None) is False


def test_local_development_fallback_permitted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)

    verifier = GitHubWebhookVerifier()
    assert verifier.secret == "default-dev-secret"

    payload = b'{"action": "synchronize"}'
    valid_sig = "sha256=" + hmac.new(b"default-dev-secret", payload, hashlib.sha256).hexdigest()
    assert verifier.verify_signature(payload, valid_sig) is True
