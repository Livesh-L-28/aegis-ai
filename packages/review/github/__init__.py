"""GitHub integration package for AEGIS AI Code Review."""

from packages.review.github.client import GitHubClient, GitHubPRMetadata, GitHubReviewComment
from packages.review.github.publisher import GitHubReviewPublisher, StaleReviewError
from packages.review.github.webhook import GitHubEventIdempotencyTracker, GitHubWebhookVerifier

__all__ = [
    "GitHubClient",
    "GitHubEventIdempotencyTracker",
    "GitHubPRMetadata",
    "GitHubReviewComment",
    "GitHubReviewPublisher",
    "GitHubWebhookVerifier",
    "StaleReviewError",
]
