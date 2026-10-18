"""Tests for GitHub integration: Webhooks, Stale-Review protection, and Publication."""

import hashlib
import hmac
from typing import Any

import pytest

from packages.review.domain.models import (
    ChangedFile,
    DiffChangeType,
    DiffHunk,
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    GitDiffSummary,
    ReviewFinding,
    SourceLocation,
)
from packages.review.github.client import (
    GitHubClient,
    GitHubPRMetadata,
    GitHubReviewComment,
)
from packages.review.github.publisher import GitHubReviewPublisher, StaleReviewError
from packages.review.github.webhook import GitHubEventIdempotencyTracker, GitHubWebhookVerifier


def test_webhook_signature_verification() -> None:
    secret = "test-webhook-secret-1234"
    verifier = GitHubWebhookVerifier(secret=secret)
    payload = b'{"action": "opened", "number": 42}'

    # Valid HMAC-SHA256
    valid_sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert verifier.verify_signature(payload=payload, signature_header=valid_sig) is True

    # Invalid HMAC
    invalid_sig = "sha256=11112222333344445555"
    assert verifier.verify_signature(payload=payload, signature_header=invalid_sig) is False

    # Missing signature
    assert verifier.verify_signature(payload=payload, signature_header=None) is False


def test_webhook_idempotency_tracker() -> None:
    tracker = GitHubEventIdempotencyTracker(max_size=10)
    del_id = "deliv-12345-uuid"

    assert tracker.is_duplicate(del_id) is False
    assert tracker.is_duplicate(del_id) is True  # Duplicate on second reception


class MockGitHubClient(GitHubClient):
    def __init__(self, current_head_sha: str) -> None:
        super().__init__()
        self.current_head_sha = current_head_sha
        self.posted_reviews: list[dict[str, Any]] = []

    async def get_pull_request(self, owner: str, repo: str, pr_number: int) -> GitHubPRMetadata:
        return GitHubPRMetadata(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            title="Update features",
            base_sha="base123",
            head_sha=self.current_head_sha,
        )

    async def post_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_id: str,
        body: str,
        event: str = "COMMENT",
        comments: list[GitHubReviewComment] | None = None,
    ) -> dict[str, Any]:
        self.posted_reviews.append({
            "owner": owner,
            "repo": repo,
            "pr_number": pr_number,
            "commit_id": commit_id,
            "body": body,
            "event": event,
            "comments": comments,
        })
        return {"id": 101, "status": "submitted"}


@pytest.mark.asyncio
async def test_publisher_rejects_stale_reviews() -> None:
    # Live PR has head_sha="head_v2", but analysis was performed on "head_v1"
    mock_client = MockGitHubClient(current_head_sha="head_v2")
    publisher = GitHubReviewPublisher(client=mock_client, publish_enabled=True)

    with pytest.raises(StaleReviewError) as exc_info:
        await publisher.publish_review(
            owner="org",
            repo="repo",
            pr_number=1,
            analyzed_head_sha="head_v1",  # Stale!
            findings=[],
            diff_summary=GitDiffSummary(),
        )
    assert "Stale review rejected" in str(exc_info.value)


@pytest.mark.asyncio
async def test_publisher_dry_run_and_inline_positioning() -> None:
    mock_client = MockGitHubClient(current_head_sha="commit_abc123")
    # Dry-run mode
    publisher = GitHubReviewPublisher(client=mock_client, publish_enabled=False)

    # Prepare diff with lines 10..15 added in app.py
    hunk = DiffHunk(
        old_start=1,
        old_length=1,
        new_start=10,
        new_length=6,
        added_lines=[10, 11, 12, 13, 14, 15],
    )
    cf = ChangedFile(
        new_path="app.py",
        change_type=DiffChangeType.MODIFIED,
        hunks=[hunk],
    )
    diff_summary = GitDiffSummary(files=[cf])

    # Finding 1: inside diff (line 12)
    f1 = ReviewFinding(
        rule_id="SEC-001",
        title="Eval in hunk",
        message="Eval call",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.SECURITY,
        origin=FindingOrigin.STATIC_ANALYSIS,
        location=SourceLocation(file_path="app.py", start_line=12),
        tool_name="ast_security",
    )
    # Finding 2: outside diff (line 99)
    f2 = ReviewFinding(
        rule_id="QUAL-001",
        title="Broad except outside hunk",
        message="Broad except",
        severity=FindingSeverity.WARNING,
        category=FindingCategory.QUALITY,
        origin=FindingOrigin.STATIC_ANALYSIS,
        location=SourceLocation(file_path="app.py", start_line=99),
        tool_name="ast_security",
    )

    result = await publisher.publish_review(
        owner="org",
        repo="repo",
        pr_number=5,
        analyzed_head_sha="commit_abc123",
        findings=[f1, f2],
        diff_summary=diff_summary,
    )

    assert result["status"] == "dry_run"
    assert result["inline_comments_count"] == 1  # Only f1 is inside the diff!
    assert "Additional File & Architecture Findings" in result["summary"]
    assert "app.py" in result["summary"]
    assert len(mock_client.posted_reviews) == 0  # Dry-run made 0 external calls
