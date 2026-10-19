"""Unit tests for GitLab MR integration (client & publisher)."""

import json

import httpx
import pytest

from packages.review.domain.models import (
    ChangedFile,
    DiffChangeType,
    DiffHunk,
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    GitDiffSummary,
    ProposedFix,
    ReviewFinding,
    SourceLocation,
)
from packages.review.github.publisher import StaleReviewError
from packages.review.gitlab.client import (
    GitLabClient,
)
from packages.review.gitlab.publisher import GitLabReviewPublisher


@pytest.fixture
def sample_diff_summary() -> GitDiffSummary:
    hunk = DiffHunk(
        old_start=1,
        old_length=5,
        new_start=1,
        new_length=7,
        added_lines=[3, 4],
        deleted_lines=[],
        lines=["@@ -1,5 +1,7 @@", " line1", " line2", "+line3", "+line4", " line5"],
    )
    cf = ChangedFile(
        old_path="app/main.py",
        new_path="app/main.py",
        change_type=DiffChangeType.MODIFIED,
        hunks=[hunk],
    )
    return GitDiffSummary(
        base_commit="base1234",
        head_commit="head1234",
        files=[cf],
    )


@pytest.fixture
def sample_findings() -> list[ReviewFinding]:
    inline_finding = ReviewFinding(
        rule_id="QUAL-002",
        title="Mutable Default Argument",
        message="Avoid items=[]",
        severity=FindingSeverity.WARNING,
        category=FindingCategory.QUALITY,
        origin=FindingOrigin.STATIC_ANALYSIS,
        location=SourceLocation(file_path="app/main.py", start_line=3),
        confidence=1.0,
        tool_name="ast_security",
        proposed_fix=ProposedFix(
            file_path="app/main.py",
            start_line=3,
            end_line=3,
            replacement_code="items=None",
        ),
    )
    out_of_diff_finding = ReviewFinding(
        rule_id="SEC-001",
        title="Repository Config Issue",
        message="Misconfigured settings",
        severity=FindingSeverity.ERROR,
        category=FindingCategory.SECURITY,
        origin=FindingOrigin.STATIC_ANALYSIS,
        location=SourceLocation(file_path="app/config.py", start_line=10),
        confidence=0.9,
        tool_name="ast_security",
    )
    return [inline_finding, out_of_diff_finding]


@pytest.mark.asyncio
async def test_gitlab_client_get_mr() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "/api/v4/projects" in request.url.path
        assert "merge_requests/42" in request.url.path
        assert request.headers["PRIVATE-TOKEN"] == "glpat-test"
        return httpx.Response(
            200,
            json={
                "id": 100,
                "iid": 42,
                "title": "Update feature",
                "sha": "head1234",
                "diff_refs": {
                    "base_sha": "base1234",
                    "head_sha": "head1234",
                    "start_sha": "start1234",
                },
                "state": "opened",
            },
        )

    transport = httpx.MockTransport(handler)
    client = GitLabClient(token="glpat-test", transport=transport)
    mr = await client.get_merge_request("group/project", 42)
    assert mr.mr_iid == 42
    assert mr.head_sha == "head1234"
    assert mr.base_sha == "base1234"


@pytest.mark.asyncio
async def test_gitlab_publisher_stale_review_rejected(
    sample_findings: list[ReviewFinding],
    sample_diff_summary: GitDiffSummary,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "iid": 42,
                "title": "PR",
                "sha": "new_head_sha_9999",  # Different from analyzed_head_sha
                "diff_refs": {"base_sha": "base1234", "head_sha": "new_head_sha_9999", "start_sha": "base1234"},
                "state": "opened",
            },
        )

    transport = httpx.MockTransport(handler)
    client = GitLabClient(token="glpat-test", transport=transport)
    publisher = GitLabReviewPublisher(client=client, publish_enabled=True)

    with pytest.raises(StaleReviewError):
        await publisher.publish_review(
            project_id="group/project",
            mr_iid=42,
            analyzed_head_sha="head1234",
            findings=sample_findings,
            diff_summary=sample_diff_summary,
        )


@pytest.mark.asyncio
async def test_gitlab_publisher_dry_run(
    sample_findings: list[ReviewFinding],
    sample_diff_summary: GitDiffSummary,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "iid": 42,
                "title": "PR",
                "sha": "head1234",
                "diff_refs": {"base_sha": "base1234", "head_sha": "head1234", "start_sha": "base1234"},
                "state": "opened",
            },
        )

    transport = httpx.MockTransport(handler)
    client = GitLabClient(token="glpat-test", transport=transport)
    publisher = GitLabReviewPublisher(client=client, publish_enabled=False)

    result = await publisher.publish_review(
        project_id="group/project",
        mr_iid=42,
        analyzed_head_sha="head1234",
        findings=sample_findings,
        diff_summary=sample_diff_summary,
    )

    assert result["status"] == "dry_run"
    assert result["inline_discussions_count"] == 1
    assert "Repository Context Findings" in result["summary"]


@pytest.mark.asyncio
async def test_gitlab_publisher_full_publish(
    sample_findings: list[ReviewFinding],
    sample_diff_summary: GitDiffSummary,
) -> None:
    posted_discussions = []
    posted_notes = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "iid": 42,
                    "title": "PR",
                    "sha": "head1234",
                    "diff_refs": {"base_sha": "base1234", "head_sha": "head1234", "start_sha": "base1234"},
                    "state": "opened",
                },
            )
        elif request.method == "POST" and "notes" in request.url.path:
            posted_notes.append(json.loads(request.content))
            return httpx.Response(201, json={"id": 555})
        elif request.method == "POST" and "discussions" in request.url.path:
            posted_discussions.append(json.loads(request.content))
            return httpx.Response(201, json={"id": "disc-777"})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    client = GitLabClient(token="glpat-test", transport=transport)
    publisher = GitLabReviewPublisher(client=client, publish_enabled=True)

    result = await publisher.publish_review(
        project_id="group/project",
        mr_iid=42,
        analyzed_head_sha="head1234",
        findings=sample_findings,
        diff_summary=sample_diff_summary,
    )

    assert result["status"] == "published"
    assert result["note_id"] == 555
    assert result["inline_published"] == 1
    assert len(posted_notes) == 1
    assert len(posted_discussions) == 1
    assert "```suggestion" in posted_discussions[0]["body"]
    assert posted_discussions[0]["position"]["new_line"] == 3
